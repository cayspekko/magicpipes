//! Upgrading this agent: to the latest release from its own release source, which it checks the
//! signature of itself, then handing over to it (`takeover`). `magicpipes --upgrade` does the same
//! from the CLI; this is for when the server asks, which it may only where the machine's user
//! allowed it (`magicpipes --upgrade --allow-remote`). The server only asks: it never says what
//! to install or where from.

use std::sync::Arc;

use magicpipes_core::error::ErrorCode;
use magicpipes_core::upgrade::{self, Offer};
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::ops::Agent;
use crate::ipc::ErrorInfo;

/// Where releases are read from, instead of the project's latest GitHub release.
pub const SOURCE_ENV: &str = "MAGICPIPES_RELEASE_SOURCE";

pub fn source() -> String {
    upgrade::source_url(std::env::var(SOURCE_ENV).ok().as_deref())
}

/// The least time between two upgrades the server asks for: a server asking over and over makes
/// the agent read the release source once a minute at most.
const ASK_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(60);

/// Takes the server's requests to upgrade, one at a time.
pub fn listen(agent: &Arc<Agent>) {
    let (tx, mut rx) = mpsc::channel::<()>(1);
    agent.session.take_upgrade_requests(tx);
    let agent = agent.clone();
    tokio::spawn(async move {
        let mut last: Option<tokio::time::Instant> = None;
        loop {
            tokio::select! {
                _ = agent.shutdown.cancelled() => return,
                asked = rx.recv() => if asked.is_none() { return },
            }
            if last.is_some_and(|t| t.elapsed() < ASK_COOLDOWN) {
                tracing::info!("the server asked again to upgrade within a minute; not this time");
                continue;
            }
            last = Some(tokio::time::Instant::now());
            tracing::info!("the server asked this agent to upgrade itself");
            match upgrade_itself(&agent).await {
                Ok(done) => tracing::info!(result = %done, "upgrade"),
                Err(e) => tracing::warn!(code = %e.code, error = %e.message, "couldn't upgrade"),
            }
        }
    });
}

/// Installs the latest release in place of this agent's binary and hands over to it; the binary
/// goes back if the hand-over fails.
pub async fn upgrade_itself(agent: &Agent) -> Result<Value, ErrorInfo> {
    let error = |e: upgrade::UpgradeError| ErrorInfo::new(e.code, e.message);
    let exe = upgrade::exe().ok_or_else(|| ErrorInfo::new(ErrorCode::UpgradeNotPossible, "the agent doesn't know where its binary is"))?.to_path_buf();
    let latest = upgrade::latest(&source()).await.map_err(error)?;
    let manifest = match Offer::of(latest, "magicpipes") {
        Offer::Newer(m) => m,
        Offer::UpToDate(m) => return Ok(json!({ "upgraded": false, "latest": m.version })),
        Offer::NotForThisPlatform(m) => {
            return Err(ErrorInfo::new(ErrorCode::UpgradeNotPossible, format!("release {} has no magicpipes for this platform", m.version)));
        }
    };
    upgrade::install(&manifest, "magicpipes", &exe).await.map_err(error)?;
    #[cfg(unix)]
    let handed = agent.hand_over().await;
    #[cfg(not(unix))]
    let handed: Result<Value, ErrorInfo> = {
        let _ = agent;
        Err(ErrorInfo::new(ErrorCode::Unsupported, "a take-over without a gap needs Linux or macOS"))
    };
    match handed {
        Ok(v) => Ok(json!({ "upgraded": true, "from": magicpipes_core::VERSION, "to": manifest.version, "pid": v["pid"] })),
        Err(e) => {
            let _ = upgrade::roll_back(&exe);
            Err(e)
        }
    }
}
