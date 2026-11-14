//! New releases: the daily check (`[upgrades] check`), and what administrators see of it. Moving
//! to a release without downtime is `crate::handover`'s.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::{self, ErrorBody, ServerOpen, StreamStatus, UPGRADES_PROTOCOL};
use magicpipes_core::release::{Manifest, Version};
use magicpipes_core::unix_now;
use magicpipes_core::upgrade::{self, Offer, UpgradeError};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

use super::{ControlPlane, err};
use crate::authz::{self, Action, Principal, Resource};
use crate::handover;

/// The first check waits this long after the server starts, so a restart loop isn't a request
/// loop; then one a day, or an hour after one that failed.
const FIRST_CHECK_AFTER: Duration = Duration::from_secs(60);
const CHECK_EVERY: Duration = Duration::from_secs(24 * 3600);
const RETRY_AFTER: Duration = Duration::from_secs(3600);

/// The last check, if there's been one.
#[derive(Default)]
pub struct Releases {
    last: Mutex<Option<Checked>>,
}

#[derive(Clone)]
struct Checked {
    at: i64,
    result: Result<Manifest, UpgradeError>,
}

/// What administrators see about versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseView {
    /// This server's version.
    pub running: String,
    /// `[upgrades] check` is on.
    pub checking: bool,
    pub checked_at: Option<i64>,
    /// The latest release, once a check found one.
    pub latest: Option<String>,
    /// It's newer than this server, and has a binary for its platform.
    pub newer: bool,
    pub security: bool,
    pub notes: Option<String>,
    /// Why the last check didn't find out.
    pub error: Option<String>,
}

impl ControlPlane {
    pub(super) fn start_release_checks(self: &Arc<Self>, shutdown: CancellationToken) {
        if !self.cfg.upgrades.check {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            let mut wait = FIRST_CHECK_AFTER;
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tokio::time::sleep(wait) => {}
                }
                wait = match me.check_releases().await {
                    Ok(_) => CHECK_EVERY,
                    Err(_) => RETRY_AFTER,
                };
            }
        });
    }

    /// Asks the release source now, and keeps the answer.
    pub async fn check_releases(&self) -> Result<Manifest, UpgradeError> {
        let result = upgrade::latest(&self.cfg.upgrades.source_url()).await;
        match &result {
            Ok(m) => tracing::info!(latest = %m.version, running = magicpipes_core::VERSION, "checked for a new release"),
            Err(e) => tracing::warn!(error = %e, "couldn't check for a new release"),
        }
        *self.releases.last.lock().unwrap_or_else(|e| e.into_inner()) = Some(Checked { at: unix_now(), result: result.clone() });
        result
    }

    /// The latest release the last check found, if it found one.
    pub fn latest_release(&self) -> Option<Manifest> {
        self.releases.last.lock().unwrap_or_else(|e| e.into_inner()).as_ref().and_then(|c| c.result.clone().ok())
    }

    pub fn releases(&self) -> ReleaseView {
        let last = self.releases.last.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let manifest = last.as_ref().and_then(|c| c.result.as_ref().ok());
        ReleaseView {
            running: magicpipes_core::VERSION.to_string(),
            checking: self.cfg.upgrades.check,
            checked_at: last.as_ref().map(|c| c.at),
            latest: manifest.map(|m| m.version.clone()),
            newer: manifest.is_some_and(|m| matches!(upgrade::Offer::of(m.clone(), "magicpipesd"), upgrade::Offer::Newer(_))),
            security: manifest.is_some_and(|m| m.security),
            notes: manifest.and_then(|m| m.notes.clone()),
            error: last.and_then(|c| c.result.err()).map(|e| e.message),
        }
    }

    /// A consistent copy of the database at `to`: a backup, or what a new version rehearses on.
    pub fn copy_database(&self, to: &Path) -> anyhow::Result<()> {
        self.store.copy_to(to)
    }

    /// Where requests to hand over to a new version go.
    pub fn set_handover(&self, asks: tokio::sync::mpsc::Sender<crate::handover::Ask>) {
        let _ = self.handover.set(asks);
    }

    /// Asks this server to hand over to the binary at its path. `false` if one is already under
    /// way, or this server can't be asked.
    pub fn request_handover(&self, ask: crate::handover::Ask) -> bool {
        self.handover.get().is_some_and(|tx| tx.try_send(ask).is_ok())
    }

    /// Why this server can't upgrade itself from the Settings page, if it can't.
    pub fn cannot_upgrade_itself(&self) -> Option<String> {
        if let Some(why) = handover::blocker() {
            return Some(why);
        }
        let exe = upgrade::exe()?;
        upgrade::cannot_replace(exe)
    }

    /// Starts upgrading this server to the latest release the daily check found: downloads it in
    /// place of this binary, then hands over to it ([`handover`]). Returns at once, with the id
    /// the status file follows it by; the Settings page shows how it goes.
    pub fn upgrade_server(self: &Arc<Self>, who: &Principal) -> Result<String, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(err(ErrorCode::Forbidden, "only administrators upgrade the server"));
        }
        if let Some(why) = self.cannot_upgrade_itself() {
            return Err(err(ErrorCode::UpgradeNotPossible, format!("this server can't upgrade itself: {why}")));
        }
        let Some(exe) = upgrade::exe().map(Path::to_path_buf) else {
            return Err(err(ErrorCode::UpgradeNotPossible, "this server doesn't know where its binary is"));
        };
        let manifest = match self.latest_release().map(|m| Offer::of(m, "magicpipesd")) {
            Some(Offer::Newer(m)) => m,
            _ => return Err(err(ErrorCode::UpgradeNotPossible, "there's no newer release for this server")),
        };
        let data_dir = self.cfg.data_dir.clone();
        if handover::under_way(&data_dir) {
            return Err(err(ErrorCode::Busy, "an upgrade is already under way"));
        }
        let ask = handover::Ask::new(Some(manifest.version.clone()));
        let id = ask.id.clone();
        handover::downloading(&data_dir, &id, &manifest.version);
        self.audit(who, "server.upgrade", "", &format!("{} to {}", magicpipes_core::VERSION, manifest.version));
        let me = self.clone();
        tokio::spawn(async move {
            if let Err(e) = upgrade::install(&manifest, "magicpipesd", &exe).await {
                tracing::warn!(error = %e, "couldn't download the new version");
                handover::failed_before(&data_dir, &ask.id, &manifest.version, &e.message);
                return;
            }
            let id = ask.id.clone();
            if !me.request_handover(ask) {
                let _ = upgrade::roll_back(&exe);
                handover::failed_before(&data_dir, &id, &manifest.version, "another upgrade was under way");
            }
        });
        Ok(id)
    }

    /// Asks an agent `who` manages to upgrade itself, which it does only if its user allowed it
    /// (`magicpipes --upgrade --allow-remote`): to the latest release from its own source, which
    /// it checks itself. `Ok(false)`: no such agent, or `who` may not manage it.
    pub async fn ask_agent_to_upgrade(&self, who: &Principal, agent_id: &str) -> Result<bool, ErrorBody> {
        let handle = {
            let st = self.state.lock().unwrap();
            if !authz::authorize(who, Action::Manage, st.agent_resource(agent_id)) || st.dir.agent(agent_id).is_none() {
                return Ok(false);
            }
            let Some(link) = st.sessions.get(agent_id) else {
                return Err(err(ErrorCode::AgentOffline, "the machine isn't connected"));
            };
            // The newest run speaks for the machine.
            let lane = link.runs.last().and_then(|r| r.lanes.iter().find(|s| !s.handle.is_closed()));
            match lane {
                Some(s) if s.remote_upgrade && s.protocol >= UPGRADES_PROTOCOL => s.handle.clone(),
                _ => return Err(err(ErrorCode::UpgradeNotPossible, "its user hasn't allowed it: on the machine, run `magicpipes --upgrade --allow-remote`")),
            }
        };
        let asked = async {
            let mut s = handle.open(Duration::from_secs(10)).await.ok()?;
            proto::write_frame(&mut s, &ServerOpen::Upgrade).await.ok()?;
            s.read_u8().await.ok().and_then(StreamStatus::from_byte)
        };
        match tokio::time::timeout(Duration::from_secs(15), asked).await.ok().flatten() {
            Some(StreamStatus::Ok) => {
                self.audit(who, "agent.upgrade", agent_id, "");
                Ok(true)
            }
            Some(_) => Err(err(ErrorCode::UpgradeNotPossible, "the agent declined; it upgrades only when its user allows it")),
            None => Err(err(ErrorCode::AgentUnavailable, "the agent didn't answer")),
        }
    }

    /// A newer release that fixes a security problem, for the alert rule.
    pub(super) fn security_release(&self) -> Option<String> {
        let latest = self.latest_release()?;
        (latest.security && latest.parsed_version().is_some_and(|v| v > Version::current())).then_some(latest.version)
    }
}
