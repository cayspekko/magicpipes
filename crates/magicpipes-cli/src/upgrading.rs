//! `magicpipes --upgrade`: puts the latest release in place of this machine's `magicpipes`, and
//! has the running agent hand over to it without dropping a connection (`agent::takeover`).
//!
//! * `--upgrade --check` only says what's available.
//! * `--upgrade --restart` hands over to the binary in place now (after installing one another way,
//!   or to restart without a gap).
//! * `--upgrade --rollback` puts back the binary the last upgrade replaced, and hands over to it.
//! * `--upgrade --allow-remote` / `--deny-remote` let the server ask this agent to upgrade itself,
//!   or stop it from asking. Off unless turned on here.

use std::path::{Path, PathBuf};

use magicpipes_core::error::ErrorCode;
use magicpipes_core::release;
use magicpipes_core::upgrade::{self, Offer, UpgradeError};
use serde_json::{Value, json};

use crate::client;
use crate::ipc::{ErrorInfo, IpcRequest};
use crate::state::AgentConfig;

pub enum What {
    Check,
    Upgrade,
    Restart,
    Rollback,
    /// `--allow-remote` (true) or `--deny-remote`.
    Remote(bool),
}

fn error(e: UpgradeError) -> ErrorInfo {
    ErrorInfo::new(e.code, e.message)
}

fn say(json: bool, line: &str) {
    if !json {
        eprintln!("{line}");
    }
}

/// The running agent's status, if one is running.
async fn running() -> Option<Value> {
    client::connect().await?;
    client::request(&IpcRequest::Status, |_, _| {}).await.ok()
}

/// The binary to replace: the running agent's, else this one.
fn binary(status: Option<&Value>) -> Result<PathBuf, ErrorInfo> {
    status
        .and_then(|s| s["agent"]["exe"].as_str())
        .map(PathBuf::from)
        .or_else(|| upgrade::exe().map(Path::to_path_buf))
        .ok_or_else(|| ErrorInfo::new(ErrorCode::UpgradeNotPossible, "can't tell where magicpipes is installed"))
}

pub async fn run(what: What, json: bool) -> Result<Value, ErrorInfo> {
    let source = crate::agent::upgrade_source();
    match what {
        What::Check => check(&source).await,
        What::Upgrade => {
            let status = running().await;
            let exe = binary(status.as_ref())?;
            let latest = upgrade::latest(&source).await.map_err(error)?;
            let manifest = match Offer::of(latest, "magicpipes") {
                Offer::Newer(m) => m,
                Offer::UpToDate(m) => {
                    let text = format!("magicpipes {} is the latest release, and this is {}: nothing to do.", m.version, magicpipes_core::VERSION);
                    return Ok(json!({ "upgraded": false, "latest": m.version, "text": text }));
                }
                Offer::NotForThisPlatform(m) => {
                    return Err(ErrorInfo::new(ErrorCode::UpgradeNotPossible, format!("release {} has no magicpipes for {}", m.version, release::TARGET.unwrap_or("this platform"))));
                }
            };
            say(json, &format!("Downloading magicpipes {} to {}…", manifest.version, exe.display()));
            upgrade::install(&manifest, "magicpipes", &exe).await.map_err(error)?;
            let Some(status) = status else {
                let text = format!("Installed magicpipes {} at {}.", manifest.version, exe.display());
                return Ok(json!({ "upgraded": true, "from": magicpipes_core::VERSION, "to": manifest.version, "agent": null, "text": text }));
            };
            match take_over(&status, json).await {
                Ok(mut out) => {
                    out["upgraded"] = json!(true);
                    out["to"] = json!(manifest.version);
                    Ok(out)
                }
                Err(e) => {
                    let _ = upgrade::roll_back(&exe);
                    Err(ErrorInfo::wire(&e.code, format!("{} The binary before is back.", e.message)))
                }
            }
        }
        What::Restart => {
            let status = running().await.ok_or_else(|| ErrorInfo::new(ErrorCode::AgentNotRunning, "the agent is not running"))?;
            take_over(&status, json).await
        }
        What::Rollback => {
            let status = running().await;
            let exe = binary(status.as_ref())?;
            match upgrade::roll_back(&exe) {
                Ok(true) => {}
                Ok(false) => return Err(ErrorInfo::new(ErrorCode::UpgradeNotPossible, format!("there's no earlier binary kept beside {}", exe.display()))),
                Err(e) => return Err(ErrorInfo::new(ErrorCode::UpgradeNotPossible, format!("putting the earlier binary back: {e}"))),
            }
            match status {
                Some(status) => take_over(&status, json).await,
                None => Ok(json!({ "rolled_back": true, "agent": null, "text": format!("Put the earlier binary back at {}.", exe.display()) })),
            }
        }
        What::Remote(on) => remote(on, json).await,
    }
}

async fn check(source: &str) -> Result<Value, ErrorInfo> {
    let latest = upgrade::latest(source).await.map_err(error)?;
    let status = running().await;
    let why_not = binary(status.as_ref()).ok().as_deref().and_then(upgrade::cannot_replace);
    let offer = Offer::of(latest, "magicpipes");
    let newer = matches!(offer, Offer::Newer(_));
    let m = offer.manifest();
    let mut text = match &offer {
        Offer::Newer(m) => format!("magicpipes {} is available; this is {}.", m.version, magicpipes_core::VERSION),
        Offer::UpToDate(m) => format!("magicpipes {} is the latest release; this is {}.", m.version, magicpipes_core::VERSION),
        Offer::NotForThisPlatform(m) => format!("magicpipes {} has no binary for {}.", m.version, release::TARGET.unwrap_or("this platform")),
    };
    if let Some(agent) = status.as_ref().and_then(|s| s["agent"]["version"].as_str()).filter(|v| *v != magicpipes_core::VERSION) {
        text.push_str(&format!(" The running agent is {agent}."));
    }
    if let Some(notes) = &m.notes {
        text.push_str(&format!("\nWhat changed: {notes}"));
    }
    match (&why_not, newer) {
        (Some(why), true) => text.push_str(&format!("\nThis install can't upgrade itself: {why}.")),
        (None, true) => text.push_str("\nRun `magicpipes --upgrade` to move to it without dropping a connection."),
        _ => {}
    }
    Ok(json!({
        "running": magicpipes_core::VERSION,
        "agent": status.as_ref().map(|s| s["agent"]["version"].clone()),
        "latest": m.version,
        "newer": newer,
        "security": m.security && newer,
        "notes": m.notes,
        "can_upgrade": newer && why_not.is_none(),
        "why_not": why_not,
        "text": text,
    }))
}

/// Has the running agent hand over to the binary at its path. An agent that can't (an older one,
/// one run in the foreground, or on Windows) is left for its user to restart, saying how.
async fn take_over(status: &Value, json: bool) -> Result<Value, ErrorInfo> {
    let before = status["agent"]["version"].as_str().unwrap_or("?").to_string();
    say(json, "Handing over to the new agent…");
    match client::request(&IpcRequest::HandOver, |_, _| {}).await {
        Ok(v) => {
            let (pid, version) = (v["pid"].clone(), v["version"].as_str().unwrap_or("?").to_string());
            let text = format!("magicpipes {version} took over from {before} without dropping a connection (pid {pid}).");
            Ok(json!({ "from": before, "pid": pid, "text": text }))
        }
        Err(e) if e.is(ErrorCode::AgentOutdated) || e.is(ErrorCode::Unsupported) => {
            let text = if status["agent"]["detached"].as_bool() == Some(false) {
                "The new binary is in place. The agent runs in the foreground (a service or a container): restart it to use the new one."
            } else {
                "The new binary is in place. The running agent can't hand over without a gap: run `magicpipes agent stop`, then `magicpipes agent start`."
            };
            Ok(json!({ "from": before, "restarted": false, "text": text }))
        }
        Err(e) => Err(e),
    }
}

async fn remote(on: bool, json: bool) -> Result<Value, ErrorInfo> {
    if on && !cfg!(unix) {
        return Err(ErrorInfo::new(ErrorCode::Unsupported, "upgrading when the server asks needs Linux or macOS"));
    }
    let mut cfg = client::require_login()?;
    if cfg.allow_remote_upgrade != on {
        cfg.allow_remote_upgrade = on;
        cfg.save().map_err(|e| ErrorInfo::new(ErrorCode::ConfigError, format!("{e:#}")))?;
    }
    let said = if on {
        format!("{} may ask this machine to upgrade magicpipes. It reads releases from their own source and installs only one signed for it.", server_name(&cfg))
    } else {
        format!("{} may no longer ask this machine to upgrade magicpipes.", server_name(&cfg))
    };
    // The agent says it when it connects: a new run reads the setting.
    let applied = match running().await {
        Some(status) if status["agent"]["allow_remote_upgrade"].as_bool() != Some(on) => {
            match client::request(&IpcRequest::HandOver, |_, _| {}).await {
                Ok(_) => "applied",
                Err(_) => "when the agent next starts",
            }
        }
        _ => "applied",
    };
    let _ = json;
    let text = if applied == "applied" { said } else { format!("{said} It takes effect when the agent next starts.") };
    Ok(json!({ "allow_remote": on, "text": text }))
}

fn server_name(cfg: &AgentConfig) -> String {
    cfg.server.trim_start_matches("https://").trim_end_matches('/').to_string()
}
