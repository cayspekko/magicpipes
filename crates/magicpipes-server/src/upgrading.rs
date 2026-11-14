//! `magicpipesd --upgrade`, run by an administrator next to the running server: checks for a new
//! release, puts it in place of the server's binary, and has the running server hand over to it
//! without downtime ([`crate::handover`]), following it until it's done.
//!
//! * `--upgrade --check` only says what's available.
//! * `--upgrade --restart` hands over to the binary in place now, downloading nothing: after
//!   installing one some other way, or to restart without downtime.
//! * `--upgrade --rollback` puts back the binary the last upgrade replaced, and hands over to it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use magicpipes_core::error::ErrorCode;
use magicpipes_core::upgrade::{self, Offer, UpgradeError};
use magicpipes_core::{release, secret, unix_now};
use serde_json::json;

use crate::config::Config;
use crate::handover::{self, RequestFile, State};

/// The longest a handover may take before `--upgrade` stops following it.
const FOLLOW_FOR: Duration = Duration::from_secs(900);

pub enum What {
    Check,
    Upgrade,
    Restart,
    Rollback,
}

/// Runs it, prints the outcome (as JSON with `json`), and gives the process's exit status.
pub fn run(what: What, cfg: &Config, json: bool) -> u8 {
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => return fail(json, UpgradeError::new(ErrorCode::Internal, e.to_string())),
    };
    let result = rt.block_on(async {
        match what {
            What::Check => check(cfg).await,
            What::Upgrade => upgrade(cfg, json).await,
            What::Restart => restart(cfg, json).await,
            What::Rollback => rollback(cfg, json).await,
        }
    });
    match result {
        Ok(out) => {
            if json {
                println!("{out}");
            } else if let Some(text) = out["text"].as_str() {
                println!("{text}");
            }
            0
        }
        Err(e) => fail(json, e),
    }
}

fn fail(json: bool, e: UpgradeError) -> u8 {
    if json {
        println!("{}", json!({ "error": { "code": e.code.as_str(), "message": e.message } }));
    } else {
        eprintln!("error: {}", e.message);
    }
    e.code.exit_code()
}

/// The running server, if there is one; an error if this user can't tell.
fn running(data_dir: &Path) -> Result<Option<handover::Running>, UpgradeError> {
    if let Err(e) = std::fs::read_dir(data_dir)
        && e.kind() == std::io::ErrorKind::PermissionDenied
    {
        return Err(UpgradeError::new(
            ErrorCode::UpgradeNotPossible,
            format!("can't read {}: run this as root, or as the user magicpipesd runs as", data_dir.display()),
        ));
    }
    Ok(handover::read_pid(data_dir).filter(|r| alive(r.pid)))
}

fn alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(pid) = i32::try_from(pid) else { return false };
        // SAFETY: signal 0 only asks whether the process exists.
        unsafe { libc::kill(pid, 0) == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

/// The binary to replace: the running server's, else this one.
fn binary(running: Option<&handover::Running>) -> Result<PathBuf, UpgradeError> {
    running
        .and_then(|r| r.exe.clone())
        .or_else(|| upgrade::exe().map(Path::to_path_buf))
        .ok_or_else(|| UpgradeError::new(ErrorCode::UpgradeNotPossible, "can't tell where magicpipesd's binary is"))
}

async fn check(cfg: &Config) -> Result<serde_json::Value, UpgradeError> {
    let latest = upgrade::latest(&cfg.upgrades.source_url()).await?;
    let running = running(&cfg.data_dir).ok().flatten();
    let exe = binary(running.as_ref()).ok();
    let why_not = exe.as_deref().and_then(upgrade::cannot_replace);
    let offer = Offer::of(latest, "magicpipesd");
    let m = offer.manifest();
    let newer = matches!(offer, Offer::Newer(_));
    let mut text = match &offer {
        Offer::Newer(m) => format!("magicpipesd {} is available; this is {}.", m.version, magicpipes_core::VERSION),
        Offer::UpToDate(m) => format!("magicpipesd {} is the latest release; this is {}.", m.version, magicpipes_core::VERSION),
        Offer::NotForThisPlatform(m) => format!("magicpipesd {} has no binary for {}.", m.version, release::TARGET.unwrap_or("this platform")),
    };
    if m.security && newer {
        text.push_str(" It fixes a security problem.");
    }
    if let Some(notes) = &m.notes {
        text.push_str(&format!("\nWhat changed: {notes}"));
    }
    match (&why_not, newer) {
        (Some(why), true) => text.push_str(&format!("\nThis install can't upgrade itself: {why}.")),
        (None, true) => text.push_str("\nRun `magicpipesd --upgrade` to move to it without downtime."),
        _ => {}
    }
    Ok(json!({
        "running": magicpipes_core::VERSION,
        "latest": m.version,
        "newer": newer,
        "security": m.security && newer,
        "notes": m.notes,
        "can_upgrade": newer && why_not.is_none(),
        "why_not": why_not,
        "text": text,
    }))
}

async fn upgrade(cfg: &Config, json: bool) -> Result<serde_json::Value, UpgradeError> {
    let running = running(&cfg.data_dir)?;
    let exe = binary(running.as_ref())?;
    let latest = upgrade::latest(&cfg.upgrades.source_url()).await?;
    let manifest = match Offer::of(latest, "magicpipesd") {
        Offer::Newer(m) => m,
        Offer::UpToDate(m) => {
            let text = format!("magicpipesd {} is the latest release, and this is {}: nothing to do.", m.version, magicpipes_core::VERSION);
            return Ok(json!({ "upgraded": false, "running": magicpipes_core::VERSION, "latest": m.version, "text": text }));
        }
        Offer::NotForThisPlatform(m) => {
            return Err(UpgradeError::new(ErrorCode::UpgradeNotPossible, format!("release {} has no magicpipesd for {}", m.version, release::TARGET.unwrap_or("this platform"))));
        }
    };
    say(json, &format!("Downloading magicpipesd {} to {}…", manifest.version, exe.display()));
    upgrade::install(&manifest, "magicpipesd", &exe).await?;
    let Some(running) = running else {
        let text = format!("Installed magicpipesd {} at {}. No server is running; start it to use it.", manifest.version, exe.display());
        return Ok(json!({ "upgraded": true, "from": magicpipes_core::VERSION, "to": manifest.version, "running": false, "text": text }));
    };
    match hand_over(cfg, &running, Some(manifest.version.clone()), json).await {
        Ok(out) => Ok(out),
        Err(e) => {
            // The old version carries on, so its binary goes back.
            let _ = upgrade::roll_back(&exe);
            Err(UpgradeError::new(e.code, format!("{} The binary {} is back.", e.message, running.version)))
        }
    }
}

async fn restart(cfg: &Config, json: bool) -> Result<serde_json::Value, UpgradeError> {
    let Some(running) = running(&cfg.data_dir)? else {
        return Err(UpgradeError::new(ErrorCode::UpgradeNotPossible, "no magicpipesd is running with this configuration"));
    };
    hand_over(cfg, &running, None, json).await
}

async fn rollback(cfg: &Config, json: bool) -> Result<serde_json::Value, UpgradeError> {
    let running = running(&cfg.data_dir)?;
    let exe = binary(running.as_ref())?;
    match upgrade::roll_back(&exe) {
        Ok(true) => {}
        Ok(false) => return Err(UpgradeError::new(ErrorCode::UpgradeNotPossible, format!("there's no earlier binary kept beside {}", exe.display()))),
        Err(e) => return Err(UpgradeError::new(ErrorCode::UpgradeNotPossible, format!("putting the earlier binary back: {e}"))),
    }
    let Some(running) = running else {
        return Ok(json!({ "rolled_back": true, "running": false, "text": format!("Put the earlier binary back at {}. Start magicpipesd to use it.", exe.display()) }));
    };
    match hand_over(cfg, &running, None, json).await {
        Ok(out) => Ok(out),
        Err(e) => {
            let _ = upgrade::roll_back(&exe);
            let backup = handover::read_status(&cfg.data_dir).and_then(|s| s.backup);
            let mut message = format!("{} The binary {} is back.", e.message, running.version);
            if let Some(b) = backup {
                message.push_str(&format!(
                    " If the newer version migrated the database, the earlier one can't open it: stop magicpipesd, copy {b} over {}, and start the earlier binary.",
                    cfg.data_dir.join("magicpipes.db").display()
                ));
            }
            Err(UpgradeError::new(e.code, message))
        }
    }
}

fn say(json: bool, line: &str) {
    if !json {
        eprintln!("{line}");
    }
}

/// Asks the running server to hand over to the binary at its path, and follows it.
async fn hand_over(cfg: &Config, running: &handover::Running, to: Option<String>, json: bool) -> Result<serde_json::Value, UpgradeError> {
    let id = secret::random_string(12);
    handover::write_request(&cfg.data_dir, &RequestFile { id: id.clone(), to, at: unix_now() })
        .map_err(|e| UpgradeError::new(ErrorCode::UpgradeNotPossible, format!("writing to {}: {e}", cfg.data_dir.display())))?;
    signal(running.pid).map_err(|e| UpgradeError::new(ErrorCode::UpgradeNotPossible, format!("asking magicpipesd (pid {}) to hand over: {e}", running.pid)))?;
    let started = std::time::Instant::now();
    let mut said = None;
    loop {
        if let Some(status) = handover::read_status(&cfg.data_dir).filter(|s| s.id == id) {
            if said != Some(status.step) && status.state == State::Running {
                say(json, &format!("{}…", handover::STEPS[status.step.min(handover::STEPS.len() - 1)]));
                said = Some(status.step);
            }
            match status.state {
                State::Running => {}
                State::Done => {
                    let to = status.to.clone().unwrap_or_else(|| "the new version".into());
                    let text = format!("magicpipesd {to} took over from {} without downtime (pid {}).", status.from, status.pid.map_or("?".into(), |p| p.to_string()));
                    return Ok(json!({ "upgraded": true, "from": status.from, "to": status.to, "pid": status.pid, "backup": status.backup, "text": text }));
                }
                State::Failed => {
                    let why = status.message.unwrap_or_else(|| "the handover failed; the server's log says why".into());
                    return Err(UpgradeError::new(ErrorCode::UpgradeFailed, format!("{why}. magicpipesd {} carries on.", status.from)));
                }
            }
        }
        if started.elapsed() > FOLLOW_FOR {
            return Err(UpgradeError::new(ErrorCode::UpgradeFailed, "the handover didn't finish in time; the server's log says where it is"));
        }
        if started.elapsed() > Duration::from_secs(10) && said.is_none() {
            return Err(UpgradeError::new(
                ErrorCode::UpgradeFailed,
                format!("magicpipesd (pid {}) didn't start the handover; it may be older than this, or not the server this configuration is for", running.pid),
            ));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn signal(pid: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let pid = i32::try_from(pid).map_err(std::io::Error::other)?;
        // SAFETY: sends a signal; no memory is involved.
        if unsafe { libc::kill(pid, libc::SIGUSR2) } == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        Err(std::io::Error::other("a handover without downtime needs Linux or macOS; restart the service instead"))
    }
}
