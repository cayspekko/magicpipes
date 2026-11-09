//! CLI side of the agent lifecycle: find the running agent or start a detached one.
//!
//! The CLI never forks itself. It spawns a fresh `magicpipes agent run --detached` process
//! (on Unix, fork immediately followed by exec with only `setsid()` in between; on Windows, a
//! detached process), so the new agent builds its own Tokio runtime from scratch and is
//! detached from the terminal's session and signals.

use std::io::{BufRead, Seek};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use magicpipes_core::error::ErrorCode;

use crate::ipc::{self, ErrorInfo, IpcRequest, Step, StepState};
use crate::platform::{self, IpcClient};
use crate::state::{self, AgentConfig};

const START_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;

pub async fn connect() -> Option<IpcClient> {
    platform::ipc_connect().await
}

pub fn require_login() -> Result<AgentConfig, ErrorInfo> {
    match AgentConfig::load() {
        Ok(Some(c)) => Ok(c),
        Ok(None) => Err(ErrorInfo::new(
            ErrorCode::NotLoggedIn,
            "this machine is not enrolled; run `magicpipes login --server https://<server>:8443 --token <enrollment token>`",
        )),
        Err(e) => Err(ErrorInfo::new(ErrorCode::ConfigError, format!("{e:#}"))),
    }
}

/// Ensures an agent is running. Returns `true` if this call started it.
pub async fn ensure_agent() -> Result<bool, ErrorInfo> {
    if connect().await.is_some() {
        return Ok(false);
    }
    require_login()?;
    state::ensure_home().map_err(|e| ErrorInfo::new(ErrorCode::ConfigError, format!("{e:#}")))?;
    let start_failed = |e: std::io::Error| ErrorInfo::new(ErrorCode::AgentStartFailed, format!("could not start agent: {e}"));
    // Held until we stop waiting; the agents we start run only while some command holds it.
    let _waiting = wait_for_agent().map_err(start_failed)?;
    let spawn = || spawn_detached().map_err(start_failed);
    let started = Instant::now();
    // The agent we started, until it exits because another agent holds the lock.
    let mut child = Some(spawn()?);
    while started.elapsed() < START_TIMEOUT {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if connect().await.is_some() {
            return Ok(child.is_some());
        }
        match child.as_mut().map(Child::try_wait) {
            // Exit 0 before we could connect: another agent holds the lock. It may be starting,
            // and its socket is about to appear, or still exiting after a stop, and nobody will
            // open one; so once it lets go of the lock, start one again.
            Some(Ok(Some(s))) if s.success() => child = None,
            Some(Ok(Some(_))) => {
                return Err(ErrorInfo::new(
                    ErrorCode::AgentStartFailed,
                    format!("the agent exited during startup:\n{}", tail_log(5).join("\n")),
                ));
            }
            _ => {}
        }
        // Only once it's free, rather than one every 50 ms that exits at once.
        if child.is_none() && lock_is_free() {
            child = Some(spawn()?);
        }
    }
    Err(ErrorInfo::new(
        ErrorCode::AgentStartFailed,
        format!("the agent did not become ready within {}s; see {}", START_TIMEOUT.as_secs(), state::log_path().display()),
    ))
}

/// Says that a command is waiting for an agent, for as long as the file is open: a shared lock
/// on `agent-start.lock`, which a detached agent checks once it holds the agent lock (see
/// `agent::run`). One we started can get there late, after we connected to another agent that has
/// since been stopped, or gave up; it then exits instead of running when nobody wants it.
fn wait_for_agent() -> std::io::Result<std::fs::File> {
    let file = std::fs::File::options().create(true).truncate(false).write(true).open(state::start_lock_path())?;
    // Blocks only while a starting agent looks, for a moment.
    file.lock_shared()?;
    Ok(file)
}

/// Whether no agent holds its lock, so that one started now would run. Taken for a moment to see.
fn lock_is_free() -> bool {
    match std::fs::File::options().create(true).truncate(false).write(true).open(state::lock_path()) {
        Ok(lock) => lock.try_lock().is_ok(),
        // Then the agent can't take it either, and says why when it's started.
        Err(_) => true,
    }
}

fn spawn_detached() -> std::io::Result<Child> {
    let exe = std::env::current_exe()?;
    let log = platform::private_options().create(true).append(true).open(state::log_path())?;
    if log.metadata()?.len() > MAX_LOG_BYTES {
        log.set_len(0)?;
    }
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["agent", "run", "--detached"]).stdin(Stdio::null()).stdout(log.try_clone()?).stderr(log);
    platform::detach(&mut cmd);
    cmd.spawn()
}

/// One IPC request to a running agent.
pub async fn request(req: &IpcRequest, on_step: impl FnMut(Step, StepState)) -> Result<serde_json::Value, ErrorInfo> {
    let stream = connect().await.ok_or_else(|| ErrorInfo::new(ErrorCode::AgentNotRunning, "the agent is not running"))?;
    ipc::call(stream, req, on_step).await.map_err(|mut e| {
        // A request this CLI builds is always valid, so the agent must be an older version.
        if e.is(ErrorCode::BadRequest) {
            e.code = ErrorCode::AgentOutdated.to_string();
            e.message = format!(
                "the running agent does not understand this request ({}); it is probably an older version. \
                 Restart it with `magicpipes agent stop`, then run the command again",
                e.message
            );
        }
        e
    })
}

/// Refuses before a running agent of an older version could ignore part of `req`, for example
/// publishing a public tunnel when a private one was asked for.
pub async fn check_agent_understands(req: &ipc::AddRequest) -> Result<(), ErrorInfo> {
    if !req.needs_current_agent() {
        return Ok(());
    }
    let status = request(&IpcRequest::Status, |_, _| {}).await?;
    if status["agent"]["ipc_version"].as_u64().unwrap_or(1) >= u64::from(ipc::IPC_VERSION) {
        return Ok(());
    }
    Err(ErrorInfo::new(
        ErrorCode::AgentOutdated,
        "the running agent is an older version that would ignore some of these options. \
         Restart it with `magicpipes agent stop`, then run the command again",
    ))
}

/// Waits for a stopping agent to release its socket.
pub async fn wait_stopped(timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if connect().await.is_none() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

pub fn tail_log(n: usize) -> Vec<String> {
    let Ok(f) = std::fs::File::open(state::log_path()) else { return Vec::new() };
    let mut f = f;
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let _ = f.seek(std::io::SeekFrom::Start(len.saturating_sub(256 * 1024)));
    let lines: Vec<String> = std::io::BufReader::new(f).lines().map_while(Result::ok).collect();
    lines[lines.len().saturating_sub(n)..].to_vec()
}
