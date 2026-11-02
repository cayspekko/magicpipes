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
    let mut child = spawn_detached().map_err(|e| ErrorInfo::new(ErrorCode::AgentStartFailed, format!("could not start agent: {e}")))?;
    let started = Instant::now();
    let mut exited_ok = false;
    while started.elapsed() < START_TIMEOUT {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if connect().await.is_some() {
            return Ok(!exited_ok);
        }
        if !exited_ok {
            match child.try_wait() {
                // Exit 0 before we could connect: another agent won the startup race. Keep
                // waiting for its socket.
                Ok(Some(s)) if s.success() => exited_ok = true,
                Ok(Some(_)) => {
                    return Err(ErrorInfo::new(
                        ErrorCode::AgentStartFailed,
                        format!("the agent exited during startup:\n{}", tail_log(5).join("\n")),
                    ));
                }
                _ => {}
            }
        }
    }
    Err(ErrorInfo::new(
        ErrorCode::AgentStartFailed,
        format!("the agent did not become ready within {}s; see {}", START_TIMEOUT.as_secs(), state::log_path().display()),
    ))
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
