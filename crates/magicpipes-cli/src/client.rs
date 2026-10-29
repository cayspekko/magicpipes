//! CLI side of the agent lifecycle: find the running agent or start a detached one.
//!
//! The CLI never forks itself. It spawns a fresh `magicpipes agent run --detached` process
//! (fork immediately followed by exec, with only `setsid()` in between), so the new agent builds
//! its own Tokio runtime from scratch and is detached from the terminal's session and signals.

use std::io::{BufRead, Seek};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use tokio::net::UnixStream;

use crate::ipc::{self, ErrorInfo, IpcRequest, Step, StepState};
use crate::state::{self, AgentConfig};

const START_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;

pub async fn connect() -> Option<UnixStream> {
    UnixStream::connect(state::socket_path()).await.ok()
}

pub fn require_login() -> Result<AgentConfig, ErrorInfo> {
    match AgentConfig::load() {
        Ok(Some(c)) => Ok(c),
        Ok(None) => Err(ErrorInfo::new(
            "not_logged_in",
            "this machine is not enrolled; run `magicpipes login --server https://<server>:8443 --token <enrollment token>`",
        )),
        Err(e) => Err(ErrorInfo::new("config_error", format!("{e:#}"))),
    }
}

/// Ensures an agent is running. Returns `true` if this call started it.
pub async fn ensure_agent() -> Result<bool, ErrorInfo> {
    if connect().await.is_some() {
        return Ok(false);
    }
    require_login()?;
    state::ensure_home().map_err(|e| ErrorInfo::new("config_error", format!("{e:#}")))?;
    let mut child = spawn_detached().map_err(|e| ErrorInfo::new("agent_start_failed", format!("could not start agent: {e}")))?;
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
                        "agent_start_failed",
                        format!("the agent exited during startup:\n{}", tail_log(5).join("\n")),
                    ));
                }
                _ => {}
            }
        }
    }
    Err(ErrorInfo::new(
        "agent_start_failed",
        format!("the agent did not become ready within {}s; see {}", START_TIMEOUT.as_secs(), state::log_path().display()),
    ))
}

fn spawn_detached() -> std::io::Result<Child> {
    let exe = std::env::current_exe()?;
    let log = std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(state::log_path())?;
    if log.metadata()?.len() > MAX_LOG_BYTES {
        log.set_len(0)?;
    }
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["agent", "run", "--detached"]).stdin(Stdio::null()).stdout(log.try_clone()?).stderr(log);
    // SAFETY: setsid() is async-signal-safe and is the only call between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn()
}

/// One IPC request to a running agent.
pub async fn request(req: &IpcRequest, on_step: impl FnMut(Step, StepState)) -> Result<serde_json::Value, ErrorInfo> {
    let stream = connect().await.ok_or_else(|| ErrorInfo::new("agent_not_running", "the agent is not running"))?;
    ipc::call(stream, req, on_step).await
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
