//! A new agent taking over from the running one without a gap (Unix): after `magicpipes
//! --upgrade` put a new binary in place, or to apply a changed setting.
//!
//! 1. The running agent (old) starts the binary at its path as a background agent, handing it the
//!    agent lock and the CLI's socket ([`magicpipes_core::fds`]), so no command ever finds no
//!    agent and no other agent can start meanwhile, and a pipe of their own.
//! 2. The new one connects as a new run of the machine naming the old one
//!    (`proto::REPLACES_HEADER`): the server sends it every new stream from then on, while the old
//!    run finishes what it has. It registers its tunnels, and says it's ready.
//! 3. The old one stops answering commands, says go, finishes its streams (at most
//!    [`DRAIN`]) and exits. The new one answers commands from then on.
//!
//! On Windows, or for an agent run in the foreground (`agent run` under a service manager or in a
//! container), there's no take-over: the CLI stops the agent and starts it again.

use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use magicpipes_core::error::ErrorCode;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;

use super::ops::Agent;
use crate::ipc::ErrorInfo;
use crate::state;

/// Names the run a new agent takes over from, for its connections.
pub const REPLACES_ENV: &str = "MAGICPIPES_REPLACES";
/// How long the new agent may take to connect and register its tunnels.
const READY_WITHIN: Duration = Duration::from_secs(60);
/// How long the old agent lets its streams run before it closes what's left.
pub const DRAIN: Duration = Duration::from_secs(30);

/// What a running background agent can hand to a new one.
pub struct Handing {
    pub lock: OwnedFd,
    pub ipc: OwnedFd,
    /// Cancelled once the new agent answers commands: this one then stops accepting them.
    pub stop_commands: CancellationToken,
    /// Handed over: the socket and the pid file are the new agent's now.
    pub handed: AtomicBool,
    busy: AtomicBool,
}

impl Handing {
    pub fn new(lock: OwnedFd, ipc: OwnedFd) -> Self {
        Self { lock, ipc, stop_commands: CancellationToken::new(), handed: AtomicBool::new(false), busy: AtomicBool::new(false) }
    }
}

fn failed(msg: impl Into<String>) -> ErrorInfo {
    ErrorInfo::new(ErrorCode::UpgradeFailed, msg)
}

impl Agent {
    /// Hands over to the binary at this agent's path, as described above. Returns once the new
    /// agent answers commands, with its pid and version.
    pub async fn hand_over(&self) -> Result<Value, ErrorInfo> {
        let Some(h) = self.handing.get() else {
            return Err(ErrorInfo::new(ErrorCode::Unsupported, "an agent run in the foreground doesn't hand over; restart it"));
        };
        if h.busy.swap(true, Ordering::SeqCst) {
            return Err(ErrorInfo::new(ErrorCode::Busy, "a take-over is already under way"));
        }
        let result = self.start_new(h).await;
        if result.is_err() {
            h.busy.store(false, Ordering::SeqCst);
        }
        result
    }

    async fn start_new(&self, h: &Handing) -> Result<Value, ErrorInfo> {
        let exe = magicpipes_core::upgrade::exe().ok_or_else(|| failed("the agent doesn't know where its binary is"))?.to_path_buf();
        let tested = {
            let exe = exe.clone();
            tokio::task::spawn_blocking(move || magicpipes_core::upgrade::self_test(&exe, "magicpipes")).await
        };
        let said = match tested {
            Ok(Ok(said)) => said,
            Ok(Err(e)) => return Err(failed(e.message)),
            Err(e) => return Err(failed(e.to_string())),
        };
        let (ours, theirs) = std::os::unix::net::UnixStream::pair().map_err(|e| failed(e.to_string()))?;
        let log = crate::platform::private_options().create(true).append(true).open(state::log_path()).map_err(|e| failed(e.to_string()))?;
        let mut cmd = std::process::Command::new(&exe);
        cmd.args(["agent", "run", "--detached"])
            .env(REPLACES_ENV, self.session.instance())
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().map_err(|e| failed(e.to_string()))?)
            .stderr(log);
        crate::platform::detach(&mut cmd);
        let fds = [("lock".to_string(), h.lock.as_raw_fd()), ("ipc".to_string(), h.ipc.as_raw_fd()), ("handover".to_string(), theirs.as_raw_fd())];
        magicpipes_core::fds::pass(&mut cmd, &fds);
        let mut child = cmd.spawn().map_err(|e| failed(format!("starting the new agent: {e}")))?;
        drop(theirs);
        let pid = child.id();
        tracing::info!(pid, "started a new agent to take over");

        ours.set_nonblocking(true).map_err(|e| failed(e.to_string()))?;
        let stream = tokio::net::UnixStream::from_std(ours).map_err(|e| failed(e.to_string()))?;
        let (r, mut w) = stream.into_split();
        let mut lines = BufReader::new(r).lines();
        let ready = tokio::time::timeout(READY_WITHIN, lines.next_line()).await;
        if !matches!(&ready, Ok(Ok(Some(l))) if l == "ready") {
            let _ = child.kill();
            let _ = child.wait();
            let why = match ready {
                Err(_) => "the new agent wasn't connected within a minute".to_string(),
                Ok(Ok(Some(l))) => format!("the new agent couldn't start: {l}"),
                _ => "the new agent stopped before it was ready; agent.log says why".to_string(),
            };
            return Err(failed(why));
        }
        // From now on, commands are the new agent's.
        h.stop_commands.cancel();
        h.handed.store(true, Ordering::SeqCst);
        let _ = w.write_all(b"go\n").await;
        // Not waited for: it outlives this agent, which exits once its streams are done.
        drop(child);
        let version = said.split_whitespace().nth(1).unwrap_or_default().to_string();
        tracing::info!(pid, %version, "the new agent took over; finishing what's under way");
        Ok(json!({ "pid": pid, "version": version }))
    }
}

/// A background agent started to take over from another.
pub struct Joining {
    pub lock: std::fs::File,
    pub ipc: OwnedFd,
    /// Made a Tokio stream once the runtime runs.
    channel: std::os::unix::net::UnixStream,
    pub replaces: Option<String>,
}

/// What the old agent handed this one, if it's taking over. Call before taking the lock.
pub fn joining() -> Option<Joining> {
    let lock = magicpipes_core::fds::take("lock")?;
    let ipc = magicpipes_core::fds::take("ipc")?;
    let channel = magicpipes_core::fds::take("handover")?;
    let channel = std::os::unix::net::UnixStream::from(channel);
    channel.set_nonblocking(true).ok()?;
    let replaces = std::env::var(REPLACES_ENV).ok().filter(|r| magicpipes_core::proto::valid_instance(r));
    Some(Joining { lock: std::fs::File::from(lock), ipc, channel, replaces })
}

impl Joining {
    /// Waits until this agent is connected and has registered every tunnel it can (or gives up
    /// after [`READY_WITHIN`], saying why), tells the old one, and waits for it to stop answering
    /// commands. A tunnel the server turned down doesn't hold it up: the old agent couldn't serve
    /// it either.
    pub async fn ready(self, agent: &Arc<Agent>) -> anyhow::Result<()> {
        let mut channel = tokio::net::UnixStream::from_std(self.channel)?;
        let served = tokio::time::timeout(READY_WITHIN, async {
            loop {
                if agent.settled().is_ok() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        if served.is_err() {
            let why = agent.settled().err().unwrap_or_default();
            let _ = channel.write_all(format!("not ready: {why}\n").as_bytes()).await;
            anyhow::bail!("couldn't serve every tunnel in time: {why}");
        }
        channel.write_all(b"ready\n").await?;
        let mut lines = BufReader::new(&mut channel).lines();
        // The old agent says go, or goes: either way the commands are this one's.
        let _ = lines.next_line().await;
        Ok(())
    }
}
