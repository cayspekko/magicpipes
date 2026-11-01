//! The local agent: one long-running process per user and machine, serving every tunnel.
//!
//! * `session` — control path: server connection, reconnects, registration RPCs.
//! * `forward` — data path: server-opened streams piped to local targets.
//! * `serve` — built-in static file server for `add --serve`, run on data streams directly.
//! * `shell` — web terminal for `add --shell` (xterm.js page + pty per browser session).
//! * `udp` — relays a UDP tunnel's datagram streams to the local UDP service.
//! * `ops` — operations exposed over IPC, including the readiness-gated `add`.
//!
//! Single instance: the agent holds an exclusive `flock` on `agent.lock` for its lifetime.
//! A second agent (e.g. from two concurrent `magicpipes add` invocations) fails to take the lock
//! and exits, and both CLIs then talk to the winner over the IPC endpoint (`agent.sock`, or a
//! named pipe on Windows; see `platform`). Because the lock dies with the process, a stale socket
//! file can always be removed safely by the lock holder.

mod forward;
mod ops;
mod probe;
mod serve;
mod session;
mod shell;
mod tunnels;
mod udp;

use std::fs::File;
use std::sync::Arc;

use anyhow::{Context, bail};
use magicpipes_core::error::ErrorCode;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, BufReader};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::ipc::{self, ErrorInfo, IpcEvent, IpcRequest};
use crate::platform::{self, IpcListener};
use crate::state::{self, AgentConfig};
use ops::Agent;

/// Outcome of trying to become the agent.
pub enum Start {
    Ran,
    AlreadyRunning,
}

pub fn run(detached: bool) -> anyhow::Result<Start> {
    state::ensure_home()?;
    let lock = File::options().create(true).truncate(false).write(true).open(state::lock_path())?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(Start::AlreadyRunning),
        Err(std::fs::TryLockError::Error(e)) => return Err(e).context("locking agent.lock"),
    }
    let Some(cfg) = AgentConfig::load()? else {
        bail!("not logged in; run `magicpipes login --server <url> --token <token>` first");
    };
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let res = rt.block_on(serve(cfg, detached));
    platform::cleanup_ipc();
    let _ = std::fs::remove_file(state::pid_path());
    drop(lock);
    res.map(|_| Start::Ran)
}

async fn serve(cfg: AgentConfig, detached: bool) -> anyhow::Result<()> {
    // We hold the lock, so any existing socket is stale.
    let mut listener = IpcListener::bind()?;
    state::write_private(&state::pid_path(), std::process::id().to_string().as_bytes())?;

    let shutdown = CancellationToken::new();
    let tunnels = tunnels::Tunnels::load()?;
    let tls = crate::https::tls_config(cfg.ca_cert_pem.as_deref())?;
    let session = session::Session::new(cfg, tunnels.clone())?;
    let agent = Agent::new(session.clone(), tunnels.clone(), tls, shutdown.clone());
    tracing::info!(pid = std::process::id(), tunnels = tunnels.len(), detached, "agent started");

    let session_task = tokio::spawn(session.clone().run(shutdown.clone()));
    let terminate = platform::terminate();
    tokio::pin!(terminate);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = platform::interrupt() => break,
            _ = &mut terminate => break,
            conn = listener.accept() => {
                let stream = match conn {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(error = %e, "IPC accept failed");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let agent = agent.clone();
                tokio::spawn(async move { handle_ipc(agent, stream).await });
            }
        }
    }
    tracing::info!("agent stopping");
    shutdown.cancel();
    // Web terminal programs get SIGHUP now and SIGKILL after shell::KILL_GRACE; those timers
    // run on this runtime, so it must outlive them.
    tunnels.end_all();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), session_task).await;
    if tunnels.list().iter().any(|t| matches!(t.target, state::Target::Shell { .. })) {
        tokio::time::sleep(shell::KILL_GRACE + std::time::Duration::from_millis(200)).await;
    }
    Ok(())
}

async fn handle_ipc<S: AsyncRead + AsyncWrite>(agent: Arc<Agent>, stream: S) {
    let (r, mut w) = tokio::io::split(stream);
    let mut reader = BufReader::new(r).take(ipc::MAX_LINE as u64);
    let mut line = String::new();
    // The CLI sends its request at once; a connection that sends nothing would otherwise hold
    // a task (and on Windows a pipe instance) forever.
    match tokio::time::timeout(std::time::Duration::from_secs(5), reader.read_line(&mut line)).await {
        Ok(Ok(_)) => {}
        _ => return,
    }
    let req: IpcRequest = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            let _ = ipc::write_line(&mut w, &IpcEvent::Error(ErrorInfo::new(ErrorCode::BadRequest, e.to_string()))).await;
            return;
        }
    };
    let (tx, mut rx) = mpsc::channel::<IpcEvent>(16);
    let work = async {
        let res = match req {
            IpcRequest::Add(a) => agent.add(a, &tx).await,
            IpcRequest::Remove { selector, force } => agent.remove(&selector, force).await,
            IpcRequest::List => Ok(agent.list()),
            IpcRequest::Status => Ok(agent.status()),
            IpcRequest::Shutdown { if_idle } => agent.shutdown(if_idle),
        };
        let _ = tx.send(match res {
            Ok(data) => IpcEvent::Ok { data },
            Err(e) => IpcEvent::Error(e),
        })
        .await;
        drop(tx);
    };
    let forward = async {
        while let Some(ev) = rx.recv().await {
            if ipc::write_line(&mut w, &ev).await.is_err() {
                // The CLI went away (e.g. Ctrl+C); the operation still runs to completion so
                // that cleanup on failure happens.
                continue;
            }
        }
    };
    tokio::join!(work, forward);
}
