//! The local agent: one long-running process per user and machine, serving every tunnel.
//!
//! * `session` — control path: server connection, reconnects, registration RPCs.
//! * `forward` — data path: server-opened streams piped to local targets.
//! * `ops` — operations exposed over IPC, including the readiness-gated `add`.
//!
//! Single instance: the agent holds an exclusive `flock` on `agent.lock` for its lifetime.
//! A second agent (e.g. from two concurrent `magicpipes add` invocations) fails to take the lock
//! and exits, and both CLIs then talk to the winner over `agent.sock`. Because the lock dies with
//! the process, a stale socket file can always be removed safely by the lock holder.

mod forward;
mod ops;
mod probe;
mod session;
mod tunnels;

use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use anyhow::{Context, bail};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::ipc::{self, ErrorInfo, IpcEvent, IpcRequest};
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
    let _ = std::fs::remove_file(state::socket_path());
    let _ = std::fs::remove_file(state::pid_path());
    drop(lock);
    res.map(|_| Start::Ran)
}

async fn serve(cfg: AgentConfig, detached: bool) -> anyhow::Result<()> {
    let sock = state::socket_path();
    if sock.as_os_str().len() > 100 {
        bail!("socket path {} is too long; set MAGICPIPES_SOCKET (or MAGICPIPES_HOME) to a shorter path", sock.display());
    }
    // We hold the lock, so any existing socket is stale.
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock).with_context(|| format!("binding {}", sock.display()))?;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
    state::write_private(&state::pid_path(), std::process::id().to_string().as_bytes())?;

    let shutdown = CancellationToken::new();
    let tunnels = tunnels::Tunnels::load()?;
    let tls = crate::https::tls_config(cfg.ca_cert_pem.as_deref())?;
    let session = session::Session::new(cfg, tunnels.clone())?;
    let agent = Agent::new(session.clone(), tunnels.clone(), tls, shutdown.clone());
    tracing::info!(pid = std::process::id(), tunnels = tunnels.len(), detached, "agent started");

    let session_task = tokio::spawn(session.clone().run(shutdown.clone()));
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let uid = unsafe { libc::getuid() };
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::signal::ctrl_c() => break,
            _ = term.recv() => break,
            conn = listener.accept() => {
                let Ok((stream, _)) = conn else { continue };
                // Defense in depth on top of the 0700 directory and 0600 socket.
                match stream.peer_cred() {
                    Ok(c) if c.uid() == uid => {}
                    Ok(c) => {
                        tracing::warn!(uid = c.uid(), "rejected IPC connection from another user");
                        continue;
                    }
                    // The peer already hung up (e.g. a CLI liveness check).
                    Err(_) => continue,
                }
                let agent = agent.clone();
                tokio::spawn(async move { handle_ipc(agent, stream).await });
            }
        }
    }
    tracing::info!("agent stopping");
    shutdown.cancel();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), session_task).await;
    Ok(())
}

async fn handle_ipc(agent: Arc<Agent>, stream: UnixStream) {
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r).take(ipc::MAX_LINE as u64);
    let mut line = String::new();
    if reader.read_line(&mut line).await.is_err() {
        return;
    }
    let req: IpcRequest = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            let _ = ipc::write_line(&mut w, &IpcEvent::Error(ErrorInfo::new("bad_request", e.to_string()))).await;
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
