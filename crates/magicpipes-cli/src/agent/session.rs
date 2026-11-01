//! Agent control path: keeps one authenticated session to the server, reconnects with
//! exponential backoff, restores registrations after every (re)connect and offers RPCs.

use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use bytes::Bytes;
use http::{Request, StatusCode, header};
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use magicpipes_core::error::ErrorCode;
use magicpipes_core::mux::{self, Mode, MuxHandle, MuxStream};
use magicpipes_core::proto::{
    self, AGENT_CONNECT_PATH, PROTOCOL_HEADER, PROTOCOL_VERSION, RegisterTunnel, Request as Rpc, Response as RpcResponse,
    UPGRADE_PROTOCOL,
};
use rustls::ClientConfig;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use super::forward;
use super::tunnels::{Registration, Tunnels};
use crate::https;
use crate::state::{AgentConfig, LocalTunnel};

const PING_INTERVAL: Duration = Duration::from_secs(15);
const PING_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub enum ConnState {
    Connecting { attempt: u32, last_error: Option<String> },
    /// `server_protocol`: the server's protocol version (`proto::PROTOCOL_VERSION`).
    Connected { handle: MuxHandle, since: i64, server_protocol: u32 },
    /// The server rejected our credentials; retried slowly in case of a transient server issue.
    Unauthorized(String),
}

pub struct Session {
    cfg: AgentConfig,
    tls: Arc<ClientConfig>,
    tunnels: Arc<Tunnels>,
    state: watch::Sender<ConnState>,
}

#[derive(Debug)]
pub enum RpcError {
    /// No usable session (with the reason).
    Unavailable(String),
    /// The server answered with an error.
    Server(proto::ErrorBody),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::Unavailable(m) => write!(f, "{m}"),
            RpcError::Server(e) => write!(f, "{} ({})", e.message, e.code),
        }
    }
}

impl Session {
    pub fn new(cfg: AgentConfig, tunnels: Arc<Tunnels>) -> anyhow::Result<Arc<Self>> {
        let tls = https::tls_config(cfg.ca_cert_pem.as_deref())?;
        let (state, _) = watch::channel(ConnState::Connecting { attempt: 0, last_error: None });
        Ok(Arc::new(Self { cfg, tls, tunnels, state }))
    }

    pub fn server(&self) -> &str {
        &self.cfg.server
    }

    pub fn state(&self) -> ConnState {
        self.state.borrow().clone()
    }

    /// Runs the connect/serve/reconnect loop until `shutdown`.
    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) {
        let mut attempt: u32 = 0;
        loop {
            let result = tokio::select! {
                _ = shutdown.cancelled() => return,
                r = self.connect() => r,
            };
            match result {
                Ok((handle, inbound, server_protocol)) => {
                    attempt = 0;
                    self.serve(handle, inbound, server_protocol, &shutdown).await;
                    if shutdown.is_cancelled() {
                        return;
                    }
                    tracing::warn!("disconnected from server; reconnecting");
                    self.tunnels.mark_all_pending();
                    self.state.send_replace(ConnState::Connecting { attempt: 0, last_error: Some("connection lost".into()) });
                }
                Err(ConnectError::Unauthorized(msg)) => {
                    tracing::error!(error = %msg, "server rejected agent credentials; run `magicpipes login` again");
                    self.state.send_replace(ConnState::Unauthorized(msg));
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                    }
                    continue;
                }
                Err(ConnectError::Other(e)) => {
                    attempt = attempt.saturating_add(1);
                    let msg = format!("{e:#}");
                    tracing::warn!(attempt, error = %msg, "could not connect to server");
                    self.state.send_replace(ConnState::Connecting { attempt, last_error: Some(msg) });
                }
            }
            let backoff = backoff(attempt);
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(backoff) => {}
            }
        }
    }

    async fn connect(&self) -> Result<(MuxHandle, mpsc::Receiver<MuxStream>, u32), ConnectError> {
        let (host, port) = https::parse_server(&self.cfg.server)?;
        let stream = https::connect(&host, port, &self.tls, None).await?;
        let req = Request::get(AGENT_CONNECT_PATH)
            .header(header::HOST, https::host_header(&host, port))
            .header(header::AUTHORIZATION, format!("Bearer {}", self.cfg.agent_token))
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, UPGRADE_PROTOCOL)
            .header(PROTOCOL_HEADER, PROTOCOL_VERSION)
            .header(header::USER_AGENT, concat!("magicpipes/", env!("CARGO_PKG_VERSION")))
            .body(Full::new(Bytes::new()))
            .map_err(|e| ConnectError::Other(e.into()))?;
        let resp = tokio::time::timeout(Duration::from_secs(15), https::send(stream, req))
            .await
            .map_err(|_| ConnectError::Other(anyhow!("server did not answer the connect request")))??;
        match resp.status() {
            StatusCode::SWITCHING_PROTOCOLS => {}
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                return Err(ConnectError::Unauthorized("agent credentials were rejected by the server".into()));
            }
            s => return Err(ConnectError::Other(anyhow!("unexpected response from server: {s}"))),
        }
        let server_protocol = proto::peer_protocol(resp.headers().get(PROTOCOL_HEADER).and_then(|v| v.to_str().ok()));
        let upgraded = hyper::upgrade::on(resp).await.map_err(|e| ConnectError::Other(e.into()))?;
        let (handle, inbound) = mux::spawn(TokioIo::new(upgraded), Mode::Client);
        Ok((handle, inbound, server_protocol))
    }

    async fn serve(
        self: &Arc<Self>,
        handle: MuxHandle,
        inbound: mpsc::Receiver<MuxStream>,
        server_protocol: u32,
        shutdown: &CancellationToken,
    ) {
        tracing::info!(server = %self.cfg.server, server_protocol, "connected to server");
        let since = magicpipes_core::unix_now();
        self.state.send_replace(ConnState::Connected { handle: handle.clone(), since, server_protocol });
        let fwd = tokio::spawn(forward::serve(inbound, self.tunnels.clone()));
        let me = self.clone();
        let restore = tokio::spawn(async move { me.restore().await });

        let mut ping = tokio::time::interval(PING_INTERVAL);
        ping.tick().await;
        // A ping that times out means the connection is gone. One that fails outright is
        // tolerated once: a busy session can briefly refuse a new stream.
        let mut failed = 0;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = handle.closed() => break,
                _ = ping.tick() => {
                    match tokio::time::timeout(PING_TIMEOUT, rpc_on(&handle, &Rpc::Ping)).await {
                        Ok(Ok(RpcResponse::Pong)) => failed = 0,
                        Err(_) => {
                            tracing::warn!("ping timed out");
                            break;
                        }
                        Ok(other) => {
                            failed += 1;
                            tracing::warn!(result = ?other.map(|_| ()), failed, "ping failed");
                            if failed >= 2 {
                                break;
                            }
                        }
                    }
                }
            }
        }
        handle.close();
        restore.abort();
        fwd.abort();
    }

    /// Re-registers every local tunnel on a new session (idempotent on the server).
    async fn restore(&self) {
        for t in self.tunnels.list() {
            let req = RegisterTunnel {
                id: Some(t.id.clone()),
                name: Some(t.name.clone()),
                target: t.server_description(),
                kind: t.kind,
                // Keeps the port if the server had to recreate the tunnel (e.g. a restored backup).
                remote_port: t.public_port,
                allow: t.allow.clone(),
            };
            match self.rpc(&Rpc::Register(req), Duration::from_secs(15)).await {
                Ok(RpcResponse::Tunnel(info)) => {
                    tracing::info!(tunnel = %t.name, "tunnel restored");
                    let updated = LocalTunnel {
                        public_url: info.public_url,
                        hostname: info.hostname,
                        name: info.name,
                        public_port: info.public_port.or(t.public_port),
                        ..t
                    };
                    self.tunnels.upsert(updated, Registration::Registered);
                }
                Err(RpcError::Server(e)) if e.is(ErrorCode::NotFound) => {
                    tracing::warn!(tunnel = %t.name, "tunnel no longer exists on the server; removing it locally");
                    self.tunnels.remove(&t.id);
                }
                Err(e) => {
                    tracing::warn!(tunnel = %t.name, error = %e, "could not restore tunnel");
                    self.tunnels.set_registration(&t.id, Registration::Failed, Some(e.to_string()));
                }
                Ok(other) => tracing::warn!(?other, "unexpected response to register"),
            }
        }
    }

    /// Waits until a session is established (or `timeout` passes).
    pub async fn wait_connected(&self, timeout: Duration) -> Result<MuxHandle, String> {
        let mut rx = self.state.subscribe();
        let res = tokio::time::timeout(timeout, async {
            loop {
                match &*rx.borrow_and_update() {
                    ConnState::Connected { handle, .. } if !handle.is_closed() => return Ok(handle.clone()),
                    ConnState::Unauthorized(m) => return Err(m.clone()),
                    _ => {}
                }
                if rx.changed().await.is_err() {
                    return Err("agent is shutting down".to_string());
                }
            }
        })
        .await;
        match res {
            Ok(r) => r,
            Err(_) => Err(match &*self.state.borrow() {
                ConnState::Connecting { last_error: Some(e), .. } => format!("could not connect to {}: {e}", self.cfg.server),
                _ => format!("timed out connecting to {}", self.cfg.server),
            }),
        }
    }

    pub async fn rpc(&self, req: &Rpc, timeout: Duration) -> Result<RpcResponse, RpcError> {
        let handle = match &*self.state.borrow() {
            ConnState::Connected { handle, .. } if !handle.is_closed() => handle.clone(),
            _ => return Err(RpcError::Unavailable("not connected to the server".into())),
        };
        match tokio::time::timeout(timeout, rpc_on(&handle, req)).await {
            Ok(Ok(RpcResponse::Error(e))) => Err(RpcError::Server(e)),
            Ok(Ok(r)) => Ok(r),
            Ok(Err(e)) => Err(RpcError::Unavailable(format!("request to server failed: {e}"))),
            Err(_) => Err(RpcError::Unavailable("request to server timed out".into())),
        }
    }
}

async fn rpc_on(handle: &MuxHandle, req: &Rpc) -> anyhow::Result<RpcResponse> {
    let mut stream = handle.open(Duration::from_secs(10)).await?;
    proto::write_frame(&mut stream, req).await?;
    let resp = proto::read_frame(&mut stream).await?;
    let _ = stream.shutdown().await;
    Ok(resp)
}

enum ConnectError {
    Unauthorized(String),
    Other(anyhow::Error),
}

impl From<anyhow::Error> for ConnectError {
    fn from(e: anyhow::Error) -> Self {
        ConnectError::Other(e)
    }
}

fn backoff(attempt: u32) -> Duration {
    if attempt == 0 {
        return Duration::from_millis(200);
    }
    let base = Duration::from_millis(500).saturating_mul(1 << attempt.min(6)).min(MAX_BACKOFF);
    // +-20% jitter so many agents don't reconnect in lockstep after a server restart.
    let jitter = (magicpipes_core::secret::random_u64() % 400) as i64 - 200;
    let ms = (base.as_millis() as i64 * (1000 + jitter) / 1000).max(100) as u64;
    Duration::from_millis(ms)
}
