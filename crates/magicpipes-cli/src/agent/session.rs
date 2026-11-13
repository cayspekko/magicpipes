//! Agent control path: keeps authenticated sessions to the server, reconnects with exponential
//! backoff, restores registrations after every reconnect and offers RPCs.
//!
//! The agent holds several connections ("lanes", [`DEFAULT_CONNECTIONS`] unless configured), each a
//! session of its own: the server spreads streams across them, and losing one leaves the others
//! serving while it reconnects. They're equal: any carries RPCs, each pings and reconnects by itself.
//! Only the first connects before the server is known to keep an agent's connections together
//! (protocol 9); an older one would let each new connection replace the last.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::anyhow;
use bytes::Bytes;
use http::{Request, StatusCode, header};
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use magicpipes_core::error::ErrorCode;
use magicpipes_core::mux::{self, Mode, MuxHandle, MuxStream};
use magicpipes_core::proto::{
    self, AGENT_CONNECT_PATH, CONNECTIONS_PROTOCOL, INSTANCE_HEADER, MAX_CONNECTIONS, PROTOCOL_HEADER, PROTOCOL_VERSION, RegisterTunnel,
    Request as Rpc, Response as RpcResponse, UPGRADE_PROTOCOL, Visibility,
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
/// A session that lasted this long resets the reconnect backoff; a shorter one (the server closing
/// it at once, say, or another machine with the same credentials) keeps it growing.
const STABLE_SESSION: Duration = Duration::from_secs(30);
/// Connections held to a server that keeps them together, unless `MAGICPIPES_CONNECTIONS` or
/// `connections` in config.json says otherwise.
pub const DEFAULT_CONNECTIONS: usize = 4;

/// Whether lane `lane` may connect, given the protocol of the server the latest connection reached
/// (0 before any): the first always may; the others only to a server that keeps an agent's
/// connections together, since an older one lets each new connection replace the last.
fn may_connect(lane: usize, reached: u32) -> bool {
    lane == 0 || reached >= CONNECTIONS_PROTOCOL
}

/// How many connections to hold: the environment's choice, else the configuration's, else the
/// default; always between 1 and [`MAX_CONNECTIONS`].
pub fn connections_wanted(configured: Option<u8>, env: Option<&str>) -> usize {
    let asked = env.and_then(|v| v.trim().parse::<usize>().ok()).or(configured.map(usize::from)).unwrap_or(DEFAULT_CONNECTIONS);
    asked.clamp(1, MAX_CONNECTIONS)
}

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
    /// Held while registering a tunnel (`add`, and restoring after a reconnect), so the two never
    /// interleave and an older copy of a tunnel's settings can't overwrite a newer one.
    pub register_lock: tokio::sync::Mutex<()>,
    /// Sent on every connection, so the server keeps this run's together: random per run.
    instance: String,
    /// The open connection of each lane.
    lanes: Mutex<Vec<Option<MuxHandle>>>,
    /// The protocol of the server the latest connection reached (0 before any): lanes past the
    /// first wait for one that keeps connections together.
    reached: watch::Sender<u32>,
    /// Re-registering the tunnels after the agent was offline; stopped if it goes offline again.
    restoring: Mutex<Option<tokio::task::JoinHandle<()>>>,
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
        let wanted = connections_wanted(cfg.connections, std::env::var("MAGICPIPES_CONNECTIONS").ok().as_deref());
        Ok(Arc::new(Self {
            cfg,
            tls,
            tunnels,
            state,
            register_lock: tokio::sync::Mutex::new(()),
            instance: magicpipes_core::secret::random_string(24),
            lanes: Mutex::new(vec![None; wanted]),
            reached: watch::Sender::new(0),
            restoring: Mutex::new(None),
        }))
    }

    /// How many connections to the server are open now.
    pub fn connections(&self) -> usize {
        self.lanes.lock().unwrap_or_else(|e| e.into_inner()).iter().flatten().filter(|h| !h.is_closed()).count()
    }

    pub fn server(&self) -> &str {
        &self.cfg.server
    }

    pub fn state(&self) -> ConnState {
        self.state.borrow().clone()
    }

    /// The connected server's protocol version.
    pub fn server_protocol(&self) -> Option<u32> {
        match &*self.state.borrow() {
            ConnState::Connected { server_protocol, .. } => Some(*server_protocol),
            _ => None,
        }
    }

    /// Runs every lane's connect/serve/reconnect loop until `shutdown`.
    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) {
        let wanted = self.lanes.lock().unwrap_or_else(|e| e.into_inner()).len();
        let mut lanes = tokio::task::JoinSet::new();
        for lane in 0..wanted {
            lanes.spawn(self.clone().lane(lane, shutdown.clone()));
        }
        while lanes.join_next().await.is_some() {}
    }

    /// One connection, kept until `shutdown`, with its own backoff. Past the first, it connects
    /// only to a server known to keep an agent's connections together, and gives up on one that
    /// has no room for more.
    async fn lane(self: Arc<Self>, lane: usize, shutdown: CancellationToken) {
        let mut attempt: u32 = 0;
        loop {
            if lane > 0 && !self.server_keeps_connections(&shutdown).await {
                return;
            }
            let result = tokio::select! {
                _ = shutdown.cancelled() => return,
                r = self.connect() => r,
            };
            match result {
                Ok((handle, inbound, server_protocol)) => {
                    self.reached.send_replace(server_protocol);
                    if !may_connect(lane, server_protocol) {
                        // The server changed under us: an older one would drop the others for this.
                        handle.close();
                        continue;
                    }
                    let started = std::time::Instant::now();
                    self.serve(lane, handle, inbound, server_protocol, &shutdown).await;
                    if shutdown.is_cancelled() {
                        return;
                    }
                    attempt = if started.elapsed() >= STABLE_SESSION { 0 } else { attempt.saturating_add(1) };
                    tracing::warn!(lane, attempt, "connection to the server lost; reconnecting");
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
                Err(ConnectError::Full) => {
                    tracing::info!(lane, "the server has no room for another connection of this agent's; going on with fewer");
                    return;
                }
                Err(ConnectError::Other(e)) => {
                    attempt = attempt.saturating_add(1);
                    let msg = format!("{e:#}");
                    tracing::warn!(lane, attempt, error = %msg, "could not connect to server");
                    if self.connections() == 0 {
                        self.state.send_replace(ConnState::Connecting { attempt, last_error: Some(msg) });
                    }
                }
            }
            let backoff = backoff(attempt);
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(backoff) => {}
            }
        }
    }

    /// Waits until a connection has reached a server that keeps an agent's connections together;
    /// `false` at shutdown.
    async fn server_keeps_connections(&self, shutdown: &CancellationToken) -> bool {
        let mut reached = self.reached.subscribe();
        tokio::select! {
            _ = shutdown.cancelled() => false,
            r = reached.wait_for(|v| may_connect(1, *v)) => r.is_ok(),
        }
    }

    /// A lane's connection is up: the agent is connected now, if it wasn't. `true` when this is
    /// the first of its connections to be up.
    fn up(&self, lane: usize, handle: &MuxHandle, server_protocol: u32) -> bool {
        let mut lanes = self.lanes.lock().unwrap_or_else(|e| e.into_inner());
        let first = lanes.iter().flatten().all(|h| h.is_closed());
        lanes[lane] = Some(handle.clone());
        if first {
            self.state.send_replace(ConnState::Connected { handle: handle.clone(), since: magicpipes_core::unix_now(), server_protocol });
        }
        first
    }

    /// A lane's connection is gone. While others are open, RPCs move to one of them; with none
    /// left, the agent is offline until one comes back.
    fn down(&self, lane: usize, handle: &MuxHandle) {
        let mut lanes = self.lanes.lock().unwrap_or_else(|e| e.into_inner());
        lanes[lane] = None;
        match lanes.iter().flatten().find(|h| !h.is_closed()).cloned() {
            Some(open) => {
                self.state.send_if_modified(|s| match s {
                    ConnState::Connected { handle: h, .. } if h.same_session(handle) => {
                        *h = open;
                        true
                    }
                    _ => false,
                });
            }
            None => {
                if let Some(restoring) = self.restoring.lock().unwrap_or_else(|e| e.into_inner()).take() {
                    restoring.abort();
                }
                self.tunnels.mark_all_pending();
                self.state.send_replace(ConnState::Connecting { attempt: 0, last_error: Some("connection lost".into()) });
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
            .header(INSTANCE_HEADER, &self.instance)
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
            StatusCode::CONFLICT => return Err(ConnectError::Full),
            s => return Err(ConnectError::Other(anyhow!("unexpected response from server: {s}"))),
        }
        let server_protocol = proto::peer_protocol(resp.headers().get(PROTOCOL_HEADER).and_then(|v| v.to_str().ok()));
        let upgraded = hyper::upgrade::on(resp).await.map_err(|e| ConnectError::Other(e.into()))?;
        let (handle, inbound) = mux::spawn(TokioIo::new(upgraded), Mode::Client);
        Ok((handle, inbound, server_protocol))
    }

    async fn serve(
        self: &Arc<Self>,
        lane: usize,
        handle: MuxHandle,
        inbound: mpsc::Receiver<MuxStream>,
        server_protocol: u32,
        shutdown: &CancellationToken,
    ) {
        if self.up(lane, &handle, server_protocol) {
            tracing::info!(server = %self.cfg.server, server_protocol, "connected to server");
            // Back from offline: the server may have lost track of the tunnels meanwhile.
            let me = self.clone();
            let restore = tokio::spawn(async move { me.restore().await });
            if let Some(old) = self.restoring.lock().unwrap_or_else(|e| e.into_inner()).replace(restore) {
                old.abort();
            }
        } else {
            tracing::debug!(lane, "another connection to the server");
        }
        let fwd = tokio::spawn(forward::serve(inbound, self.tunnels.clone(), server_protocol));

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
        fwd.abort();
        self.down(lane, &handle);
    }

    /// Re-registers every local tunnel on a new session (idempotent on the server). Each one is
    /// read again under `register_lock`, so an `add` that changed it meanwhile wins.
    async fn restore(&self) {
        for id in self.tunnels.list().into_iter().map(|t| t.id) {
            let _lock = self.register_lock.lock().await;
            let Some(t) = self.tunnels.find(|t| t.id == id) else { continue };
            let req = RegisterTunnel {
                id: Some(t.id.clone()),
                name: Some(t.name.clone()),
                target: t.server_description(),
                kind: t.kind,
                // Keeps the port if the server had to recreate the tunnel (e.g. a restored backup).
                remote_port: t.public_port,
                allow: t.allow.clone(),
                // The server keeps the tunnel's stored visibility and tags. Sending
                // ours would replay tags an administrator may have deleted since.
                visibility: None,
                tags: Vec::new(),
                // If the server lost the tunnel, it comes back at the same custom hostname.
                hostname: t.custom_hostname.then(|| t.hostname.clone()),
                // The server keeps whether it checks the tunnel, and how.
                checks: None,
                check_path: None,
            };
            match self.rpc(&Rpc::Register(req), Duration::from_secs(15)).await {
                // Never let a private tunnel come back public (e.g. after a server downgrade).
                // Never serve something other than what was added: a private tunnel the server made
                // public (after a server downgrade), or a raw port it made an HTTPS hostname. The
                // agent stops serving it even if removing it on the server fails.
                Ok(RpcResponse::Tunnel(info)) if t.visibility == Some(Visibility::Private) && info.visibility != Some(Visibility::Private) => {
                    tracing::error!(tunnel = %t.name, "the server did not keep the tunnel private; no longer serving it");
                    self.tunnels.withdraw(&t.id, "the server no longer supports private tunnels".into());
                    if let Err(e) = self.rpc(&Rpc::Unregister { id: info.id }, Duration::from_secs(10)).await {
                        tracing::warn!(tunnel = %t.name, error = %e, "could not remove the tunnel on the server");
                    }
                }
                Ok(RpcResponse::Tunnel(info)) if t.custom_hostname && info.hostname != t.hostname => {
                    tracing::error!(tunnel = %t.name, hostname = %t.hostname, "the server did not keep the tunnel's hostname; no longer serving it");
                    self.tunnels.withdraw(&t.id, format!("the server no longer serves {}", t.hostname));
                    if let Err(e) = self.rpc(&Rpc::Unregister { id: info.id }, Duration::from_secs(10)).await {
                        tracing::warn!(tunnel = %t.name, error = %e, "could not remove the tunnel on the server");
                    }
                }
                Ok(RpcResponse::Tunnel(info)) if info.kind != t.kind => {
                    tracing::error!(tunnel = %t.name, kind = %t.kind, "the server registered the tunnel as another kind; no longer serving it");
                    self.tunnels.withdraw(&t.id, format!("the server no longer supports {} tunnels", t.kind));
                    if let Err(e) = self.rpc(&Rpc::Unregister { id: info.id }, Duration::from_secs(10)).await {
                        tracing::warn!(tunnel = %t.name, error = %e, "could not remove the tunnel on the server");
                    }
                }
                Ok(RpcResponse::Tunnel(info)) => {
                    tracing::info!(tunnel = %t.name, "tunnel restored");
                    let updated = LocalTunnel {
                        public_url: info.public_url,
                        hostname: info.hostname,
                        name: info.name,
                        public_port: info.public_port.or(t.public_port),
                        visibility: info.visibility,
                        tags: info.tags,
                        access: info.access,
                        owner_tag: info.owner_tag,
                        replicas: info.replicas,
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
    /// The server has no room for another connection of this agent's.
    Full,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_connection_until_the_server_keeps_them_together() {
        assert!(may_connect(0, 0), "the first finds out what the server is");
        assert!(!may_connect(1, 0) && !may_connect(3, CONNECTIONS_PROTOCOL - 1), "an older server would drop the others");
        assert!(may_connect(1, CONNECTIONS_PROTOCOL) && may_connect(7, CONNECTIONS_PROTOCOL + 1));
    }

    #[test]
    fn connections_come_from_the_environment_then_the_configuration() {
        assert_eq!(connections_wanted(None, None), DEFAULT_CONNECTIONS);
        assert_eq!(connections_wanted(Some(2), None), 2);
        assert_eq!(connections_wanted(Some(2), Some("6")), 6, "the environment wins, for containers");
        assert_eq!(connections_wanted(Some(3), Some("lots")), 3, "an unreadable value is ignored");
        assert_eq!((connections_wanted(Some(0), None), connections_wanted(None, Some("99"))), (1, MAX_CONNECTIONS), "kept within bounds");
    }
}
