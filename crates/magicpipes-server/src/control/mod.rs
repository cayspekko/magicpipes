//! Control plane: identities, the tunnel registry, agent sessions and certificate readiness.
//!
//! The registry is the single source of truth. Every mutation is validated here, persisted to
//! SQLite, and then published to the data plane as a fresh immutable [`RouteTable`]. The
//! management API, the UI and the agent gateway all call these typed methods directly.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use magicpipes_core::mux::MuxHandle;
use magicpipes_core::proto::{
    self, CertState, ErrorBody, Kind, RegisterTunnel, STREAM_LOCAL_UNREACHABLE, STREAM_OK, STREAM_UNKNOWN_TUNNEL, ServerOpen,
    TunnelInfo,
};
use magicpipes_core::{cidr, names, rfc3339, secret, unix_now};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::certs::{CertManager, CertStatus};
use crate::config::{Config, PortRange};
use crate::data::{DataPlane, Outcome, Route, RouteStats, RouteTable};
use crate::store::{Store, TunnelRow};

pub struct ControlPlane {
    cfg: Arc<Config>,
    store: Store,
    certs: Arc<CertManager>,
    data: Arc<DataPlane>,
    state: Mutex<State>,
    started_at: i64,
}

#[derive(Default)]
struct State {
    tunnels: HashMap<String, TunnelRecord>,
    sessions: HashMap<String, Session>,
    next_conn_id: u64,
}

struct TunnelRecord {
    row: TunnelRow,
    stats: Arc<RouteStats>,
}

struct Session {
    conn_id: u64,
    handle: MuxHandle,
    connected_at: i64,
    remote: SocketAddr,
    last_ping: Instant,
}

#[derive(Debug, Clone, Serialize)]
pub struct TunnelView {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub public_url: String,
    pub kind: Kind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_port: Option<u16>,
    /// Port tunnels: allowed client networks; empty = anyone.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    pub target: String,
    pub agent_id: String,
    /// `connected`, `disconnected` (agent offline) or `error` (local application unreachable,
    /// or the tunnel's port could not be opened).
    pub status: &'static str,
    /// Port tunnels: why the public port is not open.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_error: Option<String>,
    /// `ready`, `pending` or `failed`; `none` for port tunnels.
    pub tls: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_error: Option<String>,
    pub created_at: String,
    pub requests: u64,
    pub upstream_errors: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_request_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentView {
    pub id: String,
    pub name: String,
    pub connected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<String>,
    pub tunnels: usize,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusView {
    pub version: &'static str,
    pub base_domain: String,
    pub management_hostname: String,
    pub started_at: String,
    pub tunnels: usize,
    pub agents_connected: usize,
}

fn err(code: &str, msg: impl Into<String>) -> ErrorBody {
    ErrorBody::new(code, msg)
}

fn internal(e: anyhow::Error) -> ErrorBody {
    tracing::error!(error = %format!("{e:#}"), "control plane storage error");
    err("internal", "internal server error")
}

impl ControlPlane {
    pub fn new(cfg: Arc<Config>, store: Store, certs: Arc<CertManager>, data: Arc<DataPlane>) -> anyhow::Result<Arc<Self>> {
        let mut state = State::default();
        for row in store.tunnels()? {
            state.tunnels.insert(row.id.clone(), TunnelRecord { row, stats: Arc::default() });
        }
        let cp = Arc::new(Self { cfg, store, certs, data, state: Mutex::new(state), started_at: unix_now() });
        cp.publish(&cp.state.lock().unwrap());
        Ok(cp)
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Starts certificate provisioning for known hostnames and the stale-session reaper.
    pub fn start(self: &Arc<Self>, shutdown: CancellationToken) {
        let hosts: Vec<String> = self
            .state
            .lock()
            .unwrap()
            .tunnels
            .values()
            .filter(|t| t.row.kind.is_http())
            .map(|t| t.row.hostname.clone())
            .collect();
        for h in hosts {
            self.certs.ensure(&h);
        }
        let me = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tick.tick() => me.reap_sessions(),
                }
            }
        });
    }

    fn reap_sessions(&self) {
        let timeout = self.cfg.session_timeout();
        let st = self.state.lock().unwrap();
        for (agent, s) in &st.sessions {
            if s.last_ping.elapsed() > timeout || s.handle.is_closed() {
                tracing::info!(agent = %agent, "dropping unresponsive agent session");
                s.handle.close();
            }
        }
        // Detach happens in the gateway when the session task observes the close.
    }

    /// Builds the data-plane view from the registry. Must be called with the state lock held so
    /// concurrent mutations publish in order.
    fn publish(&self, st: &State) {
        let mut table = RouteTable::default();
        for t in st.tunnels.values() {
            let session = st.sessions.get(&t.row.agent_id).map(|s| s.handle.clone());
            // Stored lists were validated on registration. If one no longer parses, fail closed:
            // an empty list would mean "anyone".
            let allow = match cidr::parse_list(&t.row.allow) {
                Ok(allow) => allow,
                Err(e) => {
                    tracing::error!(tunnel = %t.row.name, error = %e, "unreadable allow-list; tunnel not published");
                    continue;
                }
            };
            let route = Arc::new(Route { tunnel_id: t.row.id.clone(), session, stats: t.stats.clone(), allow });
            match (t.row.kind, t.row.public_port) {
                (Kind::Http, _) => {
                    table.by_host.insert(t.row.hostname.clone(), route);
                }
                (kind, Some(port)) => {
                    table.by_port.insert((kind, port), route);
                }
                (_, None) => {}
            }
        }
        self.data.publish(table);
    }

    // ---- identities ------------------------------------------------------------------------

    pub fn verify_admin(&self, token: &str) -> bool {
        self.store.verify_admin_token(token).unwrap_or_else(|e| {
            tracing::error!(error = %e, "admin token check failed");
            false
        })
    }

    pub fn authenticate_agent(&self, token: &str) -> Option<String> {
        self.store.verify_agent_token(token).unwrap_or_else(|e| {
            tracing::error!(error = %e, "agent token check failed");
            None
        })
    }

    pub fn create_enrollment(&self) -> anyhow::Result<String> {
        self.store.create_enrollment(self.cfg.agents.enrollment_ttl_secs)
    }

    pub fn enroll(&self, req: &proto::EnrollRequest) -> Result<proto::EnrollResponse, ErrorBody> {
        let name: String = req.agent_name.chars().filter(|c| !c.is_control()).take(64).collect();
        let name = if name.trim().is_empty() { "agent".to_string() } else { name.trim().to_string() };
        match self.store.enroll(&req.enrollment_token, &name).map_err(internal)? {
            Some((agent_id, agent_token)) => {
                tracing::info!(agent = %agent_id, %name, "agent enrolled");
                Ok(proto::EnrollResponse { agent_id, agent_token, base_domain: self.cfg.base_domain.clone() })
            }
            None => Err(err("invalid_enrollment_token", "enrollment token is invalid, expired or already used")),
        }
    }

    /// Revokes an agent: its credential stops working, its tunnels are deleted (new requests get
    /// 404) and its live session, if any, is closed. Returns false if the agent is unknown.
    pub fn revoke_agent(&self, agent_id: &str) -> Result<bool, ErrorBody> {
        let mut st = self.state.lock().unwrap();
        if !self.store.delete_agent(agent_id).map_err(internal)? {
            return Ok(false);
        }
        st.tunnels.retain(|_, t| t.row.agent_id != agent_id);
        let session = st.sessions.remove(agent_id);
        self.publish(&st);
        drop(st);
        if let Some(s) = session {
            s.handle.close();
        }
        tracing::info!(agent = %agent_id, "agent revoked by administrator");
        Ok(true)
    }

    // ---- sessions --------------------------------------------------------------------------

    /// Attaches a freshly authenticated agent session. A previous session of the same agent is
    /// closed (the newest connection wins, e.g. after a network change). Returns `None` if the
    /// agent was revoked after it authenticated.
    pub fn attach_session(&self, agent_id: &str, handle: MuxHandle, remote: SocketAddr) -> Option<u64> {
        let mut st = self.state.lock().unwrap();
        // Checked under the state lock, which `revoke_agent` also holds while deleting.
        if !self.store.agent_exists(agent_id).unwrap_or(false) {
            return None;
        }
        st.next_conn_id += 1;
        let conn_id = st.next_conn_id;
        let session = Session { conn_id, handle, connected_at: unix_now(), remote, last_ping: Instant::now() };
        if let Some(old) = st.sessions.insert(agent_id.to_string(), session) {
            old.handle.close();
        }
        self.publish(&st);
        drop(st);
        let _ = self.store.touch_agent(agent_id);
        tracing::info!(agent = %agent_id, %remote, conn_id, "agent connected");
        Some(conn_id)
    }

    pub fn detach_session(&self, agent_id: &str, conn_id: u64) {
        let mut st = self.state.lock().unwrap();
        if st.sessions.get(agent_id).is_some_and(|s| s.conn_id == conn_id) {
            st.sessions.remove(agent_id);
            self.publish(&st);
            tracing::info!(agent = %agent_id, conn_id, "agent disconnected");
        }
    }

    pub fn touch(&self, agent_id: &str, conn_id: u64) {
        let mut st = self.state.lock().unwrap();
        if let Some(s) = st.sessions.get_mut(agent_id).filter(|s| s.conn_id == conn_id) {
            s.last_ping = Instant::now();
        }
    }

    // ---- tunnels ---------------------------------------------------------------------------

    pub fn register(&self, agent_id: &str, req: &RegisterTunnel) -> Result<TunnelInfo, ErrorBody> {
        let target: String = req.target.chars().filter(|c| !c.is_control()).take(200).collect();
        let allow: Vec<String> = cidr::parse_list(&req.allow)
            .map_err(|m| err("invalid_cidr", m))?
            .iter()
            .map(ToString::to_string)
            .collect();
        let range = match req.kind {
            Kind::Http if req.remote_port.is_some() || !allow.is_empty() => {
                return Err(err("invalid_request", "a remote port and an allow-list apply only to TCP and UDP tunnels"));
            }
            Kind::Http => None,
            _ => Some(self.cfg.port_range().ok_or_else(|| {
                err("ports_disabled", "this server does not offer TCP or UDP ports (its configuration has no [ports] range)")
            })?),
        };
        if let (Some(r), Some(p)) = (range, req.remote_port)
            && !r.contains(p)
        {
            return Err(err("port_unavailable", format!("port {p} is outside this server's port range {}-{}", r.first, r.last)));
        }
        let mut st = self.state.lock().unwrap();

        let existing = match (&req.id, &req.name) {
            (Some(id), _) => match st.tunnels.get(id) {
                Some(t) if t.row.agent_id == agent_id => Some(id.clone()),
                _ => return Err(err("not_found", "tunnel no longer exists on the server")),
            },
            (None, Some(name)) => {
                let name = names::validate(name).map_err(|m| err("invalid_name", m))?;
                match st.tunnels.values().find(|t| t.row.name == name) {
                    Some(t) if t.row.agent_id == agent_id => Some(t.row.id.clone()),
                    Some(_) => return Err(err("name_taken", format!("the name '{name}' is used by another agent"))),
                    None => None,
                }
            }
            (None, None) => None,
        };

        if let Some(id) = existing {
            let mut row = st.tunnels[&id].row.clone();
            if row.kind != req.kind {
                return Err(err(
                    "kind_mismatch",
                    format!("tunnel '{}' is a {} tunnel; remove it first to make it {}", row.name, row.kind, req.kind),
                ));
            }
            row.target = target;
            row.allow = allow;
            if let Some(p) = req.remote_port
                && row.public_port != Some(p)
            {
                row.public_port = Some(self.claim_port(&st, row.kind, p)?);
            }
            let t = st.tunnels.get_mut(&id).expect("checked above");
            if (&t.row.target, &t.row.allow, t.row.public_port) != (&row.target, &row.allow, row.public_port) {
                self.store.update_tunnel(&row).map_err(internal)?;
                t.row = row.clone();
                self.publish(&st);
            }
            if row.kind.is_http() {
                self.certs.ensure(&row.hostname);
            }
            return Ok(self.info(&row, false));
        }

        let owned = st.tunnels.values().filter(|t| t.row.agent_id == agent_id).count();
        if owned >= self.cfg.agents.max_tunnels_per_agent {
            return Err(err("limit_reached", format!("an agent may own at most {} tunnels", self.cfg.agents.max_tunnels_per_agent)));
        }

        let name = match &req.name {
            Some(n) => names::validate(n).map_err(|m| err("invalid_name", m))?,
            None => (0..10)
                .map(names::random)
                .find(|n| !st.tunnels.values().any(|t| &t.row.name == n))
                .ok_or_else(|| err("internal", "could not allocate a tunnel name"))?,
        };
        let hostname = self.cfg.hostname_for(&name);
        if hostname == self.cfg.management.hostname {
            return Err(err("invalid_name", format!("'{name}' is reserved")));
        }
        let public_port = match (range, req.remote_port) {
            (None, _) => None,
            (Some(_), Some(p)) => Some(self.claim_port(&st, req.kind, p)?),
            (Some(r), None) => Some(self.allocate_port(&st, req.kind, r)?),
        };
        let row = TunnelRow {
            id: secret::new_id("tn"),
            name,
            hostname,
            agent_id: agent_id.to_string(),
            target,
            created_at: unix_now(),
            kind: req.kind,
            public_port,
            allow,
        };
        self.store.insert_tunnel(&row).map_err(internal)?;
        st.tunnels.insert(row.id.clone(), TunnelRecord { row: row.clone(), stats: Arc::default() });
        self.publish(&st);
        drop(st);
        let info = self.info(&row, true);
        tracing::info!(tunnel = %row.id, url = %info.public_url, agent = %agent_id, "tunnel registered");
        if row.kind.is_http() {
            self.certs.ensure(&row.hostname);
        }
        Ok(info)
    }

    /// Takes a specific public port: free among this kind's tunnels and bindable on this host.
    fn claim_port(&self, st: &State, kind: Kind, port: u16) -> Result<u16, ErrorBody> {
        if let Some(t) = st.tunnels.values().find(|t| t.row.kind == kind && t.row.public_port == Some(port)) {
            return Err(err("port_unavailable", format!("{kind} port {port} is used by tunnel '{}'", t.row.name)));
        }
        self.data
            .bind_port(kind, port)
            .map_err(|e| err("port_unavailable", format!("cannot open {kind} port {port} on the server: {e}")))?;
        Ok(port)
    }

    /// Picks a free port from the range, starting at a random point.
    fn allocate_port(&self, st: &State, kind: Kind, range: PortRange) -> Result<u16, ErrorBody> {
        let start = secret::random_u64() as usize % range.len();
        let taken = |p: u16| st.tunnels.values().any(|t| t.row.kind == kind && t.row.public_port == Some(p));
        (0..range.len())
            .map(|i| range.first + ((start + i) % range.len()) as u16)
            .filter(|p| !taken(*p))
            // Skips ports another program on the server holds.
            .find(|p| self.data.bind_port(kind, *p).is_ok())
            .ok_or_else(|| err("limit_reached", format!("no free {kind} port left in {}-{}", range.first, range.last)))
    }

    fn public_url(&self, row: &TunnelRow) -> String {
        match (row.kind, row.public_port) {
            (Kind::Http, _) | (_, None) => self.cfg.public_url(&row.hostname),
            (kind, Some(port)) => self.cfg.port_url(kind, port),
        }
    }

    fn info(&self, row: &TunnelRow, created: bool) -> TunnelInfo {
        TunnelInfo {
            id: row.id.clone(),
            name: row.name.clone(),
            hostname: row.hostname.clone(),
            public_url: self.public_url(row),
            created,
            kind: row.kind,
            public_port: row.public_port,
        }
    }

    /// Readiness check for a port tunnel owned by `agent_id`: opens a data stream to the agent,
    /// as a client connection would, and reports whether the agent reached the local service.
    pub async fn check(&self, agent_id: &str, id: &str) -> Result<(), ErrorBody> {
        let (header, session) = {
            let st = self.state.lock().unwrap();
            let t = st.tunnels.get(id).filter(|t| t.row.agent_id == agent_id).ok_or_else(|| err("not_found", "unknown tunnel"))?;
            let tunnel_id = t.row.id.clone();
            let header = match t.row.kind {
                Kind::Udp => ServerOpen::Datagram { tunnel_id, peer: None },
                _ => ServerOpen::Data { tunnel_id, peer: None },
            };
            let session = st.sessions.get(agent_id).map(|s| s.handle.clone());
            (header, session.ok_or_else(|| err("agent_unavailable", "agent is not connected"))?)
        };
        let unavailable = |_| err("agent_unavailable", "could not open a stream to the agent");
        let mut stream = session.open(Duration::from_secs(10)).await.map_err(unavailable)?;
        let status = async {
            proto::write_frame(&mut stream, &header).await?;
            stream.read_u8().await
        };
        let status = tokio::time::timeout(Duration::from_secs(15), status).await;
        let _ = stream.shutdown().await;
        match status {
            Ok(Ok(STREAM_OK)) => Ok(()),
            Ok(Ok(STREAM_LOCAL_UNREACHABLE)) => Err(err("local_unreachable", "the agent could not connect to the local service")),
            Ok(Ok(STREAM_UNKNOWN_TUNNEL)) => Err(err("not_found", "the agent does not serve this tunnel")),
            _ => Err(err("agent_unavailable", "the agent did not answer the check")),
        }
    }

    /// Removes a tunnel on behalf of its owning agent.
    pub fn unregister(&self, agent_id: &str, id: &str) -> Result<(), ErrorBody> {
        let mut st = self.state.lock().unwrap();
        match st.tunnels.get(id) {
            Some(t) if t.row.agent_id == agent_id => {}
            _ => return Ok(()), // idempotent; never reveal other agents' tunnels
        }
        self.store.delete_tunnel(id).map_err(internal)?;
        st.tunnels.remove(id);
        self.publish(&st);
        tracing::info!(tunnel = %id, agent = %agent_id, "tunnel removed by agent");
        Ok(())
    }

    /// Removes a tunnel on behalf of an administrator and notifies the agent if connected.
    pub fn delete_tunnel(&self, id: &str) -> Result<bool, ErrorBody> {
        let mut st = self.state.lock().unwrap();
        let Some(t) = st.tunnels.get(id) else { return Ok(false) };
        let agent_id = t.row.agent_id.clone();
        self.store.delete_tunnel(id).map_err(internal)?;
        st.tunnels.remove(id);
        self.publish(&st);
        let session = st.sessions.get(&agent_id).map(|s| s.handle.clone());
        drop(st);
        tracing::info!(tunnel = %id, "tunnel deleted by administrator");
        if let Some(handle) = session {
            let tunnel_id = id.to_string();
            tokio::spawn(async move {
                if let Ok(mut s) = handle.open(Duration::from_secs(5)).await {
                    let _ = proto::write_frame(&mut s, &ServerOpen::TunnelRemoved { tunnel_id }).await;
                    let _ = tokio::io::AsyncWriteExt::shutdown(&mut s).await;
                }
            });
        }
        Ok(true)
    }

    /// Certificate readiness for a hostname owned by `agent_id`.
    pub async fn cert_status(&self, agent_id: &str, hostname: &str, wait: Duration) -> Result<CertState, ErrorBody> {
        let owned = self.state.lock().unwrap().tunnels.values().any(|t| t.row.agent_id == agent_id && t.row.hostname == hostname);
        if !owned {
            return Err(err("not_found", "unknown tunnel hostname"));
        }
        Ok(match self.certs.wait(hostname, wait.min(Duration::from_secs(300))).await {
            CertStatus::Ready => CertState::Ready,
            CertStatus::Pending => CertState::Pending,
            CertStatus::Failed(message) => CertState::Failed { message },
        })
    }

    // ---- views -----------------------------------------------------------------------------

    fn view(&self, st: &State, t: &TunnelRecord) -> TunnelView {
        let connected = st.sessions.get(&t.row.agent_id).is_some_and(|s| !s.handle.is_closed());
        let port_error = t.row.public_port.and_then(|p| self.data.bind_error(t.row.kind, p));
        let status = match (connected, t.stats.last_outcome()) {
            _ if port_error.is_some() => "error",
            (false, _) => "disconnected",
            (true, Outcome::LocalUnreachable) => "error",
            (true, _) => "connected",
        };
        let cert = if t.row.kind.is_http() { Some(self.certs.status(&t.row.hostname)) } else { None };
        let last = t.stats.last_request_at.load(std::sync::atomic::Ordering::Relaxed);
        TunnelView {
            id: t.row.id.clone(),
            name: t.row.name.clone(),
            hostname: t.row.hostname.clone(),
            public_url: self.public_url(&t.row),
            kind: t.row.kind,
            public_port: t.row.public_port,
            allow: t.row.allow.clone(),
            target: t.row.target.clone(),
            agent_id: t.row.agent_id.clone(),
            status,
            port_error,
            tls: cert.as_ref().map_or("none", CertStatus::label),
            tls_error: match cert {
                Some(CertStatus::Failed(m)) => Some(m),
                _ => None,
            },
            created_at: rfc3339(t.row.created_at),
            requests: t.stats.requests.load(std::sync::atomic::Ordering::Relaxed),
            upstream_errors: t.stats.upstream_errors.load(std::sync::atomic::Ordering::Relaxed),
            last_request_at: (last > 0).then(|| rfc3339(last)),
        }
    }

    pub fn tunnels(&self) -> Vec<TunnelView> {
        let st = self.state.lock().unwrap();
        let mut v: Vec<_> = st.tunnels.values().map(|t| self.view(&st, t)).collect();
        v.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.name.cmp(&b.name)));
        v
    }

    pub fn tunnel(&self, id_or_name: &str) -> Option<TunnelView> {
        let st = self.state.lock().unwrap();
        st.tunnels
            .values()
            .find(|t| t.row.id == id_or_name || t.row.name == id_or_name)
            .map(|t| self.view(&st, t))
    }

    pub fn agents(&self) -> Vec<AgentView> {
        let rows = self.store.agents().unwrap_or_default();
        let st = self.state.lock().unwrap();
        rows.into_iter()
            .map(|a| {
                let s = st.sessions.get(&a.id);
                AgentView {
                    connected: s.is_some(),
                    remote_addr: s.map(|s| s.remote.to_string()),
                    connected_at: s.map(|s| rfc3339(s.connected_at)),
                    last_seen_at: a.last_seen_at.map(rfc3339),
                    tunnels: st.tunnels.values().filter(|t| t.row.agent_id == a.id).count(),
                    created_at: rfc3339(a.created_at),
                    id: a.id,
                    name: a.name,
                }
            })
            .collect()
    }

    pub fn agent_name(&self, agent_id: &str) -> Option<String> {
        self.store.agents().ok()?.into_iter().find(|a| a.id == agent_id).map(|a| a.name)
    }

    pub fn status(&self) -> StatusView {
        let st = self.state.lock().unwrap();
        StatusView {
            version: magicpipes_core::VERSION,
            base_domain: self.cfg.base_domain.clone(),
            management_hostname: self.cfg.management.hostname.clone(),
            started_at: rfc3339(self.started_at),
            tunnels: st.tunnels.len(),
            agents_connected: st.sessions.len(),
        }
    }

    /// Closes all agent sessions (graceful shutdown).
    pub fn close_sessions(&self) {
        for s in self.state.lock().unwrap().sessions.values() {
            s.handle.close();
        }
    }
}
