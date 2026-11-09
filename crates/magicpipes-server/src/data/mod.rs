//! Data plane: public ingress, hostname and port routing, and forwarding over agent sessions.
//!
//! The data plane only reads an immutable [`RouteTable`] snapshot that the control plane
//! replaces wholesale via [`DataPlane::publish`]. A lookup is one read-lock acquisition to clone
//! an `Arc`, so management activity (database writes, UI rendering, certificate orders) never
//! blocks proxied traffic, and no request touches the database. Publishing also binds and
//! unbinds the listeners of port tunnels ([`ports`]) to match the table.
//!
//! Route removal lifecycle: once a new table without a hostname is published, *new* requests
//! for it get 404. Requests already in flight keep their own stream and run to completion.
//! WebSockets and port connections are long-lived, so they are checked again on every publish, and
//! closed once the tunnel is gone or no longer admits them.

pub mod connect;
mod gate;
pub mod ingress;
mod io;
mod pool;
mod ports;
mod proxy;
pub mod ssh;
pub mod terminal;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;

use magicpipes_core::cidr::{self, Cidr};
use magicpipes_core::mux::{MuxHandle, MuxStream};
use magicpipes_core::proto::Kind;
use tokio::sync::{Semaphore, mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::authz::{self, Action, Principal, Resource, TunnelAuthz};
use crate::config::Config;
use crate::forwarded::TrustedProxies;
use crate::tunnel_auth::Signer;
pub use ports::PortSettings;

/// One routable hostname or public port.
#[derive(Debug)]
pub struct Route {
    pub tunnel_id: String,
    /// `None` while the owning agent is disconnected.
    pub session: Option<MuxHandle>,
    pub stats: Arc<RouteStats>,
    pub access: AccessPolicy,
    /// Changes with the tunnel's settings, which retires its pooled connections.
    pub version: u64,
    /// SSH tunnels: the host key its sshd showed the browser terminal first, if any yet.
    pub ssh_host_key: Option<String>,
}

/// Who may use a route: the client's network first, then [`authz::authorize`]. The one check
/// for HTTP requests, TCP connections and UDP flows.
#[derive(Debug)]
pub struct AccessPolicy {
    /// Client networks allowed to connect (empty = anyone). Port tunnels only, for now.
    pub allow: Vec<Cidr>,
    pub authz: TunnelAuthz,
}

impl AccessPolicy {
    /// The network check alone, which comes first for everyone.
    pub fn allows_network(&self, ip: IpAddr) -> bool {
        cidr::allowed(&self.allow, ip)
    }

    /// Whether `who`, connecting from `ip`, may reach the tunnel.
    pub fn admits(&self, who: &Principal, ip: IpAddr) -> bool {
        self.allows_network(ip) && authz::authorize(who, Action::Connect, Resource::Tunnel(&self.authz))
    }
}

/// Counters written by the data plane and read by the control plane for status display.
#[derive(Debug, Default)]
pub struct RouteStats {
    pub requests: AtomicU64,
    pub upstream_errors: AtomicU64,
    last_outcome: AtomicU8,
    pub last_request_at: AtomicI64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    None,
    Ok,
    LocalUnreachable,
    AgentOffline,
}

impl RouteStats {
    fn record(&self, outcome: Outcome) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        if outcome != Outcome::Ok {
            self.upstream_errors.fetch_add(1, Ordering::Relaxed);
        }
        self.last_outcome.store(outcome as u8, Ordering::Relaxed);
        self.last_request_at.store(magicpipes_core::unix_now(), Ordering::Relaxed);
    }

    pub fn last_outcome(&self) -> Outcome {
        match self.last_outcome.load(Ordering::Relaxed) {
            1 => Outcome::Ok,
            2 => Outcome::LocalUnreachable,
            3 => Outcome::AgentOffline,
            _ => Outcome::None,
        }
    }
}

#[derive(Debug, Default)]
pub struct RouteTable {
    pub by_host: HashMap<String, Arc<Route>>,
    /// Port tunnels, by protocol and public port.
    pub by_port: HashMap<(Kind, u16), Arc<Route>>,
    /// SSH tunnels, by name.
    pub by_ssh: HashMap<String, Arc<Route>>,
    /// Private TCP and UDP tunnels, which `magicpipes connect` reaches, by name.
    pub by_connect: HashMap<String, (Kind, Arc<Route>)>,
    /// Active users, by id, for private tunnels: who a tunnel cookie stands for now.
    pub users: HashMap<String, TunnelUser>,
    /// Public keys for the SSH gateway, by SHA-256 fingerprint.
    pub ssh_keys: HashMap<String, GatewayKey>,
}

/// A public key the SSH gateway knows, and whose it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayKey {
    pub id: String,
    pub user_id: String,
}

/// A user as private tunnels see them: current role and tags, and the time before which their
/// cookies no longer count ("sign out everywhere", password changes).
#[derive(Debug, Clone)]
pub struct TunnelUser {
    pub email: String,
    pub principal: Principal,
    pub valid_after: i64,
}

#[derive(Clone)]
pub struct ProxySettings {
    pub upstream_response_timeout: Duration,
    pub websocket_idle_timeout: Duration,
    pub stream_open_timeout: Duration,
    pub ports: PortSettings,
    /// Names under this domain mean the same to the SSH gateway as the bare name.
    pub base_domain: String,
    /// Where people reach the SSH gateway (`Config::ssh_address`).
    pub ssh_address: Option<String>,
    pub trusted_proxies: TrustedProxies,
    /// Where private tunnels send browsers to sign in, e.g. `https://example.com:8443`.
    pub management_url: String,
    /// The management hostname, which connect passes are bound to.
    pub management_host: String,
    /// How long a private tunnel's cookie lasts.
    pub tunnel_cookie_ttl_secs: i64,
    /// Hostnames an application's cookies may not reach (`public.allow_cookie_domain`): everything
    /// under the base domain, and the management host.
    pub shared_domains: Vec<String>,
    /// What an authenticating proxy may have added, which is no application's business.
    pub identity_headers: Vec<http::HeaderName>,
    pub signer: Signer,
}

impl ProxySettings {
    pub fn from_config(cfg: &Config, signer: Signer) -> Self {
        let management_url = match cfg.management.listen.port() {
            443 => format!("https://{}", cfg.management.hostname),
            port => format!("https://{}:{port}", cfg.management.hostname),
        };
        Self {
            management_url,
            management_host: cfg.management.hostname.clone(),
            tunnel_cookie_ttl_secs: cfg.users.session_max_age_secs as i64,
            shared_domains: if cfg.public.allow_cookie_domain { Vec::new() } else { vec![cfg.base_domain.clone(), cfg.management.hostname.clone()] },
            identity_headers: cfg.proxy_auth.as_ref().map(|p| p.identity_headers()).unwrap_or_default(),
            signer,
            upstream_response_timeout: Duration::from_secs(cfg.public.upstream_response_timeout_secs),
            websocket_idle_timeout: Duration::from_secs(cfg.public.websocket_idle_timeout_secs),
            stream_open_timeout: Duration::from_secs(10),
            ports: PortSettings::from_config(&cfg.ports),
            base_domain: cfg.base_domain.clone(),
            ssh_address: cfg.ssh_address(),
            trusted_proxies: cfg.trusted_proxies(),
        }
    }
}

pub struct DataPlane {
    routes: RwLock<Arc<RouteTable>>,
    settings: ProxySettings,
    /// Bound port listeners; cancelling a token closes that listener.
    listeners: Mutex<HashMap<(Kind, u16), CancellationToken>>,
    /// Ports in the route table that could not be bound, with the reason.
    bind_errors: Mutex<HashMap<(Kind, u16), String>>,
    tcp_permits: Arc<Semaphore>,
    /// Cancelled at shutdown: closes every port listener.
    shutdown: CancellationToken,
    me: Weak<DataPlane>,
    /// Bumped on every publish, so long-lived connections to private tunnels recheck access.
    generation: watch::Sender<u64>,
    /// Nonces of sign-in codes already used, per user, with when they were seen (bounded per
    /// user and in total, 65 s each).
    used_codes: Mutex<HashMap<String, HashMap<String, std::time::Instant>>>,
    /// Idle HTTP connections to agents, for the next request to the same tunnel.
    pool: pool::Pool<proxy::Progress<hyper::body::Incoming>>,
    /// The threads that carry traffic. `None` only in unit tests without a runtime.
    traffic: Option<tokio::runtime::Handle>,
    /// What the SSH gateway reports to the control plane, which is free to write it down. Traffic
    /// doesn't wait for this: when it's full, reports are dropped.
    ssh_reports: mpsc::Sender<ssh::Report>,
    ssh_reports_rx: Mutex<Option<mpsc::Receiver<ssh::Report>>>,
    /// The fingerprint of the SSH gateway's host key, once it has one.
    ssh_fingerprint: std::sync::OnceLock<String>,
    /// The SSH certificate authority browser terminals log in with, when the gateway is on.
    ssh_ca: std::sync::OnceLock<Arc<russh::keys::PrivateKey>>,
    terminals: terminal::Limits,
    /// `magicpipes connect` connections per person.
    connections: connect::Limits,
}

impl DataPlane {
    /// Call on the threads that are to carry traffic.
    pub fn new(settings: ProxySettings, shutdown: CancellationToken) -> Arc<Self> {
        let traffic = tokio::runtime::Handle::try_current().ok();
        let (ssh_reports, ssh_reports_rx) = mpsc::channel(ssh::REPORT_QUEUE);
        let dp = Arc::new_cyclic(|me| Self {
            routes: RwLock::new(Arc::new(RouteTable::default())),
            tcp_permits: Arc::new(Semaphore::new(settings.ports.max_connections)),
            settings,
            listeners: Mutex::default(),
            bind_errors: Mutex::default(),
            shutdown,
            me: me.clone(),
            generation: watch::Sender::new(0),
            used_codes: Mutex::default(),
            pool: pool::Pool::default(),
            traffic,
            ssh_reports,
            ssh_reports_rx: Mutex::new(Some(ssh_reports_rx)),
            ssh_fingerprint: std::sync::OnceLock::new(),
            ssh_ca: std::sync::OnceLock::new(),
            terminals: terminal::Limits::default(),
            connections: connect::Limits::default(),
        });
        // Closes idle pooled connections that timed out, until shutdown. (Without a runtime, in
        // unit tests, nothing is pooled anyway.)
        if let Some(rt) = &dp.traffic {
            let (me, stop) = (Arc::downgrade(&dp), dp.shutdown.clone());
            rt.spawn(async move {
                let mut tick = tokio::time::interval(pool::IDLE_TIMEOUT / 2);
                loop {
                    tokio::select! {
                        _ = stop.cancelled() => return,
                        _ = tick.tick() => match me.upgrade() {
                            Some(dp) => dp.pool.sweep(),
                            None => return,
                        },
                    }
                }
            });
        }
        dp
    }

    /// The SSH gateway's reports, for the control plane; `None` after the first call.
    pub fn take_ssh_reports(&self) -> Option<mpsc::Receiver<ssh::Report>> {
        self.ssh_reports_rx.lock().unwrap_or_else(|e| e.into_inner()).take()
    }

    /// Gives browser terminals their certificate authority (at startup, with the gateway).
    pub fn set_ssh_ca(&self, ca: russh::keys::PrivateKey) {
        let _ = self.ssh_ca.set(Arc::new(ca));
    }

    /// The certificate authority's public key, as a line for sshd (`TrustedUserCAKeys`).
    pub fn ssh_ca_public(&self) -> Option<String> {
        self.ssh_ca.get()?.public_key().to_openssh().ok()
    }

    /// The fingerprint of the SSH gateway's host key; `None` unless it's on.
    pub fn ssh_fingerprint(&self) -> Option<&str> {
        self.ssh_fingerprint.get().map(String::as_str)
    }

    pub fn signer(&self) -> &Signer {
        &self.settings.signer
    }

    /// Runs `f` so that what it spawns or binds belongs to the traffic threads, wherever this is
    /// called from: the control plane opens ports and starts agents' sessions.
    pub fn on_traffic_threads<T>(&self, f: impl FnOnce() -> T) -> T {
        let _traffic = self.traffic.as_ref().map(tokio::runtime::Handle::enter);
        f()
    }

    fn table(&self) -> Arc<RouteTable> {
        self.routes.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Marks a sign-in code's nonce as used; false if it was already. Kept per user, so one
    /// account signing in over and over can only use up its own share.
    fn use_code(&self, user_id: &str, nonce: &str) -> bool {
        // More sign-ins than this within a code's lifetime is a script, not a person.
        const PER_USER: usize = 32;
        // Codes are signed for real users, so this bounds memory, not who may sign in.
        const MAX_USERS: usize = 10_000;
        let mut used = self.used_codes.lock().unwrap_or_else(|e| e.into_inner());
        let ttl = Duration::from_secs(crate::tunnel_auth::CODE_TTL_SECS as u64 + 5);
        if !used.contains_key(user_id) && used.len() >= MAX_USERS {
            used.retain(|_, codes| {
                codes.retain(|_, at| at.elapsed() < ttl);
                !codes.is_empty()
            });
            if used.len() >= MAX_USERS {
                return false;
            }
        }
        let codes = used.entry(user_id.to_string()).or_default();
        if codes.len() >= PER_USER {
            codes.retain(|_, at| at.elapsed() < ttl);
            if codes.len() >= PER_USER {
                return false;
            }
        }
        codes.insert(nonce.to_string(), std::time::Instant::now()).is_none()
    }

    /// [`DataPlane::with_room`], and when nothing is idle to close but pooled connections on the
    /// session are on their way back, waits for one to come back ([`pool::RETURN_WAIT`] at most),
    /// which makes room. For a stream of its own; a pooled request reuses what comes back instead.
    async fn with_room_or_wait<F, Fut>(&self, session: &MuxHandle, open: F) -> std::io::Result<MuxStream>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = std::io::Result<MuxStream>>,
    {
        let deadline = tokio::time::Instant::now() + pool::RETURN_WAIT;
        loop {
            let seen = session.returns();
            match self.with_room(session, &open).await {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && session.data_streams_full() => {
                    if !session.wait_for_return(seen, deadline).await {
                        return Err(e);
                    }
                }
                other => return other,
            }
        }
    }

    /// Opens a stream with `open`. When the session's data streams are used up, idle pooled
    /// connections on it are closed to make room; a closed connection gives its stream back once
    /// its task notices, so this waits a moment between tries. A client over its own share gets
    /// no such help, and closes nothing.
    async fn with_room<F, Fut>(&self, session: &MuxHandle, open: F) -> std::io::Result<MuxStream>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = std::io::Result<MuxStream>>,
    {
        let mut tries = 0;
        loop {
            match open().await {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && tries < 3 && session.data_streams_full() && self.pool.evict(session) => {
                    tries += 1;
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                other => return other,
            }
        }
    }

    /// Atomically replaces the routing table (called by the control plane only), then binds the
    /// listeners of new port routes and closes those of removed ones.
    pub fn publish(&self, table: RouteTable) {
        let keys: Vec<(Kind, u16)> = table.by_port.keys().copied().collect();
        *self.routes.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(table);
        self.generation.send_modify(|g| *g += 1);
        self.listeners.lock().unwrap_or_else(|e| e.into_inner()).retain(|key, stop| {
            let keep = keys.contains(key);
            if !keep {
                stop.cancel();
                tracing::info!(kind = %key.0, port = key.1, "port closed");
            }
            keep
        });
        let mut errors = self.bind_errors.lock().unwrap_or_else(|e| e.into_inner());
        errors.clear();
        for (kind, port) in keys {
            if let Err(e) = self.bind_port(kind, port) {
                tracing::error!(%kind, port, error = %e, "could not open port");
                errors.insert((kind, port), e.to_string());
            }
        }
    }

    pub fn lookup(&self, host: &str) -> Option<Arc<Route>> {
        let table = self.routes.read().unwrap_or_else(|e| e.into_inner()).clone();
        table.by_host.get(host).cloned()
    }

    pub fn lookup_port(&self, kind: Kind, port: u16) -> Option<Arc<Route>> {
        let table = self.routes.read().unwrap_or_else(|e| e.into_inner()).clone();
        table.by_port.get(&(kind, port)).cloned()
    }

    /// Why a port tunnel's port is not open, if it is not.
    pub fn bind_error(&self, kind: Kind, port: u16) -> Option<String> {
        self.bind_errors.lock().unwrap_or_else(|e| e.into_inner()).get(&(kind, port)).cloned()
    }

    /// Opens the listener for a public port unless it is already open. Called before a port
    /// tunnel is registered, so that a port taken by another program fails the registration.
    pub fn bind_port(&self, kind: Kind, port: u16) -> std::io::Result<()> {
        let mut listeners = self.listeners.lock().unwrap_or_else(|e| e.into_inner());
        if listeners.contains_key(&(kind, port)) {
            return Ok(());
        }
        let me = self.me.upgrade().ok_or_else(|| std::io::Error::other("server is shutting down"))?;
        let stop = self.shutdown.child_token();
        self.on_traffic_threads(|| ports::listen(me, kind, port, stop.clone()))?;
        listeners.insert((kind, port), stop);
        tracing::info!(%kind, port, "port open");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hyper::body::Incoming;
    use hyper_util::rt::TokioIo;
    use magicpipes_core::mux::{self, MAX_DATA_STREAMS, MAX_DATA_STREAMS_PER_CLIENT, Mode};

    use super::*;

    const WAIT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn idle_connections_make_room_for_new_streams() {
        let cfg: Config = toml::from_str("base_domain = \"t.test\"\n[management]\nhostname = \"m.t.test\"\n[tls]\nmode = \"dev-ca\"").unwrap();
        let dp = DataPlane::new(ProxySettings::from_config(&cfg, Signer::for_tests()), CancellationToken::new());
        let (a, b) = tokio::io::duplex(1 << 16);
        let (session, _rpcs) = mux::spawn(a, Mode::Server);
        let (_agent, mut inbound) = mux::spawn(b, Mode::Client);
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Some(s) = inbound.recv().await {
                held.push(s);
            }
        });
        let idle = || async {
            let stream = session.open_shared(WAIT).await.unwrap();
            let (sender, conn) = hyper::client::conn::http1::handshake::<_, proxy::Progress<Incoming>>(TokioIo::new(stream)).await.unwrap();
            tokio::spawn(conn);
            dp.pool.put("tn_a", session.clone(), 0, sender);
        };
        idle().await;

        // A client over its own share closes nobody's idle connections.
        let busy: IpAddr = "203.0.113.1".parse().unwrap();
        let uses: Vec<_> = (0..MAX_DATA_STREAMS_PER_CLIENT).map(|_| session.client_use(busy).unwrap()).collect();
        assert_eq!(dp.with_room(&session, || session.open_data(WAIT, busy)).await.err().unwrap().kind(), std::io::ErrorKind::WouldBlock);
        assert_eq!(dp.pool.len(), 1);
        drop(uses);

        // Idle connections filling the budget don't stop a WebSocket or a port connection.
        for _ in 1..MAX_DATA_STREAMS {
            idle().await;
        }
        assert!(session.data_streams_full());
        let client: IpAddr = "203.0.113.2".parse().unwrap();
        assert_eq!(session.open_data(WAIT, client).await.err().unwrap().kind(), std::io::ErrorKind::WouldBlock);
        assert!(dp.with_room(&session, || session.open_data(WAIT, client)).await.is_ok());
        assert!(dp.pool.len() < MAX_DATA_STREAMS);
    }

    /// Under load, finished requests' connections hold the session's streams until their tasks
    /// put them back, and nothing is idle: a new stream waits for one, rather than being refused.
    #[tokio::test]
    async fn connections_on_their_way_back_make_room() {
        let cfg: Config = toml::from_str("base_domain = \"t.test\"\n[management]\nhostname = \"m.t.test\"\n[tls]\nmode = \"dev-ca\"").unwrap();
        let dp = DataPlane::new(ProxySettings::from_config(&cfg, Signer::for_tests()), CancellationToken::new());
        let (a, b) = tokio::io::duplex(1 << 16);
        let (session, _rpcs) = mux::spawn(a, Mode::Server);
        let (_agent, mut inbound) = mux::spawn(b, Mode::Client);
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Some(s) = inbound.recv().await {
                held.push(s);
            }
        });
        let mut lent = Vec::new();
        for _ in 0..MAX_DATA_STREAMS {
            let stream = session.open_shared(WAIT).await.unwrap();
            let (sender, conn) = hyper::client::conn::http1::handshake::<_, proxy::Progress<Incoming>>(TokioIo::new(stream)).await.unwrap();
            tokio::spawn(conn);
            session.lend();
            lent.push(sender);
        }
        assert!(session.data_streams_full() && dp.pool.len() == 0);

        let client: IpAddr = "203.0.113.2".parse().unwrap();
        let opening = tokio::spawn({
            let (dp, session) = (dp.clone(), session.clone());
            async move { dp.with_room_or_wait(&session, || session.open_data(WAIT, client)).await.map(drop) }
        });
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(!opening.is_finished(), "refused while connections were on their way back");
        // One comes back to the pool: it's closed to make room, and the stream opens.
        dp.pool.put("tn_a", session.clone(), 0, lent.pop().unwrap());
        session.came_back();
        assert!(tokio::time::timeout(WAIT, opening).await.unwrap().unwrap().is_ok());
    }
}
