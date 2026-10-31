//! Data plane: public ingress, hostname and port routing, and forwarding over agent sessions.
//!
//! The data plane only reads an immutable [`RouteTable`] snapshot that the control plane
//! replaces wholesale via [`DataPlane::publish`]. A lookup is one read-lock acquisition to clone
//! an `Arc`, so management activity (database writes, UI rendering, certificate orders) never
//! blocks proxied traffic, and no request touches the database. Publishing also binds and
//! unbinds the listeners of port tunnels ([`ports`]) to match the table.
//!
//! Route removal lifecycle: once a new table without a hostname is published, *new* requests
//! for it get 404. Requests and WebSockets already in flight keep their own stream and run to
//! completion; they end early only if the agent session itself closes.

pub mod ingress;
mod io;
mod ports;
mod proxy;
mod proxy_header;

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;

use magicpipes_core::cidr::Cidr;
use magicpipes_core::mux::MuxHandle;
use magicpipes_core::proto::Kind;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
pub use ports::PortSettings;

/// One routable hostname or public port.
#[derive(Debug)]
pub struct Route {
    pub tunnel_id: String,
    /// `None` while the owning agent is disconnected.
    pub session: Option<MuxHandle>,
    pub stats: Arc<RouteStats>,
    /// Port tunnels: client networks allowed to connect (empty = anyone).
    pub allow: Vec<Cidr>,
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
}

#[derive(Debug, Clone)]
pub struct ProxySettings {
    pub upstream_response_timeout: Duration,
    pub websocket_idle_timeout: Duration,
    pub stream_open_timeout: Duration,
    pub ports: PortSettings,
}

impl ProxySettings {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            upstream_response_timeout: Duration::from_secs(cfg.public.upstream_response_timeout_secs),
            websocket_idle_timeout: Duration::from_secs(cfg.public.websocket_idle_timeout_secs),
            stream_open_timeout: Duration::from_secs(10),
            ports: PortSettings::from_config(&cfg.ports),
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
}

impl DataPlane {
    pub fn new(settings: ProxySettings, shutdown: CancellationToken) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            routes: RwLock::new(Arc::new(RouteTable::default())),
            tcp_permits: Arc::new(Semaphore::new(settings.ports.max_connections)),
            settings,
            listeners: Mutex::default(),
            bind_errors: Mutex::default(),
            shutdown,
            me: me.clone(),
        })
    }

    /// Atomically replaces the routing table (called by the control plane only), then binds the
    /// listeners of new port routes and closes those of removed ones.
    pub fn publish(&self, table: RouteTable) {
        let keys: Vec<(Kind, u16)> = table.by_port.keys().copied().collect();
        *self.routes.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(table);
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
        ports::listen(me, kind, port, stop.clone())?;
        listeners.insert((kind, port), stop);
        tracing::info!(%kind, port, "port open");
        Ok(())
    }
}
