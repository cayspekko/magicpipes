//! Data plane: public ingress, hostname routing and forwarding over agent sessions.
//!
//! The data plane only reads an immutable [`RouteTable`] snapshot that the control plane
//! replaces wholesale via [`DataPlane::publish`]. A lookup is one read-lock acquisition to clone
//! an `Arc`, so management activity (database writes, UI rendering, certificate orders) never
//! blocks proxied traffic, and no request touches the database.
//!
//! Route removal lifecycle: once a new table without a hostname is published, *new* requests
//! for it get 404. Requests and WebSockets already in flight keep their own stream and run to
//! completion; they end early only if the agent session itself closes.

pub mod ingress;
mod io;
mod proxy;

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use magicpipes_core::mux::MuxHandle;

use crate::config::Config;

/// One routable hostname.
#[derive(Debug)]
pub struct Route {
    pub tunnel_id: String,
    /// `None` while the owning agent is disconnected.
    pub session: Option<MuxHandle>,
    pub stats: Arc<RouteStats>,
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
}

#[derive(Debug, Clone)]
pub struct ProxySettings {
    pub upstream_response_timeout: Duration,
    pub websocket_idle_timeout: Duration,
    pub stream_open_timeout: Duration,
}

impl ProxySettings {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            upstream_response_timeout: Duration::from_secs(cfg.public.upstream_response_timeout_secs),
            websocket_idle_timeout: Duration::from_secs(cfg.public.websocket_idle_timeout_secs),
            stream_open_timeout: Duration::from_secs(10),
        }
    }
}

pub struct DataPlane {
    routes: RwLock<Arc<RouteTable>>,
    settings: ProxySettings,
}

impl DataPlane {
    pub fn new(settings: ProxySettings) -> Arc<Self> {
        Arc::new(Self { routes: RwLock::new(Arc::new(RouteTable::default())), settings })
    }

    /// Atomically replaces the routing table (called by the control plane only).
    pub fn publish(&self, table: RouteTable) {
        *self.routes.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(table);
    }

    pub fn lookup(&self, host: &str) -> Option<Arc<Route>> {
        let table = self.routes.read().unwrap_or_else(|e| e.into_inner()).clone();
        table.by_host.get(host).cloned()
    }
}
