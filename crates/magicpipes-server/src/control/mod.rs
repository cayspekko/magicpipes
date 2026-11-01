//! Control plane: identities, the tunnel registry, agent sessions and certificate readiness.
//!
//! The registry is the single source of truth. Every mutation is validated here, persisted to
//! SQLite, and then published to the data plane as a fresh immutable [`RouteTable`]. The
//! management API, the UI and the agent gateway all call these typed methods directly, and every
//! access decision goes through [`authz::authorize`].
//!
//! * `registry` — registering, checking and removing tunnels;
//! * `sessions` — agent sessions;
//! * `views` — what the API and the UI show.

mod registry;
mod sessions;
mod views;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use magicpipes_core::cidr;
use magicpipes_core::error::ErrorCode;
use magicpipes_core::mux::MuxHandle;
use magicpipes_core::proto::{self, ErrorBody, Kind};
use magicpipes_core::unix_now;
use tokio_util::sync::CancellationToken;

use crate::authz::{self, Action, Principal, Resource, TunnelAuthz};
use crate::certs::CertManager;
use crate::config::Config;
use crate::data::{AccessPolicy, DataPlane, Route, RouteStats, RouteTable};
use crate::store::{Store, TunnelRow};
pub use views::TunnelView;

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
    /// Per agent: when each of its recent tunnels needed a new certificate order.
    cert_orders: HashMap<String, Vec<Instant>>,
}

const CERT_ORDER_WINDOW: Duration = Duration::from_secs(24 * 3600);

struct TunnelRecord {
    row: TunnelRow,
    stats: Arc<RouteStats>,
}

impl TunnelRecord {
    fn authz(&self) -> TunnelAuthz {
        TunnelAuthz { agent_id: self.row.agent_id.clone(), public: true }
    }
}

struct Session {
    conn_id: u64,
    handle: MuxHandle,
    connected_at: i64,
    remote: SocketAddr,
    /// The agent's protocol version (`proto::PROTOCOL_VERSION`).
    protocol: u32,
    last_ping: Instant,
}

fn err(code: ErrorCode, msg: impl Into<String>) -> ErrorBody {
    ErrorBody::new(code, msg)
}

fn internal(e: anyhow::Error) -> ErrorBody {
    tracing::error!(error = %format!("{e:#}"), "control plane storage error");
    err(ErrorCode::Internal, "internal server error")
}

/// Whether `who` may do `action` to the tunnel.
fn may(who: &Principal, action: Action, t: &TunnelRecord) -> bool {
    authz::authorize(who, action, Resource::Tunnel(&t.authz()))
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
            let access = AccessPolicy { allow, authz: t.authz() };
            let route = Arc::new(Route { tunnel_id: t.row.id.clone(), session, stats: t.stats.clone(), access });
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

    pub fn create_enrollment(&self, who: &Principal) -> Result<String, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(err(ErrorCode::Unauthorized, "only administrators create enrollment tokens"));
        }
        self.store.create_enrollment(self.cfg.agents.enrollment_ttl_secs).map_err(internal)
    }

    pub fn enroll(&self, req: &proto::EnrollRequest) -> Result<proto::EnrollResponse, ErrorBody> {
        let name: String = req.agent_name.chars().filter(|c| !c.is_control()).take(64).collect();
        let name = if name.trim().is_empty() { "agent".to_string() } else { name.trim().to_string() };
        match self.store.enroll(&req.enrollment_token, &name).map_err(internal)? {
            Some((agent_id, agent_token)) => {
                tracing::info!(agent = %agent_id, %name, "agent enrolled");
                Ok(proto::EnrollResponse { agent_id, agent_token, base_domain: self.cfg.base_domain.clone() })
            }
            None => Err(err(ErrorCode::InvalidEnrollmentToken, "enrollment token is invalid, expired or already used")),
        }
    }

    /// Revokes an agent: its credential stops working, its tunnels are deleted (new requests get
    /// 404) and its live session, if any, is closed. Returns false if the agent is unknown, or if
    /// `who` may not manage it (never revealing which).
    pub fn revoke_agent(&self, who: &Principal, agent_id: &str) -> Result<bool, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Agent(agent_id)) {
            return Ok(false);
        }
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
}

#[cfg(test)]
pub(crate) mod tests;
