//! Control plane: identities, the tunnel registry, agent sessions and certificate readiness.
//!
//! The registry is the single source of truth. Every mutation is validated here, persisted to
//! SQLite, and then published to the data plane as a fresh immutable [`RouteTable`]. The
//! management API, the UI and the agent gateway all call these typed methods directly, and every
//! access decision goes through [`authz::authorize`].
//!
//! * `device` — `magicpipes login` approved in the browser;
//! * `directory` — owners, tags and custom hostnames, kept in memory for access decisions;
//! * `email` — invitations, sign-in links and confirming an address;
//! * `hostnames` — custom hostnames and who may serve them;
//! * `oidc` — who a single sign-on signs in as;
//! * `registry` — registering, checking and removing tunnels;
//! * `sessions` — agent sessions;
//! * `ssh` — public keys for the SSH gateway, and what it reports back;
//! * `settings` — sign-in settings and certificates made on the Settings page, and the generated
//!   configuration;
//! * `tags` — the tag registry, tag assignments and enrollment tokens;
//! * `users` — accounts, logins, UI sessions, API tokens and the audit log;
//! * `views` — what the API and the UI show.

mod device;
mod directory;
mod email;
mod hostnames;
mod oidc;
mod registry;
mod sessions;
pub use sessions::Attached;
mod settings;
mod ssh;
mod tags;
mod users;
mod views;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use magicpipes_core::cidr;
use magicpipes_core::error::ErrorCode;
use magicpipes_core::mux::MuxHandle;
use magicpipes_core::proto::{self, ErrorBody, Kind};
use magicpipes_core::unix_now;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::authz::{self, Action, AgentAuthz, Principal, Resource, TunnelAuthz};
use crate::certs::CertManager;
use crate::config::Config;
use crate::data::{AccessPolicy, AgentLink, DataPlane, GatewayKey, Route, RouteStats, RouteTable, TunnelUser};
use crate::store::{Store, TunnelRow};
pub use device::{API_PASS_SECS, DEVICE_LOGIN_TTL, DevicePoll, Purpose};
pub use email::{AcceptError, INVITATION_DAYS, InvitationView, LinkError, OpenInvitation, SIGN_IN_LINK_MINUTES};
pub use oidc::SignInError;
pub use registry::TunnelSignIn;
pub use settings::{CertificateView, GENERATED_CONFIG, NewProvider, NewSmtp, ProviderChanges, ProviderView, SmtpView};
pub use ssh::looks_private as looks_like_private_key;
pub use tags::EnrollmentOptions;
pub use users::{Login, LoginError, MIN_PASSWORD_CHARS, UserView};
pub use views::TunnelView;

pub struct ControlPlane {
    cfg: Arc<Config>,
    store: Store,
    certs: Arc<CertManager>,
    data: Arc<DataPlane>,
    state: Mutex<State>,
    started_at: i64,
    /// Bounds concurrent password hashing (CPU and memory).
    hashing: Semaphore,
    accounts: users::AccountLimiter,
    devices: device::DeviceLogins,
    /// The configuration file's providers, read once.
    file_providers: Vec<Arc<crate::oidc::Provider>>,
    /// The configuration file's mail server, read once.
    file_mailer: Option<Arc<crate::mail::Mailer>>,
    /// Providers, sign-in rules and the mail server in effect; replaced whole when settings change.
    sign_in: RwLock<Arc<settings::SignIn>>,
    /// Puts settings changes in effect one at a time, so the last one holds.
    settings_lock: Mutex<()>,
    /// Bounds code exchanges under way with providers.
    oidc_exchanges: Semaphore,
    proxy_auth: Option<crate::proxy_auth::ProxyAuth>,
    mail: email::MailState,
}

#[derive(Default)]
struct State {
    tunnels: HashMap<String, TunnelRecord>,
    sessions: HashMap<String, Link>,
    next_conn_id: u64,
    /// Per agent: when each of its recent tunnels needed a new certificate order.
    cert_orders: HashMap<String, Vec<Instant>>,
    dir: directory::Directory,
    /// SSH tunnels' host keys, by tunnel id (`store::ssh_host_keys`).
    host_keys: HashMap<String, String>,
}

const CERT_ORDER_WINDOW: Duration = Duration::from_secs(24 * 3600);

struct TunnelRecord {
    row: TunnelRow,
    stats: Arc<RouteStats>,
    version: u64,
}

impl State {
    /// What `authorize` needs about a tunnel: its tags that grant access, and its owner.
    fn tunnel_authz(&self, t: &TunnelRecord) -> TunnelAuthz {
        let access = t.row.tags.iter().filter(|tag| self.dir.grants_access(tag)).cloned().collect();
        TunnelAuthz {
            agent_id: t.row.agent_id.clone(),
            owner_user_id: self.dir.owner(&t.row.agent_id).map(str::to_string),
            public: t.row.visibility == proto::Visibility::Public,
            access,
        }
    }

    /// Whether `who` may do `action` to the tunnel.
    fn may(&self, who: &Principal, action: Action, t: &TunnelRecord) -> bool {
        authz::authorize(who, action, Resource::Tunnel(&self.tunnel_authz(t)))
    }

    fn agent_resource<'a>(&'a self, agent_id: &'a str) -> Resource<'a> {
        Resource::Agent(AgentAuthz { id: agent_id, owner_user_id: self.dir.owner(agent_id) })
    }
}

/// One of an agent's connections.
struct Session {
    conn_id: u64,
    handle: MuxHandle,
    connected_at: i64,
    remote: SocketAddr,
    /// The agent's protocol version (`proto::PROTOCOL_VERSION`).
    protocol: u32,
    last_ping: Instant,
}

/// An agent's connections: those of one run of it, at most [`proto::MAX_CONNECTIONS`], in the
/// order they came. Never empty: the last one to go takes the entry with it.
struct Link {
    /// What its connections sent as `x-magicpipes-instance`; `None` from an agent before protocol
    /// 9, whose one connection the next always replaces.
    instance: Option<String>,
    lanes: Vec<Session>,
}

impl Link {
    /// An open connection, for the control plane's own streams (checks, removals).
    fn handle(&self) -> Option<MuxHandle> {
        self.lanes.iter().find(|s| !s.handle.is_closed()).map(|s| s.handle.clone())
    }

    /// The connections the data plane opens streams on.
    fn data(&self) -> AgentLink {
        AgentLink::new(self.lanes.iter().map(|s| s.handle.clone()).collect())
    }

    fn close(&self) {
        for s in &self.lanes {
            s.handle.close();
        }
    }

    /// The connection up longest, for what's shown about the agent.
    fn first(&self) -> &Session {
        &self.lanes[0]
    }

    fn is_closed(&self) -> bool {
        self.lanes.iter().all(|s| s.handle.is_closed())
    }
}

fn err(code: ErrorCode, msg: impl Into<String>) -> ErrorBody {
    ErrorBody::new(code, msg)
}

fn internal(e: anyhow::Error) -> ErrorBody {
    logged(err(ErrorCode::Internal, "internal server error"))(e)
}

/// For `map_err`: logs a storage error, which the caller then answers with `answer`.
fn logged<E>(answer: E) -> impl FnOnce(anyhow::Error) -> E {
    move |e| {
        tracing::error!(error = %format!("{e:#}"), "control plane storage error");
        answer
    }
}

/// For storage calls whose caller carries on without an answer: what they returned, or `None` after
/// logging why. A broken database must not just look like "no such session".
trait OrLog<T> {
    fn or_log(self) -> Option<T>;
}

impl<T> OrLog<T> for anyhow::Result<T> {
    fn or_log(self) -> Option<T> {
        self.map_err(logged(())).ok()
    }
}

impl ControlPlane {
    pub fn new(cfg: Arc<Config>, store: Store, certs: Arc<CertManager>, data: Arc<DataPlane>) -> anyhow::Result<Arc<Self>> {
        let mut state = State { dir: directory::Directory::load(&store)?, host_keys: store.ssh_host_keys()?, ..State::default() };
        for row in store.tunnels()? {
            if let Some(port) = row.public_port
                && !cfg.port_range().is_some_and(|r| r.contains(port))
            {
                tracing::warn!(tunnel = %row.name, port, "the tunnel's port is outside the [ports] range; it stays closed");
            }
            state.tunnels.insert(row.id.clone(), TunnelRecord { row, stats: Arc::default(), version: 0 });
        }
        let file_providers = cfg
            .oidc
            .iter()
            .map(|p| crate::oidc::Provider::load(p).map(Arc::new).with_context(|| format!("oidc provider '{}'", p.id)))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let proxy_auth = cfg.proxy_auth.as_ref().map(|p| crate::proxy_auth::ProxyAuth::load(p, cfg.trusted_proxies())).transpose().context("proxy_auth")?;
        let file_mailer = cfg.smtp.as_ref().map(|s| crate::mail::Mailer::load(s, &cfg.management.hostname).map(Arc::new)).transpose().context("smtp")?;
        let effective = settings::effective_config(&cfg, &store, &certs)?;
        let sign_in = RwLock::new(Arc::new(settings::SignIn::new(&effective, &file_providers, file_mailer.as_ref())));
        settings::write_generated(&effective);
        let cp = Arc::new(Self {
            cfg,
            store,
            certs,
            data,
            state: Mutex::new(state),
            started_at: unix_now(),
            hashing: Semaphore::new(users::HASH_CONCURRENCY),
            accounts: users::AccountLimiter::default(),
            devices: device::DeviceLogins::default(),
            file_providers,
            file_mailer,
            sign_in,
            settings_lock: Mutex::new(()),
            oidc_exchanges: Semaphore::new(oidc::MAX_EXCHANGES),
            proxy_auth,
            mail: email::MailState::default(),
        });
        cp.publish(&cp.state.lock().unwrap());
        Ok(cp)
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// The data plane, which serves browser terminals once the control plane has let them in.
    pub fn data_plane(&self) -> Arc<DataPlane> {
        self.data.clone()
    }

    /// See [`DataPlane::on_traffic_threads`].
    pub fn on_traffic_threads<T>(&self, f: impl FnOnce() -> T) -> T {
        self.data.on_traffic_threads(f)
    }

    /// Starts certificate provisioning for known hostnames, the stale-session reaper, the queue of
    /// requests for sign-in links, and hourly pruning of the audit log, expired UI sessions and
    /// emailed links.
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
        self.start_mail_queue(shutdown.clone());
        self.start_gateway_reports(shutdown.clone());
        let me = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            let mut hourly = tokio::time::interval(Duration::from_secs(3600));
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tick.tick() => me.reap_sessions(),
                    _ = hourly.tick() => me.prune(),
                }
            }
        });
    }

    /// Builds the data-plane view from the registry. Must be called with the state lock held so
    /// concurrent mutations publish in order.
    fn publish(&self, st: &State) {
        let mut table = RouteTable::default();
        for u in st.dir.active_users() {
            let principal = Principal::User { id: u.id.clone(), role: u.role, tags: st.dir.user_tags(&u.id) };
            table.users.insert(u.id.clone(), TunnelUser { email: u.email.clone(), principal, valid_after: u.sessions_valid_after });
        }
        for k in st.dir.ssh_keys() {
            table.ssh_keys.insert(k.fingerprint.clone(), GatewayKey { id: k.id.clone(), user_id: k.user_id.clone() });
        }
        // One link per agent, shared by its routes.
        let links: HashMap<&str, AgentLink> = st.sessions.iter().map(|(agent, link)| (agent.as_str(), link.data())).collect();
        for t in st.tunnels.values() {
            // A disabled owner's agents serve nothing.
            if !st.dir.agent_active(&t.row.agent_id) {
                continue;
            }
            let agent = links.get(t.row.agent_id.as_str()).cloned();
            // Stored lists were validated on registration. If one no longer parses, fail closed:
            // an empty list would mean "anyone".
            let allow = match cidr::parse_list(&t.row.allow) {
                Ok(allow) => allow,
                Err(e) => {
                    tracing::error!(tunnel = %t.row.name, error = %e, "unreadable allow-list; tunnel not published");
                    continue;
                }
            };
            let access = AccessPolicy { allow, authz: st.tunnel_authz(t) };
            let host_key = st.host_keys.get(&t.row.id).cloned();
            let route = Arc::new(Route { tunnel_id: t.row.id.clone(), agent, stats: t.stats.clone(), access, version: t.version, host_key });
            match (t.row.kind, t.row.public_port) {
                (Kind::Http, _) => {
                    table.by_host.insert(t.row.hostname.clone(), route);
                }
                (Kind::Ssh, _) => {
                    table.by_ssh.insert(t.row.name.clone(), route);
                }
                // In the browser, and through `magicpipes connect` for a native client.
                (kind @ (Kind::Rdp | Kind::Vnc), _) => {
                    table.by_connect.insert(t.row.name.clone(), (kind, route));
                }
                // The [ports] range may have been narrowed or removed since: then the port stays
                // closed (the tunnel shows as offline) rather than reopening outside it.
                (kind, Some(port)) if self.cfg.port_range().is_some_and(|r| r.contains(port)) => {
                    table.by_port.insert((kind, port), route);
                }
                (_, Some(_)) => {}
                (kind, None) => {
                    table.by_connect.insert(t.row.name.clone(), (kind, route));
                }
            }
        }
        self.data.publish(table);
        let mut wanted: std::collections::HashSet<&str> =
            st.tunnels.values().filter(|t| t.row.kind.is_http()).map(|t| t.row.hostname.as_str()).collect();
        // Registered hostnames keep their certificates without a tunnel, ready for one.
        wanted.extend(st.dir.hostnames().map(|h| h.hostname.as_str()));
        wanted.insert(&self.cfg.management.hostname);
        self.certs.set_wanted(&wanted);
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

    pub fn enroll(&self, req: &proto::EnrollRequest) -> Result<proto::EnrollResponse, ErrorBody> {
        let name: String = req.agent_name.chars().filter(|c| !c.is_control()).take(64).collect();
        let name = if name.trim().is_empty() { "agent".to_string() } else { name.trim().to_string() };
        match self.store.enroll(&req.enrollment_token, &name).map_err(internal)? {
            Some((agent_id, agent_token)) => {
                tracing::info!(agent = %agent_id, %name, "agent enrolled");
                self.refresh();
                Ok(proto::EnrollResponse { agent_id, agent_token, base_domain: self.cfg.base_domain.clone() })
            }
            None => Err(err(ErrorCode::InvalidEnrollmentToken, "enrollment token is invalid, expired or already used")),
        }
    }

    /// Revokes an agent: its credential stops working, its tunnels are deleted (new requests get
    /// 404) and its live session, if any, is closed. Returns false if the agent is unknown, or if
    /// `who` may not manage it (never revealing which).
    pub fn revoke_agent(&self, who: &Principal, agent_id: &str) -> Result<bool, ErrorBody> {
        let mut st = self.state.lock().unwrap();
        if !authz::authorize(who, Action::Manage, st.agent_resource(agent_id)) {
            return Ok(false);
        }
        if !self.store.delete_agent(agent_id).map_err(internal)? {
            return Ok(false);
        }
        st.tunnels.retain(|_, t| t.row.agent_id != agent_id);
        let link = st.sessions.remove(agent_id);
        self.publish(&st);
        drop(st);
        if let Some(link) = link {
            link.close();
        }
        tracing::info!(agent = %agent_id, by = who.actor(), "agent revoked");
        self.audit(who, "agent.revoke", agent_id, "");
        self.refresh();
        Ok(true)
    }
}

#[cfg(test)]
pub(crate) mod tests;
