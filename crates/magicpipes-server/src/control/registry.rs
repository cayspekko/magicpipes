//! The tunnel registry: registering, checking and removing tunnels.

use std::sync::Arc;
use std::time::{Duration, Instant};

use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::{self, CertState, ErrorBody, Kind, RegisterTunnel, ServerOpen, StreamStatus, TunnelInfo, Visibility};
use magicpipes_core::mux::MuxHandle;
use magicpipes_core::{cidr, names, secret, tags, unix_now};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{CERT_ORDER_WINDOW, ControlPlane, State, TunnelRecord, err, internal};
use crate::authz::{Action, Principal};
use crate::certs::CertStatus;
use crate::config::{PortRange, TlsMode};
use crate::store::TunnelRow;

/// A tunnel's visibility and tags.
type Access = (Visibility, Vec<String>);

/// A private TCP or UDP tunnel's public port: none, so nothing that applies to one.
fn private_port(allow: &[String], remote_port: Option<u16>) -> Result<Option<u16>, ErrorBody> {
    if remote_port.is_some() || !allow.is_empty() {
        return Err(err(
            ErrorCode::InvalidRequest,
            "a private TCP or UDP tunnel has no public port, so --remote-port and --allow-cidr don't apply; people you share it with reach it with \
             `magicpipes connect`",
        ));
    }
    Ok(None)
}

impl ControlPlane {
    /// What a registration asks for, within the agent's enrollment. Without a visibility, a new
    /// tunnel gets the agent's default and an existing one keeps its settings as stored. With
    /// one, the tags asked for replace the stored ones and are checked against what the agent may
    /// publish with now, every time: ordinary tags its publisher holds (the owner's, or a service
    /// agent's own), or anyone's personal tag, to share with that person. The registration then
    /// adds the owner's personal tag, so the owner can open it. That is this function's policy,
    /// not a rule of the model: `authorize` sees only the tunnel's tags.
    fn requested_access(&self, st: &State, agent_id: &str, req: &RegisterTunnel, existing: Option<&TunnelRow>) -> Result<Access, ErrorBody> {
        // An agent missing from the directory (it couldn't be reloaded) gets the narrowest
        // settings, never the widest.
        let (allow_public, default_private) = st.dir.agent(agent_id).map_or((false, true), |a| (a.allow_public, a.default_private));
        // `members_can_publish` applies to machines enrolled before it was turned off, too.
        let members_may_not = st.dir.member_owned(agent_id) && !self.cfg.users.members_can_publish;
        let invalid = |m: String| err(ErrorCode::InvalidRequest, m);
        let protocol = st.sessions.get(agent_id).map_or(proto::PROTOCOL_VERSION, |l| l.first().protocol);
        let (visibility, requested) = match (req.visibility, existing) {
            (None, Some(row)) => return Ok((row.visibility, row.tags.clone())),
            // An agent from before private tunnels would wait for its readiness probe, which
            // the sign-in page answers, and fail after minutes; and public isn't what was meant.
            (None, None) if default_private && req.kind.is_http() && protocol < 3 => {
                return Err(err(
                    ErrorCode::AgentOutdated,
                    "this machine's tunnels are private by default, which this version of magicpipes doesn't support; upgrade magicpipes on it",
                ));
            }
            // The gateway and remote desktops only let people in through a tag.
            (None, None) if req.kind == Kind::Ssh || req.kind.is_desktop() => (Visibility::Private, Vec::new()),
            // Agents from before private ports ask for an allow-list (or anyone) with every new port,
            // which they open to the public; and an allow-list is only for a public port.
            (None, None) if req.kind.has_port() && (protocol < 6 || !req.allow.is_empty()) => (Visibility::Public, Vec::new()),
            (None, None) if default_private => (Visibility::Private, Vec::new()),
            // A newer agent says `public` when it was given --allow-any, so it was given nothing.
            (None, None) if req.kind.has_port() => {
                return Err(err(
                    ErrorCode::InvalidRequest,
                    format!(
                        "this would open a {} port to the whole internet. Say who may connect with --allow-cidr <network>, or use --allow-any if anyone \
                         should; or use --private, and people you share it with reach it with `magicpipes connect`",
                        req.kind
                    ),
                ));
            }
            (None, None) => (Visibility::Public, Vec::new()),
            (Some(v), _) => (v, tags::normalize_list(&req.tags).map_err(invalid)?),
        };
        match visibility {
            Visibility::Public if req.kind == Kind::Ssh => {
                return Err(err(ErrorCode::InvalidRequest, "SSH tunnels are always private. For a port anyone can reach, use --tcp"));
            }
            Visibility::Public if req.kind.is_desktop() => {
                let kind = req.kind.as_str().to_ascii_uppercase();
                return Err(err(ErrorCode::InvalidRequest, format!("{kind} tunnels are always private. For a port anyone can reach, use --tcp")));
            }
            Visibility::Public if members_may_not => {
                return Err(err(ErrorCode::PublicNotAllowed, "members' machines may only publish private tunnels on this server"));
            }
            Visibility::Public if !allow_public => {
                return Err(err(ErrorCode::PublicNotAllowed, "this machine may only publish private tunnels (its enrollment doesn't allow public ones)"));
            }
            Visibility::Public if !requested.is_empty() => {
                return Err(err(ErrorCode::InvalidRequest, "tags apply only to private tunnels"));
            }
            // An older agent can't use it, nor tell its user how people get in.
            Visibility::Private if req.kind.has_port() && protocol < 6 => {
                return Err(err(ErrorCode::AgentOutdated, "private TCP and UDP tunnels need a newer magicpipes on this machine"));
            }
            _ => {}
        }
        let mut list = self.known_tags(&requested, true)?;
        let held = st.dir.agent_tags(agent_id);
        if let Some(t) = list.iter().find(|t| !held.contains(t) && !st.dir.is_personal(t)) {
            let whose = if st.dir.owner(agent_id).is_some() { "you don't hold" } else { "this machine doesn't have" };
            return Err(err(ErrorCode::Forbidden, format!("{whose} the tag '{t}', so it can't go on this tunnel")));
        }
        if let Some(personal) = st.dir.owner(agent_id).and_then(|o| st.dir.personal_tag(o)) {
            list.push(personal.to_string());
        }
        list.sort();
        list.dedup();
        Ok((visibility, list))
    }

    pub fn register(&self, agent_id: &str, req: &RegisterTunnel) -> Result<TunnelInfo, ErrorBody> {
        let who = Principal::Agent(agent_id.to_string());
        let target: String = req.target.chars().filter(|c| !c.is_control()).take(200).collect();
        let allow: Vec<String> = cidr::parse_list(&req.allow)
            .map_err(|m| err(ErrorCode::InvalidCidr, m))?
            .iter()
            .map(ToString::to_string)
            .collect();
        let custom = match &req.hostname {
            None => None,
            Some(_) if !req.kind.is_http() => {
                return Err(err(ErrorCode::InvalidRequest, "a custom hostname applies only to HTTP tunnels"));
            }
            Some(h) => Some(h.trim().trim_end_matches('.').to_ascii_lowercase()),
        };
        match req.kind {
            Kind::Http | Kind::Ssh | Kind::Rdp | Kind::Vnc if req.remote_port.is_some() || !allow.is_empty() => {
                return Err(err(ErrorCode::InvalidRequest, "a remote port and an allow-list apply only to TCP and UDP tunnels"));
            }
            Kind::Ssh if self.cfg.ssh.is_none() => {
                return Err(err(ErrorCode::SshDisabled, "this server does not offer SSH (its configuration has no [ssh] gateway)"));
            }
            _ => {}
        }
        // Only a public port tunnel takes a port from the range.
        let range = || {
            self.cfg.port_range().ok_or_else(|| err(ErrorCode::PortsDisabled, "this server does not offer TCP or UDP ports (its configuration has no [ports] range)"))
        };
        if let (Some(r), Some(p)) = (self.cfg.port_range(), req.remote_port)
            && !r.contains(p)
        {
            return Err(err(ErrorCode::PortUnavailable, format!("port {p} is outside this server's port range {}-{}", r.first, r.last)));
        }
        let mut st = self.state.lock().unwrap();
        let owner_tag = st.dir.owner(agent_id).and_then(|o| st.dir.personal_tag(o)).map(str::to_string);
        if let Some(h) = &custom
            && !st.may_serve(agent_id, h)
        {
            return Err(err(ErrorCode::NotFound, format!("the hostname '{h}' isn't assigned to this machine; an administrator assigns hostnames")));
        }

        let existing = match (&req.id, &req.name, &custom) {
            (Some(id), _, _) => match st.tunnels.get(id) {
                Some(t) if st.may(&who, Action::Manage, t) => Some(id.clone()),
                _ => return Err(err(ErrorCode::NotFound, "tunnel no longer exists on the server")),
            },
            (None, Some(name), _) => {
                let name = names::validate(name).map_err(|m| err(ErrorCode::InvalidName, m))?;
                match st.tunnels.values().find(|t| t.row.name == name) {
                    Some(t) if st.may(&who, Action::Manage, t) => Some(t.row.id.clone()),
                    Some(_) => return Err(err(ErrorCode::NameTaken, format!("the name '{name}' is used by another agent"))),
                    None => None,
                }
            }
            (None, None, Some(h)) => match st.tunnels.values().find(|t| &t.row.hostname == h) {
                Some(t) if st.may(&who, Action::Manage, t) => Some(t.row.id.clone()),
                Some(_) => return Err(err(ErrorCode::NameTaken, format!("'{h}' is served by another machine"))),
                None => None,
            },
            (None, None, None) => None,
        };

        if let Some(id) = existing {
            let mut row = st.tunnels[&id].row.clone();
            if let Some(h) = &custom
                && row.hostname != *h
            {
                return Err(err(
                    ErrorCode::InvalidRequest,
                    format!("tunnel '{}' is served at {}; remove it first to move it to {h}", row.name, row.hostname),
                ));
            }
            (row.visibility, row.tags) = self.requested_access(&st, agent_id, req, Some(&row))?;
            if row.kind != req.kind {
                return Err(err(
                    ErrorCode::KindMismatch,
                    format!("tunnel '{}' is a {} tunnel; remove it first to make it {}", row.name, row.kind, req.kind),
                ));
            }
            // Another machine (`--host`) has its own host key, or certificate.
            if matches!(row.kind, Kind::Ssh | Kind::Rdp) && row.target != target && st.host_keys.remove(&id).is_some() {
                self.store.forget_ssh_host_key(&id).map_err(internal)?;
            }
            row.target = target;
            row.allow = allow;
            if row.kind.has_port() {
                row.public_port = match (row.visibility, req.remote_port, row.public_port) {
                    (Visibility::Private, ..) => private_port(&row.allow, req.remote_port)?,
                    (Visibility::Public, Some(p), current) if current != Some(p) => Some(self.claim_port(&st, row.kind, p)?),
                    // It was private: it needs a port now.
                    (Visibility::Public, None, None) => {
                        self.room_for_a_port(&st, agent_id)?;
                        Some(self.allocate_port(&st, row.kind, range()?)?)
                    }
                    (Visibility::Public, _, current) => current,
                };
            }
            let t = st.tunnels.get_mut(&id).expect("checked above");
            let settings = |r: &TunnelRow| (r.target.clone(), r.allow.clone(), r.public_port, r.visibility, r.tags.clone());
            if settings(&t.row) != settings(&row) {
                self.store.update_tunnel(&row).map_err(internal)?;
                t.row = row.clone();
                t.version += 1;
                self.publish(&st);
            }
            if row.kind.is_http() {
                self.certs.ensure(&row.hostname);
            }
            let access = row.tags.iter().filter(|t| st.dir.grants_access(t)).cloned().collect();
            return Ok(self.info(&row, false, owner_tag, access));
        }

        let owned = st.tunnels.values().filter(|t| t.row.agent_id == agent_id).count();
        if owned >= self.cfg.agents.max_tunnels_per_agent {
            return Err(err(ErrorCode::LimitReached, format!("an agent may own at most {} tunnels", self.cfg.agents.max_tunnels_per_agent)));
        }
        let taken = |n: &str| st.tunnels.values().any(|t| t.row.name == n);
        let name = match &req.name {
            Some(n) => names::validate(n).map_err(|m| err(ErrorCode::InvalidName, m))?,
            // On a custom hostname, its first label when free (shop.example.com: `shop`).
            None => custom
                .as_deref()
                .and_then(|h| h.split('.').next())
                .and_then(|l| names::validate(l).ok())
                .filter(|n| !taken(n))
                .into_iter()
                .chain((0..10).map(names::random))
                .find(|n| !taken(n))
                .ok_or_else(|| err(ErrorCode::Internal, "could not allocate a tunnel name"))?,
        };
        let hostname = custom.clone().unwrap_or_else(|| self.cfg.hostname_for(&name));
        if hostname == self.cfg.management.hostname {
            return Err(err(ErrorCode::InvalidName, format!("'{name}' is reserved")));
        }
        if st.tunnels.values().any(|t| t.row.hostname == hostname) {
            return Err(err(ErrorCode::NameTaken, format!("'{hostname}' is served by another tunnel")));
        }
        // Every new hostname costs a certificate order, and the CA's limits are shared by all
        // agents (Let's Encrypt: 50 certificates per domain per week).
        let new_cert = req.kind.is_http() && self.cfg.tls.mode == TlsMode::Acme && self.certs.status(&hostname) != CertStatus::Ready;
        if new_cert {
            let max = self.cfg.agents.max_new_certificates_per_day;
            let orders = st.cert_orders.entry(agent_id.to_string()).or_default();
            orders.retain(|t| t.elapsed() < CERT_ORDER_WINDOW);
            if orders.len() >= max {
                return Err(err(ErrorCode::LimitReached, format!("an agent may add at most {max} new hostnames per day; reuse a name or try later")));
            }
        }
        let (visibility, tags) = self.requested_access(&st, agent_id, req, None)?;
        let public_port = match (req.kind.has_port(), visibility, req.remote_port) {
            (false, ..) => None,
            (true, Visibility::Private, _) => private_port(&allow, req.remote_port)?,
            (true, Visibility::Public, port) => {
                self.room_for_a_port(&st, agent_id)?;
                Some(match port {
                    Some(p) => self.claim_port(&st, req.kind, p)?,
                    None => self.allocate_port(&st, req.kind, range()?)?,
                })
            }
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
            visibility,
            tags,
        };
        self.store.insert_tunnel(&row).map_err(internal)?;
        if new_cert {
            st.cert_orders.entry(agent_id.to_string()).or_default().push(Instant::now());
        }
        st.tunnels.insert(row.id.clone(), TunnelRecord { row: row.clone(), stats: Arc::default(), version: 0 });
        self.publish(&st);
        let access = row.tags.iter().filter(|t| st.dir.grants_access(t)).cloned().collect();
        drop(st);
        let info = self.info(&row, true, owner_tag, access);
        tracing::info!(tunnel = %row.id, url = %info.public_url, agent = %agent_id, "tunnel registered");
        if row.kind.is_http() {
            self.certs.ensure(&row.hostname);
        }
        Ok(info)
    }

    /// Whether the agent may hold one more public port.
    fn room_for_a_port(&self, st: &State, agent_id: &str) -> Result<(), ErrorBody> {
        let max = self.cfg.agents.max_ports_per_agent;
        if st.tunnels.values().filter(|t| t.row.agent_id == agent_id && t.row.public_port.is_some()).count() >= max {
            return Err(err(ErrorCode::LimitReached, format!("an agent may hold at most {max} public ports")));
        }
        Ok(())
    }

    /// Takes a specific public port: free among this kind's tunnels and bindable on this host.
    fn claim_port(&self, st: &State, kind: Kind, port: u16) -> Result<u16, ErrorBody> {
        if let Some(t) = st.tunnels.values().find(|t| t.row.kind == kind && t.row.public_port == Some(port)) {
            return Err(err(ErrorCode::PortUnavailable, format!("{kind} port {port} is used by tunnel '{}'", t.row.name)));
        }
        self.data
            .bind_port(kind, port)
            .map_err(|e| err(ErrorCode::PortUnavailable, format!("cannot open {kind} port {port} on the server: {e}")))?;
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
            .ok_or_else(|| err(ErrorCode::LimitReached, format!("no free {kind} port left in {}-{}", range.first, range.last)))
    }

    pub(super) fn public_url(&self, row: &TunnelRow) -> String {
        match (row.kind, row.public_port) {
            (Kind::Ssh, _) => match self.cfg.ssh_address() {
                Some(gateway) => format!("ssh -J {gateway} {}", row.name),
                None => row.name.clone(),
            },
            (Kind::Tcp | Kind::Udp, None) => format!("magicpipes connect {}", row.name),
            (Kind::Rdp | Kind::Vnc, _) => format!("{}/desktop/{}", self.cfg.management_url(), row.name),
            (Kind::Http, _) => self.cfg.public_url(&row.hostname),
            (kind, Some(port)) => self.cfg.port_url(kind, port),
        }
    }

    fn info(&self, row: &TunnelRow, created: bool, owner_tag: Option<String>, access: Vec<String>) -> TunnelInfo {
        TunnelInfo {
            id: row.id.clone(),
            name: row.name.clone(),
            hostname: row.hostname.clone(),
            public_url: self.public_url(row),
            created,
            kind: row.kind,
            public_port: row.public_port,
            visibility: Some(row.visibility),
            tags: row.tags.clone(),
            access,
            owner_tag,
        }
    }

    /// Readiness check for a port tunnel owned by `agent_id`: opens a data stream to the agent,
    /// as a client connection would, and reports whether the agent reached the local service.
    pub async fn check(&self, agent_id: &str, id: &str) -> Result<(), ErrorBody> {
        let who = Principal::Agent(agent_id.to_string());
        let (header, session) = {
            let st = self.state.lock().unwrap();
            let t = st.tunnels.get(id).filter(|t| st.may(&who, Action::Manage, t)).ok_or_else(|| err(ErrorCode::NotFound, "unknown tunnel"))?;
            let tunnel_id = t.row.id.clone();
            let header = match t.row.kind {
                Kind::Udp => ServerOpen::Datagram { tunnel_id, peer: None },
                _ => ServerOpen::Data { tunnel_id, peer: None },
            };
            let session = st.sessions.get(agent_id).and_then(|l| l.handle());
            (header, session.ok_or_else(|| err(ErrorCode::AgentUnavailable, "agent is not connected"))?)
        };
        let unavailable = |_| err(ErrorCode::AgentUnavailable, "could not open a stream to the agent");
        let mut stream = session.open(Duration::from_secs(10)).await.map_err(unavailable)?;
        let status = async {
            proto::write_frame(&mut stream, &header).await?;
            stream.read_u8().await
        };
        let status = tokio::time::timeout(Duration::from_secs(15), status).await;
        let _ = stream.shutdown().await;
        match status.ok().and_then(Result::ok).and_then(StreamStatus::from_byte) {
            Some(StreamStatus::Ok) => Ok(()),
            Some(StreamStatus::LocalUnreachable) => Err(err(ErrorCode::LocalUnreachable, "the agent could not connect to the local service")),
            Some(StreamStatus::UnknownTunnel) => Err(err(ErrorCode::NotFound, "the agent does not serve this tunnel")),
            Some(StreamStatus::Unsupported) => Err(err(ErrorCode::AgentOutdated, "the agent is too old for this check; update magicpipes")),
            None => Err(err(ErrorCode::AgentUnavailable, "the agent did not answer the check")),
        }
    }

    /// Removes a tunnel on behalf of its owning agent.
    pub fn unregister(&self, agent_id: &str, id: &str) -> Result<(), ErrorBody> {
        let who = Principal::Agent(agent_id.to_string());
        let mut st = self.state.lock().unwrap();
        match st.tunnels.get(id) {
            Some(t) if st.may(&who, Action::Manage, t) => {}
            _ => return Ok(()), // idempotent; never reveal other agents' tunnels
        }
        self.store.delete_tunnel(id).map_err(internal)?;
        st.tunnels.remove(id);
        self.publish(&st);
        tracing::info!(tunnel = %id, agent = %agent_id, "tunnel removed by agent");
        Ok(())
    }

    /// Removes a tunnel on behalf of an administrator and notifies the agent if connected.
    /// Returns false if the tunnel is unknown or `who` may not manage it.
    pub fn delete_tunnel(&self, who: &Principal, id: &str) -> Result<bool, ErrorBody> {
        let mut st = self.state.lock().unwrap();
        let Some(t) = st.tunnels.get(id).filter(|t| st.may(who, Action::Manage, t)) else { return Ok(false) };
        let agent_id = t.row.agent_id.clone();
        self.store.delete_tunnel(id).map_err(internal)?;
        st.tunnels.remove(id);
        self.publish(&st);
        let session = st.sessions.get(&agent_id).and_then(|l| l.handle());
        drop(st);
        tracing::info!(tunnel = %id, "tunnel deleted by administrator");
        self.audit(who, "tunnel.delete", id, "");
        if let Some(handle) = session {
            tell_removed(handle, id.to_string());
        }
        Ok(true)
    }

    /// Certificate readiness for an HTTP tunnel's hostname owned by `agent_id`. Waiting can start
    /// an order, and only HTTP registrations count toward the agent's daily limit, so a port
    /// tunnel's hostname never gets here.
    pub async fn cert_status(&self, agent_id: &str, hostname: &str, wait: Duration) -> Result<CertState, ErrorBody> {
        let who = Principal::Agent(agent_id.to_string());
        let owned = {
            let st = self.state.lock().unwrap();
            st.tunnels.values().any(|t| t.row.kind.is_http() && t.row.hostname == hostname && st.may(&who, Action::Manage, t))
        };
        if !owned {
            return Err(err(ErrorCode::NotFound, "unknown tunnel hostname"));
        }
        Ok(match self.certs.wait(hostname, wait.min(Duration::from_secs(300))).await {
            CertStatus::Ready => CertState::Ready,
            CertStatus::Pending => CertState::Pending,
            CertStatus::Failed(message) => CertState::Failed { message },
        })
    }
}

/// Tells a connected agent that an administrator removed one of its tunnels.
pub(super) fn tell_removed(handle: MuxHandle, tunnel_id: String) {
    tokio::spawn(async move {
        if let Ok(mut s) = handle.open(Duration::from_secs(5)).await {
            let _ = proto::write_frame(&mut s, &ServerOpen::TunnelRemoved { tunnel_id }).await;
            let _ = s.shutdown().await;
        }
    });
}

/// The answer to "may this user into the private tunnel at this host?".
pub enum TunnelSignIn {
    /// Where to send the browser: the tunnel's callback page, with the one-time code in the
    /// fragment.
    Allowed { callback: String },
    Denied,
    NotFound,
}

impl ControlPlane {
    /// For `/auth/tunnel`: whether `who` may connect to the private tunnel at `host`, and if so a
    /// sign-in code bound to the browser's `state` nonce. Only hostnames of published private
    /// tunnels are accepted, so this never redirects anywhere else.
    pub fn tunnel_sign_in(&self, who: &Principal, host: &str, state: &str) -> TunnelSignIn {
        let host = host.trim().to_ascii_lowercase();
        let Principal::User { id, .. } = who else { return TunnelSignIn::Denied };
        let allowed = {
            let st = self.state.lock().unwrap();
            let found = st.tunnels.values().find(|t| {
                t.row.hostname == host && t.row.kind.is_http() && t.row.visibility == Visibility::Private && st.dir.agent_active(&t.row.agent_id)
            });
            match found {
                None => return TunnelSignIn::NotFound,
                Some(t) => st.may(who, Action::Connect, t),
            }
        };
        if !allowed {
            self.audit(who, "tunnel.denied", &host, "");
            return TunnelSignIn::Denied;
        }
        self.audit(who, "tunnel.sign_in", &host, "");
        let code = self.data.signer().code(id, &host, state);
        let enc = |s: &str| s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect::<String>();
        TunnelSignIn::Allowed { callback: format!("{}{}#code={}", self.cfg.public_url(&host), crate::tunnel_auth::CALLBACK_PATH, enc(&code)) }
    }
}
