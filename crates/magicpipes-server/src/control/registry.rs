//! The tunnel registry: registering, checking and removing tunnels.

use std::sync::Arc;
use std::time::{Duration, Instant};

use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::{self, CertState, ErrorBody, Kind, RegisterTunnel, ServerOpen, StreamStatus, TunnelInfo};
use magicpipes_core::{cidr, names, secret, unix_now};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{CERT_ORDER_WINDOW, ControlPlane, State, TunnelRecord, err, internal, may};
use crate::authz::{Action, Principal};
use crate::certs::CertStatus;
use crate::config::{PortRange, TlsMode};
use crate::store::TunnelRow;

impl ControlPlane {
    pub fn register(&self, agent_id: &str, req: &RegisterTunnel) -> Result<TunnelInfo, ErrorBody> {
        let who = Principal::Agent(agent_id.to_string());
        let target: String = req.target.chars().filter(|c| !c.is_control()).take(200).collect();
        let allow: Vec<String> = cidr::parse_list(&req.allow)
            .map_err(|m| err(ErrorCode::InvalidCidr, m))?
            .iter()
            .map(ToString::to_string)
            .collect();
        let range = match req.kind {
            Kind::Http if req.remote_port.is_some() || !allow.is_empty() => {
                return Err(err(ErrorCode::InvalidRequest, "a remote port and an allow-list apply only to TCP and UDP tunnels"));
            }
            Kind::Http => None,
            _ => Some(self.cfg.port_range().ok_or_else(|| {
                err(ErrorCode::PortsDisabled, "this server does not offer TCP or UDP ports (its configuration has no [ports] range)")
            })?),
        };
        if let (Some(r), Some(p)) = (range, req.remote_port)
            && !r.contains(p)
        {
            return Err(err(ErrorCode::PortUnavailable, format!("port {p} is outside this server's port range {}-{}", r.first, r.last)));
        }
        let mut st = self.state.lock().unwrap();

        let existing = match (&req.id, &req.name) {
            (Some(id), _) => match st.tunnels.get(id) {
                Some(t) if may(&who, Action::Manage, t) => Some(id.clone()),
                _ => return Err(err(ErrorCode::NotFound, "tunnel no longer exists on the server")),
            },
            (None, Some(name)) => {
                let name = names::validate(name).map_err(|m| err(ErrorCode::InvalidName, m))?;
                match st.tunnels.values().find(|t| t.row.name == name) {
                    Some(t) if may(&who, Action::Manage, t) => Some(t.row.id.clone()),
                    Some(_) => return Err(err(ErrorCode::NameTaken, format!("the name '{name}' is used by another agent"))),
                    None => None,
                }
            }
            (None, None) => None,
        };

        if let Some(id) = existing {
            let mut row = st.tunnels[&id].row.clone();
            if row.kind != req.kind {
                return Err(err(
                    ErrorCode::KindMismatch,
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
            return Err(err(ErrorCode::LimitReached, format!("an agent may own at most {} tunnels", self.cfg.agents.max_tunnels_per_agent)));
        }
        let max_ports = self.cfg.agents.max_ports_per_agent;
        if range.is_some() && st.tunnels.values().filter(|t| t.row.agent_id == agent_id && t.row.public_port.is_some()).count() >= max_ports {
            return Err(err(ErrorCode::LimitReached, format!("an agent may hold at most {max_ports} public ports")));
        }

        let name = match &req.name {
            Some(n) => names::validate(n).map_err(|m| err(ErrorCode::InvalidName, m))?,
            None => (0..10)
                .map(names::random)
                .find(|n| !st.tunnels.values().any(|t| &t.row.name == n))
                .ok_or_else(|| err(ErrorCode::Internal, "could not allocate a tunnel name"))?,
        };
        let hostname = self.cfg.hostname_for(&name);
        if hostname == self.cfg.management.hostname {
            return Err(err(ErrorCode::InvalidName, format!("'{name}' is reserved")));
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
        if new_cert {
            st.cert_orders.entry(agent_id.to_string()).or_default().push(Instant::now());
        }
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
        let who = Principal::Agent(agent_id.to_string());
        let (header, session) = {
            let st = self.state.lock().unwrap();
            let t = st.tunnels.get(id).filter(|t| may(&who, Action::Manage, t)).ok_or_else(|| err(ErrorCode::NotFound, "unknown tunnel"))?;
            let tunnel_id = t.row.id.clone();
            let header = match t.row.kind {
                Kind::Udp => ServerOpen::Datagram { tunnel_id, peer: None },
                _ => ServerOpen::Data { tunnel_id, peer: None },
            };
            let session = st.sessions.get(agent_id).map(|s| s.handle.clone());
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
            Some(t) if may(&who, Action::Manage, t) => {}
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
        let Some(t) = st.tunnels.get(id).filter(|t| may(who, Action::Manage, t)) else { return Ok(false) };
        let agent_id = t.row.agent_id.clone();
        self.store.delete_tunnel(id).map_err(internal)?;
        st.tunnels.remove(id);
        self.publish(&st);
        let session = st.sessions.get(&agent_id).map(|s| s.handle.clone());
        drop(st);
        tracing::info!(tunnel = %id, "tunnel deleted by administrator");
        self.audit(who, "tunnel.delete", id, "");
        if let Some(handle) = session {
            let tunnel_id = id.to_string();
            tokio::spawn(async move {
                if let Ok(mut s) = handle.open(Duration::from_secs(5)).await {
                    let _ = proto::write_frame(&mut s, &ServerOpen::TunnelRemoved { tunnel_id }).await;
                    let _ = s.shutdown().await;
                }
            });
        }
        Ok(true)
    }

    /// Certificate readiness for a hostname owned by `agent_id`.
    pub async fn cert_status(&self, agent_id: &str, hostname: &str, wait: Duration) -> Result<CertState, ErrorBody> {
        let who = Principal::Agent(agent_id.to_string());
        let owned = self.state.lock().unwrap().tunnels.values().any(|t| t.row.hostname == hostname && may(&who, Action::Manage, t));
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
