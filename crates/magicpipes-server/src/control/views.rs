//! What the management API and UI show. Every list is filtered by [`authz::authorize`].

use magicpipes_core::proto::{Kind, Visibility};
use magicpipes_core::rfc3339;
use serde::Serialize;

use super::{ControlPlane, State, TunnelRecord};
use crate::authz::{self, Action, Principal, Resource};
use crate::certs::CertStatus;
use crate::data::Outcome;

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
    pub visibility: Visibility,
    /// Private tunnels: the access tags in effect (limited to the agent's); empty = owner only.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub access: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
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
    /// The connected agent's protocol version (1 for agents that predate the handshake).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<u32>,
    /// The user the agent belongs to; absent for a service agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_email: Option<String>,
    /// Access tags in effect (a personal agent's are limited to its owner's).
    pub tags: Vec<String>,
    pub labels: Vec<String>,
    /// May its tunnels be public?
    pub allow_public: bool,
    /// Are its tunnels private unless asked otherwise?
    pub default_private: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<String>,
    pub tunnels: usize,
    pub created_at: String,
}

/// A tunnel shared with someone who doesn't manage it: no target, agent or statistics.
#[derive(Debug, Clone, Serialize)]
pub struct SharedTunnelView {
    pub name: String,
    pub public_url: String,
    pub kind: Kind,
    pub visibility: Visibility,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_email: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
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

impl ControlPlane {
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
            visibility: t.row.visibility,
            access: if t.row.visibility == Visibility::Private { st.tunnel_authz(t).access } else { Vec::new() },
            labels: t.row.labels.clone(),
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

    /// The tunnels `who` manages.
    pub fn tunnels(&self, who: &Principal) -> Vec<TunnelView> {
        let st = self.state.lock().unwrap();
        let mut v: Vec<_> = st.tunnels.values().filter(|t| st.may(who, Action::Manage, t)).map(|t| self.view(&st, t)).collect();
        v.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.name.cmp(&b.name)));
        v
    }

    /// Tunnels `who` can reach but doesn't manage: shared with one of their tags, or public.
    pub fn shared(&self, who: &Principal) -> Vec<SharedTunnelView> {
        let st = self.state.lock().unwrap();
        let mut v: Vec<SharedTunnelView> = st
            .tunnels
            .values()
            .filter(|t| st.dir.agent_active(&t.row.agent_id) && !st.may(who, Action::Manage, t) && st.may(who, Action::Discover, t))
            .map(|t| SharedTunnelView {
                name: t.row.name.clone(),
                public_url: self.public_url(&t.row),
                kind: t.row.kind,
                visibility: t.row.visibility,
                owner_email: st.dir.owner(&t.row.agent_id).and_then(|o| st.dir.email(o)).map(str::to_string),
                labels: t.row.labels.clone(),
            })
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    pub fn tunnel(&self, who: &Principal, id_or_name: &str) -> Option<TunnelView> {
        let st = self.state.lock().unwrap();
        st.tunnels
            .values()
            .find(|t| t.row.id == id_or_name || t.row.name == id_or_name)
            .filter(|t| st.may(who, Action::Manage, t))
            .map(|t| self.view(&st, t))
    }

    /// The agents `who` manages.
    pub fn agents(&self, who: &Principal) -> Vec<AgentView> {
        let rows = self.store.agents().unwrap_or_default();
        let st = self.state.lock().unwrap();
        rows.into_iter()
            .filter(|a| authz::authorize(who, Action::Manage, st.agent_resource(&a.id)))
            .map(|a| {
                let s = st.sessions.get(&a.id);
                AgentView {
                    connected: s.is_some(),
                    remote_addr: s.map(|s| s.remote.to_string()),
                    connected_at: s.map(|s| rfc3339(s.connected_at)),
                    protocol: s.map(|s| s.protocol),
                    owner_email: a.owner_user_id.as_deref().and_then(|u| st.dir.email(u)).map(str::to_string),
                    tags: st.dir.agent_tags(&a.id),
                    labels: a.labels,
                    allow_public: a.allow_public,
                    default_private: a.default_private,
                    owner_user_id: a.owner_user_id,
                    last_seen_at: a.last_seen_at.map(rfc3339),
                    tunnels: st.tunnels.values().filter(|t| t.row.agent_id == a.id).count(),
                    created_at: rfc3339(a.created_at),
                    id: a.id,
                    name: a.name,
                }
            })
            .collect()
    }

    pub fn agent_name(&self, who: &Principal, agent_id: &str) -> Option<String> {
        let st = self.state.lock().unwrap();
        if !authz::authorize(who, Action::Discover, st.agent_resource(agent_id)) {
            return None;
        }
        st.dir.agent(agent_id).map(|a| a.name.clone())
    }

    pub fn status(&self, who: &Principal) -> Option<StatusView> {
        if !authz::authorize(who, Action::Discover, Resource::Org) {
            return None;
        }
        let st = self.state.lock().unwrap();
        Some(StatusView {
            version: magicpipes_core::VERSION,
            base_domain: self.cfg.base_domain.clone(),
            management_hostname: self.cfg.management.hostname.clone(),
            started_at: rfc3339(self.started_at),
            tunnels: st.tunnels.len(),
            agents_connected: st.sessions.len(),
        })
    }
}
