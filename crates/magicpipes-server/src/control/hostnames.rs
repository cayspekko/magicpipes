//! Custom hostnames (`magicpipes add --hostname shop.example.com`).
//!
//! An administrator registers an exact hostname and assigns it to a user's machines or to one
//! service agent; only those may serve a tunnel on it, and one tunnel at a time. Registering
//! starts the certificate order, so the certificate can be ready before traffic moves over, and
//! the certificate manager keeps every registered hostname's certificate, with or without a
//! tunnel. Certificates are never ordered for anything else.

use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::ErrorBody;
use magicpipes_core::rfc3339;
use serde::Serialize;

use super::{ControlPlane, State, err, internal};
use crate::authz::{self, Action, HostnameAuthz, Principal, Resource};
use crate::config::{Config, TlsMode};

#[derive(Debug, Clone, Serialize)]
pub struct HostnameView {
    pub hostname: String,
    /// The user whose machines may serve it, or else the service agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    /// The tunnel on it, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<String>,
    /// `ready`, `pending` or `failed`.
    pub tls: &'static str,
    pub created_at: String,
}

/// Checks a hostname an administrator registers; returns it lowercased.
pub fn validate(cfg: &Config, raw: &str) -> Result<String, String> {
    let h = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let label_ok = |l: &str| {
        !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let labels: Vec<&str> = h.split('.').collect();
    if h.len() > 253 || labels.len() < 2 || !labels.iter().all(|l| label_ok(l)) || labels.last().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit())) {
        return Err(format!("'{}' is not a hostname such as shop.example.com", raw.trim()));
    }
    if h == cfg.management.hostname || h == cfg.base_domain {
        return Err(format!("'{h}' is this server's own address"));
    }
    let base = format!(".{}", cfg.base_domain);
    if h.strip_suffix(&base).is_some_and(|name| !name.contains('.')) {
        return Err(format!("'{h}' is a tunnel name under {}; use --name for it", cfg.base_domain));
    }
    // The development CA is name-constrained to the base domain and the management hostname.
    if cfg.tls.mode == TlsMode::DevCa && !h.ends_with(&base) && !h.ends_with(&format!(".{}", cfg.management.hostname)) {
        return Err(format!("with tls.mode = \"dev-ca\", hostnames must be under {}", cfg.base_domain));
    }
    Ok(h)
}

impl State {
    /// What `authorize` needs about a registered hostname.
    pub(super) fn hostname_resource<'a>(&'a self, hostname: &str) -> Option<Resource<'a>> {
        self.dir.hostname(hostname).map(|h| Resource::Hostname(HostnameAuthz { owner_user_id: h.owner_user_id.as_deref(), agent_id: h.agent_id.as_deref() }))
    }

    /// May `agent_id` serve a tunnel on `hostname`? A personal agent asks as its owner (without
    /// an administrator's role), a service agent as itself.
    pub(super) fn may_serve(&self, agent_id: &str, hostname: &str) -> bool {
        let who = match self.dir.owner(agent_id) {
            Some(owner) => Principal::User { id: owner.to_string(), role: authz::Role::Member, tags: Vec::new() },
            None => Principal::Agent(agent_id.to_string()),
        };
        self.hostname_resource(hostname).is_some_and(|r| authz::authorize(&who, Action::Manage, r))
    }
}

impl ControlPlane {
    /// The hostnames `who` may see: all for administrators, their own for others.
    pub fn hostnames(&self, who: &Principal) -> Vec<HostnameView> {
        let st = self.state.lock().unwrap();
        st.dir
            .hostnames()
            .filter(|h| st.hostname_resource(&h.hostname).is_some_and(|r| authz::authorize(who, Action::Discover, r)))
            .map(|h| HostnameView {
                hostname: h.hostname.clone(),
                owner_user_id: h.owner_user_id.clone(),
                owner_email: h.owner_user_id.as_deref().and_then(|u| st.dir.email(u)).map(str::to_string),
                agent_id: h.agent_id.clone(),
                agent_name: h.agent_id.as_deref().and_then(|a| st.dir.agent(a)).map(|a| a.name.clone()),
                tunnel: st.tunnels.values().find(|t| t.row.hostname == h.hostname).map(|t| t.row.name.clone()),
                tls: self.certs.status(&h.hostname).label(),
                created_at: rfc3339(h.created_at),
            })
            .collect()
    }

    /// Registers `hostname` for a user's machines or for a service agent (administrators only),
    /// and starts its certificate.
    pub fn create_hostname(&self, who: &Principal, hostname: &str, owner_user_id: Option<&str>, agent_id: Option<&str>) -> Result<HostnameView, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(err(ErrorCode::Forbidden, "only administrators register hostnames"));
        }
        let hostname = validate(&self.cfg, hostname).map_err(|m| err(ErrorCode::InvalidRequest, m))?;
        match (owner_user_id, agent_id) {
            (Some(user), None) => {
                if self.store.user(user).map_err(internal)?.is_none() {
                    return Err(err(ErrorCode::NotFound, "no such user"));
                }
            }
            (None, Some(agent)) => {
                let st = self.state.lock().unwrap();
                match st.dir.agent(agent) {
                    None => return Err(err(ErrorCode::NotFound, "no such agent")),
                    Some(a) if a.owner_user_id.is_some() => {
                        return Err(err(ErrorCode::InvalidRequest, "that machine belongs to a user: assign the hostname to them instead"));
                    }
                    Some(_) => {}
                }
            }
            _ => return Err(err(ErrorCode::InvalidRequest, "assign the hostname to one user or one service agent")),
        }
        let created_by = matches!(who, Principal::User { .. }).then(|| who.actor());
        if !self.store.create_hostname(&hostname, owner_user_id, agent_id, created_by).map_err(internal)? {
            return Err(err(ErrorCode::InvalidRequest, format!("'{hostname}' is registered already, or there are {} hostnames", crate::store::MAX_HOSTNAMES)));
        }
        self.audit(who, "hostname.create", &hostname, owner_user_id.or(agent_id).unwrap_or(""));
        self.refresh();
        self.certs.ensure(&hostname);
        self.hostnames(who).into_iter().find(|h| h.hostname == hostname).ok_or_else(|| err(ErrorCode::Internal, "hostname not found after creating it"))
    }

    /// Removes a hostname's registration and the tunnel on it (administrators only).
    pub fn delete_hostname(&self, who: &Principal, hostname: &str) -> Result<bool, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(err(ErrorCode::Forbidden, "only administrators remove hostnames"));
        }
        let hostname = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
        let removed = {
            let mut st = self.state.lock().unwrap();
            let removed: Vec<(String, String)> =
                st.tunnels.values().filter(|t| t.row.hostname == hostname).map(|t| (t.row.id.clone(), t.row.agent_id.clone())).collect();
            if !self.store.delete_hostname(&hostname).map_err(internal)? {
                return Ok(false);
            }
            st.tunnels.retain(|_, t| t.row.hostname != hostname);
            removed.into_iter().filter_map(|(id, agent)| st.sessions.get(&agent).and_then(|l| l.handle()).map(|h| (id, h))).collect::<Vec<_>>()
        };
        for (id, handle) in removed {
            super::registry::tell_removed(handle, id);
        }
        self.audit(who, "hostname.delete", &hostname, "");
        self.refresh();
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(mode: &str) -> Config {
        let mut c: Config =
            toml::from_str(&format!("base_domain = \"t.example.com\"\n[management]\nhostname = \"example.com\"\n[tls]\nmode = \"{mode}\"")).unwrap();
        c.validate().unwrap();
        c
    }

    #[test]
    fn hostnames_are_checked() {
        let acme = cfg("acme");
        for (raw, want) in [("Shop.Example.org.", "shop.example.org"), ("sonasora.com", "sonasora.com"), ("a.b.t.example.com", "a.b.t.example.com")] {
            assert_eq!(validate(&acme, raw).unwrap(), want, "{raw}");
        }
        for bad in ["localhost", "-x.example.org", "x-.example.org", "a..b", "1.2.3.4", "ex ample.org", "example.com", "t.example.com", "app.t.example.com", "é.example.org"] {
            assert!(validate(&acme, bad).is_err(), "{bad}");
        }
        assert!(validate(&acme, &format!("{}.org", "a".repeat(64))).is_err());
        let dev = cfg("dev-ca");
        assert!(validate(&dev, "sonasora.com").is_err(), "the dev CA can't issue it");
        assert!(validate(&dev, "shop.app.t.example.com").is_ok());
    }
}
