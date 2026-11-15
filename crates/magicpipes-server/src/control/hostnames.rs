//! Custom hostnames (`magicpipes add --hostname shop.example.com`).
//!
//! An administrator registers an exact hostname and assigns it to a user's machines or to one
//! service agent; only those may serve a tunnel on it, and one tunnel at a time. Registering
//! starts the certificate order, so the certificate can be ready before traffic moves over, and
//! the certificate manager keeps every registered hostname's certificate, with or without a
//! tunnel. Certificates are never ordered for anything else.
//!
//! A registration may be a wildcard, `*.exhub.internal`: its owner's tunnels may then use any
//! name one label under it (`tunnel.exhub.internal`) that has no registration of its own. Each
//! name gets its own certificate when a tunnel takes it, from Let's Encrypt or, under a
//! `[[tls.authorities]]` domain, from this server's CA.

use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::ErrorBody;
use magicpipes_core::rfc3339;
use serde::Serialize;

use super::{ControlPlane, State, TunnelRecord, err, internal};
use crate::certs::CertStatus;
use crate::authz::{self, Action, HostnameAuthz, Principal, Resource};
use crate::config::{Config, TlsMode};
use crate::store::HostnameRow;

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
    /// For a wildcard: the tunnels on names under it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tunnels: Vec<String>,
    /// `ready`, `pending` or `failed`; for a wildcard, the worst of its tunnels'.
    pub tls: &'static str,
    /// The `[[tls.authorities]]` domain whose CA issues its certificates, if one does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    pub created_at: String,
}

/// `raw` lowercased, if it's a hostname of two labels or more (not an address).
fn syntax(raw: &str) -> Option<String> {
    let h = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let label_ok = |l: &str| {
        !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let labels: Vec<&str> = h.split('.').collect();
    let ok = h.len() <= 253 && labels.len() >= 2 && labels.iter().all(|l| label_ok(l)) && !labels.last().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
    ok.then_some(h)
}

/// Checks the hostname a tunnel asks for (`--hostname`): an exact name, and not one of this
/// server's own. Whether it's registered to the machine is for [`State::may_serve`].
pub fn tunnel_hostname(cfg: &Config, raw: &str) -> Result<String, String> {
    let h = syntax(raw).ok_or_else(|| format!("'{}' is not a hostname such as shop.example.com", raw.trim()))?;
    if h == cfg.management.hostname || h == cfg.base_domain {
        return Err(format!("'{h}' is this server's own address"));
    }
    if h.strip_suffix(&format!(".{}", cfg.base_domain)).is_some_and(|name| !name.contains('.')) {
        return Err(format!("'{h}' is a tunnel name under {}; use --name for it", cfg.base_domain));
    }
    Ok(h)
}

/// Checks a hostname an administrator registers: an exact one, or a wildcard for the names one
/// label under a domain (`*.exhub.internal`). Returns it lowercased.
pub fn validate_registration(cfg: &Config, raw: &str) -> Result<String, String> {
    let Some(domain) = raw.trim().strip_prefix("*.") else {
        let h = tunnel_hostname(cfg, raw)?;
        issuable(cfg, &h)?;
        return Ok(h);
    };
    let d = syntax(domain).ok_or_else(|| format!("'{}' is not a wildcard such as *.exhub.internal", raw.trim()))?;
    if d == cfg.base_domain {
        return Err(format!("the names under {d} are tunnel names; use --name for them"));
    }
    issuable(cfg, &d)?;
    Ok(format!("*.{d}"))
}

/// Whether this server can get certificates for `host`, or for the names under it.
fn issuable(cfg: &Config, host: &str) -> Result<(), String> {
    if cfg.tls.authority_for(host).is_some() {
        return Ok(());
    }
    let under = |d: &str| host == d || host.ends_with(&format!(".{d}"));
    // The development CA is name-constrained to the base domain and the management hostname.
    if cfg.tls.mode == TlsMode::DevCa && !under(&cfg.base_domain) && !under(&cfg.management.hostname) {
        return Err(format!("with tls.mode = \"dev-ca\", hostnames must be under {} or a [[tls.authorities]] domain", cfg.base_domain));
    }
    if cfg.tls.mode == TlsMode::Acme && cfg.public.http_listen.is_none() {
        return Err("this server orders no certificates from Let's Encrypt (it has no public.http_listen): use a name under a [[tls.authorities]] domain".into());
    }
    Ok(())
}

fn wildcard_domain(hostname: &str) -> Option<&str> {
    hostname.strip_prefix("*.")
}

impl State {
    /// What `authorize` needs about a registration.
    fn hostname_resource(h: &HostnameRow) -> Resource<'_> {
        Resource::Hostname(HostnameAuthz { owner_user_id: h.owner_user_id.as_deref(), agent_id: h.agent_id.as_deref() })
    }

    /// The registration that lets a tunnel serve `host`: its own, else the wildcard one label up.
    pub(super) fn registration_for(&self, host: &str) -> Option<&HostnameRow> {
        self.dir.hostname(host).or_else(|| self.dir.hostname(&format!("*.{}", host.split_once('.')?.1)))
    }

    /// The tunnels a registration lets serve: on its name, or for a wildcard, on the names under
    /// it that have no registration of their own.
    fn tunnels_on(&self, hostname: &str) -> Vec<&TunnelRecord> {
        let mut on: Vec<&TunnelRecord> = self
            .tunnels
            .values()
            .filter(|t| t.row.hostname == hostname || (wildcard_domain(hostname).is_some() && self.registration_for(&t.row.hostname).is_some_and(|r| r.hostname == hostname)))
            .collect();
        on.sort_by(|a, b| a.row.name.cmp(&b.row.name));
        on
    }

    /// May `agent_id` serve a tunnel on `hostname`? A personal agent asks as its owner (without
    /// an administrator's role), a service agent as itself.
    pub(super) fn may_serve(&self, agent_id: &str, hostname: &str) -> bool {
        let who = match self.dir.owner(agent_id) {
            Some(owner) => Principal::User { id: owner.to_string(), role: authz::Role::Member, tags: Vec::new() },
            None => Principal::Agent(agent_id.to_string()),
        };
        self.registration_for(hostname).is_some_and(|h| authz::authorize(&who, Action::Manage, Self::hostname_resource(h)))
    }
}

impl ControlPlane {
    /// The hostnames `who` may see: all for administrators, their own for others.
    pub fn hostnames(&self, who: &Principal) -> Vec<HostnameView> {
        let st = self.state.lock().unwrap();
        st.dir
            .hostnames()
            .filter(|h| authz::authorize(who, Action::Discover, State::hostname_resource(h)))
            .map(|h| {
                let on_it = st.tunnels_on(&h.hostname);
                let names: Vec<String> = on_it.iter().map(|t| t.row.name.clone()).collect();
                let wildcard = wildcard_domain(&h.hostname);
                let tls = match wildcard {
                    None => self.certs.status(&h.hostname),
                    Some(_) => {
                        let all: Vec<CertStatus> = on_it.iter().map(|t| self.certs.status(&t.row.hostname)).collect();
                        let worst = all.iter().find(|s| matches!(s, CertStatus::Failed(_))).or_else(|| all.iter().find(|s| **s == CertStatus::Pending));
                        worst.cloned().unwrap_or(CertStatus::Ready)
                    }
                };
                HostnameView {
                    hostname: h.hostname.clone(),
                    owner_user_id: h.owner_user_id.clone(),
                    owner_email: h.owner_user_id.as_deref().and_then(|u| st.dir.email(u)).map(str::to_string),
                    agent_id: h.agent_id.clone(),
                    agent_name: h.agent_id.as_deref().and_then(|a| st.dir.agent(a)).map(|a| a.name.clone()),
                    tunnel: if wildcard.is_none() { names.first().cloned() } else { None },
                    tunnels: if wildcard.is_some() { names } else { Vec::new() },
                    tls: tls.label(),
                    authority: self.certs.authority_of(&h.hostname),
                    created_at: rfc3339(h.created_at),
                }
            })
            .collect()
    }

    /// Registers `hostname` for a user's machines or for a service agent (administrators only),
    /// and starts its certificate.
    pub fn create_hostname(&self, who: &Principal, hostname: &str, owner_user_id: Option<&str>, agent_id: Option<&str>) -> Result<HostnameView, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(err(ErrorCode::Forbidden, "only administrators register hostnames"));
        }
        let hostname = validate_registration(&self.cfg, hostname).map_err(|m| err(ErrorCode::InvalidRequest, m))?;
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
        // A name a tunnel already serves under a wildcard stays with that tunnel's owner.
        {
            let st = self.state.lock().unwrap();
            if let Some(t) = st.tunnels.values().find(|t| t.row.hostname == hostname) {
                let same = match (owner_user_id, agent_id) {
                    (Some(u), None) => st.dir.owner(&t.row.agent_id) == Some(u),
                    (None, Some(a)) => t.row.agent_id == a,
                    _ => false,
                };
                if !same {
                    return Err(err(ErrorCode::InvalidRequest, format!("tunnel '{}' serves {hostname} already, under a wildcard; remove that tunnel first", t.row.name)));
                }
            }
        }
        let created_by = matches!(who, Principal::User { .. }).then(|| who.actor());
        if !self.store.create_hostname(&hostname, owner_user_id, agent_id, created_by).map_err(internal)? {
            return Err(err(ErrorCode::InvalidRequest, format!("'{hostname}' is registered already, or there are {} hostnames", crate::store::MAX_HOSTNAMES)));
        }
        self.audit(who, "hostname.create", &hostname, owner_user_id.or(agent_id).unwrap_or(""));
        self.refresh();
        // A wildcard's names get theirs as tunnels take them.
        if wildcard_domain(&hostname).is_none() {
            self.certs.ensure(&hostname);
        }
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
            let removed: Vec<(String, String)> = st.tunnels_on(&hostname).into_iter().map(|t| (t.row.id.clone(), t.row.agent_id.clone())).collect();
            let ids: Vec<String> = removed.iter().map(|(id, _)| id.clone()).collect();
            if !self.store.delete_hostname(&hostname, &ids).map_err(internal)? {
                return Ok(false);
            }
            st.tunnels.retain(|id, _| !ids.contains(id));
            removed.into_iter().flat_map(|(id, agent)| st.sessions.get(&agent).map(|l| l.handles()).unwrap_or_default().into_iter().map(move |h| (id.clone(), h))).collect::<Vec<_>>()
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

    fn cfg(mode: &str, extra: &str) -> Config {
        let mut c: Config = toml::from_str(&format!(
            "base_domain = \"t.example.com\"\n[public]\nhttp_listen = \"0.0.0.0:80\"\n[management]\nhostname = \"example.com\"\n[tls]\nmode = \"{mode}\"\n{extra}"
        ))
        .unwrap();
        c.validate().unwrap();
        c
    }

    #[test]
    fn hostnames_are_checked() {
        let acme = cfg("acme", "");
        for (raw, want) in [("Shop.Example.org.", "shop.example.org"), ("sonasora.com", "sonasora.com"), ("a.b.t.example.com", "a.b.t.example.com")] {
            assert_eq!(validate_registration(&acme, raw).unwrap(), want, "{raw}");
        }
        for bad in ["localhost", "-x.example.org", "x-.example.org", "a..b", "1.2.3.4", "ex ample.org", "example.com", "t.example.com", "app.t.example.com", "é.example.org"] {
            assert!(validate_registration(&acme, bad).is_err(), "{bad}");
        }
        assert!(validate_registration(&acme, &format!("{}.org", "a".repeat(64))).is_err());
        let dev = cfg("dev-ca", "");
        assert!(validate_registration(&dev, "sonasora.com").is_err(), "the dev CA can't issue it");
        assert!(validate_registration(&dev, "shop.app.t.example.com").is_ok());
    }

    #[test]
    fn wildcards_cover_a_domain_one_label_down() {
        let acme = cfg("acme", "");
        assert_eq!(validate_registration(&acme, " *.Exhub.Example.ORG. ").unwrap(), "*.exhub.example.org");
        assert_eq!(validate_registration(&acme, "*.app.t.example.com").unwrap(), "*.app.t.example.com", "names two labels under the base domain");
        for bad in ["*.t.example.com", "*.org", "*.*.example.org", "*", "*.", "a.*.example.org", "*.1.2.3.4", "**.example.org"] {
            assert!(validate_registration(&acme, bad).is_err(), "{bad}");
        }
        // A tunnel asks for an exact name, never the wildcard itself.
        assert!(tunnel_hostname(&acme, "*.exhub.example.org").is_err());
        assert_eq!(tunnel_hostname(&acme, "Tunnel.Exhub.Example.org").unwrap(), "tunnel.exhub.example.org");
    }

    #[test]
    fn an_authority_issues_for_its_domain_whatever_the_mode() {
        let authority = "[[tls.authorities]]\ndomain = \"exhub.internal\"";
        let dev = cfg("dev-ca", authority);
        assert!(validate_registration(&dev, "*.exhub.internal").is_ok(), "the authority issues, not the dev CA");
        assert!(validate_registration(&dev, "a.b.exhub.internal").is_ok());
        assert!(validate_registration(&dev, "*.other.internal").is_err());
        // A closed network: authorities for the server's own names, and no Let's Encrypt.
        let mut closed: Config = toml::from_str(
            "base_domain = \"t.exhub.internal\"\n[management]\nhostname = \"mp.exhub.internal\"\n[[tls.authorities]]\ndomain = \"exhub.internal\"",
        )
        .unwrap();
        closed.public.http_listen = None;
        closed.validate().unwrap();
        assert!(validate_registration(&closed, "*.lab.exhub.internal").is_ok());
        let said = validate_registration(&closed, "shop.example.com").unwrap_err();
        assert!(said.contains("no certificates from Let's Encrypt"), "{said}");
    }
}
