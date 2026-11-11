//! The sampler behind history ([`super::history`]), and what the Health, tunnel and machine pages
//! show of it. Every view goes through `authorize`, by way of the lists `who` may see.

use std::sync::atomic::Ordering::Relaxed;

use magicpipes_core::unix_now;

use super::history::{Counters, Link as LinkNow, Period, Presence, Series, Traffic};
use super::views::{AgentView, TunnelView};
use super::{ControlPlane, Link};
use crate::authz::{self, Action, Principal};

/// A certificate is worth a word from this long before it expires. One from Let's Encrypt is
/// renewed with 30 days left, so this is two weeks of failed renewals.
pub const EXPIRING_WITHIN_SECS: i64 = 14 * 24 * 3600;

/// A machine on the Health page.
pub struct MachineHealth {
    pub agent: AgentView,
    pub recent: Series<Presence>,
}

/// A tunnel on the Health page.
pub struct TunnelHealth {
    pub tunnel: TunnelView,
    pub machine: String,
    pub recent: Series<Traffic>,
}

/// A certificate in trouble, or expiring within [`EXPIRING_WITHIN_SECS`].
pub struct CertificateHealth {
    pub hostname: String,
    pub tunnel_id: String,
    pub tunnel: String,
    /// `failed`, `pending` or `ready` (then expiring soon).
    pub state: &'static str,
    pub error: Option<String>,
    pub not_after: Option<i64>,
}

pub struct HealthView {
    pub machines: Vec<MachineHealth>,
    pub tunnels: Vec<TunnelHealth>,
    pub certificates: Vec<CertificateHealth>,
    pub period: Period,
    /// When history began, if within the period.
    pub since: Option<i64>,
    pub now: i64,
}

impl ControlPlane {
    /// Takes a sample of every tunnel's counters and every agent's connections ([`super::history`]).
    pub(super) fn sample(&self) {
        let (tunnels, agents) = {
            let st = self.state.lock().unwrap();
            let tunnels: Vec<_> = st.tunnels.iter().map(|(id, t)| (id.clone(), Counters::read(&t.stats))).collect();
            let agents: Vec<_> = st.dir.agents().map(|a| (a.id.clone(), st.sessions.get(&a.id).and_then(link_now))).collect();
            (tunnels, agents)
        };
        self.history.lock().unwrap().record(unix_now(), &tunnels, &agents);
    }

    /// Machines, tunnels and certificates `who` manages, with their history over `period`.
    pub fn health(&self, who: &Principal, period: Period) -> HealthView {
        let agents = self.agents(who);
        let tunnels = self.tunnels(who);
        let now = unix_now();
        let certificates = tunnels
            .iter()
            .filter(|t| t.kind.is_http())
            .filter_map(|t| {
                let not_after = self.certs.not_after(&t.hostname);
                let expiring = not_after.is_some_and(|at| at - now < EXPIRING_WITHIN_SECS);
                (t.tls != "ready" || expiring).then(|| CertificateHealth {
                    hostname: t.hostname.clone(),
                    tunnel_id: t.id.clone(),
                    tunnel: t.name.clone(),
                    state: t.tls,
                    error: t.tls_error.clone(),
                    not_after,
                })
            })
            .collect();
        let history = self.history.lock().unwrap();
        let machine_name = |id: &str| agents.iter().find(|a| a.id == id).map_or_else(|| id.to_string(), |a| a.name.clone());
        let tunnels: Vec<TunnelHealth> = tunnels
            .into_iter()
            .map(|t| TunnelHealth { machine: machine_name(&t.agent_id), recent: history.tunnel(&t.id, period, now), tunnel: t })
            .collect();
        let machines = agents
            .into_iter()
            .map(|a| MachineHealth { recent: history.agent(&a.id, period, now), agent: a })
            .collect();
        let since = history.since(period, now);
        HealthView { machines, tunnels, certificates, period, since, now }
    }

    /// A tunnel's history over `period`, if `who` manages it.
    pub fn tunnel_history(&self, who: &Principal, id_or_name: &str, period: Period) -> Option<Series<Traffic>> {
        let t = self.tunnel(who, id_or_name)?;
        Some(self.history.lock().unwrap().tunnel(&t.id, period, unix_now()))
    }

    /// A machine's history over `period`, if `who` manages it.
    pub fn agent_history(&self, who: &Principal, agent_id: &str, period: Period) -> Option<Series<Presence>> {
        let allowed = {
            let st = self.state.lock().unwrap();
            st.dir.agent(agent_id).is_some() && authz::authorize(who, Action::Manage, st.agent_resource(agent_id))
        };
        allowed.then(|| self.history.lock().unwrap().agent(agent_id, period, unix_now()))
    }
}

/// An agent's connections now, if any is open.
fn link_now(link: &Link) -> Option<LinkNow> {
    let open: Vec<_> = link.lanes.iter().filter(|s| !s.handle.is_closed()).collect();
    if open.is_empty() {
        return None;
    }
    let trips: Vec<u64> = open.iter().map(|s| s.round_trip.load(Relaxed)).filter(|t| *t > 0).collect();
    let round_trip = if trips.is_empty() { 0 } else { trips.iter().sum::<u64>() / trips.len() as u64 };
    Some(LinkNow { connections: u8::try_from(open.len()).unwrap_or(u8::MAX), round_trip: u32::try_from(round_trip).unwrap_or(u32::MAX) })
}
