//! The sampler behind history ([`super::history`]), and what the Health, tunnel and machine pages
//! show of it. Every view goes through `authorize`, by way of the lists `who` may see.

use std::sync::atomic::Ordering::Relaxed;

use magicpipes_core::unix_now;

use super::history::{COARSE_SECS, COARSE_SLOTS, Counters, Link as LinkNow, Period, Presence, Series, Traffic};
use super::views::{AgentView, TunnelView};
use super::{ControlPlane, Link, OrLog};
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
    /// Open alerts, the worst and oldest first; and those closed in the last 24 hours.
    pub alerts: Vec<super::alerts::AlertView>,
    pub closed: Vec<super::alerts::AlertView>,
    pub machines: Vec<MachineHealth>,
    pub tunnels: Vec<TunnelHealth>,
    pub certificates: Vec<CertificateHealth>,
    pub period: Period,
    pub history_days: u32,
    /// When history began, if within the period.
    pub since: Option<i64>,
    pub now: i64,
}

impl ControlPlane {
    /// Fills the last 24 hours in memory from the database, at startup.
    pub(super) fn load_history(&self) {
        let now = unix_now();
        let from = now - COARSE_SECS * COARSE_SLOTS as i64;
        let tunnels = self.store.tunnel_history_since(from).or_log().unwrap_or_default();
        let agents = self.store.agent_history_since(from).or_log().unwrap_or_default();
        let oldest = self.store.oldest_history().or_log().flatten();
        self.history.lock().unwrap().load(now, tunnels, agents, oldest);
    }

    /// Takes a sample of every tunnel's counters and every agent's connections ([`super::history`]),
    /// and keeps the 5-minute slots that closed in the database.
    pub(super) fn sample(&self) {
        let now = unix_now();
        let (tunnels, agents) = {
            let st = self.state.lock().unwrap();
            let tunnels: Vec<_> = st.tunnels.iter().map(|(id, t)| (id.clone(), Counters::read(&t.stats))).collect();
            let agents: Vec<_> = st.dir.agents().map(|a| (a.id.clone(), st.sessions.get(&a.id).and_then(link_now))).collect();
            (tunnels, agents)
        };
        let closed = self.history.lock().unwrap().record(now, &tunnels, &agents);
        self.store.save_history(&closed.tunnels, &closed.agents).or_log();
        self.judge(now);
    }

    /// Forgets history older than `monitoring.history_days`.
    pub(super) fn prune_history(&self) {
        let before = unix_now() - i64::from(self.cfg.monitoring.history_days) * 86_400;
        self.store.prune_history(before).or_log();
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
        // Longer periods come from the database, read before taking the history's lock.
        let (stored_tunnels, stored_agents) = if period.stored() {
            let from = period.first_slot_at(now);
            (
                self.store.tunnel_history_by(from, period.slot_secs(), None).or_log().unwrap_or_default(),
                self.store.agent_history_by(from, period.slot_secs(), None).or_log().unwrap_or_default(),
            )
        } else {
            Default::default()
        };
        let history = self.history.lock().unwrap();
        let since = history.since(period, now);
        let machine_name = |id: &str| agents.iter().find(|a| a.id == id).map_or_else(|| id.to_string(), |a| a.name.clone());
        let tunnels: Vec<TunnelHealth> = tunnels
            .into_iter()
            .map(|t| {
                let recent = if period.stored() {
                    let slots = stored_tunnels.get(&t.id).map(Vec::as_slice).unwrap_or_default();
                    Series::from_slots(period, slots, history.open_tunnel(&t.id, now), now, since, Traffic::add)
                } else {
                    history.tunnel(&t.id, period, now)
                };
                TunnelHealth { machine: machine_name(&t.agent_id), recent, tunnel: t }
            })
            .collect();
        let machines = agents
            .into_iter()
            .map(|a| {
                let recent = if period.stored() {
                    let slots = stored_agents.get(&a.id).map(Vec::as_slice).unwrap_or_default();
                    Series::from_slots(period, slots, history.open_agent(&a.id, now), now, since, Presence::add)
                } else {
                    history.agent(&a.id, period, now)
                };
                MachineHealth { recent, agent: a }
            })
            .collect();
        drop(history);
        let alerts = self.alerts(who);
        let closed = self.closed_alerts(who, now - 86_400);
        HealthView { alerts, closed, machines, tunnels, certificates, period, history_days: self.cfg.monitoring.history_days, since, now }
    }

    /// A tunnel's history over `period`, if `who` manages it.
    pub fn tunnel_history(&self, who: &Principal, id_or_name: &str, period: Period) -> Option<Series<Traffic>> {
        let t = self.tunnel(who, id_or_name)?;
        let now = unix_now();
        if !period.stored() {
            return Some(self.history.lock().unwrap().tunnel(&t.id, period, now));
        }
        let mut stored = self.store.tunnel_history_by(period.first_slot_at(now), period.slot_secs(), Some(&t.id)).or_log().unwrap_or_default();
        let slots = stored.remove(&t.id).unwrap_or_default();
        let history = self.history.lock().unwrap();
        Some(Series::from_slots(period, &slots, history.open_tunnel(&t.id, now), now, history.since(period, now), Traffic::add))
    }

    /// A machine's history over `period`, if `who` manages it.
    pub fn agent_history(&self, who: &Principal, agent_id: &str, period: Period) -> Option<Series<Presence>> {
        let allowed = {
            let st = self.state.lock().unwrap();
            st.dir.agent(agent_id).is_some() && authz::authorize(who, Action::Manage, st.agent_resource(agent_id))
        };
        if !allowed {
            return None;
        }
        let now = unix_now();
        if !period.stored() {
            return Some(self.history.lock().unwrap().agent(agent_id, period, now));
        }
        let mut stored = self.store.agent_history_by(period.first_slot_at(now), period.slot_secs(), Some(agent_id)).or_log().unwrap_or_default();
        let slots = stored.remove(agent_id).unwrap_or_default();
        let history = self.history.lock().unwrap();
        Some(Series::from_slots(period, &slots, history.open_agent(agent_id, now), now, history.since(period, now), Presence::add))
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
