//! Alerts: rules that judge machines, tunnels, certificates and the server on every sample
//! ([`super::history`]), with some patience. A subject in trouble on [`OPEN_AFTER`] samples in a
//! row opens an alert; one fine on [`CLOSE_AFTER`] in a row closes it, so a moment's trouble
//! neither opens nor closes one. Alerts are kept in the database as they open, change severity and
//! close; open ones show on the Health page, in the navigation's count and on the pages they
//! concern, to whoever may manage what they're about (`authorize`).

use std::collections::HashMap;

use magicpipes_core::proto::PROTOCOL_VERSION;
use magicpipes_core::{rfc3339, secret};

use super::history::{MachineNow, Traffic};
use super::{CERT_ORDER_WINDOW, ControlPlane, OrLog};
use crate::authz::{self, Action, Principal, Resource};
use crate::certs::CertStatus;
use crate::store::AlertRow;

pub const OPEN_AFTER: u8 = 2;
pub const CLOSE_AFTER: u8 = 3;

/// How long a refused key keeps its alert open, unless the key is forgotten first.
const KEY_REFUSED_FOR: i64 = 24 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rule {
    MachineOffline,
    FewerConnections,
    SlowRoundTrips,
    Reconnecting,
    OutdatedAgent,
    AppErrors,
    CertificateFailed,
    CertificateExpiring,
    CertificateOrders,
    PortsUsedUp,
    KeyRefused,
    CheckFailing,
    OutsideFailing,
}

impl Rule {
    const ALL: [Rule; 13] = [
        Rule::MachineOffline,
        Rule::FewerConnections,
        Rule::SlowRoundTrips,
        Rule::Reconnecting,
        Rule::OutdatedAgent,
        Rule::AppErrors,
        Rule::CertificateFailed,
        Rule::CertificateExpiring,
        Rule::CertificateOrders,
        Rule::PortsUsedUp,
        Rule::KeyRefused,
        Rule::CheckFailing,
        Rule::OutsideFailing,
    ];

    /// Its name in the database.
    pub fn key(self) -> &'static str {
        match self {
            Rule::MachineOffline => "machine_offline",
            Rule::FewerConnections => "fewer_connections",
            Rule::SlowRoundTrips => "slow_round_trips",
            Rule::Reconnecting => "reconnecting",
            Rule::OutdatedAgent => "outdated_agent",
            Rule::AppErrors => "app_errors",
            Rule::CertificateFailed => "certificate_failed",
            Rule::CertificateExpiring => "certificate_expiring",
            Rule::CertificateOrders => "certificate_orders",
            Rule::PortsUsedUp => "ports_used_up",
            Rule::KeyRefused => "key_refused",
            Rule::CheckFailing => "check_failing",
            Rule::OutsideFailing => "outside_failing",
        }
    }

    pub fn parse(s: &str) -> Option<Rule> {
        Rule::ALL.into_iter().find(|r| r.key() == s)
    }

    /// What it says, as a heading.
    pub fn title(self) -> &'static str {
        match self {
            Rule::MachineOffline => "Offline",
            Rule::FewerConnections => "Fewer connections",
            Rule::SlowRoundTrips => "Slow round trips",
            Rule::Reconnecting => "Reconnecting often",
            Rule::OutdatedAgent => "Agent out of date",
            Rule::AppErrors => "Couldn't reach app",
            Rule::CertificateFailed => "Certificate failed",
            Rule::CertificateExpiring => "Certificate expiring",
            Rule::CertificateOrders => "New certificates nearly used up",
            Rule::PortsUsedUp => "Ports nearly used up",
            Rule::KeyRefused => "Key changed",
            Rule::CheckFailing => "Check failing",
            Rule::OutsideFailing => "Unreachable from outside",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Warn,
    Bad,
}

impl Severity {
    pub fn key(self) -> &'static str {
        match self {
            Severity::Warn => "warn",
            Severity::Bad => "bad",
        }
    }

    pub(super) fn parse(s: &str) -> Severity {
        if s == "warn" { Severity::Warn } else { Severity::Bad }
    }
}

/// What one rule found wrong with one subject on a sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule: Rule,
    /// `tunnel:<id>`, `machine:<id>`, `certificate:<tunnel id>` or `server`.
    pub subject: String,
    pub name: String,
    pub severity: Severity,
    pub detail: String,
}

/// An alert as it changed, for the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Opened(AlertRow),
    Severity { id: String, severity: Severity, detail: String },
    Closed { id: String, at: i64, detail: String },
}

#[derive(Debug, Clone)]
struct Open {
    id: String,
    name: String,
    severity: Severity,
    detail: String,
    opened_at: i64,
}

#[derive(Debug, Default)]
struct Tracker {
    bad: u8,
    good: u8,
    open: Option<Open>,
}

#[derive(Debug, Default)]
pub struct Alerts {
    trackers: HashMap<(Rule, String), Tracker>,
    /// Tunnels whose machine showed a changed key, and when.
    refused_keys: HashMap<String, i64>,
}

/// An open or closed alert, for a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertView {
    pub id: String,
    pub rule: Rule,
    pub severity: Severity,
    pub subject: String,
    pub name: String,
    /// Where to look: the machine's or the tunnel's page, while it's there.
    pub href: Option<String>,
    pub detail: String,
    pub opened_at: i64,
    pub closed_at: Option<i64>,
}

impl Alerts {
    /// Alerts left open when the server stopped. They close once their subject is fine again.
    pub fn load(rows: Vec<AlertRow>) -> Alerts {
        let mut a = Alerts::default();
        for r in rows {
            let Some(rule) = Rule::parse(&r.rule) else { continue };
            let open = Open { id: r.id, name: r.subject_name, severity: Severity::parse(&r.severity), detail: r.detail, opened_at: r.opened_at };
            a.trackers.insert((rule, r.subject), Tracker { bad: OPEN_AFTER, good: 0, open: Some(open) });
        }
        a
    }

    fn is_open(&self, rule: Rule, subject: &str) -> bool {
        self.trackers.get(&(rule, subject.to_string())).is_some_and(|t| t.open.is_some())
    }

    pub fn key_refused(&mut self, tunnel_id: &str, now: i64) {
        // Bounded by the tunnels there are; gone ones are dropped at the next sample.
        self.refused_keys.insert(tunnel_id.to_string(), now);
    }

    pub fn key_forgotten(&mut self, tunnel_id: &str) {
        self.refused_keys.remove(tunnel_id);
    }

    /// Takes one sample's findings: the subjects in trouble now. Every other one tracked is fine
    /// this time, and one that's gone (`exists` says no) closes at once.
    pub fn apply(&mut self, now: i64, findings: Vec<Finding>, exists: impl Fn(&str) -> bool) -> Vec<Change> {
        let mut changes = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for f in findings {
            seen.insert((f.rule, f.subject.clone()));
            let t = self.trackers.entry((f.rule, f.subject.clone())).or_default();
            t.bad = t.bad.saturating_add(1);
            t.good = 0;
            match &mut t.open {
                Some(open) => {
                    if open.severity != f.severity {
                        changes.push(Change::Severity { id: open.id.clone(), severity: f.severity, detail: f.detail.clone() });
                    }
                    open.severity = f.severity;
                    open.detail = f.detail;
                }
                None if t.bad >= OPEN_AFTER => {
                    let open = Open { id: secret::new_token("al"), name: f.name, severity: f.severity, detail: f.detail, opened_at: now };
                    changes.push(Change::Opened(AlertRow {
                        id: open.id.clone(),
                        rule: f.rule.key().into(),
                        subject: f.subject,
                        subject_name: open.name.clone(),
                        severity: open.severity.key().into(),
                        detail: open.detail.clone(),
                        opened_at: now,
                        closed_at: None,
                    }));
                    t.open = Some(open);
                }
                None => {}
            }
        }
        self.trackers.retain(|(rule, subject), t| {
            if seen.contains(&(*rule, subject.clone())) {
                return true;
            }
            t.bad = 0;
            t.good = t.good.saturating_add(1);
            let gone = !exists(subject);
            if (t.good >= CLOSE_AFTER || gone)
                && let Some(open) = t.open.take()
            {
                changes.push(Change::Closed { id: open.id, at: now, detail: open.detail });
            }
            // A subject fine for a while, or gone, needs no tracker.
            t.open.is_some() || (t.good < CLOSE_AFTER && !gone)
        });
        self.refused_keys.retain(|tunnel, at| exists(&format!("tunnel:{tunnel}")) && now - *at < KEY_REFUSED_FOR);
        changes
    }

    fn open(&self) -> Vec<AlertView> {
        self.trackers
            .iter()
            .filter_map(|((rule, subject), t)| {
                let o = t.open.as_ref()?;
                Some(AlertView {
                    id: o.id.clone(),
                    rule: *rule,
                    severity: o.severity,
                    subject: subject.clone(),
                    name: o.name.clone(),
                    href: href(subject),
                    detail: o.detail.clone(),
                    opened_at: o.opened_at,
                    closed_at: None,
                })
            })
            .collect()
    }
}

/// The page an alert's subject has.
pub(super) fn href(subject: &str) -> Option<String> {
    match subject.split_once(':') {
        Some(("machine", id)) => Some(format!("/machines/{id}")),
        Some(("tunnel" | "certificate", id)) => Some(format!("/tunnels/{id}")),
        _ => None,
    }
}

/// `14:05 UTC` today, else `2026-11-08 14:05 UTC`.
pub(super) fn clock(at: i64, now: i64) -> String {
    let (ts, today) = (rfc3339(at), rfc3339(now));
    let (day, time) = (ts.get(..10).unwrap_or(""), ts.get(11..16).unwrap_or(""));
    if Some(day) == today.get(..10) { format!("{time} UTC") } else { format!("{day} {time} UTC") }
}

/// A machine, as the rules see it.
pub struct MachineFacts {
    pub id: String,
    pub name: String,
    pub tunnels: usize,
    /// Connections open, and the oldest protocol among them; `None` while it's offline.
    pub link: Option<(usize, u32)>,
    pub history: MachineNow,
    /// New certificates ordered for its tunnels in the last 24 hours.
    pub orders: usize,
    /// It has an open alert for being offline, perhaps from before a restart: that holds until it
    /// connects, whatever the server has seen since it started.
    pub offline_alert: bool,
}

/// A tunnel, as the rules see it.
pub struct TunnelFacts {
    pub id: String,
    pub name: String,
    pub hostname: String,
    /// The last 5 minutes.
    pub recent: Traffic,
    /// HTTP tunnels: its certificate's state and expiry.
    pub certificate: Option<(CertStatus, Option<i64>)>,
    pub key_refused: bool,
    /// Its last check's failures in a row, and why it failed.
    pub check: Option<(u32, String)>,
    /// The same from outside (`magicpipes probe`), while recent and failing.
    pub outside: Option<(u32, String)>,
}

/// What the rules see on a sample.
pub struct Facts {
    pub now: i64,
    /// When the server started: a machine never seen since has been offline at least that long.
    pub started: i64,
    pub machines: Vec<MachineFacts>,
    pub tunnels: Vec<TunnelFacts>,
    /// Public ports held, and how many the range has.
    pub ports: Option<(usize, usize)>,
    pub max_new_certificates_per_day: usize,
}

/// Every rule, on one sample.
pub fn judge(f: &Facts) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut find = |rule: Rule, subject: String, name: &str, severity: Severity, detail: String| {
        out.push(Finding { rule, subject, name: name.to_string(), severity, detail });
    };
    for m in &f.machines {
        let subject = format!("machine:{}", m.id);
        match m.link {
            None => {
                let since = m.history.last_online.unwrap_or(f.started);
                // A machine with no tunnels isn't missed.
                if m.tunnels > 0 && (f.now - since >= 120 || m.offline_alert) {
                    let detail = match m.history.last_online {
                        Some(at) => format!("Offline since {}.", clock(at, f.now)),
                        None => format!("Not connected since the server started, at {}.", clock(f.started, f.now)),
                    };
                    find(Rule::MachineOffline, subject.clone(), &m.name, Severity::Bad, detail);
                }
            }
            Some((connections, protocol)) => {
                if let Some(since) = m.history.short_since.filter(|s| f.now - s >= 300) {
                    let detail = format!("{connections} of the {} connections it had, since {}.", m.history.peak, clock(since, f.now));
                    find(Rule::FewerConnections, subject.clone(), &m.name, Severity::Warn, detail);
                }
                if protocol < PROTOCOL_VERSION {
                    let detail = format!("Its agent speaks protocol {protocol}, this server {PROTOCOL_VERSION}. Update magicpipes on it.");
                    find(Rule::OutdatedAgent, subject.clone(), &m.name, Severity::Warn, detail);
                }
            }
        }
        let mut trips = m.history.round_trips.clone();
        if trips.len() >= 10 {
            trips.sort_unstable();
            let p95 = trips[(trips.len() * 95).div_ceil(100).saturating_sub(1).min(trips.len() - 1)];
            if p95 > 500_000 {
                let detail = format!("95% of round trips within {} ms in the last 5 minutes.", p95 / 1000);
                find(Rule::SlowRoundTrips, subject.clone(), &m.name, Severity::Warn, detail);
            }
        }
        if m.history.reconnects > 5 {
            find(Rule::Reconnecting, subject.clone(), &m.name, Severity::Warn, format!("{} reconnects in the last hour.", m.history.reconnects));
        }
        let max = f.max_new_certificates_per_day;
        if max > 0 && m.orders * 5 > max * 4 {
            let detail = format!("{} of its {max} new certificates for the day.", m.orders);
            find(Rule::CertificateOrders, subject, &m.name, Severity::Warn, detail);
        }
    }
    for t in &f.tunnels {
        let failed = t.recent.unreachable + t.recent.timed_out;
        if t.recent.requests >= 20 && failed * 100 > t.recent.requests * 5 {
            let detail = format!("{failed} of {} requests in the last 5 minutes ({}%).", t.recent.requests, failed * 100 / t.recent.requests);
            find(Rule::AppErrors, format!("tunnel:{}", t.id), &t.name, Severity::Bad, detail);
        }
        if let Some((failures, why)) = t.check.as_ref().filter(|(n, _)| *n >= 2) {
            let detail = format!("The last {failures} checks failed: {why}");
            find(Rule::CheckFailing, format!("tunnel:{}", t.id), &t.name, Severity::Bad, detail);
        }
        if let Some((failures, why)) = t.outside.as_ref().filter(|(n, _)| *n >= 2) {
            let detail = format!("The last {failures} checks from outside failed: {why}");
            find(Rule::OutsideFailing, format!("tunnel:{}", t.id), &t.name, Severity::Bad, detail);
        }
        if t.key_refused {
            let detail = "Its machine showed a different key from the one kept, and the browser was refused. If the machine was reinstalled, forget the old key on this page.";
            find(Rule::KeyRefused, format!("tunnel:{}", t.id), &t.name, Severity::Bad, detail.to_string());
        }
        let subject = format!("certificate:{}", t.id);
        match &t.certificate {
            Some((CertStatus::Failed(why), _)) => find(Rule::CertificateFailed, subject, &t.hostname, Severity::Bad, why.clone()),
            Some((CertStatus::Ready, Some(not_after))) => {
                let left = not_after - f.now;
                if left < super::health::EXPIRING_WITHIN_SECS {
                    let severity = if left < 3 * 86_400 { Severity::Bad } else { Severity::Warn };
                    find(Rule::CertificateExpiring, subject, &t.hostname, severity, format!("Expires {}.", clock(*not_after, f.now)));
                }
            }
            _ => {}
        }
    }
    if let Some((used, total)) = f.ports
        && total > 0
        && used * 10 > total * 9
    {
        find(Rule::PortsUsedUp, "server".into(), "Public ports", Severity::Warn, format!("{used} of the {total} in the [ports] range are in use."));
    }
    out
}

impl ControlPlane {
    /// Judges this sample ([`judge`]), and keeps what changed.
    pub(super) fn judge(&self, now: i64) {
        let (mut machines, mut tunnels, ports) = {
            let mut st = self.state.lock().unwrap();
            let orders: HashMap<String, usize> = st
                .cert_orders
                .iter_mut()
                .map(|(agent, times)| {
                    times.retain(|t| t.elapsed() < CERT_ORDER_WINDOW);
                    (agent.clone(), times.len())
                })
                .collect();
            let machines: Vec<MachineFacts> = st
                .dir
                .agents()
                .map(|a| {
                    let link = st.sessions.get(&a.id).filter(|l| !l.is_closed()).map(|l| {
                        let open = l.lanes.iter().filter(|s| !s.handle.is_closed());
                        (open.clone().count(), open.map(|s| s.protocol).min().unwrap_or(PROTOCOL_VERSION))
                    });
                    MachineFacts {
                        id: a.id.clone(),
                        name: a.name.clone(),
                        tunnels: st.tunnels.values().filter(|t| t.row.agent_id == a.id).count(),
                        link,
                        history: MachineNow::default(),
                        orders: orders.get(&a.id).copied().unwrap_or(0),
                        offline_alert: false,
                    }
                })
                .collect();
            let tunnels: Vec<TunnelFacts> = st
                .tunnels
                .values()
                .map(|t| TunnelFacts {
                    id: t.row.id.clone(),
                    name: t.row.name.clone(),
                    hostname: t.row.hostname.clone(),
                    recent: Traffic::default(),
                    certificate: t.row.kind.is_http().then_some((CertStatus::Pending, None)),
                    key_refused: false,
                    check: None,
                    outside: None,
                })
                .collect();
            let used = st.tunnels.values().filter(|t| t.row.public_port.is_some()).count();
            (machines, tunnels, self.cfg.port_range().map(|r| (used, r.len())))
        };
        let started = {
            let history = self.history.lock().unwrap();
            for m in &mut machines {
                m.history = history.machine_now(&m.id, now);
            }
            for t in &mut tunnels {
                t.recent = history.tunnel_recent(&t.id, 300, now);
            }
            history.started()
        };
        {
            let checks = self.checks.lock().unwrap();
            for t in &mut tunnels {
                t.check = checks.get(&t.id).map(|c| (c.failures, c.said.clone()));
            }
        }
        {
            let mut outside = self.outside.lock().unwrap();
            outside.keep(|id| tunnels.iter().any(|t| t.id == id));
            for t in &mut tunnels {
                t.outside = outside.failing(&t.id, now);
            }
        }
        for t in tunnels.iter_mut().filter(|t| t.certificate.is_some()) {
            t.certificate = Some((self.certs.status(&t.hostname), self.certs.not_after(&t.hostname)));
        }
        let facts = {
            let alerts = self.alerts.lock().unwrap();
            for t in &mut tunnels {
                t.key_refused = alerts.refused_keys.contains_key(&t.id);
            }
            for m in &mut machines {
                m.offline_alert = alerts.is_open(Rule::MachineOffline, &format!("machine:{}", m.id));
            }
            Facts { now, started, machines, tunnels, ports, max_new_certificates_per_day: self.cfg.agents.max_new_certificates_per_day }
        };
        let findings = judge(&facts);
        let exists = |subject: &str| match subject.split_once(':') {
            Some(("machine", id)) => facts.machines.iter().any(|m| m.id == id),
            Some(("tunnel" | "certificate", id)) => facts.tunnels.iter().any(|t| t.id == id),
            _ => true,
        };
        let (before, changes) = {
            let mut alerts = self.alerts.lock().unwrap();
            (alerts.open(), alerts.apply(now, findings, exists))
        };
        self.tell(now, &before, &changes, exists);
        for change in changes {
            match change {
                Change::Opened(row) => {
                    tracing::info!(alert = %row.rule, subject = %row.subject, severity = %row.severity, "alert opened");
                    self.store.open_alert(&row).or_log();
                }
                Change::Severity { id, severity, detail } => {
                    self.store.update_alert(&id, severity.key(), &detail).or_log();
                }
                Change::Closed { id, at, detail } => {
                    tracing::info!(alert = %id, "alert closed");
                    self.store.close_alert(&id, at, &detail).or_log();
                }
            }
        }
    }

    /// Whether `who` may see an alert about `subject`: what they manage, and for administrators,
    /// also what's gone and the server's own.
    pub(super) fn may_see(&self, st: &super::State, who: &Principal, subject: &str) -> bool {
        match subject.split_once(':') {
            Some(("machine", id)) if st.dir.agent(id).is_some() => authz::authorize(who, Action::Manage, st.agent_resource(id)),
            Some(("tunnel" | "certificate", id)) if st.tunnels.contains_key(id) => st.tunnels.get(id).is_some_and(|t| st.may(who, Action::Manage, t)),
            _ => authz::authorize(who, Action::Discover, Resource::Org),
        }
    }

    /// Open alerts `who` may see, the worst and oldest first.
    pub fn alerts(&self, who: &Principal) -> Vec<AlertView> {
        let open = self.alerts.lock().unwrap().open();
        let st = self.state.lock().unwrap();
        let mut v: Vec<AlertView> = open.into_iter().filter(|a| self.may_see(&st, who, &a.subject)).collect();
        v.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.opened_at.cmp(&b.opened_at)));
        v
    }

    /// Open alerts about one machine or tunnel (its certificate's included).
    pub fn alerts_about(&self, who: &Principal, kind: &str, id: &str) -> Vec<AlertView> {
        let subjects = [format!("{kind}:{id}"), format!("certificate:{id}")];
        self.alerts(who).into_iter().filter(|a| subjects[0] == a.subject || (kind == "tunnel" && subjects[1] == a.subject)).collect()
    }

    /// Alerts that closed since `since`, newest first, that `who` may see.
    pub fn closed_alerts(&self, who: &Principal, since: i64) -> Vec<AlertView> {
        let rows = self.store.closed_alerts(since, 200).or_log().unwrap_or_default();
        let st = self.state.lock().unwrap();
        rows.into_iter()
            .filter(|r| self.may_see(&st, who, &r.subject))
            .filter_map(|r| {
                Some(AlertView {
                    rule: Rule::parse(&r.rule)?,
                    severity: Severity::parse(&r.severity),
                    href: href(&r.subject).filter(|_| match r.subject.split_once(':') {
                        Some(("machine", id)) => st.dir.agent(id).is_some(),
                        Some((_, id)) => st.tunnels.contains_key(id),
                        None => false,
                    }),
                    id: r.id,
                    subject: r.subject,
                    name: r.subject_name,
                    detail: r.detail,
                    opened_at: r.opened_at,
                    closed_at: r.closed_at,
                })
            })
            .collect()
    }

    /// How many open alerts `who` may see, and whether one is serious: for the navigation.
    pub fn alert_count(&self, who: &Principal) -> (usize, bool) {
        let open = self.alerts(who);
        (open.len(), open.iter().any(|a| a.severity == Severity::Bad))
    }

    /// Open alerts by severity, for `/metrics`.
    pub(super) fn open_alerts_by_severity(&self) -> (usize, usize) {
        let open = self.alerts.lock().unwrap().open();
        (open.iter().filter(|a| a.severity == Severity::Warn).count(), open.iter().filter(|a| a.severity == Severity::Bad).count())
    }

    /// Loads alerts left open at the last stop, at startup.
    pub(super) fn load_alerts(&self) {
        let rows = self.store.open_alerts().or_log().unwrap_or_default();
        *self.alerts.lock().unwrap() = Alerts::load(rows);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(subject: &str, severity: Severity) -> Finding {
        Finding { rule: Rule::MachineOffline, subject: subject.into(), name: "m".into(), severity, detail: format!("{severity:?}") }
    }

    #[test]
    fn alerts_open_after_two_samples_and_close_after_three() {
        let mut a = Alerts::default();
        let all = |_: &str| true;
        assert!(a.apply(0, vec![finding("machine:a", Severity::Warn)], all).is_empty(), "one sample isn't enough");
        let opened = a.apply(10, vec![finding("machine:a", Severity::Warn)], all);
        let [Change::Opened(row)] = opened.as_slice() else { panic!("{opened:?}") };
        assert_eq!((row.rule.as_str(), row.subject.as_str(), row.severity.as_str(), row.opened_at), ("machine_offline", "machine:a", "warn", 10));
        let worse = a.apply(20, vec![finding("machine:a", Severity::Bad)], all);
        assert_eq!(worse, vec![Change::Severity { id: row.id.clone(), severity: Severity::Bad, detail: "Bad".into() }]);
        assert!(a.apply(30, vec![finding("machine:a", Severity::Bad)], all).is_empty(), "no change, nothing to write");
        // A moment's recovery doesn't close it.
        assert!(a.apply(40, vec![], all).is_empty());
        assert!(a.apply(50, vec![finding("machine:a", Severity::Bad)], all).is_empty());
        assert!(a.apply(60, vec![], all).is_empty() && a.apply(70, vec![], all).is_empty());
        assert_eq!(a.apply(80, vec![], all), vec![Change::Closed { id: row.id.clone(), at: 80, detail: "Bad".into() }]);
        assert!(a.trackers.is_empty(), "nothing left to track");
        // Something that's gone closes at once.
        a.apply(90, vec![finding("machine:b", Severity::Bad)], all);
        let id = match &a.apply(100, vec![finding("machine:b", Severity::Bad)], all)[..] {
            [Change::Opened(row)] => row.id.clone(),
            other => panic!("{other:?}"),
        };
        assert_eq!(a.apply(110, vec![], |s| s != "machine:b"), vec![Change::Closed { id, at: 110, detail: "Bad".into() }]);
    }

    #[test]
    fn alerts_left_open_close_once_their_subject_is_fine() {
        let row = AlertRow {
            id: "al_1".into(),
            rule: "app_errors".into(),
            subject: "tunnel:t".into(),
            subject_name: "web".into(),
            severity: "bad".into(),
            detail: "x".into(),
            opened_at: 5,
            closed_at: None,
        };
        let unknown = AlertRow { id: "al_2".into(), rule: "from_a_newer_server".into(), ..row.clone() };
        let mut a = Alerts::load(vec![row, unknown]);
        assert_eq!(a.open().len(), 1, "a rule this server doesn't know is left alone");
        for now in [10, 20] {
            assert!(a.apply(now, vec![], |_| true).is_empty());
        }
        assert_eq!(a.apply(30, vec![], |_| true), vec![Change::Closed { id: "al_1".into(), at: 30, detail: "x".into() }]);
    }

    fn facts() -> Facts {
        Facts { now: 10_000, started: 0, machines: vec![], tunnels: vec![], ports: None, max_new_certificates_per_day: 20 }
    }

    fn machine(id: &str, tunnels: usize, link: Option<(usize, u32)>) -> MachineFacts {
        MachineFacts { id: id.into(), name: id.into(), tunnels, link, history: MachineNow::default(), orders: 0, offline_alert: false }
    }

    fn tunnel(id: &str, requests: u64, unreachable: u64) -> TunnelFacts {
        TunnelFacts {
            id: id.into(),
            name: id.into(),
            hostname: format!("{id}.t.test"),
            recent: Traffic { requests, unreachable, ..Default::default() },
            certificate: None,
            key_refused: false,
            check: None,
            outside: None,
        }
    }

    fn rules(f: &Facts) -> Vec<(Rule, String, Severity)> {
        judge(f).into_iter().map(|x| (x.rule, x.subject, x.severity)).collect()
    }

    #[test]
    fn machines_are_judged_by_what_they_serve_and_how_they_connect() {
        let mut f = facts();
        let mut offline = machine("off", 1, None);
        offline.history.last_online = Some(10_000 - 121);
        let mut briefly = machine("briefly", 1, None);
        briefly.history.last_online = Some(10_000 - 60);
        let mut restarted = machine("restarted", 1, None);
        restarted.offline_alert = true;
        let mut back = machine("back", 1, Some((4, PROTOCOL_VERSION)));
        back.offline_alert = true;
        let mut short = machine("short", 1, Some((2, PROTOCOL_VERSION)));
        short.history.short_since = Some(10_000 - 300);
        short.history.peak = 4;
        let mut slow = machine("slow", 1, Some((4, PROTOCOL_VERSION)));
        slow.history.round_trips = vec![600_000; 10];
        let mut few = machine("few", 1, Some((4, PROTOCOL_VERSION)));
        few.history.round_trips = vec![600_000; 9];
        let mut flapping = machine("flapping", 1, Some((4, PROTOCOL_VERSION)));
        flapping.history.reconnects = 6;
        let mut ordering = machine("ordering", 1, Some((4, PROTOCOL_VERSION)));
        ordering.orders = 17;
        let mut fine = machine("fine", 1, Some((4, PROTOCOL_VERSION)));
        fine.orders = 16;
        fine.history.reconnects = 5;
        f.started = 10_000 - 30;
        f.machines = vec![
            offline,
            briefly,
            restarted,
            back,
            machine("idle", 0, None),
            machine("never-seen", 2, None),
            short,
            machine("old", 1, Some((4, PROTOCOL_VERSION - 1))),
            slow,
            few,
            flapping,
            ordering,
            fine,
        ];
        assert_eq!(rules(&f), vec![
            (Rule::MachineOffline, "machine:off".into(), Severity::Bad),
            (Rule::MachineOffline, "machine:restarted".into(), Severity::Bad),
            (Rule::FewerConnections, "machine:short".into(), Severity::Warn),
            (Rule::OutdatedAgent, "machine:old".into(), Severity::Warn),
            (Rule::SlowRoundTrips, "machine:slow".into(), Severity::Warn),
            (Rule::Reconnecting, "machine:flapping".into(), Severity::Warn),
            (Rule::CertificateOrders, "machine:ordering".into(), Severity::Warn),
        ]);
        assert_eq!(judge(&f)[1].detail, format!("Not connected since the server started, at {}.", clock(10_000 - 30, 10_000)));
        f.started = 0;
        assert!(rules(&f).contains(&(Rule::MachineOffline, "machine:never-seen".into(), Severity::Bad)), "2 minutes after the server started");
        let detail = &judge(&f)[3].detail;
        assert!(detail.starts_with("2 of the 4 connections it had, since "), "{detail}");
    }

    #[test]
    fn tunnels_certificates_and_ports_are_judged() {
        let mut f = facts();
        let mut expiring = tunnel("expiring", 0, 0);
        expiring.certificate = Some((CertStatus::Ready, Some(10_000 + 10 * 86_400)));
        let mut soon = tunnel("soon", 0, 0);
        soon.certificate = Some((CertStatus::Ready, Some(10_000 + 2 * 86_400)));
        let mut later = tunnel("later", 0, 0);
        later.certificate = Some((CertStatus::Ready, Some(10_000 + 20 * 86_400)));
        let mut failed = tunnel("failed", 0, 0);
        failed.certificate = Some((CertStatus::Failed("no DNS".into()), None));
        let mut changed = tunnel("changed", 0, 0);
        changed.key_refused = true;
        let mut checked = tunnel("checked", 0, 0);
        checked.check = Some((2, "The app isn't accepting connections.".into()));
        let mut once = tunnel("once", 0, 0);
        once.check = Some((1, "No answer within 10 seconds.".into()));
        let mut outside = tunnel("outside", 0, 0);
        outside.outside = Some((2, "couldn't look up outside.t.test".into()));
        let mut outside_once = tunnel("outside-once", 0, 0);
        outside_once.outside = Some((1, "timed out".into()));
        f.tunnels = vec![tunnel("down", 20, 2), tunnel("quiet", 19, 19), tunnel("edge", 20, 1), expiring, soon, later, failed, changed, checked, once, outside, outside_once];
        f.ports = Some((46, 50));
        assert_eq!(rules(&f), vec![
            (Rule::AppErrors, "tunnel:down".into(), Severity::Bad),
            (Rule::CertificateExpiring, "certificate:expiring".into(), Severity::Warn),
            (Rule::CertificateExpiring, "certificate:soon".into(), Severity::Bad),
            (Rule::CertificateFailed, "certificate:failed".into(), Severity::Bad),
            (Rule::KeyRefused, "tunnel:changed".into(), Severity::Bad),
            (Rule::CheckFailing, "tunnel:checked".into(), Severity::Bad),
            (Rule::OutsideFailing, "tunnel:outside".into(), Severity::Bad),
            (Rule::PortsUsedUp, "server".into(), Severity::Warn),
        ]);
        assert_eq!(judge(&f)[6].detail, "The last 2 checks from outside failed: couldn't look up outside.t.test");
        assert_eq!(judge(&f)[5].detail, "The last 2 checks failed: The app isn't accepting connections.");
        assert_eq!(judge(&f)[0].detail, "2 of 20 requests in the last 5 minutes (10%).");
        f.tunnels.clear();
        f.ports = Some((45, 50));
        assert!(rules(&f).is_empty(), "90% isn't over 90%");
    }

    #[test]
    fn a_refused_key_stays_a_day_unless_forgotten() {
        let mut a = Alerts::default();
        a.key_refused("t", 0);
        a.apply(KEY_REFUSED_FOR - 1, vec![], |_| true);
        assert!(a.refused_keys.contains_key("t"));
        a.key_forgotten("t");
        assert!(a.refused_keys.is_empty());
        a.key_refused("t", 0);
        a.apply(KEY_REFUSED_FOR, vec![], |_| true);
        assert!(a.refused_keys.is_empty(), "a day later");
        a.key_refused("t", 0);
        a.apply(1, vec![], |s| s != "tunnel:t");
        assert!(a.refused_keys.is_empty(), "the tunnel is gone");
    }
}
