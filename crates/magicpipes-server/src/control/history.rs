//! What tunnels and machines did lately. Every [`SAMPLE_SECS`] the control plane reads the counters
//! the data plane keeps for each tunnel ([`RouteStats`]) and each agent's connections, and keeps the
//! differences here, in memory: the last 15 minutes by 10 seconds and the last day by 5 minutes.
//!
//! Only an interval with something in it is kept, so an idle tunnel costs a few counters, and a busy
//! one at most [`FINE_SLOTS`] + [`COARSE_SLOTS`] samples (about 70 KB). Closed 5-minute slots go to
//! the database ([`Closed`]), which brings the last day back after a restart and keeps longer
//! periods; the last 15 minutes start with the server. Reading the counters takes the registry
//! lock briefly; this has its own lock, which is never held while taking the registry's.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::Ordering::Relaxed;

use crate::data::{LATENCY_BUCKETS_MS, RouteStats};

/// Seconds between samples, and in a slot of the short view.
pub const SAMPLE_SECS: i64 = 10;
/// The short view: 15 minutes.
pub const FINE_SLOTS: usize = 90;
/// Seconds in a slot of the long view.
pub const COARSE_SECS: i64 = 300;
/// The long view: 24 hours.
pub const COARSE_SLOTS: usize = 288;

const BUCKETS: usize = LATENCY_BUCKETS_MS.len() + 1;

/// How far back a view goes. The first two are in memory; the others come from the database's
/// 5-minute slots, added up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Period {
    #[default]
    Minutes15,
    Hours24,
    Days7,
    Days30,
}

impl Period {
    pub const ALL: [Period; 4] = [Period::Minutes15, Period::Hours24, Period::Days7, Period::Days30];

    pub fn slot_secs(self) -> i64 {
        match self {
            Period::Minutes15 => SAMPLE_SECS,
            Period::Hours24 => COARSE_SECS,
            Period::Days7 => 3600,
            Period::Days30 => 6 * 3600,
        }
    }

    pub fn slots(self) -> usize {
        match self {
            Period::Minutes15 => FINE_SLOTS,
            Period::Hours24 => COARSE_SLOTS,
            Period::Days7 => 7 * 24,
            Period::Days30 => 30 * 4,
        }
    }

    /// Days of history it needs (`monitoring.history_days`); the first two are always there.
    pub fn days(self) -> u32 {
        match self {
            Period::Minutes15 | Period::Hours24 => 0,
            Period::Days7 => 7,
            Period::Days30 => 30,
        }
    }

    pub fn stored(self) -> bool {
        self.days() > 0
    }

    /// In an address: `?period=24h`; nothing for the first.
    pub fn key(self) -> &'static str {
        match self {
            Period::Minutes15 => "15m",
            Period::Hours24 => "24h",
            Period::Days7 => "7d",
            Period::Days30 => "30d",
        }
    }

    /// From an address; one that needs more days than are kept is the first.
    pub fn parse(s: Option<&str>, history_days: u32) -> Period {
        Period::ALL.into_iter().find(|p| Some(p.key()) == s && p.days() <= history_days).unwrap_or_default()
    }

    /// When the slot holding `now` starts, and so the period's last.
    pub fn last_slot_at(self, now: i64) -> i64 {
        now.div_euclid(self.slot_secs()) * self.slot_secs()
    }

    /// When the period's first slot starts.
    pub fn first_slot_at(self, now: i64) -> i64 {
        self.last_slot_at(now) - (self.slots() as i64 - 1) * self.slot_secs()
    }
}

/// What a tunnel carried in one interval.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Traffic {
    pub requests: u64,
    pub offline: u64,
    pub unreachable: u64,
    pub timed_out: u64,
    /// Turned away for want of streams; not among `requests`.
    pub refused: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Answers by how long they took (`LATENCY_BUCKETS_MS`, the last for longer ones).
    pub latency: [u64; BUCKETS],
}

impl Traffic {
    /// Failed before the app answered, whatever the cause.
    pub fn failed(&self) -> u64 {
        self.offline + self.unreachable + self.timed_out
    }

    fn is_empty(&self) -> bool {
        *self == Traffic::default()
    }

    pub(crate) fn add(&mut self, o: &Traffic) {
        self.requests += o.requests;
        self.offline += o.offline;
        self.unreachable += o.unreachable;
        self.timed_out += o.timed_out;
        self.refused += o.refused;
        self.bytes_in += o.bytes_in;
        self.bytes_out += o.bytes_out;
        for (a, b) in self.latency.iter_mut().zip(o.latency) {
            *a += b;
        }
    }

    /// The time within which a share `q` of the answers came, in microseconds, estimated from the
    /// buckets (linearly within one). `None` without answers; `Some(None)` past the last bucket.
    pub fn quantile(&self, q: f64) -> Option<Option<u64>> {
        let total: u64 = self.latency.iter().sum();
        if total == 0 {
            return None;
        }
        let rank = q.clamp(0.0, 1.0) * total as f64;
        let mut seen = 0u64;
        for (i, n) in self.latency.iter().copied().enumerate() {
            if n == 0 {
                continue;
            }
            if (seen + n) as f64 >= rank {
                let Some(hi) = LATENCY_BUCKETS_MS.get(i) else { return Some(None) };
                let lo = if i == 0 { 0 } else { LATENCY_BUCKETS_MS[i - 1] };
                let within = ((rank - seen as f64) / n as f64).clamp(0.0, 1.0);
                return Some(Some(((lo as f64 + (hi - lo) as f64 * within) * 1000.0) as u64));
            }
            seen += n;
        }
        Some(None)
    }
}

/// A tunnel's counters as they stand, to take differences from.
#[derive(Debug, Clone, Copy, Default)]
pub struct Counters {
    requests: u64,
    offline: u64,
    unreachable: u64,
    timed_out: u64,
    refused: u64,
    bytes_in: u64,
    bytes_out: u64,
    latency: [u64; BUCKETS],
}

impl Counters {
    pub fn read(s: &RouteStats) -> Counters {
        let mut latency = [0; BUCKETS];
        for (out, b) in latency.iter_mut().zip(&s.latency.buckets) {
            *out = b.load(Relaxed);
        }
        Counters {
            requests: s.requests.load(Relaxed),
            offline: s.offline.load(Relaxed),
            unreachable: s.unreachable.load(Relaxed),
            timed_out: s.timed_out.load(Relaxed),
            refused: s.refused.load(Relaxed),
            bytes_in: s.bytes_in.load(Relaxed),
            bytes_out: s.bytes_out.load(Relaxed),
            latency,
        }
    }

    /// What happened since `before`. Counters only grow; one that went back (a tunnel record
    /// replaced) counts from zero.
    fn since(&self, before: &Counters) -> Traffic {
        let d = |now: u64, then: u64| now.checked_sub(then).unwrap_or(now);
        let mut latency = [0; BUCKETS];
        for ((out, now), then) in latency.iter_mut().zip(self.latency).zip(before.latency) {
            *out = d(now, then);
        }
        Traffic {
            requests: d(self.requests, before.requests),
            offline: d(self.offline, before.offline),
            unreachable: d(self.unreachable, before.unreachable),
            timed_out: d(self.timed_out, before.timed_out),
            refused: d(self.refused, before.refused),
            bytes_in: d(self.bytes_in, before.bytes_in),
            bytes_out: d(self.bytes_out, before.bytes_out),
            latency,
        }
    }
}

/// An agent's connections at a sample.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Link {
    /// Connections open; 0 while it's offline.
    pub connections: u8,
    /// The average of its connections' last round trips, in microseconds; 0 if none is known.
    pub round_trip: u32,
}

/// A machine in one interval.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Presence {
    /// Samples it was connected in (of 1 in the short view, of 30 in a 5-minute slot).
    pub online: u32,
    /// Samples taken: fewer than a full slot at the start of history and in the current slot.
    pub samples: u32,
    /// The most connections it held.
    pub connections: u8,
    /// The average round trip over the samples that had one, in microseconds; 0 if none.
    pub round_trip: u32,
    /// Samples with a round trip, which `round_trip` averages.
    pub round_trips: u32,
    /// Connections made again after one was lost, or after the agent restarted.
    pub reconnects: u32,
}

impl Presence {
    pub(crate) fn add(&mut self, o: &Presence) {
        self.online = self.online.saturating_add(o.online);
        self.samples = self.samples.saturating_add(o.samples);
        self.connections = self.connections.max(o.connections);
        if o.round_trips > 0 {
            let total = u64::from(self.round_trip) * u64::from(self.round_trips) + u64::from(o.round_trip) * u64::from(o.round_trips);
            self.round_trips = self.round_trips.saturating_add(o.round_trips);
            self.round_trip = u32::try_from(total / u64::from(self.round_trips)).unwrap_or(u32::MAX);
        }
        self.reconnects = self.reconnects.saturating_add(o.reconnects);
    }
}

/// Samples in slots, oldest first, at most `cap` slots back; a slot with nothing in it isn't kept.
#[derive(Debug, Default)]
struct Ring<T> {
    entries: VecDeque<(i64, T)>,
}

impl<T: Copy + Default> Ring<T> {
    fn push(&mut self, slot: i64, value: T, cap: usize) {
        self.entries.push_back((slot, value));
        self.forget(slot, cap);
    }

    fn forget(&mut self, now: i64, cap: usize) {
        while self.entries.front().is_some_and(|(s, _)| *s <= now - cap as i64) {
            self.entries.pop_front();
        }
    }

    /// The `cap` slots up to `now`, oldest first, with `T::default()` where nothing was kept.
    fn dense(&self, now: i64, cap: usize) -> Vec<T> {
        let first = now - cap as i64 + 1;
        let mut out = vec![T::default(); cap];
        for (slot, v) in &self.entries {
            if let Some(i) = slot.checked_sub(first).and_then(|i| usize::try_from(i).ok()).filter(|i| *i < cap) {
                out[i] = *v;
            }
        }
        out
    }
}

#[derive(Debug, Default)]
struct TunnelTrack {
    last: Counters,
    fine: Ring<Traffic>,
    coarse: Ring<Traffic>,
    /// The long view's current slot, while it fills.
    open: (i64, Traffic),
}

#[derive(Debug, Default)]
struct AgentTrack {
    fine: Ring<Presence>,
    coarse: Ring<Presence>,
    open: (i64, Presence),
    /// Reconnects since the last sample.
    reconnects: u32,
    /// The run of the agent its connections came from, once one has, and the most connections
    /// that run held: below that, a new one replaces one that was lost.
    run: Option<Option<String>>,
    peak: usize,
    /// The last sample it was connected in; and since when it has held fewer connections than
    /// its run did.
    last_online: Option<i64>,
    short_since: Option<i64>,
}

/// What the alert rules need to know about a machine (`control/alerts.rs`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MachineNow {
    /// The last sample it was connected in, since the server started.
    pub last_online: Option<i64>,
    /// Since when it has had fewer connections than its run had, and how many that was.
    pub short_since: Option<i64>,
    pub peak: usize,
    /// Its round trips in the last 5 minutes' samples, in microseconds.
    pub round_trips: Vec<u32>,
    /// Reconnects in the last hour.
    pub reconnects: u32,
}

/// Closed 5-minute slots for the database: when each started (Unix time) and what it held.
#[derive(Debug, Default)]
pub struct Closed {
    pub tunnels: Vec<(String, i64, Traffic)>,
    pub agents: Vec<(String, i64, Presence)>,
}

/// A tunnel's or machine's history over a [`Period`]: one value per slot, oldest first, the last
/// one still filling.
#[derive(Debug, Clone)]
pub struct Series<T> {
    pub period: Period,
    /// When the last slot started (Unix time).
    pub last_slot_at: i64,
    pub points: Vec<T>,
    /// When history began, if within the period: nothing is known before.
    pub since: Option<i64>,
}

impl Series<Traffic> {
    pub fn total(&self) -> Traffic {
        let mut t = Traffic::default();
        for p in &self.points {
            t.add(p);
        }
        t
    }
}

impl Series<Presence> {
    pub fn total(&self) -> Presence {
        let mut t = Presence::default();
        for p in &self.points {
            t.add(p);
        }
        t
    }
}

#[derive(Debug)]
pub struct History {
    started: i64,
    /// The oldest slot the database had at startup, if older than `started`.
    known_since: i64,
    tunnels: HashMap<String, TunnelTrack>,
    agents: HashMap<String, AgentTrack>,
}

impl History {
    pub fn new(now: i64) -> History {
        History { started: now, known_since: now, tunnels: HashMap::new(), agents: HashMap::new() }
    }

    /// Fills the last 24 hours from the database's slots, at startup; `oldest`: its oldest.
    pub fn load(&mut self, now: i64, tunnels: Vec<(String, i64, Traffic)>, agents: Vec<(String, i64, Presence)>, oldest: Option<i64>) {
        let coarse = now.div_euclid(COARSE_SECS);
        for (id, at, t) in tunnels {
            let track = self.tunnels.entry(id).or_default();
            track.coarse.push(at.div_euclid(COARSE_SECS), t, COARSE_SLOTS);
            track.coarse.forget(coarse, COARSE_SLOTS);
        }
        for (id, at, p) in agents {
            let track = self.agents.entry(id).or_default();
            track.coarse.push(at.div_euclid(COARSE_SECS), p, COARSE_SLOTS);
            track.coarse.forget(coarse, COARSE_SLOTS);
        }
        self.known_since = oldest.map_or(self.started, |o| o.min(self.started));
    }

    /// Takes a sample at `now`: every tunnel's counters, and every enrolled agent's connections
    /// (`None` while it's offline). Tunnels and agents not listed are forgotten. Returns the
    /// 5-minute slots that closed, for the database.
    pub fn record(&mut self, now: i64, tunnels: &[(String, Counters)], agents: &[(String, Option<Link>)]) -> Closed {
        let fine = now.div_euclid(SAMPLE_SECS);
        let coarse = now.div_euclid(COARSE_SECS);
        let mut closed = Closed::default();
        self.tunnels.retain(|id, _| tunnels.iter().any(|(t, _)| t == id));
        for (id, counters) in tunnels {
            // Counters start at zero with the tunnel, so what it carried before its first sample counts.
            let track = self.tunnels.entry(id.clone()).or_default();
            let traffic = counters.since(&track.last);
            track.last = *counters;
            if !traffic.is_empty() {
                track.fine.push(fine, traffic, FINE_SLOTS);
            }
            track.fine.forget(fine, FINE_SLOTS);
            if let Some((slot, t)) = close(&mut track.open, &mut track.coarse, coarse) {
                closed.tunnels.push((id.clone(), slot * COARSE_SECS, t));
            }
            track.open.1.add(&traffic);
        }
        self.agents.retain(|id, _| agents.iter().any(|(a, _)| a == id));
        for (id, link) in agents {
            let track = self.agents.entry(id.clone()).or_default();
            match link {
                Some(l) => {
                    track.last_online = Some(now);
                    let short = usize::from(l.connections) < track.peak;
                    track.short_since = if short { track.short_since.or(Some(now)) } else { None };
                }
                None => track.short_since = None,
            }
            let p = Presence {
                online: u32::from(link.is_some()),
                samples: 1,
                connections: link.map_or(0, |l| l.connections),
                round_trip: link.map_or(0, |l| l.round_trip),
                round_trips: u32::from(link.is_some_and(|l| l.round_trip > 0)),
                reconnects: std::mem::take(&mut track.reconnects),
            };
            track.fine.push(fine, p, FINE_SLOTS);
            if let Some((slot, p)) = close(&mut track.open, &mut track.coarse, coarse) {
                closed.agents.push((id.clone(), slot * COARSE_SECS, p));
            }
            track.open.1.add(&p);
        }
        closed
    }

    /// What a tunnel carried in the last `secs` (at most 15 minutes).
    pub fn tunnel_recent(&self, id: &str, secs: i64, now: i64) -> Traffic {
        let from = (now - secs).div_euclid(SAMPLE_SECS);
        let mut t = Traffic::default();
        for (_, v) in self.tunnels.get(id).iter().flat_map(|t| t.fine.entries.iter()).filter(|(slot, _)| *slot > from) {
            t.add(v);
        }
        t
    }

    pub fn machine_now(&self, id: &str, now: i64) -> MachineNow {
        let Some(track) = self.agents.get(id) else { return MachineNow::default() };
        let five = (now - 300).div_euclid(SAMPLE_SECS);
        let hour = (now - 3600).div_euclid(COARSE_SECS);
        let reconnects = track.coarse.entries.iter().filter(|(slot, _)| *slot > hour).map(|(_, p)| p.reconnects).sum::<u32>()
            + if track.open.0 > hour { track.open.1.reconnects } else { 0 }
            + track.reconnects;
        MachineNow {
            last_online: track.last_online,
            short_since: track.short_since,
            peak: track.peak,
            round_trips: track.fine.entries.iter().filter(|(slot, p)| *slot > five && p.round_trip > 0).map(|(_, p)| p.round_trip).collect(),
            reconnects,
        }
    }

    /// The 5-minute slot filling now, which the database doesn't have yet.
    pub fn open_tunnel(&self, id: &str, now: i64) -> Traffic {
        self.tunnels.get(id).filter(|t| t.open.0 == now.div_euclid(COARSE_SECS)).map(|t| t.open.1).unwrap_or_default()
    }

    pub fn open_agent(&self, id: &str, now: i64) -> Presence {
        self.agents.get(id).filter(|t| t.open.0 == now.div_euclid(COARSE_SECS)).map(|t| t.open.1).unwrap_or_default()
    }

    /// When the server started.
    pub fn started(&self) -> i64 {
        self.started
    }

    /// An agent's connection from its run `instance` was attached, after `before` others from that
    /// run (`None`: it starts a run). Counts a reconnect unless it's the agent's first since the
    /// server started, or one more of a run's first connections.
    pub fn attached(&mut self, agent_id: &str, instance: Option<&str>, before: Option<usize>) {
        let track = self.agents.entry(agent_id.to_string()).or_default();
        let same_run = before.is_some() && track.run.as_ref().is_some_and(|r| r.as_deref() == instance);
        let again = match before {
            Some(n) if same_run => {
                let again = n < track.peak;
                track.peak = track.peak.max(n + 1);
                again
            }
            _ => {
                let again = track.run.is_some();
                track.run = Some(instance.map(str::to_string));
                track.peak = 1;
                again
            }
        };
        if again {
            track.reconnects = track.reconnects.saturating_add(1);
        }
    }

    /// A tunnel's history over one of the periods kept in memory; see [`Series::from_slots`] for
    /// the others.
    pub fn tunnel(&self, id: &str, period: Period, now: i64) -> Series<Traffic> {
        let track = self.tunnels.get(id);
        let points = match period {
            Period::Minutes15 => track.map(|t| t.fine.dense(now.div_euclid(SAMPLE_SECS), FINE_SLOTS)),
            _ => {
                let slot = now.div_euclid(COARSE_SECS);
                track.map(|t| with_open(t.coarse.dense(slot, COARSE_SLOTS), &t.open, slot))
            }
        };
        self.series(Period::in_memory(period), points, now)
    }

    pub fn agent(&self, id: &str, period: Period, now: i64) -> Series<Presence> {
        let track = self.agents.get(id);
        let points = match period {
            Period::Minutes15 => track.map(|t| t.fine.dense(now.div_euclid(SAMPLE_SECS), FINE_SLOTS)),
            _ => {
                let slot = now.div_euclid(COARSE_SECS);
                track.map(|t| with_open(t.coarse.dense(slot, COARSE_SLOTS), &t.open, slot))
            }
        };
        self.series(Period::in_memory(period), points, now)
    }

    /// When history began, if within `period` of `now`: nothing is known before. The short view
    /// starts with the server; the others with the oldest slot the database had.
    pub fn since(&self, period: Period, now: i64) -> Option<i64> {
        let began = if period == Period::Minutes15 { self.started } else { self.known_since };
        (began > period.first_slot_at(now)).then_some(began)
    }

    fn series<T: Copy + Default>(&self, period: Period, points: Option<Vec<T>>, now: i64) -> Series<T> {
        Series {
            period,
            last_slot_at: period.last_slot_at(now),
            points: points.unwrap_or_else(|| vec![T::default(); period.slots()]),
            since: self.since(period, now),
        }
    }
}

impl Period {
    /// The period a view in memory can show for this one.
    fn in_memory(self) -> Period {
        if self == Period::Minutes15 { self } else { Period::Hours24 }
    }
}

impl<T: Copy + Default> Series<T> {
    /// A period from the database's slots added up (`(when it starts, value)`), with the slot
    /// filling now added to the last point.
    pub fn from_slots(period: Period, slots: &[(i64, T)], open: T, now: i64, since: Option<i64>, add: impl Fn(&mut T, &T)) -> Series<T> {
        let first = period.first_slot_at(now);
        let mut points = vec![T::default(); period.slots()];
        for (at, v) in slots {
            if let Some(i) = (at - first).checked_div(period.slot_secs()).and_then(|i| usize::try_from(i).ok()).filter(|i| *i < points.len()) {
                add(&mut points[i], v);
            }
        }
        if let Some(last) = points.last_mut() {
            add(last, &open);
        }
        Series { period, last_slot_at: period.last_slot_at(now), points, since }
    }
}

/// Moves the long view's open slot into its ring once `slot` has moved on; returns it if it held
/// anything.
fn close<T: Copy + Default + PartialEq>(open: &mut (i64, T), ring: &mut Ring<T>, slot: i64) -> Option<(i64, T)> {
    let mut closed = None;
    if open.0 != slot {
        let (was, value) = std::mem::replace(open, (slot, T::default()));
        if value != T::default() {
            ring.push(was, value, COARSE_SLOTS);
            closed = Some((was, value));
        }
    }
    ring.forget(slot, COARSE_SLOTS);
    closed
}

/// The long view with its open slot in place, as the last point.
fn with_open<T: Copy>(mut points: Vec<T>, open: &(i64, T), slot: i64) -> Vec<T> {
    if open.0 == slot
        && let Some(last) = points.last_mut()
    {
        *last = open.1;
    }
    points
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counters(requests: u64, unreachable: u64, fast: u64) -> Counters {
        let mut c = Counters { requests, unreachable, ..Default::default() };
        c.latency[0] = fast;
        c
    }

    #[test]
    fn samples_keep_what_happened_in_between() {
        let mut h = History::new(1_000);
        let t = |c| vec![("t".to_string(), c)];
        h.record(1_000, &t(counters(5, 0, 5)), &[]);
        h.record(1_010, &t(counters(12, 1, 11)), &[]);
        h.record(1_020, &t(counters(12, 1, 11)), &[]);
        let s = h.tunnel("t", Period::Minutes15, 1_020);
        assert_eq!(s.points.len(), FINE_SLOTS);
        let last: Vec<u64> = s.points[FINE_SLOTS - 3..].iter().map(|p| p.requests).collect();
        // What came before the first sample, then 7 more, then none.
        assert_eq!(last, [5, 7, 0]);
        assert_eq!((s.total().requests, s.total().failed()), (12, 1));
        assert_eq!(s.since, Some(1_000), "history starts with the server");
        assert_eq!(s.last_slot_at, 1_020);
    }

    #[test]
    fn idle_tunnels_keep_nothing_and_old_samples_go() {
        let mut h = History::new(0);
        let mut now = 0;
        let mut n = 0;
        for i in 0..200 {
            now = i * SAMPLE_SECS;
            n += 1;
            h.record(now, &[("busy".into(), counters(n, 0, n)), ("idle".into(), Counters::default())], &[]);
        }
        let busy = &h.tunnels["busy"];
        assert_eq!(busy.fine.entries.len(), FINE_SLOTS, "older slots fell out");
        assert!(h.tunnels["idle"].fine.entries.is_empty() && h.tunnels["idle"].coarse.entries.is_empty());
        let s = h.tunnel("busy", Period::Minutes15, now);
        assert_eq!(s.total().requests, FINE_SLOTS as u64);
        assert_eq!(s.since, None);
        // 200 samples are 2,000 s: six 5-minute slots, the last one open.
        let day = h.tunnel("busy", Period::Hours24, now);
        assert_eq!(day.points.len(), COARSE_SLOTS);
        assert_eq!(day.total().requests, 200);
        assert_eq!(day.points.iter().filter(|p| p.requests > 0).count(), 7);
        // Gone from the registry, gone from here.
        h.record(now + SAMPLE_SECS, &[], &[]);
        assert!(h.tunnels.is_empty());
    }

    #[test]
    fn a_day_keeps_its_slots_and_no_more() {
        let mut h = History::new(0);
        let mut n = 0;
        for slot in 0..(COARSE_SLOTS as i64 + 50) {
            n += 1;
            h.record(slot * COARSE_SECS, &[("t".into(), counters(n, 0, 0))], &[]);
        }
        assert!(h.tunnels["t"].coarse.entries.len() < COARSE_SLOTS);
        let day = h.tunnel("t", Period::Hours24, (COARSE_SLOTS as i64 + 49) * COARSE_SECS);
        assert_eq!(day.total().requests, (COARSE_SLOTS - 1) as u64 + 1, "each slot one request, the open one included");
    }

    #[test]
    fn closed_slots_go_to_the_database_and_come_back() {
        let mut h = History::new(0);
        let t = |n| vec![("t".to_string(), counters(n, 0, n))];
        let a = vec![("a".to_string(), Some(Link { connections: 2, round_trip: 1_000 }))];
        let first = h.record(0, &t(3), &a);
        assert!(first.tunnels.is_empty() && first.agents.is_empty(), "nothing has closed yet");
        let closed = h.record(COARSE_SECS, &t(5), &a);
        assert_eq!(closed.tunnels.len(), 1);
        assert_eq!((closed.tunnels[0].1, closed.tunnels[0].2.requests, closed.tunnels[0].2.latency[0]), (0, 3, 3));
        assert_eq!((closed.agents[0].1, closed.agents[0].2.online, closed.agents[0].2.connections), (0, 1, 2));

        // After a restart, the day comes back from them, and so does what's known.
        let now = COARSE_SECS * 2;
        let mut again = History::new(now);
        again.load(now, closed.tunnels.clone(), closed.agents.clone(), Some(0));
        assert_eq!(again.tunnel("t", Period::Hours24, now).total().requests, 3);
        assert_eq!(again.agent("a", Period::Hours24, now).total().online, 1);
        assert_eq!(again.since(Period::Hours24, now), Some(0), "the day starts with what the database had");
        assert_eq!(again.since(Period::Minutes15, now), Some(now), "the last minutes start with the server");

        // Longer periods add those slots up, with the one filling now in the last point.
        let open = Traffic { requests: 2, ..Default::default() };
        let week = Series::from_slots(Period::Days7, &[(0, closed.tunnels[0].2)], open, now, None, Traffic::add);
        assert_eq!(week.points.len(), 7 * 24);
        assert_eq!(week.points.last().map(|p| p.requests), Some(5), "both are in the last hour");
        assert_eq!(Period::parse(Some("7d"), 7), Period::Days7);
        assert_eq!(Period::parse(Some("30d"), 7), Period::Minutes15, "not kept long enough");
        assert_eq!(Period::parse(Some("bogus"), 30), Period::Minutes15);
    }

    #[test]
    fn quantiles_come_from_the_buckets() {
        let mut t = Traffic::default();
        assert_eq!(t.quantile(0.5), None);
        // 10 answers within 1 ms, 10 between 10 and 25 ms.
        t.latency[0] = 10;
        t.latency[4] = 10;
        assert_eq!(t.quantile(0.5), Some(Some(1_000)));
        assert_eq!(t.quantile(0.75), Some(Some(17_500)));
        assert_eq!(t.quantile(1.0), Some(Some(25_000)));
        t.latency[BUCKETS - 1] = 100;
        assert_eq!(t.quantile(0.95), Some(None), "past the last bucket");
    }

    #[test]
    fn reconnects_are_connections_made_again() {
        let mut h = History::new(0);
        // A run's first four connections, after the server started: none is a reconnect.
        h.attached("a", Some("run1"), None);
        for n in 1..4 {
            h.attached("a", Some("run1"), Some(n));
        }
        assert_eq!(h.agents["a"].reconnects, 0);
        // One lost and made again; then the agent restarts.
        h.attached("a", Some("run1"), Some(3));
        h.attached("a", Some("run2"), None);
        assert_eq!(h.agents["a"].reconnects, 2);
        // An old agent without runs: every connection after its first replaces one.
        h.attached("old", None, None);
        h.attached("old", None, None);
        assert_eq!(h.agents["old"].reconnects, 1);

        let link = Some(Link { connections: 4, round_trip: 2_000 });
        h.record(0, &[], &[("a".into(), link), ("old".into(), None)]);
        h.record(10, &[], &[("a".into(), Some(Link { connections: 4, round_trip: 4_000 })), ("old".into(), None)]);
        let a = h.agent("a", Period::Minutes15, 10).total();
        assert_eq!((a.online, a.samples, a.connections, a.round_trip, a.reconnects), (2, 2, 4, 3_000, 2));
        let old = h.agent("old", Period::Hours24, 10).total();
        assert_eq!((old.online, old.samples, old.reconnects), (0, 2, 1));
    }
}
