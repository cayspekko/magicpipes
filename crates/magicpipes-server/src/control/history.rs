//! What tunnels and machines did lately. Every [`SAMPLE_SECS`] the control plane reads the counters
//! the data plane keeps for each tunnel ([`RouteStats`]) and each agent's connections, and keeps the
//! differences here, in memory: the last 15 minutes by 10 seconds and the last day by 5 minutes.
//!
//! Only an interval with something in it is kept, so an idle tunnel costs a few counters, and a busy
//! one at most [`FINE_SLOTS`] + [`COARSE_SLOTS`] samples (about 38 KB). Nothing here survives a
//! restart; history starts when the server does. Reading the counters takes the registry lock
//! briefly; this has its own lock, which is never held while taking the registry's.

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

/// How far back a view goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Period {
    #[default]
    Minutes15,
    Hours24,
}

impl Period {
    pub fn slot_secs(self) -> i64 {
        match self {
            Period::Minutes15 => SAMPLE_SECS,
            Period::Hours24 => COARSE_SECS,
        }
    }

    pub fn slots(self) -> usize {
        match self {
            Period::Minutes15 => FINE_SLOTS,
            Period::Hours24 => COARSE_SLOTS,
        }
    }

    /// For an address: `?period=24h`.
    pub fn parse(s: Option<&str>) -> Period {
        match s {
            Some("24h") => Period::Hours24,
            _ => Period::Minutes15,
        }
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
    pub latency: [u32; BUCKETS],
}

impl Traffic {
    /// Failed before the app answered, whatever the cause.
    pub fn failed(&self) -> u64 {
        self.offline + self.unreachable + self.timed_out
    }

    fn is_empty(&self) -> bool {
        *self == Traffic::default()
    }

    fn add(&mut self, o: &Traffic) {
        self.requests += o.requests;
        self.offline += o.offline;
        self.unreachable += o.unreachable;
        self.timed_out += o.timed_out;
        self.refused += o.refused;
        self.bytes_in += o.bytes_in;
        self.bytes_out += o.bytes_out;
        for (a, b) in self.latency.iter_mut().zip(o.latency) {
            *a = a.saturating_add(b);
        }
    }

    /// The time within which a share `q` of the answers came, in microseconds, estimated from the
    /// buckets (linearly within one). `None` without answers; `Some(None)` past the last bucket.
    pub fn quantile(&self, q: f64) -> Option<Option<u64>> {
        let total: u64 = self.latency.iter().map(|n| u64::from(*n)).sum();
        if total == 0 {
            return None;
        }
        let rank = q.clamp(0.0, 1.0) * total as f64;
        let mut seen = 0u64;
        for (i, n) in self.latency.iter().map(|n| u64::from(*n)).enumerate() {
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
            *out = u32::try_from(d(now, then)).unwrap_or(u32::MAX);
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
    /// Samples it was connected in (of 1 in the short view, of 30 in the long one).
    pub online: u8,
    /// Samples taken: less than a full slot at the start of history and in the current slot.
    pub samples: u8,
    /// The most connections it held.
    pub connections: u8,
    /// The average round trip over the samples that had one, in microseconds; 0 if none.
    pub round_trip: u32,
    round_trips: u8,
    /// Connections made again after one was lost, or after the agent restarted.
    pub reconnects: u16,
}

impl Presence {
    fn add(&mut self, o: &Presence) {
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
    reconnects: u16,
    /// The run of the agent its connections came from, once one has, and the most connections
    /// that run held: below that, a new one replaces one that was lost.
    run: Option<Option<String>>,
    peak: usize,
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
    tunnels: HashMap<String, TunnelTrack>,
    agents: HashMap<String, AgentTrack>,
}

impl History {
    pub fn new(now: i64) -> History {
        History { started: now, tunnels: HashMap::new(), agents: HashMap::new() }
    }

    /// Takes a sample at `now`: every tunnel's counters, and every enrolled agent's connections
    /// (`None` while it's offline). Tunnels and agents not listed are forgotten.
    pub fn record(&mut self, now: i64, tunnels: &[(String, Counters)], agents: &[(String, Option<Link>)]) {
        let fine = now.div_euclid(SAMPLE_SECS);
        let coarse = now.div_euclid(COARSE_SECS);
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
            close(&mut track.open, &mut track.coarse, coarse);
            track.open.1.add(&traffic);
        }
        self.agents.retain(|id, _| agents.iter().any(|(a, _)| a == id));
        for (id, link) in agents {
            let track = self.agents.entry(id.clone()).or_default();
            let p = Presence {
                online: u8::from(link.is_some()),
                samples: 1,
                connections: link.map_or(0, |l| l.connections),
                round_trip: link.map_or(0, |l| l.round_trip),
                round_trips: u8::from(link.is_some_and(|l| l.round_trip > 0)),
                reconnects: std::mem::take(&mut track.reconnects),
            };
            track.fine.push(fine, p, FINE_SLOTS);
            close(&mut track.open, &mut track.coarse, coarse);
            track.open.1.add(&p);
        }
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

    pub fn tunnel(&self, id: &str, period: Period, now: i64) -> Series<Traffic> {
        let track = self.tunnels.get(id);
        let (slot, points) = match period {
            Period::Minutes15 => {
                let slot = now.div_euclid(SAMPLE_SECS);
                (slot, track.map(|t| t.fine.dense(slot, FINE_SLOTS)))
            }
            Period::Hours24 => {
                let slot = now.div_euclid(COARSE_SECS);
                (slot, track.map(|t| with_open(t.coarse.dense(slot, COARSE_SLOTS), &t.open, slot)))
            }
        };
        self.series(period, slot, points)
    }

    pub fn agent(&self, id: &str, period: Period, now: i64) -> Series<Presence> {
        let track = self.agents.get(id);
        let (slot, points) = match period {
            Period::Minutes15 => {
                let slot = now.div_euclid(SAMPLE_SECS);
                (slot, track.map(|t| t.fine.dense(slot, FINE_SLOTS)))
            }
            Period::Hours24 => {
                let slot = now.div_euclid(COARSE_SECS);
                (slot, track.map(|t| with_open(t.coarse.dense(slot, COARSE_SLOTS), &t.open, slot)))
            }
        };
        self.series(period, slot, points)
    }

    /// When history began, if within `period` of `now`: nothing is known before.
    pub fn since(&self, period: Period, now: i64) -> Option<i64> {
        let slot = now.div_euclid(period.slot_secs());
        let first_at = (slot - period.slots() as i64 + 1) * period.slot_secs();
        (self.started > first_at).then_some(self.started)
    }

    fn series<T: Copy + Default>(&self, period: Period, slot: i64, points: Option<Vec<T>>) -> Series<T> {
        Series {
            period,
            last_slot_at: slot * period.slot_secs(),
            points: points.unwrap_or_else(|| vec![T::default(); period.slots()]),
            since: self.since(period, slot * period.slot_secs()),
        }
    }
}

/// Moves the long view's open slot into its ring once `slot` has moved on.
fn close<T: Copy + Default + PartialEq>(open: &mut (i64, T), ring: &mut Ring<T>, slot: i64) {
    if open.0 != slot {
        let (was, value) = std::mem::replace(open, (slot, T::default()));
        if value != T::default() {
            ring.push(was, value, COARSE_SLOTS);
        }
    }
    ring.forget(slot, COARSE_SLOTS);
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
