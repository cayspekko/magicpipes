//! The Health page, and the history sections of the tunnel and machine pages.

use axum::extract::{Query, State};
use axum::response::Response;
use serde::Deserialize;

use super::chart::{Chart, Plot, nice_max, period_words, periods, slot_words, spark};
use super::extract::UiUser;
use super::html::{Number, Text, badge, count, esc, table, when};
use super::ui::page;
use super::AppState;
use crate::control::health::{CertificateHealth, HealthView, MachineHealth, TunnelHealth};
use crate::control::history::{Period, Presence, Series, Traffic};

/// Rows a list on the Health page shows: those in trouble first, then the busiest.
const ROWS: usize = 50;

#[derive(Deserialize, Default)]
pub struct PeriodQuery {
    period: Option<String>,
}

impl PeriodQuery {
    pub fn period(&self) -> Period {
        Period::parse(self.period.as_deref())
    }
}

pub async fn health(user: UiUser, State(app): State<AppState>, Query(q): Query<PeriodQuery>) -> Response {
    let period = q.period();
    let h = app.control.health(&user.who, period);
    page("Health", Some(&user), &body(&h))
}

fn body(h: &HealthView) -> String {
    let words = period_words(h.period);
    let mut tunnels: Vec<&TunnelHealth> = h.tunnels.iter().collect();
    tunnels.sort_by_cached_key(|t| {
        let total = t.recent.total();
        (std::cmp::Reverse((total.failed(), total.refused, total.requests)), t.tunnel.name.clone())
    });
    let mut machines: Vec<&MachineHealth> = h.machines.iter().collect();
    machines.sort_by_cached_key(|m| (m.agent.connected || m.agent.tunnels == 0, std::cmp::Reverse(m.recent.total().reconnects), m.agent.name.clone()));

    let tunnel_rows: String = tunnels.iter().take(ROWS).map(|t| tunnel_row(t)).collect();
    let machine_rows: String = machines.iter().take(ROWS).map(|m| machine_row(m, h.now)).collect();
    let more = |shown: usize, all: usize, what: &str, list: &str| {
        if all > shown {
            format!(r#"<p class="note">{shown} of {all} {what}, those in trouble and the busiest first. <a href="{list}">See them all</a>.</p>"#)
        } else {
            String::new()
        }
    };
    let since = h
        .since
        .map(|at| format!(r#"<p class="note">The server started {} ago, and nothing is known from before then.</p>"#, ago(h.now - at)))
        .unwrap_or_default();
    let certificates = if h.certificates.is_empty() {
        String::new()
    } else {
        let rows: String = h.certificates.iter().map(|c| certificate_row(c, h.now)).collect();
        format!(
            r#"<div class="section" id="certificates"><h2>Certificates<span class="count">{}</span></h2></div><p class="note below-section">Only those in trouble, or expiring within 14 days.</p>{}"#,
            h.certificates.len(),
            table(&[Text("Hostname"), Text("State"), Text("Expires")], &rows, "")
        )
    };
    // With nothing yet, the lists only say where to start.
    let nothing = h.tunnels.is_empty() && h.machines.is_empty();
    let note = |text: String| if nothing { String::new() } else { format!(r#"<p class="note below-section">{text}</p>"#) };
    format!(
        r#"<h1>Health</h1>{line}
{periods}{since}
<div class="section" id="tunnels"><h2>Tunnels<span class="count">{n_tunnels}</span></h2></div>
{tunnels_note}
{tunnel_table}{more_tunnels}
<div class="section" id="machines"><h2>Machines<span class="count">{n_machines}</span></h2></div>
{machines_note}
{machine_table}{more_machines}
{certificates}"#,
        line = health_line(h),
        periods = if nothing { String::new() } else { format!(r#"<div class="spaced">{}</div>"#, periods("/health", h.period)) },
        since = if nothing { String::new() } else { since },
        tunnels_note = note(format!("What the server saw in {words}.")),
        machines_note = note("Round trips are timed every 15 seconds behind each connection's traffic, and a reconnect is a connection made again after one was lost or the agent restarted.".into()),
        n_tunnels = h.tunnels.len(),
        n_machines = h.machines.len(),
        tunnel_table = table(
            &[Text("Tunnel"), Number("Requests"), Number("Couldn't reach app"), Number("Response time"), Text("Status")],
            &tunnel_rows,
            "No tunnels yet. Run <code>magicpipes add 8080</code> on one of your machines."
        ),
        more_tunnels = more(ROWS, h.tunnels.len(), "tunnels", "/"),
        machine_table = table(
            &[Text("Machine"), Text("Status"), Number("Connections"), Number("Round trip"), Number("Reconnects")],
            &machine_rows,
            r#"No machines yet. <a href="/machines">Add one</a>."#
        ),
        more_machines = more(ROWS, h.machines.len(), "machines", "/machines"),
    )
}

/// The page's first line: what's wrong, or that nothing is.
fn health_line(h: &HealthView) -> String {
    if h.tunnels.is_empty() && h.machines.is_empty() {
        return String::new();
    }
    let offline = h.machines.iter().filter(|m| !m.agent.connected && m.agent.tunnels > 0).count();
    let app_down = h.tunnels.iter().filter(|t| {
        let total = t.recent.total();
        total.unreachable + total.timed_out > 0
    });
    let app_down = app_down.count();
    let busy = h.tunnels.iter().filter(|t| t.recent.total().refused > 0).count();
    let certs = |state: &str| h.certificates.iter().filter(|c| c.state == state).count();
    let words = period_words(h.period);
    // What's true now is said plainly; what was counted says over when.
    let mut bad = Vec::new();
    if offline > 0 {
        bad.push(format!(r##"<a href="#machines">{} offline</a>"##, count(offline, "machine", "machines")));
    }
    if app_down > 0 {
        let what = if app_down == 1 { "tunnel couldn't reach its app" } else { "tunnels couldn't reach their app" };
        bad.push(format!(r##"<a href="#tunnels">{app_down} {what} in {words}</a>"##));
    }
    if certs("failed") > 0 {
        bad.push(format!(r##"<a href="#certificates">{} failed</a>"##, count(certs("failed"), "certificate", "certificates")));
    }
    let mut warn = Vec::new();
    if busy > 0 {
        let what = if busy == 1 { "tunnel turned requests away" } else { "tunnels turned requests away" };
        warn.push(format!(r##"<a href="#tunnels">{busy} {what} in {words}</a>"##));
    }
    if certs("ready") > 0 {
        warn.push(format!(r##"<a href="#certificates">{} expiring within 14 days</a>"##, count(certs("ready"), "certificate", "certificates")));
    }
    if certs("pending") > 0 {
        warn.push(format!(r##"<a href="#certificates">{} being ordered</a>"##, count(certs("pending"), "certificate", "certificates")));
    }
    let (tone, text) = match (bad.is_empty(), warn.is_empty()) {
        (false, _) => ("bad", [bad, warn].concat().join(" · ")),
        (true, false) => ("warn", format!("{}; everything else is working", warn.join(" · "))),
        (true, true) => ("ok", format!("Everything is working: no failures in {words}")),
    };
    format!(r#"<p class="health"><span class="status {tone}"><span>{text}</span></span></p>"#)
}

fn tunnel_row(t: &TunnelHealth) -> String {
    let total = t.recent.total();
    let requests: Vec<f64> = t.recent.points.iter().map(|p| p.requests as f64).collect();
    let max = nice_max(requests.iter().cloned().fold(0.0, f64::max));
    let causes = causes(&total);
    format!(
        r#"<tr><td><a class="name" href="/tunnels/{id}">{name}</a><span class="sub">{machine}</span></td><td class="num">{requests}{spark}</td><td class="num">{failed}{causes}</td><td class="num">{time}</td><td>{status}</td></tr>"#,
        id = esc(&t.tunnel.id),
        name = esc(&t.tunnel.name),
        machine = esc(&t.machine),
        requests = thousands(total.requests),
        spark = if total.requests > 0 { spark(&Plot::Columns { values: requests, max, bad: false }) } else { String::new() },
        failed = thousands(total.failed()),
        causes = if causes.is_empty() { String::new() } else { format!(r#"<span class="sub">{}</span>"#, esc(&causes)) },
        time = response_time(&total),
        status = badge(t.tunnel.status),
    )
}

/// Why requests failed, and those turned away: `app down 3 · too slow 1 · busy 2`.
fn causes(t: &Traffic) -> String {
    let parts = [(t.unreachable, "app down"), (t.timed_out, "too slow"), (t.offline, "machine offline"), (t.refused, "turned away, busy")];
    parts.iter().filter(|(n, _)| *n > 0).map(|(n, what)| format!("{what} {}", thousands(*n))).collect::<Vec<_>>().join(" · ")
}

/// The median, with the 95th percentile under it.
fn response_time(t: &Traffic) -> String {
    match (t.quantile(0.5), t.quantile(0.95)) {
        (Some(median), Some(p95)) => format!(r#"{}<span class="sub">95% {}</span>"#, micros(median), within(p95)),
        _ => r#"<span class="when">none</span>"#.to_string(),
    }
}

fn machine_row(m: &MachineHealth, now: i64) -> String {
    let a = &m.agent;
    let total = m.recent.total();
    let owner = a.owner_email.as_deref().map_or_else(|| "service agent".to_string(), esc);
    let state = match (a.connected, a.connected_since, a.last_seen) {
        (true, Some(at), _) => format!(r#"<span class="sub">for {}</span>"#, ago(now - at)),
        (false, _, Some(at)) => format!(r#"<span class="sub">last seen {} ago</span>"#, ago(now - at)),
        _ => String::new(),
    };
    let trips = round_trips(&m.recent);
    let latest = trips.iter().rev().flatten().next().copied();
    let round_trip = match latest {
        Some(ms) if a.connected => {
            let max = nice_max(trips.iter().flatten().cloned().fold(0.0, f64::max));
            format!("{}{}", millis(ms), spark(&Plot::Line { values: trips, max }))
        }
        _ => r#"<span class="when">none</span>"#.to_string(),
    };
    format!(
        r#"<tr><td><a class="name" href="/machines/{id}">{name}</a><span class="sub">{owner}</span></td><td>{status}{state}</td><td class="num">{connections}</td><td class="num">{round_trip}</td><td class="num">{reconnects}</td></tr>"#,
        id = esc(&a.id),
        name = esc(&a.name),
        status = badge(if a.connected { "connected" } else { "disconnected" }),
        connections = a.connections,
        reconnects = total.reconnects,
    )
}

fn certificate_row(c: &CertificateHealth, now: i64) -> String {
    let state = match c.state {
        "ready" => r#"<span class="status warn">expiring</span>"#.to_string(),
        s => badge(s),
    };
    let error = c.error.as_deref().map(|e| format!(r#"<span class="sub wrap">{}</span>"#, esc(e))).unwrap_or_default();
    let expires = match c.not_after {
        Some(at) if at > now => format!(r#"in {}<span class="sub">{}</span>"#, ago(at - now), when(&magicpipes_core::rfc3339(at))),
        Some(at) => format!(r#"expired {} ago"#, ago(now - at)),
        None => r#"<span class="when">unknown</span>"#.to_string(),
    };
    format!(
        r#"<tr><td><a class="name" href="/tunnels/{id}">{host}</a><span class="sub">{tunnel}</span></td><td class="wrap">{state}{error}</td><td>{expires}</td></tr>"#,
        id = esc(&c.tunnel_id),
        host = esc(&c.hostname),
        tunnel = esc(&c.tunnel),
    )
}

/// A tunnel's history on its page: what it carried, what failed and how fast the app answered.
pub(super) fn traffic_section(href: &str, series: &Series<Traffic>, http: bool) -> String {
    let p = series.period;
    let total = series.total();
    let noun = if http { "request" } else { "connection" };
    let nouns = if http { "requests" } else { "connections" };
    let title = if http { "Requests" } else { "Connections" };
    let requests: Vec<f64> = series.points.iter().map(|t| t.requests as f64).collect();
    let peak = requests.iter().cloned().fold(0.0, f64::max);
    let max = nice_max(peak);
    let carried = Chart {
        title,
        summary: format!(
            "{} in all, at most {} in {}. {} to the app, {} back.",
            count_of(total.requests, noun, nouns),
            thousands(peak as u64),
            slot_words(p),
            bytes(total.bytes_in),
            bytes(total.bytes_out)
        ),
        period: p,
        last_slot_at: series.last_slot_at,
        plot: Plot::Columns { values: requests, max, bad: false },
        top: thousands(max as u64),
        column: title,
        rows: series.points.iter().map(|t| (t.requests > 0).then(|| thousands(t.requests))).collect(),
    };
    let failed = if total.failed() == 0 {
        let busy = if total.refused > 0 { format!(" {} turned away, busy.", thousands(total.refused)) } else { String::new() };
        format!(r#"<div class="card chart"><h3>Couldn't reach app</h3><p class="sum">None in {}.{busy}</p></div>"#, period_words(p))
    } else {
        let values: Vec<f64> = series.points.iter().map(|t| t.failed() as f64).collect();
        let max = nice_max(values.iter().cloned().fold(0.0, f64::max));
        Chart {
            title: "Couldn't reach app",
            summary: format!("{} in all: {}.", thousands(total.failed()), causes(&total)),
            period: p,
            last_slot_at: series.last_slot_at,
            plot: Plot::Columns { values, max, bad: true },
            top: thousands(max as u64),
            column: "Couldn't reach app",
            rows: series.points.iter().map(|t| (t.failed() > 0).then(|| format!("{} ({})", thousands(t.failed()), causes(t)))).collect(),
        }
        .render()
    };
    let p95: Vec<Option<f64>> = series.points.iter().map(|t| t.quantile(0.95).map(|q| q.map_or(30_000.0, |us| us as f64 / 1000.0))).collect();
    let timing = if p95.iter().all(Option::is_none) {
        format!(r#"<div class="card chart"><h3>Response time</h3><p class="sum">Nothing answered in {}.</p></div>"#, period_words(p))
    } else {
        let max = nice_max(p95.iter().flatten().cloned().fold(0.0, f64::max));
        let what = if http { "the response's headers" } else { "the machine's go-ahead" };
        Chart {
            title: "Response time, 95th percentile",
            summary: format!(
                "Time to {what}: half {}, 95% {}.",
                total.quantile(0.5).map(within).unwrap_or_default(),
                total.quantile(0.95).map(within).unwrap_or_default()
            ),
            period: p,
            last_slot_at: series.last_slot_at,
            plot: Plot::Line { values: p95.clone(), max },
            top: millis(max),
            column: "95% of answers",
            rows: series.points.iter().map(|t| t.quantile(0.95).map(within)).collect(),
        }
        .render()
    };
    format!(
        r#"<div class="section"><h2>Traffic</h2></div>{periods}{since}<div class="charts">{carried}{failed}{timing}</div>"#,
        periods = periods(href, p),
        since = since_note(series),
        carried = carried.render(),
    )
}

/// A machine's history on its page: its round trips and connections.
pub(super) fn presence_section(href: &str, series: &Series<Presence>) -> String {
    let p = series.period;
    let total = series.total();
    let trips = round_trips(series);
    let round_trip = if trips.iter().all(Option::is_none) {
        format!(r#"<div class="card chart"><h3>Round trip</h3><p class="sum">None timed in {}.</p></div>"#, period_words(p))
    } else {
        let highest = trips.iter().flatten().cloned().fold(0.0, f64::max);
        let max = nice_max(highest);
        Chart {
            title: "Round trip",
            summary: format!("Average {}, highest {}, over its connections.", millis(f64::from(total.round_trip) / 1000.0), millis(highest)),
            period: p,
            last_slot_at: series.last_slot_at,
            plot: Plot::Line { values: trips.clone(), max },
            top: millis(max),
            column: "Round trip",
            rows: trips.iter().map(|t| t.map(millis)).collect(),
        }
        .render()
    };
    let offline_secs = i64::from(total.samples.saturating_sub(total.online)) * crate::control::history::SAMPLE_SECS;
    let values: Vec<f64> = series.points.iter().map(|s| f64::from(s.connections)).collect();
    let max = nice_max(values.iter().cloned().fold(0.0, f64::max));
    let presence = match (total.samples, offline_secs) {
        (0, _) => "Nothing known yet.".to_string(),
        (_, 0) => "Connected the whole time".to_string(),
        (_, s) if total.online == 0 => format!("Offline the whole time, {}", ago(s)),
        (_, s) => format!("Offline for about {}", ago(s)),
    };
    let reconnects = match total.reconnects {
        0 => ".".to_string(),
        n => format!(", reconnected {}.", count(usize::from(n), "time", "times")),
    };
    let connections = Chart {
        title: "Connections",
        summary: format!("{presence}{reconnects}"),
        period: p,
        last_slot_at: series.last_slot_at,
        plot: Plot::Columns { values, max, bad: false },
        top: thousands(max as u64),
        column: "Connections",
        rows: series
            .points
            .iter()
            .map(|s| (s.samples > 0).then(|| if s.online == 0 { "offline".to_string() } else { s.connections.to_string() }))
            .collect(),
    };
    format!(
        r#"<div class="section"><h2>Connection</h2></div>{periods}{since}<div class="charts">{round_trip}{connections}</div>"#,
        periods = periods(href, p),
        since = since_note(series),
        connections = connections.render(),
    )
}

fn since_note<T>(series: &Series<T>) -> String {
    series
        .since
        .map(|at| format!(r#"<p class="note below-section">History starts when the server does, {}.</p>"#, esc(&magicpipes_core::rfc3339(at).replace('T', " ").replace('Z', " UTC"))))
        .unwrap_or_default()
}

/// Each slot's round trip in milliseconds, `None` where none was timed.
fn round_trips(series: &Series<Presence>) -> Vec<Option<f64>> {
    series.points.iter().map(|s| (s.round_trip > 0).then(|| f64::from(s.round_trip) / 1000.0)).collect()
}

/// `1,204`.
pub(super) fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn count_of(n: u64, one: &str, many: &str) -> String {
    format!("{} {}", thousands(n), if n == 1 { one } else { many })
}

/// A time from the buckets: `None` is past the last one. Within the first (up to 1 ms) nothing
/// more precise is known.
fn micros(us: Option<u64>) -> String {
    match us {
        Some(us) if us < 1000 => "under 1 ms".to_string(),
        Some(us) => millis(us as f64 / 1000.0),
        None => "over 30 s".to_string(),
    }
}

/// A share of answers came `within 12 ms`, `under 1 ms` or `over 30 s`.
fn within(us: Option<u64>) -> String {
    match us {
        Some(us) if us >= 1000 => format!("within {}", micros(Some(us))),
        _ => micros(us),
    }
}

/// `0.4 ms`, `12 ms`, `1.5 s`.
fn millis(ms: f64) -> String {
    if ms < 10.0 {
        format!("{ms:.1} ms")
    } else if ms < 1000.0 {
        format!("{ms:.0} ms")
    } else {
        format!("{:.1} s", ms / 1000.0)
    }
}

/// `512 B`, `3.4 MB`.
fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1000.0 && unit < UNITS.len() - 1 {
        v /= 1000.0;
        unit += 1;
    }
    if unit == 0 { format!("{n} B") } else { format!("{v:.1} {}", UNITS[unit]) }
}

/// A length of time, roughly: `40 seconds`, `3 minutes`, `5 hours`, `2 days`.
fn ago(secs: i64) -> String {
    let secs = secs.max(0);
    let (n, one, many) = match secs {
        0..60 => (secs, "second", "seconds"),
        60..3_600 => (secs / 60, "minute", "minutes"),
        3_600..86_400 => (secs / 3_600, "hour", "hours"),
        _ => (secs / 86_400, "day", "days"),
    };
    count(usize::try_from(n).unwrap_or(usize::MAX), one, many)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_read_well() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(1_234_567), "1,234,567");
        assert_eq!(millis(0.42), "0.4 ms");
        assert_eq!(millis(12.4), "12 ms");
        assert_eq!(millis(1_520.0), "1.5 s");
        assert_eq!(micros(None), "over 30 s");
        assert_eq!(micros(Some(500)), "under 1 ms");
        assert_eq!(micros(Some(1_000)), "1.0 ms");
        assert_eq!(within(Some(12_000)), "within 12 ms");
        assert_eq!(within(Some(10)), "under 1 ms");
        assert_eq!(within(None), "over 30 s");
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(3_400_000), "3.4 MB");
        assert_eq!(ago(59), "59 seconds");
        assert_eq!(ago(61), "1 minute");
        assert_eq!(ago(7_200), "2 hours");
        assert_eq!(ago(90_000), "1 day");
    }

    #[test]
    fn causes_name_each_one_that_happened() {
        let t = Traffic { unreachable: 3, timed_out: 1, refused: 1_200, ..Default::default() };
        assert_eq!(causes(&t), "app down 3 · too slow 1 · turned away, busy 1,200");
        assert_eq!(causes(&Traffic::default()), "");
    }
}
