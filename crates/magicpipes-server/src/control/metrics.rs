//! Metrics for Prometheus (`/metrics`), for administrators. What's read under the registry lock is
//! copied out (counters are shared atomics, so that's a handful of `Arc`s), and the text is written
//! after letting go, so a scrape holds up nothing else for long. Nothing here touches SQLite.

use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;

use magicpipes_core::error::ErrorCode;

use super::ControlPlane;
use crate::authz::{self, Action, Principal, Resource};
use crate::certs::CertStatus;
use crate::data::{LATENCY_BUCKETS_MS, RouteStats};

struct Tunnel {
    name: String,
    kind: &'static str,
    hostname: String,
    agent_id: String,
    up: bool,
    stats: Arc<RouteStats>,
    http: bool,
}

struct Agent {
    id: String,
    name: String,
    /// Each connection's last round trip in microseconds, 0 if unknown; empty when not connected.
    round_trips: Vec<u64>,
    data_streams: usize,
}

impl ControlPlane {
    /// The metrics in Prometheus' text format; `None` unless `who` is an administrator.
    pub fn metrics(&self, who: &Principal) -> Option<String> {
        if !authz::authorize(who, Action::Discover, Resource::Org) {
            return None;
        }
        let (tunnels, agents, ports_used) = {
            let st = self.state.lock().unwrap();
            let connected = |agent_id: &str| st.sessions.get(agent_id).is_some_and(|l| !l.is_closed());
            let tunnels: Vec<Tunnel> = st
                .tunnels
                .values()
                .map(|t| Tunnel {
                    name: t.row.name.clone(),
                    kind: t.row.kind.as_str(),
                    hostname: t.row.hostname.clone(),
                    agent_id: t.row.agent_id.clone(),
                    up: connected(&t.row.agent_id),
                    stats: t.stats.clone(),
                    http: t.row.kind.is_http(),
                })
                .collect();
            let agents: Vec<Agent> = st
                .dir
                .agents()
                .map(|a| {
                    let lanes = st.sessions.get(&a.id).map(|l| l.lanes.as_slice()).unwrap_or_default();
                    Agent {
                        id: a.id.clone(),
                        name: a.name.clone(),
                        round_trips: lanes.iter().filter(|s| !s.handle.is_closed()).map(|s| s.round_trip.load(Relaxed)).collect(),
                        data_streams: lanes.iter().map(|s| s.handle.data_streams()).sum(),
                    }
                })
                .collect();
            let ports_used = st.tunnels.values().filter(|t| t.row.public_port.is_some()).count();
            (tunnels, agents, ports_used)
        };
        let mut hosts: Vec<&str> = tunnels.iter().filter(|t| t.http).map(|t| t.hostname.as_str()).collect();
        // The management host's certificate, unless it comes from its own files.
        if self.cfg.management.cert_file.is_none() {
            hosts.push(&self.cfg.management.hostname);
        }
        let certs: Vec<(&str, bool, Option<i64>)> =
            hosts.into_iter().map(|h| (h, self.certs.status(h) == CertStatus::Ready, self.certs.not_after(h))).collect();

        let mut m = Metrics::default();
        m.family("magicpipes_build_info", "gauge", "The server's version.");
        m.line("magicpipes_build_info", &[("version", magicpipes_core::VERSION)], 1);
        m.family("magicpipes_start_time_seconds", "gauge", "When the server started, in Unix time.");
        m.line("magicpipes_start_time_seconds", &[], self.started_at);
        if let Some(range) = self.cfg.port_range() {
            m.family("magicpipes_ports", "gauge", "Public ports in the [ports] range, and how many of them tunnels hold.");
            m.line("magicpipes_ports", &[("state", "total")], range.len());
            m.line("magicpipes_ports", &[("state", "used")], ports_used);
        }

        m.family("magicpipes_agent_up", "gauge", "Whether the machine's agent is connected.");
        for a in &agents {
            m.line("magicpipes_agent_up", &[("agent_id", &a.id), ("agent", &a.name)], u8::from(!a.round_trips.is_empty()));
        }
        m.family("magicpipes_agent_connections", "gauge", "Connections the agent holds open to the server.");
        for a in agents.iter().filter(|a| !a.round_trips.is_empty()) {
            m.line("magicpipes_agent_connections", &[("agent_id", &a.id), ("agent", &a.name)], a.round_trips.len());
        }
        m.family("magicpipes_agent_data_streams", "gauge", "Streams open through the agent: requests and connections in progress, and idle connections kept for the next request.");
        for a in agents.iter().filter(|a| !a.round_trips.is_empty()) {
            m.line("magicpipes_agent_data_streams", &[("agent_id", &a.id), ("agent", &a.name)], a.data_streams);
        }
        m.family(
            "magicpipes_agent_ping_seconds",
            "gauge",
            "The last round trip timed on each of the agent's connections, behind its traffic. Missing after a ping got no answer.",
        );
        for a in &agents {
            for (i, rtt) in a.round_trips.iter().enumerate().filter(|(_, rtt)| **rtt > 0) {
                let connection = (i + 1).to_string();
                m.line("magicpipes_agent_ping_seconds", &[("agent_id", &a.id), ("agent", &a.name), ("connection", &connection)], Seconds(*rtt));
            }
        }

        m.family("magicpipes_tunnel_info", "gauge", "Each tunnel, with its kind, hostname and machine.");
        for t in &tunnels {
            m.line("magicpipes_tunnel_info", &[("tunnel", &t.name), ("kind", t.kind), ("hostname", &t.hostname), ("agent_id", &t.agent_id)], 1);
        }
        m.family("magicpipes_tunnel_up", "gauge", "Whether the agent serving the tunnel is connected.");
        for t in &tunnels {
            m.line("magicpipes_tunnel_up", &[("tunnel", &t.name)], u8::from(t.up));
        }
        m.family(
            "magicpipes_tunnel_requests_total",
            "counter",
            "HTTP requests and port connections passed to the agent, failed ones included, since the server started.",
        );
        for t in &tunnels {
            m.line("magicpipes_tunnel_requests_total", &[("tunnel", &t.name)], t.stats.requests.load(Relaxed));
        }
        m.family(
            "magicpipes_tunnel_failures_total",
            "counter",
            "Requests and connections that failed before the app answered, by cause. The app's own errors are not counted.",
        );
        for t in &tunnels {
            for (cause, n) in [
                (ErrorCode::AgentOffline, &t.stats.offline),
                (ErrorCode::LocalUnreachable, &t.stats.unreachable),
                (ErrorCode::UpstreamTimeout, &t.stats.timed_out),
            ] {
                m.line("magicpipes_tunnel_failures_total", &[("tunnel", &t.name), ("cause", cause.as_str())], n.load(Relaxed));
            }
        }
        m.family(
            "magicpipes_tunnel_refused_total",
            "counter",
            "Requests and connections turned away because the agent or the client had no streams left.",
        );
        for t in &tunnels {
            m.line("magicpipes_tunnel_refused_total", &[("tunnel", &t.name)], t.stats.refused.load(Relaxed));
        }
        m.family(
            "magicpipes_tunnel_response_seconds",
            "histogram",
            "Time until the app answered: the response's headers over HTTP, the agent's go-ahead for a port connection.",
        );
        for t in &tunnels {
            let latency = &t.stats.latency;
            let mut count = 0;
            for (i, bucket) in latency.buckets.iter().enumerate() {
                count += bucket.load(Relaxed);
                let le = LATENCY_BUCKETS_MS.get(i).map_or_else(|| "+Inf".to_string(), |ms| (*ms as f64 / 1000.0).to_string());
                m.line("magicpipes_tunnel_response_seconds_bucket", &[("tunnel", &t.name), ("le", &le)], count);
            }
            m.line("magicpipes_tunnel_response_seconds_sum", &[("tunnel", &t.name)], Seconds(latency.sum_micros.load(Relaxed)));
            m.line("magicpipes_tunnel_response_seconds_count", &[("tunnel", &t.name)], count);
        }
        m.family(
            "magicpipes_tunnel_bytes_total",
            "counter",
            "Bytes through the tunnel: to_app from visitors, from_app back to them. Bodies over HTTP; everything once a connection is joined through.",
        );
        for t in &tunnels {
            m.line("magicpipes_tunnel_bytes_total", &[("tunnel", &t.name), ("direction", "to_app")], t.stats.bytes_in.load(Relaxed));
            m.line("magicpipes_tunnel_bytes_total", &[("tunnel", &t.name), ("direction", "from_app")], t.stats.bytes_out.load(Relaxed));
        }
        m.family("magicpipes_tunnel_last_request_time_seconds", "gauge", "When the tunnel last had a request or connection, in Unix time.");
        for t in &tunnels {
            let last = t.stats.last_request_at.load(Relaxed);
            if last > 0 {
                m.line("magicpipes_tunnel_last_request_time_seconds", &[("tunnel", &t.name)], last);
            }
        }

        let (warn, bad) = self.open_alerts_by_severity();
        m.family("magicpipes_alerts_open", "gauge", "Alerts open on the Health page, by severity.");
        m.line("magicpipes_alerts_open", &[("severity", "warn")], warn);
        m.line("magicpipes_alerts_open", &[("severity", "bad")], bad);

        m.family("magicpipes_certificate_ready", "gauge", "Whether the hostname has a certificate in use.");
        for (host, ready, _) in &certs {
            m.line("magicpipes_certificate_ready", &[("hostname", host)], u8::from(*ready));
        }
        m.family("magicpipes_certificate_expiry_time_seconds", "gauge", "When the hostname's certificate expires, in Unix time.");
        for (host, _, not_after) in &certs {
            if let Some(t) = not_after {
                m.line("magicpipes_certificate_expiry_time_seconds", &[("hostname", host)], t);
            }
        }
        Some(m.text)
    }
}

/// Microseconds, written as seconds.
struct Seconds(u64);

impl std::fmt::Display for Seconds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{:06}", self.0 / 1_000_000, self.0 % 1_000_000)
    }
}

/// Prometheus' text format, version 0.0.4.
#[derive(Default)]
struct Metrics {
    text: String,
}

impl Metrics {
    fn family(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.text, "# HELP {name} {help}\n# TYPE {name} {kind}");
    }

    fn line(&mut self, name: &str, labels: &[(&str, &str)], value: impl std::fmt::Display) {
        self.text.push_str(name);
        if !labels.is_empty() {
            self.text.push('{');
            for (i, (k, v)) in labels.iter().enumerate() {
                if i > 0 {
                    self.text.push(',');
                }
                self.text.push_str(k);
                self.text.push_str("=\"");
                escape_into(&mut self.text, v);
                self.text.push('"');
            }
            self.text.push('}');
        }
        let _ = writeln!(self.text, " {value}");
    }
}

/// A label value: backslash, double quote and line feed are escaped; nothing else needs to be.
fn escape_into(out: &mut String, value: &str) {
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_values_are_escaped() {
        let mut m = Metrics::default();
        m.line("x", &[("a", "say \"hi\"\\\nbye"), ("b", "ü")], 2);
        assert_eq!(m.text, "x{a=\"say \\\"hi\\\"\\\\\\nbye\",b=\"ü\"} 2\n");
        let mut m = Metrics::default();
        m.line("y", &[], 0);
        assert_eq!(m.text, "y 0\n");
    }

    #[test]
    fn seconds_keep_their_microseconds() {
        assert_eq!(Seconds(0).to_string(), "0.000000");
        assert_eq!(Seconds(1_500).to_string(), "0.001500");
        assert_eq!(Seconds(61_000_001).to_string(), "61.000001");
    }
}
