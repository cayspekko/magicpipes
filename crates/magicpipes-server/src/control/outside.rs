//! What `magicpipes probe` found from outside the server's network: each tunnel's public address,
//! reached as a visitor reaches it, through DNS, firewalls and any proxy in front of the server,
//! none of which the server's own checks ([`super::checks`]) pass through. People run the probe
//! wherever they like, with an API token, and it reports here (`POST /api/v1/probes`). A report
//! counts only for tunnels its sender manages. Two failed reports in a row open an alert, while
//! the last is under [`FRESH_SECS`] old. Results are kept in memory, the last one per tunnel.

use std::collections::HashMap;

use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::ErrorBody;
use magicpipes_core::unix_now;
use serde::Deserialize;

use super::users::denied;
use super::{ControlPlane, err};
use crate::authz::{Action, Principal};

/// How long a report counts for an alert: a probe that stopped running says nothing new.
pub const FRESH_SECS: i64 = 3600;
/// Results in one report.
pub const MAX_RESULTS: usize = 1000;

/// One tunnel's result, as the probe sends it.
#[derive(Debug, Clone, Deserialize)]
pub struct ProbeResult {
    /// The tunnel's id.
    pub tunnel: String,
    pub ok: bool,
    /// What answered, or what went wrong.
    #[serde(default)]
    pub said: String,
}

/// A tunnel's last result from outside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutsideResult {
    pub at: i64,
    pub ok: bool,
    pub said: String,
    /// Failures in a row, this one included.
    pub failures: u32,
}

#[derive(Debug, Default)]
pub struct Outside {
    last: HashMap<String, OutsideResult>,
}

impl Outside {
    pub fn get(&self, tunnel_id: &str) -> Option<&OutsideResult> {
        self.last.get(tunnel_id)
    }

    /// The failures in a row and why, for a recent result that failed.
    pub fn failing(&self, tunnel_id: &str, now: i64) -> Option<(u32, String)> {
        self.last.get(tunnel_id).filter(|r| !r.ok && now - r.at < FRESH_SECS).map(|r| (r.failures, r.said.clone()))
    }

    fn record(&mut self, tunnel_id: String, ok: bool, said: String, at: i64) {
        let before = self.last.get(&tunnel_id).map_or(0, |r| r.failures);
        let failures = if ok { 0 } else { before.saturating_add(1) };
        self.last.insert(tunnel_id, OutsideResult { at, ok, said, failures });
    }

    /// Forgets tunnels that are gone.
    pub fn keep(&mut self, present: impl Fn(&str) -> bool) {
        self.last.retain(|id, _| present(id));
    }
}

impl ControlPlane {
    /// Keeps a probe's results for the tunnels `who` manages, and says how many that was; others
    /// are left out as if they didn't exist. One result per tunnel counts, the last.
    pub fn report_outside(&self, who: &Principal, results: Vec<ProbeResult>) -> Result<usize, ErrorBody> {
        if matches!(who, Principal::Anonymous) {
            return Err(denied(who));
        }
        if results.len() > MAX_RESULTS {
            return Err(err(ErrorCode::InvalidRequest, format!("at most {MAX_RESULTS} results in one report")));
        }
        let mut by_tunnel: HashMap<String, ProbeResult> = HashMap::new();
        for r in results {
            by_tunnel.insert(r.tunnel.clone(), r);
        }
        let kept: Vec<ProbeResult> = {
            let st = self.state.lock().unwrap();
            by_tunnel.into_values().filter(|r| st.tunnels.get(&r.tunnel).is_some_and(|t| st.may(who, Action::Manage, t))).collect()
        };
        let now = unix_now();
        let mut outside = self.outside.lock().unwrap();
        for r in &kept {
            outside.record(r.tunnel.clone(), r.ok, super::checks::printable(r.said.as_bytes()), now);
        }
        Ok(kept.len())
    }

    /// A tunnel's last result from outside.
    pub fn outside_result(&self, tunnel_id: &str) -> Option<OutsideResult> {
        self.outside.lock().unwrap().get(tunnel_id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_count_in_a_row_and_go_stale() {
        let mut o = Outside::default();
        o.record("t".into(), false, "no DNS".into(), 100);
        assert_eq!(o.failing("t", 100), Some((1, "no DNS".into())));
        o.record("t".into(), false, "no DNS".into(), 200);
        assert_eq!(o.failing("t", 200), Some((2, "no DNS".into())));
        assert_eq!(o.failing("t", 200 + FRESH_SECS), None, "an old report");
        o.record("t".into(), true, "HTTP 200".into(), 300);
        assert_eq!(o.failing("t", 300), None);
        assert_eq!(o.get("t").map(|r| r.failures), Some(0));
        o.keep(|_| false);
        assert!(o.get("t").is_none());
    }
}
