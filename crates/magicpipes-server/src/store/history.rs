//! History in 5-minute slots, and alerts (`control/history.rs`, `control/alerts.rs`). Written by
//! the control plane's sampler, once per slot and when an alert opens, changes or closes; pruned
//! hourly to `monitoring.history_days`.

use std::collections::HashMap;

use rusqlite::params;

use super::Store;
use crate::control::history::{Presence, Traffic};

/// Closed alerts kept at most, whatever their age: one flapping all day can't fill the disk.
pub const MAX_CLOSED_ALERTS: i64 = 10_000;

const TRAFFIC_COLUMNS: &str = "requests, offline, unreachable, timed_out, refused, bytes_in, bytes_out, \
    l0, l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertRow {
    pub id: String,
    pub rule: String,
    pub subject: String,
    pub subject_name: String,
    /// `warn` or `bad`.
    pub severity: String,
    pub detail: String,
    pub opened_at: i64,
    pub closed_at: Option<i64>,
}

/// SQLite keeps integers signed: counters past `i64::MAX` are stored as that.
fn int(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn uint(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

/// A row's traffic, from column `at` on.
fn traffic(r: &rusqlite::Row<'_>, at: usize) -> rusqlite::Result<Traffic> {
    let n = |i: usize| r.get::<_, i64>(at + i).map(uint);
    let mut latency = [0u64; 15];
    for (i, l) in latency.iter_mut().enumerate() {
        *l = n(7 + i)?;
    }
    Ok(Traffic {
        requests: n(0)?,
        offline: n(1)?,
        unreachable: n(2)?,
        timed_out: n(3)?,
        refused: n(4)?,
        bytes_in: n(5)?,
        bytes_out: n(6)?,
        latency,
    })
}

fn presence(r: &rusqlite::Row<'_>, at: usize) -> rusqlite::Result<Presence> {
    let n = |i: usize| r.get::<_, i64>(at + i).map(|v| u32::try_from(v.max(0)).unwrap_or(u32::MAX));
    Ok(Presence {
        online: n(0)?,
        samples: n(1)?,
        connections: u8::try_from(n(2)?).unwrap_or(u8::MAX),
        round_trip: n(3)?,
        round_trips: n(4)?,
        reconnects: n(5)?,
    })
}

fn alert(r: &rusqlite::Row<'_>) -> rusqlite::Result<AlertRow> {
    Ok(AlertRow {
        id: r.get(0)?,
        rule: r.get(1)?,
        subject: r.get(2)?,
        subject_name: r.get(3)?,
        severity: r.get(4)?,
        detail: r.get(5)?,
        opened_at: r.get(6)?,
        closed_at: r.get(7)?,
    })
}

const ALERT_COLUMNS: &str = "id, rule, subject, subject_name, severity, detail, opened_at, closed_at";

impl Store {
    /// Keeps closed 5-minute slots. A tunnel or agent deleted meanwhile is skipped.
    pub fn save_history(&self, tunnels: &[(String, i64, Traffic)], agents: &[(String, i64, Presence)]) -> anyhow::Result<()> {
        if tunnels.is_empty() && agents.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        {
            let mut t = tx.prepare(&format!(
                "INSERT OR REPLACE INTO tunnel_history (tunnel_id, slot, {TRAFFIC_COLUMNS}) \
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24 \
                 WHERE EXISTS (SELECT 1 FROM tunnels WHERE id = ?1)"
            ))?;
            for (id, slot, x) in tunnels {
                let l = x.latency.map(int);
                t.execute(params![
                    id, slot, int(x.requests), int(x.offline), int(x.unreachable), int(x.timed_out), int(x.refused), int(x.bytes_in),
                    int(x.bytes_out), l[0], l[1], l[2], l[3], l[4], l[5], l[6], l[7], l[8], l[9], l[10], l[11], l[12], l[13], l[14]
                ])?;
            }
            let mut a = tx.prepare(
                "INSERT OR REPLACE INTO agent_history (agent_id, slot, online, samples, connections, round_trip, round_trips, reconnects) \
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8 WHERE EXISTS (SELECT 1 FROM agents WHERE id = ?1)",
            )?;
            for (id, slot, p) in agents {
                a.execute(params![id, slot, p.online, p.samples, p.connections, p.round_trip, p.round_trips, p.reconnects])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Every tunnel's slots from `from` on, oldest first, to fill the day in memory at startup.
    pub fn tunnel_history_since(&self, from: i64) -> anyhow::Result<Vec<(String, i64, Traffic)>> {
        self.with(|c| {
            let mut q = c.prepare(&format!("SELECT tunnel_id, slot, {TRAFFIC_COLUMNS} FROM tunnel_history WHERE slot >= ?1 ORDER BY slot"))?;
            q.query_map([from], |r| Ok((r.get(0)?, r.get(1)?, traffic(r, 2)?)))?.collect()
        })
    }

    pub fn agent_history_since(&self, from: i64) -> anyhow::Result<Vec<(String, i64, Presence)>> {
        self.with(|c| {
            let mut q = c.prepare(
                "SELECT agent_id, slot, online, samples, connections, round_trip, round_trips, reconnects FROM agent_history \
                 WHERE slot >= ?1 ORDER BY slot",
            )?;
            q.query_map([from], |r| Ok((r.get(0)?, r.get(1)?, presence(r, 2)?)))?.collect()
        })
    }

    /// Tunnels' history from `from` on, added up in slots of `slot_secs` (keyed by when each
    /// starts): every tunnel's, or `only` one's.
    pub fn tunnel_history_by(&self, from: i64, slot_secs: i64, only: Option<&str>) -> anyhow::Result<HashMap<String, Vec<(i64, Traffic)>>> {
        // TOTAL, which doesn't fail on overflow, made an integer again, which saturates.
        let sums: String = TRAFFIC_COLUMNS.split(',').map(|c| format!("CAST(TOTAL({}) AS INTEGER)", c.trim())).collect::<Vec<_>>().join(", ");
        let rows: Vec<(String, i64, Traffic)> = self.with(|c| {
            let mut q = c.prepare(&format!(
                "SELECT tunnel_id, (slot / ?2) * ?2 AS s, {sums} FROM tunnel_history \
                 WHERE slot >= ?1 AND (?3 IS NULL OR tunnel_id = ?3) GROUP BY tunnel_id, s ORDER BY s"
            ))?;
            q.query_map(params![from, slot_secs.max(1), only], |r| Ok((r.get(0)?, r.get(1)?, traffic(r, 2)?)))?.collect()
        })?;
        let mut out: HashMap<String, Vec<(i64, Traffic)>> = HashMap::new();
        for (id, slot, t) in rows {
            out.entry(id).or_default().push((slot, t));
        }
        Ok(out)
    }

    /// Agents' history from `from` on, in slots of `slot_secs`: every agent's, or `only` one's.
    pub fn agent_history_by(&self, from: i64, slot_secs: i64, only: Option<&str>) -> anyhow::Result<HashMap<String, Vec<(i64, Presence)>>> {
        let rows: Vec<(String, i64, Presence)> = self.with(|c| {
            let mut q = c.prepare(
                "SELECT agent_id, (slot / ?2) * ?2 AS s, CAST(TOTAL(online) AS INTEGER), CAST(TOTAL(samples) AS INTEGER), MAX(connections), \
                 CAST(COALESCE(TOTAL(round_trip * round_trips) / NULLIF(TOTAL(round_trips), 0), 0) AS INTEGER), \
                 CAST(TOTAL(round_trips) AS INTEGER), CAST(TOTAL(reconnects) AS INTEGER) \
                 FROM agent_history WHERE slot >= ?1 AND (?3 IS NULL OR agent_id = ?3) GROUP BY agent_id, s ORDER BY s",
            )?;
            q.query_map(params![from, slot_secs.max(1), only], |r| Ok((r.get(0)?, r.get(1)?, presence(r, 2)?)))?.collect()
        })?;
        let mut out: HashMap<String, Vec<(i64, Presence)>> = HashMap::new();
        for (id, slot, p) in rows {
            out.entry(id).or_default().push((slot, p));
        }
        Ok(out)
    }

    /// When the oldest slot kept starts.
    pub fn oldest_history(&self) -> anyhow::Result<Option<i64>> {
        self.with(|c| c.query_row("SELECT MIN(m) FROM (SELECT MIN(slot) AS m FROM tunnel_history UNION ALL SELECT MIN(slot) FROM agent_history)", [], |r| r.get(0)))
    }

    /// Forgets slots before `before`, and closed alerts before then or past [`MAX_CLOSED_ALERTS`].
    pub fn prune_history(&self, before: i64) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute("DELETE FROM tunnel_history WHERE slot < ?1", [before])?;
            c.execute("DELETE FROM agent_history WHERE slot < ?1", [before])?;
            c.execute("DELETE FROM alerts WHERE closed_at IS NOT NULL AND closed_at < ?1", [before])?;
            c.execute(
                "DELETE FROM alerts WHERE closed_at IS NOT NULL AND id NOT IN \
                 (SELECT id FROM alerts WHERE closed_at IS NOT NULL ORDER BY closed_at DESC LIMIT ?1)",
                [MAX_CLOSED_ALERTS],
            )
        })?;
        Ok(())
    }

    pub fn open_alert(&self, a: &AlertRow) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                &format!("INSERT INTO alerts ({ALERT_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"),
                params![a.id, a.rule, a.subject, a.subject_name, a.severity, a.detail, a.opened_at, a.closed_at],
            )
        })?;
        Ok(())
    }

    /// An open alert got worse or better: its severity and what it says now.
    pub fn update_alert(&self, id: &str, severity: &str, detail: &str) -> anyhow::Result<()> {
        self.with(|c| c.execute("UPDATE alerts SET severity = ?2, detail = ?3 WHERE id = ?1 AND closed_at IS NULL", params![id, severity, detail]))?;
        Ok(())
    }

    pub fn close_alert(&self, id: &str, closed_at: i64, detail: &str) -> anyhow::Result<()> {
        self.with(|c| c.execute("UPDATE alerts SET closed_at = ?2, detail = ?3 WHERE id = ?1 AND closed_at IS NULL", params![id, closed_at, detail]))?;
        Ok(())
    }

    pub fn open_alerts(&self) -> anyhow::Result<Vec<AlertRow>> {
        self.with(|c| {
            let mut q = c.prepare(&format!("SELECT {ALERT_COLUMNS} FROM alerts WHERE closed_at IS NULL ORDER BY opened_at"))?;
            q.query_map([], alert)?.collect()
        })
    }

    /// Alerts closed from `since` on, newest first, at most `limit`.
    pub fn closed_alerts(&self, since: i64, limit: usize) -> anyhow::Result<Vec<AlertRow>> {
        self.with(|c| {
            let mut q = c.prepare(&format!("SELECT {ALERT_COLUMNS} FROM alerts WHERE closed_at >= ?1 ORDER BY closed_at DESC LIMIT ?2"))?;
            q.query_map(params![since, i64::try_from(limit).unwrap_or(i64::MAX)], alert)?.collect()
        })
    }

    #[cfg(test)]
    pub(crate) fn alert(&self, id: &str) -> anyhow::Result<Option<AlertRow>> {
        self.with(|c| rusqlite::OptionalExtension::optional(c.query_row(&format!("SELECT {ALERT_COLUMNS} FROM alerts WHERE id = ?1"), [id], alert)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use magicpipes_core::secret;

    fn store() -> (Store, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("mp-store-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        (Store::open(&dir.join("db.sqlite")).unwrap(), dir)
    }

    #[test]
    fn history_is_kept_added_up_and_pruned() {
        let (store, dir) = store();
        store.with(|c| c.execute("INSERT INTO agents (id, name, token_hash, created_at) VALUES ('ag_a', 'a', 'x', 0)", [])).unwrap();
        store
            .with(|c| {
                c.execute(
                    "INSERT INTO tunnels (id, name, hostname, agent_id, target, created_at) VALUES ('tn_a', 'a', 'a.t.test', 'ag_a', 'http://x', 0)",
                    [],
                )
            })
            .unwrap();
        let mut t = Traffic { requests: 10, unreachable: 1, bytes_out: u64::MAX, ..Default::default() };
        t.latency[3] = 9;
        let p = Presence { online: 30, samples: 30, connections: 4, round_trip: 2_000, round_trips: 30, reconnects: 1 };
        let gone = Presence { online: 1, ..Default::default() };
        store
            .save_history(&[("tn_a".into(), 0, t), ("tn_a".into(), 300, t), ("tn_gone".into(), 0, t)], &[("ag_a".into(), 0, p), ("ag_gone".into(), 0, gone)])
            .unwrap();
        let back = store.tunnel_history_since(0).unwrap();
        assert_eq!(back.len(), 2, "a tunnel that's gone is skipped");
        assert_eq!(back[0].2.bytes_out, i64::MAX as u64, "kept as the largest it can");
        assert_eq!((back[1].1, back[1].2.requests, back[1].2.latency[3]), (300, 10, 9));
        let hourly = store.tunnel_history_by(0, 3600, None).unwrap();
        assert!(store.tunnel_history_by(0, 3600, Some("tn_other")).unwrap().is_empty());
        assert_eq!((hourly["tn_a"].len(), hourly["tn_a"][0].1.requests, hourly["tn_a"][0].1.latency[3]), (1, 20, 18));
        let agents = store.agent_history_by(0, 3600, Some("ag_a")).unwrap();
        assert_eq!(agents["ag_a"], vec![(0, p)]);
        assert!(!agents.contains_key("ag_gone"));
        assert_eq!(store.oldest_history().unwrap(), Some(0));
        store.prune_history(300).unwrap();
        assert_eq!(store.tunnel_history_since(0).unwrap().len(), 1);
        // And it goes with its tunnel.
        store.with(|c| c.execute("DELETE FROM tunnels WHERE id = 'tn_a'", [])).unwrap();
        assert!(store.tunnel_history_since(0).unwrap().is_empty());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn alerts_open_change_close_and_are_pruned() {
        let (store, dir) = store();
        let row = |id: &str, opened_at| AlertRow {
            id: id.into(),
            rule: "machine_offline".into(),
            subject: "machine:ag_a".into(),
            subject_name: "a".into(),
            severity: "warn".into(),
            detail: "Offline for 3 minutes".into(),
            opened_at,
            closed_at: None,
        };
        store.open_alert(&row("al_1", 10)).unwrap();
        store.open_alert(&row("al_2", 20)).unwrap();
        store.update_alert("al_1", "bad", "Offline for an hour").unwrap();
        assert_eq!(store.open_alerts().unwrap().iter().map(|a| a.id.as_str()).collect::<Vec<_>>(), ["al_1", "al_2"]);
        store.close_alert("al_1", 100, "Was offline for an hour").unwrap();
        store.update_alert("al_1", "warn", "a closed alert doesn't change").unwrap();
        let closed = store.alert("al_1").unwrap().unwrap();
        assert_eq!((closed.severity.as_str(), closed.detail.as_str(), closed.closed_at), ("bad", "Was offline for an hour", Some(100)));
        assert_eq!(store.closed_alerts(50, 10).unwrap(), vec![closed]);
        assert!(store.closed_alerts(101, 10).unwrap().is_empty());
        store.prune_history(101).unwrap();
        assert!(store.alert("al_1").unwrap().is_none(), "closed before the cutoff");
        assert!(store.alert("al_2").unwrap().is_some(), "an open alert stays, however old");
        std::fs::remove_dir_all(dir).ok();
    }
}
