//! SQLite persistence (control plane only — the data plane never touches the database).
//!
//! Secrets are stored as SHA-256 digests. All queries are short; callers hold the connection
//! mutex only for the duration of one statement or transaction.

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use magicpipes_core::{secret, unix_now};
use rusqlite::{Connection, OptionalExtension, params};

#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

#[derive(Debug, Clone)]
pub struct TunnelRow {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub agent_id: String,
    pub target: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct AgentRow {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS admin_tokens (
    id          TEXT PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER
);
CREATE TABLE IF NOT EXISTS enrollments (
    token_hash  TEXT PRIMARY KEY,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER,
    agent_id    TEXT
);
CREATE TABLE IF NOT EXISTS tunnels (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    hostname    TEXT NOT NULL UNIQUE,
    agent_id    TEXT NOT NULL REFERENCES agents(id),
    target      TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);
"#;

impl Store {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> anyhow::Result<T> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        Ok(f(&conn)?)
    }

    // ---- administrators -------------------------------------------------------------------

    pub fn admin_token_count(&self) -> anyhow::Result<i64> {
        self.with(|c| c.query_row("SELECT COUNT(*) FROM admin_tokens", [], |r| r.get(0)))
    }

    /// Creates a new admin token. With `replace_all`, every existing admin token is revoked.
    pub fn create_admin_token(&self, replace_all: bool) -> anyhow::Result<String> {
        let token = secret::new_token("mpadm");
        self.with(|c| {
            if replace_all {
                c.execute("DELETE FROM admin_tokens", [])?;
            }
            c.execute(
                "INSERT INTO admin_tokens (id, token_hash, created_at) VALUES (?1, ?2, ?3)",
                params![secret::new_id("adm"), secret::sha256_hex(&token), unix_now()],
            )
        })?;
        Ok(token)
    }

    pub fn verify_admin_token(&self, token: &str) -> anyhow::Result<bool> {
        if !token.starts_with("mpadm_") {
            return Ok(false);
        }
        let hash = secret::sha256_hex(token);
        let found: Option<String> = self.with(|c| {
            c.query_row("SELECT token_hash FROM admin_tokens WHERE token_hash = ?1", [&hash], |r| r.get(0))
                .optional()
        })?;
        Ok(found.is_some_and(|h| secret::constant_time_eq(h.as_bytes(), hash.as_bytes())))
    }

    // ---- enrollment & agents --------------------------------------------------------------

    pub fn create_enrollment(&self, ttl_secs: u64) -> anyhow::Result<String> {
        let token = secret::new_token("mpenr");
        let now = unix_now();
        self.with(|c| {
            c.execute("DELETE FROM enrollments WHERE expires_at < ?1 AND used_at IS NULL", [now])?;
            c.execute(
                "INSERT INTO enrollments (token_hash, created_at, expires_at) VALUES (?1, ?2, ?3)",
                params![secret::sha256_hex(&token), now, now + ttl_secs as i64],
            )
        })?;
        Ok(token)
    }

    /// Atomically consumes an enrollment token and creates an agent identity.
    /// Returns `(agent_id, agent_token)`, or `None` if the token is unknown, used or expired.
    pub fn enroll(&self, enrollment_token: &str, agent_name: &str) -> anyhow::Result<Option<(String, String)>> {
        let hash = secret::sha256_hex(enrollment_token);
        let now = unix_now();
        let agent_id = secret::new_id("ag");
        let agent_secret = secret::new_token("mpa");
        let agent_token = format!("{agent_id}.{agent_secret}");
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let updated = tx.execute(
            "UPDATE enrollments SET used_at = ?1, agent_id = ?2
             WHERE token_hash = ?3 AND used_at IS NULL AND expires_at >= ?1",
            params![now, agent_id, hash],
        )?;
        if updated != 1 {
            return Ok(None);
        }
        tx.execute(
            "INSERT INTO agents (id, name, token_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![agent_id, agent_name, secret::sha256_hex(&agent_token), now],
        )?;
        tx.commit()?;
        Ok(Some((agent_id, agent_token)))
    }

    /// Verifies an agent token (`<agent id>.<secret>`) and returns the agent id.
    pub fn verify_agent_token(&self, token: &str) -> anyhow::Result<Option<String>> {
        let Some((agent_id, _)) = token.split_once('.') else { return Ok(None) };
        if !agent_id.starts_with("ag_") {
            return Ok(None);
        }
        let stored: Option<String> = self.with(|c| {
            c.query_row("SELECT token_hash FROM agents WHERE id = ?1", [agent_id], |r| r.get(0)).optional()
        })?;
        Ok(stored.filter(|h| secret::verify(token, h)).map(|_| agent_id.to_string()))
    }

    pub fn touch_agent(&self, agent_id: &str) -> anyhow::Result<()> {
        self.with(|c| c.execute("UPDATE agents SET last_seen_at = ?1 WHERE id = ?2", params![unix_now(), agent_id]))?;
        Ok(())
    }

    pub fn agents(&self) -> anyhow::Result<Vec<AgentRow>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT id, name, created_at, last_seen_at FROM agents ORDER BY created_at")?;
            st.query_map([], |r| {
                Ok(AgentRow { id: r.get(0)?, name: r.get(1)?, created_at: r.get(2)?, last_seen_at: r.get(3)? })
            })?
            .collect()
        })
    }

    // ---- tunnels --------------------------------------------------------------------------

    pub fn tunnels(&self) -> anyhow::Result<Vec<TunnelRow>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT id, name, hostname, agent_id, target, created_at FROM tunnels ORDER BY created_at",
            )?;
            st.query_map([], |r| {
                Ok(TunnelRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    hostname: r.get(2)?,
                    agent_id: r.get(3)?,
                    target: r.get(4)?,
                    created_at: r.get(5)?,
                })
            })?
            .collect()
        })
    }

    pub fn insert_tunnel(&self, t: &TunnelRow) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO tunnels (id, name, hostname, agent_id, target, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![t.id, t.name, t.hostname, t.agent_id, t.target, t.created_at],
            )
        })?;
        Ok(())
    }

    pub fn update_tunnel_target(&self, id: &str, target: &str) -> anyhow::Result<()> {
        self.with(|c| c.execute("UPDATE tunnels SET target = ?1 WHERE id = ?2", params![target, id]))?;
        Ok(())
    }

    pub fn delete_tunnel(&self, id: &str) -> anyhow::Result<()> {
        self.with(|c| c.execute("DELETE FROM tunnels WHERE id = ?1", [id]))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_is_single_use() {
        let dir = std::env::temp_dir().join(format!("mp-store-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("db.sqlite")).unwrap();
        let enr = store.create_enrollment(60).unwrap();
        let (id, token) = store.enroll(&enr, "laptop").unwrap().unwrap();
        assert!(store.enroll(&enr, "again").unwrap().is_none());
        assert_eq!(store.verify_agent_token(&token).unwrap().as_deref(), Some(id.as_str()));
        assert!(store.verify_agent_token(&format!("{id}.wrong")).unwrap().is_none());
        let adm = store.create_admin_token(false).unwrap();
        assert!(store.verify_admin_token(&adm).unwrap());
        assert!(!store.verify_admin_token("mpadm_nope").unwrap());
        std::fs::remove_dir_all(dir).ok();
    }
}
