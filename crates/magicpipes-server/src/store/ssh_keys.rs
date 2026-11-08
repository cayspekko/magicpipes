//! Public keys for the SSH gateway (migration 8). Callers pass parsed, canonical keys
//! (`control::ssh`). They aren't secrets, so they're stored as they are.

use magicpipes_core::{secret, unix_now};
use rusqlite::{ErrorCode, params};

use super::Store;
use super::users::DEFAULT_ORG;

/// At most this many keys per account: a person has a few machines.
pub const MAX_SSH_KEYS_PER_USER: i64 = 20;

#[derive(Debug, Clone)]
pub struct SshKeyRow {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub algorithm: String,
    /// `SHA256:…`, which identifies the key to the gateway.
    pub fingerprint: String,
    /// The key in `authorized_keys` form, without a comment.
    pub public_key: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

pub struct NewSshKey<'a> {
    pub user_id: &'a str,
    pub name: &'a str,
    pub algorithm: &'a str,
    pub fingerprint: &'a str,
    pub public_key: &'a str,
}

pub enum AddedSshKey {
    Added(SshKeyRow),
    /// The account has [`MAX_SSH_KEYS_PER_USER`].
    Full,
    /// An account already has this key.
    Taken,
}

fn read(r: &rusqlite::Row<'_>) -> rusqlite::Result<SshKeyRow> {
    Ok(SshKeyRow {
        id: r.get(0)?,
        user_id: r.get(1)?,
        name: r.get(2)?,
        algorithm: r.get(3)?,
        fingerprint: r.get(4)?,
        public_key: r.get(5)?,
        created_at: r.get(6)?,
        last_used_at: r.get(7)?,
    })
}

const COLUMNS: &str = "id, user_id, name, algorithm, fingerprint, public_key, created_at, last_used_at";

impl Store {
    /// Every key, for the directory.
    pub fn ssh_keys(&self) -> anyhow::Result<Vec<SshKeyRow>> {
        self.with(|c| {
            let mut st = c.prepare(&format!("SELECT {COLUMNS} FROM ssh_keys"))?;
            st.query_map([], read)?.collect()
        })
    }

    pub fn user_ssh_keys(&self, user_id: &str) -> anyhow::Result<Vec<SshKeyRow>> {
        self.with(|c| {
            let mut st = c.prepare(&format!("SELECT {COLUMNS} FROM ssh_keys WHERE user_id = ?1 ORDER BY created_at, rowid"))?;
            st.query_map([user_id], read)?.collect()
        })
    }

    pub fn add_ssh_key(&self, key: &NewSshKey<'_>) -> anyhow::Result<AddedSshKey> {
        let row = SshKeyRow {
            id: secret::new_id("key"),
            user_id: key.user_id.to_string(),
            name: key.name.to_string(),
            algorithm: key.algorithm.to_string(),
            fingerprint: key.fingerprint.to_string(),
            public_key: key.public_key.to_string(),
            created_at: unix_now(),
            last_used_at: None,
        };
        self.with(|c| {
            let held: i64 = c.query_row("SELECT COUNT(*) FROM ssh_keys WHERE user_id = ?1", [key.user_id], |r| r.get(0))?;
            if held >= MAX_SSH_KEYS_PER_USER {
                return Ok(AddedSshKey::Full);
            }
            let inserted = c.execute(
                "INSERT INTO ssh_keys (id, user_id, org_id, name, algorithm, fingerprint, public_key, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![row.id, row.user_id, DEFAULT_ORG, row.name, row.algorithm, row.fingerprint, row.public_key, row.created_at],
            );
            match inserted {
                Ok(_) => Ok(AddedSshKey::Added(row.clone())),
                Err(e) if e.sqlite_error_code() == Some(ErrorCode::ConstraintViolation) => Ok(AddedSshKey::Taken),
                Err(e) => Err(e),
            }
        })
    }

    pub fn delete_ssh_key(&self, user_id: &str, id: &str) -> anyhow::Result<bool> {
        let n = self.with(|c| c.execute("DELETE FROM ssh_keys WHERE id = ?1 AND user_id = ?2", params![id, user_id]))?;
        Ok(n == 1)
    }

    /// The host key kept for each SSH tunnel, by tunnel id.
    pub fn ssh_host_keys(&self) -> anyhow::Result<std::collections::HashMap<String, String>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT tunnel_id, fingerprint FROM ssh_host_keys")?;
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
        })
    }

    /// Keeps a tunnel's host key unless it has one. Returns whether this one was kept.
    pub fn keep_ssh_host_key(&self, tunnel_id: &str, fingerprint: &str) -> anyhow::Result<bool> {
        let n = self.with(|c| {
            c.execute(
                "INSERT OR IGNORE INTO ssh_host_keys (tunnel_id, fingerprint, seen_at) SELECT id, ?2, ?3 FROM tunnels WHERE id = ?1",
                params![tunnel_id, fingerprint, unix_now()],
            )
        })?;
        Ok(n == 1)
    }

    /// Forgets a tunnel's host key, so the next one is kept. Returns whether it had one.
    pub fn forget_ssh_host_key(&self, tunnel_id: &str) -> anyhow::Result<bool> {
        Ok(self.with(|c| c.execute("DELETE FROM ssh_host_keys WHERE tunnel_id = ?1", [tunnel_id]))? == 1)
    }

    pub fn touch_ssh_key(&self, id: &str, at: i64) -> anyhow::Result<()> {
        self.with(|c| c.execute("UPDATE ssh_keys SET last_used_at = ?2 WHERE id = ?1", params![id, at]))?;
        Ok(())
    }
}
