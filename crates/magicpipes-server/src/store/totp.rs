//! Sign-in codes (migration 16): each account's authenticator key, sealed by the caller
//! (`Signer::encrypt_for`), the last step a code was used for, and recovery codes as digests.

use magicpipes_core::unix_now;
use rusqlite::{OptionalExtension, params};

use super::Store;

#[derive(Debug, Clone)]
pub struct TotpRow {
    /// The key, encrypted.
    pub secret: Vec<u8>,
    /// The 30-second step the last code was for: only a later one works.
    pub last_step: i64,
    pub created_at: i64,
    /// Recovery codes not used yet.
    pub recovery_left: i64,
}

impl Store {
    pub fn totp(&self, user_id: &str) -> anyhow::Result<Option<TotpRow>> {
        self.with(|c| {
            c.query_row(
                "SELECT secret, last_step, created_at, (SELECT COUNT(*) FROM recovery_codes r WHERE r.user_id = t.user_id) FROM totp t WHERE user_id = ?1",
                [user_id],
                |r| Ok(TotpRow { secret: r.get(0)?, last_step: r.get(1)?, created_at: r.get(2)?, recovery_left: r.get(3)? }),
            )
            .optional()
        })
    }

    /// Turns sign-in codes on with `secret`, whose code for `step` was just entered, and these
    /// recovery codes. `false` if they're on already, or the account is gone.
    pub fn set_totp(&self, user_id: &str, secret: &[u8], step: i64, recovery: &[String]) -> anyhow::Result<bool> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let n = tx.execute(
            "INSERT INTO totp (user_id, secret, last_step, created_at) SELECT ?1, ?2, ?3, ?4 WHERE EXISTS (SELECT 1 FROM users WHERE id = ?1)
             ON CONFLICT (user_id) DO NOTHING",
            params![user_id, secret, step, unix_now()],
        )?;
        if n == 1 {
            replace_recovery_codes(&tx, user_id, recovery)?;
        }
        tx.commit()?;
        Ok(n == 1)
    }

    /// Turns sign-in codes off, recovery codes and all. `false` if they were off.
    pub fn clear_totp(&self, user_id: &str) -> anyhow::Result<bool> {
        let n = self.with(|c| {
            c.execute("DELETE FROM recovery_codes WHERE user_id = ?1", [user_id])?;
            c.execute("DELETE FROM totp WHERE user_id = ?1", [user_id])
        })?;
        Ok(n == 1)
    }

    /// Records a code for `step` as used, if no code for it or a later step was. Two sign-ins with
    /// the same code can't both get here.
    pub fn use_totp_step(&self, user_id: &str, step: i64) -> anyhow::Result<bool> {
        let n = self.with(|c| c.execute("UPDATE totp SET last_step = ?2 WHERE user_id = ?1 AND last_step < ?2", params![user_id, step]))?;
        Ok(n == 1)
    }

    /// Uses up a recovery code. `false` if it isn't one of theirs, or was used.
    pub fn use_recovery_code(&self, user_id: &str, digest: &str) -> anyhow::Result<bool> {
        let n = self.with(|c| c.execute("DELETE FROM recovery_codes WHERE user_id = ?1 AND code_hash = ?2", params![user_id, digest]))?;
        Ok(n == 1)
    }

    /// New recovery codes in place of the old ones. `false` if sign-in codes are off.
    pub fn set_recovery_codes(&self, user_id: &str, recovery: &[String]) -> anyhow::Result<bool> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let on: bool = tx.query_row("SELECT EXISTS (SELECT 1 FROM totp WHERE user_id = ?1)", [user_id], |r| r.get(0))?;
        if on {
            replace_recovery_codes(&tx, user_id, recovery)?;
        }
        tx.commit()?;
        Ok(on)
    }
}

fn replace_recovery_codes(tx: &rusqlite::Transaction<'_>, user_id: &str, recovery: &[String]) -> rusqlite::Result<()> {
    tx.execute("DELETE FROM recovery_codes WHERE user_id = ?1", [user_id])?;
    for digest in recovery {
        tx.execute("INSERT OR IGNORE INTO recovery_codes (user_id, code_hash) VALUES (?1, ?2)", params![user_id, digest])?;
    }
    Ok(())
}
