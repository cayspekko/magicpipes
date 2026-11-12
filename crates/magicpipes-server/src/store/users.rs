//! Users, UI sessions, API tokens and the audit log (migration 2).

use magicpipes_core::{secret, unix_now};
use rusqlite::{OptionalExtension, params};

use super::Store;
use crate::authz::Role;

/// The one organization until there are more.
pub const DEFAULT_ORG: &str = "org_default";
/// Identity issuer for accounts that log in with a password; the subject is the email.
pub const LOCAL_ISSUER: &str = "local";
/// UI sessions kept per user; logging in again drops the oldest.
const MAX_SESSIONS_PER_USER: i64 = 20;
/// API tokens one user may hold.
pub const MAX_API_TOKENS_PER_USER: i64 = 20;
/// Single sign-on stops creating accounts at this many: a provider that admits too many people
/// must not be able to grow the database without limit.
pub const MAX_USERS: i64 = 10_000;
/// The audit log never grows beyond this many entries, whatever the retention.
const MAX_AUDIT_ROWS: i64 = 100_000;
/// `users.disabled_reason` for an account disabled for going without a single sign-on.
const IDLE: &str = "idle";

#[derive(Debug, Clone)]
pub struct UserRow {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub role: Role,
    pub disabled: bool,
    /// Disabled for going without a single sign-on for `disable_idle_after_days`, not by an
    /// administrator: the next one enables it again.
    pub disabled_idle: bool,
    pub must_change_password: bool,
    /// Sessions created before this are no longer valid ("log out everywhere").
    pub sessions_valid_after: i64,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
    /// False for someone who only signs in with single sign-on.
    pub has_password: bool,
    /// They proved the address is theirs: through a provider that vouched for it, an invitation or
    /// a link sent there. An address an administrator typed in hasn't been proved.
    pub email_verified: bool,
}

pub(super) const USER_SELECT: &str = "SELECT u.id, u.email, u.display_name, m.role, u.disabled_at, COALESCE(p.must_change, 0),
    u.sessions_valid_after, u.created_at, (SELECT MAX(i.last_login_at) FROM identities i WHERE i.user_id = u.id),
    p.user_id IS NOT NULL, u.email_verified_at IS NOT NULL, u.disabled_reason IS 'idle'
    FROM users u JOIN memberships m ON m.user_id = u.id AND m.org_id = 'org_default'
    LEFT JOIN passwords p ON p.user_id = u.id";

pub(super) fn user_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<UserRow> {
    let role: String = r.get(3)?;
    let disabled: Option<i64> = r.get(4)?;
    let must_change: i64 = r.get(5)?;
    Ok(UserRow {
        id: r.get(0)?,
        email: r.get(1)?,
        display_name: r.get(2)?,
        // A role that can't be read grants the least.
        role: Role::parse(&role).unwrap_or(Role::Member),
        disabled: disabled.is_some(),
        disabled_idle: disabled.is_some() && r.get::<_, bool>(11)?,
        must_change_password: must_change != 0,
        sessions_valid_after: r.get(6)?,
        created_at: r.get(7)?,
        last_login_at: r.get(8)?,
        has_password: r.get(9)?,
        email_verified: r.get(10)?,
    })
}

/// A session to check with its provider.
#[derive(Debug, Clone)]
pub struct RecheckRow {
    pub id_hash: String,
    pub user_id: String,
    pub issuer: String,
    /// Encrypted.
    pub tokens: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SessionRow {
    /// `None` for a session created with an admin token.
    pub user_id: Option<String>,
    pub csrf: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ApiTokenRow {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct AuditRow {
    pub at: i64,
    pub actor: String,
    pub action: String,
    pub resource: String,
    pub detail: String,
}

/// The rows every account has: the user, their membership, and their personal tag, which they
/// hold from the start. An invitation for that address has nothing left to do.
pub(super) fn insert_user(tx: &rusqlite::Transaction<'_>, email: &str, display_name: &str, role: Role) -> rusqlite::Result<String> {
    let id = secret::new_id("us");
    let now = unix_now();
    tx.execute("DELETE FROM invitations WHERE email = ?1", [email])?;
    tx.execute("INSERT INTO users (id, email, display_name, created_at) VALUES (?1, ?2, ?3, ?4)", params![id, email, display_name, now])?;
    tx.execute("INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?1, ?2, ?3, ?4)", params![DEFAULT_ORG, id, role.as_str(), now])?;
    let tag = personal_tag_name(tx)?;
    tx.execute("INSERT INTO tags (org_id, name, access, user_id, created_at) VALUES (?1, ?2, 1, ?3, ?4)", params![DEFAULT_ORG, tag, id, now])?;
    tx.execute("INSERT INTO user_tags (org_id, user_id, tag, created_at) VALUES (?1, ?2, ?3, ?4)", params![DEFAULT_ORG, id, tag, now])?;
    Ok(id)
}

/// A new personal tag name, `user:` and 10 random lowercase letters and digits. It says nothing
/// about the person (the UI shows their email instead), so it never goes stale.
fn personal_tag_name(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<String> {
    loop {
        let mut n = secret::random_u64();
        let mut name = String::from("user:");
        for _ in 0..10 {
            name.push(char::from(b"0123456789abcdefghijklmnopqrstuvwxyz"[(n % 36) as usize]));
            n /= 36;
        }
        let taken: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM tags WHERE org_id = ?1 AND name = ?2)", params![DEFAULT_ORG, name], |r| r.get(0))?;
        if !taken {
            return Ok(name);
        }
    }
}

impl Store {
    // ---- users ----------------------------------------------------------------------------

    /// Creates a password account. Returns `None` if the email already has an account.
    pub fn create_user(&self, email: &str, display_name: &str, role: Role, password_hash: &str) -> anyhow::Result<Option<String>> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let taken: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM users WHERE email = ?1)", [email], |r| r.get(0))?;
        if taken {
            return Ok(None);
        }
        let id = insert_user(&tx, email, display_name, role)?;
        tx.execute("INSERT INTO identities (issuer, subject, user_id) VALUES (?1, ?2, ?3)", params![LOCAL_ISSUER, email, id])?;
        tx.execute("INSERT INTO passwords (user_id, hash, must_change, updated_at) VALUES (?1, ?2, 1, ?3)", params![id, password_hash, unix_now()])?;
        tx.commit()?;
        Ok(Some(id))
    }

    /// Creates an account that signs in with an outside identity. Returns `None` if the email
    /// already has an account, the identity already belongs to one, or there are [`MAX_USERS`].
    pub fn create_sso_user(&self, email: &str, display_name: &str, role: Role, issuer: &str, subject: &str) -> anyhow::Result<Option<String>> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let taken: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE email = ?1) OR EXISTS(SELECT 1 FROM identities WHERE issuer = ?2 AND subject = ?3)
             OR (SELECT COUNT(*) FROM users) >= ?4",
            params![email, issuer, subject, MAX_USERS],
            |r| r.get(0),
        )?;
        if taken {
            return Ok(None);
        }
        let id = insert_user(&tx, email, display_name, role)?;
        tx.execute("INSERT INTO identities (issuer, subject, user_id) VALUES (?1, ?2, ?3)", params![issuer, subject, id])?;
        tx.commit()?;
        Ok(Some(id))
    }

    /// The account an outside identity signs in to.
    pub fn identity_user(&self, issuer: &str, subject: &str) -> anyhow::Result<Option<UserRow>> {
        let id: Option<String> = self.with(|c| {
            c.query_row("SELECT user_id FROM identities WHERE issuer = ?1 AND subject = ?2", params![issuer, subject], |r| r.get(0)).optional()
        })?;
        match id {
            Some(id) => self.user(&id),
            None => Ok(None),
        }
    }

    pub fn user_by_email(&self, email: &str) -> anyhow::Result<Option<UserRow>> {
        self.with(|c| c.query_row(&format!("{USER_SELECT} WHERE u.email = ?1"), [email], user_row).optional())
    }

    /// Adds an outside identity to an account. `false` if the account already has an identity
    /// from this issuer: a reused address must not reach an account that signs in as someone
    /// else there.
    pub fn link_identity(&self, user_id: &str, issuer: &str, subject: &str) -> anyhow::Result<bool> {
        let n = self.with(|c| {
            c.execute(
                "INSERT INTO identities (issuer, subject, user_id) SELECT ?1, ?2, ?3
                 WHERE NOT EXISTS (SELECT 1 FROM identities WHERE issuer = ?1 AND user_id = ?3)
                 ON CONFLICT (issuer, subject) DO NOTHING",
                params![issuer, subject, user_id],
            )
        })?;
        Ok(n == 1)
    }

    /// Records a single sign-on, which vouches for the account: one disabled for going without
    /// ([`Self::disable_idle`]) is enabled again, and `true` says so. A temporary password an
    /// administrator set stops working here: its owner no longer needs it, and nobody else should
    /// keep a way in.
    pub fn finish_sso_login(&self, user_id: &str, issuer: &str) -> anyhow::Result<bool> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let now = unix_now();
        tx.execute("UPDATE identities SET last_login_at = ?1 WHERE user_id = ?2 AND issuer = ?3", params![now, user_id, issuer])?;
        tx.execute("DELETE FROM passwords WHERE user_id = ?1 AND must_change = 1", [user_id])?;
        let woke = tx.execute("UPDATE users SET disabled_at = NULL, disabled_reason = NULL WHERE id = ?1 AND disabled_reason = ?2", params![user_id, IDLE])? == 1;
        tx.execute("UPDATE users SET vouched_at = ?1 WHERE id = ?2", params![now, user_id])?;
        tx.commit()?;
        Ok(woke)
    }

    pub fn users(&self) -> anyhow::Result<Vec<UserRow>> {
        self.with(|c| {
            let mut st = c.prepare(&format!("{USER_SELECT} ORDER BY u.created_at"))?;
            st.query_map([], user_row)?.collect()
        })
    }

    pub fn user(&self, id: &str) -> anyhow::Result<Option<UserRow>> {
        self.with(|c| c.query_row(&format!("{USER_SELECT} WHERE u.id = ?1"), [id], user_row).optional())
    }

    /// The account that logs in with `email` and its password hash.
    pub fn password_login(&self, email: &str) -> anyhow::Result<Option<(UserRow, String)>> {
        let found: Option<(String, String)> = self.with(|c| {
            c.query_row(
                "SELECT i.user_id, p.hash FROM identities i JOIN passwords p ON p.user_id = i.user_id
                 WHERE i.issuer = ?1 AND i.subject = ?2",
                params![LOCAL_ISSUER, email],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
        })?;
        let Some((id, hash)) = found else { return Ok(None) };
        Ok(self.user(&id)?.map(|u| (u, hash)))
    }

    pub fn touch_login(&self, user_id: &str, issuer: &str) -> anyhow::Result<()> {
        self.with(|c| c.execute("UPDATE identities SET last_login_at = ?1 WHERE user_id = ?2 AND issuer = ?3", params![unix_now(), user_id, issuer]))?;
        Ok(())
    }

    /// Sets the password of an existing account, which may not have had one (single sign-on).
    pub fn set_password(&self, user_id: &str, hash: &str, must_change: bool) -> anyhow::Result<bool> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let email: Option<String> = tx.query_row("SELECT email FROM users WHERE id = ?1", [user_id], |r| r.get(0)).optional()?;
        let Some(email) = email else { return Ok(false) };
        tx.execute(
            "INSERT INTO passwords (user_id, hash, must_change, updated_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (user_id) DO UPDATE SET hash = excluded.hash, must_change = excluded.must_change, updated_at = excluded.updated_at",
            params![user_id, hash, must_change as i64, unix_now()],
        )?;
        tx.execute("INSERT OR IGNORE INTO identities (issuer, subject, user_id) VALUES (?1, ?2, ?3)", params![LOCAL_ISSUER, email, user_id])?;
        tx.commit()?;
        Ok(true)
    }

    /// Someone who stops being an administrator takes the invitations they sent with them: those
    /// were theirs to give.
    pub fn set_role(&self, user_id: &str, role: Role) -> anyhow::Result<bool> {
        let n = self.with(|c| {
            if role != Role::Admin {
                c.execute("DELETE FROM invitations WHERE created_by = ?1", [user_id])?;
            }
            c.execute("UPDATE memberships SET role = ?1 WHERE user_id = ?2 AND org_id = ?3", params![role.as_str(), user_id, DEFAULT_ORG])
        })?;
        Ok(n == 1)
    }

    /// Disabling also ends every session and the invitations they sent; the user's API tokens stop
    /// working while disabled. An administrator enabling an account vouches for it, so it has
    /// `disable_idle_after_days` from now.
    pub fn set_disabled(&self, user_id: &str, disabled: bool) -> anyhow::Result<bool> {
        let n = self.with(|c| {
            if disabled {
                c.execute("DELETE FROM invitations WHERE created_by = ?1", [user_id])?;
                c.execute("UPDATE users SET disabled_at = ?1, disabled_reason = NULL WHERE id = ?2", params![unix_now(), user_id])
            } else {
                c.execute("UPDATE users SET disabled_at = NULL, disabled_reason = NULL, vouched_at = ?1 WHERE id = ?2", params![unix_now(), user_id])
            }
        })?;
        if disabled {
            self.end_sessions(user_id)?;
        }
        Ok(n == 1)
    }

    /// Disables, as [`Self::set_disabled`] does, every account that signs in only through single
    /// sign-on (no password, an identity from elsewhere) and that nothing has vouched for since
    /// `before`, with an audit entry saying `why`. Returns them as they were, with how many machines
    /// each owns.
    pub fn disable_idle(&self, before: i64, why: &str) -> anyhow::Result<Vec<(UserRow, i64)>> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let idle: Vec<(UserRow, i64)> = {
            let mut st = tx.prepare(&format!(
                "{USER_SELECT} WHERE u.disabled_at IS NULL AND p.user_id IS NULL AND COALESCE(u.vouched_at, u.created_at) < ?1
                 AND EXISTS (SELECT 1 FROM identities i WHERE i.user_id = u.id AND i.issuer != ?2)"
            ))?;
            let rows = st.query_map(params![before, LOCAL_ISSUER], user_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
            let mut machines = tx.prepare("SELECT COUNT(*) FROM agents WHERE owner_user_id = ?1")?;
            let mut idle = Vec::with_capacity(rows.len());
            for u in rows {
                let n: i64 = machines.query_row([&u.id], |r| r.get(0))?;
                idle.push((u, n));
            }
            idle
        };
        let now = unix_now();
        for (u, _) in &idle {
            tx.execute("UPDATE users SET disabled_at = ?1, disabled_reason = ?2, sessions_valid_after = ?1 WHERE id = ?3", params![now, IDLE, u.id])?;
            tx.execute("DELETE FROM invitations WHERE created_by = ?1", [&u.id])?;
            tx.execute("DELETE FROM email_tokens WHERE user_id = ?1", [&u.id])?;
            tx.execute("DELETE FROM sessions WHERE user_id = ?1", [&u.id])?;
            tx.execute(
                "INSERT INTO audit_log (at, org_id, actor, action, resource, detail) VALUES (?1, ?2, 'anonymous', 'user.disable', ?3, ?4)",
                params![now, DEFAULT_ORG, u.id, why],
            )?;
        }
        tx.commit()?;
        Ok(idle)
    }

    /// Ends every UI session of a user ("log out everywhere", password changes), and the emailed
    /// links that would start another.
    pub fn end_sessions(&self, user_id: &str) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute("UPDATE users SET sessions_valid_after = ?1 WHERE id = ?2", params![unix_now(), user_id])?;
            c.execute("DELETE FROM email_tokens WHERE user_id = ?1", [user_id])?;
            c.execute("DELETE FROM sessions WHERE user_id = ?1", [user_id])
        })?;
        Ok(())
    }

    // ---- UI sessions ----------------------------------------------------------------------

    /// Creates a session for a user (or, with `None`, an admin token). Returns `(cookie, csrf)`.
    pub fn create_session(&self, user_id: Option<&str>, ttl_secs: u64) -> anyhow::Result<(String, String)> {
        let cookie = secret::random_string(43);
        let csrf = secret::random_string(32);
        let now = unix_now();
        self.with(|c| {
            c.execute("DELETE FROM sessions WHERE expires_at < ?1", [now])?;
            c.execute(
                "INSERT INTO sessions (id_hash, user_id, org_id, csrf, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![secret::sha256_hex(&cookie), user_id, DEFAULT_ORG, csrf, now, now + ttl_secs as i64],
            )?;
            if let Some(u) = user_id {
                c.execute(
                    "DELETE FROM sessions WHERE user_id = ?1 AND id_hash NOT IN
                     (SELECT id_hash FROM sessions WHERE user_id = ?1 ORDER BY created_at DESC, rowid DESC LIMIT ?2)",
                    params![u, MAX_SESSIONS_PER_USER],
                )?;
            }
            Ok(())
        })?;
        Ok((cookie, csrf))
    }

    /// The unexpired session for a cookie.
    pub fn session(&self, cookie: &str) -> anyhow::Result<Option<SessionRow>> {
        self.with(|c| {
            c.query_row(
                "SELECT user_id, csrf, created_at FROM sessions WHERE id_hash = ?1 AND expires_at >= ?2",
                params![secret::sha256_hex(cookie), unix_now()],
                |r| Ok(SessionRow { user_id: r.get(0)?, csrf: r.get(1)?, created_at: r.get(2)? }),
            )
            .optional()
        })
    }

    pub fn delete_session(&self, cookie: &str) -> anyhow::Result<()> {
        self.with(|c| c.execute("DELETE FROM sessions WHERE id_hash = ?1", [secret::sha256_hex(cookie)]))?;
        Ok(())
    }

    /// Marks a session as a single sign-on's: its source (the issuer), and the provider's tokens,
    /// encrypted by the caller. `rechecks`: they include a refresh token to check it with.
    pub fn set_session_source(&self, cookie: &str, issuer: &str, tokens: Option<&[u8]>, rechecks: bool) -> anyhow::Result<()> {
        let checked_at = rechecks.then(unix_now);
        self.with(|c| {
            c.execute("UPDATE sessions SET source = ?2, tokens = ?3, checked_at = ?4 WHERE id_hash = ?1", params![secret::sha256_hex(cookie), issuer, tokens, checked_at])
        })?;
        Ok(())
    }

    /// A session's source and its tokens, still encrypted.
    pub fn session_source(&self, cookie: &str) -> anyhow::Result<Option<(String, Option<Vec<u8>>)>> {
        self.with(|c| {
            c.query_row("SELECT source, tokens FROM sessions WHERE id_hash = ?1 AND source IS NOT NULL", [secret::sha256_hex(cookie)], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()
        })
    }

    /// Sessions with tokens whose provider last vouched for them before `before`, the longest ago
    /// first, at most `limit`.
    pub fn sessions_to_recheck(&self, before: i64, limit: usize) -> anyhow::Result<Vec<RecheckRow>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT id_hash, user_id, source, tokens FROM sessions
                 WHERE tokens IS NOT NULL AND user_id IS NOT NULL AND source IS NOT NULL AND expires_at >= ?1 AND checked_at IS NOT NULL AND checked_at < ?2
                 ORDER BY checked_at LIMIT ?3",
            )?;
            st.query_map(params![unix_now(), before, i64::try_from(limit).unwrap_or(i64::MAX)], |r| {
                Ok(RecheckRow { id_hash: r.get(0)?, user_id: r.get(1)?, issuer: r.get(2)?, tokens: r.get(3)? })
            })?
            .collect()
        })
    }

    /// A session was checked with its provider: its tokens now, encrypted. `vouched`: the provider
    /// answered for it, which vouches for the account too, rather than couldn't be asked.
    pub fn session_rechecked(&self, id_hash: &str, tokens: &[u8], vouched: bool) -> anyhow::Result<()> {
        self.with(|c| {
            let now = unix_now();
            if vouched {
                c.execute("UPDATE users SET vouched_at = ?2 WHERE id = (SELECT user_id FROM sessions WHERE id_hash = ?1)", params![id_hash, now])?;
            }
            c.execute("UPDATE sessions SET tokens = ?2, checked_at = ?3 WHERE id_hash = ?1", params![id_hash, tokens, now])
        })?;
        Ok(())
    }

    /// Ends a session the provider stopped vouching for. `false` if it was gone.
    pub fn end_session(&self, id_hash: &str) -> anyhow::Result<bool> {
        Ok(self.with(|c| c.execute("DELETE FROM sessions WHERE id_hash = ?1", [id_hash]))? == 1)
    }

    /// Who a user is at an issuer.
    pub fn identity_subject(&self, user_id: &str, issuer: &str) -> anyhow::Result<Option<String>> {
        self.with(|c| c.query_row("SELECT subject FROM identities WHERE user_id = ?1 AND issuer = ?2", params![user_id, issuer], |r| r.get(0)).optional())
    }

    // ---- API tokens -----------------------------------------------------------------------

    /// Creates a named API token (`tok_<id>.mpu_<secret>`), shown once. `None` when the user
    /// already holds [`MAX_API_TOKENS_PER_USER`].
    pub fn create_api_token(&self, user_id: &str, name: &str, expires_at: Option<i64>) -> anyhow::Result<Option<(ApiTokenRow, String)>> {
        let id = secret::new_id("tok");
        let token = format!("{id}.{}", secret::new_token("mpu"));
        let now = unix_now();
        let created = self.with(|c| {
            let held: i64 = c.query_row("SELECT COUNT(*) FROM api_tokens WHERE user_id = ?1", [user_id], |r| r.get(0))?;
            if held >= MAX_API_TOKENS_PER_USER {
                return Ok(false);
            }
            c.execute(
                "INSERT INTO api_tokens (id, token_hash, user_id, org_id, name, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![id, secret::sha256_hex(&token), user_id, DEFAULT_ORG, name, now, expires_at],
            )?;
            Ok(true)
        })?;
        let row = ApiTokenRow { id, name: name.to_string(), created_at: now, expires_at, last_used_at: None };
        Ok(created.then_some((row, token)))
    }

    pub fn api_tokens(&self, user_id: &str) -> anyhow::Result<Vec<ApiTokenRow>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT id, name, created_at, expires_at, last_used_at FROM api_tokens WHERE user_id = ?1 ORDER BY created_at")?;
            st.query_map([user_id], |r| {
                Ok(ApiTokenRow { id: r.get(0)?, name: r.get(1)?, created_at: r.get(2)?, expires_at: r.get(3)?, last_used_at: r.get(4)? })
            })?
            .collect()
        })
    }

    pub fn delete_api_token(&self, user_id: &str, id: &str) -> anyhow::Result<bool> {
        let n = self.with(|c| c.execute("DELETE FROM api_tokens WHERE id = ?1 AND user_id = ?2", params![id, user_id]))?;
        Ok(n == 1)
    }

    /// Deletes all of a user's API tokens; returns how many there were.
    pub fn delete_api_tokens(&self, user_id: &str) -> anyhow::Result<usize> {
        self.with(|c| c.execute("DELETE FROM api_tokens WHERE user_id = ?1", [user_id]))
    }

    /// Verifies an unexpired API token and returns its user's id.
    pub fn verify_api_token(&self, token: &str) -> anyhow::Result<Option<String>> {
        let Some((id, _)) = token.split_once('.') else { return Ok(None) };
        if !id.starts_with("tok_") {
            return Ok(None);
        }
        let now = unix_now();
        let found: Option<(String, String, Option<i64>)> = self.with(|c| {
            c.query_row("SELECT token_hash, user_id, expires_at FROM api_tokens WHERE id = ?1", [id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .optional()
        })?;
        let Some((hash, user_id, expires_at)) = found else { return Ok(None) };
        if !secret::verify(token, &hash) || expires_at.is_some_and(|e| e < now) {
            return Ok(None);
        }
        self.with(|c| c.execute("UPDATE api_tokens SET last_used_at = ?1 WHERE id = ?2", params![now, id]))?;
        Ok(Some(user_id))
    }

    // ---- audit log ------------------------------------------------------------------------

    pub fn audit(&self, actor: &str, action: &str, resource: &str, detail: &str) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO audit_log (at, org_id, actor, action, resource, detail) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![unix_now(), DEFAULT_ORG, actor, action, resource, detail],
            )
        })?;
        Ok(())
    }

    /// The newest entries first.
    pub fn audit_entries(&self, limit: u32) -> anyhow::Result<Vec<AuditRow>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT at, actor, action, resource, detail FROM audit_log ORDER BY id DESC LIMIT ?1")?;
            st.query_map([limit], |r| Ok(AuditRow { at: r.get(0)?, actor: r.get(1)?, action: r.get(2)?, resource: r.get(3)?, detail: r.get(4)? }))?
                .collect()
        })
    }

    /// Drops entries older than `before`, and the oldest beyond [`MAX_AUDIT_ROWS`]. Also drops
    /// expired sessions.
    pub fn prune(&self, audit_before: i64) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute("DELETE FROM audit_log WHERE at < ?1", [audit_before])?;
            c.execute("DELETE FROM audit_log WHERE id <= (SELECT MAX(id) FROM audit_log) - ?1", [MAX_AUDIT_ROWS])?;
            c.execute("DELETE FROM sessions WHERE expires_at < ?1", [unix_now()])
        })?;
        self.prune_email()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (Store, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("mp-store-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        (Store::open(&dir.join("db.sqlite")).unwrap(), dir)
    }

    #[test]
    fn single_sign_on_accounts() {
        let dir = std::env::temp_dir().join(format!("mp-sso-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db.sqlite");
        // A database from before the migration keeps its accounts.
        {
            let c = rusqlite::Connection::open(&path).unwrap();
            for m in &super::super::MIGRATIONS[..2] {
                c.execute_batch(m).unwrap();
            }
            c.pragma_update(None, "user_version", 2).unwrap();
        }
        let s = Store::open(&path).unwrap();
        let (iss, other) = ("https://idp.example.com", "https://other.example.com");
        let pat = s.create_user("pat@example.com", "Pat", Role::Member, "hash").unwrap().unwrap();

        let ann = s.create_sso_user("ann@example.com", "Ann", Role::Admin, iss, "sub-ann").unwrap().unwrap();
        let row = s.identity_user(iss, "sub-ann").unwrap().unwrap();
        assert_eq!((row.id.as_str(), row.role, row.has_password), (ann.as_str(), Role::Admin, false));
        assert!(s.identity_user(other, "sub-ann").unwrap().is_none(), "a subject means something only at its issuer");
        // Every account has its personal tag.
        assert_eq!(s.tags().unwrap().iter().filter(|t| t.user_id.is_some()).count(), 2);
        // One account per email and per identity, however the first one was made.
        assert!(s.create_sso_user("ann@example.com", "", Role::Member, iss, "sub-2").unwrap().is_none());
        assert!(s.create_sso_user("pat@example.com", "", Role::Member, iss, "sub-2").unwrap().is_none());
        assert!(s.create_sso_user("new@example.com", "", Role::Member, iss, "sub-ann").unwrap().is_none());
        assert!(s.create_user("ann@example.com", "", Role::Member, "hash").unwrap().is_none());
        assert_eq!(s.user_by_email("ann@example.com").unwrap().unwrap().id, ann);

        // Linking: once per issuer, and a taken subject stays with its owner.
        assert!(!s.link_identity(&pat, iss, "sub-ann").unwrap());
        assert!(s.link_identity(&pat, iss, "sub-pat").unwrap());
        assert!(!s.link_identity(&pat, iss, "sub-reused").unwrap());
        assert!(s.link_identity(&pat, other, "sub-pat").unwrap());
        assert_eq!(s.identity_user(iss, "sub-pat").unwrap().unwrap().id, pat);

        // Signing in ends a temporary password, not one its owner chose.
        assert!(s.user(&pat).unwrap().unwrap().must_change_password);
        s.finish_sso_login(&pat, iss).unwrap();
        let row = s.user(&pat).unwrap().unwrap();
        assert!(!row.has_password && !row.must_change_password && row.last_login_at.is_some());
        assert!(s.password_login("pat@example.com").unwrap().is_none());
        assert!(s.set_password(&pat, "chosen", false).unwrap());
        s.finish_sso_login(&pat, iss).unwrap();
        assert_eq!(s.password_login("pat@example.com").unwrap().unwrap().1, "chosen");

        // An administrator can give an account that never had a password one.
        assert!(s.set_password(&ann, "temporary", true).unwrap());
        assert_eq!(s.password_login("ann@example.com").unwrap().unwrap().1, "temporary");
        assert!(!s.set_password("us_nobody", "x", true).unwrap());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn users_sessions_and_tokens() {
        let (s, dir) = store();
        let id = s.create_user("ann@example.com", "Ann", Role::Member, "hash1").unwrap().unwrap();
        assert!(s.create_user("ann@example.com", "Other", Role::Admin, "hash2").unwrap().is_none(), "emails log in one account");
        let (u, hash) = s.password_login("ann@example.com").unwrap().unwrap();
        assert_eq!((u.id.as_str(), u.role, u.must_change_password, hash.as_str()), (id.as_str(), Role::Member, true, "hash1"));
        assert!(s.password_login("nobody@example.com").unwrap().is_none());
        assert!(s.set_password(&id, "hash3", false).unwrap());
        assert!(s.set_role(&id, Role::Admin).unwrap());
        let u = s.user(&id).unwrap().unwrap();
        assert_eq!((u.role, u.must_change_password), (Role::Admin, false));

        // Sessions: per cookie, capped per user, ended by disabling.
        let (cookie, csrf) = s.create_session(Some(&id), 60).unwrap();
        let row = s.session(&cookie).unwrap().unwrap();
        assert_eq!((row.user_id.as_deref(), row.csrf.as_str()), (Some(id.as_str()), csrf.as_str()));
        assert!(s.session("forged").unwrap().is_none());
        for _ in 0..MAX_SESSIONS_PER_USER {
            s.create_session(Some(&id), 60).unwrap();
        }
        assert!(s.session(&cookie).unwrap().is_none(), "the oldest session was dropped");
        let (admin_cookie, _) = s.create_session(None, 60).unwrap();
        assert!(s.session(&admin_cookie).unwrap().unwrap().user_id.is_none());
        let (latest, _) = s.create_session(Some(&id), 60).unwrap();
        assert!(s.set_disabled(&id, true).unwrap());
        assert!(s.session(&latest).unwrap().is_none());
        assert!(s.user(&id).unwrap().unwrap().disabled);
        assert!(s.session(&admin_cookie).unwrap().is_some());

        // API tokens: shown once, verified by hash, capped, deletable only by their owner.
        let (row, token) = s.create_api_token(&id, "ci", None).unwrap().unwrap();
        assert_eq!(s.verify_api_token(&token).unwrap().as_deref(), Some(id.as_str()));
        assert!(s.verify_api_token(&format!("{}.mpu_wrong", row.id)).unwrap().is_none());
        let (_, expired) = s.create_api_token(&id, "old", Some(1)).unwrap().unwrap();
        assert!(s.verify_api_token(&expired).unwrap().is_none());
        for i in 2..MAX_API_TOKENS_PER_USER {
            s.create_api_token(&id, &format!("t{i}"), None).unwrap().unwrap();
        }
        assert!(s.create_api_token(&id, "one too many", None).unwrap().is_none());
        assert!(!s.delete_api_token("us_other", &row.id).unwrap());
        assert!(s.delete_api_token(&id, &row.id).unwrap());
        assert!(s.verify_api_token(&token).unwrap().is_none());

        s.audit("admin-token", "user.create", &id, "ann@example.com").unwrap();
        assert_eq!(s.audit_entries(10).unwrap()[0].action, "user.create");
        s.prune(unix_now() + 1).unwrap();
        assert!(s.audit_entries(10).unwrap().is_empty());
        std::fs::remove_dir_all(dir).ok();
    }
}
