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
/// The audit log never grows beyond this many entries, whatever the retention.
const MAX_AUDIT_ROWS: i64 = 100_000;

#[derive(Debug, Clone)]
pub struct UserRow {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub role: Role,
    pub disabled: bool,
    pub must_change_password: bool,
    /// Sessions created before this are no longer valid ("log out everywhere").
    pub sessions_valid_after: i64,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
}

const USER_SELECT: &str = "SELECT u.id, u.email, u.display_name, m.role, u.disabled_at, COALESCE(p.must_change, 0),
    u.sessions_valid_after, u.created_at, (SELECT MAX(i.last_login_at) FROM identities i WHERE i.user_id = u.id)
    FROM users u JOIN memberships m ON m.user_id = u.id AND m.org_id = 'org_default'
    LEFT JOIN passwords p ON p.user_id = u.id";

fn user_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<UserRow> {
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
        must_change_password: must_change != 0,
        sessions_valid_after: r.get(6)?,
        created_at: r.get(7)?,
        last_login_at: r.get(8)?,
    })
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

impl Store {
    // ---- users ----------------------------------------------------------------------------

    /// Creates a password account. Returns `None` if another account already logs in with this
    /// email.
    pub fn create_user(&self, email: &str, display_name: &str, role: Role, password_hash: &str) -> anyhow::Result<Option<String>> {
        let id = secret::new_id("us");
        let now = unix_now();
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let taken: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM identities WHERE issuer = ?1 AND subject = ?2)",
            params![LOCAL_ISSUER, email],
            |r| r.get(0),
        )?;
        if taken {
            return Ok(None);
        }
        tx.execute("INSERT INTO users (id, email, display_name, created_at) VALUES (?1, ?2, ?3, ?4)", params![id, email, display_name, now])?;
        tx.execute("INSERT INTO identities (issuer, subject, user_id) VALUES (?1, ?2, ?3)", params![LOCAL_ISSUER, email, id])?;
        tx.execute(
            "INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![DEFAULT_ORG, id, role.as_str(), now],
        )?;
        tx.execute("INSERT INTO passwords (user_id, hash, must_change, updated_at) VALUES (?1, ?2, 1, ?3)", params![id, password_hash, now])?;
        tx.commit()?;
        Ok(Some(id))
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

    pub fn set_password(&self, user_id: &str, hash: &str, must_change: bool) -> anyhow::Result<bool> {
        let n = self.with(|c| {
            c.execute(
                "UPDATE passwords SET hash = ?1, must_change = ?2, updated_at = ?3 WHERE user_id = ?4",
                params![hash, must_change as i64, unix_now(), user_id],
            )
        })?;
        Ok(n == 1)
    }

    pub fn set_role(&self, user_id: &str, role: Role) -> anyhow::Result<bool> {
        let n = self.with(|c| {
            c.execute("UPDATE memberships SET role = ?1 WHERE user_id = ?2 AND org_id = ?3", params![role.as_str(), user_id, DEFAULT_ORG])
        })?;
        Ok(n == 1)
    }

    /// Disabling also ends every session; the user's API tokens stop working while disabled.
    pub fn set_disabled(&self, user_id: &str, disabled: bool) -> anyhow::Result<bool> {
        let n = self.with(|c| {
            let at = disabled.then(unix_now);
            c.execute("UPDATE users SET disabled_at = ?1 WHERE id = ?2", params![at, user_id])
        })?;
        if disabled {
            self.end_sessions(user_id)?;
        }
        Ok(n == 1)
    }

    /// Ends every UI session of a user ("log out everywhere", password changes).
    pub fn end_sessions(&self, user_id: &str) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute("UPDATE users SET sessions_valid_after = ?1 WHERE id = ?2", params![unix_now(), user_id])?;
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
        Ok(())
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
