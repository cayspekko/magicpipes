//! Accounts: password logins, UI sessions, API tokens, user administration and the audit log.
//!
//! Passwords are hashed with Argon2id (OWASP parameters: 19 MiB, 2 iterations, 1 lane) on the
//! blocking pool, at most [`HASH_CONCURRENCY`] at a time, so a burst of logins can't use up
//! memory or CPU. Unlike tokens, passwords can be guessed: on top of the per-client limiter in
//! `mgmt`, each account is throttled after repeated failures *before* its password is checked.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};
use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::ErrorBody;
use magicpipes_core::{rfc3339, secret, unix_now};
use serde::Serialize;

use super::{ControlPlane, err, internal};
use crate::authz::{self, Action, Principal, Resource, Role};
use crate::store::{ApiTokenRow, LOCAL_ISSUER, MAX_API_TOKENS_PER_USER, UserRow};

pub(super) const HASH_CONCURRENCY: usize = 4;
pub const MIN_PASSWORD_CHARS: usize = 12;
const MAX_PASSWORD_BYTES: usize = 256;
/// Length of passwords the server generates (base62, ~119 bits).
const GENERATED_PASSWORD_CHARS: usize = 20;

/// After this many failures within [`ACCOUNT_WINDOW`], an account accepts one attempt per
/// [`ACCOUNT_SPACING`], right password or not. That slows guessing down without letting anyone
/// lock an account out.
const ACCOUNT_FAILURES: u32 = 10;
const ACCOUNT_WINDOW: Duration = Duration::from_secs(15 * 60);
const ACCOUNT_SPACING: Duration = Duration::from_secs(10);
const ACCOUNT_TRACKED: usize = 10_000;

fn argon2() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(19 * 1024, 2, 1, None).expect("valid Argon2 parameters"))
}

/// Failed password logins per account (by email).
#[derive(Default)]
pub(super) struct AccountLimiter {
    map: Mutex<HashMap<String, (u32, Instant, Instant)>>,
}

impl AccountLimiter {
    fn throttled(&self, email: &str) -> bool {
        let map = self.map.lock().unwrap();
        map.get(email).is_some_and(|(n, since, next)| *n >= ACCOUNT_FAILURES && since.elapsed() < ACCOUNT_WINDOW && Instant::now() < *next)
    }

    fn failed(&self, email: &str) {
        let mut map = self.map.lock().unwrap();
        if map.len() >= ACCOUNT_TRACKED && !map.contains_key(email) {
            map.retain(|_, (_, since, _)| since.elapsed() < ACCOUNT_WINDOW);
            if map.len() >= ACCOUNT_TRACKED {
                let oldest = map.iter().min_by_key(|(_, (_, since, _))| *since).map(|(k, _)| k.clone());
                oldest.map(|k| map.remove(&k));
            }
        }
        let now = Instant::now();
        let e = map.entry(email.to_string()).or_insert((0, now, now));
        if e.1.elapsed() >= ACCOUNT_WINDOW {
            *e = (0, now, now);
        }
        e.0 = e.0.saturating_add(1);
        if e.0 >= ACCOUNT_FAILURES {
            e.2 = now + ACCOUNT_SPACING;
        }
    }

    fn succeeded(&self, email: &str) {
        self.map.lock().unwrap().remove(email);
    }
}

/// A new UI session.
pub struct Login {
    pub cookie: String,
    /// The user must pick a new password before doing anything else.
    pub must_change_password: bool,
}

pub enum LoginError {
    /// Wrong email or password, or a disabled account: the caller can't tell which.
    Invalid,
    /// Too many failures for this account; try again shortly.
    Throttled,
    Internal,
}

/// A valid UI session.
pub struct UiSession {
    pub who: Principal,
    pub csrf: String,
    /// `None` for an admin-token session.
    pub user: Option<UserView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserView {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub role: Role,
    pub disabled: bool,
    pub must_change_password: bool,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login_at: Option<String>,
}

impl From<UserRow> for UserView {
    fn from(u: UserRow) -> Self {
        Self {
            id: u.id,
            email: u.email,
            display_name: u.display_name,
            role: u.role,
            disabled: u.disabled,
            must_change_password: u.must_change_password,
            created_at: rfc3339(u.created_at),
            last_login_at: u.last_login_at.map(rfc3339),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenView {
    pub id: String,
    pub name: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
}

impl From<ApiTokenRow> for TokenView {
    fn from(t: ApiTokenRow) -> Self {
        Self {
            id: t.id,
            name: t.name,
            created_at: rfc3339(t.created_at),
            expires_at: t.expires_at.map(rfc3339),
            last_used_at: t.last_used_at.map(rfc3339),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditView {
    pub at: String,
    pub actor: String,
    pub action: String,
    pub resource: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

/// Lowercased and checked: one `@` with something on both sides, no spaces or control
/// characters, at most 254 bytes.
pub fn normalize_email(email: &str) -> Option<String> {
    let e = email.trim().to_lowercase();
    let (local, domain) = e.split_once('@')?;
    let ok = !local.is_empty()
        && !domain.is_empty()
        && !domain.contains('@')
        && e.len() <= 254
        && !e.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | '"' | '\''));
    ok.then_some(e)
}

fn check_password(password: &str, email: &str) -> Result<(), ErrorBody> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(err(ErrorCode::InvalidRequest, format!("passwords need at least {MIN_PASSWORD_CHARS} characters")));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(err(ErrorCode::InvalidRequest, format!("passwords may have at most {MAX_PASSWORD_BYTES} bytes")));
    }
    if password.trim().eq_ignore_ascii_case(email) {
        return Err(err(ErrorCode::InvalidRequest, "the password may not be the email address"));
    }
    Ok(())
}

fn clean_name(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect::<String>().trim().to_string()
}

/// Refusal for a principal that may not do something: `forbidden` when logged in.
fn denied(who: &Principal) -> ErrorBody {
    match who {
        Principal::Anonymous => err(ErrorCode::Unauthorized, "log in first"),
        _ => err(ErrorCode::Forbidden, "only administrators can do this"),
    }
}

impl ControlPlane {
    async fn hash_password(&self, password: String) -> Result<String, ErrorBody> {
        let _permit = self.hashing.acquire().await.map_err(|_| err(ErrorCode::Internal, "server is shutting down"))?;
        tokio::task::spawn_blocking(move || argon2().hash_password(password.as_bytes()).map(|h| h.to_string()))
            .await
            .map_err(|e| internal(e.into()))?
            .map_err(|e| internal(anyhow::anyhow!("hashing a password: {e}")))
    }

    /// Checks `password` against `hash`, or against a throwaway hash when there is no account,
    /// so an unknown email takes as long as a wrong password.
    async fn password_matches(&self, password: String, hash: Option<String>) -> bool {
        static DUMMY: OnceLock<String> = OnceLock::new();
        let Ok(_permit) = self.hashing.acquire().await else { return false };
        tokio::task::spawn_blocking(move || {
            let dummy = DUMMY.get_or_init(|| {
                argon2().hash_password(secret::random_string(32).as_bytes()).map(|h| h.to_string()).unwrap_or_default()
            });
            let hash = hash.as_deref().unwrap_or(dummy);
            argon2().verify_password(password.as_bytes(), hash).is_ok()
        })
        .await
        .unwrap_or(false)
    }

    pub(super) fn audit(&self, who: &Principal, action: &str, resource: &str, detail: &str) {
        if let Err(e) = self.store.audit(who.actor(), action, resource, detail) {
            tracing::error!(error = %format!("{e:#}"), action, "could not write the audit log");
        }
    }

    // ---- logging in -------------------------------------------------------------------------

    pub async fn login_password(&self, email: &str, password: &str) -> Result<Login, LoginError> {
        let email = normalize_email(email).unwrap_or_default();
        if !email.is_empty() && self.accounts.throttled(&email) {
            return Err(LoginError::Throttled);
        }
        let found = if email.is_empty() { None } else { self.store.password_login(&email).map_err(|_| LoginError::Internal)? };
        let hash = found.as_ref().map(|(_, h)| h.clone());
        let matches = self.password_matches(password.to_string(), hash).await;
        let user = match found {
            Some((u, _)) if matches && !u.disabled => u,
            _ => {
                if !email.is_empty() {
                    self.accounts.failed(&email);
                }
                self.audit(&Principal::Anonymous, "login.failed", "password", &email);
                return Err(LoginError::Invalid);
            }
        };
        self.accounts.succeeded(&email);
        let _ = self.store.touch_login(&user.id, LOCAL_ISSUER);
        let (cookie, _) = self.store.create_session(Some(&user.id), self.cfg.users.session_max_age_secs).map_err(|_| LoginError::Internal)?;
        let who = Principal::User { id: user.id.clone(), role: user.role };
        self.audit(&who, "session.login", &user.id, "password");
        Ok(Login { cookie, must_change_password: user.must_change_password })
    }

    /// A UI session for an admin token; `None` if the token is not valid.
    pub fn login_admin_token(&self, token: &str) -> Result<Option<Login>, ErrorBody> {
        if !self.verify_admin(token) {
            return Ok(None);
        }
        let (cookie, _) = self.store.create_session(None, self.cfg.users.session_max_age_secs).map_err(internal)?;
        self.audit(&Principal::AdminToken, "session.login", "admin-token", "");
        Ok(Some(Login { cookie, must_change_password: false }))
    }

    /// The principal of an active user, or `None` if the account is disabled or gone.
    fn user_principal(&self, user_id: &str) -> Option<(Principal, UserRow)> {
        let u = self.store.user(user_id).ok().flatten().filter(|u| !u.disabled)?;
        Some((Principal::User { id: u.id.clone(), role: u.role }, u))
    }

    pub fn session(&self, cookie: &str) -> Option<UiSession> {
        let row = self.store.session(cookie).ok().flatten()?;
        let Some(user_id) = row.user_id else {
            return Some(UiSession { who: Principal::AdminToken, csrf: row.csrf, user: None });
        };
        let (who, user) = self.user_principal(&user_id)?;
        if row.created_at < user.sessions_valid_after {
            return None;
        }
        Some(UiSession { who, csrf: row.csrf, user: Some(user.into()) })
    }

    pub fn logout(&self, who: &Principal, cookie: &str) {
        let _ = self.store.delete_session(cookie);
        self.audit(who, "session.logout", who.actor(), "");
    }

    /// Who a bearer token stands for: an admin token or a user's API token.
    pub fn bearer(&self, token: &str) -> Option<Principal> {
        if self.verify_admin(token) {
            return Some(Principal::AdminToken);
        }
        let user_id = self.store.verify_api_token(token).unwrap_or_else(|e| {
            tracing::error!(error = %e, "API token check failed");
            None
        })?;
        self.user_principal(&user_id).map(|(who, _)| who)
    }

    // ---- your own account -------------------------------------------------------------------

    /// Changes the logged-in user's password after checking the current one. Ends every session
    /// of the user and returns a new one for the caller.
    pub async fn change_password(&self, who: &Principal, current: &str, new: &str) -> Result<Login, ErrorBody> {
        let Principal::User { id, .. } = who else {
            return Err(err(ErrorCode::InvalidRequest, "only user accounts have a password"));
        };
        let user = self.store.user(id).map_err(internal)?.ok_or_else(|| err(ErrorCode::NotFound, "no such user"))?;
        let stored = self.store.password_login(&user.email).map_err(internal)?.map(|(_, h)| h);
        if self.accounts.throttled(&user.email) {
            return Err(err(ErrorCode::RateLimited, "too many failed attempts; wait a few seconds"));
        }
        if !self.password_matches(current.to_string(), stored).await {
            self.accounts.failed(&user.email);
            return Err(err(ErrorCode::Unauthorized, "the current password is not correct"));
        }
        check_password(new, &user.email)?;
        if new == current {
            return Err(err(ErrorCode::InvalidRequest, "choose a password different from the current one"));
        }
        let hash = self.hash_password(new.to_string()).await?;
        self.store.set_password(id, &hash, false).map_err(internal)?;
        self.store.end_sessions(id).map_err(internal)?;
        self.audit(who, "user.password_change", id, "");
        let (cookie, _) = self.store.create_session(Some(id), self.cfg.users.session_max_age_secs).map_err(internal)?;
        Ok(Login { cookie, must_change_password: false })
    }

    /// Ends every UI session of the logged-in user, this one included.
    pub fn logout_everywhere(&self, who: &Principal) -> Result<(), ErrorBody> {
        let Principal::User { id, .. } = who else {
            return Err(err(ErrorCode::InvalidRequest, "admin-token sessions end when you log out"));
        };
        self.store.end_sessions(id).map_err(internal)?;
        self.audit(who, "session.logout_everywhere", id, "");
        Ok(())
    }

    pub fn tokens(&self, who: &Principal) -> Vec<TokenView> {
        match who {
            Principal::User { id, .. } => self.store.api_tokens(id).unwrap_or_default().into_iter().map(Into::into).collect(),
            _ => Vec::new(),
        }
    }

    /// Creates an API token for the logged-in user. Returns it with the secret, shown once.
    pub fn create_token(&self, who: &Principal, name: &str, expires_in_days: Option<u32>) -> Result<(TokenView, String), ErrorBody> {
        let Principal::User { id, .. } = who else {
            return Err(err(ErrorCode::InvalidRequest, "API tokens belong to a user; log in with your account"));
        };
        let name = clean_name(name, 64);
        if name.is_empty() {
            return Err(err(ErrorCode::InvalidRequest, "give the token a name"));
        }
        let expires_at = expires_in_days.filter(|d| *d > 0).map(|d| unix_now() + i64::from(d.min(3650)) * 86_400);
        let (row, token) = self.store.create_api_token(id, &name, expires_at).map_err(internal)?.ok_or_else(|| {
            err(ErrorCode::LimitReached, format!("a user may hold at most {MAX_API_TOKENS_PER_USER} API tokens; delete one first"))
        })?;
        self.audit(who, "token.create", &row.id, &name);
        Ok((row.into(), token))
    }

    pub fn delete_token(&self, who: &Principal, token_id: &str) -> Result<bool, ErrorBody> {
        let Principal::User { id, .. } = who else { return Ok(false) };
        let deleted = self.store.delete_api_token(id, token_id).map_err(internal)?;
        if deleted {
            self.audit(who, "token.delete", token_id, "");
        }
        Ok(deleted)
    }

    // ---- user administration ----------------------------------------------------------------

    /// The accounts `who` manages: every account for administrators, your own otherwise.
    pub fn users(&self, who: &Principal) -> Vec<UserView> {
        let rows = self.store.users().unwrap_or_else(|e| {
            tracing::error!(error = %e, "listing users failed");
            Vec::new()
        });
        rows.into_iter().filter(|u| authz::authorize(who, Action::Manage, Resource::User(&u.id))).map(Into::into).collect()
    }

    pub fn user(&self, who: &Principal, id: &str) -> Option<UserView> {
        if !authz::authorize(who, Action::Manage, Resource::User(id)) {
            return None;
        }
        self.store.user(id).ok().flatten().map(Into::into)
    }

    /// Creates a password account. Without `password`, one is generated and returned (shown
    /// once). Either way the user must change it at first login.
    pub async fn create_user(
        &self,
        who: &Principal,
        email: &str,
        display_name: &str,
        role: Role,
        password: Option<&str>,
    ) -> Result<(UserView, Option<String>), ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(denied(who));
        }
        let email = normalize_email(email).ok_or_else(|| err(ErrorCode::InvalidRequest, "that is not an email address"))?;
        let display_name = clean_name(display_name, 100);
        let (password, generated) = match password.filter(|p| !p.is_empty()) {
            Some(p) => (p.to_string(), None),
            None => {
                let p = secret::random_string(GENERATED_PASSWORD_CHARS);
                (p.clone(), Some(p))
            }
        };
        check_password(&password, &email)?;
        let hash = self.hash_password(password).await?;
        let id = self
            .store
            .create_user(&email, &display_name, role, &hash)
            .map_err(internal)?
            .ok_or_else(|| err(ErrorCode::EmailTaken, format!("an account for {email} already exists")))?;
        self.audit(who, "user.create", &id, &format!("{email} {}", role.as_str()));
        let user = self.store.user(&id).map_err(internal)?.ok_or_else(|| err(ErrorCode::Internal, "the new user disappeared"))?;
        Ok((user.into(), generated))
    }

    /// Changes another account's role or disables or enables it.
    pub fn update_user(&self, who: &Principal, id: &str, role: Option<Role>, disabled: Option<bool>) -> Result<UserView, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(denied(who));
        }
        if matches!(who, Principal::User { id: me, .. } if me == id) {
            return Err(err(ErrorCode::InvalidRequest, "another administrator has to change your own role or status"));
        }
        if self.store.user(id).map_err(internal)?.is_none() {
            return Err(err(ErrorCode::NotFound, "no such user"));
        }
        if let Some(role) = role {
            self.store.set_role(id, role).map_err(internal)?;
            self.audit(who, "user.role", id, role.as_str());
        }
        if let Some(disabled) = disabled {
            self.store.set_disabled(id, disabled).map_err(internal)?;
            self.audit(who, if disabled { "user.disable" } else { "user.enable" }, id, "");
        }
        self.store.user(id).map_err(internal)?.map(Into::into).ok_or_else(|| err(ErrorCode::NotFound, "no such user"))
    }

    /// Sets a new generated password (shown once) that the user must change, and ends the
    /// user's sessions.
    pub async fn reset_password(&self, who: &Principal, id: &str) -> Result<String, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(denied(who));
        }
        if self.store.user(id).map_err(internal)?.is_none() {
            return Err(err(ErrorCode::NotFound, "no such user"));
        }
        let password = secret::random_string(GENERATED_PASSWORD_CHARS);
        let hash = self.hash_password(password.clone()).await?;
        self.store.set_password(id, &hash, true).map_err(internal)?;
        self.store.end_sessions(id).map_err(internal)?;
        self.audit(who, "user.password_reset", id, "");
        Ok(password)
    }

    pub fn audit_entries(&self, who: &Principal, limit: u32) -> Result<Vec<AuditView>, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(denied(who));
        }
        let rows = self.store.audit_entries(limit.clamp(1, 1000)).map_err(internal)?;
        Ok(rows
            .into_iter()
            .map(|r| AuditView { at: rfc3339(r.at), actor: r.actor, action: r.action, resource: r.resource, detail: r.detail })
            .collect())
    }

    /// Drops old audit entries and expired sessions (hourly).
    pub(super) fn prune(&self) {
        let before = unix_now() - (self.cfg.users.audit_retention_days as i64).saturating_mul(86_400);
        if let Err(e) = self.store.prune(before) {
            tracing::error!(error = %format!("{e:#}"), "pruning the audit log failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_and_passwords() {
        assert_eq!(normalize_email(" Ann@Example.COM ").as_deref(), Some("ann@example.com"));
        for bad in ["", "ann", "@example.com", "ann@", "a b@example.com", "a@b@c", "<a>@example.com"] {
            assert!(normalize_email(bad).is_none(), "{bad}");
        }
        assert!(check_password("short", "a@b.c").is_err());
        assert!(check_password("ann@example.com", "ann@example.com").is_err());
        assert!(check_password(&"x".repeat(MAX_PASSWORD_BYTES + 1), "a@b.c").is_err());
        assert!(check_password("correct horse battery", "a@b.c").is_ok());
    }

    #[test]
    fn account_limiter_spaces_attempts_after_failures() {
        let l = AccountLimiter::default();
        for _ in 0..ACCOUNT_FAILURES - 1 {
            l.failed("a@b.c");
        }
        assert!(!l.throttled("a@b.c"));
        l.failed("a@b.c");
        assert!(l.throttled("a@b.c"));
        assert!(!l.throttled("other@b.c"));
        l.succeeded("a@b.c");
        assert!(!l.throttled("a@b.c"));
        for i in 0..ACCOUNT_TRACKED + 5 {
            l.failed(&format!("{i}@b.c"));
        }
        assert!(l.map.lock().unwrap().len() <= ACCOUNT_TRACKED);
    }
}
