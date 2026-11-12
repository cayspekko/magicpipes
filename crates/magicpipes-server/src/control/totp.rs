//! Sign-in codes (`docs/USERS.md`, "Sign-in codes"): someone with a password can make signing in
//! also take a code from an authenticator app, or one of their recovery codes.
//!
//! A password that checks out for such an account doesn't start a session. It gives the browser a
//! signed note (`Pending`, five minutes) that only a code can finish, and an emailed link asks for
//! the code before it's used up. Codes are limited per account ([`super::users::AccountLimiter::for_codes`])
//! on top of the per-client limit, none works twice, and the key is kept encrypted under a key from
//! `session-key`, bound to its account. If that key can't be read, codes fail closed: a recovery
//! code or an administrator's "Reset password" gets the person back in.

use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::ErrorBody;
use magicpipes_core::{rfc3339, unix_now};

use super::users::Login;
use super::{ControlPlane, OrLog, err, internal, logged};
use crate::authz::Principal;
use crate::store::UserRow;
use crate::totp::{self, Key};

/// Seconds between a password and the code that finishes the sign-in.
const PENDING_SECS: i64 = 5 * 60;
/// Seconds a key shown for setting up stays good.
const SETUP_SECS: i64 = 30 * 60;

/// A password or an emailed link that checked out.
pub enum SignedIn {
    Session(Login),
    /// The account takes a code too. This is the signed note that says the password was right, for
    /// [`ControlPlane::finish_with_code`].
    Code(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum CodeError {
    /// The note is too old or not ours, or the account changed since: start again.
    Expired,
    Wrong,
    /// Too many wrong codes for this account lately.
    Throttled,
    Internal,
}

/// A key to scan, while setting codes up.
pub struct TotpSetup {
    /// As typed into an app.
    pub key: String,
    /// What the QR code carries.
    pub uri: String,
    /// The key, signed for this account, for the form to send back.
    pub sealed: String,
}

/// Someone's sign-in codes, when they're on.
pub struct TotpView {
    pub since: String,
    pub recovery_left: i64,
}

/// What a key is encrypted as: bound to its account.
fn sealed_as(user_id: &str) -> Vec<u8> {
    format!("totp\0{user_id}").into_bytes()
}

impl ControlPlane {
    /// The signed-in person's account, if it has a password: codes go with one.
    fn password_account(&self, who: &Principal) -> Result<UserRow, ErrorBody> {
        let Principal::User { id, .. } = who else {
            return Err(err(ErrorCode::InvalidRequest, "only user accounts have sign-in codes"));
        };
        let user = self.store.user(id).map_err(internal)?.ok_or_else(|| err(ErrorCode::NotFound, "no such user"))?;
        if !user.has_password || self.proxy_auth.is_some() {
            return Err(err(ErrorCode::InvalidRequest, "sign-in codes go with a password, and this account signs in another way"));
        }
        Ok(user)
    }

    /// Their password again, before a change to how they sign in.
    async fn check_own_password(&self, user: &UserRow, password: &str) -> Result<(), ErrorBody> {
        if self.accounts.throttled(&user.email) {
            return Err(err(ErrorCode::RateLimited, "too many failed attempts; wait a few seconds"));
        }
        let stored = self.store.password_login(&user.email).map_err(internal)?.map(|(_, h)| h);
        if !self.password_matches(password.to_string(), stored).await {
            self.accounts.failed(&user.email);
            return Err(err(ErrorCode::Unauthorized, "the password is not correct"));
        }
        Ok(())
    }

    pub fn totp_status(&self, who: &Principal) -> Option<TotpView> {
        let Principal::User { id, .. } = who else { return None };
        let row = self.store.totp(id).or_log().flatten()?;
        Some(TotpView { since: rfc3339(row.created_at), recovery_left: row.recovery_left })
    }

    /// A new key to scan, or the one `sealed` still holds, so a setup that went wrong keeps the key
    /// the app already has.
    pub fn totp_setup(&self, who: &Principal, sealed: Option<&str>) -> Result<TotpSetup, ErrorBody> {
        let user = self.password_account(who)?;
        let signer = self.data.signer();
        let key = sealed.and_then(|s| self.open_setup(&user.id, s)).unwrap_or_else(Key::generate);
        let host = &self.cfg.management.hostname;
        let sealed = signer.seal(&format!("n~{}~{}~{}", user.id, unix_now() + SETUP_SECS, key.text()));
        Ok(TotpSetup { key: key.text(), uri: key.uri(&format!("MagicPipes ({host})"), &user.email), sealed })
    }

    fn open_setup(&self, user_id: &str, sealed: &str) -> Option<Key> {
        let payload = self.data.signer().open(sealed)?;
        let ["n", user, expires, key] = payload.split('~').collect::<Vec<_>>()[..] else { return None };
        if user != user_id || expires.parse::<i64>().ok()? < unix_now() {
            return None;
        }
        Key::from_text(key)
    }

    /// Turns codes on with the key from [`Self::totp_setup`], once a code from it and their password
    /// check out. Other sessions end, as they began with less. Returns the session to carry on
    /// with and the recovery codes, shown once.
    pub async fn turn_on_totp(&self, who: &Principal, sealed: &str, password: &str, code: &str) -> Result<(Login, Vec<String>), ErrorBody> {
        let user = self.password_account(who)?;
        let key = self.open_setup(&user.id, sealed).ok_or_else(|| err(ErrorCode::InvalidRequest, "that setup has expired; scan the new code"))?;
        self.check_own_password(&user, password).await?;
        let step = key.matching_step(code, unix_now(), 0).ok_or_else(|| err(ErrorCode::InvalidRequest, "that code isn't right; enter the one the app shows now"))?;
        let codes = totp::new_recovery_codes();
        let digests: Vec<String> = codes.iter().filter_map(|c| totp::recovery_digest(c)).collect();
        let secret = self.data.signer().encrypt_for(&sealed_as(&user.id), key.bytes());
        if !self.store.set_totp(&user.id, &secret, step, &digests).map_err(internal)? {
            return Err(err(ErrorCode::InvalidRequest, "sign-in codes are on already"));
        }
        self.store.end_sessions(&user.id).map_err(internal)?;
        // Tunnel cookies issued before now stop working too.
        self.refresh();
        self.audit(who, "user.totp_on", &user.id, "");
        let (cookie, _) = self.store.create_session(Some(&user.id), self.cfg.users.session_max_age_secs).map_err(internal)?;
        Ok((Login { cookie, must_change_password: false }, codes))
    }

    pub async fn turn_off_totp(&self, who: &Principal, password: &str) -> Result<(), ErrorBody> {
        let user = self.password_account(who)?;
        self.check_own_password(&user, password).await?;
        if self.store.clear_totp(&user.id).map_err(internal)? {
            self.audit(who, "user.totp_off", &user.id, "");
        }
        Ok(())
    }

    /// New recovery codes, shown once, in place of the old.
    pub async fn new_recovery_codes(&self, who: &Principal, password: &str) -> Result<Vec<String>, ErrorBody> {
        let user = self.password_account(who)?;
        self.check_own_password(&user, password).await?;
        let codes = totp::new_recovery_codes();
        let digests: Vec<String> = codes.iter().filter_map(|c| totp::recovery_digest(c)).collect();
        if !self.store.set_recovery_codes(&user.id, &digests).map_err(internal)? {
            return Err(err(ErrorCode::InvalidRequest, "sign-in codes are off"));
        }
        self.audit(who, "user.recovery_codes", &user.id, "");
        Ok(codes)
    }

    /// The note a right password gives an account that takes a code too.
    pub(super) fn pending_sign_in(&self, user: &UserRow) -> String {
        let now = unix_now();
        self.data.signer().seal(&format!("k~{}~{now}~{}", user.id, now + PENDING_SECS))
    }

    /// Finishes a sign-in with the code after a password. `true` with the session: it took a
    /// recovery code, which is now used up.
    pub async fn finish_with_code(&self, pending: &str, code: &str) -> Result<(Login, bool), CodeError> {
        let payload = self.data.signer().open(pending).ok_or(CodeError::Expired)?;
        let ["k", user_id, issued, expires] = payload.split('~').collect::<Vec<_>>()[..] else { return Err(CodeError::Expired) };
        let (issued, expires) = (issued.parse::<i64>().map_err(|_| CodeError::Expired)?, expires.parse::<i64>().map_err(|_| CodeError::Expired)?);
        if expires < unix_now() {
            return Err(CodeError::Expired);
        }
        let user = self.store.user(user_id).map_err(logged(CodeError::Internal))?.ok_or(CodeError::Expired)?;
        // Disabled, or the password changed, since: that password no longer counts.
        if user.disabled || !user.has_password || issued < user.sessions_valid_after {
            return Err(CodeError::Expired);
        }
        let recovery = self.second_factor(&user, code, "password")?;
        self.store.touch_login(&user.id, crate::store::LOCAL_ISSUER).or_log();
        let (cookie, _) = self.store.create_session(Some(&user.id), self.cfg.users.session_max_age_secs).map_err(logged(CodeError::Internal))?;
        let who = Principal::User { id: user.id.clone(), role: user.role, tags: Vec::new() };
        self.audit(&who, "session.login", &user.id, if recovery { "password and recovery code" } else { "password and code" });
        Ok((Login { cookie, must_change_password: user.must_change_password }, recovery))
    }

    /// Checks the code that goes with a password or link (`after`, for the audit log), using it up.
    /// `true`: it was a recovery code.
    pub(super) fn second_factor(&self, user: &UserRow, code: &str, after: &str) -> Result<bool, CodeError> {
        if self.codes.throttled(&user.id) {
            return Err(CodeError::Throttled);
        }
        let recovery = !totp::is_app_code(code);
        let right = if recovery {
            match totp::recovery_digest(code) {
                Some(digest) => self.store.use_recovery_code(&user.id, &digest).map_err(logged(CodeError::Internal))?,
                None => false,
            }
        } else {
            // Turned off since the password: there's nothing to check it against.
            let row = self.store.totp(&user.id).map_err(logged(CodeError::Internal))?.ok_or(CodeError::Expired)?;
            match self.data.signer().decrypt_for(&sealed_as(&user.id), &row.secret).and_then(Key::from_bytes) {
                Some(key) => match key.matching_step(code, unix_now(), row.last_step) {
                    Some(step) => self.store.use_totp_step(&user.id, step).map_err(logged(CodeError::Internal))?,
                    None => false,
                },
                None => {
                    tracing::error!(user = %user.id, "an authenticator key can't be read (was session-key replaced?); only a recovery code or a password reset gets them in");
                    false
                }
            }
        };
        if !right {
            self.codes.failed(&user.id);
            self.audit(&Principal::Anonymous, "login.failed", "code", &format!("{} after {after}", user.email));
            return Err(CodeError::Wrong);
        }
        self.codes.succeeded(&user.id);
        Ok(recovery)
    }
}
