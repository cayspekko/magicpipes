//! Who a single sign-on signs in as (`docs/USERS.md`, "SSO (OIDC)"). The protocol is in
//! [`crate::oidc`]; here a verified person becomes an account, or doesn't.
//!
//! An identity is `(issuer, subject)`, so an address changing at the provider changes nothing
//! here. A first sign-in reaches an account only through a verified email (any address, on a
//! provider with `trust_email`), in one of three ways: an existing account with that email on a
//! provider with `link_by_email`, or a new account for an address in `bootstrap_admins` (an
//! administrator) or `allowed_email_domains` (a member). Anyone else is refused. Those lists are
//! the configuration file's plus the Settings page's (`settings`).
//!
//! Anyone who can choose their address at a `trust_email` provider can use any address, so one the
//! provider didn't vouch for doesn't reach an administrator's account, new or existing, unless the
//! provider also has `allow_unverified_admin`.

use std::sync::Arc;
use std::time::Duration;

use magicpipes_core::secret;

use super::users::{Login, clean_name, normalize_email};
use super::{ControlPlane, logged};
use crate::authz::{Principal, Role};
use crate::oidc::{Attempt, Person, Provider};
use crate::store::UserRow;

/// Code exchanges under way at once; more wait for a retry rather than pile up on the provider.
pub(super) const MAX_EXCHANGES: usize = 16;
/// Fits in the management listener's request deadline, so the browser gets a page, not a timeout.
const FINISH_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Debug)]
pub enum OidcError {
    /// The provider can't be reached or misbehaves.
    Unavailable,
    /// The browser's attempt doesn't match this answer: expired, another browser, or forged.
    Expired,
    /// The provider's answer failed its checks.
    Refused,
    /// A real person, whom this server doesn't admit. `None`: no verified email to show.
    NotAllowed(Option<String>),
    Busy,
    Internal,
}

impl ControlPlane {
    pub fn oidc_providers(&self) -> Vec<Arc<Provider>> {
        self.sign_in().providers.clone()
    }

    pub fn oidc_provider(&self, id: &str) -> Option<Arc<Provider>> {
        self.sign_in().providers.iter().find(|p| p.id == id).cloned()
    }

    /// Starts a sign-in: where to send the browser, and the cookie to set for the way back.
    pub async fn oidc_start(&self, provider: &Provider, next: Option<&str>, redirect_uri: &str) -> Result<(String, String), OidcError> {
        let attempt = Attempt::new(&provider.id, next);
        let url = provider.authorization_url(&attempt, redirect_uri).await.map_err(|e| {
            tracing::warn!(provider = %provider.id, error = %format!("{e:#}"), "could not start a sign-in");
            OidcError::Unavailable
        })?;
        Ok((url, attempt.seal(self.data.signer())))
    }

    /// The browser's attempt, if it's intact and for this provider.
    pub fn oidc_attempt(&self, provider: &Provider, cookie: &str) -> Option<Attempt> {
        Attempt::open(self.data.signer(), cookie).filter(|a| a.provider == provider.id)
    }

    /// Finishes a sign-in with the provider's answer.
    pub async fn oidc_finish(&self, provider: &Provider, attempt: &Attempt, state: &str, code: &str, iss: Option<&str>, redirect_uri: &str) -> Result<Login, OidcError> {
        // This is what stops another site from signing a browser in to the attacker's account.
        if !secret::constant_time_eq(state.as_bytes(), attempt.state.as_bytes()) {
            return Err(OidcError::Expired);
        }
        // RFC 9207: a mix-up with another provider shows here, if this one says who it is.
        if iss.is_some_and(|i| i != provider.issuer) {
            return Err(OidcError::Refused);
        }
        let _permit = self.oidc_exchanges.try_acquire().map_err(|_| OidcError::Busy)?;
        let person = match tokio::time::timeout(FINISH_TIMEOUT, provider.finish(attempt, code, redirect_uri)).await {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                tracing::info!(provider = %provider.id, error = %format!("{e:#}"), "a sign-in failed");
                self.audit(&Principal::Anonymous, "login.failed", &format!("oidc:{}", provider.id), "");
                return Err(OidcError::Refused);
            }
            Err(_) => return Err(OidcError::Unavailable),
        };
        let user = self.oidc_account(provider, &person).inspect_err(|e| {
            if let OidcError::NotAllowed(email) = e {
                self.audit(&Principal::Anonymous, "login.failed", &format!("oidc:{}", provider.id), email.as_deref().unwrap_or(""));
            }
        })?;
        self.store.finish_sso_login(&user.id, &provider.issuer).map_err(logged(OidcError::Internal))?;
        let (cookie, _) = self.store.create_session(Some(&user.id), self.cfg.users.session_max_age_secs).map_err(logged(OidcError::Internal))?;
        let who = Principal::User { id: user.id.clone(), role: user.role, tags: Vec::new() };
        self.audit(&who, "session.login", &user.id, &format!("oidc:{}", provider.id));
        // Finishing can have removed a temporary password, which was forcing a change.
        Ok(Login { cookie, must_change_password: false })
    }

    /// The account `person` signs in to.
    fn oidc_account(&self, provider: &Provider, person: &Person) -> Result<UserRow, OidcError> {
        let email = person.verified_email.as_deref().and_then(normalize_email);
        let refused = || OidcError::NotAllowed(email.clone());
        let known = self.store.identity_user(&provider.issuer, &person.subject).map_err(logged(OidcError::Internal))?;
        if let Some(user) = known {
            return if user.disabled { Err(refused()) } else { Ok(user) };
        }
        let Some(address) = email.as_deref() else { return Err(refused()) };
        let may_be_admin = person.vouched_for || provider.allow_unverified_admin;
        let unverified = if person.vouched_for { "" } else { " unverified address" };
        if let Some(user) = self.store.user_by_email(address).map_err(logged(OidcError::Internal))? {
            if !provider.link_by_email || user.disabled {
                return Err(refused());
            }
            if user.role == Role::Admin && !may_be_admin {
                tracing::warn!(provider = %provider.id, "refused a sign-in: an unverified address can't take over an administrator's account without allow_unverified_admin");
                return Err(refused());
            }
            if !self.store.link_identity(&user.id, &provider.issuer, &person.subject).map_err(logged(OidcError::Internal))? {
                return Err(refused());
            }
            self.audit(&Principal::Anonymous, "user.link", &user.id, &format!("oidc:{}{unverified}", provider.id));
            self.refresh();
            return Ok(user);
        }
        let rules = self.sign_in();
        let role = if rules.bootstrap_admins.iter().any(|a| a == address) {
            // Refused rather than made a member, or the real administrator could never sign in.
            if !may_be_admin {
                tracing::warn!(provider = %provider.id, "refused a sign-in: an unverified address can't become an administrator without allow_unverified_admin");
                return Err(refused());
            }
            Role::Admin
        } else if address.rsplit_once('@').is_some_and(|(_, domain)| rules.allowed_email_domains.iter().any(|d| d == domain)) {
            Role::Member
        } else {
            return Err(refused());
        };
        let name = clean_name(&person.name, 100);
        let id = self.store.create_sso_user(address, &name, role, &provider.issuer, &person.subject).map_err(logged(OidcError::Internal))?.ok_or_else(refused)?;
        self.audit(&Principal::Anonymous, "user.create", &id, &format!("oidc:{} {}{unverified}", provider.id, role.as_str()));
        self.refresh();
        self.store.user(&id).map_err(logged(OidcError::Internal))?.ok_or(OidcError::Internal)
    }
}
