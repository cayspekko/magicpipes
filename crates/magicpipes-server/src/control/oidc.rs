//! Who a single sign-on signs in as (`docs/USERS.md`, "SSO (OIDC)" and "Authenticating proxy"). The
//! protocols are in [`crate::oidc`] and [`crate::proxy_auth`]; here a verified person becomes an
//! account, or doesn't.
//!
//! An identity is `(issuer, subject)`, so an address changing at the provider changes nothing
//! here. A first sign-in reaches an account only through a verified email (any address, on a
//! provider with `trust_email`), in one of these ways: an existing account with that email where
//! the source links by email (`link_by_email`, and always behind a proxy, where an administrator
//! creating the account is how someone is let in), or a new account for an address in
//! `bootstrap_admins` (an administrator), in `allowed_email_domains` (a member), or behind a proxy
//! with `auto_create` (a member). Anyone else is refused. Those lists are the configuration file's
//! plus the Settings page's (`settings`).
//!
//! Anyone who can choose their address at a `trust_email` source can use any address, so one it
//! didn't vouch for doesn't reach an administrator's account, new or existing, unless it also has
//! `allow_unverified_admin`.

use std::sync::Arc;
use std::time::Duration;

use magicpipes_core::secret;

use super::users::{Login, clean_name, normalize_email};
use super::{ControlPlane, logged};
use crate::authz::{Principal, Role};
use crate::oidc::{Attempt, Person, Provider, Tokens};
use crate::proxy_auth::ProxyAuth;
use crate::store::UserRow;

/// Code exchanges under way at once; more wait for a retry rather than pile up on the provider.
pub(super) const MAX_EXCHANGES: usize = 16;
/// Fits in the management listener's request deadline, so the browser gets a page, not a timeout.
const FINISH_TIMEOUT: Duration = Duration::from_secs(12);

/// What the account rules need to know about where a person comes from.
pub(super) struct Source<'a> {
    /// For the audit log and the server's log.
    pub(super) name: String,
    pub(super) issuer: &'a str,
    link_by_email: bool,
    allow_unverified_admin: bool,
    auto_create: bool,
}

impl<'a> From<&'a Provider> for Source<'a> {
    fn from(p: &'a Provider) -> Self {
        Self { name: format!("oidc:{}", p.id), issuer: &p.issuer, link_by_email: p.link_by_email, allow_unverified_admin: p.allow_unverified_admin, auto_create: false }
    }
}

impl<'a> From<&'a ProxyAuth> for Source<'a> {
    fn from(p: &'a ProxyAuth) -> Self {
        Self { name: "proxy".to_string(), issuer: &p.issuer, link_by_email: true, allow_unverified_admin: p.allow_unverified_admin, auto_create: p.auto_create }
    }
}

#[derive(Debug)]
pub enum SignInError {
    /// The provider can't be reached or misbehaves.
    Unavailable,
    /// The browser's attempt doesn't match this answer: expired, another browser, or forged.
    Expired,
    /// The provider's answer failed its checks.
    Refused,
    /// A real person, whom this server doesn't admit. `None`: no verified email to show.
    NotAllowed(Option<String>),
    Busy,
    /// The invitation being accepted is unknown, expired or already used.
    InvitationGone,
    /// The invitation's address got an account some other way meanwhile.
    AccountExists,
    /// This identity at the provider already signs in to another account here.
    IdentityTaken,
    Internal,
}

impl ControlPlane {
    /// The providers people can choose. None behind an authenticating proxy: a session from
    /// anywhere else would end at the next request, which doesn't name its user.
    pub fn oidc_providers(&self) -> Vec<Arc<Provider>> {
        if self.proxy_auth.is_some() { Vec::new() } else { self.sign_in().providers.clone() }
    }

    pub fn oidc_provider(&self, id: &str) -> Option<Arc<Provider>> {
        self.oidc_providers().into_iter().find(|p| p.id == id)
    }

    /// The authenticating proxy, if this server signs people in through one.
    pub fn proxy_auth(&self) -> Option<&ProxyAuth> {
        self.proxy_auth.as_ref()
    }

    /// Takes the proxy's word for `person`. `current`: the user of the session the request came
    /// with. `None` when that's already them, or the new session.
    pub fn proxy_sign_in(&self, proxy: &ProxyAuth, person: &Person, current: Option<&str>) -> Result<Option<Login>, SignInError> {
        let source = Source::from(proxy);
        // Every page request gets here, so a refusal is only worth a line in the log.
        let user = self.sso_account(&source, person).inspect_err(|e| {
            if let SignInError::NotAllowed(email) = e {
                tracing::info!(address = email.as_deref().unwrap_or("none"), "refused someone the authenticating proxy named");
            }
        })?;
        if current == Some(user.id.as_str()) {
            return Ok(None);
        }
        self.sso_session(&source, &user, person, None).map(Some)
    }

    /// Starts a sign-in: where to send the browser, and the cookie to set for the way back.
    pub async fn oidc_start(&self, provider: &Provider, next: Option<&str>, redirect_uri: &str) -> Result<(String, String), SignInError> {
        self.leave_for(provider, Attempt::new(&provider.id, next), redirect_uri).await
    }

    /// As [`Self::oidc_start`], to accept the invitation a code opens with this provider's identity.
    pub async fn oidc_start_invited(&self, provider: &Provider, code: &str, redirect_uri: &str) -> Result<(String, String), SignInError> {
        let invite = self.invitation_digest(code).ok_or(SignInError::InvitationGone)?;
        let mut attempt = Attempt::new(&provider.id, None);
        attempt.invite = Some(invite);
        self.leave_for(provider, attempt, redirect_uri).await
    }

    async fn leave_for(&self, provider: &Provider, attempt: Attempt, redirect_uri: &str) -> Result<(String, String), SignInError> {
        let wanted = self.wanted_claims(&provider.issuer);
        let url = provider.authorization_url(&attempt, redirect_uri, &wanted).await.map_err(|e| {
            tracing::warn!(provider = %provider.id, error = %format!("{e:#}"), "could not start a sign-in");
            SignInError::Unavailable
        })?;
        Ok((url, attempt.seal(self.data.signer())))
    }

    /// The browser's attempt, if it's intact and for this provider.
    pub fn oidc_attempt(&self, provider: &Provider, cookie: &str) -> Option<Attempt> {
        Attempt::open(self.data.signer(), cookie).filter(|a| a.provider == provider.id)
    }

    /// Finishes a sign-in with the provider's answer.
    pub async fn oidc_finish(&self, provider: &Provider, attempt: &Attempt, state: &str, code: &str, iss: Option<&str>, redirect_uri: &str) -> Result<Login, SignInError> {
        // This is what stops another site from signing a browser in to the attacker's account.
        if !secret::constant_time_eq(state.as_bytes(), attempt.state.as_bytes()) {
            return Err(SignInError::Expired);
        }
        // RFC 9207: a mix-up with another provider shows here, if this one says who it is. GitHub's
        // address isn't a promise of what it would call itself, and its callback has its own attempt.
        if provider.kind.is_oidc() && iss.is_some_and(|i| i != provider.issuer) {
            return Err(SignInError::Refused);
        }
        let _permit = self.oidc_exchanges.try_acquire().map_err(|_| SignInError::Busy)?;
        let wanted = self.wanted_claims(&provider.issuer);
        let (person, tokens) = match tokio::time::timeout(FINISH_TIMEOUT, provider.finish(attempt, code, redirect_uri, &wanted)).await {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                tracing::info!(provider = %provider.id, error = %format!("{e:#}"), "a sign-in failed");
                self.audit(&Principal::Anonymous, "login.failed", &format!("oidc:{}", provider.id), "");
                return Err(SignInError::Refused);
            }
            Err(_) => return Err(SignInError::Unavailable),
        };
        let source = Source::from(provider);
        // An invitation's code is the proof here, and what the provider says about the address
        // doesn't matter: it goes to the address the invitation went to.
        if let Some(invite) = &attempt.invite {
            let user = self.accept_invitation_with(invite, &source, &person)?;
            return self.sso_session(&source, &user, &person, Some(&tokens));
        }
        let user = self.sso_account(&source, &person).inspect_err(|e| {
            if let SignInError::NotAllowed(email) = e {
                self.audit(&Principal::Anonymous, "login.failed", &source.name, email.as_deref().unwrap_or(""));
            }
        })?;
        self.sso_session(&source, &user, &person, Some(&tokens))
    }

    /// A new session for someone a single sign-on vouched for. Where it vouched for the account's own
    /// address, that address counts as verified from now on.
    /// `tokens`: what the provider gave, kept encrypted with the session for re-checks and signing
    /// out there.
    fn sso_session(&self, source: &Source, user: &UserRow, person: &Person, tokens: Option<&Tokens>) -> Result<Login, SignInError> {
        if person.vouched_for && !user.email_verified && person.verified_email.as_deref().and_then(normalize_email).as_deref() == Some(user.email.as_str()) {
            self.store.mark_email_verified(&user.id).map_err(logged(SignInError::Internal))?;
        }
        if self.store.finish_sso_login(&user.id, source.issuer).map_err(logged(SignInError::Internal))? {
            self.audit(&Principal::Anonymous, "user.enable", &user.id, &format!("signed in again through {}", source.name));
            // Their machines serve again.
            self.refresh();
        }
        self.match_tag_rules(source.issuer, &user.id, &person.claims);
        let (cookie, _) = self.store.create_session(Some(&user.id), self.cfg.users.session_max_age_secs).map_err(logged(SignInError::Internal))?;
        let kept = tokens.filter(|t| !t.is_empty());
        let sealed = kept.and_then(|t| serde_json::to_vec(t).ok()).map(|plain| self.data.signer().encrypt(&plain));
        let rechecks = kept.is_some_and(|t| t.refresh.is_some()) && self.cfg.users.sso_recheck_secs > 0;
        self.store.set_session_source(&cookie, source.issuer, sealed.as_deref(), rechecks).map_err(logged(SignInError::Internal))?;
        let who = Principal::User { id: user.id.clone(), role: user.role, tags: Vec::new() };
        self.audit(&who, "session.login", &user.id, &source.name);
        // Finishing can have removed a temporary password, which was forcing a change.
        Ok(Login { cookie, must_change_password: false })
    }

    /// The account `person` signs in to.
    fn sso_account(&self, source: &Source, person: &Person) -> Result<UserRow, SignInError> {
        let email = person.verified_email.as_deref().and_then(normalize_email);
        let refused = || SignInError::NotAllowed(email.clone());
        let known = self.store.identity_user(source.issuer, &person.subject).map_err(logged(SignInError::Internal))?;
        if let Some(user) = known {
            // Going without a sign-in disabled it, and this is one.
            return if user.disabled && !user.disabled_idle { Err(refused()) } else { Ok(user) };
        }
        let Some(address) = email.as_deref() else { return Err(refused()) };
        let may_be_admin = person.vouched_for || source.allow_unverified_admin;
        let unverified = if person.vouched_for { "" } else { " unverified address" };
        if let Some(user) = self.store.user_by_email(address).map_err(logged(SignInError::Internal))? {
            if !source.link_by_email || user.disabled {
                return Err(refused());
            }
            if user.role == Role::Admin && !may_be_admin {
                tracing::warn!(source = %source.name, "refused a sign-in: an unverified address can't take over an administrator's account without allow_unverified_admin");
                return Err(refused());
            }
            if !self.store.link_identity(&user.id, source.issuer, &person.subject).map_err(logged(SignInError::Internal))? {
                return Err(refused());
            }
            self.audit(&Principal::Anonymous, "user.link", &user.id, &format!("{}{unverified}", source.name));
            self.refresh();
            return Ok(user);
        }
        let rules = self.sign_in();
        let role = if rules.bootstrap_admins.iter().any(|a| a == address) {
            // Refused rather than made a member, or the real administrator could never sign in.
            if !may_be_admin {
                tracing::warn!(source = %source.name, "refused a sign-in: an unverified address can't become an administrator without allow_unverified_admin");
                return Err(refused());
            }
            Role::Admin
        } else if source.auto_create || address.rsplit_once('@').is_some_and(|(_, domain)| rules.allowed_email_domains.iter().any(|d| d == domain)) {
            Role::Member
        } else {
            return Err(refused());
        };
        let name = clean_name(&person.name, 100);
        let id = self.store.create_sso_user(address, &name, role, source.issuer, &person.subject).map_err(logged(SignInError::Internal))?.ok_or_else(refused)?;
        self.audit(&Principal::Anonymous, "user.create", &id, &format!("{} {}{unverified}", source.name, role.as_str()));
        self.refresh();
        self.store.user(&id).map_err(logged(SignInError::Internal))?.ok_or(SignInError::Internal)
    }
}
