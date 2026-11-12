//! What email is for (`docs/USERS.md`, "Email invitations" and "Emailed sign-in links"): inviting
//! people, signing in when a password has been forgotten, and proving an address is yours. The
//! sending is in [`crate::mail`], the storing in `store::email`.
//!
//! An invitation is an administrator's promise of an account, to whoever holds the code that went to
//! that address. It's accepted with a password or any provider: the code is the proof, so a provider's
//! own idea of the person's address doesn't matter.
//!
//! A sign-in link needs an account with a password and a verified address. Not an address an
//! administrator typed, which could be someone else's. Not an account that only signs in with a
//! provider, since a link would be a way around that provider's own checks, such as a second factor.
//!
//! Asking for a link says nothing about who has an account. The request only joins a queue, and
//! everything that differs between accounts (the lookup, writing a code, the mail server) happens
//! in the background, so neither the answer nor how long it takes can tell.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::ErrorBody;
use magicpipes_core::{rfc3339, secret, unix_now};
use serde::Serialize;
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

use super::oidc::{SignInError, Source};
use super::users::{Login, check_password, clean_name, denied, normalize_email};
use super::{CodeError, ControlPlane, OrLog, err, internal, logged};
use crate::authz::{self, Action, Principal, Resource, Role};
use crate::forwarded::client_key;
use crate::mail::{self, Mail, Mailer};
use crate::oidc::Person;
use crate::store::{AcceptWith, Accepted, InvitationRow, Invited, LOCAL_ISSUER, LinkPurpose, NewInvitation, UserRow};

pub const INVITATION_DAYS: i64 = 7;
pub const SIGN_IN_LINK_MINUTES: i64 = 15;
const CONFIRM_HOURS: i64 = 24;

/// Requests for a sign-in link waiting to be looked at. More are dropped, with a line in the log: the
/// answer to each is the same anyway, and whoever needs one can ask again.
const QUEUE: usize = 256;
/// Messages being sent at once.
const CONCURRENT_SENDS: usize = 4;
/// Requests for a sign-in link from one client (an address, or an IPv6 /64).
const PER_CLIENT: (u32, Duration) = (10, Duration::from_secs(3600));
/// Links sent to one account. It's someone's inbox, and asking takes no credentials.
const PER_ACCOUNT: (u32, Duration) = (3, Duration::from_secs(15 * 60));
/// Invitations and test messages from one administrator.
const PER_ADMIN: (u32, Duration) = (100, Duration::from_secs(3600));
/// Everything this server sends. A mail server or service has limits of its own, and one account
/// being abused shouldn't get the server's address blocked.
const PER_SERVER: (u32, Duration) = (500, Duration::from_secs(3600));
/// Clients and administrators remembered per limit. The oldest makes way.
const TRACKED: usize = 10_000;

/// How many times each key may do something per period. Resets a period after its first use.
struct Allowance<K> {
    limit: u32,
    period: Duration,
    map: Mutex<HashMap<K, (u32, Instant)>>,
}

impl<K: Eq + Hash + Clone> Allowance<K> {
    fn new((limit, period): (u32, Duration)) -> Self {
        Self { limit, period, map: Mutex::default() }
    }

    fn allow(&self, key: K) -> bool {
        let mut map = self.map.lock().unwrap();
        if map.len() >= TRACKED && !map.contains_key(&key) {
            map.retain(|_, (_, since)| since.elapsed() < self.period);
            if map.len() >= TRACKED
                && let Some(oldest) = map.iter().min_by_key(|(_, (_, since))| *since).map(|(k, _)| k.clone())
            {
                map.remove(&oldest);
            }
        }
        let e = map.entry(key).or_insert((0, Instant::now()));
        if e.1.elapsed() >= self.period {
            *e = (0, Instant::now());
        }
        if e.0 >= self.limit {
            return false;
        }
        e.0 += 1;
        true
    }
}

/// What email needs while the server runs.
pub(super) struct MailState {
    pub(super) sends: Semaphore,
    queue: mpsc::Sender<String>,
    waiting: Mutex<Option<mpsc::Receiver<String>>>,
    by_client: Allowance<IpAddr>,
    by_account: Allowance<String>,
    by_admin: Allowance<String>,
    by_server: Allowance<()>,
}

impl Default for MailState {
    fn default() -> Self {
        let (queue, waiting) = mpsc::channel(QUEUE);
        Self {
            sends: Semaphore::new(CONCURRENT_SENDS),
            queue,
            waiting: Mutex::new(Some(waiting)),
            by_client: Allowance::new(PER_CLIENT),
            by_account: Allowance::new(PER_ACCOUNT),
            by_admin: Allowance::new(PER_ADMIN),
            by_server: Allowance::new(PER_SERVER),
        }
    }
}

/// One invitation, for the Users page and the API. Never its code.
#[derive(Debug, Clone, Serialize)]
pub struct InvitationView {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub role: Role,
    pub tags: Vec<String>,
    /// `us_…` or `admin-token`.
    pub invited_by: String,
    pub created_at: String,
    pub expires_at: String,
    pub expired: bool,
}

impl From<InvitationRow> for InvitationView {
    fn from(r: InvitationRow) -> Self {
        Self {
            expired: r.expires_at < unix_now(),
            id: r.id,
            email: r.email,
            display_name: r.display_name,
            role: r.role,
            tags: r.tags,
            invited_by: r.created_by,
            created_at: rfc3339(r.created_at),
            expires_at: rfc3339(r.expires_at),
        }
    }
}

/// An invitation that a code opened, for the person it's for.
#[derive(Debug, Clone)]
pub struct OpenInvitation {
    pub email: String,
    pub display_name: String,
    pub role: Role,
    /// Who sent it, as they can be named to the person it's for.
    pub invited_by: String,
}

#[derive(Debug)]
pub enum AcceptError {
    /// Unknown, expired or already used.
    Gone,
    /// The password can't be used. The invitation is still good.
    Password(String),
    /// The address got an account some other way meanwhile.
    AccountExists,
    Full,
    Internal,
}

#[derive(Debug)]
pub enum LinkError {
    /// Unknown, expired or already used, or the account can't use one any more.
    Invalid,
    /// The new password can't be used. The link is still good.
    Password(String),
    /// An administrator set a password that's still waiting to be replaced: it needs a new one.
    MustChoosePassword,
    /// The account takes a sign-in code too. The link is still good.
    NeedsCode,
    /// That code isn't right. The link is still good.
    WrongCode,
    /// Too many wrong codes for the account lately. The link is still good.
    CodeThrottled,
    Internal,
}

/// A code as a digest, however it was pasted.
fn digest(code: &str) -> String {
    secret::sha256_hex(code.trim())
}

impl ControlPlane {
    /// Can this server send email? Not behind an authenticating proxy, which is where people sign
    /// in and get in: there's nothing for an invitation or a link to do.
    pub fn mail_on(&self) -> bool {
        self.proxy_auth.is_none() && self.sign_in().mailer.is_some()
    }

    fn mailer(&self) -> Result<Arc<Mailer>, ErrorBody> {
        let not_here = || err(ErrorCode::MailNotConfigured, "this server has no mail server to send through");
        if self.proxy_auth.is_some() {
            return Err(not_here());
        }
        self.sign_in().mailer.clone().ok_or_else(not_here)
    }

    /// Sends one message, within the server's limit. The error says why, for an administrator.
    pub(super) async fn deliver(&self, to: &str, mail: &Mail) -> Result<(), ErrorBody> {
        let mailer = self.mailer()?;
        if !self.mail.by_server.allow(()) {
            return Err(err(ErrorCode::RateLimited, "this server has sent as much email as it may this hour; try again later"));
        }
        let _permit = self.mail.sends.acquire().await.map_err(|_| err(ErrorCode::Internal, "server is shutting down"))?;
        mailer.send(to, mail).await.map_err(|e| err(ErrorCode::MailFailed, format!("The message couldn't be sent: {e:#}")))
    }

    #[allow(clippy::result_large_err)]
    fn within_admin_allowance(&self, who: &Principal) -> Result<(), ErrorBody> {
        if self.mail.by_admin.allow(who.actor().to_string()) { Ok(()) } else { Err(err(ErrorCode::RateLimited, "that's as much email as one administrator can send in an hour; try again later")) }
    }

    /// The name an invitation goes out under.
    fn name_for_invitee(&self, created_by: &str) -> String {
        self.store.user(created_by).or_log().flatten().map_or("An administrator".to_string(), |u| u.email)
    }

    // ---- invitations ------------------------------------------------------------------------

    pub fn invitations(&self, who: &Principal) -> Result<Vec<InvitationView>, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(denied(who));
        }
        Ok(self.store.invitations().map_err(internal)?.into_iter().map(Into::into).collect())
    }

    /// Sends someone an invitation, replacing any already out for that address. It's written once
    /// the mail server has taken the message, so a failure leaves an earlier one working.
    pub async fn invite(&self, who: &Principal, email: &str, display_name: &str, role: Role, tags: &[String]) -> Result<InvitationView, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(denied(who));
        }
        let email = normalize_email(email).ok_or_else(|| err(ErrorCode::InvalidRequest, "that is not an email address"))?;
        let tags = self.registered(tags)?;
        if self.store.user_by_email(&email).map_err(internal)?.is_some() {
            return Err(err(ErrorCode::EmailTaken, format!("an account for {email} already exists")));
        }
        if !self.store.invitation_fits(&email).map_err(internal)? {
            return Err(err(ErrorCode::LimitReached, "too many invitations are waiting; revoke some first"));
        }
        self.within_admin_allowance(who)?;
        let code = secret::new_token("mpi");
        let mail = mail::invitation(&self.cfg.management_url(), &self.name_for_invitee(who.actor()), &code, INVITATION_DAYS);
        self.deliver(&email, &mail).await?;
        let new = NewInvitation {
            token_hash: &digest(&code),
            email: &email,
            display_name: &clean_name(display_name, 100),
            role,
            tags: &tags,
            created_by: who.actor(),
            ttl_secs: INVITATION_DAYS * 86_400,
        };
        let id = match self.store.create_invitation(&new).map_err(internal)? {
            Invited::Created(id) => id,
            Invited::EmailTaken => return Err(err(ErrorCode::EmailTaken, format!("an account for {email} already exists"))),
            Invited::TooMany => return Err(err(ErrorCode::LimitReached, "too many invitations are waiting; revoke some first")),
        };
        self.audit(who, "invitation.create", &id, &format!("{email} {}", role.as_str()));
        let row = self.store.invitation(&id).map_err(internal)?.ok_or_else(|| err(ErrorCode::Internal, "the new invitation disappeared"))?;
        Ok(row.into())
    }

    /// Sends an invitation again with a new code, for another full period. The old code stops
    /// working only once the new one is on its way. `None`: there's no such invitation.
    pub async fn resend_invitation(&self, who: &Principal, id: &str) -> Result<Option<InvitationView>, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(denied(who));
        }
        let Some(row) = self.store.invitation(id).map_err(internal)? else { return Ok(None) };
        self.within_admin_allowance(who)?;
        let code = secret::new_token("mpi");
        let mail = mail::invitation(&self.cfg.management_url(), &self.name_for_invitee(who.actor()), &code, INVITATION_DAYS);
        self.deliver(&row.email, &mail).await?;
        if !self.store.renew_invitation(id, &digest(&code), INVITATION_DAYS * 86_400).map_err(internal)? {
            return Ok(None);
        }
        self.audit(who, "invitation.resend", id, &row.email);
        Ok(self.store.invitation(id).map_err(internal)?.map(Into::into))
    }

    pub fn revoke_invitation(&self, who: &Principal, id: &str) -> Result<bool, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(denied(who));
        }
        let deleted = self.store.delete_invitation(id).map_err(internal)?;
        if deleted {
            self.audit(who, "invitation.revoke", id, "");
        }
        Ok(deleted)
    }

    /// What a code opens, without using it up.
    pub fn open_invitation(&self, code: &str) -> Option<OpenInvitation> {
        let row = self.store.invitation_by_token(&digest(code)).or_log().flatten()?;
        let invited_by = self.name_for_invitee(&row.created_by);
        Some(OpenInvitation { email: row.email, display_name: row.display_name, role: row.role, invited_by })
    }

    /// Accepts an invitation with a password. Signs the new account in.
    pub async fn accept_invitation(&self, code: &str, display_name: &str, password: &str) -> Result<Login, AcceptError> {
        let hash = digest(code);
        let Some(row) = self.store.invitation_by_token(&hash).map_err(logged(AcceptError::Internal))? else { return Err(AcceptError::Gone) };
        check_password(password, &row.email).map_err(|e| AcceptError::Password(e.message))?;
        let password_hash = self.hash_password(password.to_string()).await.map_err(|_| AcceptError::Internal)?;
        let accepted = self.store.accept_invitation(&hash, &clean_name(display_name, 100), AcceptWith::Password(&password_hash)).map_err(logged(AcceptError::Internal))?;
        let id = match accepted {
            Accepted::Account(id) => id,
            Accepted::Gone => return Err(AcceptError::Gone),
            Accepted::EmailTaken => return Err(AcceptError::AccountExists),
            Accepted::Full => return Err(AcceptError::Full),
            // Only a provider's identity can be someone else's.
            Accepted::IdentityTaken => return Err(AcceptError::Internal),
        };
        let who = Principal::User { id: id.clone(), role: row.role, tags: Vec::new() };
        self.audit(&who, "invitation.accept", &row.id, "password");
        self.refresh();
        self.store.touch_login(&id, LOCAL_ISSUER).or_log();
        let (cookie, _) = self.store.create_session(Some(&id), self.cfg.users.session_max_age_secs).map_err(logged(AcceptError::Internal))?;
        self.audit(&who, "session.login", &id, "invitation");
        Ok(Login { cookie, must_change_password: false })
    }

    /// The account an invitation becomes when accepted with a provider's identity.
    pub(super) fn accept_invitation_with(&self, token_hash: &str, source: &Source<'_>, person: &Person) -> Result<UserRow, SignInError> {
        let accepted = self.store.accept_invitation(token_hash, &clean_name(&person.name, 100), AcceptWith::Identity(source.issuer, &person.subject)).map_err(logged(SignInError::Internal))?;
        let id = match accepted {
            Accepted::Account(id) => id,
            Accepted::Gone => return Err(SignInError::InvitationGone),
            Accepted::EmailTaken => return Err(SignInError::AccountExists),
            Accepted::IdentityTaken => return Err(SignInError::IdentityTaken),
            Accepted::Full => return Err(SignInError::Internal),
        };
        self.audit(&Principal::Anonymous, "invitation.accept", &id, &source.name);
        self.refresh();
        self.store.user(&id).map_err(logged(SignInError::Internal))?.ok_or(SignInError::Internal)
    }

    /// The digest of an invitation's code, if it can still be accepted, to carry to a provider.
    pub(super) fn invitation_digest(&self, code: &str) -> Option<String> {
        let hash = digest(code);
        self.store.invitation_by_token(&hash).or_log().flatten().map(|_| hash)
    }

    // ---- sign-in links ----------------------------------------------------------------------

    /// Someone asks for a sign-in link to `address`. `Err`: this client has asked too many times,
    /// which says nothing about the address.
    pub fn request_sign_in_link(&self, address: &str, client: Option<IpAddr>) -> Result<(), ()> {
        if let Some(client) = client.map(client_key)
            && !self.mail.by_client.allow(client)
        {
            return Err(());
        }
        let Some(email) = normalize_email(address) else { return Ok(()) };
        if self.mail.queue.try_send(email).is_err() {
            tracing::warn!("too many requests for sign-in links are waiting; dropped one");
        }
        Ok(())
    }

    /// Answers the requests in the queue, one at a time, until the server stops.
    pub(super) fn start_mail_queue(self: &Arc<Self>, shutdown: CancellationToken) {
        let Some(mut waiting) = self.mail.waiting.lock().unwrap().take() else { return };
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    next = waiting.recv() => match next {
                        Some(email) => me.answer_sign_in_request(&email).await,
                        None => return,
                    },
                }
            }
        });
    }

    async fn answer_sign_in_request(&self, email: &str) {
        let Some(user) = self.store.user_by_email(email).or_log().flatten() else { return };
        if user.disabled || !user.email_verified || !user.has_password || !self.mail_on() {
            return;
        }
        if !self.mail.by_account.allow(user.id.clone()) {
            tracing::info!(user = %user.id, "enough sign-in links went to this account for now");
            return;
        }
        let code = secret::new_token("mpl");
        let hash = digest(&code);
        if self.store.create_email_token(LinkPurpose::SignIn, &user.id, &hash, SIGN_IN_LINK_MINUTES * 60).or_log().is_none() {
            return;
        }
        match self.deliver(email, &mail::sign_in_link(&self.cfg.management_url(), &code, SIGN_IN_LINK_MINUTES)).await {
            Ok(()) => self.audit(&Principal::Anonymous, "email.sign_in_link", &user.id, ""),
            Err(e) => {
                tracing::warn!(user = %user.id, error = %e.message, "could not send a sign-in link");
                self.store.delete_email_token(&hash).or_log();
            }
        }
    }

    /// Signs in with an emailed link. With `new_password`, also replaces the password, which ends
    /// other sessions. A password that can't be used leaves the link as it was. An account with
    /// sign-in codes needs one too (`second`), checked before the link is used up.
    pub async fn use_sign_in_link(&self, code: &str, new_password: Option<&str>, second: Option<&str>) -> Result<Login, LinkError> {
        let hash = digest(code);
        let user_id = self.store.email_token_user(&hash, LinkPurpose::SignIn).map_err(logged(LinkError::Internal))?.ok_or(LinkError::Invalid)?;
        let user = self.store.user(&user_id).map_err(logged(LinkError::Internal))?.ok_or(LinkError::Invalid)?;
        if user.disabled || !user.has_password {
            return Err(LinkError::Invalid);
        }
        let new_hash = match new_password {
            Some(password) => {
                check_password(password, &user.email).map_err(|e| LinkError::Password(e.message))?;
                Some(self.hash_password(password.to_string()).await.map_err(|_| LinkError::Internal)?)
            }
            None if user.must_change_password => return Err(LinkError::MustChoosePassword),
            None => None,
        };
        let mut with = "email link";
        if user.has_totp {
            let second = second.map(str::trim).filter(|c| !c.is_empty()).ok_or(LinkError::NeedsCode)?;
            with = match self.second_factor(&user, second, "email link") {
                Ok(true) => "email link and recovery code",
                Ok(false) => "email link and code",
                Err(CodeError::Wrong | CodeError::Expired) => return Err(LinkError::WrongCode),
                Err(CodeError::Throttled) => return Err(LinkError::CodeThrottled),
                Err(CodeError::Internal) => return Err(LinkError::Internal),
            };
        }
        // Whoever gets here first with a link is the one who used it.
        if self.store.take_email_token(&hash, LinkPurpose::SignIn).map_err(logged(LinkError::Internal))?.as_deref() != Some(user.id.as_str()) {
            return Err(LinkError::Invalid);
        }
        let who = Principal::User { id: user.id.clone(), role: user.role, tags: Vec::new() };
        if let Some(new_hash) = new_hash {
            self.store.set_password(&user.id, &new_hash, false).map_err(logged(LinkError::Internal))?;
            self.store.end_sessions(&user.id).map_err(logged(LinkError::Internal))?;
            // Tunnel cookies issued before now stop working too.
            self.refresh();
            self.audit(&who, "user.password_change", &user.id, "email link");
        }
        self.store.touch_login(&user.id, LOCAL_ISSUER).or_log();
        let (cookie, _) = self.store.create_session(Some(&user.id), self.cfg.users.session_max_age_secs).map_err(logged(LinkError::Internal))?;
        self.audit(&who, "session.login", &user.id, with);
        Ok(Login { cookie, must_change_password: false })
    }

    // ---- confirming your address ------------------------------------------------------------

    /// Sends the signed-in user a link to their own address.
    pub async fn request_address_confirmation(&self, who: &Principal) -> Result<(), ErrorBody> {
        let Principal::User { id, .. } = who else {
            return Err(err(ErrorCode::InvalidRequest, "only user accounts have an address"));
        };
        let user = self.store.user(id).map_err(internal)?.ok_or_else(|| err(ErrorCode::NotFound, "no such user"))?;
        if user.email_verified {
            return Ok(());
        }
        if !self.mail.by_account.allow(user.id.clone()) {
            return Err(err(ErrorCode::RateLimited, "Enough links went to that address for now. Try again in a few minutes."));
        }
        let code = secret::new_token("mpc");
        let hash = digest(&code);
        self.store.create_email_token(LinkPurpose::Confirm, id, &hash, CONFIRM_HOURS * 3600).map_err(internal)?;
        self.deliver(&user.email, &mail::confirm_address(&self.cfg.management_url(), &code, CONFIRM_HOURS)).await.map_err(|e| {
            // Not someone who can do anything about the mail server's answer.
            tracing::warn!(user = %id, error = %e.message, "could not send a confirmation link");
            self.store.delete_email_token(&hash).or_log();
            err(ErrorCode::MailFailed, "That message couldn't be sent. Try again later, or ask an administrator.")
        })?;
        self.audit(who, "email.confirmation_link", id, "");
        Ok(())
    }

    /// Marks the signed-in user's address as verified, with a link sent there. It has to be their own
    /// session: getting the message doesn't prove the account is theirs. If an administrator mistyped
    /// the address, whoever owns the typo must not be able to confirm it, and then ask for sign-in
    /// links to it. `false`: not a link for this account.
    pub fn confirm_address(&self, who: &Principal, code: &str) -> Result<bool, ErrorBody> {
        let Principal::User { id, .. } = who else { return Ok(false) };
        let hash = digest(code);
        if self.store.email_token_user(&hash, LinkPurpose::Confirm).map_err(internal)?.as_deref() != Some(id.as_str()) {
            return Ok(false);
        }
        if self.store.take_email_token(&hash, LinkPurpose::Confirm).map_err(internal)?.as_deref() != Some(id.as_str()) {
            return Ok(false);
        }
        self.store.mark_email_verified(id).map_err(internal)?;
        self.audit(who, "user.email_verified", id, "email link");
        Ok(true)
    }

    // ---- trying it ---------------------------------------------------------------------------

    /// A test message from an administrator, to any address.
    pub async fn send_test_message(&self, who: &Principal, to: &str) -> Result<(), ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(denied(who));
        }
        let to = normalize_email(to).ok_or_else(|| err(ErrorCode::InvalidRequest, "that is not an email address"))?;
        self.within_admin_allowance(who)?;
        self.deliver(&to, &mail::test_message(&self.cfg.management_url())).await?;
        self.audit(who, "settings.smtp.test", "", &to);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_allowance_counts_per_key_and_stays_bounded() {
        let a = Allowance::<String>::new((2, Duration::from_secs(3600)));
        assert!(a.allow("x".into()) && a.allow("x".into()));
        assert!(!a.allow("x".into()), "the third in a period");
        assert!(a.allow("y".into()), "someone else");
        for i in 0..TRACKED + 50 {
            a.allow(format!("key{i}"));
        }
        assert!(a.map.lock().unwrap().len() <= TRACKED);

        // A used-up allowance comes back after its period, which here is none at all.
        let a = Allowance::<u8>::new((1, Duration::ZERO));
        assert!(a.allow(1) && a.allow(1));
    }
}
