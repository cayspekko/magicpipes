//! Single sign-on past the sign-in itself (`docs/USERS.md`, "SSO (OIDC)"): checking sessions with
//! their provider again, signing out there, and the provider the sign-in page goes straight to.
//!
//! A session an OpenID Connect provider signed in keeps the tokens it gave, encrypted with a key
//! derived from `session-key` (`Signer::encrypt`): the refresh token, and the ID token to sign out
//! with. Every `[users] sso_recheck_secs` the server trades each session's refresh token at the
//! provider. If the provider no longer honors it (`invalid_grant`: the person was removed or
//! disabled there, or signed out of everything), the session ends at once and their tag rule
//! matches from that provider go. Otherwise the fresh claims update their tag rules, and the new
//! refresh token is kept. A provider that can't be reached leaves sessions as they are until the
//! next round. GitHub and the proxy have no refresh tokens: their sessions last as long as a
//! session does.
//!
//! With `[users] disable_idle_after_days`, an account that signs in only through single sign-on is
//! disabled once nothing has vouched for it in that long: no sign-in, no re-check its provider
//! answered, no administrator enabling it. Someone a provider dropped never signs in again, so
//! what they left here (API tokens, machines, tags an administrator gave) stops with the account.
//! Anyone else signs in, which enables it again at once; until then their machines serve nothing,
//! so whoever owns one is told by email how to get back in.

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use magicpipes_core::unix_now;
use tokio_util::sync::CancellationToken;

use super::{ControlPlane, OrLog};
use crate::authz::Principal;
use crate::mail;
use crate::oidc::{Provider, Refused, Tokens};
use crate::store::RecheckRow;

/// Sessions checked in one round; more wait for the next.
const BATCH: usize = 500;
/// Checks under way at once.
const AT_ONCE: usize = 8;
/// People told their account was disabled, in one hourly round. The rest of the server's hourly
/// mail allowance stays for sign-in links and invitations.
const MAX_TOLD: usize = 100;

impl ControlPlane {
    /// The provider the sign-in page goes straight to, if one does and people can use it.
    pub fn auto_redirect_provider(&self) -> Option<Arc<Provider>> {
        self.oidc_providers().into_iter().find(|p| p.auto_redirect)
    }

    /// Where to send someone signing out of this session to sign out at its provider too, and the
    /// provider's name: only for a provider set to, that says where.
    pub async fn provider_sign_out(&self, cookie: &str, back: &str) -> Option<(String, String)> {
        let (issuer, sealed) = self.store.session_source(cookie).or_log().flatten()?;
        let provider = self.oidc_providers().into_iter().find(|p| p.issuer == issuer && p.sign_out)?;
        let tokens: Tokens = sealed.and_then(|s| self.data.signer().decrypt(&s)).and_then(|plain| serde_json::from_slice(&plain).ok()).unwrap_or_default();
        let url = provider.sign_out_url(tokens.id_token.as_deref(), back).await?;
        Some((url, provider.label.clone()))
    }

    /// Checks sessions with their providers every `sso_recheck_secs`, unless that's 0.
    pub(super) fn start_sso_rechecks(self: &Arc<Self>, shutdown: CancellationToken) {
        let every = self.cfg.users.sso_recheck_secs;
        if every == 0 {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            // A session comes due at most this long after its time.
            let mut tick = tokio::time::interval(Duration::from_secs((every / 4).clamp(5, 300)));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tick.tick() => me.recheck_due().await,
                }
            }
        });
    }

    /// Checks the sessions whose provider last vouched for them a round ago or more.
    async fn recheck_due(&self) {
        let before = unix_now().saturating_sub(i64::try_from(self.cfg.users.sso_recheck_secs).unwrap_or(i64::MAX));
        let due = self.store.sessions_to_recheck(before, BATCH).or_log().unwrap_or_default();
        futures_util::stream::iter(due).for_each_concurrent(AT_ONCE, |row| self.recheck(row)).await;
    }

    async fn recheck(&self, row: RecheckRow) {
        let signer = self.data.signer();
        let tokens: Option<Tokens> = signer.decrypt(&row.tokens).and_then(|plain| serde_json::from_slice(&plain).ok());
        let Some(refresh) = tokens.as_ref().and_then(|t| t.refresh.clone()) else {
            // Sealed with another key, or changed: there's nothing to vouch for it with.
            tracing::warn!(user = %row.user_id, "a session's tokens can't be read, so it ends");
            self.end_sso_session(&row, "its tokens can't be read");
            return;
        };
        // A provider that's gone, or no longer offered, can't be asked; the session lasts its age.
        let Some(provider) = self.oidc_providers().into_iter().find(|p| p.issuer == row.issuer && p.kind.is_oidc()) else {
            self.store.session_rechecked(&row.id_hash, &row.tokens, false).or_log();
            return;
        };
        let Some(subject) = self.store.identity_subject(&row.user_id, &row.issuer).or_log().flatten() else {
            self.end_sso_session(&row, "the account no longer signs in there");
            return;
        };
        let wanted = self.wanted_claims(&row.issuer);
        match provider.refresh(&refresh, &subject, &wanted).await {
            Ok((person, kept)) => {
                if let Some(person) = person {
                    self.match_tag_rules(&row.issuer, &row.user_id, &person.claims);
                }
                if let Ok(plain) = serde_json::to_vec(&kept) {
                    self.store.session_rechecked(&row.id_hash, &signer.encrypt(&plain), true).or_log();
                }
            }
            Err(Refused::Grant) => self.end_sso_session(&row, &format!("{} no longer vouches for it", provider.label)),
            Err(Refused::Unavailable(why)) => {
                tracing::warn!(provider = %provider.id, %why, "couldn't check a session with its provider; trying again next round");
                self.store.session_rechecked(&row.id_hash, &row.tokens, false).or_log();
            }
        }
    }

    /// Disables the accounts nothing has vouched for in `disable_idle_after_days` (hourly), and tells
    /// those who own machines, which stop with it, how to get back in.
    pub(super) fn disable_idle_accounts(self: &Arc<Self>) {
        let days = self.cfg.users.disable_idle_after_days;
        if days == 0 {
            return;
        }
        let before = unix_now().saturating_sub(i64::try_from(days.saturating_mul(86_400)).unwrap_or(i64::MAX));
        let why = format!("no single sign-on in {days} days");
        // The audit entries are written with the change, in one transaction however many there are.
        let idle = self.store.disable_idle(before, &why).or_log().unwrap_or_default();
        if idle.is_empty() {
            return;
        }
        tracing::info!(accounts = idle.len(), "disabled accounts: {why}");
        // Their machines stop, and their tunnel cookies with them.
        self.refresh();
        if !self.mail_on() {
            return;
        }
        let to: Vec<String> = idle.into_iter().filter(|(u, machines)| u.email_verified && *machines > 0).map(|(u, _)| u.email).collect();
        if to.len() > MAX_TOLD {
            tracing::warn!(told = MAX_TOLD, left = to.len() - MAX_TOLD, "too many disabled accounts to email them all");
        }
        let message = mail::account_disabled(&self.cfg.management_url(), days);
        let me = self.clone();
        tokio::spawn(async move {
            for address in to.into_iter().take(MAX_TOLD) {
                if let Err(e) = me.deliver(&address, &message).await {
                    tracing::warn!(error = %e.message, "couldn't email someone whose account was disabled");
                }
            }
        });
    }

    /// Ends a session its provider stopped vouching for, and what its rules gave from there.
    fn end_sso_session(&self, row: &RecheckRow, why: &str) {
        if self.store.end_session(&row.id_hash).or_log() == Some(true) {
            tracing::info!(user = %row.user_id, %why, "ended a session");
            self.audit(&Principal::Anonymous, "session.ended", &row.user_id, why);
        }
        if self.store.set_rule_matches(&row.user_id, &row.issuer, &[]).or_log() == Some(true) {
            self.refresh();
        }
    }
}
