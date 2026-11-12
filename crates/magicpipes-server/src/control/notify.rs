//! Telling people about alerts ([`super::alerts`]) as they open, get worse and close: by email to
//! each person who asked for it on their Account page, and to every webhook an administrator added
//! on the Settings page.
//!
//! Email comes as a digest. The first change waits [`GATHER_SECS`] for what comes with it, and one
//! person gets at most one message every [`EMAIL_GAP_SECS`], listing what changed since the last.
//! It goes only to a confirmed address, and only about what that person may see (`authorize`):
//! `mine` is their own machines and tunnels, and for an administrator also service agents and the
//! server; `all`, for administrators, is every alert.
//!
//! A webhook gets each change as it happens: JSON with a `text` field that chat services show as
//! is, signed with HMAC-SHA256 under a secret shown once, when it's added. Each webhook has its own
//! bounded queue and task, tries three times, and keeps how its last delivery went for the Settings
//! page. Its address and secret are a file in `<data_dir>/webhooks/`. An address like Slack's is a
//! secret itself, so the log and the page show only its host.
//!
//! What's waiting is kept in memory, so a restart loses it.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use hmac::{KeyInit, Mac};
use http::header::HeaderName;
use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::ErrorBody;
use magicpipes_core::{rfc3339, secret, unix_now};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::alerts::{AlertView, Change, Rule, Severity};
use super::users::{clean_name, denied};
use super::{ControlPlane, OrLog, err, internal};
use crate::authz::{self, Action, Principal, Resource, Role};
use crate::mail::{self, AlertLine};
use crate::store::{AlertEmail, MAX_WEBHOOKS, UserRow, WebhookRow};

/// How long the first change waits for others before a message goes.
const GATHER_SECS: i64 = 30;
/// The least time between two messages to one person.
pub const EMAIL_GAP_SECS: i64 = 600;
/// Changes listed in one message; more are counted.
const MAX_IN_MESSAGE: usize = 50;
/// Deliveries waiting for one webhook. More are dropped, with a line in the log.
const WEBHOOK_QUEUE: usize = 100;
/// How long a receiver has to answer.
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);
/// The waits before the second and third tries.
const RETRY_AFTER: [Duration; 2] = [Duration::from_secs(10), Duration::from_secs(60)];
const MAX_NAME: usize = 64;
const MAX_URL: usize = 2048;
/// In `data_dir`.
const WEBHOOKS_DIR: &str = "webhooks";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Opened,
    /// Its severity rose, from warn to bad.
    Worse,
    Closed,
}

impl Event {
    fn key(self) -> &'static str {
        match self {
            Event::Opened => "opened",
            Event::Worse => "worse",
            Event::Closed => "closed",
        }
    }

    fn word(self) -> &'static str {
        match self {
            Event::Opened => "Opened",
            Event::Worse => "Worse",
            Event::Closed => "Closed",
        }
    }
}

/// One change to tell people about.
#[derive(Debug, Clone)]
pub struct Notice {
    pub event: Event,
    pub at: i64,
    pub alert: AlertView,
}

/// What's waiting for one person.
#[derive(Debug, Default)]
struct Inbox {
    notices: Vec<Notice>,
    more: usize,
    /// When the next message goes; `None` while there's nothing to say.
    due: Option<i64>,
    last_sent: Option<i64>,
}

/// A webhook's address and signing secret, as kept in its file.
#[derive(Serialize, Deserialize)]
struct Target {
    url: String,
    secret: String,
}

/// How a webhook's last delivery went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivered {
    pub at: i64,
    pub ok: bool,
    pub said: String,
}

struct Hook {
    queue: mpsc::Sender<(Event, Bytes)>,
    stop: CancellationToken,
    last: Arc<Mutex<Option<Delivered>>>,
}

#[derive(Default)]
pub(super) struct Notifier {
    inboxes: Mutex<HashMap<String, Inbox>>,
    /// Webhooks whose file could be read, by id.
    hooks: Mutex<HashMap<String, Hook>>,
    shutdown: OnceLock<CancellationToken>,
}

/// A webhook, for the Settings page.
#[derive(Debug, Clone)]
pub struct WebhookView {
    pub id: String,
    pub name: String,
    pub host: String,
    pub last: Option<Delivered>,
    /// Its file can't be read, so nothing goes to it.
    pub broken: bool,
}

/// What a person's choice means for them: an administrator's role decides whether `all` is all.
fn effective(choice: AlertEmail, role: Role) -> AlertEmail {
    match (choice, role) {
        (AlertEmail::All, Role::Member) => AlertEmail::Mine,
        (c, _) => c,
    }
}

/// Whether someone with `choice` hears about an alert whose subject belongs to `owner` (`None`: a
/// service agent's, or the server's).
fn wants(choice: AlertEmail, role: Role, user_id: &str, owner: Option<&str>) -> bool {
    match effective(choice, role) {
        AlertEmail::Off => false,
        AlertEmail::All => true,
        AlertEmail::Mine => owner == Some(user_id) || (role == Role::Admin && owner.is_none()),
    }
}

/// Someone an alert email can go to: an address shown to be theirs, on an account in use.
fn can_get(u: &UserRow) -> bool {
    u.email_verified && !u.disabled
}

/// `opened: Offline, studio-mac. Offline since 14:03 UTC.` and where to look.
fn line(n: &Notice, server: &str, now: i64) -> AlertLine {
    AlertLine {
        word: n.event.word(),
        at: super::alerts::clock(n.at, now),
        title: n.alert.rule.title(),
        name: n.alert.name.clone(),
        detail: n.alert.detail.clone(),
        link: n.alert.href.as_ref().map(|h| format!("{server}{h}")),
    }
}

/// What a webhook gets for a change.
fn payload(n: &Notice, server: &str, now: i64) -> Bytes {
    let link = n.alert.href.as_ref().map(|h| format!("{server}{h}"));
    let mut text = format!("{}: {}, {}. {}", n.event.word(), n.alert.rule.title(), n.alert.name, n.alert.detail);
    if let Some(l) = &link {
        text.push(' ');
        text.push_str(l);
    }
    let body = json!({
        "event": n.event.key(),
        "text": text,
        "alert": {
            "id": n.alert.id,
            "rule": n.alert.rule.key(),
            "title": n.alert.rule.title(),
            "severity": n.alert.severity.key(),
            "subject": n.alert.subject,
            "name": n.alert.name,
            "detail": n.alert.detail,
            "opened_at": rfc3339(n.alert.opened_at),
            "closed_at": n.alert.closed_at.map(rfc3339),
            "url": link,
        },
        "server": server,
        "sent_at": rfc3339(now),
    });
    Bytes::from(body.to_string())
}

fn test_payload(server: &str, now: i64) -> Bytes {
    let host = server.strip_prefix("https://").unwrap_or(server);
    let body = json!({
        "event": "test",
        "text": format!("A test from the Settings page at {host}: alerts will arrive here."),
        "alert": null,
        "server": server,
        "sent_at": rfc3339(now),
    });
    Bytes::from(body.to_string())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `sha256=<hex>`: HMAC-SHA256 of the body under the webhook's secret.
fn signature(secret: &str, body: &[u8]) -> String {
    let mut mac = <hmac::Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes()).expect("HMAC takes any key length");
    mac.update(body);
    format!("sha256={}", hex(&mac.finalize().into_bytes()))
}

/// Posts one delivery. What the receiver answered, or why nothing did, never with the address.
async fn post(target: &Target, host: &str, event: &str, body: &Bytes) -> Result<String, String> {
    let headers = [
        (HeaderName::from_static("x-magicpipes-event"), event.to_string()),
        (HeaderName::from_static("x-magicpipes-signature"), signature(&target.secret, body)),
    ];
    match crate::oidc::post_json(&target.url, &headers, body.clone(), WEBHOOK_TIMEOUT).await {
        Ok(status) if status.is_success() => Ok(format!("{host} answered {status}")),
        Ok(status) => Err(format!("{host} answered {status}")),
        Err(e) => Err(format!("{e:#}").replace(&target.url, host)),
    }
}

/// A webhook address this server will post to, and its host: HTTPS, or HTTP to this machine.
fn check_url(raw: &str) -> Result<(String, String), ErrorBody> {
    let url = raw.trim();
    let bad = |why: &str| err(ErrorCode::InvalidRequest, why);
    if url.is_empty() {
        return Err(bad("Enter the address to post alerts to."));
    }
    if url.len() > MAX_URL {
        return Err(bad("That address is too long."));
    }
    let uri: http::Uri = url.parse().map_err(|_| bad("That isn't a web address."))?;
    let authority = uri.authority().map(|a| a.as_str()).unwrap_or("");
    let host = uri.host().unwrap_or("").to_string();
    if host.is_empty() || authority.contains('@') || !crate::oidc::allowed_url(url) {
        return Err(bad("Use an https:// address, or http:// to this machine."));
    }
    Ok((url.to_string(), host))
}

/// What's worth telling about a sample's changes: alerts that opened, got worse, or closed because
/// their subject is fine again. One that closed because its subject is gone, which someone removed,
/// and one that got better, aren't.
fn notices(now: i64, before: &[AlertView], changes: &[Change], exists: impl Fn(&str) -> bool) -> Vec<Notice> {
    changes
        .iter()
        .filter_map(|c| match c {
            Change::Opened(row) => Some(Notice {
                event: Event::Opened,
                at: now,
                alert: AlertView {
                    id: row.id.clone(),
                    rule: Rule::parse(&row.rule)?,
                    severity: Severity::parse(&row.severity),
                    subject: row.subject.clone(),
                    name: row.subject_name.clone(),
                    href: super::alerts::href(&row.subject),
                    detail: row.detail.clone(),
                    opened_at: row.opened_at,
                    closed_at: None,
                },
            }),
            Change::Severity { id, severity, detail } => {
                let was = before.iter().find(|a| a.id == *id)?;
                (*severity > was.severity).then(|| Notice { event: Event::Worse, at: now, alert: AlertView { severity: *severity, detail: detail.clone(), ..was.clone() } })
            }
            Change::Closed { id, at, detail } => {
                let was = before.iter().find(|a| a.id == *id).filter(|a| exists(&a.subject))?;
                Some(Notice { event: Event::Closed, at: *at, alert: AlertView { detail: detail.clone(), closed_at: Some(*at), ..was.clone() } })
            }
        })
        .collect()
}

impl ControlPlane {
    fn webhook_path(&self, id: &str) -> PathBuf {
        self.cfg.data_dir.join(WEBHOOKS_DIR).join(format!("{id}.json"))
    }

    fn read_target(&self, id: &str) -> anyhow::Result<Target> {
        let text = std::fs::read_to_string(self.webhook_path(id))?;
        Ok(serde_json::from_str(&text)?)
    }

    fn write_target(&self, id: &str, target: &Target) -> anyhow::Result<()> {
        let mut dir = std::fs::DirBuilder::new();
        dir.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut dir, 0o700);
        dir.create(self.cfg.data_dir.join(WEBHOOKS_DIR))?;
        crate::certs::write_private(&self.webhook_path(id), serde_json::to_string(target)?.as_bytes())?;
        Ok(())
    }

    /// Starts a task for each webhook whose file can be read.
    pub(super) fn start_webhooks(&self, shutdown: CancellationToken) {
        let _ = self.notify.shutdown.set(shutdown);
        for row in self.store.webhooks().or_log().unwrap_or_default() {
            match self.read_target(&row.id) {
                Ok(target) => self.run_hook(&row, target),
                Err(e) => tracing::error!(webhook = %row.id, host = %row.host, error = %format!("{e:#}"), "this webhook's file can't be read, so nothing goes to it"),
            }
        }
    }

    fn run_hook(&self, row: &WebhookRow, target: Target) {
        let (queue, mut waiting) = mpsc::channel::<(Event, Bytes)>(WEBHOOK_QUEUE);
        let stop = self.notify.shutdown.get().map_or_else(CancellationToken::new, CancellationToken::child_token);
        let last = Arc::new(Mutex::new(None));
        let (id, host, until, kept) = (row.id.clone(), row.host.clone(), stop.clone(), last.clone());
        tokio::spawn(async move {
            loop {
                let (event, body) = tokio::select! {
                    _ = until.cancelled() => return,
                    next = waiting.recv() => match next {
                        Some(next) => next,
                        None => return,
                    },
                };
                let mut waits = RETRY_AFTER.iter();
                loop {
                    let result = post(&target, &host, event.key(), &body).await;
                    let ok = result.is_ok();
                    let said = result.unwrap_or_else(|e| e);
                    *kept.lock().unwrap() = Some(Delivered { at: unix_now(), ok, said: said.clone() });
                    if ok {
                        break;
                    }
                    let Some(wait) = waits.next() else {
                        tracing::warn!(webhook = %id, %said, "gave up on a webhook delivery after three tries");
                        break;
                    };
                    tokio::select! {
                        _ = until.cancelled() => return,
                        _ = tokio::time::sleep(*wait) => {}
                    }
                }
            }
        });
        if let Some(old) = self.notify.hooks.lock().unwrap().insert(row.id.clone(), Hook { queue, stop, last }) {
            old.stop.cancel();
        }
    }

    /// Tells webhooks and people about what changed on this sample. `before`: the alerts open
    /// before it; `exists`: whether a subject is still there.
    pub(super) fn tell(&self, now: i64, before: &[AlertView], changes: &[Change], exists: impl Fn(&str) -> bool) {
        let notices = notices(now, before, changes, exists);
        if notices.is_empty() {
            return;
        }
        let server = self.cfg.management_url();
        {
            let hooks = self.notify.hooks.lock().unwrap();
            if !hooks.is_empty() {
                for n in &notices {
                    let body = payload(n, &server, now);
                    for (id, hook) in hooks.iter() {
                        if hook.queue.try_send((n.event, body.clone())).is_err() {
                            tracing::warn!(webhook = %id, "a webhook's queue is full; dropped a delivery");
                        }
                    }
                }
            }
        }
        if self.mail_on() {
            self.queue_alert_mail(now, notices);
        }
    }

    fn queue_alert_mail(&self, now: i64, notices: Vec<Notice>) {
        let accounts = self.store.alert_email_accounts().or_log().unwrap_or_default();
        if accounts.is_empty() {
            return;
        }
        // Who each subject belongs to, and who may see it, while the state is at hand.
        let audience: Vec<(String, Vec<&Notice>)> = {
            let st = self.state.lock().unwrap();
            let owner = |subject: &str| -> Option<String> {
                match subject.split_once(':') {
                    Some(("machine", id)) => st.dir.owner(id).map(str::to_string),
                    Some(("tunnel" | "certificate", id)) => st.tunnels.get(id).and_then(|t| st.dir.owner(&t.row.agent_id)).map(str::to_string),
                    _ => None,
                }
            };
            accounts
                .iter()
                .filter(|(u, _)| can_get(u))
                .map(|(u, choice)| {
                    let who = Principal::User { id: u.id.clone(), role: u.role, tags: st.dir.user_tags(&u.id) };
                    let mine = notices
                        .iter()
                        .filter(|n| wants(*choice, u.role, &u.id, owner(&n.alert.subject).as_deref()) && self.may_see(&st, &who, &n.alert.subject))
                        .collect();
                    (u.id.clone(), mine)
                })
                .collect()
        };
        let mut inboxes = self.notify.inboxes.lock().unwrap();
        for (user_id, mine) in audience.into_iter().filter(|(_, m)| !m.is_empty()) {
            let inbox = inboxes.entry(user_id).or_default();
            for n in mine {
                if inbox.notices.len() < MAX_IN_MESSAGE {
                    inbox.notices.push(n.clone());
                } else {
                    inbox.more += 1;
                }
            }
            if inbox.due.is_none() {
                inbox.due = Some((now + GATHER_SECS).max(inbox.last_sent.map_or(0, |t| t + EMAIL_GAP_SECS)));
            }
        }
    }

    /// Sends the messages that are due, to whoever still wants them at their address now.
    pub(super) fn send_alert_mail(self: &Arc<Self>, now: i64) {
        let due: Vec<(String, Vec<Notice>, usize)> = {
            let mut inboxes = self.notify.inboxes.lock().unwrap();
            inboxes.retain(|_, b| b.due.is_some() || b.last_sent.is_some_and(|t| now - t < EMAIL_GAP_SECS));
            inboxes
                .iter_mut()
                .filter(|(_, b)| b.due.is_some_and(|d| d <= now))
                .map(|(id, b)| {
                    b.due = None;
                    b.last_sent = Some(now);
                    (id.clone(), std::mem::take(&mut b.notices), std::mem::take(&mut b.more))
                })
                .collect()
        };
        if due.is_empty() {
            return;
        }
        let accounts = self.store.alert_email_accounts().or_log().unwrap_or_default();
        let server = self.cfg.management_url();
        let messages: Vec<(String, String, mail::Mail)> = due
            .into_iter()
            .filter_map(|(user_id, notices, more)| {
                let (u, _) = accounts.iter().find(|(u, _)| u.id == user_id && can_get(u))?;
                let lines: Vec<AlertLine> = notices.iter().map(|n| line(n, &server, now)).collect();
                Some((u.id.clone(), u.email.clone(), mail::alert_digest(&server, &lines, more)))
            })
            .collect();
        let me = self.clone();
        tokio::spawn(async move {
            for (user_id, to, message) in messages {
                if let Err(e) = me.deliver(&to, &message).await {
                    tracing::warn!(user = %user_id, error = %e.message, "couldn't send alert email");
                }
            }
        });
    }

    // ---- what people choose -----------------------------------------------------------------

    /// What alerts `who` gets by email.
    pub fn alert_email(&self, who: &Principal) -> AlertEmail {
        match who {
            Principal::User { id, .. } => self.store.alert_email(id).or_log().unwrap_or_default(),
            _ => AlertEmail::Off,
        }
    }

    pub fn set_alert_email(&self, who: &Principal, choice: AlertEmail) -> Result<(), ErrorBody> {
        let Principal::User { id, role, .. } = who else {
            return Err(err(ErrorCode::Forbidden, "the admin token has no address to email"));
        };
        if choice == AlertEmail::All && *role != Role::Admin {
            return Err(err(ErrorCode::Forbidden, "only administrators get every alert"));
        }
        if choice != AlertEmail::Off {
            if !self.mail_on() {
                return Err(err(ErrorCode::MailNotConfigured, "this server has no mail server to send through"));
            }
            let me = self.store.user(id).map_err(internal)?.ok_or_else(|| denied(who))?;
            if !me.email_verified {
                return Err(err(ErrorCode::InvalidRequest, "Confirm your address first: alerts only go to an address shown to be yours."));
            }
        }
        if !self.store.set_alert_email(id, choice).map_err(internal)? {
            return Err(denied(who));
        }
        self.audit(who, "account.alert_email", id, choice.as_str());
        Ok(())
    }

    // ---- webhooks ---------------------------------------------------------------------------

    pub fn webhooks(&self, who: &Principal) -> Result<Vec<WebhookView>, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(denied(who));
        }
        let rows = self.store.webhooks().map_err(internal)?;
        let hooks = self.notify.hooks.lock().unwrap();
        Ok(rows
            .into_iter()
            .map(|r| {
                let hook = hooks.get(&r.id);
                WebhookView {
                    last: hook.and_then(|h| h.last.lock().unwrap().clone()),
                    broken: hook.is_none(),
                    id: r.id,
                    name: r.name,
                    host: r.host,
                }
            })
            .collect())
    }

    /// Adds a webhook, and gives its signing secret, which isn't shown again.
    pub fn add_webhook(&self, who: &Principal, name: &str, url: &str) -> Result<(WebhookView, String), ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(denied(who));
        }
        let (url, host) = check_url(url)?;
        let name = match clean_name(name, MAX_NAME) {
            n if n.is_empty() => host.clone(),
            n => n,
        };
        let row = WebhookRow { id: secret::new_token("wh"), name, host, created_by: who.actor().to_string(), created_at: unix_now() };
        let target = Target { url, secret: secret::new_token("whsec") };
        self.write_target(&row.id, &target).map_err(internal)?;
        if !self.store.create_webhook(&row).map_err(internal)? {
            let _ = std::fs::remove_file(self.webhook_path(&row.id));
            return Err(err(ErrorCode::LimitReached, format!("There are {MAX_WEBHOOKS} webhooks already; remove one first.")));
        }
        let secret = target.secret.clone();
        self.run_hook(&row, target);
        self.audit(who, "webhook.create", &row.id, &row.host);
        let view = WebhookView { id: row.id, name: row.name, host: row.host, last: None, broken: false };
        Ok((view, secret))
    }

    /// `false` if it was already gone.
    pub fn delete_webhook(&self, who: &Principal, id: &str) -> Result<bool, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(denied(who));
        }
        if !self.store.delete_webhook(id).map_err(internal)? {
            return Ok(false);
        }
        if let Some(hook) = self.notify.hooks.lock().unwrap().remove(id) {
            hook.stop.cancel();
        }
        if let Err(e) = std::fs::remove_file(self.webhook_path(id))
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(webhook = %id, error = %e, "could not remove a deleted webhook's file");
        }
        self.audit(who, "webhook.delete", id, "");
        Ok(true)
    }

    /// Posts a test to a webhook now, and says how it went: `Ok` with what the receiver answered.
    pub async fn test_webhook(&self, who: &Principal, id: &str) -> Result<String, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(denied(who));
        }
        let row = self.store.webhooks().map_err(internal)?.into_iter().find(|r| r.id == id).ok_or_else(|| err(ErrorCode::NotFound, "That webhook is gone."))?;
        let target = self.read_target(&row.id).map_err(logged_target(&row.id))?;
        let result = post(&target, &row.host, "test", &test_payload(&self.cfg.management_url(), unix_now())).await;
        if let Some(hook) = self.notify.hooks.lock().unwrap().get(id) {
            let (ok, said) = match &result {
                Ok(s) => (true, s.clone()),
                Err(s) => (false, s.clone()),
            };
            *hook.last.lock().unwrap() = Some(Delivered { at: unix_now(), ok, said });
        }
        result.map_err(|e| err(ErrorCode::UpstreamError, e))
    }
}

fn logged_target(id: &str) -> impl FnOnce(anyhow::Error) -> ErrorBody + '_ {
    move |e| {
        tracing::error!(webhook = %id, error = %format!("{e:#}"), "this webhook's file can't be read");
        err(ErrorCode::Internal, "This webhook's file can't be read, so nothing goes to it. Remove it and add it again.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn people_hear_about_what_they_chose_and_may_see() {
        use AlertEmail::*;
        // A member: their own machines, whatever they chose beyond that.
        for choice in [Mine, All] {
            assert!(wants(choice, Role::Member, "u1", Some("u1")));
            assert!(!wants(choice, Role::Member, "u1", Some("u2")));
            assert!(!wants(choice, Role::Member, "u1", None), "a service agent's or the server's");
        }
        // An administrator: theirs, service agents and the server; or everything.
        assert!(wants(Mine, Role::Admin, "a", Some("a")) && wants(Mine, Role::Admin, "a", None));
        assert!(!wants(Mine, Role::Admin, "a", Some("u2")));
        assert!(wants(All, Role::Admin, "a", Some("u2")));
        assert!(!wants(Off, Role::Admin, "a", None));
    }

    #[test]
    fn webhook_addresses_are_https_or_local_and_shown_by_host() {
        assert_eq!(check_url(" https://hooks.slack.com/services/T0/B0/xyz ").unwrap(), ("https://hooks.slack.com/services/T0/B0/xyz".into(), "hooks.slack.com".into()));
        assert_eq!(check_url("http://127.0.0.1:9000/hook").unwrap().1, "127.0.0.1");
        for bad in ["", "hooks.slack.com/x", "http://hooks.example.com/x", "ftp://example.com/", "https://user:pass@example.com/x", "https:///x", &format!("https://example.com/{}", "a".repeat(MAX_URL))] {
            assert!(check_url(bad).is_err(), "{bad}");
        }
    }

    fn view(id: &str, subject: &str, severity: Severity) -> AlertView {
        AlertView {
            id: id.into(),
            rule: Rule::CertificateExpiring,
            severity,
            subject: subject.into(),
            name: "web.t.test".into(),
            href: None,
            detail: "Expires 2026-11-20 14:05 UTC.".into(),
            opened_at: 5,
            closed_at: None,
        }
    }

    #[test]
    fn opened_worse_and_fine_again_are_told_and_nothing_else() {
        let row = crate::store::AlertRow {
            id: "al_new".into(),
            rule: "check_failing".into(),
            subject: "tunnel:t1".into(),
            subject_name: "web".into(),
            severity: "bad".into(),
            detail: "The last 2 checks failed: x".into(),
            opened_at: 100,
            closed_at: None,
        };
        let unknown = crate::store::AlertRow { id: "al_odd".into(), rule: "from_a_newer_server".into(), ..row.clone() };
        let before = [view("al_warn", "certificate:t2", Severity::Warn), view("al_bad", "certificate:t3", Severity::Bad), view("al_fine", "tunnel:t4", Severity::Bad), view("al_gone", "tunnel:t5", Severity::Bad)];
        let changes = [
            Change::Opened(row),
            Change::Opened(unknown),
            Change::Severity { id: "al_warn".into(), severity: Severity::Bad, detail: "Expires today.".into() },
            Change::Severity { id: "al_bad".into(), severity: Severity::Warn, detail: "Better.".into() },
            Change::Closed { id: "al_fine".into(), at: 100, detail: "d".into() },
            Change::Closed { id: "al_gone".into(), at: 100, detail: "d".into() },
        ];
        let told = notices(100, &before, &changes, |s| s != "tunnel:t5");
        let what: Vec<(Event, &str)> = told.iter().map(|n| (n.event, n.alert.id.as_str())).collect();
        assert_eq!(what, vec![(Event::Opened, "al_new"), (Event::Worse, "al_warn"), (Event::Closed, "al_fine")]);
        assert_eq!((told[0].alert.href.as_deref(), told[1].alert.detail.as_str(), told[2].alert.closed_at), (Some("/tunnels/t1"), "Expires today.", Some(100)));
    }

    #[test]
    fn a_delivery_is_signed_and_says_what_changed() {
        let alert = AlertView {
            id: "al_1".into(),
            rule: Rule::MachineOffline,
            severity: Severity::Bad,
            subject: "machine:ag_1".into(),
            name: "studio-mac".into(),
            href: Some("/machines/ag_1".into()),
            detail: "Offline since 14:03 UTC.".into(),
            opened_at: 1_800_000_000,
            closed_at: None,
        };
        let n = Notice { event: Event::Opened, at: 1_800_000_000, alert };
        let body = payload(&n, "https://mp.example.com", 1_800_000_010);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["text"], "Opened: Offline, studio-mac. Offline since 14:03 UTC. https://mp.example.com/machines/ag_1");
        assert_eq!((v["event"].as_str(), v["alert"]["rule"].as_str(), v["alert"]["severity"].as_str()), (Some("opened"), Some("machine_offline"), Some("bad")));
        assert_eq!(v["alert"]["closed_at"], serde_json::Value::Null);
        // RFC 4231, test case 2.
        let sig = signature("Jefe", b"what do ya want for nothing?");
        assert_eq!(sig, "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }
}
