//! Browser SSH terminals: a signed-in person's own shell on an SSH tunnel's machine.
//!
//! The browser's WebSocket arrives here once the management side has checked the session cookie,
//! the page's origin and that the person may reach the tunnel. This side is an SSH client: it opens
//! a data stream to the tunnel's agent, as `ssh -J` does, so the agent only connects to the sshd its
//! own user configured, and logs in as the user the person named, with a key made for this session
//! and a five-minute certificate from the server's authority (`ssh-user-ca`). The certificate names
//! the person by their email address, and the machine decides which accounts that may log in as
//! (`AuthorizedPrincipalsFile`). Nothing that can log in outlives the session but the authority.
//!
//! The machine's host key is kept the first time (`Report::HostKey`), and a different one later is
//! refused: the stream crosses the agent's network, and a session typed into the wrong machine is
//! worse than none. The session ends when the person loses access to the tunnel, signs out
//! everywhere, or the tunnel goes, checked on every publish.
//!
//! The messages are the shared terminal page's (`magicpipes_core::terminal`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::ServerOpen;
use russh::client::{self, AuthResult, Handle};
use russh::keys::ssh_key::certificate::{Builder, CertType};
use russh::keys::{Certificate, HashAlg, PrivateKey, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect, SshId};
use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use super::ssh::{Report, new_key, random};
use super::{DataPlane, Route, RouteTable, ports};

/// Open browser terminals, in all and per person; the same again for remote desktops.
const MAX_TERMINALS: usize = 256;
pub(super) const MAX_PER_PERSON: usize = 8;
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Reaching the machine and logging in.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(20);
/// How long a certificate is good for. It's only used to log in, once, right away; a little before
/// now as well, for a machine whose clock is behind.
const CERTIFICATE_SECS: u64 = 300;
const CLOCK_SKEW_SECS: u64 = 60;
const PING_EVERY: Duration = Duration::from_secs(30);
/// Output is sent to the browser in messages of at most this size.
const MAX_CHUNK: usize = 64 * 1024;

/// Who is opening a terminal, as the management side found them.
#[derive(Debug, Clone)]
pub struct Opening {
    pub user_id: String,
    /// The certificate's principal.
    pub email: String,
    pub tunnel_id: String,
    pub name: String,
    pub client: IpAddr,
    /// When the browser signed in: signing out everywhere after that ends the session.
    pub signed_in_at: i64,
}

pub(super) struct Limits {
    all: Arc<Semaphore>,
    per_person: Arc<Mutex<HashMap<String, usize>>>,
}

impl Default for Limits {
    fn default() -> Self {
        Self { all: Arc::new(Semaphore::new(MAX_TERMINALS)), per_person: Arc::default() }
    }
}

impl Limits {
    pub(super) fn take(&self, user_id: &str) -> Option<Slot> {
        let permit = self.all.clone().try_acquire_owned().ok()?;
        let mut people = self.per_person.lock().unwrap_or_else(|e| e.into_inner());
        let n = people.entry(user_id.to_string()).or_insert(0);
        if *n >= MAX_PER_PERSON {
            return None;
        }
        *n += 1;
        Some(Slot { _permit: permit, people: self.per_person.clone(), user_id: user_id.to_string() })
    }
}

pub(super) struct Slot {
    _permit: tokio::sync::OwnedSemaphorePermit,
    people: Arc<Mutex<HashMap<String, usize>>>,
    user_id: String,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut people = self.people.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = people.get_mut(&self.user_id) {
            *n -= 1;
            if *n == 0 {
                people.remove(&self.user_id);
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Control {
    Hello { login: String, cols: u16, rows: u16 },
    Resize { cols: u16, rows: u16 },
}

fn size(cols: u16, rows: u16) -> (u32, u32) {
    (u32::from(cols.clamp(2, 500)), u32::from(rows.clamp(2, 300)))
}

/// A user name sshd could take: what POSIX allows, and nothing a shell or a log would misread.
pub fn valid_login(login: &str) -> bool {
    (1..=32).contains(&login.len())
        && !login.starts_with('-')
        && login.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// Why a session couldn't start, for the page.
struct Refusal {
    code: &'static str,
    message: String,
}

fn refusal(code: ErrorCode, message: impl Into<String>) -> Refusal {
    Refusal { code: code.as_str(), message: message.into() }
}

/// What sshd said its host key was.
#[derive(Default)]
struct Seen(Mutex<Option<String>>);

/// The SSH client's side of host keys: the kept one must match.
struct Machine {
    kept: Option<String>,
    seen: Arc<Seen>,
}

impl client::Handler for Machine {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let fingerprint = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.fingerprint(HashAlg::Sha256),
            PublicKeyOrCertificate::Certificate(cert) => cert.public_key().fingerprint(HashAlg::Sha256),
        }
        .to_string();
        let ok = self.kept.as_ref().is_none_or(|k| *k == fingerprint);
        *self.seen.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(fingerprint);
        Ok(ok)
    }
}

/// A key made for this session, and a certificate for it naming `principal`.
fn certificate(ca: &PrivateKey, principal: &str, key_id: &str) -> anyhow::Result<(PrivateKey, Certificate)> {
    let key = new_key("")?;
    let now = magicpipes_core::unix_now().max(0) as u64;
    let mut cert = Builder::new(random::<32>()?.to_vec(), key.public_key().key_data().clone(), now.saturating_sub(CLOCK_SKEW_SECS), now + CERTIFICATE_SECS)?;
    cert.serial(u64::from_be_bytes(random()?))?;
    cert.cert_type(CertType::User)?;
    cert.key_id(key_id)?;
    cert.valid_principal(principal)?;
    // A terminal, and nothing else: no forwarding, no agent, no X11.
    cert.extension("permit-pty", "")?;
    Ok((key, cert.sign(ca)?))
}

/// Serves one browser terminal until it ends.
pub async fn run<S>(dp: Arc<DataPlane>, mut ws: WebSocketStream<S>, o: Opening)
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let hello = match tokio::time::timeout(HELLO_TIMEOUT, ws.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => serde_json::from_str::<Control>(&t).ok(),
        _ => None,
    };
    let Some(Control::Hello { login, cols, rows }) = hello else {
        return finish(ws, json!({ "type": "error", "code": ErrorCode::Protocol.as_str(), "message": "expected a hello message" })).await;
    };
    if !valid_login(&login) {
        let message = "That isn't a user name. Use letters, digits, dots, dashes and underscores, as in doug or deploy-bot.";
        return finish(ws, json!({ "type": "error", "code": ErrorCode::InvalidRequest.as_str(), "message": message })).await;
    }
    let Some(_slot) = dp.terminals.take(&o.user_id) else {
        let message = format!("You have {MAX_PER_PERSON} terminals open already, or the server is at its limit. Close one first.");
        return finish(ws, json!({ "type": "error", "code": ErrorCode::Busy.as_str(), "message": message })).await;
    };
    let (handle, mut channel) = match log_in(&dp, &o, &login, size(cols, rows)).await {
        Ok(v) => v,
        Err(r) => return finish(ws, json!({ "type": "error", "code": r.code, "message": r.message })).await,
    };
    tracing::info!(user = %o.user_id, tunnel = %o.tunnel_id, %login, client = %o.client, "browser terminal opened");
    let _ = dp.ssh_reports.try_send(Report::Terminal { user_id: o.user_id.clone(), tunnel_id: o.tunnel_id.clone(), login, client: o.client });
    let last = pump(&dp, &mut ws, &mut channel, &o).await;
    let _ = handle.disconnect(Disconnect::ByApplication, "", "").await;
    if let Some(msg) = last {
        finish(ws, msg).await;
    }
}

/// Reaches the machine and logs in, as far as a shell in a pty.
async fn log_in(dp: &DataPlane, o: &Opening, login: &str, (cols, rows): (u32, u32)) -> Result<(Handle<Machine>, russh::Channel<client::Msg>), Refusal> {
    let gone = || refusal(ErrorCode::NotFound, "You can't reach this machine, or it no longer exists.");
    let table = dp.table();
    let route = admitted(&table, o).ok_or_else(gone)?.clone();
    let agent = match route.agent.as_ref().filter(|a| a.is_online()) {
        Some(a) => a.clone(),
        None => return Err(refusal(ErrorCode::AgentOffline, format!("{} is offline.", o.name))),
    };
    let ca = dp.ssh_ca.get().cloned().ok_or_else(|| refusal(ErrorCode::SshDisabled, "This server has no SSH gateway."))?;
    let did_not_answer = || refusal(ErrorCode::LocalUnreachable, format!("{} did not answer. Is its sshd running?", o.name));
    let header = ServerOpen::Data { tunnel_id: route.tunnel_id.clone(), peer: Some(o.client.to_string()) };
    let stream = ports::open(dp, &route, &agent, o.client, header).await.ok_or_else(did_not_answer)?;

    let seen = Arc::new(Seen::default());
    let config = Arc::new(client::Config {
        client_id: SshId::Standard("SSH-2.0-magicpipes".into()),
        inactivity_timeout: None,
        keepalive_interval: Some(PING_EVERY),
        keepalive_max: 3,
        ..client::Config::default()
    });
    let machine = Machine { kept: route.host_key.clone(), seen: seen.clone() };
    let connect = tokio::time::timeout(LOGIN_TIMEOUT, client::connect_stream(config, stream, machine));
    let mut handle = match connect.await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            let shown = seen.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if let (Some(kept), Some(shown)) = (&route.host_key, shown)
                && *kept != shown
            {
                tracing::warn!(tunnel = %o.tunnel_id, %kept, %shown, "browser terminal refused a changed host key");
                return Err(refusal(
                    ErrorCode::Forbidden,
                    format!(
                        "{}'s host key isn't the one it showed before ({kept}; now {shown}). Someone may be in between. If the machine was reinstalled, \
                         its owner can forget the old key on the tunnel's page.",
                        o.name
                    ),
                ));
            }
            tracing::debug!(tunnel = %o.tunnel_id, error = %e, "browser terminal: no SSH session");
            return Err(did_not_answer());
        }
        Err(_) => return Err(did_not_answer()),
    };
    let (key, cert) = certificate(&ca, &o.email, &format!("magicpipes {} {}", o.user_id, o.name)).map_err(|e| {
        tracing::error!(error = %format!("{e:#}"), "could not make a certificate");
        refusal(ErrorCode::Internal, "The server couldn't make a certificate. Its log says why.")
    })?;
    let auth = tokio::time::timeout(LOGIN_TIMEOUT, handle.authenticate_openssh_cert(login, Arc::new(key), cert)).await;
    if !matches!(auth, Ok(Ok(AuthResult::Success))) {
        return Err(refusal(
            ErrorCode::Forbidden,
            format!(
                "{name} didn't let {email} log in as {login}. Its sshd has to trust this server's certificates, and {login}'s authorized_principals \
                 file has to list {email}. The tunnel's page shows how.",
                name = o.name,
                email = o.email,
            ),
        ));
    }
    if route.host_key.is_none()
        && let Some(fingerprint) = seen.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    {
        let _ = dp.ssh_reports.try_send(Report::HostKey { tunnel_id: route.tunnel_id.clone(), fingerprint });
    }
    let failed = |e: russh::Error| {
        tracing::debug!(tunnel = %o.tunnel_id, error = %e, "browser terminal: no shell");
        refusal(ErrorCode::LocalUnreachable, format!("{} let you in but didn't start a shell.", o.name))
    };
    let channel = handle.channel_open_session().await.map_err(failed)?;
    channel.request_pty(false, "xterm-256color", cols, rows, 0, 0, &[]).await.map_err(failed)?;
    channel.request_shell(false).await.map_err(failed)?;
    Ok((handle, channel))
}

/// The tunnel's route, if the person may still use it.
fn admitted<'t>(table: &'t RouteTable, o: &Opening) -> Option<&'t Arc<Route>> {
    let user = table.users.get(&o.user_id).filter(|u| u.valid_after <= o.signed_in_at)?;
    table.by_ssh.get(&o.name).filter(|r| r.tunnel_id == o.tunnel_id && r.access.admits(&user.principal, o.client))
}

/// Moves keystrokes one way and output the other. Returns the last message for the page, if the
/// browser is still there to get it.
async fn pump<S>(dp: &DataPlane, ws: &mut WebSocketStream<S>, channel: &mut russh::Channel<client::Msg>, o: &Opening) -> Option<serde_json::Value>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if send(ws, json!({ "type": "ready", "writable": true })).await.is_err() {
        return None;
    }
    let mut changes = dp.generation.subscribe();
    let mut ping = tokio::time::interval(PING_EVERY);
    ping.tick().await;
    let (mut code, mut signal): (Option<u32>, Option<String>) = (None, None);
    let ended = |message: &str| Some(json!({ "type": "ended", "message": message }));
    loop {
        tokio::select! {
            _ = dp.shutdown.cancelled() => return ended("The server is restarting."),
            r = changes.changed() => {
                if r.is_err() || admitted(&dp.table(), o).is_none() {
                    tracing::debug!(user = %o.user_id, tunnel = %o.tunnel_id, "closing a browser terminal its user may no longer use");
                    return ended("You can no longer reach this machine.");
                }
            }
            msg = ws.next() => match msg {
                Some(Ok(Message::Binary(data))) => {
                    if channel.data_bytes(data).await.is_err() {
                        return ended("The machine closed the connection.");
                    }
                }
                Some(Ok(Message::Text(t))) => {
                    if let Ok(Control::Resize { cols, rows }) = serde_json::from_str(&t) {
                        let (cols, rows) = size(cols, rows);
                        let _ = channel.window_change(cols, rows, 0, 0).await;
                    }
                }
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return None,
                Some(Ok(_)) => {}
            },
            msg = channel.wait() => match msg {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    for chunk in data.chunks(MAX_CHUNK) {
                        if ws.send(Message::Binary(chunk.to_vec().into())).await.is_err() {
                            return None;
                        }
                    }
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => code = Some(exit_status),
                Some(ChannelMsg::ExitSignal { signal_name, .. }) => signal = Some(format!("{signal_name:?}")),
                Some(ChannelMsg::Close) | None => {
                    return Some(json!({ "type": "exit", "code": code.unwrap_or(if signal.is_some() { 1 } else { 0 }), "signal": signal }));
                }
                Some(_) => {}
            },
            _ = ping.tick() => {
                if ws.send(Message::Ping(Default::default())).await.is_err() {
                    return None;
                }
            }
        }
    }
}

async fn send<S>(ws: &mut WebSocketStream<S>, msg: serde_json::Value) -> Result<(), ()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ws.send(Message::Text(msg.to_string().into())).await.map_err(|_| ())
}

/// Sends a last message and closes the WebSocket.
async fn finish<S>(mut ws: WebSocketStream<S>, msg: serde_json::Value)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = send(&mut ws, msg).await;
        let _ = ws.close(None).await;
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::ssh_key::certificate::CertType;

    #[test]
    fn user_names_are_plain() {
        for ok in ["doug", "deploy-bot", "a.b_c", "x", &"a".repeat(32)] {
            assert!(valid_login(ok), "{ok}");
        }
        for bad in ["", "-oProxyCommand=x", "root@host", "a b", "dou\ng", "ü", &"a".repeat(33), "a;b", "$(id)"] {
            assert!(!valid_login(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_certificate_is_brief_and_for_a_terminal_only() {
        let ca = new_key("ca").unwrap();
        let (key, cert) = certificate(&ca, "ann@example.com", "magicpipes us_a dev").unwrap();
        assert_eq!(cert.public_key(), key.public_key().key_data());
        assert_eq!(cert.cert_type(), CertType::User);
        assert_eq!(cert.valid_principals(), ["ann@example.com"]);
        assert_eq!(cert.key_id(), "magicpipes us_a dev");
        assert_eq!(cert.valid_before() - cert.valid_after(), CERTIFICATE_SECS + CLOCK_SKEW_SECS);
        assert!(cert.critical_options().is_empty());
        assert_eq!(cert.extensions().keys().collect::<Vec<_>>(), ["permit-pty"]);
        assert_eq!(cert.signature_key(), ca.public_key().key_data());
        // A new key every time.
        let (other, _) = certificate(&ca, "ann@example.com", "x").unwrap();
        assert_ne!(other.public_key(), key.public_key());
    }

    #[test]
    fn a_person_has_a_few_terminals_and_the_server_a_few_hundred() {
        let limits = Limits::default();
        let mine: Vec<_> = (0..MAX_PER_PERSON).map(|_| limits.take("us_a").expect("room")).collect();
        assert!(limits.take("us_a").is_none(), "over the per-person limit");
        assert!(limits.take("us_b").is_some(), "others still get one");
        drop(mine);
        assert!(limits.take("us_a").is_some(), "given back");
    }
}
