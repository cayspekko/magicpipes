//! `magicpipes connect`: reach a private TCP or UDP tunnel, or a remote desktop, from this computer, as yourself.
//!
//! It listens here and, for each local connection (TCP) or local client (UDP), makes an HTTPS
//! connection to the server's management address and upgrades it with a connect pass
//! (`GET /api/v1/connect/<name>`; `data::connect` on the server). After that the connection is
//! the tunnel's: raw bytes for TCP, and for UDP each datagram behind its `u16` length, as the agent
//! carries them.
//!
//! A pass comes from signing in: approved in a browser, on this computer or any other, and kept in
//! `connect.json` until it expires. For scripts, an API token (`MAGICPIPES_API_TOKEN`) is traded for
//! a short pass instead, and again before that one expires. The agent plays no part, so a computer
//! that was never enrolled can connect.

use std::collections::HashMap;
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, StatusCode, header};
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use magicpipes_core::error::ErrorCode;
use magicpipes_core::mux::COPY_BUFFER;
use magicpipes_core::proto::{self, CONNECT_PATH, CONNECT_PROTOCOL, Kind};
use magicpipes_core::unix_now;
use rustls::ClientConfig;
use serde_json::{Value, json};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Semaphore, mpsc};

use crate::ipc::ErrorInfo;
use crate::state::{AgentConfig, ConnectPasses, SavedPass};
use crate::{https, platform};

/// Connections and UDP clients at once; the server allows a person as many.
const MAX_OPEN: usize = 64;
/// How long a UDP client's flow lasts without a datagram either way.
const UDP_IDLE: Duration = Duration::from_secs(60);
/// Datagrams queued for a flow while it connects or is busy; more are dropped.
const FLOW_QUEUE: usize = 64;
/// A pass this close to expiring is renewed (with an API token), or replaced by signing in again
/// before listening.
const RENEW_BEFORE_SECS: i64 = 300;
/// Time for a connection's handshake, which includes the agent reaching its service.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

pub struct Options {
    pub tunnel: String,
    pub local: Option<SocketAddr>,
    pub server: Option<String>,
    pub ca_cert: Option<PathBuf>,
    pub no_browser: bool,
    pub api_token: Option<String>,
    pub json: bool,
    pub quiet: bool,
}

/// What a sign-in approved in a browser is for, in the words the CLI shows.
pub struct SignIn<'a> {
    /// Where to ask for a code, and with what.
    pub start: &'a str,
    pub body: Value,
    /// The command to run again when it fails.
    pub command: &'a str,
    /// What to tell the person, before the page's address.
    pub ask: &'a str,
    /// The error when it's denied or expires.
    pub refused: ErrorCode,
}

/// A sign-in approved in a browser, on this computer or any other: asks the server for a code,
/// shows the page to approve it at (and opens it here if `open`), and waits. Returns the server's
/// answer once approved, or `None` if the server predates this kind of sign-in.
pub async fn approve_in_browser(server: &str, tls: &Arc<ClientConfig>, s: SignIn<'_>, open: bool, quiet: bool) -> Result<Option<Value>, ErrorInfo> {
    let (status, resp) = https::post_json(server, s.start, tls, &s.body).await.map_err(|e| crate::unreachable_server(&e))?;
    if matches!(status.as_u16(), 404 | 405) {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(error_from(status, &resp, "the server refused to start a sign-in"));
    }
    let bad = || ErrorInfo::new(ErrorCode::Protocol, "unexpected answer to the sign-in request");
    let device_code = resp["device_code"].as_str().ok_or_else(bad)?.to_string();
    // The URL is built here, from the server address the user typed; only a well-formed code
    // from the server goes into it.
    let user_code = resp["user_code"].as_str().filter(|c| c.len() <= 16 && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')).ok_or_else(bad)?;
    let expires = Duration::from_secs(resp["expires_in_secs"].as_u64().unwrap_or(600).min(900));
    let interval = Duration::from_secs(resp["interval_secs"].as_u64().unwrap_or(2).clamp(1, 10));
    let url = format!("{server}/cli?code={user_code}");
    if !quiet {
        eprintln!("{}\n\n  {url}\n\nIt should show the code {user_code}. Waiting for approval...", s.ask);
    }
    if open {
        platform::open_url(&url);
    }
    let deadline = std::time::Instant::now() + expires;
    let expired = || ErrorInfo::new(s.refused, format!("the code expired before it was approved; run magicpipes {} again", s.command));
    loop {
        tokio::time::sleep(interval).await;
        if std::time::Instant::now() > deadline {
            return Err(expired());
        }
        // A failed poll (network hiccup) is retried until the deadline.
        let Ok((_, resp)) = https::post_json(server, "/api/v1/device/poll", tls, &json!({ "device_code": device_code })).await else { continue };
        match resp["status"].as_str() {
            Some("approved") => return Ok(Some(resp)),
            Some("denied") => return Err(ErrorInfo::new(s.refused, "it was denied in the browser")),
            Some("expired") => return Err(expired()),
            _ => {}
        }
    }
}

/// The server's error, or what its status means when it sent none (an older server).
fn error_from(status: StatusCode, v: &Value, otherwise: &str) -> ErrorInfo {
    match (v["error"]["code"].as_str(), v["error"]["message"].as_str()) {
        (Some(code), message) => ErrorInfo::wire(code, message.unwrap_or(otherwise).to_string()),
        (None, _) if matches!(status.as_u16(), 404 | 405) => outdated(),
        (None, _) => ErrorInfo::new(ErrorCode::Protocol, format!("{otherwise} (HTTP {status})")),
    }
}

fn outdated() -> ErrorInfo {
    ErrorInfo::new(ErrorCode::ServerOutdated, "this server doesn't offer magicpipes connect; it needs a newer magicpipesd")
}

/// A tunnel's name as typed: its name, or its name under the base domain.
fn tunnel_name(asked: &str) -> Result<String, ErrorInfo> {
    let name = asked.trim().trim_end_matches('.');
    if name.is_empty() || name.len() > 253 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.') {
        return Err(ErrorInfo::new(ErrorCode::InvalidName, format!("'{asked}' isn't a tunnel's name")));
    }
    Ok(name.to_ascii_lowercase())
}

/// The server, and the pass this computer connects with.
struct Link {
    server: String,
    tls: Arc<ClientConfig>,
    ca_pem: Option<String>,
    api_token: Option<String>,
    /// The pass in use and when it expires. Held while one is renewed, so one at a time is.
    pass: tokio::sync::Mutex<Option<(String, i64)>>,
}

impl Link {
    fn new(o: &Options) -> Result<Self, ErrorInfo> {
        let config = |e: String| ErrorInfo::new(ErrorCode::ConfigError, e);
        let enrolled = AgentConfig::load().map_err(|e| config(format!("{e:#}")))?;
        let server = match (&o.server, &enrolled) {
            (Some(s), _) => s.trim().trim_end_matches('/').to_string(),
            (None, Some(c)) => c.server.clone(),
            (None, None) => {
                return Err(ErrorInfo::new(
                    ErrorCode::NotLoggedIn,
                    "say which server with --server https://<server>, or enroll this machine with `magicpipes login`",
                ));
            }
        };
        https::parse_server(&server).map_err(|e| ErrorInfo::new(ErrorCode::InvalidServer, e.to_string()))?;
        let saved = ConnectPasses::load().passes.remove(&server);
        let ca_pem = match &o.ca_cert {
            Some(p) => Some(std::fs::read_to_string(p).map_err(|e| config(format!("reading {}: {e}", p.display())))?),
            None => saved.as_ref().and_then(|s| s.ca_cert_pem.clone()).or_else(|| enrolled.filter(|c| c.server == server).and_then(|c| c.ca_cert_pem)),
        };
        let tls = https::tls_config(ca_pem.as_deref()).map_err(|e| config(format!("{e:#}")))?;
        let api_token = o.api_token.as_deref().map(str::trim).filter(|t| !t.is_empty()).map(str::to_string);
        // An API token stands for its own person, whoever signed in on this computer.
        let pass = if api_token.is_none() { saved.map(|s| (s.pass, s.expires_at)) } else { None };
        Ok(Self { server, tls, ca_pem, api_token, pass: tokio::sync::Mutex::new(pass) })
    }

    /// The pass to present: the current one while it lasts; with an API token, a new one shortly
    /// before then.
    async fn pass(&self) -> Result<String, ErrorInfo> {
        let mut current = self.pass.lock().await;
        let left = current.as_ref().map_or(0, |(_, expires)| expires - unix_now());
        match (current.as_ref(), &self.api_token) {
            (Some((p, _)), None) if left > 0 => Ok(p.clone()),
            (Some((p, _)), Some(_)) if left > RENEW_BEFORE_SECS => Ok(p.clone()),
            (_, Some(token)) => {
                let (status, v) =
                    https::call(&self.server, Method::POST, "/api/v1/passes", &self.tls, Some(token), None).await.map_err(|e| crate::unreachable_server(&e))?;
                if !status.is_success() {
                    return Err(error_from(status, &v, "the server refused the API token"));
                }
                let pass = v["pass"].as_str().ok_or_else(|| ErrorInfo::new(ErrorCode::Protocol, "unexpected answer to the API token"))?.to_string();
                *current = Some((pass.clone(), v["expires_at"].as_i64().unwrap_or(0)));
                Ok(pass)
            }
            (_, None) => Err(signed_out()),
        }
    }

    /// Signs in in a browser and keeps the pass, for later runs too.
    async fn sign_in(&self, o: &Options) -> Result<(), ErrorInfo> {
        let s = SignIn {
            start: "/api/v1/passes/device",
            body: json!({ "machine": platform::hostname() }),
            command: "connect",
            ask: "To connect as you, open this page and approve it, in a browser here or on any other device:",
            refused: ErrorCode::Unauthenticated,
        };
        let open = !o.no_browser && std::io::stdin().is_terminal();
        let v = approve_in_browser(&self.server, &self.tls, s, open, o.quiet).await?.ok_or_else(outdated)?;
        let bad = || ErrorInfo::new(ErrorCode::Protocol, "unexpected answer to the sign-in");
        let pass = v["pass"].as_str().ok_or_else(bad)?.to_string();
        let expires_at = v["expires_at"].as_i64().ok_or_else(bad)?;
        let mut saved = ConnectPasses::load();
        saved.passes.retain(|_, p| p.expires_at > unix_now());
        saved.passes.insert(self.server.clone(), SavedPass { pass: pass.clone(), expires_at, ca_cert_pem: self.ca_pem.clone() });
        if let Err(e) = saved.save() {
            eprintln!("Warning: couldn't keep the sign-in for next time: {e:#}");
        }
        *self.pass.lock().await = Some((pass, expires_at));
        Ok(())
    }

    /// Forgets a pass the server no longer takes.
    async fn forget(&self) {
        *self.pass.lock().await = None;
        let mut saved = ConnectPasses::load();
        if saved.passes.remove(&self.server).is_some() {
            let _ = saved.save();
        }
    }

    /// What the tunnel is and whether it's online, signing in first when this computer has no pass
    /// that will last a while.
    async fn find(&self, name: &str, o: &Options) -> Result<(Kind, bool), ErrorInfo> {
        let mut signed_in = false;
        loop {
            let lasting = self.pass.lock().await.as_ref().is_some_and(|(_, expires)| expires - unix_now() > RENEW_BEFORE_SECS);
            if self.api_token.is_none() && !lasting {
                self.sign_in(o).await?;
                signed_in = true;
            }
            let pass = self.pass().await?;
            let path = format!("{CONNECT_PATH}{name}");
            let (status, v) = https::call(&self.server, Method::GET, &path, &self.tls, Some(&pass), None).await.map_err(|e| crate::unreachable_server(&e))?;
            if status.is_success() {
                // An RDP tunnel is TCP to a Remote Desktop client.
                let kind = serde_json::from_value::<Kind>(v["kind"].clone()).ok().filter(|k| k.has_port() || *k == Kind::Rdp);
                let kind = kind.ok_or_else(|| ErrorInfo::new(ErrorCode::Protocol, "unexpected answer about the tunnel"))?;
                return Ok((kind, v["online"].as_bool().unwrap_or(true)));
            }
            // Signed out everywhere, or a pass from before the server's key changed.
            if status == StatusCode::UNAUTHORIZED && self.api_token.is_none() && !signed_in {
                self.forget().await;
                continue;
            }
            return Err(error_from(status, &v, "the server refused"));
        }
    }

    /// A connection to the tunnel through the server.
    async fn open(&self, name: &str) -> Result<TokioIo<hyper::upgrade::Upgraded>, ErrorInfo> {
        let pass = self.pass().await?;
        let (host, port) = https::parse_server(&self.server).map_err(|e| ErrorInfo::new(ErrorCode::InvalidServer, e.to_string()))?;
        let attempt = async {
            let stream = https::connect(&host, port, &self.tls, None).await.map_err(|e| crate::unreachable_server(&e))?;
            let req = Request::get(format!("{CONNECT_PATH}{name}"))
                .header(header::HOST, https::host_header(&host, port))
                .header(header::AUTHORIZATION, format!("Bearer {pass}"))
                .header(header::CONNECTION, "upgrade")
                .header(header::UPGRADE, CONNECT_PROTOCOL)
                .header(header::USER_AGENT, https::USER_AGENT)
                .body(Full::new(Bytes::new()))
                .map_err(|e| ErrorInfo::new(ErrorCode::Internal, e.to_string()))?;
            let resp = https::send(stream, req).await.map_err(|e| crate::unreachable_server(&e))?;
            if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
                let upgraded = hyper::upgrade::on(resp).await.map_err(|e| ErrorInfo::new(ErrorCode::Protocol, format!("the connection didn't switch over: {e}")))?;
                return Ok(TokioIo::new(upgraded));
            }
            let status = resp.status();
            let v = https::read_json(resp).await.unwrap_or(Value::Null);
            Err(error_from(status, &v, "the server refused the connection"))
        };
        tokio::time::timeout(HANDSHAKE_TIMEOUT, attempt)
            .await
            .map_err(|_| ErrorInfo::new(ErrorCode::ServerUnreachable, format!("the server didn't connect to {name} within {}s", HANDSHAKE_TIMEOUT.as_secs())))?
    }
}

fn signed_out() -> ErrorInfo {
    ErrorInfo::new(ErrorCode::Unauthenticated, "your sign-in has expired or was ended; run magicpipes connect again to sign in")
}

/// What one connection or flow that couldn't open means: a line about it, or the end, when no
/// connection can open any more.
fn failed(e: ErrorInfo, what: &str, fatal: &mpsc::Sender<ErrorInfo>, quiet: bool) {
    if e.is(ErrorCode::Unauthenticated) || e.is(ErrorCode::Unauthorized) || e.is(ErrorCode::Forbidden) || e.is(ErrorCode::NotFound) {
        let _ = fatal.try_send(e);
    } else if !quiet {
        eprintln!("{what}: {}", e.message);
    }
}

pub async fn run(o: Options) -> Result<(), ErrorInfo> {
    let name = tunnel_name(&o.tunnel)?;
    let link = Link::new(&o)?;
    let (kind, online) = link.find(&name, &o).await?;
    let local = o.local.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
    let cannot_listen = |e: std::io::Error| ErrorInfo::new(ErrorCode::InvalidPort, format!("can't listen on {local}: {e}. Choose another with --local"));
    let (link, name): (Arc<Link>, Arc<str>) = (Arc::new(link), name.into());
    let (fatal, mut ended) = mpsc::channel(1);
    let (bound, serving) = match kind {
        Kind::Udp => {
            let socket = UdpSocket::bind(local).await.map_err(cannot_listen)?;
            let bound = socket.local_addr().map_err(cannot_listen)?;
            (bound, futures_util::future::Either::Left(serve_udp(link.clone(), name.clone(), socket, fatal, o.quiet)))
        }
        _ => {
            let listener = TcpListener::bind(local).await.map_err(cannot_listen)?;
            let bound = listener.local_addr().map_err(cannot_listen)?;
            (bound, futures_util::future::Either::Right(serve_tcp(link.clone(), name.clone(), listener, fatal, o.quiet)))
        }
    };
    if o.json {
        // One line, so a script can read it and carry on while this keeps running.
        println!("{}", json!({ "tunnel": &*name, "kind": kind, "local": bound.to_string(), "server": link.server, "online": online }));
    } else {
        println!("Forwarding {bound} to {name} ({}), as you, through {}.\nPress Ctrl+C to stop.", kind.to_string().to_uppercase(), link.server);
    }
    if !online && !o.quiet {
        eprintln!("Warning: the machine serving {name} is offline right now; connections fail until it's back.");
    }
    tokio::select! {
        _ = serving => Ok(()),
        _ = platform::interrupt() => Ok(()),
        _ = platform::terminate() => Ok(()),
        e = ended.recv() => Err(e.unwrap_or_else(signed_out)),
    }
}

async fn serve_tcp(link: Arc<Link>, name: Arc<str>, listener: TcpListener, fatal: mpsc::Sender<ErrorInfo>, quiet: bool) {
    let open = Arc::new(Semaphore::new(MAX_OPEN));
    loop {
        let (mut local, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = open.clone().try_acquire_owned() else {
            if !quiet {
                eprintln!("{MAX_OPEN} connections are open already; refused one from {peer}");
            }
            continue;
        };
        let _ = local.set_nodelay(true);
        let (link, name, fatal) = (link.clone(), name.clone(), fatal.clone());
        tokio::spawn(async move {
            let _permit = permit;
            match link.open(&name).await {
                Ok(mut remote) => {
                    let _ = tokio::io::copy_bidirectional_with_sizes(&mut local, &mut remote, COPY_BUFFER, COPY_BUFFER).await;
                }
                Err(e) => failed(e, &format!("A connection from {peer} failed"), &fatal, quiet),
            }
        });
    }
}

async fn serve_udp(link: Arc<Link>, name: Arc<str>, socket: UdpSocket, fatal: mpsc::Sender<ErrorInfo>, quiet: bool) {
    let socket = Arc::new(socket);
    let mut flows: HashMap<SocketAddr, mpsc::Sender<Bytes>> = HashMap::new();
    let mut buf = vec![0u8; proto::MAX_DATAGRAM];
    loop {
        // e.g. an ICMP "port unreachable" from an earlier reply, reported on some systems.
        let Ok((n, peer)) = socket.recv_from(&mut buf).await else { continue };
        let datagram = Bytes::copy_from_slice(&buf[..n]);
        if let Some(tx) = flows.get(&peer)
            && !tx.is_closed()
        {
            // A full queue drops the datagram, as a congested network would.
            let _ = tx.try_send(datagram);
            continue;
        }
        flows.retain(|_, tx| !tx.is_closed());
        if flows.len() >= MAX_OPEN {
            continue;
        }
        let (tx, rx) = mpsc::channel(FLOW_QUEUE);
        let _ = tx.try_send(datagram);
        flows.insert(peer, tx);
        let (link, name, socket, fatal) = (link.clone(), name.clone(), socket.clone(), fatal.clone());
        tokio::spawn(async move {
            match link.open(&name).await {
                Ok(remote) => udp_flow(remote, &socket, peer, rx).await,
                Err(e) => failed(e, &format!("Datagrams from {peer} couldn't get through"), &fatal, quiet),
            }
        });
    }
}

/// One local UDP client: its datagrams go out on one connection, and replies come back on it.
async fn udp_flow(remote: TokioIo<hyper::upgrade::Upgraded>, socket: &UdpSocket, peer: SocketAddr, mut rx: mpsc::Receiver<Bytes>) {
    let (mut rd, mut wr) = tokio::io::split(remote);
    let quiet_since = std::sync::Mutex::new(tokio::time::Instant::now());
    let touch = || *quiet_since.lock().unwrap_or_else(|e| e.into_inner()) = tokio::time::Instant::now();
    // Replies run as one future: a frame read must never be cancelled halfway.
    let replies = async {
        let mut buf = Vec::new();
        while let Ok(true) = proto::read_datagram(&mut rd, &mut buf).await {
            touch();
            if socket.send_to(&buf, peer).await.is_err() {
                break;
            }
        }
    };
    let requests = async {
        let mut tick = tokio::time::interval(UDP_IDLE / 4);
        loop {
            tokio::select! {
                d = rx.recv() => match d {
                    Some(d) => {
                        touch();
                        if proto::write_datagram(&mut wr, &d).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
                _ = tick.tick() => {
                    if quiet_since.lock().unwrap_or_else(|e| e.into_inner()).elapsed() >= UDP_IDLE {
                        break;
                    }
                }
            }
        }
    };
    tokio::select! {
        _ = replies => {}
        _ = requests => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_names_as_typed() {
        assert_eq!(tunnel_name("db").unwrap(), "db");
        assert_eq!(tunnel_name(" DB.example.com. ").unwrap(), "db.example.com");
        for bad in ["", "a/b", "a b", "../x", "a?b", "a#b", "%2e"] {
            assert!(tunnel_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn errors_say_what_the_server_said() {
        let e = error_from(StatusCode::NOT_FOUND, &json!({ "error": { "code": "not_found", "message": "no tunnel named 'x'" } }), "x");
        assert!(e.is(ErrorCode::NotFound) && e.message.contains("no tunnel"));
        assert!(error_from(StatusCode::NOT_FOUND, &Value::Null, "x").is(ErrorCode::ServerOutdated), "an older server's page");
        assert!(error_from(StatusCode::BAD_GATEWAY, &Value::Null, "x").is(ErrorCode::Protocol));
    }
}
