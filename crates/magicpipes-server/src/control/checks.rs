//! The server's own checks of each tunnel (`[monitoring] synthetics`). Every
//! `check_interval_secs` it opens a stream through each tunnel's machine to its app, as a
//! visitor's request does, and has a short exchange: an HTTP request for the tunnel's check path
//! (any answer counts), SSH's banner, VNC's greeting, RDP's answer to a connection request. Other
//! ports count once the machine has connected. A tunnel whose machine is offline isn't checked:
//! that has its own alert. Two failures in a row open an alert (`control/alerts.rs`).
//!
//! The checks run on the control threads, a bounded number at once, each on a control stream
//! (`MuxHandle::open`) with a timeout, so they never take from a tunnel's data streams. Results
//! are kept in memory, the last one per tunnel.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use magicpipes_core::mux::MuxHandle;
use magicpipes_core::proto::{self, Kind, ServerOpen, StreamStatus, UnreachableReason};
use magicpipes_core::unix_now;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use super::ControlPlane;

/// Checks under way at once.
const AT_ONCE: usize = 16;
/// How long one may take, all of it.
const CHECK_TIMEOUT: Duration = Duration::from_secs(10);
/// The most read from an app before its answer has to make sense.
const MAX_ANSWER: usize = 1024;

/// An RDP connection request asking for TLS or CredSSP: TPKT, X.224 Connection Request, RDP
/// negotiation request.
const RDP_REQUEST: [u8; 19] = [3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Passed,
    Failed,
    /// Its machine was offline.
    Skipped,
}

/// A tunnel's last check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub at: i64,
    pub outcome: Outcome,
    pub took_ms: u64,
    /// What the app answered, or what went wrong.
    pub said: String,
    /// Failures in a row, this one included.
    pub failures: u32,
}

#[derive(Debug, Default)]
pub struct Checks {
    last: HashMap<String, CheckResult>,
}

impl Checks {
    pub fn get(&self, tunnel_id: &str) -> Option<&CheckResult> {
        self.last.get(tunnel_id)
    }

    /// Keeps a round's results; tunnels not in `present` are forgotten.
    fn record(&mut self, results: Vec<(String, Outcome, u64, String)>, at: i64, present: impl Fn(&str) -> bool) {
        for (id, outcome, took_ms, said) in results {
            let before = self.last.get(&id).map_or(0, |r| r.failures);
            let failures = match outcome {
                Outcome::Failed => before.saturating_add(1),
                // Not checked: whatever happened before doesn't count against it now.
                Outcome::Passed | Outcome::Skipped => 0,
            };
            self.last.insert(id, CheckResult { at, outcome, took_ms, said, failures });
        }
        self.last.retain(|id, _| present(id));
    }
}

/// A tunnel to check, and how.
struct Target {
    tunnel_id: String,
    kind: Kind,
    hostname: String,
    path: String,
    /// `None`: its machine is offline.
    handle: Option<MuxHandle>,
}

impl ControlPlane {
    /// Checks every tunnel that has them on, every `check_interval_secs`, unless
    /// `[monitoring] synthetics` is off.
    pub(super) fn start_checks(self: &Arc<Self>, shutdown: CancellationToken) {
        if !self.cfg.monitoring.synthetics {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(Duration::from_secs(me.cfg.monitoring.check_interval_secs));
            every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = every.tick() => me.check_all().await,
                }
            }
        });
    }

    async fn check_all(&self) {
        let targets: Vec<Target> = {
            let st = self.state.lock().unwrap();
            st.tunnels
                .values()
                .filter(|t| t.row.checks)
                .map(|t| Target {
                    tunnel_id: t.row.id.clone(),
                    kind: t.row.kind,
                    hostname: t.row.hostname.clone(),
                    path: t.row.check_path.clone(),
                    handle: st.sessions.get(&t.row.agent_id).and_then(|l| l.handle()),
                })
                .collect()
        };
        let results: Vec<(String, Outcome, u64, String)> = futures_util::stream::iter(targets)
            .map(|t| async move {
                let Some(handle) = t.handle.clone() else {
                    return (t.tunnel_id, Outcome::Skipped, 0, "Its machine is offline.".to_string());
                };
                let started = Instant::now();
                let answer = tokio::time::timeout(CHECK_TIMEOUT, check(&handle, &t)).await.unwrap_or_else(|_| {
                    Err(format!("No answer within {} seconds.", CHECK_TIMEOUT.as_secs()))
                });
                let took = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                match answer {
                    Ok(said) => (t.tunnel_id, Outcome::Passed, took, said),
                    Err(why) => (t.tunnel_id, Outcome::Failed, took, why),
                }
            })
            .buffer_unordered(AT_ONCE)
            .collect()
            .await;
        let present: std::collections::HashSet<String> = self.state.lock().unwrap().tunnels.keys().cloned().collect();
        self.checks.lock().unwrap().record(results, unix_now(), |id| present.contains(id));
    }

    /// A tunnel's last check, if it has had one.
    pub fn check_result(&self, tunnel_id: &str) -> Option<CheckResult> {
        self.checks.lock().unwrap().get(tunnel_id).cloned()
    }

    /// Whether this server checks tunnels at all.
    pub fn checks_on(&self) -> bool {
        self.cfg.monitoring.synthetics
    }
}

/// One check: a stream to the app through its machine, then a short exchange by kind. What the
/// app said, or why it failed, as a sentence.
async fn check(handle: &MuxHandle, t: &Target) -> Result<String, String> {
    let mut s = handle.open(CHECK_TIMEOUT).await.map_err(|_| "Couldn't open a stream to its machine.".to_string())?;
    let header = match t.kind {
        Kind::Udp => ServerOpen::Datagram { tunnel_id: t.tunnel_id.clone(), peer: None },
        _ => ServerOpen::Data { tunnel_id: t.tunnel_id.clone(), peer: None },
    };
    proto::write_frame(&mut s, &header).await.map_err(|_| "Its machine closed the stream.".to_string())?;
    match s.read_u8().await.ok().and_then(StreamStatus::from_byte) {
        Some(StreamStatus::Ok) => {}
        Some(StreamStatus::LocalUnreachable) => {
            return Err(match proto::read_unreachable(&mut s).await {
                Some(why) => format!("Couldn't reach the app: {}.", reason_words(&why)),
                None => "The app isn't accepting connections.".into(),
            });
        }
        Some(StreamStatus::UnknownTunnel) => return Err("Its machine doesn't serve this tunnel.".into()),
        Some(StreamStatus::Unsupported) => return Err("Its machine's agent is too old to be checked.".into()),
        None => return Err("Its machine didn't answer.".into()),
    }
    let said = match t.kind {
        Kind::Http => {
            let request = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: MagicPipes-Check\r\nX-Magicpipes-Probe: check\r\nX-Forwarded-Proto: https\r\nAccept: */*\r\nConnection: close\r\n\r\n",
                t.path, t.hostname
            );
            s.write_all(request.as_bytes()).await.map_err(|_| "The app closed the connection.".to_string())?;
            let line = first_line(&mut s).await?;
            let status = line.strip_prefix("HTTP/1.").and_then(|r| r.get(2..5)).filter(|c| c.bytes().all(|b| b.is_ascii_digit()));
            match status {
                Some(code) => format!("HTTP {code} for {}", t.path),
                None => return Err("The app didn't answer in HTTP.".into()),
            }
        }
        Kind::Ssh => {
            let line = first_line(&mut s).await?;
            if !line.starts_with("SSH-") {
                return Err("The app didn't answer like an SSH server.".into());
            }
            line
        }
        Kind::Vnc => {
            let mut greeting = [0u8; 12];
            s.read_exact(&mut greeting).await.map_err(|_| "The app closed the connection without a VNC greeting.".to_string())?;
            if !greeting.starts_with(b"RFB ") {
                return Err("The app didn't answer like a VNC server.".into());
            }
            printable(&greeting)
        }
        Kind::Rdp => {
            s.write_all(&RDP_REQUEST).await.map_err(|_| "The app closed the connection.".to_string())?;
            let mut tpkt = [0u8; 4];
            s.read_exact(&mut tpkt).await.map_err(|_| "The app closed the connection without an RDP answer.".to_string())?;
            if tpkt[..2] != [3, 0] {
                return Err("The app didn't answer like an RDP server.".into());
            }
            "Answered an RDP connection request".into()
        }
        Kind::Tcp | Kind::Udp => "Its machine reached the app".into(),
    };
    let _ = s.shutdown().await;
    Ok(said)
}

/// Why an agent couldn't reach an app, for its owner: what it saw, or the kind of failure if it
/// said nothing more. An agent is trusted with no more than its own text: kept short and plain.
pub(super) fn reason_words(why: &proto::Unreachable) -> String {
    let detail = printable(why.detail.as_bytes());
    if !detail.is_empty() {
        return detail;
    }
    match why.reason {
        UnreachableReason::Refused => "the connection was refused",
        UnreachableReason::TimedOut => "it didn't accept a connection in time",
        UnreachableReason::NotFound => "there's nothing at its address",
        UnreachableReason::Permission => "the agent's user may not connect to it",
        UnreachableReason::CertificateChanged => "it showed a certificate other than the one kept",
        UnreachableReason::Tls => "TLS with it failed",
        UnreachableReason::Other => "something went wrong",
    }
    .to_string()
}

/// The app's first line, at most [`MAX_ANSWER`] bytes in.
async fn first_line<R: AsyncRead + Unpin>(r: &mut R) -> Result<String, String> {
    let mut got = Vec::with_capacity(128);
    let mut buf = [0u8; 256];
    loop {
        if let Some(end) = got.iter().position(|b| *b == b'\n') {
            return Ok(printable(&got[..end]));
        }
        if got.len() >= MAX_ANSWER {
            return Err("The app's answer made no sense.".into());
        }
        match r.read(&mut buf).await {
            Ok(0) | Err(_) if got.is_empty() => return Err("The app closed the connection without answering.".into()),
            Ok(0) | Err(_) => return Ok(printable(&got)),
            Ok(n) => got.extend_from_slice(&buf[..n]),
        }
    }
}

/// What an app or agent said, safe to show: printable ASCII, trimmed and short.
fn printable(bytes: &[u8]) -> String {
    let s: String = bytes.iter().map(|b| if b.is_ascii_graphic() || *b == b' ' { *b as char } else { ' ' }).collect();
    s.trim().chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use magicpipes_core::mux::{self, Mode};

    use super::*;

    /// A machine that answers a check stream with `status`, then plays `app` (or, for an app it
    /// couldn't reach, says why).
    async fn machine(status: StreamStatus, app: impl Fn(Vec<u8>) -> Vec<u8> + Send + 'static) -> MuxHandle {
        let (a, b) = tokio::io::duplex(1 << 16);
        let (server, _rpcs) = mux::spawn(a, Mode::Server);
        let (_agent, mut inbound) = mux::spawn(b, Mode::Client);
        tokio::spawn(async move {
            let _agent = _agent;
            while let Some(mut s) = inbound.recv().await {
                let _: ServerOpen = proto::read_frame(&mut s).await.unwrap();
                s.write_all(&[status.byte()]).await.unwrap();
                let mut asked = vec![0u8; 512];
                let n = tokio::time::timeout(Duration::from_millis(200), s.read(&mut asked)).await.ok().and_then(Result::ok).unwrap_or(0);
                asked.truncate(n);
                let _ = s.write_all(&app(asked)).await;
                let _ = s.shutdown().await;
            }
        });
        server
    }

    fn target(kind: Kind) -> Target {
        Target { tunnel_id: "tn".into(), kind, hostname: "web.t.test".into(), path: "/health".into(), handle: None }
    }

    #[tokio::test]
    async fn each_kind_has_its_exchange() {
        let http = machine(StreamStatus::Ok, |asked| {
            let asked = String::from_utf8(asked).unwrap();
            assert!(asked.starts_with("GET /health HTTP/1.1\r\nHost: web.t.test\r\n") && asked.contains("X-Magicpipes-Probe: check"), "{asked}");
            b"HTTP/1.1 401 Unauthorized\r\n\r\n".to_vec()
        })
        .await;
        assert_eq!(check(&http, &target(Kind::Http)).await, Ok("HTTP 401 for /health".into()), "any answer counts");

        let ssh = machine(StreamStatus::Ok, |_| b"SSH-2.0-OpenSSH_9.6\r\n".to_vec()).await;
        assert_eq!(check(&ssh, &target(Kind::Ssh)).await, Ok("SSH-2.0-OpenSSH_9.6".into()));
        let not_ssh = machine(StreamStatus::Ok, |_| b"220 smtp ready\r\n".to_vec()).await;
        assert!(check(&not_ssh, &target(Kind::Ssh)).await.unwrap_err().contains("SSH"));

        let vnc = machine(StreamStatus::Ok, |_| b"RFB 003.008\n".to_vec()).await;
        assert_eq!(check(&vnc, &target(Kind::Vnc)).await, Ok("RFB 003.008".into()));

        let rdp = machine(StreamStatus::Ok, |asked| {
            assert_eq!(asked, RDP_REQUEST);
            vec![3, 0, 0, 19, 14, 0xd0, 0, 0, 0, 0, 0, 2, 0, 8, 0, 1, 0, 0, 0]
        })
        .await;
        assert_eq!(check(&rdp, &target(Kind::Rdp)).await, Ok("Answered an RDP connection request".into()));

        let port = machine(StreamStatus::Ok, |_| Vec::new()).await;
        assert!(check(&port, &target(Kind::Tcp)).await.is_ok(), "a port counts once it's reached");
    }

    #[tokio::test]
    async fn failures_say_why() {
        let down = machine(StreamStatus::LocalUnreachable, |_| Vec::new()).await;
        assert_eq!(check(&down, &target(Kind::Http)).await, Err("The app isn't accepting connections.".into()), "an agent from before reasons");
        let said = |why: serde_json::Value| move |_: Vec<u8>| {
            let body = serde_json::to_vec(&why).unwrap();
            [(body.len() as u32).to_be_bytes().to_vec(), body].concat()
        };
        let refused = machine(StreamStatus::LocalUnreachable, said(serde_json::json!({ "reason": "refused", "detail": "connection refused by 127.0.0.1:8080" }))).await;
        assert_eq!(check(&refused, &target(Kind::Http)).await, Err("Couldn't reach the app: connection refused by 127.0.0.1:8080.".into()));
        let terse = machine(StreamStatus::LocalUnreachable, said(serde_json::json!({ "reason": "permission", "detail": "\u{1b}[31m" }))).await;
        assert_eq!(check(&terse, &target(Kind::Ssh)).await, Err("Couldn't reach the app: [31m.".into()), "an agent's text is kept plain");
        let silent = machine(StreamStatus::Ok, |_| Vec::new()).await;
        assert_eq!(check(&silent, &target(Kind::Http)).await, Err("The app closed the connection without answering.".into()));
        let garbage = machine(StreamStatus::Ok, |_| b"\x00\x01 hello\n".to_vec()).await;
        assert_eq!(check(&garbage, &target(Kind::Http)).await, Err("The app didn't answer in HTTP.".into()));
        let rambling = machine(StreamStatus::Ok, |_| vec![b'x'; 4096]).await;
        assert_eq!(check(&rambling, &target(Kind::Ssh)).await, Err("The app's answer made no sense.".into()));
    }

    #[test]
    fn failures_in_a_row_are_counted_and_gone_tunnels_forgotten() {
        let mut c = Checks::default();
        let round = |o| vec![("a".to_string(), o, 5, "x".to_string())];
        c.record(round(Outcome::Failed), 1, |_| true);
        c.record(round(Outcome::Failed), 2, |_| true);
        assert_eq!(c.get("a").map(|r| r.failures), Some(2));
        c.record(round(Outcome::Skipped), 3, |_| true);
        assert_eq!(c.get("a").map(|r| (r.outcome, r.failures)), Some((Outcome::Skipped, 0)), "an offline machine starts over");
        c.record(round(Outcome::Failed), 4, |_| true);
        c.record(round(Outcome::Passed), 5, |_| true);
        assert_eq!(c.get("a").map(|r| r.failures), Some(0));
        c.record(vec![], 6, |_| false);
        assert!(c.get("a").is_none());
    }
}
