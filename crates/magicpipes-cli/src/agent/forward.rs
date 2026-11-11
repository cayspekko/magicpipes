//! Agent data path: serves server-opened streams by piping them to local targets (a TCP or Unix
//! socket connection, TLS to an app that only speaks HTTPS, the built-in file server or web
//! terminal, or a UDP socket for datagram streams).

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use magicpipes_core::mux::{COPY_BUFFER, MuxStream};
use magicpipes_core::proto::{self, Kind, REASONS_PROTOCOL, ServerOpen, StreamStatus, Unreachable, UnreachableReason};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::local_tls;
use super::serve::{self, Site};
use super::shell::{self, Terminal};
use super::tunnels::{Route, Tunnels};
use super::udp;
use crate::platform;
use crate::state::Target;

const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const LOCAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Accepts inbound streams until the session ends. Each stream runs on its own task, so one
/// slow or failing local application never blocks other tunnels. `server_protocol`: the
/// server's, which decides whether it's told why an app couldn't be reached.
pub async fn serve(mut inbound: mpsc::Receiver<MuxStream>, tunnels: Arc<Tunnels>, server_protocol: u32) {
    let reasons = server_protocol >= REASONS_PROTOCOL;
    while let Some(stream) = inbound.recv().await {
        let tunnels = tunnels.clone();
        tokio::spawn(async move { handle(stream, tunnels, reasons).await });
    }
}

async fn handle(mut stream: MuxStream, tunnels: Arc<Tunnels>, reasons: bool) {
    let open = match tokio::time::timeout(HEADER_TIMEOUT, proto::read_frame_bytes(&mut stream)).await {
        Ok(Ok(body)) => serde_json::from_slice::<ServerOpen>(&body),
        _ => return,
    };
    let open = match open {
        Ok(o) => o,
        Err(e) => {
            // A newer server's stream type: say so, rather than leaving the server to time out.
            tracing::debug!(error = %e, "unsupported server-opened stream");
            let _ = StreamStatus::Unsupported.write(&mut stream).await;
            let _ = stream.shutdown().await;
            return;
        }
    };
    match open {
        ServerOpen::Ping => {
            let _ = StreamStatus::Ok.write(&mut stream).await;
            let _ = stream.shutdown().await;
        }
        ServerOpen::TunnelRemoved { tunnel_id } => {
            if let Some(t) = tunnels.remove(&tunnel_id) {
                tracing::warn!(tunnel = %t.name, "tunnel was deleted on the server; no longer serving it");
            }
        }
        ServerOpen::Datagram { tunnel_id, peer } => match tunnels.route(&tunnel_id) {
            Some(Route { kind: Kind::Udp, target: Target::Port { host, port, .. }, streams_ok, .. }) => {
                tracing::debug!(%host, port, peer = peer.as_deref().unwrap_or("-"), "UDP client");
                udp::relay(stream, &host, port, &streams_ok, reasons).await;
            }
            _ => {
                let _ = StreamStatus::UnknownTunnel.write(&mut stream).await;
                let _ = stream.shutdown().await;
            }
        },
        ServerOpen::Data { tunnel_id, peer } => {
            let route = tunnels.route(&tunnel_id).filter(|r| r.kind != Kind::Udp);
            let Some(Route { kind, target, streams_ok: counter, ended, sessions, spawns }) = route else {
                let _ = StreamStatus::UnknownTunnel.write(&mut stream).await;
                let _ = stream.shutdown().await;
                return;
            };
            match target {
                Target::Port { host, port, https: Some(pin) } => {
                    let connecting = local_tls::connect(&host, port, &pin);
                    let log = |e: &std::io::Error| {
                        if local_tls::is_other_certificate(e) {
                            tracing::warn!(%host, port, "the app showed a certificate other than the one kept; if it has a new one, run the same magicpipes add again");
                        } else {
                            tracing::debug!(%host, port, error = %e, "local HTTPS app unreachable");
                        }
                    };
                    let at = || format!("https://{host}:{port}");
                    let Some(local) = connect_local(&mut stream, connecting, at, reasons, log).await else { return };
                    if let Some(peer) = peer {
                        tracing::debug!(%host, port, %peer, "HTTPS client");
                    }
                    pipe(stream, local, kind, counter, ended).await;
                }
                Target::Port { host, port, https: None } => {
                    let connecting = TcpStream::connect((host.as_str(), port));
                    let at = || format!("{host}:{port}");
                    let Some(local) = connect_local(&mut stream, connecting, at, reasons, |e| tracing::debug!(%host, port, error = %e, "local target unreachable")).await else { return };
                    let _ = local.set_nodelay(true);
                    if let Some(peer) = peer {
                        tracing::debug!(%host, port, %peer, "TCP client");
                    }
                    pipe(stream, local, kind, counter, ended).await;
                }
                Target::Unix { unix } => {
                    let connecting = platform::unix_connect(&unix);
                    let at = || unix.display().to_string();
                    let Some(local) = connect_local(&mut stream, connecting, at, reasons, |e| tracing::debug!(socket = %unix.display(), error = %e, "local target unreachable")).await else { return };
                    if let Some(peer) = peer {
                        tracing::debug!(socket = %unix.display(), %peer, "client");
                    }
                    pipe(stream, local, kind, counter, ended).await;
                }
                Target::Static { serve: root, list, site } => {
                    if StreamStatus::Ok.write(&mut stream).await.is_err() {
                        return;
                    }
                    counter.fetch_add(1, Ordering::Relaxed);
                    // The server keeps HTTP connections for later requests: end this one when the
                    // tunnel's settings change, so it never serves the old ones.
                    tokio::select! {
                        _ = serve::serve(stream, Arc::new(Site { root, list, scripts: site })) => {}
                        _ = ended.cancelled() => {}
                    }
                }
                Target::Shell { shell: command, cwd, writable, key, max_clients } => {
                    if StreamStatus::Ok.write(&mut stream).await.is_err() {
                        return;
                    }
                    counter.fetch_add(1, Ordering::Relaxed);
                    let key = key.filter(|_| writable);
                    shell::serve(stream, Arc::new(Terminal { command, cwd, key, max_clients, sessions, spawns, ended })).await;
                }
            }
        }
    }
}

/// Connects to a local target within the time limit. `None`: the stream has been told it
/// couldn't, and why when the server reads that (`reasons`), naming the target as `at` shows it
/// (made only then: a connection that works costs nothing more).
async fn connect_local<T>(
    stream: &mut MuxStream,
    connecting: impl Future<Output = std::io::Result<T>>,
    at: impl FnOnce() -> String,
    reasons: bool,
    log: impl FnOnce(&std::io::Error),
) -> Option<T> {
    let why = match tokio::time::timeout(LOCAL_CONNECT_TIMEOUT, connecting).await {
        Ok(Ok(local)) => return Some(local),
        Ok(Err(e)) => {
            log(&e);
            unreachable(&e, &at())
        }
        Err(_) => Unreachable {
            reason: UnreachableReason::TimedOut,
            detail: format!("{} didn't accept a connection within {} seconds", at(), LOCAL_CONNECT_TIMEOUT.as_secs()),
        },
    };
    tell_unreachable(stream, reasons, &why).await;
    None
}

/// Tells the server an app couldn't be reached, and why if it reads that.
pub(super) async fn tell_unreachable(stream: &mut MuxStream, reasons: bool, why: &Unreachable) {
    if StreamStatus::LocalUnreachable.write(stream).await.is_ok() && reasons {
        let _ = proto::write_frame(stream, why).await;
    }
    let _ = stream.shutdown().await;
}

/// Why connecting to `at` failed, for the tunnel's owner.
pub(super) fn unreachable(e: &std::io::Error, at: &str) -> Unreachable {
    use std::io::ErrorKind;
    let (reason, detail) = if local_tls::is_other_certificate(e) {
        (UnreachableReason::CertificateChanged, format!("{at} showed a certificate other than the one kept; if it has a new one, run the same magicpipes add again"))
    } else {
        match e.kind() {
            ErrorKind::ConnectionRefused => (UnreachableReason::Refused, format!("connection refused by {at}")),
            ErrorKind::NotFound => (UnreachableReason::NotFound, format!("nothing at {at}")),
            ErrorKind::PermissionDenied => (UnreachableReason::Permission, format!("this agent's user may not connect to {at}")),
            ErrorKind::TimedOut => (UnreachableReason::TimedOut, format!("{at} didn't accept a connection in time")),
            ErrorKind::InvalidData if at.starts_with("https://") => (UnreachableReason::Tls, format!("TLS with {at} failed: {e}")),
            _ => (UnreachableReason::Other, format!("{at}: {e}")),
        }
    };
    Unreachable { reason, detail }
}

/// Carries a data stream to and from a connection to its local target.
async fn pipe<L>(mut stream: MuxStream, mut local: L, kind: Kind, counter: Arc<AtomicU64>, ended: CancellationToken)
where
    L: AsyncRead + AsyncWrite + Unpin,
{
    if StreamStatus::Ok.write(&mut stream).await.is_err() {
        return;
    }
    counter.fetch_add(1, Ordering::Relaxed);
    // As for static files: a pooled HTTP connection must not outlive a target change.
    // Raw TCP connections keep going, as they always have.
    let changed = async {
        if kind.is_http() { ended.cancelled().await } else { std::future::pending().await }
    };
    tokio::select! {
        r = tokio::io::copy_bidirectional_with_sizes(&mut stream, &mut local, COPY_BUFFER, COPY_BUFFER) => {
            if let Err(e) = r {
                tracing::debug!(error = %e, "data stream ended");
            }
        }
        _ = changed => {}
    }
}

#[cfg(test)]
mod tests {
    use magicpipes_core::mux::{self, Mode};
    use serde_json::json;
    use tokio::io::AsyncReadExt;

    use super::*;

    /// The status byte the agent answers a server-opened stream with.
    async fn status_for(header: serde_json::Value) -> u8 {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (server, _rpcs) = mux::spawn(a, Mode::Server);
        let (_agent, inbound) = mux::spawn(b, Mode::Client);
        tokio::spawn(serve(inbound, Arc::new(Tunnels::default()), proto::PROTOCOL_VERSION));
        let mut s = server.open(Duration::from_secs(5)).await.unwrap();
        proto::write_frame(&mut s, &header).await.unwrap();
        s.read_u8().await.unwrap()
    }

    /// What a server at `protocol` hears when the tunnel's app refuses the connection.
    async fn refused_as_heard_by(protocol: u32) -> (u8, Option<proto::Unreachable>) {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let tunnels = Arc::new(Tunnels::default());
        let json = format!(r#"{{"id":"tn_1","name":"a","hostname":"a.t.test","public_url":"https://a.t.test","host":"127.0.0.1","port":{closed},"created_at":1}}"#);
        tunnels.upsert(serde_json::from_str(&json).unwrap(), super::super::tunnels::Registration::Registered);
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (server, _rpcs) = mux::spawn(a, Mode::Server);
        let (_agent, inbound) = mux::spawn(b, Mode::Client);
        tokio::spawn(serve(inbound, tunnels, protocol));
        let mut s = server.open(Duration::from_secs(5)).await.unwrap();
        proto::write_frame(&mut s, &json!({ "kind": "data", "tunnel_id": "tn_1" })).await.unwrap();
        let status = s.read_u8().await.unwrap();
        (status, proto::read_unreachable(&mut s).await)
    }

    #[tokio::test]
    async fn the_server_hears_why_an_app_couldnt_be_reached() {
        let (status, why) = refused_as_heard_by(proto::REASONS_PROTOCOL).await;
        assert_eq!(status, StreamStatus::LocalUnreachable.byte());
        let why = why.expect("a reason");
        assert!(why.reason == UnreachableReason::Refused && why.detail.starts_with("connection refused by 127.0.0.1:"), "{why:?}");
        // An older server reads only the status byte: it's sent nothing else.
        assert_eq!(refused_as_heard_by(proto::REASONS_PROTOCOL - 1).await, (StreamStatus::LocalUnreachable.byte(), None));
    }

    #[test]
    fn reasons_come_from_the_error() {
        use std::io::{Error, ErrorKind};
        let why = |kind| unreachable(&Error::from(kind), "/run/app.sock").reason;
        assert_eq!(why(ErrorKind::NotFound), UnreachableReason::NotFound);
        assert_eq!(why(ErrorKind::PermissionDenied), UnreachableReason::Permission);
        assert_eq!(why(ErrorKind::TimedOut), UnreachableReason::TimedOut);
        assert_eq!(why(ErrorKind::InvalidData), UnreachableReason::Other, "TLS only for an HTTPS app");
        assert_eq!(unreachable(&Error::from(ErrorKind::InvalidData), "https://127.0.0.1:8006").reason, UnreachableReason::Tls);
    }

    #[tokio::test]
    async fn unknown_streams_are_answered() {
        // A newer server's stream type gets an answer instead of a timeout.
        assert_eq!(status_for(json!({ "kind": "from_the_future" })).await, StreamStatus::Unsupported.byte());
        assert_eq!(status_for(json!({ "kind": "data", "tunnel_id": "tn_unknown" })).await, StreamStatus::UnknownTunnel.byte());
        assert_eq!(status_for(json!({ "kind": "ping" })).await, StreamStatus::Ok.byte(), "the server times the round trip");
    }
}
