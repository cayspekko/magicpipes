//! Agent data path: serves server-opened streams by piping them to local targets (a TCP or Unix
//! socket connection, TLS to an app that only speaks HTTPS, the built-in file server or web
//! terminal, or a UDP socket for datagram streams).

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use magicpipes_core::mux::{COPY_BUFFER, MuxStream};
use magicpipes_core::proto::{self, Kind, ServerOpen, StreamStatus};
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
/// slow or failing local application never blocks other tunnels.
pub async fn serve(mut inbound: mpsc::Receiver<MuxStream>, tunnels: Arc<Tunnels>) {
    while let Some(stream) = inbound.recv().await {
        let tunnels = tunnels.clone();
        tokio::spawn(async move { handle(stream, tunnels).await });
    }
}

async fn handle(mut stream: MuxStream, tunnels: Arc<Tunnels>) {
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
        ServerOpen::TunnelRemoved { tunnel_id } => {
            if let Some(t) = tunnels.remove(&tunnel_id) {
                tracing::warn!(tunnel = %t.name, "tunnel was deleted on the server; no longer serving it");
            }
        }
        ServerOpen::Datagram { tunnel_id, peer } => match tunnels.route(&tunnel_id) {
            Some(Route { kind: Kind::Udp, target: Target::Port { host, port, .. }, streams_ok, .. }) => {
                tracing::debug!(%host, port, peer = peer.as_deref().unwrap_or("-"), "UDP client");
                udp::relay(stream, &host, port, &streams_ok).await;
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
                    let Some(local) = connect_local(&mut stream, connecting, log).await else { return };
                    if let Some(peer) = peer {
                        tracing::debug!(%host, port, %peer, "HTTPS client");
                    }
                    pipe(stream, local, kind, counter, ended).await;
                }
                Target::Port { host, port, https: None } => {
                    let connecting = TcpStream::connect((host.as_str(), port));
                    let Some(local) = connect_local(&mut stream, connecting, |e| tracing::debug!(%host, port, error = %e, "local target unreachable")).await else { return };
                    let _ = local.set_nodelay(true);
                    if let Some(peer) = peer {
                        tracing::debug!(%host, port, %peer, "TCP client");
                    }
                    pipe(stream, local, kind, counter, ended).await;
                }
                Target::Unix { unix } => {
                    let connecting = platform::unix_connect(&unix);
                    let Some(local) = connect_local(&mut stream, connecting, |e| tracing::debug!(socket = %unix.display(), error = %e, "local target unreachable")).await else { return };
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

/// Connects to a local target within the time limit. `None`: the stream has been told it couldn't.
async fn connect_local<T>(stream: &mut MuxStream, connecting: impl Future<Output = std::io::Result<T>>, log: impl FnOnce(&std::io::Error)) -> Option<T> {
    match tokio::time::timeout(LOCAL_CONNECT_TIMEOUT, connecting).await {
        Ok(Ok(local)) => Some(local),
        failed => {
            if let Ok(Err(e)) = &failed {
                log(e);
            }
            let _ = StreamStatus::LocalUnreachable.write(stream).await;
            let _ = stream.shutdown().await;
            None
        }
    }
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
        tokio::spawn(serve(inbound, Arc::new(Tunnels::default())));
        let mut s = server.open(Duration::from_secs(5)).await.unwrap();
        proto::write_frame(&mut s, &header).await.unwrap();
        s.read_u8().await.unwrap()
    }

    #[tokio::test]
    async fn unknown_streams_are_answered() {
        // A newer server's stream type gets an answer instead of a timeout.
        assert_eq!(status_for(json!({ "kind": "from_the_future" })).await, StreamStatus::Unsupported.byte());
        assert_eq!(status_for(json!({ "kind": "data", "tunnel_id": "tn_unknown" })).await, StreamStatus::UnknownTunnel.byte());
    }
}
