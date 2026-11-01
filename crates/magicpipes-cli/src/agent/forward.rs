//! Agent data path: serves server-opened streams by piping them to local targets (a TCP
//! connection, the built-in file server or web terminal, or a UDP socket for datagram streams).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use magicpipes_core::mux::MuxStream;
use magicpipes_core::proto::{self, Kind, ServerOpen, StreamStatus};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::serve::{self, Site};
use super::shell::{self, Terminal};
use super::tunnels::{Route, Tunnels};
use super::udp;
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
            Some(Route { kind: Kind::Udp, target: Target::Port { host, port }, streams_ok, .. }) => {
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
            let Some(Route { target, streams_ok: counter, ended, sessions, .. }) = route else {
                let _ = StreamStatus::UnknownTunnel.write(&mut stream).await;
                let _ = stream.shutdown().await;
                return;
            };
            let (host, port) = match target {
                Target::Port { host, port } => (host, port),
                Target::Static { serve: root, list } => {
                    if StreamStatus::Ok.write(&mut stream).await.is_err() {
                        return;
                    }
                    counter.fetch_add(1, Ordering::Relaxed);
                    serve::serve(stream, Arc::new(Site { root, list })).await;
                    return;
                }
                Target::Shell { shell: command, cwd, writable, key, max_clients } => {
                    if StreamStatus::Ok.write(&mut stream).await.is_err() {
                        return;
                    }
                    counter.fetch_add(1, Ordering::Relaxed);
                    let key = key.filter(|_| writable);
                    shell::serve(stream, Arc::new(Terminal { command, cwd, key, max_clients, sessions, ended })).await;
                    return;
                }
            };
            let local = tokio::time::timeout(LOCAL_CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port))).await;
            let mut local = match local {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    tracing::debug!(%host, port, error = %e, "local target unreachable");
                    let _ = StreamStatus::LocalUnreachable.write(&mut stream).await;
                    let _ = stream.shutdown().await;
                    return;
                }
                Err(_) => {
                    let _ = StreamStatus::LocalUnreachable.write(&mut stream).await;
                    let _ = stream.shutdown().await;
                    return;
                }
            };
            let _ = local.set_nodelay(true);
            if let Some(peer) = peer {
                tracing::debug!(%host, port, %peer, "TCP client");
            }
            if StreamStatus::Ok.write(&mut stream).await.is_err() {
                return;
            }
            counter.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut local).await {
                tracing::debug!(error = %e, "data stream ended");
            }
        }
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
