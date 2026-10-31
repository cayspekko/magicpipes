//! Agent data path: serves server-opened streams by piping them to local targets (a TCP
//! connection, the built-in file server or web terminal, or a UDP socket for datagram streams).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use magicpipes_core::mux::MuxStream;
use magicpipes_core::proto::{self, Kind, STREAM_LOCAL_UNREACHABLE, STREAM_OK, STREAM_UNKNOWN_TUNNEL, ServerOpen};
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
    let open: ServerOpen = match tokio::time::timeout(HEADER_TIMEOUT, proto::read_frame(&mut stream)).await {
        Ok(Ok(o)) => o,
        _ => return,
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
                let _ = stream.write_all(&[STREAM_UNKNOWN_TUNNEL]).await;
                let _ = stream.shutdown().await;
            }
        },
        ServerOpen::Data { tunnel_id, peer } => {
            let route = tunnels.route(&tunnel_id).filter(|r| r.kind != Kind::Udp);
            let Some(Route { target, streams_ok: counter, ended, sessions, .. }) = route else {
                let _ = stream.write_all(&[STREAM_UNKNOWN_TUNNEL]).await;
                let _ = stream.shutdown().await;
                return;
            };
            let (host, port) = match target {
                Target::Port { host, port } => (host, port),
                Target::Static { serve: root, list } => {
                    if stream.write_all(&[STREAM_OK]).await.is_err() {
                        return;
                    }
                    counter.fetch_add(1, Ordering::Relaxed);
                    serve::serve(stream, Arc::new(Site { root, list })).await;
                    return;
                }
                Target::Shell { shell: command, cwd, writable, key, max_clients } => {
                    if stream.write_all(&[STREAM_OK]).await.is_err() {
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
                    let _ = stream.write_all(&[STREAM_LOCAL_UNREACHABLE]).await;
                    let _ = stream.shutdown().await;
                    return;
                }
                Err(_) => {
                    let _ = stream.write_all(&[STREAM_LOCAL_UNREACHABLE]).await;
                    let _ = stream.shutdown().await;
                    return;
                }
            };
            let _ = local.set_nodelay(true);
            if let Some(peer) = peer {
                tracing::debug!(%host, port, %peer, "TCP client");
            }
            if stream.write_all(&[STREAM_OK]).await.is_err() {
                return;
            }
            counter.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut local).await {
                tracing::debug!(error = %e, "data stream ended");
            }
        }
    }
}
