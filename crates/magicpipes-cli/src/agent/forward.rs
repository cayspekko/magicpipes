//! Agent data path: serves server-opened streams by piping them to local targets.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use magicpipes_core::mux::MuxStream;
use magicpipes_core::proto::{self, STREAM_LOCAL_UNREACHABLE, STREAM_OK, STREAM_UNKNOWN_TUNNEL, ServerOpen};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::tunnels::Tunnels;

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
        ServerOpen::Data { tunnel_id } => {
            let Some((host, port, counter)) = tunnels.target(&tunnel_id) else {
                let _ = stream.write_all(&[STREAM_UNKNOWN_TUNNEL]).await;
                let _ = stream.shutdown().await;
                return;
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
