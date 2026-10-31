//! UDP tunnels on the agent side: each datagram stream is one public client, relayed through a
//! connected UDP socket of its own, so the local service's replies go back to that client.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

use magicpipes_core::mux::MuxStream;
use magicpipes_core::proto::{self, STREAM_LOCAL_UNREACHABLE, STREAM_OK};
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;

pub async fn relay(mut stream: MuxStream, host: &str, port: u16, streams_ok: &AtomicU64) {
    let socket = match connect(host, port).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(%host, port, error = %e, "local UDP target unusable");
            let _ = stream.write_all(&[STREAM_LOCAL_UNREACHABLE]).await;
            let _ = stream.shutdown().await;
            return;
        }
    };
    if stream.write_all(&[STREAM_OK]).await.is_err() {
        return;
    }
    streams_ok.fetch_add(1, Ordering::Relaxed);
    let (mut rd, mut wr) = tokio::io::split(stream);
    // The server ends the stream when the client goes quiet, which ends both directions here.
    let to_local = async {
        let mut buf = Vec::new();
        while let Ok(true) = proto::read_datagram(&mut rd, &mut buf).await {
            // Nothing listening (yet) is not fatal for UDP: the datagram is simply lost.
            let _ = socket.send(&buf).await;
        }
    };
    let from_local = async {
        let mut buf = vec![0u8; proto::MAX_DATAGRAM];
        loop {
            match socket.recv(&mut buf).await {
                Ok(n) => {
                    if proto::write_datagram(&mut wr, &buf[..n]).await.is_err() {
                        break;
                    }
                }
                // An ICMP "port unreachable" for an earlier datagram.
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused || e.kind() == io::ErrorKind::ConnectionReset => {}
                Err(_) => break,
            }
        }
    };
    tokio::select! {
        _ = to_local => {}
        _ = from_local => {}
    }
}

async fn connect(host: &str, port: u16) -> io::Result<UdpSocket> {
    let addr = tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "host has no address"))?;
    let socket = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?;
    socket.connect(addr).await?;
    Ok(socket)
}
