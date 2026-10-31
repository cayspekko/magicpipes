//! Port tunnels: a TCP listener or UDP socket per allocated public port.
//!
//! Each accepted TCP connection becomes one [`ServerOpen::Data`] stream to the owning agent,
//! piped byte for byte once the agent reports [`STREAM_OK`]. UDP has no connections, so each
//! client address (a "flow") gets one [`ServerOpen::Datagram`] stream carrying its datagrams in
//! both directions; a flow ends after `udp_idle_timeout` without traffic.
//!
//! Routes are looked up per connection or flow, so an agent reconnecting or a tunnel changing
//! its allow-list takes effect immediately. A port stays open while its agent is offline (so no
//! other program can take it); connections then close at once and datagrams are dropped.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use magicpipes_core::cidr;
use magicpipes_core::mux::{MuxHandle, MuxStream};
use magicpipes_core::proto::{self, Kind, STREAM_LOCAL_UNREACHABLE, STREAM_OK, ServerOpen};
use socket2::{SockRef, TcpKeepalive};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::{DataPlane, Outcome, Route};
use crate::forwarded::client_key;
use crate::proxy_header;
use crate::config::PortsConfig;

#[derive(Debug, Clone)]
pub struct PortSettings {
    pub bind: IpAddr,
    pub proxy_protocol: bool,
    pub max_connections: usize,
    pub udp_idle_timeout: Duration,
    pub udp_max_flows: usize,
}

impl PortSettings {
    pub fn from_config(cfg: &PortsConfig) -> Self {
        Self {
            bind: cfg.bind,
            proxy_protocol: cfg.proxy_protocol,
            max_connections: cfg.max_connections.max(1),
            udp_idle_timeout: Duration::from_secs(cfg.udp_idle_timeout_secs.max(1)),
            udp_max_flows: cfg.udp_max_flows.max(1),
        }
    }
}

/// Queued datagrams per UDP flow while its stream is opening or busy; more are dropped.
const FLOW_QUEUE: usize = 64;

/// Binds `port` and serves it until `stop` is cancelled. Binding is synchronous so the caller
/// learns at once if the port is taken.
pub(super) fn listen(dp: Arc<DataPlane>, kind: Kind, port: u16, stop: CancellationToken) -> io::Result<()> {
    let addr = SocketAddr::new(dp.settings.ports.bind, port);
    match kind {
        Kind::Tcp => {
            // std sets SO_REUSEADDR on Unix, so a restarted server can rebind at once.
            let std = std::net::TcpListener::bind(addr)?;
            std.set_nonblocking(true)?;
            let listener = TcpListener::from_std(std)?;
            tokio::spawn(serve_tcp(dp, port, listener, stop));
        }
        Kind::Udp => {
            let std = std::net::UdpSocket::bind(addr)?;
            std.set_nonblocking(true)?;
            let socket = Arc::new(UdpSocket::from_std(std)?);
            tokio::spawn(serve_udp(dp, port, socket, stop));
        }
        Kind::Http => return Err(io::Error::other("HTTP tunnels have no port of their own")),
    }
    Ok(())
}

/// The route for a new connection or flow, if the client may use it and the agent is online.
fn admit(dp: &DataPlane, kind: Kind, port: u16, peer: SocketAddr) -> Option<(Arc<Route>, MuxHandle)> {
    let route = dp.lookup_port(kind, port)?;
    if !cidr::allowed(&route.allow, peer.ip()) {
        tracing::debug!(%kind, port, %peer, "client not in the tunnel's allow-list");
        return None;
    }
    match &route.session {
        Some(s) if !s.is_closed() => {
            let session = s.clone();
            Some((route, session))
        }
        _ => {
            route.stats.record(Outcome::AgentOffline);
            None
        }
    }
}

/// Opens a data stream to the agent for `client` and waits for its status byte.
async fn open(dp: &DataPlane, route: &Route, session: &MuxHandle, client: IpAddr, header: ServerOpen) -> Option<MuxStream> {
    let timeout = dp.settings.stream_open_timeout;
    let mut stream = match session.open_data(timeout, client_key(client)).await {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
            tracing::debug!(tunnel = %route.tunnel_id, %client, "agent stream budget used up; refusing");
            return None;
        }
        Err(_) => {
            route.stats.record(Outcome::AgentOffline);
            return None;
        }
    };
    let status = async {
        proto::write_frame(&mut stream, &header).await?;
        stream.read_u8().await
    };
    match tokio::time::timeout(timeout, status).await {
        Ok(Ok(STREAM_OK)) => {
            route.stats.record(Outcome::Ok);
            Some(stream)
        }
        Ok(Ok(STREAM_LOCAL_UNREACHABLE)) => {
            route.stats.record(Outcome::LocalUnreachable);
            None
        }
        _ => {
            route.stats.record(Outcome::AgentOffline);
            None
        }
    }
}

async fn serve_tcp(dp: Arc<DataPlane>, port: u16, listener: TcpListener, stop: CancellationToken) {
    loop {
        let (tcp, peer) = tokio::select! {
            _ = stop.cancelled() => return,
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(port, error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let Ok(permit) = dp.tcp_permits.clone().try_acquire_owned() else {
            tracing::warn!(port, %peer, "too many open port connections; refusing");
            continue;
        };
        let dp = dp.clone();
        tokio::spawn(async move {
            let _permit = permit;
            tcp_connection(&dp, port, tcp, peer).await;
        });
    }
}

async fn tcp_connection(dp: &DataPlane, port: u16, mut tcp: TcpStream, mut peer: SocketAddr) {
    let _ = tcp.set_nodelay(true);
    // Notices clients that vanished without closing, which would otherwise hold a stream forever.
    let _ = SockRef::from(&tcp).set_tcp_keepalive(&TcpKeepalive::new().with_time(Duration::from_secs(60)));
    if dp.settings.ports.proxy_protocol {
        match proxy_header::client_addr(&mut tcp, peer, &dp.settings.trusted_proxies).await {
            Ok(client) => peer = client,
            Err(e) => return tracing::debug!(port, %peer, error = %e, "bad PROXY header"),
        }
    }
    let Some((route, session)) = admit(dp, Kind::Tcp, port, peer) else { return };
    let header = ServerOpen::Data { tunnel_id: route.tunnel_id.clone(), peer: Some(peer.to_string()) };
    let Some(mut stream) = open(dp, &route, &session, peer.ip(), header).await else { return };
    if let Err(e) = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await {
        tracing::debug!(port, %peer, error = %e, "port connection ended");
    }
}

async fn serve_udp(dp: Arc<DataPlane>, port: u16, socket: Arc<UdpSocket>, stop: CancellationToken) {
    let mut flows: HashMap<SocketAddr, mpsc::Sender<Bytes>> = HashMap::new();
    let mut buf = vec![0u8; proto::MAX_DATAGRAM];
    loop {
        let (n, peer) = tokio::select! {
            _ = stop.cancelled() => return,
            r = socket.recv_from(&mut buf) => match r {
                Ok(v) => v,
                // e.g. an ICMP "port unreachable" from an earlier reply (reported on Windows).
                Err(e) => {
                    tracing::debug!(port, error = %e, "UDP receive failed");
                    continue;
                }
            },
        };
        let datagram = Bytes::copy_from_slice(&buf[..n]);
        if let Some(tx) = flows.get(&peer)
            && !tx.is_closed()
        {
            // A full queue drops the datagram, as a congested network would.
            let _ = tx.try_send(datagram);
            continue;
        }
        flows.retain(|_, tx| !tx.is_closed());
        if flows.len() >= dp.settings.ports.udp_max_flows {
            tracing::debug!(port, %peer, "too many UDP clients; dropping datagram");
            continue;
        }
        let Some((route, session)) = admit(&dp, Kind::Udp, port, peer) else { continue };
        let (tx, rx) = mpsc::channel(FLOW_QUEUE);
        let _ = tx.try_send(datagram);
        flows.insert(peer, tx);
        tokio::spawn(udp_flow(dp.clone(), route, session, socket.clone(), peer, rx));
    }
}

/// One UDP client: its datagrams go to the agent on one stream, and replies come back on it.
async fn udp_flow(
    dp: Arc<DataPlane>,
    route: Arc<Route>,
    session: MuxHandle,
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    mut rx: mpsc::Receiver<Bytes>,
) {
    let header = ServerOpen::Datagram { tunnel_id: route.tunnel_id.clone(), peer: Some(peer.to_string()) };
    let Some(stream) = open(&dp, &route, &session, peer.ip(), header).await else { return };
    let (mut rd, mut wr) = tokio::io::split(stream);
    let idle = dp.settings.ports.udp_idle_timeout;
    let epoch = Instant::now();
    let last = AtomicU64::new(0);
    let touch = || last.store(epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
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
        let mut tick = tokio::time::interval((idle / 4).clamp(Duration::from_millis(100), Duration::from_secs(5)));
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
                    let quiet = epoch.elapsed().saturating_sub(Duration::from_millis(last.load(Ordering::Relaxed)));
                    if quiet >= idle {
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
    tracing::debug!(port = ?socket.local_addr().map(|a| a.port()), %peer, "UDP flow ended");
}
