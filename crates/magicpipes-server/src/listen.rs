//! Shared accept loop: connection limit, optional TLS, HTTP/1.1 with upgrades, graceful shutdown.

use std::convert::Infallible;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::{Request, Response};
use hyper::body::{Body, Incoming};
use hyper::service::Service;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::forwarded::{TrustedProxies, client_key};
use crate::proxy_header;

#[derive(Clone, Debug)]
pub struct ListenOpts {
    pub name: &'static str,
    pub max_connections: usize,
    /// Open connections per client (see [`client_key`]). A trusted proxy that did not name the
    /// client is not counted, since it carries many clients.
    pub max_per_client: usize,
    pub header_read_timeout: Duration,
    pub trusted_proxies: TrustedProxies,
    /// Connections from `trusted_proxies` start with a PROXY header naming the client.
    pub proxy_protocol: bool,
}

/// Open connections per client key.
#[derive(Default)]
struct PerClient(Mutex<HashMap<IpAddr, usize>>);

/// One counted connection; released on drop.
struct ClientSlot(Arc<PerClient>, IpAddr);

impl PerClient {
    fn acquire(self: &Arc<Self>, ip: IpAddr, max: usize) -> Option<ClientSlot> {
        let key = client_key(ip);
        let mut map = self.0.lock().unwrap();
        let n = map.entry(key).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(ClientSlot(self.clone(), key))
    }
}

impl Drop for ClientSlot {
    fn drop(&mut self) {
        let mut map = self.0.0.lock().unwrap();
        if let Some(n) = map.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.1);
            }
        }
    }
}

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A connection's share of the listener's limits: its permit and its per-client slot, released
/// when the last holder drops it. The connection task holds it, and so must anything that
/// outlives the HTTP connection (an upgraded WebSocket), so the limits keep counting it.
pub struct ConnLimits {
    _permit: OwnedSemaphorePermit,
    _slot: Option<ClientSlot>,
}

impl std::fmt::Debug for ConnLimits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConnLimits")
    }
}

/// Per-connection facts handed to the service factory.
#[derive(Clone, Debug)]
pub struct ConnInfo {
    pub peer: SocketAddr,
    /// TLS SNI (lowercase), if the connection is TLS and the client sent one.
    pub sni: Option<String>,
    pub limits: Arc<ConnLimits>,
}

pub async fn serve<F, S, B>(
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    opts: ListenOpts,
    shutdown: CancellationToken,
    tracker: TaskTracker,
    make_service: F,
) where
    F: Fn(ConnInfo) -> S + Send + Sync + 'static,
    S: Service<Request<Incoming>, Response = Response<B>, Error = Infallible> + Send + 'static,
    S::Future: Send + 'static,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let permits = Arc::new(Semaphore::new(opts.max_connections));
    let per_client = Arc::new(PerClient::default());
    let make_service = Arc::new(make_service);
    loop {
        let permit = tokio::select! {
            _ = shutdown.cancelled() => return,
            p = permits.clone().acquire_owned() => p.expect("semaphore never closed"),
        };
        let (tcp, peer) = tokio::select! {
            _ = shutdown.cancelled() => return,
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(listener = opts.name, error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let _ = tcp.set_nodelay(true);
        let make_service = make_service.clone();
        let tls = tls.clone();
        let shutdown = shutdown.clone();
        let header_timeout = opts.header_read_timeout;
        let opts = opts.clone();
        let per_client = per_client.clone();
        tracker.spawn(async move {
            let mut tcp = tcp;
            let mut peer = peer;
            if opts.proxy_protocol {
                match proxy_header::client_addr(&mut tcp, peer, &opts.trusted_proxies).await {
                    Ok(client) => peer = client,
                    Err(e) => return tracing::debug!(%peer, error = %e, "bad PROXY header"),
                }
            }
            let slot = if opts.trusted_proxies.trusts(peer.ip()) {
                None
            } else {
                match per_client.acquire(peer.ip(), opts.max_per_client) {
                    Some(slot) => Some(slot),
                    None => return tracing::debug!(listener = opts.name, %peer, "too many connections from this client"),
                }
            };
            let limits = Arc::new(ConnLimits { _permit: permit, _slot: slot });
            match tls {
                Some(acceptor) => match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                    Ok(Ok(stream)) => {
                        let sni = stream.get_ref().1.server_name().map(str::to_ascii_lowercase);
                        let svc = make_service(ConnInfo { peer, sni, limits });
                        serve_conn(stream, svc, header_timeout, shutdown).await
                    }
                    Ok(Err(e)) => tracing::debug!(%peer, error = %e, "TLS handshake failed"),
                    Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
                },
                None => serve_conn(tcp, make_service(ConnInfo { peer, sni: None, limits }), header_timeout, shutdown).await,
            }
        });
    }
}

async fn serve_conn<I, S, B>(io: I, svc: S, header_timeout: Duration, shutdown: CancellationToken)
where
    I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    S: Service<Request<Incoming>, Response = Response<B>, Error = Infallible> + Send + 'static,
    S::Future: Send + 'static,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder.timer(TokioTimer::new()).header_read_timeout(header_timeout).keep_alive(true);
    let conn = builder.serve_connection(TokioIo::new(io), svc).with_upgrades();
    tokio::pin!(conn);
    tokio::select! {
        res = conn.as_mut() => {
            if let Err(e) = res {
                tracing::debug!(error = %e, "connection error");
            }
        }
        _ = shutdown.cancelled() => {
            conn.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(Duration::from_secs(10), conn).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::Empty;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// Opens a connection and asks to upgrade it; true if the listener answered 101.
    async fn upgrade(addr: SocketAddr) -> Option<tokio::net::TcpStream> {
        let mut s = tokio::net::TcpStream::connect(addr).await.ok()?;
        s.write_all(b"GET / HTTP/1.1\r\nhost: x\r\nconnection: upgrade\r\nupgrade: test\r\n\r\n").await.ok()?;
        let mut buf = [0u8; 12];
        let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await.ok()?.ok()?;
        buf[..n].starts_with(b"HTTP/1.1 101").then_some(s)
    }

    #[tokio::test]
    async fn upgraded_connections_keep_their_slot() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let opts = ListenOpts {
            name: "test",
            max_connections: 10,
            max_per_client: 1,
            header_read_timeout: Duration::from_secs(5),
            trusted_proxies: TrustedProxies::default(),
            proxy_protocol: false,
        };
        let make = |info: ConnInfo| {
            hyper::service::service_fn(move |mut req: Request<Incoming>| {
                let limits = info.limits.clone();
                async move {
                    // Like the proxy's WebSocket bridge: holds the limits until the upgraded
                    // connection closes.
                    let on = hyper::upgrade::on(&mut req);
                    tokio::spawn(async move {
                        if let Ok(io) = on.await {
                            let mut io = TokioIo::new(io);
                            let _ = io.read(&mut [0u8; 1]).await;
                        }
                        drop(limits);
                    });
                    let resp = Response::builder().status(101).header("connection", "upgrade").header("upgrade", "test");
                    Ok::<_, Infallible>(resp.body(Empty::<bytes::Bytes>::new()).unwrap())
                }
            })
        };
        tokio::spawn(serve(listener, None, opts, CancellationToken::new(), TaskTracker::new(), make));
        let first = upgrade(addr).await.expect("first connection upgrades");
        assert!(upgrade(addr).await.is_none(), "the upgraded connection still uses the client's only slot");
        drop(first);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(upgrade(addr).await.is_some(), "its slot is free once it closes");
    }
}
