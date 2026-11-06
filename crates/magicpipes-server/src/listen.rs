//! Shared accept loop: connection limit, optional TLS, HTTP/1.1 with upgrades, graceful shutdown.

use std::convert::Infallible;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use http::{Request, Response};
use hyper::body::{Body, Incoming};
use hyper::service::Service;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
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
    /// Close a connection after this long with no byte moving in either direction.
    pub idle_timeout: Option<Duration>,
}

/// When any of a connection's streams last moved a byte, in either direction.
#[derive(Clone)]
pub struct Activity {
    last: Arc<AtomicU64>,
    epoch: Instant,
}

impl Activity {
    pub fn new() -> Self {
        Self { last: Arc::default(), epoch: Instant::now() }
    }

    pub fn track<S>(&self, inner: S) -> Tracked<S> {
        Tracked { inner, activity: self.clone() }
    }

    fn moved(&self) {
        self.last.store(self.epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    /// Returns once `limit` has passed with no byte moving.
    pub async fn stalled(&self, limit: Duration) {
        let mut tick = tokio::time::interval((limit / 4).clamp(Duration::from_millis(100), Duration::from_secs(30)));
        loop {
            tick.tick().await;
            if self.epoch.elapsed().saturating_sub(Duration::from_millis(self.last.load(Ordering::Relaxed))) >= limit {
                return;
            }
        }
    }
}

/// A stream that reports every byte it moves to its [`Activity`].
pub struct Tracked<S> {
    inner: S,
    activity: Activity,
}

impl<S: AsyncRead + Unpin> AsyncRead for Tracked<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(res, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.activity.moved();
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tracked<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(res, Poll::Ready(Ok(n)) if n > 0) {
            self.activity.moved();
        }
        res
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
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
/// when the last holder drops it. The connection task holds it for as long as the HTTP connection
/// lasts, on every listener. Anything that outlives the HTTP connection and should go on counting
/// keeps a clone (a proxied WebSocket); an agent's session doesn't, so an authenticated session
/// gives its place back once it has upgraded.
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
        let (header_timeout, idle_timeout) = (opts.header_read_timeout, opts.idle_timeout);
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
                        let svc = make_service(ConnInfo { peer, sni, limits: limits.clone() });
                        serve_conn(stream, svc, header_timeout, idle_timeout, shutdown).await
                    }
                    Ok(Err(e)) => tracing::debug!(%peer, error = %e, "TLS handshake failed"),
                    Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
                },
                None => serve_conn(tcp, make_service(ConnInfo { peer, sni: None, limits: limits.clone() }), header_timeout, idle_timeout, shutdown).await,
            }
        });
    }
}

async fn serve_conn<I, S, B>(io: I, svc: S, header_timeout: Duration, idle_timeout: Option<Duration>, shutdown: CancellationToken)
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
    let activity = Activity::new();
    let conn = builder.serve_connection(TokioIo::new(activity.track(io)), svc).with_upgrades();
    tokio::pin!(conn);
    let stalled = async {
        match idle_timeout {
            Some(limit) => activity.stalled(limit).await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        res = conn.as_mut() => {
            if let Err(e) = res {
                tracing::debug!(error = %e, "connection error");
            }
        }
        // Dropping the connection closes it, and ends the request it was in the middle of.
        _ = stalled => tracing::debug!("closing a stalled connection"),
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

    fn opts(max_per_client: usize) -> ListenOpts {
        ListenOpts {
            name: "test",
            max_connections: 10,
            max_per_client,
            header_read_timeout: Duration::from_secs(5),
            trusted_proxies: TrustedProxies::default(),
            proxy_protocol: false,
            idle_timeout: None,
        }
    }

    /// With an idle timeout, a request that stops moving ends; one that keeps moving doesn't.
    #[tokio::test]
    async fn stalled_connections_are_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let make = |_: ConnInfo| {
            hyper::service::service_fn(|req: Request<Incoming>| async move {
                let _ = http_body_util::BodyExt::collect(req.into_body()).await;
                Ok::<_, Infallible>(Response::new(Empty::<bytes::Bytes>::new()))
            })
        };
        let opts = ListenOpts { idle_timeout: Some(Duration::from_millis(400)), ..opts(4) };
        tokio::spawn(serve(listener, None, opts, CancellationToken::new(), TaskTracker::new(), make));
        let head = b"POST / HTTP/1.1\r\nhost: x\r\ncontent-length: 100\r\n\r\n";

        // An upload that keeps moving outlives the timeout.
        let mut moving = tokio::net::TcpStream::connect(addr).await.unwrap();
        moving.write_all(head).await.unwrap();
        for _ in 0..8 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            moving.write_all(b"x").await.unwrap();
        }

        // One that stops is closed.
        let mut buf = [0u8; 16];
        let closed = tokio::time::timeout(Duration::from_secs(3), moving.read(&mut buf)).await;
        assert!(matches!(closed, Ok(Ok(0)) | Ok(Err(_))), "{closed:?}");
    }

    /// A service that keeps nothing of the connection's: the listener still counts it.
    #[tokio::test]
    async fn every_connection_counts_until_it_ends() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let make = |_: ConnInfo| hyper::service::service_fn(|_: Request<Incoming>| async { Ok::<_, Infallible>(Response::new(Empty::<bytes::Bytes>::new())) });
        tokio::spawn(serve(listener, None, opts(1), CancellationToken::new(), TaskTracker::new(), make));
        let request = |addr| async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.ok()?;
            s.write_all(b"GET / HTTP/1.1\r\nhost: x\r\n\r\n").await.ok()?;
            let mut buf = [0u8; 12];
            let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await.ok()?.ok()?;
            buf[..n].starts_with(b"HTTP/1.1 200").then_some(s)
        };
        let first = request(addr).await.expect("first connection is served");
        assert!(request(addr).await.is_none(), "the kept-alive connection still uses the client's only slot");
        drop(first);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(request(addr).await.is_some(), "its slot is free once it closes");
    }

    /// Like an agent's session: once upgraded, it no longer uses the listener's limits.
    #[tokio::test]
    async fn upgrades_that_keep_no_limits_give_their_slot_back() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let make = |_: ConnInfo| {
            hyper::service::service_fn(|mut req: Request<Incoming>| async move {
                let on = hyper::upgrade::on(&mut req);
                tokio::spawn(async move {
                    if let Ok(io) = on.await {
                        let _ = TokioIo::new(io).read(&mut [0u8; 1]).await;
                    }
                });
                let resp = Response::builder().status(101).header("connection", "upgrade").header("upgrade", "test");
                Ok::<_, Infallible>(resp.body(Empty::<bytes::Bytes>::new()).unwrap())
            })
        };
        tokio::spawn(serve(listener, None, opts(1), CancellationToken::new(), TaskTracker::new(), make));
        let first = upgrade(addr).await.expect("first connection upgrades");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(upgrade(addr).await.is_some(), "the upgraded connection gave its slot back");
        drop(first);
    }

    #[tokio::test]
    async fn upgraded_connections_keep_their_slot() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
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
        tokio::spawn(serve(listener, None, opts(1), CancellationToken::new(), TaskTracker::new(), make));
        let first = upgrade(addr).await.expect("first connection upgrades");
        assert!(upgrade(addr).await.is_none(), "the upgraded connection still uses the client's only slot");
        drop(first);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(upgrade(addr).await.is_some(), "its slot is free once it closes");
    }
}
