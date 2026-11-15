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
use tokio::net::{TcpListener, TcpStream};
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

/// A connection's service, noting when its first request starts ([`Notify::notify_one`] keeps the
/// note for a waiter that comes later). After that, a request costs one relaxed load.
struct FirstRequest<S> {
    inner: S,
    started: Arc<tokio::sync::Notify>,
    seen: std::sync::atomic::AtomicBool,
}

impl<S, R> Service<R> for FirstRequest<S>
where
    S: Service<R>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn call(&self, req: R) -> Self::Future {
        if !self.seen.load(Ordering::Relaxed) {
            self.seen.store(true, Ordering::Relaxed);
            self.started.notify_one();
        }
        self.inner.call(req)
    }
}

/// Open connections per client key.
#[derive(Default)]
pub(crate) struct PerClient(Mutex<HashMap<IpAddr, usize>>);

/// One counted connection; released on drop.
pub(crate) struct ClientSlot(Arc<PerClient>, IpAddr);

impl PerClient {
    pub(crate) fn acquire(self: &Arc<Self>, ip: IpAddr, max: usize) -> Option<ClientSlot> {
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

/// How a listener stops. `shutdown` ends its accept loop; each connection then finishes the request
/// under way, and one accepted a moment before gets its first request answered, since at a handover
/// another process takes the new ones. On a plain stop nobody does, and `nobody_takes_over` closes
/// the connections still waiting for a first request at once: waiting only lengthens the outage, and
/// the spare connections browsers open in advance never send one (they held a stopping server for
/// its whole 15 s, behind every restart of a Docker container).
#[derive(Clone, Debug, Default)]
pub struct Stop {
    pub shutdown: CancellationToken,
    pub nobody_takes_over: CancellationToken,
}

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
    stop: Stop,
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
    let counts = Counts::new(&opts);
    let make_service = Arc::new(make_service);
    while let Some((tcp, peer, permit)) = accept(&listener, &counts, &opts, &stop.shutdown).await {
        let make_service = make_service.clone();
        let tls = tls.clone();
        let stop = stop.clone();
        let opts = opts.clone();
        let counts = counts.clone();
        tracker.spawn(async move {
            let Some((tcp, peer, limits)) = admit(tcp, peer, permit, &opts, &counts).await else { return };
            let (header_timeout, idle_timeout) = (opts.header_read_timeout, opts.idle_timeout);
            match tls {
                Some(acceptor) => {
                    let Some(stream) = handshake(&acceptor, tcp, peer).await else { return };
                    let sni = stream.get_ref().1.server_name().map(str::to_ascii_lowercase);
                    let svc = make_service(ConnInfo { peer, sni, limits: limits.clone() });
                    serve_conn(stream, svc, header_timeout, idle_timeout, stop).await
                }
                None => serve_conn(tcp, make_service(ConnInfo { peer, sni: None, limits: limits.clone() }), header_timeout, idle_timeout, stop).await,
            }
        });
    }
}

/// A second site on a TLS listener, chosen by the name a connection asks for (SNI): the
/// management host on the public listener.
pub struct Site<F> {
    /// Lowercase.
    pub host: String,
    pub opts: ListenOpts,
    pub make_service: F,
}

/// Like [`serve`] with TLS, sending connections that ask for `site.host` to `site`. Until the
/// handshake says which side a connection is for, it counts as one being set up, under `opts`
/// (PROXY header and handshake included); then it takes a place on its side, `opts`' counts for
/// the tunnels or the site's own, and is dropped if that side is full. So the two sides never share
/// a count: a client with every place it may have on tunnels (a whole office behind one address)
/// still reaches the management host, and the reverse.
pub async fn serve_with_site<F, S, B, G, T, C>(
    listener: TcpListener,
    tls: TlsAcceptor,
    opts: ListenOpts,
    stop: Stop,
    tracker: TaskTracker,
    make_service: F,
    site: Site<G>,
) where
    F: Fn(ConnInfo) -> S + Send + Sync + 'static,
    S: Service<Request<Incoming>, Response = Response<B>, Error = Infallible> + Send + 'static,
    S::Future: Send + 'static,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    G: Fn(ConnInfo) -> T + Send + Sync + 'static,
    T: Service<Request<Incoming>, Response = Response<C>, Error = Infallible> + Send + 'static,
    T::Future: Send + 'static,
    C: Body + Send + 'static,
    C::Data: Send,
    C::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let setting_up = Counts::new(&opts);
    let tunnels = Counts::new(&opts);
    let site_counts = Counts::new(&site.opts);
    let make_service = Arc::new(make_service);
    let site = Arc::new(site);
    while let Some((tcp, peer, permit)) = accept(&listener, &setting_up, &opts, &stop.shutdown).await {
        let make_service = make_service.clone();
        let site = site.clone();
        let tls = tls.clone();
        let stop = stop.clone();
        let opts = opts.clone();
        let (setting_up, tunnels, site_counts) = (setting_up.clone(), tunnels.clone(), site_counts.clone());
        tracker.spawn(async move {
            let Some((tcp, peer, pending)) = admit(tcp, peer, permit, &opts, &setting_up).await else { return };
            let Some(stream) = handshake(&tls, tcp, peer).await else { return };
            let sni = stream.get_ref().1.server_name().map(str::to_ascii_lowercase);
            let to_site = sni.as_deref() == Some(site.host.as_str());
            let Some(limits) = (if to_site { place(peer, &site.opts, &site_counts) } else { place(peer, &opts, &tunnels) }) else { return };
            drop(pending);
            let info = ConnInfo { peer, sni, limits: limits.clone() };
            if to_site {
                serve_conn(stream, (site.make_service)(info), site.opts.header_read_timeout, site.opts.idle_timeout, stop).await
            } else {
                serve_conn(stream, make_service(info), opts.header_read_timeout, opts.idle_timeout, stop).await
            }
        });
    }
}

/// A place among `counts` for an established connection, without waiting: a listener of the
/// side's own would have left it in the kernel's queue instead. `None` drops it.
fn place(peer: SocketAddr, opts: &ListenOpts, counts: &Counts) -> Option<Arc<ConnLimits>> {
    let Ok(permit) = counts.permits.clone().try_acquire_owned() else {
        tracing::debug!(listener = opts.name, %peer, "too many connections");
        return None;
    };
    let slot = client_slot(peer, opts, counts)?;
    Some(Arc::new(ConnLimits { _permit: permit, _slot: slot }))
}

/// A listener's (or a site's) open connections, in all and per client.
#[derive(Clone)]
struct Counts {
    permits: Arc<Semaphore>,
    per_client: Arc<PerClient>,
}

impl Counts {
    fn new(opts: &ListenOpts) -> Self {
        Self { permits: Arc::new(Semaphore::new(opts.max_connections)), per_client: Arc::default() }
    }
}

/// The next connection, once there's room for it; `None` at shutdown.
async fn accept(listener: &TcpListener, counts: &Counts, opts: &ListenOpts, shutdown: &CancellationToken) -> Option<(TcpStream, SocketAddr, OwnedSemaphorePermit)> {
    loop {
        let permit = tokio::select! {
            _ = shutdown.cancelled() => return None,
            p = counts.permits.clone().acquire_owned() => p.expect("semaphore never closed"),
        };
        let (tcp, peer) = tokio::select! {
            _ = shutdown.cancelled() => return None,
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
        // For agents' sessions, see `SEND_QUEUE`. A public client's connection has one request at a
        // time, but it has no use for megabytes of kernel memory for a slow reader either.
        #[cfg(target_os = "linux")]
        let _ = socket2::SockRef::from(&tcp).set_tcp_notsent_lowat(magicpipes_core::mux::SEND_QUEUE);
        return Some((tcp, peer, permit));
    }
}

/// Learns who the client is (from a PROXY header, if the listener expects one) and counts the
/// connection against it; `None` drops the connection.
async fn admit(mut tcp: TcpStream, mut peer: SocketAddr, permit: OwnedSemaphorePermit, opts: &ListenOpts, counts: &Counts) -> Option<(TcpStream, SocketAddr, Arc<ConnLimits>)> {
    if opts.proxy_protocol {
        match proxy_header::client_addr(&mut tcp, peer, &opts.trusted_proxies).await {
            Ok(client) => peer = client,
            Err(e) => {
                tracing::debug!(%peer, error = %e, "bad PROXY header");
                return None;
            }
        }
    }
    let slot = client_slot(peer, opts, counts)?;
    Some((tcp, peer, Arc::new(ConnLimits { _permit: permit, _slot: slot })))
}

/// The client's place among its connections: `Some(None)` for a trusted proxy, which carries many
/// clients, and `None` when the client has no room left.
fn client_slot(peer: SocketAddr, opts: &ListenOpts, counts: &Counts) -> Option<Option<ClientSlot>> {
    if opts.trusted_proxies.trusts(peer.ip()) {
        return Some(None);
    }
    let slot = counts.per_client.acquire(peer.ip(), opts.max_per_client);
    if slot.is_none() {
        tracing::debug!(listener = opts.name, %peer, "too many connections from this client");
    }
    slot.map(Some)
}

async fn handshake(acceptor: &TlsAcceptor, tcp: TcpStream, peer: SocketAddr) -> Option<tokio_rustls::server::TlsStream<TcpStream>> {
    match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
        Ok(Ok(stream)) => Some(stream),
        Ok(Err(e)) => {
            tracing::debug!(%peer, error = %e, "TLS handshake failed");
            None
        }
        Err(_) => {
            tracing::debug!(%peer, "TLS handshake timed out");
            None
        }
    }
}

async fn serve_conn<I, S, B>(io: I, svc: S, header_timeout: Duration, idle_timeout: Option<Duration>, stop: Stop)
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
    let first = Arc::new(tokio::sync::Notify::new());
    let svc = FirstRequest { inner: svc, started: first.clone(), seen: std::sync::atomic::AtomicBool::new(false) };
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
        // The request under way finishes, then the connection closes. How long that may take is
        // the caller's: 15 seconds at shutdown, `upgrades.drain_secs` at a handover. At a handover,
        // a connection accepted a moment before gets its first request answered: closing it before
        // that would fail a client that did nothing wrong, while another process takes the new
        // ones. On a plain stop nobody takes them, so it closes at once ([`Stop`]).
        _ = stop.shutdown.cancelled() => {
            tokio::select! {
                res = conn.as_mut() => {
                    if let Err(e) = res {
                        tracing::debug!(error = %e, "connection error");
                    }
                    return;
                }
                _ = first.notified() => {}
                _ = tokio::time::sleep(header_timeout) => {}
                _ = stop.nobody_takes_over.cancelled() => {}
            }
            conn.as_mut().graceful_shutdown();
            let _ = conn.await;
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
        tokio::spawn(serve(listener, None, opts, Stop::default(), TaskTracker::new(), make));
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

    /// A connection that never sends a request (a browser's spare one) is kept at a handover, where
    /// it may still be used, and closed at once on a plain stop, which it would otherwise hold.
    #[tokio::test]
    async fn a_plain_stop_closes_connections_that_sent_nothing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let make = |_: ConnInfo| hyper::service::service_fn(|_: Request<Incoming>| async { Ok::<_, Infallible>(Response::new(Empty::<bytes::Bytes>::new())) });
        let (stop, tracker) = (Stop::default(), TaskTracker::new());
        tokio::spawn(serve(listener, None, opts(4), stop.clone(), tracker.clone(), make));
        let mut spare = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        stop.shutdown.cancel();
        let mut buf = [0u8; 16];
        assert!(tokio::time::timeout(Duration::from_millis(300), spare.read(&mut buf)).await.is_err(), "kept while another process may take over");
        stop.nobody_takes_over.cancel();
        let closed = tokio::time::timeout(Duration::from_secs(2), spare.read(&mut buf)).await;
        assert!(matches!(closed, Ok(Ok(0)) | Ok(Err(_))), "{closed:?}");
        tracker.close();
        assert!(tokio::time::timeout(Duration::from_secs(2), tracker.wait()).await.is_ok(), "nothing left to wait for");
    }

    /// A plain stop still lets the request under way finish.
    #[tokio::test]
    async fn a_plain_stop_lets_the_request_under_way_finish() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let make = |_: ConnInfo| {
            hyper::service::service_fn(|req: Request<Incoming>| async move {
                let _ = http_body_util::BodyExt::collect(req.into_body()).await;
                Ok::<_, Infallible>(Response::new(Empty::<bytes::Bytes>::new()))
            })
        };
        let stop = Stop::default();
        tokio::spawn(serve(listener, None, opts(4), stop.clone(), TaskTracker::new(), make));
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"POST / HTTP/1.1\r\nhost: x\r\ncontent-length: 4\r\n\r\nab").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        stop.nobody_takes_over.cancel();
        stop.shutdown.cancel();
        tokio::time::sleep(Duration::from_millis(100)).await;
        s.write_all(b"cd").await.unwrap();
        let mut buf = [0u8; 12];
        let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await.unwrap().unwrap();
        assert!(buf[..n].starts_with(b"HTTP/1.1 200"), "{:?}", String::from_utf8_lossy(&buf[..n]));
    }

    /// A service that keeps nothing of the connection's: the listener still counts it.
    #[tokio::test]
    async fn every_connection_counts_until_it_ends() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let make = |_: ConnInfo| hyper::service::service_fn(|_: Request<Incoming>| async { Ok::<_, Infallible>(Response::new(Empty::<bytes::Bytes>::new())) });
        tokio::spawn(serve(listener, None, opts(1), Stop::default(), TaskTracker::new(), make));
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
        tokio::spawn(serve(listener, None, opts(1), Stop::default(), TaskTracker::new(), make));
        let first = upgrade(addr).await.expect("first connection upgrades");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(upgrade(addr).await.is_some(), "the upgraded connection gave its slot back");
        drop(first);
    }

    /// One listener, two sides: once the handshake names its side, a connection counts only there,
    /// so a client with every place it may have on one still gets onto the other.
    #[tokio::test]
    async fn the_site_and_the_tunnels_count_apart() {
        use http_body_util::{BodyExt, Full};
        use rustls_pki_types::pem::PemObject;
        use rustls_pki_types::{CertificateDer, ServerName};

        let dir = std::env::temp_dir().join(format!("mp-listen-{}", magicpipes_core::secret::random_string(8)));
        let ca = crate::certs::devca::DevCa::load_or_create(&dir, &["t.test"]).unwrap();
        let resolver = Arc::new(crate::certs::CertResolver::default());
        for name in ["app.t.test", "m.t.test"] {
            let (chain, key) = ca.issue(name).unwrap();
            resolver.insert(name, crate::certs::load_pem(chain.as_bytes(), key.as_bytes()).unwrap().key);
        }
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_file_iter(ca.ca_path()).unwrap() {
            roots.add(cert.unwrap()).unwrap();
        }
        std::fs::remove_dir_all(&dir).ok();
        let client = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let client = tokio_rustls::TlsConnector::from(Arc::new(client));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let answer = |body: &'static str| {
            move |_: ConnInfo| {
                hyper::service::service_fn(move |_: Request<Incoming>| async move { Ok::<_, Infallible>(Response::new(Full::new(bytes::Bytes::from_static(body.as_bytes())))) })
            }
        };
        let site = Site { host: "m.t.test".into(), opts: opts(1), make_service: answer("site") };
        let acceptor = TlsAcceptor::from(crate::certs::server_config(resolver));
        tokio::spawn(serve_with_site(listener, acceptor, opts(1), Stop::default(), TaskTracker::new(), answer("tunnels"), site));

        // A connection that has had one answer and stays open, with that answer; `None` if refused.
        let open = |name: &'static str| {
            let client = client.clone();
            async move {
                let tcp = tokio::net::TcpStream::connect(addr).await.ok()?;
                let tls = client.connect(ServerName::try_from(name).unwrap(), tcp).await.ok()?;
                let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.ok()?;
                tokio::spawn(conn);
                let req = Request::get("/").header("host", name).body(Empty::<bytes::Bytes>::new()).unwrap();
                let resp = tokio::time::timeout(Duration::from_secs(2), sender.send_request(req)).await.ok()?.ok()?;
                let body = resp.into_body().collect().await.ok()?.to_bytes();
                Some((sender, String::from_utf8_lossy(&body).into_owned()))
            }
        };
        let (tunnel, said) = open("app.t.test").await.expect("a connection to a tunnel");
        assert_eq!(said, "tunnels");
        let (site_conn, said) = open("m.t.test").await.expect("the client's place on the tunnels doesn't count on the site");
        assert_eq!(said, "site");
        assert!(open("app.t.test").await.is_none(), "its one place on the tunnels is taken");
        assert!(open("m.t.test").await.is_none(), "and its one on the site");
        drop(tunnel);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(open("app.t.test").await.map(|o| o.1).as_deref(), Some("tunnels"), "its place on the tunnels is free again");
        drop(site_conn);
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
        tokio::spawn(serve(listener, None, opts(1), Stop::default(), TaskTracker::new(), make));
        let first = upgrade(addr).await.expect("first connection upgrades");
        assert!(upgrade(addr).await.is_none(), "the upgraded connection still uses the client's only slot");
        drop(first);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(upgrade(addr).await.is_some(), "its slot is free once it closes");
    }
}
