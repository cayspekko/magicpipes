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
use tokio::sync::Semaphore;
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

/// Per-connection facts handed to the service factory.
#[derive(Clone, Debug)]
pub struct ConnInfo {
    pub peer: SocketAddr,
    /// TLS SNI (lowercase), if the connection is TLS and the client sent one.
    pub sni: Option<String>,
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
            let _permit = permit;
            let mut tcp = tcp;
            let mut peer = peer;
            if opts.proxy_protocol {
                match proxy_header::client_addr(&mut tcp, peer, &opts.trusted_proxies).await {
                    Ok(client) => peer = client,
                    Err(e) => return tracing::debug!(%peer, error = %e, "bad PROXY header"),
                }
            }
            let _slot = if opts.trusted_proxies.trusts(peer.ip()) {
                None
            } else {
                match per_client.acquire(peer.ip(), opts.max_per_client) {
                    Some(slot) => Some(slot),
                    None => return tracing::debug!(listener = opts.name, %peer, "too many connections from this client"),
                }
            };
            match tls {
                Some(acceptor) => match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                    Ok(Ok(stream)) => {
                        let sni = stream.get_ref().1.server_name().map(str::to_ascii_lowercase);
                        let svc = make_service(ConnInfo { peer, sni });
                        serve_conn(stream, svc, header_timeout, shutdown).await
                    }
                    Ok(Err(e)) => tracing::debug!(%peer, error = %e, "TLS handshake failed"),
                    Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
                },
                None => serve_conn(tcp, make_service(ConnInfo { peer, sni: None }), header_timeout, shutdown).await,
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
