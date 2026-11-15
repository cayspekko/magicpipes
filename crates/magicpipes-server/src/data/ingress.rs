//! Public listeners: HTTPS (proxied tunnel traffic) and HTTP (ACME challenges + redirects).

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode, header};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::task::TaskTracker;

use super::DataPlane;
use crate::certs::Http01Challenges;
use crate::forwarded::TrustedProxies;
use crate::listen::{ConnInfo, ListenOpts, Site, Stop, serve, serve_with_site};

pub async fn serve_https(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    dp: Arc<DataPlane>,
    opts: ListenOpts,
    stop: Stop,
    tracker: TaskTracker,
) {
    serve(listener, Some(acceptor), opts, stop, tracker, move |conn| {
        let dp = dp.clone();
        let conn = Arc::new(conn);
        service_fn(move |req| super::proxy::handle(dp.clone(), conn.clone(), req))
    })
    .await
}

/// [`serve_https`] with the management host on the same listener: connections asking for its
/// name go to `management`, which is served on the control side as on a listener of its own.
pub async fn serve_https_with<G, T, C>(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    dp: Arc<DataPlane>,
    opts: ListenOpts,
    management: Site<G>,
    stop: Stop,
    tracker: TaskTracker,
) where
    G: Fn(ConnInfo) -> T + Send + Sync + 'static,
    T: hyper::service::Service<Request<Incoming>, Response = Response<C>, Error = Infallible> + Send + 'static,
    T::Future: Send + 'static,
    C: hyper::body::Body + Send + 'static,
    C::Data: Send,
    C::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let tunnels = move |conn: ConnInfo| {
        let dp = dp.clone();
        let conn = Arc::new(conn);
        service_fn(move |req| super::proxy::handle(dp.clone(), conn.clone(), req))
    };
    serve_with_site(listener, acceptor, opts, stop, tracker, tunnels, management).await
}

const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

pub async fn serve_http(
    listener: TcpListener,
    challenges: Arc<Http01Challenges>,
    https_port: u16,
    stop: Stop,
    tracker: TaskTracker,
) {
    let opts = ListenOpts {
        name: "public-http",
        max_connections: 1024,
        max_per_client: 64,
        header_read_timeout: Duration::from_secs(10),
        trusted_proxies: TrustedProxies::default(),
        proxy_protocol: false,
        idle_timeout: None,
    };
    serve(listener, None, opts, stop, tracker, move |_conn| {
        let challenges = challenges.clone();
        service_fn(move |req| {
            let challenges = challenges.clone();
            async move { Ok::<_, Infallible>(http_response(&challenges, https_port, &req)) }
        })
    })
    .await
}

fn http_response(challenges: &Http01Challenges, https_port: u16, req: &Request<Incoming>) -> Response<Full<Bytes>> {
    let path = req.uri().path();
    if let Some(token) = path.strip_prefix(CHALLENGE_PREFIX) {
        return match challenges.get(token) {
            Some(key_auth) => Response::builder()
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Full::new(Bytes::from(key_auth)))
                .unwrap(),
            None => plain(StatusCode::NOT_FOUND, "unknown challenge"),
        };
    }
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.rsplit_once(':').map_or(h, |(host, _)| host))
        .filter(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.'));
    let Some(host) = host else { return plain(StatusCode::BAD_REQUEST, "missing Host header") };
    let pq = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let location = match https_port {
        443 => format!("https://{host}{pq}"),
        p => format!("https://{host}:{p}{pq}"),
    };
    Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header(header::LOCATION, location)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

fn plain(status: StatusCode, msg: &'static str) -> Response<Full<Bytes>> {
    Response::builder().status(status).body(Full::new(Bytes::from_static(msg.as_bytes()))).unwrap()
}
