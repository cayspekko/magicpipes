//! HTTP/1.1 reverse proxy over agent data streams.
//!
//! For each public request: resolve the route, then send the request over an HTTP/1.1 client
//! connection to the owning agent: an idle one from the [`super::pool`] when there is one, else
//! a new yamux stream on the agent's session that announces the tunnel id. A connection goes
//! back to the pool once its response has been read to the end. Bodies stream in both directions
//! (hyper `Incoming` is passed through untouched). `Upgrade` requests (WebSockets) and readiness
//! probes get a connection of their own; upgrades are bridged as raw byte streams after the
//! `101` response.

// Error pages are returned by value through `Result<_, Response>` on purpose.
#![allow(clippy::result_large_err)]

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use hyper::client::conn::http1::SendRequest;
use magicpipes_core::error::ErrorCode;
use magicpipes_core::mux::{ClientUse, MuxHandle};
use magicpipes_core::proto::{self, ERROR_HEADER, PROBE_ACK_HEADER, PROBE_HEADER, ServerOpen};
use magicpipes_core::theme::PALETTE;
use tokio_util::sync::CancellationToken;

use super::gate;
use super::io::{StatusPrefixed, UpstreamStatus, bridge, find_status};
use super::{DataPlane, Outcome, Route};
use crate::authz::Principal;
use crate::forwarded::{TrustedProxies, client_key};
use crate::listen::ConnInfo;

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// How long a removed tunnel's WebSockets may stay open for the agent to end them.
const REMOVAL_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

const HOP_BY_HOP: &[HeaderName] = &[
    header::CONNECTION,
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
];

pub async fn handle(
    dp: Arc<DataPlane>,
    conn: Arc<ConnInfo>,
    req: Request<Incoming>,
) -> Result<Response<ProxyBody>, Infallible> {
    Ok(match proxy(&dp, &conn, req).await {
        Ok(resp) => resp,
        Err(resp) => resp,
    })
}

async fn proxy(dp: &Arc<DataPlane>, conn: &ConnInfo, mut req: Request<Incoming>) -> Result<Response<ProxyBody>, Response<ProxyBody>> {
    if req.method() == Method::CONNECT {
        return Err(error_page(ErrorCode::MethodNotAllowed, "CONNECT is not supported."));
    }
    let host = request_host(&req)
        .ok_or_else(|| error_page(ErrorCode::BadHost, "Missing or invalid Host header."))?;
    // The certificate presented was chosen by SNI; never serve another tunnel's hostname on it.
    if conn.sni.as_deref().is_some_and(|sni| sni != host) {
        return Err(error_page(ErrorCode::MisdirectedRequest, "Host does not match the TLS server name."));
    }
    let route = dp
        .lookup(&host)
        .ok_or_else(|| error_page(ErrorCode::TunnelNotFound, "There is no tunnel at this address."))?;
    let client_ip = dp.settings.trusted_proxies.client_ip(conn.peer.ip(), req.headers());
    // Fails like an unknown hostname: a client outside the allowed networks learns nothing.
    if !route.access.allows_network(client_ip) {
        return Err(error_page(ErrorCode::TunnelNotFound, "There is no tunnel at this address."));
    }
    // Private tunnel hosts: MagicPipes answers its own sign-in paths.
    if !route.access.authz.public && req.uri().path().starts_with(crate::tunnel_auth::RESERVED_PREFIX) {
        return Err(gate::reserved(dp, req, &host).await);
    }
    // Public tunnels admit anyone; private ones a signed-in user who may connect.
    let admitted = match route.access.admits(&Principal::Anonymous, client_ip) {
        true => None,
        false => Some(gate::check(dp, &req, &host, &route)?),
    };

    let session = match &route.session {
        Some(s) if !s.is_closed() => s.clone(),
        _ => {
            route.stats.record(Outcome::AgentOffline);
            return Err(error_page(
                ErrorCode::AgentOffline,
                "The MagicPipes agent serving this tunnel is not connected.",
            ));
        }
    };

    let client = client_key(client_ip);
    let probe = take_probe_nonce(req.headers_mut());
    let upgrade = is_upgrade(req.headers());
    let client_upgrade = upgrade.then(|| hyper::upgrade::on(&mut req));
    prepare_request(&mut req, &host, conn.peer, upgrade, &dp.settings.trusted_proxies)?;
    // MagicPipes' own cookies are never the application's, public or private: a name can pass to
    // someone else, and a browser still sends what it was given for it.
    gate::strip_cookies(req.headers_mut());
    if let Some(a) = &admitted {
        // The application learns who is asking. Clients can't forge these: `prepare_request`
        // dropped every client-sent x-magicpipes-* header.
        let h = req.headers_mut();
        if let (Ok(email), Ok(id)) = (HeaderValue::from_str(&a.user.email), HeaderValue::from_str(&a.user_id)) {
            h.insert("x-magicpipes-user", email);
            h.insert("x-magicpipes-user-id", id);
        }
    }

    // An upgraded connection outlives this HTTP connection; it keeps the listener's limits.
    let limits = conn.limits.clone();
    let (progress, uploading) = tokio::sync::watch::channel(());
    let req = req.map(|inner| Progress { inner, progress });
    let timeout = dp.settings.upstream_response_timeout;
    // A probe checks that the agent opened a stream for it, and an upgrade keeps its stream:
    // both get a connection of their own. Everything else shares pooled ones.
    let (resp, reuse) = if upgrade || probe.is_some() {
        let upstream = open_upstream(dp, &route, &session, client).await?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Progress<Incoming>>(TokioIo::new(upstream))
            .await
            .map_err(|_| upstream_error(&route, UpstreamStatus::Closed))?;
        tokio::spawn(async move {
            if let Err(e) = conn.with_upgrades().await {
                tracing::debug!(error = %e, "upstream connection ended");
            }
        });
        (answer(&route, response_within(sender.send_request(req), uploading, timeout).await)?, None)
    } else {
        let used = session.client_use(client).ok_or_else(busy)?;
        let version = route.version;
        let (resp, sender) = send_shared(dp, &route, &session, req, uploading).await?;
        (resp, Some((sender, used, version)))
    };
    route.stats.record(Outcome::Ok);
    // Back to the pool once the response has been read to the end; a response cut short closes
    // the connection instead. The client's place is kept until then.
    let resp = match reuse {
        Some((mut sender, used, version)) => {
            let (dp, tunnel, session) = (dp.clone(), route.tunnel_id.clone(), session.clone());
            tokio::spawn(async move {
                if sender.ready().await.is_ok() {
                    dp.pool.put(&tunnel, session, version, sender);
                }
            });
            resp.map(|inner| Holding { inner, _used: used }.boxed())
        }
        None => resp.map(|b| b.boxed()),
    };
    let mut resp = resp;

    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        let Some(client_upgrade) = client_upgrade else {
            return Err(error_page(ErrorCode::BadUpstream, "Unexpected protocol switch."));
        };
        let upstream_upgrade = hyper::upgrade::on(&mut resp);
        let idle = dp.settings.websocket_idle_timeout;
        let stop = CancellationToken::new();
        // Recheck on every change to routes, users or tags, for everyone: a public tunnel can turn
        // private. Close once access is gone.
        {
            let (dp, stop, host, tunnel) = (dp.clone(), stop.clone(), host.clone(), route.tunnel_id.clone());
            tokio::spawn(async move {
                tokio::select! {
                    _ = stop.cancelled() => {}
                    _ = revoked(&dp, &host, &tunnel, admitted.as_ref(), client_ip) => stop.cancel(),
                }
            });
        }
        tokio::spawn(async move {
            match tokio::try_join!(client_upgrade, upstream_upgrade) {
                Ok((client, upstream)) => bridge(TokioIo::new(client), TokioIo::new(upstream), Some(idle), stop.clone()).await,
                Err(e) => tracing::debug!(error = %e, "upgrade failed"),
            }
            // Ends the watcher, if any.
            stop.cancel();
            drop(limits);
        });
        clean_response_headers(resp.headers_mut(), true);
    } else {
        clean_response_headers(resp.headers_mut(), false);
    }
    gate::keep_cookies_to_the_tunnel(resp.headers_mut(), &dp.settings.shared_domains);
    if let Some(nonce) = probe
        && let Ok(v) = HeaderValue::from_str(&format!("{} {}", route.tunnel_id, nonce)) {
            resp.headers_mut().insert(PROBE_ACK_HEADER, v);
        }
    Ok(resp)
}

/// Returns once a long-lived connection may no longer use the tunnel it was opened to: at once if
/// its access is gone. A removed tunnel's agent ends the connection itself, with a last word for
/// the visitor if it has one (a web terminal's), so that gets a moment first.
async fn revoked(dp: &DataPlane, host: &str, tunnel: &str, who: Option<&gate::Admitted>, client: IpAddr) {
    let mut changes = dp.generation.subscribe();
    loop {
        let table = dp.table();
        if !gate::still_admitted(&table, host, tunnel, who, client) {
            if table.by_host.get(host).is_none_or(|r| r.tunnel_id != tunnel) {
                tokio::time::sleep(REMOVAL_GRACE).await;
            }
            return;
        }
        if changes.changed().await.is_err() {
            return;
        }
    }
}

type Sent = Option<Result<Response<Incoming>, hyper::Error>>;

/// The response, or the error page for a failed or timed-out request.
fn answer(route: &Route, sent: Sent) -> Result<Response<Incoming>, Response<ProxyBody>> {
    match sent {
        Some(Ok(resp)) => Ok(resp),
        Some(Err(e)) => {
            let status = find_status(&e).unwrap_or(UpstreamStatus::Closed);
            Err(upstream_error(route, status))
        }
        None => {
            route.stats.record(Outcome::LocalUnreachable);
            Err(error_page(ErrorCode::UpstreamTimeout, "The local application did not respond in time."))
        }
    }
}

fn busy() -> Response<ProxyBody> {
    error_page(ErrorCode::AgentBusy, "This tunnel is handling too many connections. Try again shortly.")
}

/// Sends `req` over an idle pooled connection, or a new one. A pooled connection that the
/// application closed just as it was taken refuses the request before sending any of it; the
/// request then goes over a new connection.
async fn send_shared(
    dp: &DataPlane,
    route: &Route,
    session: &MuxHandle,
    req: Request<Progress<Incoming>>,
    uploading: tokio::sync::watch::Receiver<()>,
) -> Result<(Response<Incoming>, SendRequest<Progress<Incoming>>), Response<ProxyBody>> {
    let timeout = dp.settings.upstream_response_timeout;
    let mut req = req;
    if let Some(mut sender) = dp.pool.take(&route.tunnel_id, session, route.version) {
        match response_within(sender.try_send_request(req), uploading.clone(), timeout).await {
            Some(Ok(resp)) => return Ok((resp, sender)),
            Some(Err(mut e)) => match e.take_message() {
                Some(unsent) => req = unsent,
                None => return Err(answer(route, Some(Err(e.into_error()))).unwrap_err()),
            },
            None => return Err(answer(route, None).unwrap_err()),
        }
    }
    let mut sender = connect_shared(dp, route, session).await?;
    let resp = answer(route, response_within(sender.send_request(req), uploading, timeout).await)?;
    Ok((resp, sender))
}

/// A new HTTP/1.1 connection over a shared stream, for the pool. When the session's streams are
/// used up, idle pooled ones on it are closed to make room.
async fn connect_shared(dp: &DataPlane, route: &Route, session: &MuxHandle) -> Result<SendRequest<Progress<Incoming>>, Response<ProxyBody>> {
    let fail = || {
        route.stats.record(Outcome::AgentOffline);
        error_page(ErrorCode::AgentUnavailable, "Could not open a stream to the MagicPipes agent.")
    };
    let open = dp.settings.stream_open_timeout;
    let mut stream = match dp.with_room(session, || session.open_shared(open)).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Err(busy()),
        Err(_) => return Err(fail()),
    };
    proto::write_frame(&mut stream, &ServerOpen::Data { tunnel_id: route.tunnel_id.clone(), peer: None })
        .await
        .map_err(|_| fail())?;
    let (sender, conn) = hyper::client::conn::http1::handshake::<_, Progress<Incoming>>(TokioIo::new(StatusPrefixed::new(stream)))
        .await
        .map_err(|_| upstream_error(route, UpstreamStatus::Closed))?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "upstream connection ended");
        }
    });
    Ok(sender)
}

/// A response body that keeps the client's place in the agent's budget until it is done.
struct Holding<B> {
    inner: B,
    _used: ClientUse,
}

impl<B: hyper::body::Body + Unpin> hyper::body::Body for Holding<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        std::pin::Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// A request body that reports each chunk it passes on, so a long upload counts as progress.
pub(super) struct Progress<B> {
    inner: B,
    progress: tokio::sync::watch::Sender<()>,
}

impl<B: hyper::body::Body + Unpin> hyper::body::Body for Progress<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let polled = std::pin::Pin::new(&mut self.inner).poll_frame(cx);
        if let std::task::Poll::Ready(Some(Ok(_))) = &polled {
            self.progress.send_replace(());
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// Waits for the response head, allowing `timeout` without progress: each request body chunk
/// starts the wait again, so an upload can take as long as it needs while it keeps moving, and
/// the application then has `timeout` to start answering. `None` when the time ran out.
async fn response_within<F: std::future::Future>(send: F, mut uploading: tokio::sync::watch::Receiver<()>, timeout: std::time::Duration) -> Option<F::Output> {
    tokio::pin!(send);
    let mut body_open = true;
    loop {
        let step = async {
            if body_open {
                tokio::select! {
                    r = &mut send => return Some(r),
                    // An error means the body is finished (and dropped): only the answer is left.
                    changed = uploading.changed() => body_open = changed.is_ok(),
                }
                None
            } else {
                Some((&mut send).await)
            }
        };
        match tokio::time::timeout(timeout, step).await {
            Ok(Some(r)) => return Some(r),
            Ok(None) => {}
            Err(_) => return None,
        }
    }
}

async fn open_upstream(
    dp: &DataPlane,
    route: &Route,
    session: &magicpipes_core::mux::MuxHandle,
    client: IpAddr,
) -> Result<StatusPrefixed<magicpipes_core::mux::MuxStream>, Response<ProxyBody>> {
    let fail = || {
        route.stats.record(Outcome::AgentOffline);
        error_page(ErrorCode::AgentUnavailable, "Could not open a stream to the MagicPipes agent.")
    };
    let timeout = dp.settings.stream_open_timeout;
    let mut stream = match dp.with_room(session, || session.open_data(timeout, client)).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Err(busy()),
        Err(_) => return Err(fail()),
    };
    proto::write_frame(&mut stream, &ServerOpen::Data { tunnel_id: route.tunnel_id.clone(), peer: None })
        .await
        .map_err(|_| fail())?;
    Ok(StatusPrefixed::new(stream))
}

fn upstream_error(route: &Route, status: UpstreamStatus) -> Response<ProxyBody> {
    match status {
        UpstreamStatus::LocalUnreachable => {
            route.stats.record(Outcome::LocalUnreachable);
            error_page(
                ErrorCode::LocalUnreachable,
                "The tunnel is connected, but the local application is not accepting connections.",
            )
        }
        UpstreamStatus::UnknownTunnel => {
            route.stats.record(Outcome::AgentOffline);
            error_page(ErrorCode::TunnelInactive, "The agent no longer serves this tunnel.")
        }
        _ => {
            route.stats.record(Outcome::LocalUnreachable);
            error_page(
                ErrorCode::UpstreamError,
                "The local application closed the connection without a valid response.",
            )
        }
    }
}

/// Lowercased host without port, from `Host` (or the authority of an absolute-form URI, which
/// must then match `Host`). Absolute-form URIs naming other hosts are rejected: no open proxy.
fn request_host(req: &Request<Incoming>) -> Option<String> {
    let header = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()).map(strip_port);
    let uri_host = req.uri().host().map(|h| h.to_ascii_lowercase());
    match (header, uri_host) {
        (Some(h), Some(u)) if h != u => None,
        (Some(h), _) => Some(h),
        (None, u) => u,
    }
    .filter(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.'))
}

fn strip_port(h: &str) -> String {
    let h = h.trim();
    let host = match h.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => h,
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn take_probe_nonce(headers: &mut HeaderMap) -> Option<String> {
    let nonce = headers.get(PROBE_HEADER).and_then(|v| v.to_str().ok()).map(str::to_string);
    nonce.filter(|n| !n.is_empty() && n.len() <= 64 && n.bytes().all(|b| b.is_ascii_alphanumeric()))
}

fn connection_has(headers: &HeaderMap, token: &str) -> bool {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case(token))
}

fn is_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key(header::UPGRADE) && connection_has(headers, "upgrade")
}

/// Removes hop-by-hop and MagicPipes headers and adds forwarding headers.
fn prepare_request(
    req: &mut Request<Incoming>,
    host: &str,
    peer: SocketAddr,
    upgrade: bool,
    trusted: &TrustedProxies,
) -> Result<(), Response<ProxyBody>> {
    // Absolute-form -> origin-form.
    if req.uri().authority().is_some() {
        let pq = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/").to_string();
        *req.uri_mut() = pq.parse::<Uri>().map_err(|_| error_page(ErrorCode::BadUri, "Invalid request URI."))?;
    }
    let headers = req.headers_mut();
    let upgrade_value = headers.get(header::UPGRADE).cloned();
    strip_hop_by_hop(headers);
    let mp: Vec<HeaderName> = headers.keys().filter(|k| k.as_str().starts_with("x-magicpipes-")).cloned().collect();
    for k in mp {
        headers.remove(k);
    }
    if upgrade {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        if let Some(v) = upgrade_value {
            headers.insert(header::UPGRADE, v);
        }
    }
    trusted.rewrite(peer.ip(), headers);
    headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    if let Ok(v) = HeaderValue::from_str(host) {
        headers.insert("x-forwarded-host", v);
    }
    Ok(())
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let listed: Vec<String> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    for name in listed {
        if let Ok(h) = HeaderName::from_bytes(name.as_bytes()) {
            headers.remove(h);
        }
    }
    for h in HOP_BY_HOP {
        headers.remove(h);
    }
    headers.remove("keep-alive");
    headers.remove("proxy-connection");
}

fn clean_response_headers(headers: &mut HeaderMap, switching: bool) {
    let upgrade_value = headers.get(header::UPGRADE).cloned();
    strip_hop_by_hop(headers);
    let mp: Vec<HeaderName> = headers.keys().filter(|k| k.as_str().starts_with("x-magicpipes-")).cloned().collect();
    for k in mp {
        headers.remove(k);
    }
    if switching {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        if let Some(v) = upgrade_value {
            headers.insert(header::UPGRADE, v);
        }
    }
}

/// A response generated by MagicPipes (never by the application); tagged with `x-magicpipes-error`.
pub fn error_page(code: ErrorCode, message: &str) -> Response<ProxyBody> {
    let status = StatusCode::from_u16(code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    // The management UI's palette, without the rest of its styles: these pages can be requested by anyone.
    let body = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>{status}</title><style>
{PALETTE}body{{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px 16px;box-sizing:border-box;background:var(--bg);color:var(--ink);font:15px/1.55 ui-sans-serif,-apple-system,"Helvetica Neue",sans-serif}}
main{{width:min(520px,100%)}}.code{{margin:0;font:400 clamp(72px,18vw,112px)/1 ui-serif,"New York",Georgia,serif;letter-spacing:-.04em;color:var(--accent)}}
p{{margin:18px 0 0;font-size:19px}}.meta{{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);font-size:13.5px;color:var(--muted);display:flex;justify-content:space-between;gap:12px}}
code{{font:12.5px ui-monospace,"SF Mono",Menlo,monospace}}</style></head>
<body><main><h1 class="code">{}</h1><p>{message}</p><div class="meta"><span>MagicPipes</span><code>{code}</code></div></main></body></html>"#,
        status.as_u16()
    );
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(ERROR_HEADER, code.as_str())
        .body(Full::new(Bytes::from(body)).map_err(|never| match never {}).boxed())
        .expect("static response is valid")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::response_within;

    #[tokio::test]
    async fn uploads_count_as_progress() {
        let timeout = Duration::from_millis(200);
        // The answer comes 600 ms in, after an upload that kept sending until 450 ms.
        let (tx, rx) = tokio::sync::watch::channel(());
        tokio::spawn(async move {
            for _ in 0..9 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                tx.send_replace(());
            }
        });
        let answer = async {
            tokio::time::sleep(Duration::from_millis(600)).await;
            "ok"
        };
        assert_eq!(response_within(answer, rx, timeout).await, Some("ok"));

        // No upload and no answer: the wait ends after the timeout.
        let (_tx, rx) = tokio::sync::watch::channel(());
        assert_eq!(response_within(std::future::pending::<()>(), rx, timeout).await, None);
        // The body is finished: the application has the timeout to answer, no more.
        let (tx, rx) = tokio::sync::watch::channel(());
        drop(tx);
        let late = async {
            tokio::time::sleep(Duration::from_millis(400)).await;
        };
        assert_eq!(response_within(late, rx, timeout).await, None);
    }
}
