//! HTTP/1.1 reverse proxy over agent data streams.
//!
//! For each public request: resolve the route, open a yamux stream on the owning agent's session,
//! announce the tunnel id, run a fresh HTTP/1.1 client connection over the stream and forward the
//! request. Bodies stream in both directions (hyper `Incoming` is passed through untouched).
//! `Upgrade` requests (WebSockets) are bridged as raw byte streams after the `101` response.

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
use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::{self, ERROR_HEADER, PROBE_ACK_HEADER, PROBE_HEADER, ServerOpen};
use tokio_util::sync::CancellationToken;

use super::gate;
use super::io::{StatusPrefixed, UpstreamStatus, bridge, find_status};
use super::{DataPlane, Outcome, Route};
use crate::authz::Principal;
use crate::forwarded::{TrustedProxies, client_key};
use crate::listen::ConnInfo;

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

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
    if let Some(a) = &admitted {
        // The application learns who is asking, never the tunnel cookie. Clients can't forge
        // these: `prepare_request` dropped every client-sent x-magicpipes-* header.
        gate::strip_cookies(req.headers_mut());
        let h = req.headers_mut();
        if let (Ok(email), Ok(id)) = (HeaderValue::from_str(&a.user.email), HeaderValue::from_str(&a.user_id)) {
            h.insert("x-magicpipes-user", email);
            h.insert("x-magicpipes-user-id", id);
        }
    }

    let upstream = open_upstream(dp, &route, &session, client).await?;
    // An upgraded connection outlives this HTTP connection; it keeps the listener's limits.
    let limits = conn.limits.clone();
    let (progress, uploading) = tokio::sync::watch::channel(());
    let req = req.map(|inner| Progress { inner, progress });
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Progress<Incoming>>(TokioIo::new(upstream))
        .await
        .map_err(|_| upstream_error(&route, UpstreamStatus::Closed))?;
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::debug!(error = %e, "upstream connection ended");
        }
    });

    let mut resp = match response_within(sender.send_request(req), uploading, dp.settings.upstream_response_timeout).await {
        Some(Ok(resp)) => resp,
        Some(Err(e)) => {
            let status = find_status(&e).unwrap_or(UpstreamStatus::Closed);
            return Err(upstream_error(&route, status));
        }
        None => {
            route.stats.record(Outcome::LocalUnreachable);
            return Err(error_page(
                ErrorCode::UpstreamTimeout,
                "The local application did not respond in time.",
            ));
        }
    };
    route.stats.record(Outcome::Ok);

    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        let Some(client_upgrade) = client_upgrade else {
            return Err(error_page(ErrorCode::BadUpstream, "Unexpected protocol switch."));
        };
        let upstream_upgrade = hyper::upgrade::on(&mut resp);
        let idle = dp.settings.websocket_idle_timeout;
        let stop = CancellationToken::new();
        if let Some(a) = admitted {
            // Recheck on every change to routes, users or tags; close once access is gone.
            let (dp, stop, host) = (dp.clone(), stop.clone(), host.clone());
            let mut changes = dp.generation.subscribe();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = stop.cancelled() => return,
                        changed = changes.changed() => {
                            if changed.is_err() || !gate::still_admitted(&dp.table(), &host, &a.user_id, a.issued_at) {
                                stop.cancel();
                                return;
                            }
                        }
                    }
                }
            });
        }
        tokio::spawn(async move {
            match tokio::try_join!(client_upgrade, upstream_upgrade) {
                Ok((client, upstream)) => bridge(TokioIo::new(client), TokioIo::new(upstream), idle, stop.clone()).await,
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
    if let Some(nonce) = probe
        && let Ok(v) = HeaderValue::from_str(&format!("{} {}", route.tunnel_id, nonce)) {
            resp.headers_mut().insert(PROBE_ACK_HEADER, v);
        }
    Ok(resp.map(|b| b.boxed()))
}

/// A request body that reports each chunk it passes on, so a long upload counts as progress.
struct Progress<B> {
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
    let mut stream = match session.open_data(dp.settings.stream_open_timeout, client).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            return Err(error_page(
                ErrorCode::AgentBusy,
                "This tunnel is handling too many connections. Try again shortly.",
            ));
        }
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
    // Same palette and type as the management UI, kept self-contained.
    let body = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>{status}</title><style>
:root{{--bg:#f6f4ef;--ink:#1d1c1a;--muted:#7a766d;--line:#e6e1d6;--accent:#c2562b}}
@media (prefers-color-scheme:dark){{:root{{--bg:#131312;--ink:#ece9e2;--muted:#8e8a82;--line:#2a2927;--accent:#ec7a4b}}}}
body{{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px 16px;box-sizing:border-box;background:var(--bg);color:var(--ink);font:16px/1.55 ui-sans-serif,-apple-system,"Helvetica Neue",sans-serif}}
main{{width:min(520px,100%)}}.code{{font:400 clamp(72px,18vw,112px)/1 ui-serif,"New York",Georgia,serif;letter-spacing:-.04em;color:var(--accent)}}
p{{margin:18px 0 0;font-size:18px}}.meta{{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);font-size:13px;color:var(--muted);display:flex;justify-content:space-between;gap:12px}}
code{{font:12.5px ui-monospace,"SF Mono",Menlo,monospace}}</style></head>
<body><main><div class="code">{}</div><p>{message}</p><div class="meta"><span>MagicPipes</span><code>{code}</code></div></main></body></html>"#,
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
