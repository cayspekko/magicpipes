//! HTTP/1.1 reverse proxy over agent data streams.
//!
//! For each public request: resolve the route, open a yamux stream on the owning agent's session,
//! announce the tunnel id, run a fresh HTTP/1.1 client connection over the stream and forward the
//! request. Bodies stream in both directions (hyper `Incoming` is passed through untouched).
//! `Upgrade` requests (WebSockets) are bridged as raw byte streams after the `101` response.

// Error pages are returned by value through `Result<_, Response>` on purpose.
#![allow(clippy::result_large_err)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use magicpipes_core::proto::{self, ERROR_HEADER, PROBE_ACK_HEADER, PROBE_HEADER, ServerOpen};

use super::io::{StatusPrefixed, UpstreamStatus, bridge, find_status};
use super::{DataPlane, Outcome, Route};
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

async fn proxy(dp: &DataPlane, conn: &ConnInfo, mut req: Request<Incoming>) -> Result<Response<ProxyBody>, Response<ProxyBody>> {
    if req.method() == Method::CONNECT {
        return Err(error_page(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed", "CONNECT is not supported."));
    }
    let host = request_host(&req)
        .ok_or_else(|| error_page(StatusCode::BAD_REQUEST, "bad_host", "Missing or invalid Host header."))?;
    // The certificate presented was chosen by SNI; never serve another tunnel's hostname on it.
    if conn.sni.as_deref().is_some_and(|sni| sni != host) {
        return Err(error_page(StatusCode::MISDIRECTED_REQUEST, "misdirected_request", "Host does not match the TLS server name."));
    }
    let route = dp
        .lookup(&host)
        .ok_or_else(|| error_page(StatusCode::NOT_FOUND, "tunnel_not_found", "There is no tunnel at this address."))?;

    let session = match &route.session {
        Some(s) if !s.is_closed() => s.clone(),
        _ => {
            route.stats.record(Outcome::AgentOffline);
            return Err(error_page(
                StatusCode::BAD_GATEWAY,
                "agent_offline",
                "The MagicPipes agent serving this tunnel is not connected.",
            ));
        }
    };

    let probe = take_probe_nonce(req.headers_mut());
    let upgrade = is_upgrade(req.headers());
    let client_upgrade = upgrade.then(|| hyper::upgrade::on(&mut req));
    prepare_request(&mut req, &host, conn.peer, upgrade)?;

    let upstream = open_upstream(dp, &route, &session).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Incoming>(TokioIo::new(upstream))
        .await
        .map_err(|_| upstream_error(&route, UpstreamStatus::Closed))?;
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::debug!(error = %e, "upstream connection ended");
        }
    });

    let mut resp = match tokio::time::timeout(dp.settings.upstream_response_timeout, sender.send_request(req)).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            let status = find_status(&e).unwrap_or(UpstreamStatus::Closed);
            return Err(upstream_error(&route, status));
        }
        Err(_) => {
            route.stats.record(Outcome::LocalUnreachable);
            return Err(error_page(
                StatusCode::GATEWAY_TIMEOUT,
                "upstream_timeout",
                "The local application did not respond in time.",
            ));
        }
    };
    route.stats.record(Outcome::Ok);

    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        let Some(client_upgrade) = client_upgrade else {
            return Err(error_page(StatusCode::BAD_GATEWAY, "bad_upstream", "Unexpected protocol switch."));
        };
        let upstream_upgrade = hyper::upgrade::on(&mut resp);
        let idle = dp.settings.websocket_idle_timeout;
        tokio::spawn(async move {
            match tokio::try_join!(client_upgrade, upstream_upgrade) {
                Ok((client, upstream)) => bridge(TokioIo::new(client), TokioIo::new(upstream), idle).await,
                Err(e) => tracing::debug!(error = %e, "upgrade failed"),
            }
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

async fn open_upstream(
    dp: &DataPlane,
    route: &Route,
    session: &magicpipes_core::mux::MuxHandle,
) -> Result<StatusPrefixed<magicpipes_core::mux::MuxStream>, Response<ProxyBody>> {
    let fail = || {
        route.stats.record(Outcome::AgentOffline);
        error_page(StatusCode::BAD_GATEWAY, "agent_unavailable", "Could not open a stream to the MagicPipes agent.")
    };
    let mut stream = session.open(dp.settings.stream_open_timeout).await.map_err(|_| fail())?;
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
                StatusCode::BAD_GATEWAY,
                "local_unreachable",
                "The tunnel is connected, but the local application is not accepting connections.",
            )
        }
        UpstreamStatus::UnknownTunnel => {
            route.stats.record(Outcome::AgentOffline);
            error_page(StatusCode::BAD_GATEWAY, "tunnel_inactive", "The agent no longer serves this tunnel.")
        }
        _ => {
            route.stats.record(Outcome::LocalUnreachable);
            error_page(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
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
fn prepare_request(req: &mut Request<Incoming>, host: &str, peer: SocketAddr, upgrade: bool) -> Result<(), Response<ProxyBody>> {
    // Absolute-form -> origin-form.
    if req.uri().authority().is_some() {
        let pq = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/").to_string();
        *req.uri_mut() = pq.parse::<Uri>().map_err(|_| error_page(StatusCode::BAD_REQUEST, "bad_uri", "Invalid request URI."))?;
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
    let ip = peer.ip().to_canonical().to_string();
    let xff = match headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        Some(prev) => format!("{prev}, {ip}"),
        None => ip,
    };
    if let Ok(v) = HeaderValue::from_str(&xff) {
        headers.insert("x-forwarded-for", v);
    }
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
pub fn error_page(status: StatusCode, code: &'static str, message: &str) -> Response<ProxyBody> {
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
        .header(ERROR_HEADER, code)
        .body(Full::new(Bytes::from(body)).map_err(|never| match never {}).boxed())
        .expect("static response is valid")
}
