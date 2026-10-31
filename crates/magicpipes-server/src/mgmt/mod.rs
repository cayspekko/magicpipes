//! Management listener: JSON API, server-rendered UI and the agent endpoint.
//!
//! Authentication boundaries:
//! * `/api/v1/*` (except enroll/agent connect): `Authorization: Bearer <admin token>`.
//! * UI pages: session cookie created by logging in with an admin token; state-changing forms
//!   carry a per-session CSRF token.
//! * `/api/v1/enroll`: a single-use enrollment token in the body.
//! * `/api/v1/agent/connect`: `Authorization: Bearer <agent token>`.

mod api;
mod ui;

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use hyper::body::Incoming;
use hyper::service::service_fn;
use magicpipes_core::secret;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tower::ServiceExt;

use crate::control::ControlPlane;
use crate::forwarded::client_key;
use crate::listen::{ListenOpts, serve};

/// Remote address of the management connection, inserted into request extensions.
#[derive(Clone, Copy, Debug)]
pub struct PeerAddr(pub SocketAddr);

/// The client's address: the peer, or what a trusted proxy reported (`trusted_proxies`).
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub IpAddr);

#[derive(Clone)]
pub struct AppState {
    pub control: Arc<ControlPlane>,
    sessions: Arc<UiSessions>,
    limiter: Arc<FailureLimiter>,
}

pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

pub fn router(control: Arc<ControlPlane>) -> Router {
    let state = AppState {
        control,
        sessions: Arc::new(UiSessions::default()),
        limiter: Arc::new(FailureLimiter::default()),
    };
    Router::new()
        .route("/", get(ui::index))
        .route("/login", get(ui::login_form).post(ui::login))
        .route("/logout", post(ui::logout))
        .route("/tunnels/{id}", get(ui::tunnel_detail))
        .route("/tunnels/{id}/delete", post(ui::delete_tunnel))
        .route("/agents/{id}/revoke", post(ui::revoke_agent))
        .route("/enrollments", post(ui::create_enrollment))
        .route("/ui.js", get(ui::script))
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/v1/status", get(api::status))
        .route("/api/v1/tunnels", get(api::list_tunnels))
        .route("/api/v1/tunnels/{id}", get(api::get_tunnel).delete(api::delete_tunnel))
        .route("/api/v1/agents", get(api::list_agents))
        .route("/api/v1/agents/{id}", axum::routing::delete(api::revoke_agent))
        .route("/api/v1/enrollments", post(api::create_enrollment))
        .route("/api/v1/enroll", post(api::enroll))
        .route(magicpipes_core::proto::AGENT_CONNECT_PATH, get(crate::gateway::connect))
        .layer(axum::middleware::from_fn(request_deadline))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        .layer(axum::middleware::from_fn_with_state(state.clone(), require_host))
        .layer(axum::middleware::map_response(security_headers))
        .with_state(state)
}

/// Management requests and forms are small.
const MAX_BODY: usize = 64 * 1024;
/// Time allowed for a whole request, body included. hyper only bounds the headers, so without
/// this a client that announces a body and never sends it would hold a connection forever.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Applies [`REQUEST_TIMEOUT`] to every request except the agent upgrade, which is long-lived.
async fn request_deadline(req: Request, next: Next) -> axum::response::Response {
    if req.uri().path() == magicpipes_core::proto::AGENT_CONNECT_PATH {
        return next.run(req).await;
    }
    match tokio::time::timeout(REQUEST_TIMEOUT, next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => (StatusCode::REQUEST_TIMEOUT, [(header::CONNECTION, "close")], "Request timed out.\n").into_response(),
    }
}

/// Requests must name the management hostname (the TLS layer already refuses other SNI names;
/// this also covers a mismatched Host header on a valid connection).
async fn require_host(State(app): State<AppState>, req: Request, next: Next) -> axum::response::Response {
    let host = req.uri().authority().map(|a| a.host().to_string()).or_else(|| {
        let h = req.headers().get(header::HOST)?.to_str().ok()?;
        h.parse::<http::uri::Authority>().ok().map(|a| a.host().to_string())
    });
    let expected = &app.control.config().management.hostname;
    if host.is_some_and(|h| h.trim_end_matches('.').eq_ignore_ascii_case(expected)) {
        next.run(req).await
    } else {
        (StatusCode::MISDIRECTED_REQUEST, "This server's management interface is not served at this address.\n").into_response()
    }
}

async fn security_headers(mut resp: axum::response::Response) -> axum::response::Response {
    let h = resp.headers_mut();
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000"));
    h.entry(header::CACHE_CONTROL).or_insert(HeaderValue::from_static("no-store"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"),
    );
    resp
}

pub async fn serve_mgmt(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    control: Arc<ControlPlane>,
    shutdown: CancellationToken,
    tracker: TaskTracker,
) {
    let cfg = control.config();
    let trusted = cfg.trusted_proxies();
    let opts = ListenOpts {
        name: "management",
        max_connections: 1024,
        max_per_client: 64,
        header_read_timeout: Duration::from_secs(30),
        trusted_proxies: trusted.clone(),
        proxy_protocol: cfg.management.proxy_protocol,
    };
    let app = router(control);
    serve(listener, Some(acceptor), opts, shutdown, tracker, move |conn| {
        let app = app.clone();
        let peer = conn.peer;
        let trusted = trusted.clone();
        service_fn(move |mut req: http::Request<Incoming>| {
            let client = trusted.client_ip(peer.ip(), req.headers());
            req.extensions_mut().insert(PeerAddr(peer));
            req.extensions_mut().insert(ClientIp(client));
            let app = app.clone();
            async move { Ok::<_, Infallible>(app.oneshot(req).await.unwrap_or_else(|e| match e {})) }
        })
    })
    .await
}

// ---- UI sessions -------------------------------------------------------------------------

const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
/// `__Host-`: browsers only accept it from this exact host, Secure, with `Path=/` and no
/// `Domain`, so content on a tunnel subdomain cannot set or shadow it.
pub const SESSION_COOKIE: &str = "__Host-mp_session";

struct UiSession {
    csrf: String,
    expires: Instant,
}

#[derive(Default)]
struct UiSessions {
    // Keyed by SHA-256 of the cookie value.
    map: Mutex<HashMap<String, UiSession>>,
}

impl UiSessions {
    /// Returns `(cookie value, csrf token)`.
    fn create(&self) -> (String, String) {
        let cookie = secret::random_string(43);
        let csrf = secret::random_string(32);
        let mut map = self.map.lock().unwrap();
        map.retain(|_, s| s.expires > Instant::now());
        map.insert(secret::sha256_hex(&cookie), UiSession { csrf: csrf.clone(), expires: Instant::now() + SESSION_TTL });
        (cookie, csrf)
    }

    /// Returns the CSRF token for a valid session cookie.
    fn csrf_for(&self, cookie: &str) -> Option<String> {
        let map = self.map.lock().unwrap();
        map.get(&secret::sha256_hex(cookie)).filter(|s| s.expires > Instant::now()).map(|s| s.csrf.clone())
    }

    fn remove(&self, cookie: &str) {
        self.map.lock().unwrap().remove(&secret::sha256_hex(cookie));
    }
}

// ---- brute-force limiter -----------------------------------------------------------------

const MAX_FAILURES: u32 = 10;
const FAILURE_WINDOW: Duration = Duration::from_secs(300);
const MAX_TRACKED: usize = 10_000;

/// Failed credential checks per client. Every credential carries at least 192 bits, so this
/// sheds load from guessing rather than protecting the secret: callers check credentials first,
/// and valid ones are accepted even from a blocked address, so nobody can lock an admin out.
#[derive(Default)]
struct FailureLimiter {
    map: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl FailureLimiter {
    /// Records a failed attempt; `true` when the client was already over the limit.
    fn reject(&self, ip: Option<IpAddr>) -> bool {
        let Some(ip) = ip.map(client_key) else { return false };
        let mut map = self.map.lock().unwrap();
        if map.len() >= MAX_TRACKED && !map.contains_key(&ip) {
            map.retain(|_, (_, since)| since.elapsed() < FAILURE_WINDOW);
            if map.len() >= MAX_TRACKED {
                let oldest = map.iter().min_by_key(|(_, (_, since))| *since).map(|(k, _)| *k);
                oldest.map(|k| map.remove(&k));
            }
        }
        let e = map.entry(ip).or_insert((0, Instant::now()));
        if e.1.elapsed() >= FAILURE_WINDOW {
            *e = (0, Instant::now());
        }
        e.0 = e.0.saturating_add(1);
        e.0 > MAX_FAILURES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_blocks_per_client_and_per_ipv6_prefix() {
        let l = FailureLimiter::default();
        let a: IpAddr = "203.0.113.9".parse().unwrap();
        for _ in 0..MAX_FAILURES {
            assert!(!l.reject(Some(a)));
        }
        assert!(l.reject(Some(a)));
        assert!(!l.reject(Some("203.0.113.10".parse().unwrap())));
        for i in 0..MAX_FAILURES {
            assert!(!l.reject(Some(format!("2001:db8::{i:x}").parse().unwrap())));
        }
        assert!(l.reject(Some("2001:db8::ffff:1".parse().unwrap())), "same /64");
        assert!(!l.reject(None));
    }

    #[test]
    fn limiter_memory_is_bounded() {
        let l = FailureLimiter::default();
        for i in 0..(MAX_TRACKED as u32 + 50) {
            l.reject(Some(IpAddr::from(i.to_be_bytes())));
        }
        assert!(l.map.lock().unwrap().len() <= MAX_TRACKED);
    }
}
