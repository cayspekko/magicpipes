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
use axum::routing::{get, post};
use http::{HeaderMap, HeaderValue, header};
use hyper::body::Incoming;
use hyper::service::service_fn;
use magicpipes_core::secret;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tower::ServiceExt;

use crate::control::ControlPlane;
use crate::listen::{ListenOpts, serve};

/// Remote address of the management connection, inserted into request extensions.
#[derive(Clone, Copy, Debug)]
pub struct PeerAddr(pub SocketAddr);

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
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/v1/status", get(api::status))
        .route("/api/v1/tunnels", get(api::list_tunnels))
        .route("/api/v1/tunnels/{id}", get(api::get_tunnel).delete(api::delete_tunnel))
        .route("/api/v1/agents", get(api::list_agents))
        .route("/api/v1/agents/{id}", axum::routing::delete(api::revoke_agent))
        .route("/api/v1/enrollments", post(api::create_enrollment))
        .route("/api/v1/enroll", post(api::enroll))
        .route(magicpipes_core::proto::AGENT_CONNECT_PATH, get(crate::gateway::connect))
        .layer(axum::middleware::map_response(security_headers))
        .with_state(state)
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
        HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"),
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
    let app = router(control);
    let opts = ListenOpts { name: "management", max_connections: 1024, header_read_timeout: Duration::from_secs(30) };
    serve(listener, Some(acceptor), opts, shutdown, tracker, move |conn| {
        let app = app.clone();
        let peer = conn.peer;
        service_fn(move |mut req: http::Request<Incoming>| {
            req.extensions_mut().insert(PeerAddr(peer));
            let app = app.clone();
            async move { Ok::<_, Infallible>(app.oneshot(req).await.unwrap_or_else(|e| match e {})) }
        })
    })
    .await
}

// ---- UI sessions -------------------------------------------------------------------------

const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
pub const SESSION_COOKIE: &str = "mp_session";

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

#[derive(Default)]
struct FailureLimiter {
    map: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl FailureLimiter {
    fn blocked(&self, ip: IpAddr) -> bool {
        let map = self.map.lock().unwrap();
        map.get(&ip).is_some_and(|(n, since)| *n >= MAX_FAILURES && since.elapsed() < FAILURE_WINDOW)
    }

    fn fail(&self, ip: IpAddr) {
        let mut map = self.map.lock().unwrap();
        if map.len() > 10_000 {
            map.retain(|_, (_, since)| since.elapsed() < FAILURE_WINDOW);
        }
        let e = map.entry(ip).or_insert((0, Instant::now()));
        if e.1.elapsed() >= FAILURE_WINDOW {
            *e = (0, Instant::now());
        }
        e.0 += 1;
    }
}
