//! Management listener: JSON API, server-rendered UI and the agent endpoint.
//!
//! Authentication boundaries:
//! * `/api/v1/*` (except enroll/agent connect): `Authorization: Bearer <admin token or a user's
//!   API token>`.
//! * `/metrics`: the same bearer token, or a UI session; administrators only.
//! * UI pages: session cookie created by logging in with an email and password, an emailed link, an
//!   OpenID Connect provider, an authenticating proxy or an admin token; state-changing forms carry
//!   a per-session CSRF token.
//!
//! What each caller may do is decided by `authz::authorize`, in the control plane.
//! * `/api/v1/enroll`: a single-use enrollment token in the body.
//! * `/api/v1/agent/connect`: `Authorization: Bearer <agent token>`.

mod accounts;
mod api;
mod certificates;
mod chart;
mod codes;
mod desktop;
mod email;
mod extract;
mod health;
mod html;
mod icons;
mod machine;
mod notify;
mod novnc;
mod oidc;
mod picker;
mod proxy_auth;
mod settings;
mod ssh;
mod terminal;
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
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_util::task::{AbortOnDropHandle, TaskTracker};
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
    limiter: Arc<FailureLimiter>,
}

/// Why a presented credential was refused.
pub enum Rejected<E> {
    Invalid(E),
    /// Too many failed attempts from this client.
    RateLimited,
}

impl AppState {
    /// Should a password login from this client be refused before it is checked?
    fn password_blocked(&self, client: Option<IpAddr>) -> bool {
        self.limiter.over_limit(client)
    }

    /// The one sequence for every presented credential. A valid one is accepted even from a
    /// rate-limited client, so nobody can lock an administrator out; an invalid one counts
    /// against the client, which is refused once it is over the limit.
    fn check_credential<T, E>(&self, checked: Result<T, E>, client: Option<IpAddr>) -> Result<T, Rejected<E>> {
        match checked {
            Ok(v) => Ok(v),
            Err(_) if self.limiter.reject(client) => Err(Rejected::RateLimited),
            Err(e) => Err(Rejected::Invalid(e)),
        }
    }
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
    let state = AppState { control, limiter: Arc::new(FailureLimiter::default()) };
    let mut router = Router::new();
    for (path, body, kind) in ui::ICONS {
        router = router.route(path, get(move || async move { ui::icon(body, kind) }));
    }
    router
        .route("/", get(ui::index))
        .route("/login", get(ui::login_form).post(ui::login))
        .route("/login/email", get(email::ask_form).post(email::ask))
        .route("/login/link", get(email::link_form).post(email::use_link))
        .route("/login/code", get(codes::code_form).post(codes::use_code))
        .route("/invite", get(email::invitation_form).post(email::open_invitation))
        .route("/invite/accept", post(email::accept_invitation))
        .route("/invite/provider/{id}", post(email::invitation_provider))
        .route("/logout", post(ui::logout))
        .route("/signed-out", get(ui::signed_out))
        .route("/machines", get(ui::machines))
        .route("/machines/{id}", get(machine::machine))
        .route("/health", get(health::health))
        .route("/tunnels/{id}", get(ui::tunnel_detail))
        .route("/tunnels/{id}/delete", post(ui::delete_tunnel))
        .route("/tunnels/{id}/host-key/forget", post(terminal::forget_host_key))
        .route("/terminal/{name}", get(terminal::page))
        .route("/terminal/{name}/ws", get(terminal::socket))
        .route("/desktop/{name}", get(desktop::page))
        .route("/desktop/{name}/ws", get(desktop::socket))
        .route("/assets/desktop/{version}/{file}", get(desktop::asset))
        .route("/assets/vnc/{version}/{*path}", get(desktop::vnc_asset))
        .route("/assets/terminal/{file}", get(terminal::asset))
        .route("/agents/{id}/revoke", post(ui::revoke_agent))
        .route("/agents/{id}/tags", get(ui::agent_tags_page).post(ui::agent_tags))
        .route("/tags", get(accounts::tags).post(accounts::create_tag))
        .route("/tags/delete", post(accounts::delete_tag))
        .route("/tags/access", post(accounts::tag_access))
        .route("/tags/rules", post(accounts::create_tag_rule))
        .route("/tags/rules/{id}/delete", post(accounts::delete_tag_rule))
        .route("/hostnames", get(accounts::hostnames).post(accounts::create_hostname))
        .route("/hostnames/delete", post(accounts::delete_hostname))
        .route("/enrollments", post(ui::create_enrollment))
        .route("/password", get(accounts::password_form).post(accounts::change_password))
        .route("/account", get(accounts::account))
        .route("/account/codes", get(codes::codes).post(codes::turn_on))
        .route("/account/codes/recovery", post(codes::new_recovery_codes))
        .route("/account/codes/off", post(codes::turn_off))
        .route("/account/tokens", post(accounts::create_token))
        .route("/account/tokens/{id}/delete", post(accounts::delete_token))
        .route("/account/logout-everywhere", post(accounts::logout_everywhere))
        .route("/account/ssh-keys", post(ssh::add_key))
        .route("/account/ssh-keys/{id}/delete", post(ssh::delete_key))
        .route("/account/address", post(email::request_confirmation))
        .route("/account/alerts", post(notify::save_alert_email))
        .route("/account/address/confirm", get(email::confirm_form).post(email::confirm))
        .route("/users", get(accounts::users).post(accounts::create_user))
        .route("/invitations/{id}/resend", post(accounts::resend_invitation))
        .route("/invitations/{id}/revoke", post(accounts::revoke_invitation))
        .route("/users/{id}", post(accounts::update_user))
        .route("/users/{id}/tags", get(accounts::user_tags_page).post(accounts::user_tags))
        .route("/audit", get(accounts::audit))
        .route("/settings", get(settings::settings))
        .route("/settings/export", get(settings::export))
        .route("/settings/sign-in", post(settings::save_rules))
        .route("/settings/providers/new", get(settings::new_provider).post(settings::create_provider))
        .route("/settings/providers/{id}", get(settings::edit_provider).post(settings::update_provider))
        .route("/settings/providers/{id}/delete", post(settings::delete_provider))
        .route("/settings/email", get(email::email_form).post(email::save_email))
        .route("/settings/email/delete", post(email::delete_email))
        .route("/settings/email/test", post(email::test_email))
        .route("/settings/webhooks", post(notify::create_webhook))
        .route("/settings/webhooks/new", get(notify::new_webhook))
        .route("/settings/webhooks/{id}/delete", post(notify::delete_webhook))
        .route("/settings/webhooks/{id}/test", post(notify::test_webhook))
        .route("/settings/certificates/new", get(certificates::new_certificate).post(certificates::add_certificate))
        .route("/settings/certificates/{id}/delete", post(certificates::delete_certificate))
        .route("/cli", get(accounts::device).post(accounts::answer_device))
        .route("/auth/tunnel", get(accounts::auth_tunnel))
        .route("/auth/oidc/{id}", get(oidc::start))
        .route("/auth/oidc/{id}/callback", get(oidc::callback))
        .route("/ui.js", get(ui::script))

        .route("/healthz", get(|| async { "ok" }))
        .route("/metrics", get(api::metrics))
        .route("/api/v1/status", get(api::status))
        .route("/api/v1/tunnels", get(api::list_tunnels))
        .route("/api/v1/shared", get(api::shared_tunnels))
        .route("/api/v1/tunnels/{id}", get(api::get_tunnel).delete(api::delete_tunnel))
        .route("/api/v1/probes", post(api::report_probes))
        .route("/api/v1/agents", get(api::list_agents))
        .route("/api/v1/agents/{id}", axum::routing::delete(api::revoke_agent).patch(api::update_agent))
        .route("/api/v1/tags", get(api::list_tags).post(api::create_tag))
        .route("/api/v1/tags/{name}", axum::routing::delete(api::delete_tag).patch(api::update_tag))
        .route("/api/v1/tag-rules", get(api::list_tag_rules).post(api::create_tag_rule))
        .route("/api/v1/tag-rules/{id}", axum::routing::delete(api::delete_tag_rule))
        .route("/api/v1/hostnames", get(api::list_hostnames).post(api::create_hostname))
        .route("/api/v1/hostnames/{hostname}", axum::routing::delete(api::delete_hostname))
        .route("/api/v1/enrollments", post(api::create_enrollment))
        .route("/api/v1/me", get(api::me))
        .route("/api/v1/users", get(api::list_users).post(api::create_user))
        .route("/api/v1/users/{id}", get(api::get_user).patch(api::update_user))
        .route("/api/v1/users/{id}/password", post(api::reset_password))
        .route("/api/v1/users/{id}/tokens", axum::routing::delete(api::revoke_user_tokens))
        .route("/api/v1/invitations", get(api::list_invitations).post(api::create_invitation))
        .route("/api/v1/invitations/{id}", axum::routing::delete(api::delete_invitation))
        .route("/api/v1/invitations/{id}/resend", post(api::resend_invitation))
        .route("/api/v1/tokens", get(api::list_tokens).post(api::create_token))
        .route("/api/v1/tokens/{id}", axum::routing::delete(api::delete_token))
        .route("/api/v1/ssh-keys", get(api::list_ssh_keys).post(api::add_ssh_key))
        .route("/api/v1/ssh-keys/{id}", axum::routing::delete(api::delete_ssh_key))
        .route("/api/v1/ssh-ca", get(api::ssh_ca))
        .route("/api/v1/audit", get(api::audit))
        .route("/api/v1/enroll", post(api::enroll))
        .route("/api/v1/device", post(api::start_device))
        .route("/api/v1/device/poll", post(api::poll_device))
        .route("/api/v1/passes", post(api::create_pass))
        .route("/api/v1/passes/device", post(api::start_pass_sign_in))
        .route("/api/v1/connect/{name}", get(api::connect))
        .route(magicpipes_core::proto::AGENT_CONNECT_PATH, get(crate::gateway::connect))
        .fallback(ui::not_found)
        .layer(axum::middleware::from_fn_with_state(state.clone(), proxy_auth::identify))
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
    // The terminal page sets its own, which also allows its WebSocket, fonts and stylesheet.
    h.entry(header::CONTENT_SECURITY_POLICY).or_insert(HeaderValue::from_static(
        "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self'; frame-ancestors 'none'",
    ));
    resp
}

pub async fn serve_mgmt(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    control: Arc<ControlPlane>,
    control_rt: tokio::runtime::Handle,
    shutdown: CancellationToken,
    tracker: TaskTracker,
) {
    let cfg = control.config();
    let trusted = cfg.trusted_proxies();
    let opts = ListenOpts {
        name: "management",
        max_connections: cfg.management.max_connections.max(1),
        max_per_client: cfg.management.max_connections_per_client.max(1),
        header_read_timeout: Duration::from_secs(30),
        trusted_proxies: trusted.clone(),
        proxy_protocol: cfg.management.proxy_protocol,
        // Requests here have their own deadline, and an agent's session stops being HTTP.
        idle_timeout: None,
    };
    let app = router(control);
    serve(listener, Some(acceptor), opts, shutdown, tracker, move |conn| {
        let app = app.clone();
        let peer = conn.peer;
        let trusted = trusted.clone();
        let control_rt = control_rt.clone();
        service_fn(move |mut req: http::Request<Incoming>| {
            let client = trusted.client_ip(peer.ip(), req.headers());
            req.extensions_mut().insert(PeerAddr(peer));
            req.extensions_mut().insert(ClientIp(client));
            // The connection stays on the traffic threads, with every agent's session. Handlers
            // block on the database, so they run on the control plane's threads.
            let handler = AbortOnDropHandle::new(control_rt.spawn(app.clone().oneshot(req)));
            async move {
                Ok::<_, Infallible>(match handler.await {
                    Ok(resp) => resp.unwrap_or_else(|e| match e {}),
                    Err(e) => {
                        tracing::error!(error = %e, "a management request failed");
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    }
                })
            }
        })
    })
    .await
}

// ---- UI sessions -------------------------------------------------------------------------

/// `__Host-`: browsers only accept it from this exact host, Secure, with `Path=/` and no
/// `Domain`, so content on a tunnel subdomain cannot set or shadow it. Sessions live in the
/// database (`control::users`).
pub const SESSION_COOKIE: &str = "__Host-mp_session";

// ---- brute-force limiter -----------------------------------------------------------------

const MAX_FAILURES: u32 = 10;
const FAILURE_WINDOW: Duration = Duration::from_secs(300);
const MAX_TRACKED: usize = 10_000;

/// Failed credential checks per client. Admin and API tokens carry at least 192 bits, so for
/// them this sheds load from guessing rather than protecting the secret: callers check them
/// first, and valid ones are accepted even from a blocked address, so nobody can lock an admin
/// out. Passwords are guessable, so a blocked client's password logins are refused before they
/// are hashed (`over_limit`).
#[derive(Default)]
struct FailureLimiter {
    map: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl FailureLimiter {
    /// Is the client over the limit? Records nothing.
    fn over_limit(&self, ip: Option<IpAddr>) -> bool {
        let Some(ip) = ip.map(client_key) else { return false };
        let map = self.map.lock().unwrap();
        map.get(&ip).is_some_and(|(n, since)| *n >= MAX_FAILURES && since.elapsed() < FAILURE_WINDOW)
    }

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
        assert!(l.over_limit(Some(a)));
        assert!(l.reject(Some(a)));
        assert!(!l.over_limit(Some("203.0.113.10".parse().unwrap())));
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
