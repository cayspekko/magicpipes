//! Browser SSH terminals on the management host: the page, its vendored files, and the WebSocket,
//! which is checked here and served on the traffic threads (`data::terminal`).

use std::sync::OnceLock;

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use hyper_util::rt::TokioIo;
use magicpipes_core::terminal;
use magicpipes_core::theme::{GLYPH, STYLE};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};

use super::extract::{NoFields, Posted, UiUser};
use super::html::esc;
use super::ui::{Done, not_there, outcome, server_url};
use super::{AppState, ClientIp};
use crate::data::terminal::{Opening, run};

/// Where the page's files are served.
pub(super) const ASSETS: &str = "/assets/terminal";
/// Largest message accepted from the browser: keystrokes and pastes.
const MAX_MESSAGE: usize = 1024 * 1024;

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self'; \
                   img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// The address of the terminal for an SSH tunnel.
pub(super) fn href(name: &str) -> String {
    format!("/terminal/{name}")
}

/// A guess at someone's user name on a machine, for the form's placeholder.
fn guess(email: &str) -> String {
    let local = email.split('@').next().unwrap_or_default();
    let name: String = local.chars().filter(|c| c.is_ascii_alphanumeric() || "._-".contains(*c)).take(32).collect();
    if name.is_empty() { "you".into() } else { name.to_ascii_lowercase() }
}

pub async fn page(user: UiUser, State(app): State<AppState>, Path(name): Path<String>) -> Response {
    let Some(t) = app.control.terminal(&user.who, &name) else {
        return not_there(&user, "/", "Tunnels", "There's no SSH tunnel by that name that you can reach.");
    };
    let address = app.control.config().ssh_address().unwrap_or_default();
    let html = format!(
        r##"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><meta name="referrer" content="no-referrer"><title>{name} · MagicPipes</title>
<link rel="stylesheet" href="{ASSETS}/xterm.css"><style>{STYLE}{term_style}</style></head>
<body data-access="login" data-ws="/terminal/{name}/ws">
<header class="top"><div class="top-in"><h1 class="brand"><a href="/" aria-label="Back to your tunnels">{GLYPH}</a>{name}</h1>
<div class="side"><span class="status" id="st" role="status">Not connected</span><span class="badge rw" id="mode">SSH</span></div></div></header>
<main class="tm">
<div class="cmd"><form class="login" id="login"><label for="ln">Log in as</label><input id="ln" type="text" name="login" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="32" pattern="[A-Za-z0-9._][A-Za-z0-9._\-]*" placeholder="{guess}" required><button class="btn primary" id="ln-go">Connect</button></form><span class="hint">Your own session, as {email}</span></div>
<div class="screen"><div id="t"></div><div class="notice" id="nt" hidden><span id="nt-text"></span><button class="btn" id="nt-btn" type="button"></button></div></div>
<noscript><p class="note">The terminal needs JavaScript. Without it, use <code>ssh -J {address} {name}</code>.</p></noscript>
</main>
<script type="module" src="{ASSETS}/page.mjs"></script>
</body></html>"##,
        name = esc(&t.name),
        term_style = terminal::style(ASSETS),
        guess = esc(&guess(&t.email)),
        email = esc(&t.email),
        address = esc(&address),
    );
    let mut resp = Response::new(Body::from(html));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    resp
}

/// The page's vendored files and its script. They're public: anyone can get xterm.js.
pub async fn asset(Path(file): Path<String>) -> Response {
    static SCRIPT: OnceLock<String> = OnceLock::new();
    let (body, kind): (Body, &str) = match file.as_str() {
        "page.mjs" => (Body::from(SCRIPT.get_or_init(|| terminal::script(ASSETS)).as_str()), "text/javascript; charset=utf-8"),
        "xterm.mjs" => (Body::from(terminal::XTERM_JS), "text/javascript; charset=utf-8"),
        "addon-fit.mjs" => (Body::from(terminal::FIT_JS), "text/javascript; charset=utf-8"),
        "addon-unicode11.mjs" => (Body::from(terminal::UNICODE11_JS), "text/javascript; charset=utf-8"),
        "xterm.css" => (Body::from(terminal::XTERM_CSS), "text/css; charset=utf-8"),
        "symbols-nerd-font-mono.woff2" => (Body::from(terminal::SYMBOLS_FONT), "font/woff2"),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let mut resp = Response::new(body);
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(kind));
    // They change only with the server, which an hour is short enough to follow.
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=3600"));
    resp
}

/// Whether a request came from a page on this management host: browsers send `Origin` with
/// every WebSocket, and a page elsewhere would otherwise get the session cookie sent along.
fn same_origin(headers: &HeaderMap, management_url: &str) -> bool {
    headers.get(header::ORIGIN).and_then(|o| o.to_str().ok()).is_some_and(|o| o.eq_ignore_ascii_case(management_url))
}

pub async fn socket(user: UiUser, State(app): State<AppState>, Path(name): Path<String>, mut req: Request) -> Response {
    let h = req.headers();
    if !same_origin(h, &server_url(&app)) {
        return (StatusCode::FORBIDDEN, "cross-origin WebSocket refused\n").into_response();
    }
    let upgrade = h.get(header::UPGRADE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    let version = h.get(header::SEC_WEBSOCKET_VERSION).is_some_and(|v| v == "13");
    let Some(key) = h.get(header::SEC_WEBSOCKET_KEY).filter(|_| upgrade && version) else {
        return (StatusCode::BAD_REQUEST, "expected a WebSocket\n").into_response();
    };
    let accept = derive_accept_key(key.as_bytes());
    let Some(t) = app.control.terminal(&user.who, &name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(on_upgrade) = req.extensions_mut().remove::<hyper::upgrade::OnUpgrade>() else {
        return (StatusCode::BAD_REQUEST, "connection is not upgradable\n").into_response();
    };
    let client = req.extensions().get::<ClientIp>().map(|c| c.0).unwrap_or(std::net::IpAddr::from([0, 0, 0, 0]));
    let opening = Opening { user_id: t.user_id, email: t.email, tunnel_id: t.tunnel_id, name: t.name, client, signed_in_at: user.signed_in_at };
    let dp = app.control.data_plane();
    // A session is traffic: it belongs on the traffic threads, with the agent's stream.
    dp.clone().on_traffic_threads(move || {
        tokio::spawn(async move {
            let Ok(upgraded) = on_upgrade.await else { return };
            let config = WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE)).max_frame_size(Some(MAX_MESSAGE));
            let ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, Some(config)).await;
            run(dp, ws, opening).await;
        })
    });
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    let h = resp.headers_mut();
    h.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    h.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    if let Ok(v) = HeaderValue::from_str(&accept) {
        h.insert(header::SEC_WEBSOCKET_ACCEPT, v);
    }
    resp
}

pub async fn forget_host_key(State(app): State<AppState>, Path(id): Path<String>, Posted(user, _): Posted<NoFields>) -> Response {
    let back = format!("/tunnels/{id}");
    outcome(&user, app.control.forget_host_key(&user.who, &id), &back, "Tunnel", Done::HostKeyForgotten, "No host key is kept for that tunnel.")
}

/// What a machine needs to let people in from browser terminals, for the tunnel's page.
pub(super) fn setup(ca: &str, email: &str) -> String {
    format!(
        r#"<details class="more"><summary>Set the machine up for browser terminals</summary><div>
<p class="note">Once, as root on the machine, then reload sshd. This trusts certificates from this server, for the accounts that say so.</p>
<pre class="term">echo '{ca}' &gt; /etc/ssh/magicpipes_ca.pub
cat &gt;&gt; /etc/ssh/sshd_config &lt;&lt;'EOF'
TrustedUserCAKeys /etc/ssh/magicpipes_ca.pub
AuthorizedPrincipalsFile %h/.ssh/authorized_principals
EOF</pre>
<p class="note">Then, in each account people may log in as, list their MagicPipes addresses, one per line. For you:</p>
<pre class="term">echo '{email}' &gt;&gt; ~/.ssh/authorized_principals</pre>
</div></details>"#,
        ca = esc(ca.trim()),
        email = esc(email),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_this_host_may_open_a_terminal() {
        let h = |origin: Option<&str>| {
            let mut h = HeaderMap::new();
            if let Some(o) = origin {
                h.insert(header::ORIGIN, HeaderValue::from_str(o).unwrap());
            }
            h
        };
        let here = "https://mp.example.com:8443";
        assert!(same_origin(&h(Some("https://mp.example.com:8443")), here));
        assert!(same_origin(&h(Some("https://MP.example.com:8443")), here));
        for other in [None, Some("https://evil.example"), Some("https://mp.example.com"), Some("http://mp.example.com:8443"), Some("null"), Some("https://dev.mp.example.com:8443")] {
            assert!(!same_origin(&h(other), here), "{other:?}");
        }
    }

    #[test]
    fn the_name_guess_is_only_a_placeholder() {
        assert_eq!(guess("Ann.Lee@example.com"), "ann.lee");
        assert_eq!(guess("+++@example.com"), "you");
    }
}
