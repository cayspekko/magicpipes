//! Remote desktops on the management host: the page, IronRDP's vendored web client, and the
//! WebSocket, which is checked here and served on the traffic threads (`data::desktop`).

use std::sync::LazyLock;

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};
use hyper_util::rt::TokioIo;
use magicpipes_core::terminal;
use magicpipes_core::theme::{GLYPH, STYLE};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};

use super::extract::UiUser;
use super::html::esc;
use super::terminal::same_origin;
use super::ui::{not_there, server_url};
use super::{AppState, ClientIp};
use crate::data::desktop::run;
use crate::data::terminal::Opening;

/// What names this server's version of the page's files: a digest of all three, in their path,
/// so they can be kept for good and a new server's reach browsers at once. `page.mjs` imports the
/// others by relative path, so they come from the same version.
static VERSION: LazyLock<String> = LazyLock::new(|| {
    let digest = magicpipes_core::secret::sha256_hex(&[PAGE_JS, COMPONENT_JS, RDP_JS].concat());
    digest[..16].to_string()
});
/// Largest message accepted from the browser: input, and clipboard contents.
const MAX_MESSAGE: usize = 4 * 1024 * 1024;

/// The client is WebAssembly (`wasm-unsafe-eval`), which the published build carries as a `data:`
/// URL it fetches; its web component injects styles, and draws cursors from `data:` images.
const CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self'; \
                   connect-src 'self' data:; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const PAGE_JS: &str = include_str!("assets/desktop/page.mjs");
const COMPONENT_JS: &str = include_str!("assets/desktop/iron-remote-desktop.js");
const RDP_JS: &str = include_str!("assets/desktop/iron-remote-desktop-rdp.js");

/// What the desktop page adds to the terminal page's layout.
const DESKTOP_STYLE: &str = r#"
.screen.desk{padding:0;background:#000;display:flex}
.screen.desk iron-remote-desktop{flex:1;min-width:0;min-height:0;display:block}
.login .field{display:flex;align-items:center;gap:8px;min-width:0}
.login input.pw{font-family:inherit}
.keys{display:flex;gap:8px;flex-wrap:wrap}.keys[hidden],.login[hidden]{display:none}
.keys .btn{padding:6px 12px;font-size:13px}
"#;

/// The address of the remote desktop of an RDP tunnel.
pub(super) fn href(name: &str) -> String {
    format!("/desktop/{name}")
}

pub async fn page(user: UiUser, State(app): State<AppState>, Path(name): Path<String>) -> Response {
    let Some(t) = app.control.desktop(&user.who, &name) else {
        return not_there(&user, "/", "Tunnels", "There's no remote desktop by that name that you can reach.");
    };
    let html = format!(
        r##"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><meta name="referrer" content="no-referrer"><title>{name} · MagicPipes</title>
<style>{STYLE}{term_style}{DESKTOP_STYLE}</style></head>
<body data-ws="/desktop/{name}/ws" data-name="{name}">
<header class="top"><div class="top-in"><h1 class="brand"><a href="/" aria-label="Back to your tunnels">{GLYPH}</a><span class="nm">{name}</span></h1>
<div class="side"><span class="status" id="st" role="status">Not connected</span><span class="badge rw">RDP</span></div></div></header>
<main class="tm">
<div class="cmd"><form class="login" id="login"><span class="field"><label for="du">User</label><input id="du" type="text" name="user" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="256" required></span>
<span class="field"><label for="dd">Domain</label><input id="dd" type="text" name="domain" autocapitalize="none" spellcheck="false" maxlength="256" placeholder="optional"></span>
<span class="field"><label for="dp">Password</label><input id="dp" class="pw" type="password" name="password" autocomplete="current-password" maxlength="512" required></span><button class="btn primary">Connect</button></form>
<div class="keys" id="keys" hidden><button class="btn" id="cad" type="button">Ctrl+Alt+Del</button><button class="btn" id="win" type="button">Windows key</button><button class="btn" id="bye" type="button">Disconnect</button></div>
<span class="hint">Windows checks the password; MagicPipes doesn't keep it</span></div>
<div class="screen desk" id="screen"><iron-remote-desktop id="rd" scale="fit" flexcenter="true"></iron-remote-desktop><div class="notice" id="nt" hidden><span id="nt-text"></span></div></div>
<noscript><p class="note">The remote desktop needs JavaScript. Without it, use <code>magicpipes connect {name}</code> with a Remote Desktop client.</p></noscript>
</main>
<script type="module" src="/assets/desktop/{version}/page.mjs"></script>
</body></html>"##,
        name = esc(&t.name),
        term_style = terminal::style(super::terminal::ASSETS),
        version = *VERSION,
    );
    let mut resp = Response::new(Body::from(html));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    resp
}

/// The page's script and IronRDP's web client. They're public: anyone can get them from npm.
pub async fn asset(Path((version, file)): Path<(String, String)>) -> Response {
    // Another version's address would keep these files under it for good.
    if version != *VERSION {
        return StatusCode::NOT_FOUND.into_response();
    }
    let body = match file.as_str() {
        "page.mjs" => PAGE_JS,
        "iron-remote-desktop.js" => COMPONENT_JS,
        "iron-remote-desktop-rdp.js" => RDP_JS,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let mut resp = Response::new(Body::from(body));
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/javascript; charset=utf-8"));
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=31536000, immutable"));
    resp
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
    let Some(t) = app.control.desktop(&user.who, &name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(on_upgrade) = req.extensions_mut().remove::<hyper::upgrade::OnUpgrade>() else {
        return (StatusCode::BAD_REQUEST, "connection is not upgradable\n").into_response();
    };
    let client = req.extensions().get::<ClientIp>().map(|c| c.0).unwrap_or(std::net::IpAddr::from([0, 0, 0, 0]));
    let opening = Opening { user_id: t.user_id, email: t.email, tunnel_id: t.tunnel_id, name: t.name, client, signed_in_at: user.signed_in_at };
    let dp = app.control.data_plane();
    // A desktop is traffic: it belongs on the traffic threads, with the agent's stream.
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
