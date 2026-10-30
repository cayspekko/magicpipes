//! Minimal server-rendered management UI. Uses the same control-plane methods as the API.

use axum::Form;
use axum::extract::{FromRequestParts, Path, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use http::request::Parts;
use http::{HeaderValue, StatusCode, header};
use serde::Deserialize;

use super::{AppState, PeerAddr, SESSION_COOKIE};
use crate::control::TunnelView;

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn cookie_value(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == SESSION_COOKIE)
        .map(|(_, v)| v.to_string())
}

/// Extractor: a logged-in UI session. Redirects to the login page otherwise.
pub struct UiUser {
    cookie: String,
    csrf: String,
}

impl FromRequestParts<AppState> for UiUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, app: &AppState) -> Result<Self, Self::Rejection> {
        let cookie = cookie_value(parts).ok_or_else(|| Redirect::to("/login").into_response())?;
        let csrf = app.sessions.csrf_for(&cookie).ok_or_else(|| Redirect::to("/login").into_response())?;
        Ok(UiUser { cookie, csrf })
    }
}

impl UiUser {
    #[allow(clippy::result_large_err)] // error pages are returned by value on purpose
    fn check_csrf(&self, submitted: &str) -> Result<(), Response> {
        if magicpipes_core::secret::constant_time_eq(self.csrf.as_bytes(), submitted.as_bytes()) {
            Ok(())
        } else {
            Err((StatusCode::FORBIDDEN, "invalid CSRF token").into_response())
        }
    }
}

const STYLE: &str = r#"
:root{--bg:#f7f7f8;--fg:#1d1d1f;--muted:#6b6b76;--card:#fff;--line:#e4e4e8;--accent:#3b5bdb;--ok:#2b8a3e;--warn:#e67700;--bad:#c92a2a}
@media (prefers-color-scheme:dark){:root{--bg:#15161a;--fg:#ececf1;--muted:#9a9aa6;--card:#1e1f24;--line:#2e2f36;--accent:#7b93ff;--ok:#51cf66;--warn:#ffa94d;--bad:#ff6b6b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
header{display:flex;align-items:center;justify-content:space-between;padding:14px 24px;border-bottom:1px solid var(--line);background:var(--card)}
header b{font-size:17px}main{max-width:1100px;margin:0 auto;padding:24px 16px}
h2{font-size:16px;margin:28px 0 10px}a{color:var(--accent)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow-x:auto}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);white-space:nowrap}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:600}tr:last-child td{border-bottom:0}
.badge{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.connected,.ready{color:var(--ok)}.pending{color:var(--warn)}.disconnected,.error,.failed{color:var(--bad)}
.muted{color:var(--muted)}button,.btn{font:inherit;padding:6px 14px;border-radius:7px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer;text-decoration:none}
button.danger{color:var(--bad);border-color:var(--bad)}input[type=password]{font:inherit;padding:8px 10px;width:100%;border:1px solid var(--line);border-radius:7px;background:var(--bg);color:var(--fg)}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}code,pre{font:13px ui-monospace,Menlo,monospace}pre{background:var(--bg);border:1px solid var(--line);padding:12px;border-radius:8px;overflow-x:auto}
dl{display:grid;grid-template-columns:max-content 1fr;gap:8px 20px;padding:16px;margin:0}dt{color:var(--muted)}dd{margin:0;word-break:break-all}
.notice{padding:12px 16px;border:1px solid var(--line);border-radius:10px;background:var(--card);margin-top:16px}
"#;

fn page(title: &str, user: Option<&UiUser>, body: &str) -> Response {
    let logout = user
        .map(|u| {
            format!(
                r#"<form method="post" action="/logout"><input type="hidden" name="csrf" value="{}"><button>Log out</button></form>"#,
                esc(&u.csrf)
            )
        })
        .unwrap_or_default();
    Html(format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{} · MagicPipes</title><style>{STYLE}</style></head><body>
<header><b>MagicPipes</b>{logout}</header><main>{body}</main></body></html>"#,
        esc(title)
    ))
    .into_response()
}

fn badge(class: &str) -> String {
    format!(r#"<span class="badge {0}">{0}</span>"#, esc(class))
}

pub async fn index(user: UiUser, State(app): State<AppState>) -> Response {
    let agents = app.control.agents();
    let agent_name = |id: &str| agents.iter().find(|a| a.id == id).map(|a| a.name.clone()).unwrap_or_else(|| id.to_string());
    let tunnels = app.control.tunnels();
    let mut rows = String::new();
    for t in &tunnels {
        rows.push_str(&format!(
            r#"<tr><td><a href="/tunnels/{id}">{name}</a></td><td><a href="{url}" target="_blank" rel="noopener noreferrer">{url}</a></td><td><code>{target}</code></td><td>{agent}</td><td>{status}</td><td>{tls}</td><td class="muted">{created}</td></tr>"#,
            id = esc(&t.id),
            name = esc(&t.name),
            url = esc(&t.public_url),
            target = esc(&t.target),
            agent = esc(&agent_name(&t.agent_id)),
            status = badge(t.status),
            tls = badge(t.tls),
            created = esc(&t.created_at),
        ));
    }
    if tunnels.is_empty() {
        rows = r#"<tr><td colspan="7" class="muted">No tunnels yet. Run <code>magicpipes add 8080</code> on an enrolled machine.</td></tr>"#.into();
    }
    let mut agent_rows = String::new();
    for a in &agents {
        agent_rows.push_str(&format!(
            r#"<tr><td>{}</td><td><code>{id}</code></td><td>{}</td><td>{}</td><td class="muted">{}</td><td><form method="post" action="/agents/{id}/revoke"><input type="hidden" name="csrf" value="{csrf}"><button class="danger">Revoke</button></form></td></tr>"#,
            esc(&a.name),
            badge(if a.connected { "connected" } else { "disconnected" }),
            a.tunnels,
            esc(a.last_seen_at.as_deref().unwrap_or("never")),
            id = esc(&a.id),
            csrf = esc(&user.csrf),
        ));
    }
    if agents.is_empty() {
        agent_rows = r#"<tr><td colspan="6" class="muted">No agents enrolled.</td></tr>"#.into();
    }
    let body = format!(
        r#"<div class="row" style="justify-content:space-between"><h2 style="margin:0">Tunnels ({n})</h2><a class="btn" href="/">Refresh</a></div>
<p class="muted">Public URLs are reachable by anyone who knows them; a random name is not access control.</p>
<div class="card"><table><thead><tr><th>Tunnel</th><th>Public URL</th><th>Target</th><th>Agent</th><th>Status</th><th>TLS</th><th>Created</th></tr></thead><tbody>{rows}</tbody></table></div>
<h2>Agents</h2>
<div class="card"><table><thead><tr><th>Name</th><th>ID</th><th>Status</th><th>Tunnels</th><th>Last seen</th><th></th></tr></thead><tbody>{agent_rows}</tbody></table></div>
<h2>Enroll a machine</h2>
<form method="post" action="/enrollments"><input type="hidden" name="csrf" value="{csrf}"><button>Create enrollment token</button></form>"#,
        n = tunnels.len(),
        csrf = esc(&user.csrf),
    );
    page("Tunnels", Some(&user), &body)
}

pub async fn tunnel_detail(user: UiUser, State(app): State<AppState>, Path(id): Path<String>) -> Response {
    let Some(t) = app.control.tunnel(&id) else {
        return (StatusCode::NOT_FOUND, page("Not found", Some(&user), "<p>No such tunnel. <a href=\"/\">Back</a></p>")).into_response();
    };
    let agent = app.control.agent_name(&t.agent_id).unwrap_or_default();
    page(&t.name, Some(&user), &detail_body(&t, &agent, &user.csrf))
}

fn detail_body(t: &TunnelView, agent: &str, csrf: &str) -> String {
    let field = |k: &str, v: &str| format!("<dt>{}</dt><dd>{}</dd>", esc(k), v);
    let mut dl = String::new();
    dl.push_str(&field("ID", &format!("<code>{}</code>", esc(&t.id))));
    dl.push_str(&field("Public URL", &format!(r#"<a href="{0}" target="_blank" rel="noopener noreferrer">{0}</a>"#, esc(&t.public_url))));
    dl.push_str(&field("Target", &format!("<code>{}</code>", esc(&t.target))));
    dl.push_str(&field("Agent", &format!("{} <span class=\"muted\">({})</span>", esc(agent), esc(&t.agent_id))));
    dl.push_str(&field("Status", &badge(t.status)));
    dl.push_str(&field("TLS", &badge(t.tls)));
    if let Some(e) = &t.tls_error {
        dl.push_str(&field("TLS error", &esc(e)));
    }
    dl.push_str(&field("Requests", &t.requests.to_string()));
    dl.push_str(&field("Upstream errors", &t.upstream_errors.to_string()));
    dl.push_str(&field("Last request", &esc(t.last_request_at.as_deref().unwrap_or("never"))));
    dl.push_str(&field("Created", &esc(&t.created_at)));
    format!(
        r#"<p><a href="/">&larr; All tunnels</a></p><div class="row" style="justify-content:space-between"><h2 style="margin:0">{name}</h2><a class="btn" href="/tunnels/{id}">Refresh</a></div>
<div class="card" style="margin-top:12px"><dl>{dl}</dl></div>
<form method="post" action="/tunnels/{id}/delete" style="margin-top:16px"><input type="hidden" name="csrf" value="{csrf}"><button class="danger">Delete tunnel</button></form>"#,
        name = esc(&t.name),
        id = esc(&t.id),
        csrf = esc(csrf),
    )
}

#[derive(Deserialize)]
pub struct CsrfForm {
    csrf: String,
}

pub async fn delete_tunnel(user: UiUser, State(app): State<AppState>, Path(id): Path<String>, Form(f): Form<CsrfForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    let _ = app.control.delete_tunnel(&id);
    Redirect::to("/").into_response()
}

pub async fn revoke_agent(user: UiUser, State(app): State<AppState>, Path(id): Path<String>, Form(f): Form<CsrfForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    let _ = app.control.revoke_agent(&id);
    Redirect::to("/").into_response()
}

pub async fn create_enrollment(user: UiUser, State(app): State<AppState>, Form(f): Form<CsrfForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    let Ok(token) = app.control.create_enrollment() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "could not create enrollment token").into_response();
    };
    let cfg = app.control.config();
    let port = cfg.management.listen.port();
    let server = if port == 443 { format!("https://{}", cfg.management.hostname) } else { format!("https://{}:{port}", cfg.management.hostname) };
    let body = format!(
        r#"<p><a href="/">&larr; All tunnels</a></p><h2>Enrollment token</h2>
<div class="notice">Single use, valid for {mins} minutes. It is shown only once. Run on the machine to enroll:</div>
<pre>magicpipes login --server {server} --token {token}</pre>"#,
        mins = cfg.agents.enrollment_ttl_secs / 60,
        server = esc(&server),
        token = esc(&token),
    );
    page("Enrollment token", Some(&user), &body)
}

fn login_page(error: Option<&str>) -> Response {
    let err = error.map(|e| format!(r#"<p class="bad" style="color:var(--bad)">{}</p>"#, esc(e))).unwrap_or_default();
    page(
        "Log in",
        None,
        &format!(
            r#"<div class="card" style="max-width:420px;margin:40px auto;padding:24px"><h2 style="margin-top:0">Log in</h2>{err}
<form method="post" action="/login"><p><label for="t">Admin token</label></p><input id="t" type="password" name="token" autocomplete="current-password" autofocus required>
<p><button>Log in</button></p></form><p class="muted">The initial admin token is in <code>&lt;data_dir&gt;/admin-token</code>. Create a new one with <code>magicpipesd admin-token</code>.</p></div>"#
        ),
    )
}

pub async fn login_form() -> Response {
    login_page(None)
}

#[derive(Deserialize)]
pub struct LoginForm {
    token: String,
}

pub async fn login(State(app): State<AppState>, peer: Option<axum::Extension<PeerAddr>>, Form(f): Form<LoginForm>) -> Response {
    let ip = peer.map(|p| p.0.0.ip());
    if ip.is_some_and(|ip| app.limiter.blocked(ip)) {
        return (StatusCode::TOO_MANY_REQUESTS, login_page(Some("Too many failed attempts. Try again later."))).into_response();
    }
    if !app.control.verify_admin(f.token.trim()) {
        if let Some(ip) = ip {
            app.limiter.fail(ip);
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        return (StatusCode::UNAUTHORIZED, login_page(Some("Invalid admin token."))).into_response();
    }
    let (cookie, _) = app.sessions.create();
    let mut resp = Redirect::to("/").into_response();
    let value = format!("{SESSION_COOKIE}={cookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=43200");
    resp.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&value).expect("cookie is ASCII"));
    resp
}

pub async fn logout(user: UiUser, State(app): State<AppState>, Form(f): Form<CsrfForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    app.sessions.remove(&user.cookie);
    let mut resp = Redirect::to("/login").into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("mp_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"),
    );
    resp
}
