//! Minimal server-rendered management UI. Uses the same control-plane methods as the API.

use axum::Form;
use axum::extract::{FromRequestParts, Path, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use http::request::Parts;
use http::{HeaderValue, StatusCode, header};
use magicpipes_core::theme::{GLYPH, STYLE};
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

/// Progressive enhancement for every page: a copy-to-clipboard button on each `pre.term` code
/// block. Add `data-nocopy` to a block to leave it without one. Served from `/ui.js` because the
/// CSP forbids inline scripts.
const SCRIPT: &str = r#"(() => {
  const COPY = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/></svg>';
  const DONE = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>';
  // The text a user would want to paste: the block's content without prompt markers.
  const text = (pre) => {
    const c = pre.cloneNode(true);
    c.querySelectorAll('.p').forEach((p) => p.remove());
    return c.textContent.trim();
  };
  const fallback = (s) => {
    const t = document.createElement('textarea');
    t.value = s;
    t.setAttribute('readonly', '');
    t.style.cssText = 'position:fixed;opacity:0';
    document.body.appendChild(t);
    t.select();
    const ok = document.execCommand('copy');
    t.remove();
    return ok;
  };
  document.querySelectorAll('pre.term:not([data-nocopy])').forEach((pre) => {
    const box = document.createElement('div');
    box.className = 'codebox';
    pre.replaceWith(box);
    box.appendChild(pre);
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'copy';
    btn.title = 'Copy to clipboard';
    btn.setAttribute('aria-label', 'Copy to clipboard');
    btn.innerHTML = COPY;
    let timer;
    btn.addEventListener('click', async () => {
      const s = text(pre);
      let ok;
      try { await navigator.clipboard.writeText(s); ok = true; } catch { ok = fallback(s); }
      if (!ok) return;
      btn.classList.add('done');
      btn.innerHTML = DONE;
      btn.title = 'Copied';
      clearTimeout(timer);
      timer = setTimeout(() => { btn.classList.remove('done'); btn.innerHTML = COPY; btn.title = 'Copy to clipboard'; }, 1600);
    });
    box.appendChild(btn);
  });
})();
"#;

pub async fn script() -> Response {
    ([(header::CONTENT_TYPE, HeaderValue::from_static("text/javascript; charset=utf-8"))], SCRIPT).into_response()
}

fn page(title: &str, user: Option<&UiUser>, body: &str) -> Response {
    let logout = user
        .map(|u| {
            format!(
                r#"<form method="post" action="/logout"><input type="hidden" name="csrf" value="{}"><button class="btn ghost">Log out</button></form>"#,
                esc(&u.csrf)
            )
        })
        .unwrap_or_default();
    Html(format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><title>{} · MagicPipes</title><style>{STYLE}</style><script src="/ui.js" defer></script></head><body>
<header class="top"><div class="top-in"><a class="brand" href="/">{GLYPH}MagicPipes</a>{logout}</div></header>
<main>{body}</main><footer class="foot">MagicPipes {version} · self-hosted HTTPS tunnels</footer></body></html>"#,
        esc(title),
        version = esc(magicpipes_core::VERSION),
    ))
    .into_response()
}

/// A status dot plus its label. The tone comes from the state, the text stays the raw state name.
fn badge(state: &str) -> String {
    let tone = match state {
        "connected" | "ready" => "ok",
        "pending" => "warn",
        "disconnected" | "error" | "failed" => "bad",
        _ => "",
    };
    format!(r#"<span class="status {tone}">{}</span>"#, esc(state))
}

/// `2026-10-30T04:08:00Z` -> `2026-10-30 · 04:08 UTC`, with the exact value as a tooltip.
fn when(ts: &str) -> String {
    let short = match (ts.get(..10), ts.get(11..16)) {
        (Some(d), Some(t)) if ts.as_bytes().get(10) == Some(&b'T') => format!("{d} · {t} UTC"),
        _ => ts.to_string(),
    };
    format!(r#"<time class="when" datetime="{0}" title="{0}">{1}</time>"#, esc(ts), esc(&short))
}

fn display_url(url: &str) -> &str {
    url.strip_prefix("https://").unwrap_or(url)
}

pub async fn index(user: UiUser, State(app): State<AppState>) -> Response {
    let agents = app.control.agents();
    let agent_name = |id: &str| agents.iter().find(|a| a.id == id).map(|a| a.name.clone()).unwrap_or_else(|| id.to_string());
    let tunnels = app.control.tunnels();
    let mut rows = String::new();
    for t in &tunnels {
        rows.push_str(&format!(
            r#"<tr><td><a class="name" href="/tunnels/{id}">{name}</a><a class="sub" href="{url}" target="_blank" rel="noopener noreferrer">{shown} ↗</a></td><td><code>{target}</code></td><td>{agent}</td><td>{status}</td><td>{tls}</td><td class="num">{requests}</td></tr>"#,
            id = esc(&t.id),
            name = esc(&t.name),
            url = esc(&t.public_url),
            shown = esc(display_url(&t.public_url)),
            target = esc(&t.target),
            agent = esc(&agent_name(&t.agent_id)),
            status = badge(t.status),
            tls = badge(t.tls),
            requests = t.requests,
        ));
    }
    if tunnels.is_empty() {
        rows = r#"<tr><td colspan="6" class="empty">No tunnels yet. Run <code>magicpipes add 8080</code> on an enrolled machine.</td></tr>"#.into();
    }
    let mut agent_rows = String::new();
    for a in &agents {
        let last_seen = a.last_seen_at.as_deref().map(when).unwrap_or_else(|| r#"<span class="when">never</span>"#.into());
        agent_rows.push_str(&format!(
            r#"<tr><td><span class="name">{name}</span><code class="sub">{id}</code></td><td>{status}</td><td class="num">{tunnels}</td><td>{last_seen}</td><td class="num"><form method="post" action="/agents/{id}/revoke"><input type="hidden" name="csrf" value="{csrf}"><button class="btn danger small">Revoke</button></form></td></tr>"#,
            name = esc(&a.name),
            status = badge(if a.connected { "connected" } else { "disconnected" }),
            tunnels = a.tunnels,
            id = esc(&a.id),
            csrf = esc(&user.csrf),
        ));
    }
    if agents.is_empty() {
        agent_rows = r#"<tr><td colspan="5" class="empty">No agents enrolled yet.</td></tr>"#.into();
    }
    let status = app.control.status();
    let online = agents.iter().filter(|a| a.connected).count();
    let requests: u64 = tunnels.iter().map(|t| t.requests).sum();
    let errors: u64 = tunnels.iter().map(|t| t.upstream_errors).sum();
    let body = format!(
        r#"<div class="head"><div><div class="eyebrow">Control plane · {domain}</div><h1>Tunnels</h1>
<p class="lede">Public URLs are reachable by anyone who knows them. A random name is not access control.</p></div>
<a class="btn" href="/">Refresh</a></div>
<div class="stats">
<div class="stat"><div class="k">Tunnels</div><div class="v">{n}</div></div>
<div class="stat"><div class="k">Agents online</div><div class="v">{online}<small>of {agents_total}</small></div></div>
<div class="stat"><div class="k">Requests</div><div class="v">{requests}</div></div>
<div class="stat"><div class="k">Upstream errors</div><div class="v">{errors}</div></div>
</div>
<div class="section"><h2>Tunnels<span class="count">{n}</span></h2></div>
<div class="card scroll"><table><thead><tr><th>Tunnel</th><th>Target</th><th>Agent</th><th>Status</th><th>TLS</th><th class="num">Requests</th></tr></thead><tbody>{rows}</tbody></table></div>
<div class="section"><h2>Agents<span class="count">{agents_total}</span></h2></div>
<div class="card scroll"><table><thead><tr><th>Agent</th><th>Status</th><th class="num">Tunnels</th><th>Last seen</th><th></th></tr></thead><tbody>{agent_rows}</tbody></table></div>
<div class="card panel" style="margin-top:20px"><div><h3>Enroll a machine</h3><p>Creates a single-use token for <code>magicpipes login</code>. It is shown once and expires after {mins} minutes.</p></div>
<form method="post" action="/enrollments"><input type="hidden" name="csrf" value="{csrf}"><button class="btn primary">Create enrollment token</button></form></div>"#,
        domain = esc(&status.base_domain),
        n = tunnels.len(),
        agents_total = agents.len(),
        mins = app.control.config().agents.enrollment_ttl_secs / 60,
        csrf = esc(&user.csrf),
    );
    page("Tunnels", Some(&user), &body)
}

pub async fn tunnel_detail(user: UiUser, State(app): State<AppState>, Path(id): Path<String>) -> Response {
    let Some(t) = app.control.tunnel(&id) else {
        let body = r#"<a class="crumb" href="/">← Tunnels</a><h1>Not found</h1><p class="lede">There is no tunnel with that id or name. It may have been deleted.</p>"#;
        return (StatusCode::NOT_FOUND, page("Not found", Some(&user), body)).into_response();
    };
    let agent = app.control.agent_name(&t.agent_id).unwrap_or_default();
    page(&t.name, Some(&user), &detail_body(&t, &agent, &user.csrf))
}

fn detail_body(t: &TunnelView, agent: &str, csrf: &str) -> String {
    let field = |k: &str, v: &str| format!("<dt>{}</dt><dd>{}</dd>", esc(k), v);
    let mut dl = String::new();
    dl.push_str(&field("Target", &format!("<code>{}</code>", esc(&t.target))));
    dl.push_str(&field("Agent", &format!(r#"{} <code class="sub">{}</code>"#, esc(agent), esc(&t.agent_id))));
    dl.push_str(&field("TLS certificate", &badge(t.tls)));
    if let Some(e) = &t.tls_error {
        dl.push_str(&field("TLS error", &esc(e)));
    }
    dl.push_str(&field("Tunnel ID", &format!("<code>{}</code>", esc(&t.id))));
    dl.push_str(&field("Created", &when(&t.created_at)));
    let last = t.last_request_at.as_deref().map(when).unwrap_or_else(|| "never".into());
    format!(
        r#"<a class="crumb" href="/">← Tunnels</a>
<div class="head"><div><h1>{name}</h1><p class="lede"><a href="{url}" target="_blank" rel="noopener noreferrer">{shown} ↗</a></p></div>
<a class="btn" href="/tunnels/{id}">Refresh</a></div>
<div class="stats">
<div class="stat"><div class="k">Status</div><div class="v sm">{status}</div></div>
<div class="stat"><div class="k">Requests</div><div class="v">{requests}</div></div>
<div class="stat"><div class="k">Upstream errors</div><div class="v">{errors}</div></div>
<div class="stat"><div class="k">Last request</div><div class="v sm">{last}</div></div>
</div>
<div class="section"><h2>Details</h2></div>
<div class="card"><dl>{dl}</dl></div>
<div class="card panel danger" style="margin-top:20px"><div><h3>Delete tunnel</h3><p>The public URL stops working at once and the agent stops serving it. In-flight requests finish.</p></div>
<form method="post" action="/tunnels/{id}/delete"><input type="hidden" name="csrf" value="{csrf}"><button class="btn danger">Delete tunnel</button></form></div>"#,
        name = esc(&t.name),
        url = esc(&t.public_url),
        shown = esc(display_url(&t.public_url)),
        id = esc(&t.id),
        status = badge(t.status),
        requests = t.requests,
        errors = t.upstream_errors,
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
        r#"<a class="crumb" href="/">← Tunnels</a>
<div class="eyebrow" style="margin-top:22px">Enrollment token</div><h1>Enroll a <em>machine</em></h1>
<p class="lede">Run this on the machine you want to enroll. The token works once, expires in {mins} minutes, and is not shown again.</p>
<pre class="term"><span class="p">$ </span>magicpipes login --server {server} --token {token}</pre>
<p class="note">Then expose a local port with <code>magicpipes add 8080</code>.</p>"#,
        mins = cfg.agents.enrollment_ttl_secs / 60,
        server = esc(&server),
        token = esc(&token),
    );
    page("Enrollment token", Some(&user), &body)
}

fn login_page(error: Option<&str>) -> Response {
    let err = error.map(|e| format!(r#"<div class="alert" role="alert">{}</div>"#, esc(e))).unwrap_or_default();
    page(
        "Log in",
        None,
        &format!(
            r#"<div class="auth"><div class="eyebrow">Administration</div><h1>Sign <em>in</em></h1>
<p class="lede">Use an admin token to manage tunnels and agents.</p>
<div class="card" style="margin-top:28px">{err}
<form method="post" action="/login"><label for="t" style="margin-top:0">Admin token</label><input id="t" type="password" name="token" placeholder="mpadm_…" autocomplete="current-password" autofocus required>
<button class="btn primary block" style="margin-top:18px">Log in</button></form></div>
<p class="note">The first admin token is written to <code>&lt;data_dir&gt;/admin-token</code>. Create another with <code>magicpipesd admin-token</code>.</p></div>"#
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
