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

// Warm paper and ink, one terracotta accent, serif display type over a sans body, hairlines
// instead of shadows. The CSP allows inline styles only: no web fonts, scripts or images.
const STYLE: &str = r#"
:root{--bg:#f6f4ef;--surface:#fffdf8;--hover:#f8f5ee;--ink:#1d1c1a;--ink-2:#4b4842;--muted:#7a766d;--line:#e6e1d6;--line-2:#d6d0c3;
--accent:#c2562b;--ok:#3f7d50;--warn:#b0741c;--bad:#b23a2c;--term:#1d1c1a;--term-ink:#ece9e2;
--serif:ui-serif,"New York","Iowan Old Style",Georgia,serif;--sans:ui-sans-serif,-apple-system,"Helvetica Neue","Segoe UI",sans-serif;--mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#131312;--surface:#1a1a18;--hover:#1f1f1d;--ink:#ece9e2;--ink-2:#c3bfb6;--muted:#8e8a82;--line:#2a2927;--line-2:#3a3834;
--accent:#ec7a4b;--ok:#7cc48e;--warn:#e2a954;--bad:#ef7a6b;--term:#0c0c0b;--term-ink:#ece9e2}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;min-height:100vh;display:flex;flex-direction:column;background:var(--bg);color:var(--ink);font:15px/1.55 var(--sans);-webkit-font-smoothing:antialiased}
a{color:inherit;text-decoration-color:var(--line-2);text-underline-offset:3px}a:hover{color:var(--accent);text-decoration-color:currentColor}
code{font:12.5px var(--mono);color:var(--ink-2)}
.top{border-bottom:1px solid var(--line)}
.top-in,main,.foot{width:100%;max-width:1080px;margin:0 auto;padding-left:24px;padding-right:24px}
.top-in{display:flex;align-items:center;justify-content:space-between;gap:16px;height:64px}
.brand{display:flex;align-items:center;gap:10px;font:400 20px/1 var(--serif);letter-spacing:-.01em;text-decoration:none}
.brand:hover{color:var(--ink)}
.glyph{color:var(--ink)}.glyph .flow{stroke:var(--accent);stroke-dasharray:1.5 3.5}
@media (prefers-reduced-motion:no-preference){.glyph .flow{animation:flow 1.6s linear infinite}}
@keyframes flow{to{stroke-dashoffset:-10}}
main{flex:1;padding-top:44px;padding-bottom:72px}
.foot{padding-top:20px;padding-bottom:28px;font-size:12.5px;color:var(--muted);border-top:1px solid var(--line)}
.eyebrow{font-size:11.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
h1{font:400 clamp(34px,5.4vw,48px)/1.05 var(--serif);letter-spacing:-.022em;margin:10px 0 12px}
h1 em{font-style:italic;color:var(--accent)}
h2{font:400 23px/1.2 var(--serif);letter-spacing:-.01em;margin:0}
.lede{color:var(--muted);max-width:62ch;margin:0}
.head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;flex-wrap:wrap}
.section{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin:52px 0 14px}
.count{font:13px var(--sans);color:var(--muted);margin-left:8px;letter-spacing:0}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:1px;margin-top:32px;background:var(--line);border:1px solid var(--line);border-radius:14px;overflow:hidden}
.stat{background:var(--surface);padding:18px 20px 16px}
.stat .k{font-size:12.5px;color:var(--muted)}
.stat .v{font:400 34px/1.15 var(--serif);letter-spacing:-.02em;margin-top:6px;font-variant-numeric:tabular-nums}
.stat .v small{font:14px var(--sans);color:var(--muted);letter-spacing:0;margin-left:6px}
.stat .v.sm{font:15px/1.4 var(--sans);letter-spacing:0;margin-top:16px;min-height:23px}
.stat .v.sm .status,.stat .v.sm .when{font-size:15px;color:var(--ink)}
.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;overflow:hidden}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th{font-size:11px;font-weight:500;letter-spacing:.09em;text-transform:uppercase;color:var(--muted);text-align:left;padding:13px 18px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:15px 18px;border-bottom:1px solid var(--line);vertical-align:middle;white-space:nowrap}
tbody tr:last-child td{border-bottom:0}tbody tr:hover td{background:var(--hover)}
.num{text-align:right;font-variant-numeric:tabular-nums}
.name{font-weight:500;text-decoration:none}
.sub{display:block;margin-top:2px;font:12.5px var(--mono);color:var(--muted);text-decoration:none}
a.sub:hover{color:var(--accent)}
.when{color:var(--muted);font-size:13.5px;font-variant-numeric:tabular-nums}
.empty{padding:36px 20px;text-align:center;color:var(--muted)}
.status{display:inline-flex;align-items:center;gap:8px;font-size:13.5px;color:var(--ink-2)}
.status::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--muted);box-shadow:0 0 0 3px color-mix(in srgb,var(--muted) 16%,transparent)}
.status.ok::before{background:var(--ok);box-shadow:0 0 0 3px color-mix(in srgb,var(--ok) 18%,transparent)}
.status.warn::before{background:var(--warn);box-shadow:0 0 0 3px color-mix(in srgb,var(--warn) 18%,transparent)}
.status.bad::before{background:var(--bad);box-shadow:0 0 0 3px color-mix(in srgb,var(--bad) 18%,transparent)}
form{margin:0}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;font:500 13.5px/1 var(--sans);padding:10px 15px;border-radius:9px;border:1px solid var(--line-2);background:var(--surface);color:var(--ink);cursor:pointer;text-decoration:none;white-space:nowrap;transition:border-color .15s,background .15s,transform .08s}
.btn:hover{border-color:var(--ink);color:var(--ink)}.btn:active{transform:scale(.985)}
.btn.primary{background:var(--ink);border-color:var(--ink);color:var(--bg)}.btn.primary:hover{background:var(--ink-2);border-color:var(--ink-2);color:var(--bg)}
.btn.ghost{background:transparent;border-color:transparent;color:var(--muted)}.btn.ghost:hover{color:var(--ink);border-color:var(--line-2)}
.btn.danger{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 35%,var(--line))}
.btn.danger:hover{border-color:var(--bad);background:color-mix(in srgb,var(--bad) 7%,var(--surface));color:var(--bad)}
.btn.small{padding:7px 11px;font-size:12.5px}.btn.block{width:100%}
.panel{display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap;padding:22px 24px}
.panel h3{font:400 19px/1.25 var(--serif);margin:0 0 4px}.panel p{margin:0;color:var(--muted);max-width:56ch}
.panel.danger{border-color:color-mix(in srgb,var(--bad) 30%,var(--line))}
.crumb{display:inline-flex;gap:6px;font-size:13.5px;color:var(--muted);text-decoration:none}
dl{display:grid;grid-template-columns:200px 1fr;margin:0}
dt,dd{padding:14px 22px;border-bottom:1px solid var(--line);margin:0}
dt{color:var(--muted);font-size:13.5px}dd{overflow-wrap:anywhere}
dl>:nth-last-child(-n+2){border-bottom:0}
.term{background:var(--term);color:var(--term-ink);border-radius:14px;padding:20px 22px;margin:24px 0 0;overflow-x:auto;font:13.5px/1.6 var(--mono)}
.term .p{color:#8e8a82;user-select:none}
.note{margin:16px 0 0;color:var(--muted);font-size:13.5px}
.auth{width:100%;max-width:400px;margin:6vh auto 0}
.auth .card{padding:30px 28px 26px}
label{display:block;font-size:13px;font-weight:500;color:var(--ink-2);margin:22px 0 8px}
input[type=password]{width:100%;font:14px var(--mono);padding:12px 14px;border-radius:10px;border:1px solid var(--line-2);background:var(--bg);color:var(--ink);outline:none;transition:border-color .15s,box-shadow .15s}
input[type=password]:focus{border-color:var(--accent);box-shadow:0 0 0 4px color-mix(in srgb,var(--accent) 16%,transparent)}
.alert{margin:0 0 20px;padding:11px 14px;border-radius:10px;font-size:13.5px;color:var(--bad);background:color-mix(in srgb,var(--bad) 8%,var(--surface));border:1px solid color-mix(in srgb,var(--bad) 25%,var(--line))}
@media (max-width:640px){.top-in,main,.foot{padding-left:16px;padding-right:16px}main{padding-top:32px}dl{grid-template-columns:1fr}dt{border-bottom:0;padding-bottom:2px}dd{padding-top:0}}
"#;

/// The MagicPipes mark: two endpoints joined by a flowing line.
const GLYPH: &str = r#"<svg class="glyph" width="26" height="14" viewBox="0 0 26 14" aria-hidden="true"><line class="flow" x1="6" y1="7" x2="20" y2="7" stroke-width="2.4" stroke-linecap="round"/><circle cx="4.5" cy="7" r="3.2" fill="none" stroke="currentColor" stroke-width="1.6"/><circle cx="21.5" cy="7" r="3.2" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>"#;

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
<meta name="color-scheme" content="light dark"><title>{} · MagicPipes</title><style>{STYLE}</style></head><body>
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
