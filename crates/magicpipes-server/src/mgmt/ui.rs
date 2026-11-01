//! Minimal server-rendered management UI. Uses the same control-plane methods as the API.
//! Tunnels, agents and the login screen live here; accounts and users in `accounts`.

use axum::Form;
use axum::extract::{FromRequestParts, Path, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use http::request::Parts;
use http::{HeaderValue, StatusCode, header};
use magicpipes_core::proto::Visibility;
use magicpipes_core::theme::{GLYPH, STYLE};
use serde::Deserialize;

use super::{AppState, ClientIp, Rejected, SESSION_COOKIE};
use crate::authz::Principal;
use crate::control::{EnrollmentOptions, Login, LoginError, TunnelView, UserView};

/// Percent-encodes everything but unreserved characters.
pub(super) fn url_encode(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

/// A `next` target that stays on this site: a path, never `//host` or a scheme.
pub(super) fn safe_next(next: Option<&str>) -> Option<&str> {
    next.filter(|n| n.starts_with('/') && !n.starts_with("//") && !n.contains('\\') && n.len() < 512 && !n.chars().any(char::is_control))
}

pub(super) fn esc(s: &str) -> String {
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

/// Extractor: a logged-in UI session. Redirects to the login page otherwise, and to the password
/// page while the user still has to replace a password an administrator set.
pub struct UiUser {
    pub(super) cookie: String,
    pub(super) who: Principal,
    pub(super) csrf: String,
    /// `None` for an admin-token session.
    pub(super) user: Option<UserView>,
}

impl FromRequestParts<AppState> for UiUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, app: &AppState) -> Result<Self, Self::Rejection> {
        // After signing in, the browser comes back to the page it asked for.
        let here = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let back = |to: &str| match here {
            "/" => Redirect::to(to).into_response(),
            _ => Redirect::to(&format!("{to}?next={}", url_encode(here))).into_response(),
        };
        let cookie = cookie_value(parts).ok_or_else(|| back("/login"))?;
        let s = app.control.session(&cookie).ok_or_else(|| back("/login"))?;
        let must_change = s.user.as_ref().is_some_and(|u| u.must_change_password);
        if must_change && !matches!(parts.uri.path(), "/password" | "/logout") {
            return Err(back("/password"));
        }
        Ok(UiUser { cookie, who: s.who, csrf: s.csrf, user: s.user })
    }
}

impl UiUser {
    #[allow(clippy::result_large_err)] // error pages are returned by value on purpose
    pub(super) fn check_csrf(&self, submitted: &str) -> Result<(), Response> {
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

pub(super) fn page(title: &str, user: Option<&UiUser>, body: &str) -> Response {
    let logout = user
        .map(|u| {
            let links: &[(&str, &str)] = if u.who.is_admin() {
                &[("/", "Tunnels"), ("/users", "Users"), ("/tags", "Tags"), ("/audit", "Audit log"), ("/account", "Account")]
            } else {
                &[("/", "Machines"), ("/account", "Account")]
            };
            let nav: String = links.iter().map(|(href, label)| format!(r#"<a class="btn ghost" href="{href}">{label}</a>"#)).collect();
            let me = u.user.as_ref().map_or("admin token".to_string(), |v| v.email.clone());
            format!(
                r#"<nav style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">{nav}<span class="sub">{me}</span><form method="post" action="/logout"><input type="hidden" name="csrf" value="{csrf}"><button class="btn ghost">Log out</button></form></nav>"#,
                me = esc(&me),
                csrf = esc(&u.csrf)
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
pub(super) fn when(ts: &str) -> String {
    let short = match (ts.get(..10), ts.get(11..16)) {
        (Some(d), Some(t)) if ts.as_bytes().get(10) == Some(&b'T') => format!("{d} · {t} UTC"),
        _ => ts.to_string(),
    };
    format!(r#"<time class="when" datetime="{0}" title="{0}">{1}</time>"#, esc(ts), esc(&short))
}

fn display_url(url: &str) -> &str {
    url.strip_prefix("https://").unwrap_or(url)
}

/// The public address: a link for HTTP tunnels; `tcp://` and `udp://` are not browsable.
fn public_address(t: &TunnelView, class: &str) -> String {
    if t.kind.is_http() {
        format!(
            r#"<a class="{class}" href="{url}" target="_blank" rel="noopener noreferrer">{shown} ↗</a>"#,
            url = esc(&t.public_url),
            shown = esc(display_url(&t.public_url)),
        )
    } else {
        format!(r#"<code class="{class}">{}</code>"#, esc(&t.public_url))
    }
}

/// The management URL agents and `magicpipes login` use.
pub(super) fn server_url(app: &AppState) -> String {
    let cfg = app.control.config();
    match cfg.management.listen.port() {
        443 => format!("https://{}", cfg.management.hostname),
        port => format!("https://{}:{port}", cfg.management.hostname),
    }
}

/// Tags as small chips; `none` when empty.
pub(super) fn chips(tags: &[String]) -> String {
    if tags.is_empty() {
        return r#"<span class="sub">none</span>"#.into();
    }
    tags.iter().map(|t| format!("<code>{}</code>", esc(t))).collect::<Vec<_>>().join(" ")
}

/// Tunnels and agents: everything for administrators, your own machines for members.
pub async fn index(user: UiUser, State(app): State<AppState>) -> Response {
    let admin = user.who.is_admin();
    let agents = app.control.agents(&user.who);
    let agent_name = |id: &str| agents.iter().find(|a| a.id == id).map(|a| a.name.clone()).unwrap_or_else(|| id.to_string());
    let tunnels = app.control.tunnels(&user.who);
    let mut rows = String::new();
    for t in &tunnels {
        rows.push_str(&format!(
            r#"<tr><td><a class="name" href="/tunnels/{id}">{name}</a>{address}</td><td><code>{target}</code></td><td>{access}</td><td>{agent}</td><td>{status}</td><td>{tls}</td><td class="num">{requests}</td></tr>"#,
            id = esc(&t.id),
            name = esc(&t.name),
            address = public_address(t, "sub"),
            target = esc(&t.target),
            access = access_cell(t),
            agent = esc(&agent_name(&t.agent_id)),
            status = badge(t.status),
            tls = if t.kind.is_http() { badge(t.tls) } else { r#"<span class="sub">—</span>"#.into() },
            requests = t.requests,
        ));
    }
    if tunnels.is_empty() {
        rows = r#"<tr><td colspan="7" class="empty">No tunnels yet. Run <code>magicpipes add 8080</code> on an enrolled machine.</td></tr>"#.into();
    }
    let mut agent_rows = String::new();
    for a in &agents {
        let last_seen = a.last_seen_at.as_deref().map(when).unwrap_or_else(|| r#"<span class="when">never</span>"#.into());
        let owner = a.owner_email.as_deref().map(esc).unwrap_or_else(|| r#"<span class="sub">service agent</span>"#.into());
        agent_rows.push_str(&format!(
            r#"<tr><td><span class="name">{name}</span><code class="sub">{id}</code></td><td>{owner}</td><td><form method="post" action="/agents/{id}/tags" style="display:flex;gap:6px;align-items:center"><input type="hidden" name="csrf" value="{csrf}"><input name="tags" value="{tags}" aria-label="Tags" style="min-width:9em"><button class="btn small">Save</button></form></td><td>{status}</td><td class="num">{tunnels}</td><td>{last_seen}</td><td class="num"><form method="post" action="/agents/{id}/revoke"><input type="hidden" name="csrf" value="{csrf}"><button class="btn danger small">Revoke</button></form></td></tr>"#,
            name = esc(&a.name),
            tags = esc(&a.tags.join(", ")),
            status = badge(if a.connected { "connected" } else { "disconnected" }),
            tunnels = a.tunnels,
            id = esc(&a.id),
            csrf = esc(&user.csrf),
        ));
    }
    if agents.is_empty() {
        agent_rows = r#"<tr><td colspan="7" class="empty">No agents enrolled yet.</td></tr>"#.into();
    }
    let domain = app.control.config().base_domain.clone();
    let online = agents.iter().filter(|a| a.connected).count();
    let requests: u64 = tunnels.iter().map(|t| t.requests).sum();
    let errors: u64 = tunnels.iter().map(|t| t.upstream_errors).sum();
    let body = format!(
        r#"<div class="head"><div><div class="eyebrow">Control plane · {domain}</div><h1>Tunnels</h1>
<p class="lede">Public tunnels are reachable by anyone who knows the address. Private ones ask people to sign in, and let in their owner and anyone who shares one of their access tags.</p></div>
<a class="btn" href="/">Refresh</a></div>
<div class="stats">
<div class="stat"><div class="k">Tunnels</div><div class="v">{n}</div></div>
<div class="stat"><div class="k">Agents online</div><div class="v">{online}<small>of {agents_total}</small></div></div>
<div class="stat"><div class="k">Requests</div><div class="v">{requests}</div></div>
<div class="stat"><div class="k">Upstream errors</div><div class="v">{errors}</div></div>
</div>
<div class="section"><h2>Tunnels<span class="count">{n}</span></h2></div>
<div class="card scroll"><table><thead><tr><th>Tunnel</th><th>Target</th><th>Who can open it</th><th>Agent</th><th>Status</th><th>TLS</th><th class="num">Requests</th></tr></thead><tbody>{rows}</tbody></table></div>
{shared}
<div class="section"><h2>Agents<span class="count">{agents_total}</span></h2></div>
<div class="card scroll"><table><thead><tr><th>Agent</th><th>Owner</th><th>Access tags</th><th>Status</th><th class="num">Tunnels</th><th>Last seen</th><th></th></tr></thead><tbody>{agent_rows}</tbody></table></div>
{enroll}"#,
        domain = esc(&domain),
        n = tunnels.len(),
        agents_total = agents.len(),
        enroll = if admin { enroll_panel(&app, &user) } else { member_enroll_hint(&app) },
        shared = shared_section(&app, &user),
    );
    page("Tunnels", Some(&user), &body)
}

pub async fn tunnel_detail(user: UiUser, State(app): State<AppState>, Path(id): Path<String>) -> Response {
    let Some(t) = app.control.tunnel(&user.who, &id) else {
        let body = r#"<a class="crumb" href="/">← Tunnels</a><h1>Not found</h1><p class="lede">There is no tunnel with that id or name. It may have been deleted.</p>"#;
        return (StatusCode::NOT_FOUND, page("Not found", Some(&user), body)).into_response();
    };
    let agent = app.control.agent_name(&user.who, &t.agent_id).unwrap_or_default();
    page(&t.name, Some(&user), &detail_body(&t, &agent, &user.csrf))
}

fn detail_body(t: &TunnelView, agent: &str, csrf: &str) -> String {
    let field = |k: &str, v: &str| format!("<dt>{}</dt><dd>{}</dd>", esc(k), v);
    let mut dl = String::new();
    dl.push_str(&field("Target", &format!("<code>{}</code>", esc(&t.target))));
    dl.push_str(&field("Agent", &format!(r#"{} <code class="sub">{}</code>"#, esc(agent), esc(&t.agent_id))));
    dl.push_str(&field("Who can open it", &access_cell(t)));
    if !t.labels.is_empty() {
        dl.push_str(&field("Labels", &chips(&t.labels)));
    }
    if t.kind.is_http() {
        dl.push_str(&field("TLS certificate", &badge(t.tls)));
    } else {
        let allow = if t.allow.is_empty() { "anyone".to_string() } else { esc(&t.allow.join(", ")) };
        dl.push_str(&field("Allowed clients", &allow));
    }
    if let Some(e) = &t.tls_error {
        dl.push_str(&field("TLS error", &esc(e)));
    }
    if let Some(e) = &t.port_error {
        dl.push_str(&field("Port error", &esc(e)));
    }
    dl.push_str(&field("Tunnel ID", &format!("<code>{}</code>", esc(&t.id))));
    dl.push_str(&field("Created", &when(&t.created_at)));
    let last = t.last_request_at.as_deref().map(when).unwrap_or_else(|| "never".into());
    format!(
        r#"<a class="crumb" href="/">← Tunnels</a>
<div class="head"><div><h1>{name}</h1><p class="lede">{address}</p></div>
<a class="btn" href="/tunnels/{id}">Refresh</a></div>
<div class="stats">
<div class="stat"><div class="k">Status</div><div class="v sm">{status}</div></div>
<div class="stat"><div class="k">{requests_label}</div><div class="v">{requests}</div></div>
<div class="stat"><div class="k">Upstream errors</div><div class="v">{errors}</div></div>
<div class="stat"><div class="k">Last request</div><div class="v sm">{last}</div></div>
</div>
<div class="section"><h2>Details</h2></div>
<div class="card"><dl>{dl}</dl></div>
<div class="card panel danger" style="margin-top:20px"><div><h3>Delete tunnel</h3><p>The public URL stops working at once and the agent stops serving it. In-flight requests finish.</p></div>
<form method="post" action="/tunnels/{id}/delete"><input type="hidden" name="csrf" value="{csrf}"><button class="btn danger">Delete tunnel</button></form></div>"#,
        name = esc(&t.name),
        address = public_address(t, ""),
        requests_label = if t.kind.is_http() { "Requests" } else { "Connections" },
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

impl CsrfForm {
    pub(super) fn csrf(&self) -> &str {
        &self.csrf
    }
}

pub async fn delete_tunnel(user: UiUser, State(app): State<AppState>, Path(id): Path<String>, Form(f): Form<CsrfForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    let _ = app.control.delete_tunnel(&user.who, &id);
    Redirect::to("/").into_response()
}

#[derive(Deserialize)]
pub struct TagsForm {
    csrf: String,
    #[serde(default)]
    tags: String,
}

pub async fn agent_tags(user: UiUser, State(app): State<AppState>, Path(id): Path<String>, Form(f): Form<TagsForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    match app.control.update_agent(&user.who, &id, Some(&[f.tags]), None) {
        Ok(()) => Redirect::to("/").into_response(),
        Err(e) => {
            let body = format!(r#"<a class="crumb" href="/">← Tunnels</a><div class="alert" role="alert">{}</div>"#, esc(&e.message));
            (StatusCode::BAD_REQUEST, page("Agent", Some(&user), &body)).into_response()
        }
    }
}

pub async fn revoke_agent(user: UiUser, State(app): State<AppState>, Path(id): Path<String>, Form(f): Form<CsrfForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    let _ = app.control.revoke_agent(&user.who, &id);
    Redirect::to("/").into_response()
}

/// Who can open a tunnel: anyone, or the owner plus these tags.
fn access_cell(t: &TunnelView) -> String {
    match t.visibility {
        Visibility::Public => r#"<span class="status warn">anyone</span>"#.into(),
        Visibility::Private if t.access.is_empty() => r#"<span class="status ok">private</span> <span class="sub">owner only</span>"#.into(),
        Visibility::Private => format!(r#"<span class="status ok">private</span> {}"#, chips(&t.access)),
    }
}

/// Tunnels shared with you that you don't manage.
fn shared_section(app: &AppState, user: &UiUser) -> String {
    let shared = app.control.shared(&user.who);
    if shared.is_empty() || user.user.is_none() {
        return String::new();
    }
    let rows: String = shared
        .iter()
        .map(|t| {
            let link = if t.kind.is_http() {
                format!(r#"<a class="name" href="{0}" target="_blank" rel="noopener noreferrer">{1} ↗</a>"#, esc(&t.public_url), esc(display_url(&t.public_url)))
            } else {
                format!("<code>{}</code>", esc(&t.public_url))
            };
            let owner = t.owner_email.as_deref().map(esc).unwrap_or_else(|| r#"<span class="sub">service agent</span>"#.into());
            format!(r#"<tr><td>{link}<span class="sub">{name}</span></td><td>{owner}</td><td>{vis}</td><td>{labels}</td></tr>"#,
                name = esc(&t.name),
                vis = t.visibility.as_str(),
                labels = chips(&t.labels))
        })
        .collect();
    format!(
        r#"<div class="section"><h2>Shared with you<span class="count">{n}</span></h2></div>
<div class="card scroll"><table><thead><tr><th>Tunnel</th><th>Owner</th><th>Visibility</th><th>Labels</th></tr></thead><tbody>{rows}</tbody></table></div>"#,
        n = shared.len()
    )
}

fn enroll_panel(app: &AppState, user: &UiUser) -> String {
    let users = app.control.users(&user.who);
    let owners: String = users
        .iter()
        .filter(|u| !u.disabled)
        .map(|u| format!(r#"<option value="{}">{}</option>"#, esc(&u.id), esc(&u.email)))
        .collect();
    let private = if users.is_empty() { "" } else { " checked" };
    format!(
        r#"<div class="section"><h2>Enroll a machine</h2></div>
<div class="card form"><p class="note" style="margin-top:0">Creates a single-use token for <code>magicpipes login</code>, shown once and valid for {mins} minutes. People can also enroll their own machines with <code>magicpipes login --server {server}</code>.</p>
<form method="post" action="/enrollments"><input type="hidden" name="csrf" value="{csrf}">
<label for="eo">Belongs to</label><select id="eo" name="owner"><option value="">Nobody (a service agent, managed by administrators)</option>{owners}</select>
<label for="et">Access tags</label><input id="et" name="tags" placeholder="team:dev, team:ops">
<label for="el">Labels (not used for access)</label><input id="el" name="labels" placeholder="environment:staging">
<label><input type="checkbox" name="allow_public" checked> Its tunnels may be public</label>
<label><input type="checkbox" name="default_private"{private}> Its tunnels are private unless asked otherwise</label>
<button class="btn primary" style="margin-top:14px">Create enrollment token</button></form></div>"#,
        mins = app.control.config().agents.enrollment_ttl_secs / 60,
        server = esc(&server_url(app)),
        csrf = esc(&user.csrf),
    )
}

fn member_enroll_hint(app: &AppState) -> String {
    format!(
        r#"<div class="card panel" style="margin-top:20px"><div><h3>Add a machine</h3><p>On the machine, run the command below and approve it in your browser.</p></div></div>
<pre class="term"><span class="p">$ </span>magicpipes login --server {}</pre>"#,
        esc(&server_url(app))
    )
}

#[derive(Deserialize)]
pub struct EnrollForm {
    csrf: String,
    #[serde(default)]
    owner: String,
    #[serde(default)]
    tags: String,
    #[serde(default)]
    labels: String,
    allow_public: Option<String>,
    default_private: Option<String>,
}

pub async fn create_enrollment(user: UiUser, State(app): State<AppState>, Form(f): Form<EnrollForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    let opts = EnrollmentOptions {
        owner_user_id: (!f.owner.is_empty()).then_some(f.owner),
        tags: vec![f.tags],
        labels: vec![f.labels],
        allow_public: Some(f.allow_public.is_some()),
        default_private: Some(f.default_private.is_some()),
    };
    let token = match app.control.create_enrollment(&user.who, opts) {
        Ok(t) => t,
        Err(e) => {
            let body = format!(r#"<a class="crumb" href="/">← Tunnels</a><div class="alert" role="alert">{}</div>"#, esc(&e.message));
            return (StatusCode::BAD_REQUEST, page("Enrollment token", Some(&user), &body)).into_response();
        }
    };
    let cfg = app.control.config();
    let server = server_url(&app);
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

fn login_page(error: Option<&str>, admin_token: bool, next: Option<&str>) -> Response {
    let err = error.map(|e| format!(r#"<div class="alert" role="alert">{}</div>"#, esc(e))).unwrap_or_default();
    let next = safe_next(next).map(|n| format!(r#"<input type="hidden" name="next" value="{}">"#, esc(n))).unwrap_or_default();
    let form = if admin_token {
        r#"<form method="post" action="/login">{next}<label for="t" style="margin-top:0">Admin token</label><input id="t" type="password" name="token" placeholder="mpadm_…" autocomplete="current-password" autofocus required>
<button class="btn primary block" style="margin-top:18px">Log in</button></form></div>
<p class="note"><a href="/login">Sign in with email and password</a> instead. The first admin token is written to <code>&lt;data_dir&gt;/admin-token</code>; create another with <code>magicpipesd admin-token</code>.</p>"#
    } else {
        r#"<form method="post" action="/login">{next}<label for="e" style="margin-top:0">Email</label><input id="e" type="email" name="email" autocomplete="username" autofocus required>
<label for="p">Password</label><input id="p" type="password" name="password" autocomplete="current-password" required>
<button class="btn primary block" style="margin-top:18px">Sign in</button></form></div>
<p class="note">Administrators create accounts. <a href="/login?method=token">Use an admin token</a></p>"#
    };
    page(
        "Sign in",
        None,
        &format!(r#"<div class="auth"><div class="eyebrow">MagicPipes</div><h1>Sign <em>in</em></h1><div class="card" style="margin-top:28px">{err}{form}</div>"#, form = form.replace("{next}", &next)),
    )
}

#[derive(Deserialize)]
pub struct LoginQuery {
    method: Option<String>,
    next: Option<String>,
}

pub async fn login_form(axum::extract::Query(q): axum::extract::Query<LoginQuery>) -> Response {
    login_page(None, q.method.as_deref() == Some("token"), q.next.as_deref())
}

#[derive(Deserialize)]
pub struct LoginForm {
    token: Option<String>,
    email: Option<String>,
    password: Option<String>,
    next: Option<String>,
}

/// Sets the session cookie and sends the browser on: to `next` (a path on this site), via the
/// password page if the user must replace an administrator-set password first.
pub(super) fn logged_in(app: &AppState, login: Login, next: Option<&str>) -> Response {
    let next = safe_next(next);
    let to = match (login.must_change_password, next) {
        (true, Some(n)) => format!("/password?next={}", url_encode(n)),
        (true, None) => "/password".to_string(),
        (false, Some(n)) => n.to_string(),
        (false, None) => "/".to_string(),
    };
    let mut resp = Redirect::to(&to).into_response();
    let max_age = app.control.config().users.session_max_age_secs;
    let value = format!("{SESSION_COOKIE}={}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={max_age}", login.cookie);
    resp.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&value).expect("cookie is ASCII"));
    resp
}

pub async fn login(State(app): State<AppState>, client: Option<axum::Extension<ClientIp>>, Form(f): Form<LoginForm>) -> Response {
    let client = client.map(|c| c.0.0);
    let next = f.next.as_deref();
    if let Some(token) = f.token {
        let checked = match app.control.login_admin_token(token.trim()) {
            Ok(found) => found.ok_or(()),
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, login_page(Some("Something went wrong. Try again."), true, next)).into_response(),
        };
        return match app.check_credential(checked, client) {
            Ok(login) => logged_in(&app, login, next),
            Err(Rejected::RateLimited) => {
                (StatusCode::TOO_MANY_REQUESTS, login_page(Some("Too many failed attempts. Try again later."), true, next)).into_response()
            }
            Err(Rejected::Invalid(())) => {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                (StatusCode::UNAUTHORIZED, login_page(Some("Invalid admin token."), true, next)).into_response()
            }
        };
    }
    let (email, password) = (f.email.unwrap_or_default(), f.password.unwrap_or_default());
    let checked = match app.control.login_password(&email, &password).await {
        Ok(login) => Ok(login),
        Err(LoginError::Invalid) => Err(()),
        Err(LoginError::Throttled) => {
            let msg = "Too many failed attempts for this account. Wait a few seconds and try again.";
            return (StatusCode::TOO_MANY_REQUESTS, login_page(Some(msg), false, next)).into_response();
        }
        Err(LoginError::Internal) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, login_page(Some("Something went wrong. Try again."), false, next)).into_response();
        }
    };
    match app.check_credential(checked, client) {
        Ok(login) => logged_in(&app, login, next),
        Err(Rejected::RateLimited) => {
            (StatusCode::TOO_MANY_REQUESTS, login_page(Some("Too many failed attempts. Try again later."), false, next)).into_response()
        }
        Err(Rejected::Invalid(())) => (StatusCode::UNAUTHORIZED, login_page(Some("Email or password is incorrect."), false, next)).into_response(),
    }
}

pub async fn logout(user: UiUser, State(app): State<AppState>, Form(f): Form<CsrfForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    app.control.logout(&user.who, &user.cookie);
    let mut resp = Redirect::to("/login").into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!("{SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"))
            .expect("cookie is ASCII"),
    );
    resp
}
