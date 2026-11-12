//! Minimal server-rendered management UI. Uses the same control-plane methods as the API.
//! Tunnels, agents and the login screen live here; accounts and users in `accounts`.

use std::collections::HashMap;
use std::sync::LazyLock;

use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use http::{HeaderValue, StatusCode, Uri, header};
use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::{ErrorBody, Kind, Visibility};
use magicpipes_core::theme::{GLYPH, STYLE};
use magicpipes_core::url;
use serde::Deserialize;

use super::extract::{Fields, NoFields, Posted, SignOut, UiUser};
use super::html::{self, Actions, Number, Text, alert, back, badge, chips, count, esc, form_alert, menu_post, row_menu, table, tag_chip, title_of, tone, when};
use super::icons::{self, CHECK, GLOBE, LOCK, OPENS_ELSEWHERE};
use super::picker::{self, Holder, Submitted};
use super::{AppState, ClientIp, Rejected, SESSION_COOKIE};
use crate::control::{EnrollmentOptions, Login, LoginError, TunnelView};
use crate::tunnel_auth::safe_path;

/// What a change did, said in one quiet line on the page it redirects to. The address carries only
/// a key from this list, so a link can't put words on the page.
macro_rules! done_messages {
    ($($name:ident $key:literal $message:literal,)*) => {
        #[derive(Clone, Copy)]
        pub(super) enum Done { $($name),* }

        impl Done {
            fn key(self) -> &'static str {
                match self { $(Done::$name => $key),* }
            }

            fn message(key: &str) -> Option<&'static str> {
                match key { $($key => Some($message),)* _ => None }
            }

            /// What the address says a change just did.
            pub(super) fn from_query(query: Option<&str>) -> Option<&'static str> {
                query?.split('&').find_map(|pair| Self::message(pair.strip_prefix("done=")?))
            }
        }
    };
}

done_messages! {
    TunnelDeleted "tunnel-deleted" "Tunnel deleted. Its address stopped working.",
    MachineRevoked "machine-revoked" "Machine revoked, and its tunnels deleted.",
    TagsSaved "tags-saved" "Tags saved.",
    TokenDeleted "token-deleted" "API token deleted.",
    SshKeyAdded "ssh-key-added" "SSH key added.",
    SshKeyDeleted "ssh-key-deleted" "SSH key deleted.",
    HostKeyForgotten "host-key-forgotten" "Host key forgotten. The next one the machine shows is kept.",
    CertificateForgotten "certificate-forgotten" "Certificate forgotten. The next one the machine shows is kept.",
    PasswordChanged "password-changed" "Password changed. Other devices were signed out.",
    UserAdded "user-added" "User added. They replace that password when they first sign in.",
    UserAddedForProxy "user-added-proxy" "User added.",
    RoleChanged "role-changed" "Role changed.",
    UserDisabled "user-disabled" "User disabled. They were signed out, and their machines stopped serving tunnels.",
    UserEnabled "user-enabled" "User enabled.",
    UserKeptDisabled "user-kept-disabled" "User kept disabled. Signing in won't enable it again.",
    TokensRevoked "tokens-revoked" "Their API tokens were revoked.",
    TagCreated "tag-created" "Tag created.",
    TagDeleted "tag-deleted" "Tag deleted.",
    RuleAdded "rule-added" "Rule added. People get its tag at their next sign-in through it.",
    RuleAddedNow "rule-added-now" "Rule added. Everyone with a confirmed address there holds its tag now.",
    RuleRemoved "rule-removed" "Rule removed. Whoever held its tag only through it lost it.",
    AccessOn "access-on" "That tag grants access now.",
    AccessOff "access-off" "That tag no longer grants access.",
    HostnameRegistered "hostname-registered" "Hostname registered. Its certificate is being ordered.",
    HostnameCovered "hostname-covered" "Hostname registered. It uses the certificate you added.",
    HostnameRemoved "hostname-removed" "Hostname removed, with the tunnel on it.",
    SignInSaved "sign-in-saved" "Saved. It applies from the next sign-in.",
    ProviderAdded "provider-added" "Provider added. Try it from a private window.",
    ProviderSaved "provider-saved" "Provider saved.",
    ProviderRemoved "provider-removed" "Provider removed.",
    CertificateAdded "certificate-added" "Certificate added. Its names use it now.",
    CertificateRemoved "certificate-removed" "Certificate removed.",
    InvitationSent "invitation-sent" "Invitation sent.",
    InvitationResent "invitation-resent" "Invitation sent again. The earlier link no longer works.",
    InvitationRevoked "invitation-revoked" "Invitation revoked. Its link no longer works.",
    Welcome "welcome" "Welcome. Your account is ready.",
    ConfirmationSent "confirmation-sent" "Check your email for a link to confirm your address.",
    AddressConfirmed "address-confirmed" "Address confirmed. You can get a sign-in link if you forget your password.",
    EmailSaved "email-saved" "Email settings saved. Send a test message to make sure mail arrives.",
    EmailRemoved "email-removed" "Email settings removed.",
    TestMessageSent "test-message-sent" "Test message sent. Check that it arrived.",
    AlertEmailOn "alert-email-on" "Saved. Alerts come by email, at most one message every 10 minutes.",
    AlertEmailOff "alert-email-off" "Saved. Alerts no longer come by email.",
    WebhookRemoved "webhook-removed" "Webhook removed.",
    WebhookTested "webhook-tested" "The test arrived.",
}

/// The address of `to`, saying what a change did.
pub(super) fn done_url(to: &str, what: Done) -> String {
    format!("{to}?done={}", what.key())
}

/// Back to `to` after a change, saying what happened.
pub(super) fn done(to: &str, what: Done) -> Response {
    Redirect::to(&done_url(to, what)).into_response()
}

/// A change that didn't happen: the reason, and the way back to `to`.
pub(super) fn failed(user: &UiUser, status: StatusCode, to: &str, to_label: &str, message: &str) -> Response {
    let body = format!(r#"{}<div class="spaced">{}</div>"#, back(to, to_label), alert(Some(message)));
    (status, page("Error", Some(user), &body)).into_response()
}

/// A thing that isn't there, or that this user may not know about.
pub(super) fn not_there(user: &UiUser, to: &str, to_label: &str, why: &str) -> Response {
    let body = format!(r#"{}<h1>Not found</h1><p class="lede">{}</p>"#, back(to, to_label), esc(why));
    (StatusCode::NOT_FOUND, page("Not found", Some(user), &body)).into_response()
}

/// What a change to one thing came to: back to `to` saying so, or the reason it didn't happen.
/// `false` means there was nothing the user may change, and never says which.
pub(super) fn outcome(user: &UiUser, result: Result<bool, ErrorBody>, to: &str, to_label: &str, what: Done, gone: &str) -> Response {
    match result {
        Ok(true) => done(to, what),
        Ok(false) => failed(user, StatusCode::NOT_FOUND, to, to_label, gone),
        Err(e) => failed(user, StatusCode::BAD_REQUEST, to, to_label, &e.message),
    }
}

/// Progressive enhancement for every page: a copy-to-clipboard button on each `pre.term` code
/// block. Add `data-nocopy` to a block to leave it without one. Served from `/ui.js` because the
/// CSP forbids inline scripts.
const SCRIPT: &str = include_str!("ui.js");

/// The script's address, with its digest in it, so browsers can keep it and a new version still
/// reaches them at once.
static SCRIPT_URL: LazyLock<String> = LazyLock::new(|| format!("/ui.js?v={}", &magicpipes_core::secret::sha256_hex(SCRIPT)[..16]));

pub async fn script() -> Response {
    let headers = [
        (header::CONTENT_TYPE, HeaderValue::from_static("text/javascript; charset=utf-8")),
        (header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=31536000, immutable")),
    ];
    (headers, SCRIPT).into_response()
}

/// The browser icons: an SVG that follows the light or dark theme, and bitmaps for browsers
/// without SVG icons and for home screens. The bitmaps come from `assets/favicon-tile.svg`
/// (`scripts/favicons.sh`).
pub const ICONS: [(&str, &[u8], &str); 3] = [
    ("/favicon.svg", include_bytes!("assets/favicon.svg"), "image/svg+xml"),
    ("/favicon.ico", include_bytes!("assets/favicon.ico"), "image/x-icon"),
    ("/apple-touch-icon.png", include_bytes!("assets/apple-touch-icon.png"), "image/png"),
];

pub fn icon(body: &'static [u8], kind: &'static str) -> Response {
    let headers = [(header::CONTENT_TYPE, HeaderValue::from_static(kind)), (header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=86400"))];
    (headers, body).into_response()
}

/// Which navigation link a page belongs under.
fn nav_section(path: &str) -> &'static str {
    match path.split('/').nth(1).unwrap_or("") {
        "" | "tunnels" => "/",
        "machines" | "agents" | "enrollments" => "/machines",
        "health" => "/health",
        "users" | "invitations" => "/users",
        "tags" => "/tags",
        "hostnames" => "/hostnames",
        "audit" => "/audit",
        "settings" => "/settings",
        "account" | "password" => "/account",
        _ => "",
    }
}

pub(super) fn page(title: &str, user: Option<&UiUser>, body: &str) -> Response {
    let nav = user
        .map(|u| {
            let links: &[(&str, &str)] = if u.who.is_admin() {
                &[("/", "Tunnels"), ("/machines", "Machines"), ("/health", "Health"), ("/users", "Users"), ("/tags", "Tags"), ("/hostnames", "Hostnames"), ("/audit", "Audit log"), ("/settings", "Settings"), ("/account", "Account")]
            } else {
                &[("/", "Tunnels"), ("/machines", "Machines"), ("/health", "Health"), ("/account", "Account")]
            };
            let section = nav_section(&u.path);
            let nav: String = links
                .iter()
                .map(|(href, label)| {
                    let current = match *href {
                        href if href == u.path => r#" aria-current="page""#,
                        href if href == section => r#" aria-current="true""#,
                        _ => "",
                    };
                    // Health carries a count of open alerts; a serious one fills it in.
                    let count = match u.alerts {
                        (0, _) => String::new(),
                        (n, bad) if *href == "/health" => format!(
                            r#"<span class="pill{}">{n}<span class="sr"> open {}</span></span>"#,
                            if bad { " bad" } else { "" },
                            if n == 1 { "alert" } else { "alerts" }
                        ),
                        _ => String::new(),
                    };
                    format!(r#"<a class="btn ghost" href="{href}"{current}>{label}{count}</a>"#)
                })
                .collect();
            let me = u.user.as_ref().map_or("admin token".to_string(), |v| v.email.clone());
            let sign_out = match &u.sign_out {
                SignOut::Here => format!(r#"<form method="post" action="/logout">{}<button class="btn ghost">Sign out</button></form>"#, u.csrf_field()),
                SignOut::AtProxy(url) => format!(r#"<a class="btn ghost" href="{}">Sign out</a>"#, esc(url)),
                SignOut::AtProxyElsewhere => String::new(),
            };
            format!(r#"<nav class="nav" aria-label="Main">{nav}<span class="sub me" title="{me}">{me}</span>{sign_out}</nav>"#, me = esc(&me))
        })
        .unwrap_or_default();
    let done = user.and_then(|u| u.done).map(|m| format!(r#"<div class="done with-ic" role="status">{CHECK}<span>{m}</span></div>"#)).unwrap_or_default();
    Html(format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><title>{} · MagicPipes</title>
<link rel="icon" href="/favicon.ico" sizes="32x32"><link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="apple-touch-icon" href="/apple-touch-icon.png"><style>{STYLE}{icon_style}{picker}{shared}{charts}</style><script src="{script}" defer></script></head><body>
<header class="top"><div class="top-in"><a class="brand" href="/">{GLYPH}MagicPipes</a>{nav}</div></header>
<main>{done}{body}</main><footer class="foot">MagicPipes {version} · self-hosted HTTPS tunnels</footer></body></html>"#,
        esc(title),
        icon_style = icons::STYLE,
        picker = picker::STYLE,
        shared = html::STYLE,
        charts = super::chart::STYLE,
        script = SCRIPT_URL.as_str(),
        version = esc(magicpipes_core::VERSION),
    ))
    .into_response()
}

/// Anything else on the management listener. The API's clients get its error format.
pub async fn not_found(uri: Uri) -> Response {
    if uri.path().starts_with("/api/") {
        let error = ErrorBody::new(ErrorCode::NotFound, "there is no such API path");
        return (StatusCode::NOT_FOUND, axum::Json(serde_json::json!({ "error": error }))).into_response();
    }
    let body = r#"<div class="auth"><h1>Not <em>found</em></h1><p class="lede">There's nothing at this address. <a href="/">Go to your tunnels</a>.</p></div>"#;
    (StatusCode::NOT_FOUND, page("Not found", None, body)).into_response()
}

/// A tunnel's certificate, in the Tunnels list: only worth a line while it isn't ready.
fn certificate_note(t: &TunnelView) -> String {
    if !t.kind.is_http() || t.tls == "ready" {
        return String::new();
    }
    format!(r#"<span class="status {} below">certificate {}</span>"#, tone(t.tls), esc(t.tls))
}

fn display_url(url: &str) -> &str {
    url.strip_prefix("https://").unwrap_or(url)
}

/// The public address: a link for HTTP tunnels; `tcp://` and `udp://` are not browsable.
fn public_address(t: &TunnelView, class: &str) -> String {
    if t.kind.is_desktop() {
        return format!(r#"<a class="{class}" href="{}">Open desktop</a>"#, esc(&super::desktop::href(&t.name)));
    }
    if t.kind == Kind::Ssh && class.contains("sub") {
        return format!(
            r#"<code class="{class}">{}</code><a class="sub" href="{}">Open terminal</a>"#,
            esc(&t.public_url),
            esc(&super::terminal::href(&t.name))
        );
    }
    if t.kind.is_http() {
        format!(
            r#"<a class="{class}" href="{url}" target="_blank" rel="noopener noreferrer">{shown} {OPENS_ELSEWHERE}</a>"#,
            url = esc(&t.public_url),
            shown = esc(display_url(&t.public_url)),
        )
    } else {
        format!(r#"<code class="{class}">{}</code>"#, esc(&t.public_url))
    }
}

/// The management URL agents and `magicpipes login` use.
pub(super) fn server_url(app: &AppState) -> String {
    app.control.config().management_url()
}

/// How many of a tunnel's `total` tags its row in the list shows. The list is for scanning, and the
/// tunnel's page has them all. Never hides one tag, because "+1 more" takes the same room.
fn tags_in_a_row(total: usize) -> usize {
    const SHOWN: usize = 3;
    if total <= SHOWN + 1 { total } else { SHOWN }
}

/// What's wrong, in one line, for the top of the home page. Machines without tunnels aren't a
/// problem by being off. `None` while there's nothing to report on.
fn health_line(tunnels: &[TunnelView], offline_machines: usize, certificates_expiring: usize) -> Option<String> {
    if tunnels.is_empty() {
        return None;
    }
    let tunnel_errors = tunnels.iter().filter(|t| t.status == "error").count();
    let failed_certs = tunnels.iter().filter(|t| t.kind.is_http() && t.tls == "failed").count();
    let pending_certs = tunnels.iter().filter(|t| t.kind.is_http() && t.tls == "pending").count();
    let mut problems = Vec::new();
    if offline_machines > 0 {
        problems.push(format!(r#"<a href="/machines">{} offline</a>"#, count(offline_machines, "machine", "machines")));
    }
    if tunnel_errors > 0 {
        problems.push(format!(r##"<a href="#tunnels">{} with an error</a>"##, count(tunnel_errors, "tunnel", "tunnels")));
    }
    if failed_certs > 0 {
        problems.push(format!(r##"<a href="#tunnels">{} failed</a>"##, count(failed_certs, "certificate", "certificates")));
    }
    let mut notes = Vec::new();
    if pending_certs > 0 {
        notes.push(format!("{} being ordered", count(pending_certs, "certificate", "certificates")));
    }
    if certificates_expiring > 0 {
        notes.push(format!(r#"<a href="/settings#certificates">{certificates_expiring} of your certificates expiring soon</a>"#));
    }
    let (tone, text) = match (problems.is_empty(), notes.is_empty()) {
        (false, _) => ("bad", [problems, notes].concat().join(" · ")),
        (true, true) => (
            "ok",
            match tunnels.len() {
                1 => "Your tunnel is healthy".to_string(),
                2 => "Both tunnels are healthy".to_string(),
                n => format!("All {n} tunnels are healthy"),
            },
        ),
        (true, false) => ("warn", format!("{}; everything else is healthy", notes.join(" · "))),
    };
    // The inner span keeps links and words in one line of text, or a flex gap comes between them.
    Some(format!(r#"<p class="health"><span class="status {tone}"><span>{text}</span></span></p>"#))
}

/// The way from nothing to a working tunnel.
fn first_steps(app: &AppState, user: &UiUser) -> String {
    let server = esc(&server_url(app));
    // An admin token has no account for `magicpipes login` to sign in to.
    let sign_in = if user.user.is_some() {
        format!(r#"<p>Sign in from that machine, and approve it in your browser.</p><pre class="term"><span class="p">$ </span>magicpipes login --server {server}</pre>"#)
    } else {
        r#"<p>Create an enrollment token under <a href="/machines">Machines</a>, and run the command it shows on that machine.</p>"#.to_string()
    };
    format!(
        r#"<div class="section"><h2>Get started</h2></div>
<ol class="steps">
<li><div><p>Install <code>magicpipes</code> on the machine running your application. <a href="https://github.com/cayspekko/magicpipes/releases" rel="noopener noreferrer">Download it</a> {OPENS_ELSEWHERE}</p></div></li>
<li><div>{sign_in}</div></li>
<li><div><p>Publish a local port, and it gets its own address.</p><pre class="term"><span class="p">$ </span>magicpipes add 8080</pre></div></li>
</ol>"#
    )
}

/// Tunnels: everything for administrators, your own and what's shared with you for members.
pub async fn index(user: UiUser, State(app): State<AppState>) -> Response {
    let agents = app.control.agents(&user.who);
    let agent_name = |id: &str| agents.iter().find(|a| a.id == id).map(|a| a.name.clone()).unwrap_or_else(|| id.to_string());
    let tunnels = app.control.tunnels(&user.who);
    let people = app.control.people(&user.who);
    let lede = r#"<p class="lede">Public tunnels open for anyone with the address; private ones ask people to sign in first.</p>"#;
    let shared = shared_section(&app, &user);
    if tunnels.is_empty() && agents.is_empty() {
        return page("Tunnels", Some(&user), &format!(r#"<h1>Tunnels</h1>{lede}{shared}{}"#, first_steps(&app, &user)));
    }
    let mut rows = String::new();
    for t in &tunnels {
        let (kind_icon, kind_name) = icons::tunnel_kind(t.kind, &t.target);
        rows.push_str(&format!(
            r#"<tr><td><div class="with-ic"><span class="kind" title="{kind_name}">{kind_icon}</span><div><a class="name" href="/tunnels/{id}">{name}</a>{address}</div></div></td><td>{access}</td><td>{agent}<code class="sub wrap">{target}</code></td><td>{status}{certificate}</td><td class="num">{requests}</td></tr>"#,
            id = esc(&t.id),
            name = esc(&t.name),
            address = public_address(t, "sub wrap"),
            target = esc(&t.target),
            access = access_cell(t, &people, true),
            agent = esc(&agent_name(&t.agent_id)),
            status = badge(t.status),
            certificate = certificate_note(t),
            requests = t.requests,
        ));
    }
    let online = agents.iter().filter(|a| a.connected).count();
    let offline_with_tunnels = agents.iter().filter(|a| !a.connected && a.tunnels > 0).count();
    let requests: u64 = tunnels.iter().map(|t| t.requests).sum();
    let errors: u64 = tunnels.iter().map(|t| t.upstream_errors).sum();
    let body = format!(
        r#"<h1>Tunnels</h1>{lede}{health}
<div class="stats">
<div class="stat"><div class="k">Tunnels</div><div class="v">{n}</div></div>
<div class="stat"><div class="k"><a href="/machines">Machines online</a></div><div class="v">{online}<small>of {agents_total}</small></div></div>
<div class="stat"><div class="k">Requests</div><div class="v">{requests}</div></div>
<div class="stat"><div class="k">Couldn't reach app</div><div class="v">{errors}</div></div>
</div>
<p class="note">Requests are counted since the server last started.</p>
<div class="spaced" id="tunnels">{list}</div>
{shared}"#,
        health = health_line(&tunnels, offline_with_tunnels, app.control.certificates_expiring(&user.who)).unwrap_or_default(),
        list = table(&[Text("Tunnel"), Text("Who can open it"), Text("Machine"), Text("Status"), Number("Requests")], &rows, "No tunnels yet. Run <code>magicpipes add 8080</code> on one of your machines."),
        n = tunnels.len(),
        agents_total = agents.len(),
    );
    page("Tunnels", Some(&user), &body)
}

/// What the enrollment form submitted, to show it again with an error.
struct EnrollAttempt<'a> {
    form: &'a Submitted,
    error: &'a str,
}

/// Machines: everything for administrators, your own for members, and how to add another.
fn machines_page(app: &AppState, user: &UiUser, attempt: Option<EnrollAttempt>) -> Response {
    let admin = user.who.is_admin();
    let agents = app.control.agents(&user.who);
    let reach = app.control.private_reach(&user.who);
    let mut rows = String::new();
    for a in &agents {
        let last_seen = a.last_seen_at.as_deref().map(when).unwrap_or_else(|| r#"<span class="when">never</span>"#.into());
        let owner = a.owner_email.as_deref().map(esc).unwrap_or_else(|| r#"<span class="sub">service agent</span>"#.into());
        let edit = picker::Edit {
            held: &a.tags,
            href: format!("/agents/{}/tags", a.id),
            subject: &a.name,
            addable: admin,
            holder: Holder::Agent,
            reach: reach.by_agent.get(&a.id),
        };
        // A personal machine publishes with its owner's tags; only service agents have their own,
        // which administrators edit.
        let editable = admin && a.owner_user_id.is_none();
        let tags = if a.owner_user_id.is_some() {
            r#"<span class="sub">its owner's</span>"#.to_string()
        } else if editable {
            edit.cell(user)
        } else {
            chips(&a.tags)
        };
        let question = format!("Revoke {}? Its tunnels are deleted, and it can't connect again until it is enrolled again.", a.name);
        let revoke_url = format!("/agents/{}/revoke", a.id);
        // A menu only when there's more than one thing to do.
        let actions = if editable {
            row_menu(&a.name, &[
                edit.link(user, "menu-item", "Edit tags", &format!("Edit tags of {}", a.name)),
                "<hr>".into(),
                menu_post(&revoke_url, &user.csrf_field(), &[], "Revoke", true, Some(&question)),
            ])
        } else {
            format!(
                r#"<form method="post" action="{url}" data-confirm="{question}">{csrf}<button class="btn danger small" aria-label="Revoke {name}">Revoke</button></form>"#,
                url = esc(&revoke_url),
                question = esc(&question),
                csrf = user.csrf_field(),
                name = esc(&a.name),
            )
        };
        rows.push_str(&format!(
            r#"<tr><td><a class="name" href="/machines/{id}">{name}</a><code class="sub">{id}</code></td><td>{owner}</td><td>{tags}</td><td>{status}</td><td class="num">{tunnels}</td><td>{last_seen}</td><td class="num">{actions}</td></tr>"#,
            name = esc(&a.name),
            status = badge(if a.connected { "connected" } else { "disconnected" }),
            tunnels = a.tunnels,
            id = esc(&a.id),
        ));
    }
    let error = attempt.as_ref().map(|a| a.error);
    let body = format!(
        r#"<h1>Machines</h1><p class="lede">The computers running the <code>magicpipes</code> agent, each serving its own tunnels.</p>
<div class="spaced">{list}</div>
{enroll}{registry}"#,
        list = table(&[Text("Machine"), Text("Owner"), Text("Tags"), Text("Status"), Number("Tunnels"), Text("Last seen"), Actions], &rows, "No machines yet."),
        registry = picker::registry(app, user),
        enroll = if admin { enroll_panel(app, user, attempt.as_ref()) } else { member_enroll_hint(app) },
    );
    page(&title_of("Machines", error.is_some()), Some(user), &body)
}

pub async fn machines(user: UiUser, State(app): State<AppState>) -> Response {
    machines_page(&app, &user, None)
}

pub async fn tunnel_detail(user: UiUser, State(app): State<AppState>, Path(id): Path<String>, Query(q): Query<super::health::PeriodQuery>) -> Response {
    let gone = "There is no tunnel with that id or name. It may have been deleted.";
    let Some(t) = app.control.tunnel(&user.who, &id) else {
        return not_there(&user, "/", "Tunnels", gone);
    };
    let Some(series) = app.control.tunnel_history(&user.who, &t.id, q.period(&app)) else {
        return not_there(&user, "/", "Tunnels", gone);
    };
    let history_days = app.control.config().monitoring.history_days;
    let traffic = super::health::traffic_section(&format!("/tunnels/{}", t.id), &series, t.kind.is_http(), history_days);
    let notices = super::health::notices(&app.control.alerts_about(&user.who, "tunnel", &t.id));
    let now = magicpipes_core::unix_now();
    let check = super::health::check_field(&t, app.control.check_result(&t.id).as_ref(), app.control.checks_on(), now);
    let outside = super::health::outside_field(&t, app.control.outside_result(&t.id).as_ref(), now);
    let agent = app.control.agent_name(&user.who, &t.agent_id).unwrap_or_default();
    let people = app.control.people(&user.who);
    let ssh_ca = app.control.ssh_ca();
    let viewer_email = user.user.as_ref().map(|u| u.email.as_str()).unwrap_or("you@example.com");
    let parts = Parts { notices: &notices, traffic: &traffic, check: &check, outside: outside.as_deref() };
    page(&t.name, Some(&user), &detail_body(&t, &agent, &user.csrf_field(), &people, ssh_ca.as_deref(), viewer_email, &parts))
}

/// What a tunnel's page shows about its health, ready.
struct Parts<'a> {
    notices: &'a str,
    traffic: &'a str,
    check: &'a str,
    /// For a tunnel `magicpipes probe` checks.
    outside: Option<&'a str>,
}

fn detail_body(t: &TunnelView, agent: &str, csrf: &str, people: &HashMap<String, String>, ssh_ca: Option<&str>, viewer_email: &str, parts: &Parts<'_>) -> String {
    let Parts { notices, traffic, check, outside } = *parts;
    let field = |k: &str, v: &str| format!("<dt>{}</dt><dd>{}</dd>", esc(k), v);
    let mut dl = String::new();
    dl.push_str(&field("Target", &format!("<code>{}</code>", esc(&t.target))));
    dl.push_str(&field("Machine", &format!(r#"<a href="/machines/{id}">{}</a> <code class="sub">{id}</code>"#, esc(agent), id = esc(&t.agent_id))));
    // SSH tunnels and desktops are always private: only their tags change.
    let change = if t.kind == Kind::Ssh || t.kind.is_desktop() {
        r#"<p class="note">To change it, run the same <code>magicpipes add</code> on that machine with <code>--tag</code>.</p>"#
    } else {
        r#"<p class="note">To change it, run the same <code>magicpipes add</code> on that machine with <code>--private</code>, <code>--public</code> or <code>--tag</code>.</p>"#
    };
    dl.push_str(&field("Who can open it", &format!("{}{change}", access_cell(t, people, false))));
    if t.kind.is_http() {
        dl.push_str(&field("TLS certificate", &badge(t.tls)));
    } else if t.kind.has_port() {
        // A private one has no public port, so nothing to allow anyone into.
        if t.public_port.is_some() {
            let allow = if t.allow.is_empty() { "anyone".to_string() } else { esc(&t.allow.join(", ")) };
            dl.push_str(&field("Allowed clients", &allow));
        }
    } else if let (Kind::Ssh, Some(ca)) = (t.kind, ssh_ca) {
        let open = format!(r#"<a href="{}">Open terminal</a>{}"#, esc(&super::terminal::href(&t.name)), super::terminal::setup(ca, viewer_email));
        dl.push_str(&field("Browser terminal", &open));
        let host_key = match &t.ssh_host_key {
            None => r#"<span class="sub">Kept the first time a browser terminal connects.</span>"#.to_string(),
            Some(k) => format!(
                r#"<code>{k}</code><form method="post" action="/tunnels/{id}/host-key/forget" data-confirm="Forget {name}'s host key? The next one it shows is trusted, so only do this after reinstalling the machine.">{csrf}<button class="btn small spaced">Forget host key</button></form>"#,
                k = esc(k),
                id = esc(&t.id),
                name = esc(&t.name),
            ),
        };
        dl.push_str(&field("Machine's host key", &host_key));
    } else if t.kind == Kind::Rdp {
        dl.push_str(&field("Remote Desktop clients", &format!("<code>magicpipes connect {}</code>", esc(&t.name))));
        let kept = match &t.rdp_certificate {
            None => r#"<span class="sub">Kept the first time a remote desktop connects.</span>"#.to_string(),
            Some(k) => format!(
                r#"<code>{k}</code><form method="post" action="/tunnels/{id}/host-key/forget" data-confirm="Forget {name}'s certificate? The next one it shows is trusted, so only do this after reinstalling the machine or replacing its certificate.">{csrf}<button class="btn small spaced">Forget certificate</button></form>"#,
                k = esc(k),
                id = esc(&t.id),
                name = esc(&t.name),
            ),
        };
        dl.push_str(&field("Machine's certificate", &kept));
    } else if t.kind == Kind::Vnc {
        dl.push_str(&field("VNC viewers", &format!("<code>magicpipes connect {}</code>", esc(&t.name))));
    }
    if let Some(e) = &t.tls_error {
        dl.push_str(&field("TLS error", &esc(e)));
    }
    dl.push_str(&field("Check", check));
    if let Some(outside) = outside {
        dl.push_str(&field("From outside", outside));
    }
    if let Some(e) = &t.port_error {
        dl.push_str(&field("Port error", &esc(e)));
    }
    dl.push_str(&field("Tunnel ID", &format!("<code>{}</code>", esc(&t.id))));
    dl.push_str(&field("Created", &when(&t.created_at)));
    let last = t.last_request_at.as_deref().map(when).unwrap_or_else(|| "never".into());
    format!(
        r#"{back}
<h1>{name}</h1><p class="lede">{address}</p>{notices}
<div class="stats">
<div class="stat"><div class="k">Status</div><div class="v sm">{status}</div></div>
<div class="stat"><div class="k">{requests_label}</div><div class="v">{requests}</div></div>
<div class="stat"><div class="k">Couldn't reach app</div><div class="v">{errors}</div></div>
<div class="stat"><div class="k">Last request</div><div class="v sm">{last}</div></div>
</div>
{traffic}
<div class="section"><h2>Details</h2></div>
<div class="card"><dl>{dl}</dl></div>
<div class="card panel danger spaced"><div><h3>Delete tunnel</h3><p>The public URL stops working at once and the agent stops serving it. In-flight requests finish.</p></div>
<form method="post" action="/tunnels/{id}/delete" data-confirm="Delete {name}? Its address stops working at once.">{csrf}<button class="btn danger">Delete tunnel</button></form></div>"#,
        back = back("/", "Tunnels"),
        name = esc(&t.name),
        address = public_address(t, ""),
        requests_label = if t.kind.is_http() { "Requests" } else { "Connections" },
        id = esc(&t.id),
        status = badge(t.status),
        requests = t.requests,
        errors = t.upstream_errors,
    )
}

pub async fn delete_tunnel(State(app): State<AppState>, Path(id): Path<String>, Posted(user, _): Posted<NoFields>) -> Response {
    outcome(&user, app.control.delete_tunnel(&user.who, &id), "/", "Tunnels", Done::TunnelDeleted, "That tunnel is already gone.")
}

/// Without scripts, an agent's Edit link opens this page of checkboxes.
pub async fn agent_tags_page(user: UiUser, State(app): State<AppState>, Path(id): Path<String>) -> Response {
    let Some(agent) = app.control.agents(&user.who).into_iter().find(|a| a.id == id) else {
        return not_there(&user, "/machines", "Machines", "There is no machine with that id.");
    };
    if agent.owner_user_id.is_some() || !user.who.is_admin() {
        let body = format!(
            r#"{}<h1>Tags of <em>{}</em></h1><p class="lede">A personal machine publishes with its owner's tags. Only service agents have tags of their own, which administrators set.</p>"#,
            back("/machines", "Machines"),
            esc(&agent.name)
        );
        return page("Machine tags", Some(&user), &body);
    }
    let all: Vec<(String, String)> = app.control.tags(&user.who).into_iter().map(|t| (t.name, t.description)).collect();
    let body = format!(
        r#"{back}<div class="eyebrow spaced">Service agent</div><h1>Tags of <em>{name}</em></h1>
<div class="card form"><form method="post" action="/agents/{id}/tags">{csrf}<input type="hidden" name="base" value="{base}">
{boxes}<p class="note">Its tunnels can carry only these tags.</p><button class="btn primary">Save</button></form></div>"#,
        back = back("/machines", "Machines"),
        name = esc(&agent.name),
        id = esc(&agent.id),
        csrf = user.csrf_field(),
        base = esc(&agent.tags.join(" ")),
        boxes = picker::fieldset("Tags", &all, &agent.tags, None),
    );
    page("Machine tags", Some(&user), &body)
}

pub async fn agent_tags(State(app): State<AppState>, Path(id): Path<String>, Posted(user, fields): Posted<Fields>) -> Response {
    let refused = |message: &str| failed(&user, StatusCode::BAD_REQUEST, "/machines", "Machines", message);
    let form = match Submitted::parse(fields) {
        Ok(f) => f,
        Err(e) => return refused(&e),
    };
    if let Err(e) = form.create_missing(&app, &user.who) {
        return refused(&e);
    }
    let result = match form.change() {
        Some((add, remove)) => app.control.change_agent_tags(&user.who, &id, &add, &remove).map(drop),
        None => app.control.set_agent_tags(&user.who, &id, &form.want).map(drop),
    };
    match result {
        Ok(()) => done("/machines", Done::TagsSaved),
        Err(e) => refused(&e.message),
    }
}

pub async fn revoke_agent(State(app): State<AppState>, Path(id): Path<String>, Posted(user, _): Posted<NoFields>) -> Response {
    outcome(&user, app.control.revoke_agent(&user.who, &id), "/machines", "Machines", Done::MachineRevoked, "That machine is already gone.")
}

/// Who can open a tunnel: anyone, or people with one of these tags; a personal tag shows as its
/// person where `people` knows them. `in_a_row`: only the first few, with a link to the rest.
fn access_cell(t: &TunnelView, people: &HashMap<String, String>, in_a_row: bool) -> String {
    match t.visibility {
        Visibility::Public => format!(r#"<span class="status warn iconic">{GLOBE}anyone</span>"#),
        Visibility::Private if t.access.is_empty() => format!(r#"<div class="access"><span class="status ok iconic">{LOCK}private</span><span class="sub">nobody: it has no tag that grants access</span></div>"#),
        Visibility::Private => {
            // Whoever is looking first, then other people, then groups.
            let mut tags: Vec<(&str, Option<&str>)> = t
                .access
                .iter()
                .map(|tag| match people.get(tag) {
                    Some(person) => (person.as_str(), Some(tag.as_str())),
                    None => (tag.as_str(), None),
                })
                .collect();
            tags.sort_by_key(|(shown, title)| match (*shown, title) {
                ("you", Some(_)) => 0,
                (_, Some(_)) => 1,
                (_, None) => 2,
            });
            let shown = if in_a_row { tags_in_a_row(tags.len()) } else { tags.len() };
            let mut list: Vec<String> = tags[..shown].iter().map(|(name, title)| tag_chip(name, *title)).collect();
            if shown < tags.len() {
                let rest: Vec<&str> = tags[shown..].iter().map(|(name, _)| *name).collect();
                list.push(format!(
                    r#"<a class="tagmore" href="/tunnels/{id}" title="{rest}" aria-label="All {total} tags of {name}">+{n} more</a>"#,
                    id = esc(&t.id),
                    rest = esc(&rest.join(", ")),
                    total = tags.len(),
                    name = esc(&t.name),
                    n = rest.len(),
                ));
            }
            format!(r#"<div class="access"><span class="status ok iconic">{LOCK}private</span><span class="taglist">{}</span></div>"#, list.join(" "))
        }
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
                format!(r#"<a class="name" href="{0}" target="_blank" rel="noopener noreferrer">{1} {OPENS_ELSEWHERE}</a>"#, esc(&t.public_url), esc(display_url(&t.public_url)))
            } else if t.kind == Kind::Ssh {
                format!(r#"<code>{}</code><a class="sub" href="{}">Open terminal</a>"#, esc(&t.public_url), esc(&super::terminal::href(&t.name)))
            } else if t.kind.is_desktop() {
                format!(r#"<a class="name" href="{}">Open desktop</a>"#, esc(&super::desktop::href(&t.name)))
            } else {
                format!("<code>{}</code>", esc(&t.public_url))
            };
            let owner = t.owner_email.as_deref().map(esc).unwrap_or_else(|| r#"<span class="sub">service agent</span>"#.into());
            format!(r#"<tr><td>{link}<span class="sub">{name}</span></td><td>{owner}</td><td>{who}</td></tr>"#,
                name = esc(&t.name),
                who = if t.visibility == Visibility::Public { "anyone" } else { "private" })
        })
        .collect();
    format!(
        r#"<div class="section"><h2>Shared with you<span class="count">{n}</span></h2></div>
{list}"#,
        n = shared.len(),
        list = table(&[Text("Tunnel"), Text("Owner"), Text("Who can open it")], &rows, ""),
    )
}

fn enroll_panel(app: &AppState, user: &UiUser, attempt: Option<&EnrollAttempt>) -> String {
    let users = app.control.users(&user.who);
    let typed = attempt.map(|a| a.form);
    let owner = typed.and_then(|f| f.get("owner")).unwrap_or("");
    let owners: String = users
        .iter()
        .filter(|u| !u.disabled)
        .map(|u| format!(r#"<option value="{id}"{selected}>{email}</option>"#, id = esc(&u.id), selected = if u.id == owner { " selected" } else { "" }, email = esc(&u.email)))
        .collect();
    let checked = |name: &str, otherwise: bool| if typed.map_or(otherwise, |f| f.get(name).is_some()) { " checked" } else { "" };
    let all: Vec<(String, String)> = app.control.tags(&user.who).into_iter().map(|t| (t.name, t.description)).collect();
    let tags = picker::fieldset("Tags for a service agent", &all, typed.map_or(&[], |f| &f.want), Some("For the new machine"));
    format!(
        r#"<div class="section"><h2>Enroll a machine</h2></div>
<div class="card form">{error}<p class="note">Creates a single-use token for <code>magicpipes login</code>, shown once and valid for {mins} minutes. People can also enroll their own machines with <code>magicpipes login --server {server}</code>.</p>
<form method="post" action="/enrollments">{csrf}
<label for="eo">Belongs to</label><select id="eo" name="owner"><option value="">Nobody (a service agent, managed by administrators)</option>{owners}</select>
{tags}
<label><input type="checkbox" name="allow_public"{allow_public}> Its tunnels may be public</label>
<label><input type="checkbox" name="default_private"{private}> Its tunnels are private unless asked otherwise</label>
<button class="btn primary">Create enrollment token</button></form></div>"#,
        error = form_alert(attempt.map(|a| a.error)),
        mins = app.control.config().agents.enrollment_ttl_secs / 60,
        server = esc(&server_url(app)),
        csrf = user.csrf_field(),
        allow_public = checked("allow_public", true),
        private = checked("default_private", !users.is_empty()),
    )
}

fn member_enroll_hint(app: &AppState) -> String {
    format!(
        r#"<div class="section"><h2>Add a machine</h2></div><div class="card panel"><div><p>On the machine, run the command below and approve it in your browser.</p></div></div>
<pre class="term"><span class="p">$ </span>magicpipes login --server {}</pre>"#,
        esc(&server_url(app))
    )
}

pub async fn create_enrollment(State(app): State<AppState>, Posted(user, fields): Posted<Fields>) -> Response {
    // Checkboxes named `tag`, or a `tags` field from an older page.
    let form = match Submitted::parse(fields) {
        Ok(f) => f,
        Err(e) => return failed(&user, StatusCode::BAD_REQUEST, "/machines", "Machines", &e),
    };
    let refused = |error: &str| (StatusCode::BAD_REQUEST, machines_page(&app, &user, Some(EnrollAttempt { form: &form, error }))).into_response();
    if let Err(e) = form.create_missing(&app, &user.who) {
        return refused(&e);
    }
    let owner = form.get("owner").unwrap_or("");
    let opts = EnrollmentOptions {
        owner_user_id: (!owner.is_empty()).then(|| owner.to_string()),
        tags: form.want.clone(),
        allow_public: Some(form.get("allow_public").is_some()),
        default_private: Some(form.get("default_private").is_some()),
    };
    let token = match app.control.create_enrollment(&user.who, opts) {
        Ok(t) => t,
        Err(e) => return refused(&e.message),
    };
    let cfg = app.control.config();
    let server = server_url(&app);
    let body = format!(
        r#"{back}
<div class="eyebrow spaced">Enrollment token</div><h1>Enroll a <em>machine</em></h1>
<p class="lede">Run this on the machine you want to enroll. The token works once, expires in {mins} minutes, and is not shown again.</p>
<pre class="term"><span class="p">$ </span>magicpipes login --server {server} --token {token}</pre>
<p class="note">Then expose a local port with <code>magicpipes add 8080</code>.</p>"#,
        back = back("/machines", "Machines"),
        mins = cfg.agents.enrollment_ttl_secs / 60,
        server = esc(&server),
        token = esc(&token),
    );
    page("Enrollment token", Some(&user), &body)
}

pub(super) fn login_page(app: &AppState, error: Option<&str>, admin_token: bool, next: Option<&str>) -> Response {
    login_page_saying(app, error, None, admin_token, next)
}

/// The sign-in page, with `said` above it: what just happened.
fn login_page_saying(app: &AppState, error: Option<&str>, said: Option<&str>, admin_token: bool, next: Option<&str>) -> Response {
    let err = format!("{}{}", said.map(|s| format!(r#"<div class="done" role="status">{}</div>"#, esc(s))).unwrap_or_default(), alert(error));
    let next = safe_path(next);
    let proxied = app.control.proxy_auth().is_some();
    let providers = app.control.oidc_providers();
    // One link per provider, above the password form. They carry the destination too.
    let sso = if admin_token || providers.is_empty() {
        String::new()
    } else {
        let links: String = providers
            .iter()
            .map(|p| {
                let q = next.map(|n| format!("?next={}", url::encode(n))).unwrap_or_default();
                format!(r#"<a class="btn block sso" href="/auth/oidc/{}{q}">Continue with {}</a>"#, esc(&p.id), esc(&p.label))
            })
            .collect();
        format!(r#"{links}<p class="note or">or</p>"#)
    };
    // Switching between the two forms keeps the destination.
    let nq = next.map(|n| format!("&amp;next={}", url::encode(n))).unwrap_or_default();
    let next = next.map(|n| format!(r#"<input type="hidden" name="next" value="{}">"#, esc(n))).unwrap_or_default();
    const TOKEN_FORM: &str = r#"<form method="post" action="/login">{next}<label for="t">Admin token</label><input id="t" type="password" name="token" placeholder="mpadm_…" autocomplete="current-password" autofocus required>
<button class="btn primary block">Sign in</button></form></div>"#;
    let form = if proxied {
        format!(r#"{TOKEN_FORM}
<p class="note">This server signs people in through its proxy, which hasn't said who you are. Administrators can use an admin token here if the proxy is down.</p>"#)
    } else if admin_token {
        format!(r#"{TOKEN_FORM}
<p class="note"><a href="/login?method=password{{nq}}">Sign in with email and password</a> instead. The first admin token is written to <code>&lt;data_dir&gt;/admin-token</code>; create another with <code>magicpipesd admin-token</code>.</p>"#)
    } else {
        r#"<form method="post" action="/login">{next}<label for="e">Email</label><input id="e" type="email" name="email" autocomplete="username" autofocus required>
<label for="p">Password</label><input id="p" type="password" name="password" autocomplete="current-password" required>
<button class="btn primary block">Sign in</button></form>{forgot}</div>
<p class="note">Administrators create accounts. <a href="/login?method=token{nq}">Use an admin token</a></p>"#
            .replace("{forgot}", if app.control.mail_on() { r#"<p class="note"><a href="/login/email">Forgot your password?</a></p>"# } else { "" })
    };
    page(
        "Sign in",
        None,
        &format!(r#"<div class="auth"><h1>Sign <em>in</em></h1><div class="card">{err}{sso}{form}</div>"#, form = form.replace("{next}", &next).replace("{nq}", &nq)),
    )
}

#[derive(Deserialize)]
pub struct LoginQuery {
    pub(super) method: Option<String>,
    pub(super) next: Option<String>,
}

pub async fn login_form(State(app): State<AppState>, axum::extract::Query(q): axum::extract::Query<LoginQuery>) -> Response {
    // Straight to the provider, unless another way in was asked for.
    if q.method.is_none()
        && let Some(p) = app.control.auto_redirect_provider()
    {
        let to = match safe_path(q.next.as_deref()) {
            Some(n) => format!("/auth/oidc/{}?next={}", p.id, url::encode(n)),
            None => format!("/auth/oidc/{}", p.id),
        };
        return Redirect::to(&to).into_response();
    }
    login_page(&app, None, q.method.as_deref() == Some("token"), q.next.as_deref())
}

/// Where signing out lands when the sign-in page would go straight back to a provider, and where
/// a provider's own sign-out returns: the sign-in page, without going anywhere by itself.
pub async fn signed_out(State(app): State<AppState>) -> Response {
    login_page_saying(&app, None, Some("You're signed out."), false, None)
}

#[derive(Deserialize)]
pub struct LoginForm {
    token: Option<String>,
    email: Option<String>,
    password: Option<String>,
    next: Option<String>,
}

/// The session cookie. `SameSite=Lax` so it comes along when a private tunnel on another site
/// sends the browser here to sign in; every state-changing form also needs its CSRF token.
pub(super) fn session_cookie(value: &str, max_age: u64) -> HeaderValue {
    let c = format!("{SESSION_COOKIE}={value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age}");
    HeaderValue::from_str(&c).expect("cookie is ASCII")
}

/// Sets the session cookie and sends the browser on: to `next` (a path on this site), via the
/// password page if the user must replace an administrator-set password first.
///
/// This answers a form submission, and browsers apply the CSP's `form-action 'self'` to every
/// redirect after one. `next` can lead off this host (`/auth/tunnel` sends the browser to a
/// tunnel), so it is reached through a page of ours that starts a fresh navigation, never a
/// redirect.
pub(super) fn logged_in(app: &AppState, login: Login, next: Option<&str>) -> Response {
    logged_in_to(app, login, next, "/")
}

/// As [`logged_in`], going to `landing` when nothing asked for another page.
pub(super) fn logged_in_to(app: &AppState, login: Login, next: Option<&str>, landing: &str) -> Response {
    let next = safe_path(next);
    let mut resp = match (login.must_change_password, next) {
        (true, Some(n)) => Redirect::to(&format!("/password?next={}", url::encode(n))).into_response(),
        (true, None) => Redirect::to("/password").into_response(),
        (false, Some(n)) => continue_page(n),
        (false, None) => Redirect::to(landing).into_response(),
    };
    let max_age = app.control.config().users.session_max_age_secs;
    resp.headers_mut().insert(header::SET_COOKIE, session_cookie(&login.cookie, max_age));
    resp
}

/// "Signed in; continuing…": a page that moves on with a `Refresh`, a navigation of its own that
/// the form's CSP no longer covers, plus a link for browsers that don't follow it.
fn continue_page(to: &str) -> Response {
    let body = format!(
        r#"<div class="auth"><div class="eyebrow">Signed in</div><h1>Continuing…</h1><p class="lede"><a href="{0}">Continue</a> if nothing happens.</p></div>"#,
        esc(to)
    );
    let mut resp = page("Signed in", None, &body);
    if let Ok(v) = HeaderValue::from_str(&format!("0;url={to}")) {
        resp.headers_mut().insert("refresh", v);
    }
    resp
}

/// "Continuing to X": the same, for leaving to a sign-in provider from a form.
pub(super) fn leaving_page(to: &str, label: &str) -> Response {
    let body = format!(
        r#"<div class="auth"><h1>Continuing to <em>{label}</em></h1><p class="lede"><a href="{to}">Continue</a> if nothing happens.</p></div>"#,
        label = esc(label),
        to = esc(to),
    );
    let mut resp = page("Continuing", None, &body);
    if let Ok(v) = HeaderValue::from_str(&format!("0;url={to}")) {
        resp.headers_mut().insert("refresh", v);
    }
    resp
}

/// Was this request sent by a page on another site? Browsers say so in `Sec-Fetch-Site`, and
/// older ones only in `Origin`. Our pages send `Referrer-Policy: no-referrer`, which makes even a
/// same-origin form post say `Origin: null`, so that value proves nothing. A client that sends
/// neither header (a script, curl) is not a browser being tricked.
pub(super) fn cross_site(headers: &http::HeaderMap) -> bool {
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    if let Some(site) = get("sec-fetch-site") {
        return site != "same-origin" && site != "none";
    }
    match (get("origin"), get("host")) {
        (None | Some("null"), _) => false,
        (Some(origin), Some(host)) => !origin.split_once("://").is_some_and(|(_, h)| h.eq_ignore_ascii_case(host)),
        (Some(_), None) => true,
    }
}

pub async fn login(
    State(app): State<AppState>,
    client: Option<axum::Extension<ClientIp>>,
    headers: http::HeaderMap,
    Form(f): Form<LoginForm>,
) -> Response {
    let client = client.map(|c| c.0.0);
    let next = f.next.as_deref();
    // Login CSRF: another site's form would sign this browser into the attacker's account (and a
    // machine approved there would then be enrolled as theirs).
    if cross_site(&headers) {
        return (StatusCode::FORBIDDEN, login_page(&app, Some("Sign in from this page, not from another site."), f.token.is_some(), next)).into_response();
    }
    if f.token.is_none() && app.control.proxy_auth().is_some() {
        return (StatusCode::FORBIDDEN, login_page(&app, Some("This server signs people in through its proxy."), true, next)).into_response();
    }
    if let Some(token) = f.token {
        let checked = match app.control.login_admin_token(token.trim()) {
            Ok(found) => found.ok_or(()),
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, login_page(&app, Some("Something went wrong. Try again."), true, next)).into_response(),
        };
        return match app.check_credential(checked, client) {
            Ok(login) => logged_in(&app, login, next),
            Err(Rejected::RateLimited) => {
                (StatusCode::TOO_MANY_REQUESTS, login_page(&app, Some("Too many failed attempts. Try again later."), true, next)).into_response()
            }
            Err(Rejected::Invalid(())) => {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                (StatusCode::UNAUTHORIZED, login_page(&app, Some("Invalid admin token."), true, next)).into_response()
            }
        };
    }
    let too_many = || (StatusCode::TOO_MANY_REQUESTS, login_page(&app, Some("Too many failed attempts. Try again later."), false, next)).into_response();
    // A password can be guessed, so a client over the limit isn't even checked (or hashed).
    if app.password_blocked(client) {
        return too_many();
    }
    let (email, password) = (f.email.unwrap_or_default(), f.password.unwrap_or_default());
    let checked = match app.control.login_password(&email, &password).await {
        Ok(login) => Ok(login),
        Err(LoginError::Invalid) => Err(()),
        Err(LoginError::Throttled) => {
            let msg = "Too many failed attempts for this account. Wait a few seconds and try again.";
            return (StatusCode::TOO_MANY_REQUESTS, login_page(&app, Some(msg), false, next)).into_response();
        }
        Err(LoginError::Internal) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, login_page(&app, Some("Something went wrong. Try again."), false, next)).into_response();
        }
    };
    match app.check_credential(checked, client) {
        Ok(login) => logged_in(&app, login, next),
        Err(Rejected::RateLimited) => too_many(),
        Err(Rejected::Invalid(())) => (StatusCode::UNAUTHORIZED, login_page(&app, Some("Email or password is incorrect."), false, next)).into_response(),
    }
}

#[derive(Deserialize)]
pub struct LogoutForm {
    /// "Switch account": where to go after signing in again.
    next: Option<String>,
}

pub async fn logout(State(app): State<AppState>, Posted(user, f): Posted<LogoutForm>) -> Response {
    let next = safe_path(f.next.as_deref());
    // Signing out at the provider too, where it's set to: asked before the session goes.
    let back = format!("{}/signed-out", server_url(&app));
    let at_provider = if next.is_none() { app.control.provider_sign_out(&user.cookie, &back).await } else { None };
    app.control.logout(&user.who, &user.cookie);
    let to = match next {
        Some(n) => format!("/login?next={}", url::encode(n)),
        // The sign-in page would only go straight back to the provider.
        None if app.control.auto_redirect_provider().is_some() => "/signed-out".to_string(),
        None => "/login".to_string(),
    };
    // A form's redirect can't leave this host, so a page of ours moves on to the provider.
    let mut resp = match at_provider {
        Some((url, label)) => leaving_page(&url, &label),
        None => Redirect::to(&to).into_response(),
    };
    resp.headers_mut().insert(header::SET_COOKIE, session_cookie("", 0));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_row_shows_a_few_tags_and_never_hides_just_one() {
        assert_eq!((0..=7).map(tags_in_a_row).collect::<Vec<_>>(), [0, 1, 2, 3, 4, 3, 3, 3]);
    }

    #[test]
    fn only_known_keys_say_anything() {
        assert_eq!(Done::from_query(Some("done=tag-created")), Some("Tag created."));
        assert_eq!(Done::from_query(Some("a=b&done=tag-created&c=d")), Some("Tag created."));
        assert_eq!(Done::from_query(Some("done=%3Cscript%3E")), None);
        assert_eq!(Done::from_query(Some("done=")), None);
        assert_eq!(Done::from_query(None), None);
        assert_eq!(done_url("/tags", Done::TagCreated), "/tags?done=tag-created");
    }

    #[test]
    fn pages_belong_under_their_navigation_link() {
        assert_eq!(nav_section("/"), "/");
        assert_eq!(nav_section("/tunnels/tn_a"), "/");
        assert_eq!(nav_section("/agents/ag_a/tags"), "/machines");
        assert_eq!(nav_section("/enrollments"), "/machines");
        assert_eq!(nav_section("/password"), "/account");
        assert_eq!(nav_section("/settings/providers/new"), "/settings");
        assert_eq!(nav_section("/cli"), "");
    }

    #[test]
    fn sign_in_posts_from_other_sites_are_refused() {
        let req = |pairs: &[(&'static str, &'static str)]| {
            let mut h = http::HeaderMap::new();
            h.insert(header::HOST, HeaderValue::from_static("mp.example.com"));
            for (k, v) in pairs {
                h.insert(*k, HeaderValue::from_static(v));
            }
            cross_site(&h)
        };
        assert!(!req(&[]), "a script sends neither header");
        assert!(!req(&[("sec-fetch-site", "same-origin"), ("origin", "https://mp.example.com")]));
        assert!(!req(&[("sec-fetch-site", "none")]), "typed or bookmarked");
        assert!(req(&[("sec-fetch-site", "cross-site")]));
        assert!(req(&[("sec-fetch-site", "same-site")]), "a tunnel subdomain is another origin");
        assert!(req(&[("origin", "https://evil.example")]), "a browser without Sec-Fetch-Site");
        assert!(!req(&[("sec-fetch-site", "same-origin"), ("origin", "null")]), "our own page, under no-referrer");
        assert!(req(&[("sec-fetch-site", "cross-site"), ("origin", "null")]));
    }
}
