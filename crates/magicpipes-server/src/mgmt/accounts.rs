//! UI pages for accounts: changing your password, your API tokens and sessions, user
//! administration and the audit log.

use axum::Form;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use http::StatusCode;
use serde::Deserialize;

use super::AppState;
use super::ui::{CsrfForm, UiUser, chips, esc, logged_in, page, safe_next, when};
use crate::authz::{Principal, Role};
use crate::control::{MIN_PASSWORD_CHARS, TunnelSignIn, UserView};

fn alert(msg: Option<&str>) -> String {
    msg.map(|m| format!(r#"<div class="alert" role="alert">{}</div>"#, esc(m))).unwrap_or_default()
}

/// A hidden CSRF field for a form.
fn csrf(user: &UiUser) -> String {
    format!(r#"<input type="hidden" name="csrf" value="{}">"#, esc(&user.csrf))
}

/// A page that shows a secret once, with a way back.
fn shown_once(user: &UiUser, title: &str, lede: &str, secret: &str, back: &str) -> Response {
    let body = format!(
        r#"<a class="crumb" href="{back}">← Back</a><div class="eyebrow" style="margin-top:22px">Shown once</div><h1>{title}</h1>
<p class="lede">{lede}</p><pre class="term">{secret}</pre>"#,
        back = esc(back),
        title = esc(title),
        lede = esc(lede),
        secret = esc(secret),
    );
    page(title, Some(user), &body)
}

// ---- password --------------------------------------------------------------------------------

fn password_page(user: &UiUser, error: Option<&str>, next: Option<&str>) -> Response {
    let next = safe_next(next).map(|n| format!(r#"<input type="hidden" name="next" value="{}">"#, esc(n))).unwrap_or_default();
    let forced = user.user.as_ref().is_some_and(|u| u.must_change_password);
    let lede = if forced {
        "An administrator set your password. Choose your own to continue."
    } else {
        "Changing your password signs you out everywhere else."
    };
    let body = format!(
        r#"<div class="auth"><div class="eyebrow">Account</div><h1>Change <em>password</em></h1><p class="lede">{lede}</p>
<div class="card" style="margin-top:28px">{err}<form method="post" action="/password">{csrf}{next}
<label for="c" style="margin-top:0">Current password</label><input id="c" type="password" name="current" autocomplete="current-password" required autofocus>
<label for="n">New password</label><input id="n" type="password" name="new" autocomplete="new-password" minlength="{min}" required>
<label for="r">Repeat the new password</label><input id="r" type="password" name="repeat" autocomplete="new-password" minlength="{min}" required>
<button class="btn primary block" style="margin-top:18px">Change password</button></form></div>
<p class="note">At least {min} characters. A long phrase is easier to remember than a short jumble.</p></div>"#,
        lede = esc(lede),
        err = alert(error),
        csrf = csrf(user),
        min = MIN_PASSWORD_CHARS,
    );
    page("Change password", Some(user), &body)
}

#[derive(Deserialize)]
pub struct NextQuery {
    next: Option<String>,
}

pub async fn password_form(user: UiUser, axum::extract::Query(q): axum::extract::Query<NextQuery>) -> Response {
    if user.user.is_none() {
        return Redirect::to("/account").into_response();
    }
    password_page(&user, None, q.next.as_deref())
}

#[derive(Deserialize)]
pub struct PasswordForm {
    csrf: String,
    current: String,
    new: String,
    repeat: String,
    next: Option<String>,
}

pub async fn change_password(user: UiUser, State(app): State<AppState>, Form(f): Form<PasswordForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    let next = f.next.as_deref();
    if f.new != f.repeat {
        return (StatusCode::BAD_REQUEST, password_page(&user, Some("The new passwords don't match."), next)).into_response();
    }
    match app.control.change_password(&user.who, &f.current, &f.new).await {
        Ok(login) => logged_in(&app, login, next),
        Err(e) => (StatusCode::BAD_REQUEST, password_page(&user, Some(&e.message), next)).into_response(),
    }
}

// ---- your account ----------------------------------------------------------------------------

pub async fn account(user: UiUser, State(app): State<AppState>) -> Response {
    let Some(me) = &user.user else {
        let body = r#"<div class="eyebrow">Account</div><h1>Admin <em>token</em></h1>
<p class="lede">You are signed in with an admin token, which has no account of its own. Create a user for yourself under <a href="/users">Users</a> and sign in with it; keep the admin token for emergencies.</p>"#;
        return page("Account", Some(&user), body);
    };
    let mut rows = String::new();
    for t in app.control.tokens(&user.who) {
        rows.push_str(&format!(
            r#"<tr><td><span class="name">{name}</span><code class="sub">{id}</code></td><td>{created}</td><td>{used}</td><td>{expires}</td><td class="num"><form method="post" action="/account/tokens/{id}/delete">{csrf}<button class="btn danger small">Delete</button></form></td></tr>"#,
            name = esc(&t.name),
            id = esc(&t.id),
            created = when(&t.created_at),
            used = t.last_used_at.as_deref().map(when).unwrap_or_else(|| "never".into()),
            expires = t.expires_at.as_deref().map(when).unwrap_or_else(|| "never".into()),
            csrf = csrf(&user),
        ));
    }
    if rows.is_empty() {
        rows = r#"<tr><td colspan="5" class="empty">No API tokens.</td></tr>"#.into();
    }
    let body = format!(
        r#"<div class="eyebrow">Account</div><h1>{name}</h1><p class="lede">{email} · {role}</p>
<div class="card panel" style="margin-top:20px"><div><h3>Password</h3><p>Changing it signs you out on other devices.</p></div><a class="btn" href="/password">Change password</a></div>
<div class="section"><h2>API tokens</h2></div>
<div class="card scroll"><table><thead><tr><th>Token</th><th>Created</th><th>Last used</th><th>Expires</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>
<div class="card form" style="margin-top:12px"><form method="post" action="/account/tokens">{csrf}
<label for="tn" style="margin-top:0">Name</label><input id="tn" name="name" maxlength="64" placeholder="ci-deploy" required>
<label for="te">Expires after (days, empty = never)</label><input id="te" name="expires_in_days" inputmode="numeric" pattern="[0-9]*">
<button class="btn primary" style="margin-top:14px">Create API token</button></form>
<p class="note">Use it as <code>Authorization: Bearer &lt;token&gt;</code>. It acts as you, with your current role.</p></div>
<div class="card panel danger" style="margin-top:20px"><div><h3>Sign out everywhere</h3><p>Ends every browser session of this account, this one included. API tokens keep working.</p></div>
<form method="post" action="/account/logout-everywhere">{csrf}<button class="btn danger">Sign out everywhere</button></form></div>"#,
        name = esc(if me.display_name.is_empty() { &me.email } else { &me.display_name }),
        email = esc(&me.email),
        role = me.role.as_str(),
        csrf = csrf(&user),
    );
    page("Account", Some(&user), &body)
}

#[derive(Deserialize)]
pub struct TokenForm {
    csrf: String,
    name: String,
    #[serde(default)]
    expires_in_days: String,
}

pub async fn create_token(user: UiUser, State(app): State<AppState>, Form(f): Form<TokenForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    let days = f.expires_in_days.trim().parse::<u32>().ok();
    match app.control.create_token(&user.who, &f.name, days) {
        Ok((t, secret)) => shown_once(
            &user,
            &format!("API token “{}”", t.name),
            "Copy it now: it is not shown again. Send it as Authorization: Bearer <token>.",
            &secret,
            "/account",
        ),
        Err(e) => (StatusCode::BAD_REQUEST, page("API token", Some(&user), &format!(r#"<a class="crumb" href="/account">← Account</a>{}"#, alert(Some(&e.message)))))
            .into_response(),
    }
}

pub async fn delete_token(user: UiUser, State(app): State<AppState>, Path(id): Path<String>, Form(f): Form<CsrfForm>) -> Response {
    if let Err(r) = user.check_csrf(f.csrf()) {
        return r;
    }
    let _ = app.control.delete_token(&user.who, &id);
    Redirect::to("/account").into_response()
}

pub async fn logout_everywhere(user: UiUser, State(app): State<AppState>, Form(f): Form<CsrfForm>) -> Response {
    if let Err(r) = user.check_csrf(f.csrf()) {
        return r;
    }
    let _ = app.control.logout_everywhere(&user.who);
    Redirect::to("/login").into_response()
}

// ---- users -----------------------------------------------------------------------------------

fn users_page(user: &UiUser, users: &[UserView], error: Option<&str>) -> Response {
    let mut rows = String::new();
    for u in users {
        let state = match (u.disabled, u.must_change_password) {
            (true, _) => r#"<span class="status bad">disabled</span>"#,
            (false, true) => r#"<span class="status warn">must change password</span>"#,
            (false, false) => r#"<span class="status ok">active</span>"#,
        };
        let me = matches!(&user.who, Principal::User { id, .. } if *id == u.id);
        let button = |action: &str, label: &str, class: &str| {
            format!(
                r#"<form method="post" action="/users/{id}" style="display:inline">{csrf}<input type="hidden" name="action" value="{action}"><button class="btn small {class}">{label}</button></form>"#,
                id = esc(&u.id),
                csrf = csrf(user),
            )
        };
        let actions = if me {
            r#"<span class="sub">you</span>"#.to_string()
        } else {
            let role = if u.role == Role::Admin { button("member", "Make member", "") } else { button("admin", "Make admin", "") };
            let status = if u.disabled { button("enable", "Enable", "") } else { button("disable", "Disable", "danger") };
            format!("{role} {status} {}", button("reset", "Reset password", ""))
        };
        let tags = format!(
            r#"<form method="post" action="/users/{id}" style="display:flex;gap:6px;align-items:center">{csrf}<input type="hidden" name="action" value="tags"><input name="tags" value="{tags}" aria-label="Access tags" style="min-width:9em"><button class="btn small">Save</button></form>"#,
            id = esc(&u.id),
            csrf = csrf(user),
            tags = esc(&u.tags.join(", ")),
        );
        rows.push_str(&format!(
            r#"<tr><td><span class="name">{name}</span><span class="sub">{email}</span></td><td>{role}</td><td>{tags}</td><td>{state}</td><td>{last}</td><td class="num">{actions}</td></tr>"#,
            name = esc(if u.display_name.is_empty() { &u.email } else { &u.display_name }),
            email = esc(&u.email),
            role = u.role.as_str(),
            last = u.last_login_at.as_deref().map(when).unwrap_or_else(|| "never".into()),
        ));
    }
    if rows.is_empty() {
        rows = r#"<tr><td colspan="6" class="empty">No users yet.</td></tr>"#.into();
    }
    let body = format!(
        r#"<div class="head"><div><div class="eyebrow">Administration</div><h1>Users</h1>
<p class="lede">People sign in with their email and a password. A password you set here must be changed at first sign-in. Access tags decide which private tunnels they reach; create tags under <a href="/tags">Tags</a>.</p></div></div>
{err}<div class="card scroll"><table><thead><tr><th>User</th><th>Role</th><th>Access tags</th><th>Status</th><th>Last sign-in</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>
<div class="section"><h2>Add a user</h2></div>
<div class="card form"><form method="post" action="/users">{csrf}
<label for="ue" style="margin-top:0">Email</label><input id="ue" type="email" name="email" required>
<label for="un">Name</label><input id="un" name="display_name" maxlength="100">
<label for="ur">Role</label><select id="ur" name="role"><option value="member">Member</option><option value="admin">Administrator</option></select>
<label for="up">Password (empty = generate one)</label><input id="up" type="password" name="password" autocomplete="new-password" minlength="{min}">
<button class="btn primary" style="margin-top:14px">Add user</button></form></div>"#,
        err = alert(error),
        csrf = csrf(user),
        min = MIN_PASSWORD_CHARS,
    );
    page("Users", Some(user), &body)
}

fn admins_only(user: &UiUser) -> Option<Response> {
    (!user.who.is_admin()).then(|| Redirect::to("/account").into_response())
}

pub async fn users(user: UiUser, State(app): State<AppState>) -> Response {
    if let Some(r) = admins_only(&user) {
        return r;
    }
    users_page(&user, &app.control.users(&user.who), None)
}

#[derive(Deserialize)]
pub struct NewUserForm {
    csrf: String,
    email: String,
    #[serde(default)]
    display_name: String,
    role: String,
    #[serde(default)]
    password: String,
}

pub async fn create_user(user: UiUser, State(app): State<AppState>, Form(f): Form<NewUserForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    let role = Role::parse(&f.role).unwrap_or(Role::Member);
    let password = (!f.password.is_empty()).then_some(f.password.as_str());
    match app.control.create_user(&user.who, &f.email, &f.display_name, role, password).await {
        Ok((u, Some(generated))) => shown_once(
            &user,
            &format!("Password for {}", u.email),
            "Give it to them over a channel you trust. They must replace it when they first sign in.",
            &generated,
            "/users",
        ),
        Ok(_) => Redirect::to("/users").into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, users_page(&user, &app.control.users(&user.who), Some(&e.message))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct UserActionForm {
    csrf: String,
    action: String,
    #[serde(default)]
    tags: String,
}

pub async fn update_user(user: UiUser, State(app): State<AppState>, Path(id): Path<String>, Form(f): Form<UserActionForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    let result = match f.action.as_str() {
        "reset" => match app.control.reset_password(&user.who, &id).await {
            Ok(password) => {
                let email = app.control.user(&user.who, &id).map(|u| u.email).unwrap_or_default();
                return shown_once(
                    &user,
                    &format!("New password for {email}"),
                    "Their sessions have ended. They must replace this password when they next sign in.",
                    &password,
                    "/users",
                );
            }
            Err(e) => Err(e),
        },
        "tags" => app.control.set_user_tags(&user.who, &id, &[f.tags]).map(drop),
        "admin" => app.control.update_user(&user.who, &id, Some(Role::Admin), None).map(drop),
        "member" => app.control.update_user(&user.who, &id, Some(Role::Member), None).map(drop),
        "disable" => app.control.update_user(&user.who, &id, None, Some(true)).map(drop),
        "enable" => app.control.update_user(&user.who, &id, None, Some(false)).map(drop),
        _ => return (StatusCode::BAD_REQUEST, "unknown action").into_response(),
    };
    match result {
        Ok(()) => Redirect::to("/users").into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, users_page(&user, &app.control.users(&user.who), Some(&e.message))).into_response(),
    }
}

// ---- signing in to private tunnels -----------------------------------------------------------

#[derive(Deserialize)]
pub struct TunnelQuery {
    #[serde(default)]
    host: String,
    #[serde(default)]
    state: String,
    #[serde(default, rename = "return")]
    back: String,
}

/// Where a private tunnel sends a browser that has no tunnel cookie yet. Signed in (the
/// extractor sees to that) and allowed, the browser goes back with a one-time code.
pub async fn auth_tunnel(user: UiUser, State(app): State<AppState>, axum::extract::Query(q): axum::extract::Query<TunnelQuery>) -> Response {
    let Some(me) = &user.user else {
        let body = r#"<div class="auth"><h1>Use your <em>account</em></h1><p class="lede">Private tunnels open for user accounts. You are signed in with an admin token; sign out and sign in with your email.</p></div>"#;
        return (StatusCode::FORBIDDEN, page("Private tunnel", Some(&user), body)).into_response();
    };
    if !crate::tunnel_auth::token_safe(&q.state) {
        return (StatusCode::BAD_REQUEST, page("Private tunnel", Some(&user), &alert(Some("This sign-in link is incomplete. Open the tunnel's address again.")))).into_response();
    }
    match app.control.tunnel_sign_in(&user.who, &q.host, &q.state) {
        TunnelSignIn::Allowed { callback } => {
            let back = if q.back.starts_with('/') && !q.back.starts_with("//") { q.back.as_str() } else { "/" };
            Redirect::to(&format!("{callback}&return={}", super::ui::url_encode(back))).into_response()
        }
        TunnelSignIn::NotFound => {
            let body = format!(r#"<div class="auth"><h1>Not found</h1><p class="lede">There is no private tunnel at <code>{}</code>.</p></div>"#, esc(&q.host));
            (StatusCode::NOT_FOUND, page("Private tunnel", Some(&user), &body)).into_response()
        }
        TunnelSignIn::Denied => {
            let body = format!(
                r#"<div class="auth"><div class="eyebrow">Private tunnel</div><h1>No <em>access</em></h1>
<p class="lede">You're signed in as {email}, but you don't have access to <code>{host}</code>. Ask its owner or an administrator.</p>
<form method="post" action="/logout" style="margin-top:20px">{csrf}<button class="btn">Switch account</button></form></div>"#,
                email = esc(&me.email),
                host = esc(&q.host),
                csrf = csrf(&user),
            );
            (StatusCode::FORBIDDEN, page("No access", Some(&user), &body)).into_response()
        }
    }
}

// ---- approving `magicpipes login` -------------------------------------------------------------

#[derive(Deserialize)]
pub struct CodeQuery {
    #[serde(default)]
    code: String,
}

/// The page `magicpipes login` opens: shows the waiting request and asks to approve it.
pub async fn device(user: UiUser, State(app): State<AppState>, axum::extract::Query(q): axum::extract::Query<CodeQuery>) -> Response {
    let Some(me) = &user.user else {
        let body = r#"<h1>Use your <em>account</em></h1><p class="lede">You are signed in with an admin token. Sign in with your user account to enroll your own machine, or create an enrollment token on the Tunnels page.</p>"#;
        return page("Approve a machine", Some(&user), body);
    };
    let Some(req) = app.control.device_request(&q.code) else {
        let body = format!(
            r#"<h1>Code not found</h1><p class="lede">The login code <code>{}</code> is unknown, was already used, or has expired. Run <code>magicpipes login</code> again.</p>"#,
            esc(&q.code)
        );
        return (StatusCode::NOT_FOUND, page("Approve a machine", Some(&user), &body)).into_response();
    };
    let boxes: String = me
        .tags
        .iter()
        .map(|t| format!(r#"<label><input type="checkbox" name="tag" value="{0}" checked> <code>{0}</code></label>"#, esc(t)))
        .collect();
    let tags = if boxes.is_empty() { r#"<p class="note">You hold no access tags, so this machine gets none: its private tunnels are for you alone.</p>"#.to_string() } else { boxes };
    let body = format!(
        r#"<div class="auth"><div class="eyebrow">magicpipes login</div><h1>Approve <em>{name}</em>?</h1>
<p class="lede">A machine asked to sign in as you {ago} seconds ago, from <code>{client}</code>. Compare the code with the one in its terminal.</p>
<div class="card" style="margin-top:20px"><div class="stat"><div class="k">Code</div><div class="v sm"><code>{code}</code></div></div>
<form method="post" action="/cli">{csrf}<input type="hidden" name="code" value="{code}">
<h3 style="margin-top:18px">Access tags for this machine</h3>{tags}
<div style="display:flex;gap:10px;margin-top:18px"><button class="btn primary" name="answer" value="approve">Approve</button><button class="btn danger" name="answer" value="deny">Deny</button></div></form></div>
<p class="note">Only approve a request you just started yourself: an approved machine acts as you and can publish tunnels in your name.</p></div>"#,
        name = esc(&req.agent_name),
        ago = req.age_secs,
        client = esc(&req.client.to_string()),
        code = esc(&req.user_code),
        csrf = csrf(&user),
    );
    page("Approve a machine", Some(&user), &body)
}

pub async fn answer_device(user: UiUser, State(app): State<AppState>, axum::extract::RawForm(raw): axum::extract::RawForm) -> Response {
    // Repeated `tag` fields, so not a plain `Form` struct.
    let fields: Vec<(String, String)> = form_urlencoded_pairs(&raw);
    let get = |k: &str| fields.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str()).unwrap_or("");
    if let Err(r) = user.check_csrf(get("csrf")) {
        return r;
    }
    let code = get("code").to_string();
    let approve = (get("answer") == "approve").then(|| fields.iter().filter(|(n, _)| n == "tag").map(|(_, v)| v.clone()).collect());
    let approved = approve.is_some();
    match app.control.answer_device_login(&user.who, &code, approve) {
        Ok(()) => {
            let (title, lede) = if approved {
                ("Approved", "Go back to the terminal: the machine finishes signing in by itself.")
            } else {
                ("Denied", "The machine was not signed in.")
            };
            page(title, Some(&user), &format!(r#"<div class="auth"><h1>{title}</h1><p class="lede">{lede}</p></div>"#))
        }
        Err(e) => (StatusCode::BAD_REQUEST, page("Approve a machine", Some(&user), &alert(Some(&e.message)))).into_response(),
    }
}

/// `application/x-www-form-urlencoded` pairs, decoded.
fn form_urlencoded_pairs(body: &[u8]) -> Vec<(String, String)> {
    let decode = |s: &str| {
        let s = s.replace('+', " ");
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            match (b[i], b.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok()).and_then(|h| u8::from_str_radix(h, 16).ok())) {
                (b'%', Some(v)) => {
                    out.push(v);
                    i += 3;
                }
                (c, _) => {
                    out.push(c);
                    i += 1;
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    };
    String::from_utf8_lossy(body)
        .split('&')
        .filter(|kv| !kv.is_empty())
        .take(500)
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (decode(k), decode(v))
        })
        .collect()
}

// ---- tags ----------------------------------------------------------------------------------

fn tags_page(user: &UiUser, app: &AppState, error: Option<&str>) -> Response {
    let mut rows = String::new();
    for t in app.control.tags(&user.who) {
        rows.push_str(&format!(
            r#"<tr><td><code>{name}</code></td><td>{description}</td><td>{created}</td><td class="num"><form method="post" action="/tags/delete">{csrf}<input type="hidden" name="name" value="{name}"><button class="btn danger small">Delete</button></form></td></tr>"#,
            name = esc(&t.name),
            description = esc(&t.description),
            created = when(&t.created_at),
            csrf = csrf(user),
        ));
    }
    if rows.is_empty() {
        rows = r#"<tr><td colspan="4" class="empty">No access tags yet.</td></tr>"#.into();
    }
    let body = format!(
        r#"<div class="head"><div><div class="eyebrow">Administration</div><h1>Access tags</h1>
<p class="lede">A person reaches a private tunnel when they share one of its access tags, or own it. Matching is exact. Deleting a tag removes it from everyone and everything at once.</p></div></div>
{err}<div class="card scroll"><table><thead><tr><th>Tag</th><th>Description</th><th>Created</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>
<div class="section"><h2>Create a tag</h2></div>
<div class="card form"><form method="post" action="/tags">{csrf}
<label for="tn" style="margin-top:0">Name</label><input id="tn" name="name" placeholder="team:dev" maxlength="64" required>
<label for="td">Description</label><input id="td" name="description" maxlength="200">
<button class="btn primary" style="margin-top:14px">Create tag</button></form>
<p class="note">Lowercase <code>key</code> or <code>key:value</code> with a-z, 0-9 and <code>._-</code>. Labels such as <code>environment:prod</code> on agents and tunnels are separate and never grant access. Example tags: {examples}</p></div>"#,
        err = alert(error),
        csrf = csrf(user),
        examples = chips(&["team:dev".into(), "contractor:acme".into()]),
    );
    page("Access tags", Some(user), &body)
}

pub async fn tags(user: UiUser, State(app): State<AppState>) -> Response {
    if let Some(r) = admins_only(&user) {
        return r;
    }
    tags_page(&user, &app, None)
}

#[derive(Deserialize)]
pub struct TagForm {
    csrf: String,
    name: String,
    #[serde(default)]
    description: String,
}

pub async fn create_tag(user: UiUser, State(app): State<AppState>, Form(f): Form<TagForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    match app.control.create_tag(&user.who, &f.name, &f.description) {
        Ok(_) => Redirect::to("/tags").into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, tags_page(&user, &app, Some(&e.message))).into_response(),
    }
}

pub async fn delete_tag(user: UiUser, State(app): State<AppState>, Form(f): Form<TagForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    let _ = app.control.delete_tag(&user.who, &f.name);
    Redirect::to("/tags").into_response()
}

// ---- audit log -------------------------------------------------------------------------------

pub async fn audit(user: UiUser, State(app): State<AppState>) -> Response {
    if let Some(r) = admins_only(&user) {
        return r;
    }
    let entries = app.control.audit_entries(&user.who, 200).unwrap_or_default();
    let users = app.control.users(&user.who);
    let name = |id: &str| users.iter().find(|u| u.id == id).map(|u| u.email.clone()).unwrap_or_else(|| id.to_string());
    let mut rows = String::new();
    for e in &entries {
        rows.push_str(&format!(
            "<tr><td>{at}</td><td>{actor}</td><td><code>{action}</code></td><td><code>{resource}</code></td><td>{detail}</td></tr>",
            at = when(&e.at),
            actor = esc(&name(&e.actor)),
            action = esc(&e.action),
            resource = esc(&e.resource),
            detail = esc(&e.detail),
        ));
    }
    if rows.is_empty() {
        rows = r#"<tr><td colspan="5" class="empty">Nothing recorded yet.</td></tr>"#.into();
    }
    let body = format!(
        r#"<div class="head"><div><div class="eyebrow">Administration</div><h1>Audit log</h1>
<p class="lede">Sign-ins, account changes and management actions, newest first. Kept for {days} days.</p></div><a class="btn" href="/audit">Refresh</a></div>
<div class="card scroll"><table><thead><tr><th>When</th><th>Who</th><th>Action</th><th>On</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table></div>"#,
        days = app.control.config().users.audit_retention_days,
    );
    page("Audit log", Some(&user), &body)
}
