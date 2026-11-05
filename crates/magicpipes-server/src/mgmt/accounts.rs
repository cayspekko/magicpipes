//! UI pages for accounts: changing your password, your API tokens and sessions, user
//! administration, tags, custom hostnames and the audit log.

use axum::Form;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use http::StatusCode;
use serde::Deserialize;

use super::AppState;
use super::icons::BACK;
use super::picker::{self, Holder, Submitted};
use super::ui::{CsrfForm, UiUser, alert, badge, chips, esc, logged_in, menu_post, page, row_menu, safe_next, when};
use crate::authz::{Principal, Role};
use crate::control::{MIN_PASSWORD_CHARS, TunnelSignIn};

/// A hidden CSRF field for a form.
pub(super) fn csrf(user: &UiUser) -> String {
    format!(r#"<input type="hidden" name="csrf" value="{}">"#, esc(&user.csrf))
}

/// A page that shows a secret once, with a way back.
fn shown_once(user: &UiUser, title: &str, lede: &str, secret: &str, back: &str) -> Response {
    let body = format!(
        r#"<a class="crumb" href="{back}">{BACK}Back</a><div class="eyebrow" style="margin-top:22px">Shown once</div><h1>{title}</h1>
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
{password}
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
        // Someone who only signs in with single sign-on has no password to change.
        password = if me.has_password {
            r#"<div class="card panel" style="margin-top:20px"><div><h3>Password</h3><p>Changing it signs you out on other devices.</p></div><a class="btn" href="/password">Change password</a></div>"#
        } else {
            ""
        },
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
        Err(e) => (StatusCode::BAD_REQUEST, page("API token", Some(&user), &format!(r#"<a class="crumb" href="/account">{BACK}Account</a>{}"#, alert(Some(&e.message)))))
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

fn users_page(user: &UiUser, app: &AppState, error: Option<&str>) -> Response {
    let users = app.control.users(&user.who);
    let reach = app.control.private_reach(&user.who);
    let mut rows = String::new();
    for u in &users {
        let state = match (u.disabled, u.must_change_password) {
            (true, _) => r#"<span class="status bad">disabled</span>"#,
            (false, true) => r#"<span class="status warn">must change password</span>"#,
            (false, false) => r#"<span class="status ok">active</span>"#,
        };
        let me = matches!(&user.who, Principal::User { id, .. } if *id == u.id);
        let edit = picker::Edit {
            held: &u.tags,
            href: format!("/users/{}/tags", u.id),
            subject: &u.email,
            addable: true,
            holder: Holder::User,
            reach: Some(&reach.by_tag),
        };
        let tags = edit.cell(user);
        let post = |action: &str, label: &str, danger: bool, confirm: Option<String>| {
            menu_post(&format!("/users/{}", u.id), &user.csrf, &[("action", action)], label, danger, confirm.as_deref())
        };
        let mut items = vec![edit.link(user, "menu-item", "Edit tags", &format!("Edit tags of {}", u.email))];
        if !me {
            items.push(if u.role == Role::Admin { post("member", "Make member", false, None) } else { post("admin", "Make admin", false, None) });
            let reset = format!("Reset the password of {}? Their sessions end, and they must replace the new password when they next sign in.", u.email);
            items.push(post("reset", "Reset password", false, Some(reset)));
            items.push("<hr>".into());
            items.push(if u.disabled {
                post("enable", "Enable", false, None)
            } else {
                post("disable", "Disable", true, Some(format!("Disable {}? They are signed out, and their machines stop serving tunnels.", u.email)))
            });
        }
        let you = if me { r#"<span class="sub" style="display:inline;margin-right:8px">you</span>"# } else { "" };
        let actions = format!("{you}{}", row_menu(&u.email, &items));
        rows.push_str(&format!(
            r#"<tr><td><span class="name">{name}</span><span class="sub">{email}{personal}</span></td><td>{role}</td><td>{tags}</td><td>{state}</td><td>{last}</td><td class="num">{actions}</td></tr>"#,
            name = esc(if u.display_name.is_empty() { &u.email } else { &u.display_name }),
            email = esc(&u.email),
            personal = u.personal_tag.as_deref().map(|t| format!(" · <code>{}</code>", esc(t))).unwrap_or_default(),
            role = u.role.as_str(),
            last = u.last_login_at.as_deref().map(when).unwrap_or_else(|| "never".into()),
        ));
    }
    if rows.is_empty() {
        rows = r#"<tr><td colspan="6" class="empty">No users yet.</td></tr>"#.into();
    }
    let body = format!(
        r#"<div class="head"><div><div class="eyebrow">Administration</div><h1>Users</h1>
<p class="lede">People sign in with their email and a password, or with a single sign-on provider if the server has one. A password you set here must be changed at first sign-in. Their tags decide which private tunnels they reach, next to their own personal tag (<code>user:…</code>); create tags under <a href="/tags">Tags</a>.</p></div></div>
{err}<div class="card scroll"><table><thead><tr><th>User</th><th>Role</th><th>Tags</th><th>Status</th><th>Last sign-in</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>
<div class="section"><h2>Add a user</h2></div>
<div class="card form"><form method="post" action="/users">{csrf}
<label for="ue" style="margin-top:0">Email</label><input id="ue" type="email" name="email" required>
<label for="un">Name</label><input id="un" name="display_name" maxlength="100">
<label for="ur">Role</label><select id="ur" name="role"><option value="member">Member</option><option value="admin">Administrator</option></select>
<label for="up">Password (empty = generate one)</label><input id="up" type="password" name="password" autocomplete="new-password" minlength="{min}">
<button class="btn primary" style="margin-top:14px">Add user</button></form></div>{registry}"#,
        registry = picker::registry(app, user),
        err = alert(error),
        csrf = csrf(user),
        min = MIN_PASSWORD_CHARS,
    );
    page("Users", Some(user), &body)
}

pub(super) fn admins_only(user: &UiUser) -> Option<Response> {
    (!user.who.is_admin()).then(|| Redirect::to("/account").into_response())
}

pub async fn users(user: UiUser, State(app): State<AppState>) -> Response {
    if let Some(r) = admins_only(&user) {
        return r;
    }
    users_page(&user, &app, None)
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
        Err(e) => (StatusCode::BAD_REQUEST, users_page(&user, &app, Some(&e.message))).into_response(),
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
        Err(e) => (StatusCode::BAD_REQUEST, users_page(&user, &app, Some(&e.message))).into_response(),
    }
}

/// Without scripts, a user's Edit link opens this page of checkboxes.
pub async fn user_tags_page(user: UiUser, State(app): State<AppState>, Path(id): Path<String>) -> Response {
    if let Some(r) = admins_only(&user) {
        return r;
    }
    let Some(u) = app.control.user(&user.who, &id) else {
        return (StatusCode::NOT_FOUND, page("Not found", Some(&user), &format!(r#"<a class="crumb" href="/users">{BACK}Users</a><h1>Not found</h1>"#))).into_response();
    };
    let all: Vec<(String, String)> = app.control.tags(&user.who).into_iter().map(|t| (t.name, t.description)).collect();
    let boxes = if all.is_empty() {
        r#"<p class="note">There are no tags yet: create them under <a href="/tags">Tags</a>.</p>"#.to_string()
    } else {
        picker::fieldset("Tags", &all, &u.tags, None)
    };
    let body = format!(
        r#"<a class="crumb" href="/users">{BACK}Users</a><div class="head"><div><div class="eyebrow">User</div><h1>Tags of <em>{email}</em></h1></div></div>
<div class="card form"><form method="post" action="/users/{id}/tags">{csrf}<input type="hidden" name="base" value="{base}">
{boxes}<button class="btn primary" style="margin-top:18px">Save</button></form></div>"#,
        email = esc(&u.email),
        id = esc(&u.id),
        csrf = csrf(&user),
        base = esc(&u.tags.join(" ")),
    );
    page("User tags", Some(&user), &body)
}

/// Saves a user's tags from the picker or the page above: only what changed since it was shown.
pub async fn user_tags(user: UiUser, State(app): State<AppState>, Path(id): Path<String>, axum::extract::RawForm(raw): axum::extract::RawForm) -> Response {
    let form = match Submitted::parse(&raw) {
        Ok(f) => f,
        Err(e) => return (StatusCode::BAD_REQUEST, users_page(&user, &app, Some(&e))).into_response(),
    };
    if let Err(r) = user.check_csrf(&form.csrf) {
        return r;
    }
    if let Err(e) = form.create_missing(&app, &user.who) {
        return (StatusCode::BAD_REQUEST, users_page(&user, &app, Some(&e))).into_response();
    }
    let result = match form.change() {
        Some((add, remove)) => app.control.change_user_tags(&user.who, &id, &add, &remove),
        None => app.control.set_user_tags(&user.who, &id, &form.want),
    };
    match result {
        Ok(_) => Redirect::to("/users").into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, users_page(&user, &app, Some(&e.message))).into_response(),
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
<form method="post" action="/logout" style="margin-top:20px">{csrf}<input type="hidden" name="next" value="{here}"><button class="btn">Switch account</button></form></div>"#,
                email = esc(&me.email),
                host = esc(&q.host),
                csrf = csrf(&user),
                here = esc(&format!(
                    "/auth/tunnel?host={}&state={}&return={}",
                    super::ui::url_encode(&q.host),
                    super::ui::url_encode(&q.state),
                    super::ui::url_encode(&q.back)
                )),
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
    if user.user.is_none() {
        let body = r#"<h1>Use your <em>account</em></h1><p class="lede">You are signed in with an admin token. Sign in with your user account to enroll your own machine, or create an enrollment token on the Tunnels page.</p>"#;
        return page("Approve a machine", Some(&user), body);
    }
    let Some(req) = app.control.device_request(&q.code) else {
        let body = format!(
            r#"<h1>Code not found</h1><p class="lede">The login code <code>{}</code> is unknown, was already used, or has expired. Run <code>magicpipes login</code> again.</p>"#,
            esc(&q.code)
        );
        return (StatusCode::NOT_FOUND, page("Approve a machine", Some(&user), &body)).into_response();
    };
    let body = format!(
        r#"<div class="auth"><div class="eyebrow">magicpipes login</div><h1>Approve <em>{name}</em>?</h1>
<p class="lede">A machine asked to sign in as you {ago} seconds ago, from <code>{client}</code>. Compare the code with the one in its terminal.</p>
<div class="card" style="margin-top:20px"><div class="stat"><div class="k">Code</div><div class="v sm"><code>{code}</code></div></div>
<form method="post" action="/cli">{csrf}<input type="hidden" name="code" value="{code}">
<p class="note">Its private tunnels are for you alone until it shares one with a tag you hold (<code>magicpipes add --tag</code>).</p>
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

#[derive(Deserialize)]
pub struct DeviceAnswer {
    csrf: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    answer: String,
}

pub async fn answer_device(user: UiUser, State(app): State<AppState>, Form(f): Form<DeviceAnswer>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    let approved = f.answer == "approve";
    match app.control.answer_device_login(&user.who, &f.code, approved) {
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
pub(super) fn form_urlencoded_pairs(body: &[u8]) -> Vec<(String, String)> {
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
        let (state, flip, label) = if t.access {
            (r#"<span class="status ok">grants access</span>"#, "off", "Turn off")
        } else {
            (r#"<span class="sub">label only</span>"#, "on", "Turn on")
        };
        rows.push_str(&format!(
            r#"<tr><td><code>{name}</code></td><td>{description}</td><td>{state} <form method="post" action="/tags/access" style="display:inline">{csrf}<input type="hidden" name="name" value="{name}"><input type="hidden" name="access" value="{flip}"><button class="btn small ghost">{label}</button></form></td><td>{created}</td><td class="num"><form method="post" action="/tags/delete">{csrf}<input type="hidden" name="name" value="{name}"><button class="btn danger small">Delete</button></form></td></tr>"#,
            name = esc(&t.name),
            description = esc(&t.description),
            created = when(&t.created_at),
            csrf = csrf(user),
        ));
    }
    if rows.is_empty() {
        rows = r#"<tr><td colspan="5" class="empty">No tags yet.</td></tr>"#.into();
    }
    let body = format!(
        r#"<div class="head"><div><div class="eyebrow">Administration</div><h1>Tags</h1>
<p class="lede">Tags label people, machines and tunnels. A person can open a private tunnel when they share a tag with it that grants access; everyone holds a personal tag (<code>user:…</code>) that the server puts on the tunnels of their machines. Matching is exact. Deleting a tag removes it from everyone and everything at once.</p></div></div>
{err}<div class="card scroll"><table><thead><tr><th>Tag</th><th>Description</th><th>Access</th><th>Created</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>
<div class="section"><h2>Create a tag</h2></div>
<div class="card form"><form method="post" action="/tags">{csrf}
<label for="tn" style="margin-top:0">Name</label><input id="tn" name="name" placeholder="team:dev" maxlength="64" required>
<label for="td">Description</label><input id="td" name="description" maxlength="200">
<label><input type="checkbox" name="access" value="on" checked> Grants access: people and private tunnels sharing it connect</label>
<button class="btn primary" style="margin-top:14px">Create tag</button></form>
<p class="note">Lowercase <code>key</code> or <code>key:value</code> with a-z, 0-9 and <code>._-</code>; <code>user:</code> is for personal tags. Example tags: {examples}</p></div>"#,
        err = alert(error),
        csrf = csrf(user),
        examples = chips(&["team:dev".into(), "contractor:acme".into()]),
    );
    page("Tags", Some(user), &body)
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
    /// `on` or absent (an unchecked box), or `off`.
    access: Option<String>,
}

pub async fn create_tag(user: UiUser, State(app): State<AppState>, Form(f): Form<TagForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    match app.control.create_tag(&user.who, &f.name, &f.description, f.access.as_deref() == Some("on")) {
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

pub async fn tag_access(user: UiUser, State(app): State<AppState>, Form(f): Form<TagForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    match app.control.set_tag_access(&user.who, &f.name, f.access.as_deref() == Some("on")) {
        Ok(_) => Redirect::to("/tags").into_response(),
        Err(e) => (StatusCode::FORBIDDEN, tags_page(&user, &app, Some(&e.message))).into_response(),
    }
}

// ---- hostnames ---------------------------------------------------------------------------------

fn hostnames_page(user: &UiUser, app: &AppState, error: Option<&str>) -> Response {
    let mut rows = String::new();
    for h in app.control.hostnames(&user.who) {
        let served_by = match (&h.owner_email, &h.agent_name) {
            (Some(email), _) => format!(r#"{} <span class="sub">their machines</span>"#, esc(email)),
            (None, Some(agent)) => format!(r#"{} <span class="sub">service agent</span>"#, esc(agent)),
            (None, None) => "—".into(),
        };
        let tunnel = h.tunnel.as_deref().map(|t| format!("<code>{}</code>", esc(t))).unwrap_or_else(|| r#"<span class="sub">none yet</span>"#.into());
        rows.push_str(&format!(
            r#"<tr><td><span class="name">{host}</span></td><td>{served_by}</td><td>{tunnel}</td><td>{tls}</td><td>{created}</td><td class="num"><form method="post" action="/hostnames/delete" data-confirm="Remove {host}? The tunnel on it is deleted.">{csrf}<input type="hidden" name="hostname" value="{host}"><button class="btn danger small">Remove</button></form></td></tr>"#,
            host = esc(&h.hostname),
            tls = badge(h.tls),
            created = when(&h.created_at),
            csrf = csrf(user),
        ));
    }
    if rows.is_empty() {
        rows = r#"<tr><td colspan="6" class="empty">No custom hostnames yet.</td></tr>"#.into();
    }
    let users: String = app
        .control
        .users(&user.who)
        .iter()
        .filter(|u| !u.disabled)
        .map(|u| format!(r#"<option value="user:{}">{} (their machines)</option>"#, esc(&u.id), esc(&u.email)))
        .collect();
    let agents: String = app
        .control
        .agents(&user.who)
        .iter()
        .filter(|a| a.owner_user_id.is_none())
        .map(|a| format!(r#"<option value="agent:{}">{} (service agent)</option>"#, esc(&a.id), esc(&a.name)))
        .collect();
    let body = format!(
        r#"<div class="head"><div><div class="eyebrow">Administration</div><h1>Hostnames</h1>
<p class="lede">Your own domains, outside <code>{base}</code>. Register a hostname for one person's machines or one service agent; it can then serve a tunnel on it with <code>magicpipes add PORT --hostname NAME</code>. Its DNS must point at this server. The certificate is ordered as soon as you register it, so it can be ready before traffic moves over.</p></div></div>
{err}<div class="card scroll"><table><thead><tr><th>Hostname</th><th>Served by</th><th>Tunnel</th><th>TLS</th><th>Registered</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>
<div class="section"><h2>Register a hostname</h2></div>
<div class="card form"><form method="post" action="/hostnames">{csrf}
<label for="hn" style="margin-top:0">Hostname</label><input id="hn" name="hostname" placeholder="shop.example.com" maxlength="253" required>
<label for="ha">Served by</label><select id="ha" name="assign" required><option value="">Choose…</option>{users}{agents}</select>
<button class="btn primary" style="margin-top:14px">Register</button></form>
<p class="note">One exact name, no wildcards. Removing it deletes the tunnel on it.</p></div>"#,
        base = esc(&app.control.config().base_domain),
        err = alert(error),
        csrf = csrf(user),
    );
    page("Hostnames", Some(user), &body)
}

pub async fn hostnames(user: UiUser, State(app): State<AppState>) -> Response {
    if let Some(r) = admins_only(&user) {
        return r;
    }
    hostnames_page(&user, &app, None)
}

#[derive(Deserialize)]
pub struct HostnameForm {
    csrf: String,
    hostname: String,
    /// `user:<id>` or `agent:<id>`.
    #[serde(default)]
    assign: String,
}

pub async fn create_hostname(user: UiUser, State(app): State<AppState>, Form(f): Form<HostnameForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    let (owner, agent) = match f.assign.split_once(':') {
        Some(("user", id)) => (Some(id), None),
        Some(("agent", id)) => (None, Some(id)),
        _ => (None, None),
    };
    match app.control.create_hostname(&user.who, &f.hostname, owner, agent) {
        Ok(_) => Redirect::to("/hostnames").into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, hostnames_page(&user, &app, Some(&e.message))).into_response(),
    }
}

pub async fn delete_hostname(user: UiUser, State(app): State<AppState>, Form(f): Form<HostnameForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    let _ = app.control.delete_hostname(&user.who, &f.hostname);
    Redirect::to("/hostnames").into_response()
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
