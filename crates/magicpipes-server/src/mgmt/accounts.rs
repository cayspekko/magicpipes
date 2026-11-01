//! UI pages for accounts: changing your password, your API tokens and sessions, user
//! administration and the audit log.

use axum::Form;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use http::StatusCode;
use serde::Deserialize;

use super::AppState;
use super::ui::{CsrfForm, UiUser, esc, logged_in, page, when};
use crate::authz::{Principal, Role};
use crate::control::{MIN_PASSWORD_CHARS, UserView};

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

fn password_page(user: &UiUser, error: Option<&str>) -> Response {
    let forced = user.user.as_ref().is_some_and(|u| u.must_change_password);
    let lede = if forced {
        "An administrator set your password. Choose your own to continue."
    } else {
        "Changing your password signs you out everywhere else."
    };
    let body = format!(
        r#"<div class="auth"><div class="eyebrow">Account</div><h1>Change <em>password</em></h1><p class="lede">{lede}</p>
<div class="card" style="margin-top:28px">{err}<form method="post" action="/password">{csrf}
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

pub async fn password_form(user: UiUser) -> Response {
    if user.user.is_none() {
        return Redirect::to("/account").into_response();
    }
    password_page(&user, None)
}

#[derive(Deserialize)]
pub struct PasswordForm {
    csrf: String,
    current: String,
    new: String,
    repeat: String,
}

pub async fn change_password(user: UiUser, State(app): State<AppState>, Form(f): Form<PasswordForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    if f.new != f.repeat {
        return (StatusCode::BAD_REQUEST, password_page(&user, Some("The new passwords don't match."))).into_response();
    }
    match app.control.change_password(&user.who, &f.current, &f.new).await {
        Ok(login) => logged_in(&app, login),
        Err(e) => (StatusCode::BAD_REQUEST, password_page(&user, Some(&e.message))).into_response(),
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
<div class="card" style="margin-top:12px"><form method="post" action="/account/tokens">{csrf}
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
        rows.push_str(&format!(
            r#"<tr><td><span class="name">{name}</span><span class="sub">{email}</span></td><td>{role}</td><td>{state}</td><td>{last}</td><td class="num">{actions}</td></tr>"#,
            name = esc(if u.display_name.is_empty() { &u.email } else { &u.display_name }),
            email = esc(&u.email),
            role = u.role.as_str(),
            last = u.last_login_at.as_deref().map(when).unwrap_or_else(|| "never".into()),
        ));
    }
    if rows.is_empty() {
        rows = r#"<tr><td colspan="5" class="empty">No users yet.</td></tr>"#.into();
    }
    let body = format!(
        r#"<div class="head"><div><div class="eyebrow">Administration</div><h1>Users</h1>
<p class="lede">People sign in with their email and a password. A password you set here must be changed at first sign-in.</p></div></div>
{err}<div class="card scroll"><table><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Last sign-in</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>
<div class="section"><h2>Add a user</h2></div>
<div class="card"><form method="post" action="/users">{csrf}
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
