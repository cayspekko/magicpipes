//! UI pages for accounts: changing your password, your API tokens and sessions, user
//! administration, tags, custom hostnames and the audit log.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use http::StatusCode;
use magicpipes_core::url;
use serde::Deserialize;

use super::AppState;
use super::extract::{AdminUser, Fields, NoFields, Posted, UiUser};
use super::html::{Actions, Text, alert, back, badge, chips, count, esc, form_alert, invalid, menu_post, row_menu, table, title_of, when};
use super::picker::{self, Holder, Submitted};
use super::ui::{Done, done, done_url, failed, logged_in_to, not_there, outcome, page, server_url};
use crate::authz::{Principal, Role};
use crate::control::{MIN_PASSWORD_CHARS, TunnelSignIn};
use crate::tunnel_auth::safe_path;

/// A page that shows a secret once, with a way back. `more`: HTML to follow it.
fn shown_once(user: &UiUser, title: &str, lede: &str, secret: &str, more: &str, to: &str) -> Response {
    let body = format!(
        r#"{back}<div class="eyebrow spaced">Shown once</div><h1>{title}</h1>
<p class="lede">{lede}</p><pre class="term">{secret}</pre>{more}"#,
        back = back(to, "Back"),
        title = esc(title),
        lede = esc(lede),
        secret = esc(secret),
    );
    page(title, Some(user), &body)
}

/// Someone's new password with everything else they need, ready to send.
fn invitation(app: &AppState, email: &str, password: &str) -> String {
    let message = format!(
        "Your MagicPipes account is ready.\n\nSign in at {}\nEmail: {email}\nPassword: {password}\n\nYou'll choose your own password when you sign in.",
        server_url(app)
    );
    format!(r#"<p class="note spaced">Or send them all of it:</p><pre class="term">{}</pre>"#, esc(&message))
}

// ---- password --------------------------------------------------------------------------------

fn password_page(user: &UiUser, error: Option<&str>, next: Option<&str>) -> Response {
    let next = safe_path(next).map(|n| format!(r#"<input type="hidden" name="next" value="{}">"#, esc(n))).unwrap_or_default();
    let forced = user.user.as_ref().is_some_and(|u| u.must_change_password);
    let lede = if forced {
        "An administrator set your password. Choose your own to continue."
    } else {
        "Changing your password signs you out everywhere else."
    };
    let body = format!(
        r#"<div class="auth"><div class="eyebrow">Account</div><h1>Change <em>password</em></h1><p class="lede">{lede}</p>
<div class="card">{err}<form method="post" action="/password">{csrf}{next}
<label for="c">Current password</label><input id="c" type="password" name="current" autocomplete="current-password" required autofocus>
<label for="n">New password</label><input id="n" type="password" name="new" autocomplete="new-password" minlength="{min}" required>
<label for="r">Repeat the new password</label><input id="r" type="password" name="repeat" autocomplete="new-password" minlength="{min}" required>
<button class="btn primary block">Change password</button></form></div>
<p class="note">At least {min} characters. A long phrase is easier to remember than a short jumble.</p></div>"#,
        lede = esc(lede),
        err = alert(error),
        csrf = user.csrf_field(),
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
    current: String,
    new: String,
    repeat: String,
    next: Option<String>,
}

pub async fn change_password(State(app): State<AppState>, Posted(user, f): Posted<PasswordForm>) -> Response {
    let next = f.next.as_deref();
    if f.new != f.repeat {
        return (StatusCode::BAD_REQUEST, password_page(&user, Some("The new passwords don't match."), next)).into_response();
    }
    // Someone made to choose a password was on their way somewhere else.
    let forced = user.user.as_ref().is_some_and(|u| u.must_change_password);
    let landing = done_url(if forced { "/" } else { "/account" }, Done::PasswordChanged);
    match app.control.change_password(&user.who, &f.current, &f.new).await {
        Ok(login) => logged_in_to(&app, login, next, &landing),
        Err(e) => (StatusCode::BAD_REQUEST, password_page(&user, Some(&e.message), next)).into_response(),
    }
}

// ---- your account ----------------------------------------------------------------------------

const BAD_EXPIRY: &str = "The expiry must be a whole number of days, or empty for a token that never expires.";

fn account_page(user: &UiUser, app: &AppState, attempt: Option<(&TokenForm, &str)>) -> Response {
    let Some(me) = &user.user else {
        let body = r#"<div class="eyebrow">Account</div><h1>Admin <em>token</em></h1>
<p class="lede">You are signed in with an admin token, which has no account of its own. Keep it for emergencies, and use an account of your own day to day.</p>
<a class="btn primary spaced" href="/users#add">Create your account</a>"#;
        return page("Account", Some(user), body);
    };
    let mut rows = String::new();
    for t in app.control.tokens(&user.who) {
        rows.push_str(&format!(
            r#"<tr><td><span class="name">{name}</span><code class="sub">{id}</code></td><td>{created}</td><td>{used}</td><td>{expires}</td><td class="num"><form method="post" action="/account/tokens/{id}/delete" data-confirm="Delete the API token {name}? Anything using it stops working.">{csrf}<button class="btn danger small" aria-label="Delete {name}">Delete</button></form></td></tr>"#,
            name = esc(&t.name),
            id = esc(&t.id),
            created = when(&t.created_at),
            used = t.last_used_at.as_deref().map(when).unwrap_or_else(|| "never".into()),
            expires = t.expires_at.as_deref().map(when).unwrap_or_else(|| "never".into()),
            csrf = user.csrf_field(),
        ));
    }
    let error = attempt.map(|(_, m)| m);
    let bad_expiry = error == Some(BAD_EXPIRY);
    let body = format!(
        r#"<div class="eyebrow">Account</div><h1>{name}</h1><p class="lede">{email} · {role}</p>
{password}
<div class="section"><h2>API tokens</h2></div>
{list}
<div class="card form spaced">{form_error}<form method="post" action="/account/tokens">{csrf}
<label for="tn">Name</label><input id="tn" name="name" maxlength="64" placeholder="ci-deploy" value="{typed_name}"{name_invalid} required>
<label for="te">Expires after (days, empty = never)</label><input id="te" name="expires_in_days" inputmode="numeric" pattern="[0-9]*" value="{typed_days}"{days_invalid}>
<button class="btn primary">Create API token</button></form>
<p class="note">Use it as <code>Authorization: Bearer &lt;token&gt;</code>. It acts as you, with your current role.</p></div>
<div class="card panel danger spaced"><div><h2>Sign out everywhere</h2><p>Ends every browser session of this account, this one included. API tokens keep working.</p></div>
<form method="post" action="/account/logout-everywhere">{csrf}<button class="btn danger">Sign out everywhere</button></form></div>"#,
        name = esc(if me.display_name.is_empty() { &me.email } else { &me.display_name }),
        email = esc(&me.email),
        role = me.role.as_str(),
        list = table(&[Text("Token"), Text("Created"), Text("Last used"), Text("Expires"), Actions], &rows, "No API tokens yet. Create one below for scripts and CI."),
        csrf = user.csrf_field(),
        form_error = form_alert(error),
        typed_name = esc(attempt.map_or("", |(f, _)| &f.name)),
        typed_days = esc(attempt.map_or("", |(f, _)| &f.expires_in_days)),
        name_invalid = invalid(error.is_some() && !bad_expiry),
        days_invalid = invalid(bad_expiry),
        // Someone who only signs in with single sign-on has no password to change.
        password = if me.has_password {
            r#"<div class="card panel spaced"><div><h2>Password</h2><p>Changing it signs you out on other devices.</p></div><a class="btn" href="/password">Change password</a></div>"#
        } else {
            ""
        },
    );
    page(&title_of("Account", error.is_some()), Some(user), &body)
}

pub async fn account(user: UiUser, State(app): State<AppState>) -> Response {
    account_page(&user, &app, None)
}

#[derive(Deserialize)]
pub struct TokenForm {
    name: String,
    #[serde(default)]
    expires_in_days: String,
}

pub async fn create_token(State(app): State<AppState>, Posted(user, f): Posted<TokenForm>) -> Response {
    let refused = |message: &str| (StatusCode::BAD_REQUEST, account_page(&user, &app, Some((&f, message)))).into_response();
    let days = match f.expires_in_days.trim() {
        "" => None,
        days => match days.parse::<u32>() {
            Ok(d) if d > 0 => Some(d),
            // Never a token that lasts forever because of a typo.
            _ => return refused(BAD_EXPIRY),
        },
    };
    match app.control.create_token(&user.who, &f.name, days) {
        Ok((t, secret)) => shown_once(
            &user,
            &format!("API token “{}”", t.name),
            "Copy it now: it is not shown again. Send it as Authorization: Bearer <token>.",
            &secret,
            "",
            "/account",
        ),
        Err(e) => refused(&e.message),
    }
}

pub async fn delete_token(State(app): State<AppState>, Path(id): Path<String>, Posted(user, _): Posted<NoFields>) -> Response {
    outcome(&user, app.control.delete_token(&user.who, &id), "/account", "Account", Done::TokenDeleted, "That API token is already gone.")
}

pub async fn logout_everywhere(State(app): State<AppState>, Posted(user, _): Posted<NoFields>) -> Response {
    match app.control.logout_everywhere(&user.who) {
        Ok(()) => Redirect::to("/login").into_response(),
        Err(e) => failed(&user, StatusCode::INTERNAL_SERVER_ERROR, "/account", "Account", &e.message),
    }
}

// ---- users -----------------------------------------------------------------------------------

/// `error`: about the list. `attempt`: the form that came back, and why.
fn users_page(user: &UiUser, app: &AppState, error: Option<&str>, attempt: Option<(&NewUserForm, &str)>) -> Response {
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
            menu_post(&format!("/users/{}", u.id), &user.csrf_field(), &[("action", action)], label, danger, confirm.as_deref())
        };
        let mut items = vec![edit.link(user, "menu-item", "Edit tags", &format!("Edit tags of {}", u.email))];
        if !me {
            items.push(if u.role == Role::Admin {
                post("member", "Make member", false, None)
            } else {
                post("admin", "Make admin", false, Some(format!("Make {} an administrator? They can see and change everything here.", u.email)))
            });
            let reset = format!("Reset the password of {}? Their sessions end, their API tokens are revoked, and they must replace the new password when they next sign in.", u.email);
            items.push(post("reset", "Reset password", false, Some(reset)));
            let revoke = format!("Revoke every API token of {}? Anything using them stops working.", u.email);
            items.push(post("revoke-tokens", "Revoke API tokens", false, Some(revoke)));
            items.push("<hr>".into());
            items.push(if u.disabled {
                post("enable", "Enable", false, None)
            } else {
                post("disable", "Disable", true, Some(format!("Disable {}? They are signed out, and their machines stop serving tunnels.", u.email)))
            });
        }
        let you = if me { r#"<span class="sub you">you</span>"# } else { "" };
        let actions = format!("{you}{}", row_menu(&u.email, &items));
        rows.push_str(&format!(
            r#"<tr><td><span class="name">{name}</span><span class="sub wrap">{email}{personal}</span></td><td>{role}</td><td>{tags}</td><td>{state}</td><td>{last}</td><td class="num">{actions}</td></tr>"#,
            name = esc(if u.display_name.is_empty() { &u.email } else { &u.display_name }),
            email = esc(&u.email),
            personal = u.personal_tag.as_deref().map(|t| format!(" · <code>{}</code>", esc(t))).unwrap_or_default(),
            role = u.role.as_str(),
            last = u.last_login_at.as_deref().map(when).unwrap_or_else(|| "never".into()),
        ));
    }
    let form_error = attempt.map(|(_, m)| m);
    let bad_password = form_error.is_some_and(|m| m.contains("password"));
    let typed = |value: fn(&NewUserForm) -> &str| esc(attempt.map_or("", |(f, _)| value(f)));
    let admin_role = attempt.is_some_and(|(f, _)| f.role == "admin");
    let body = format!(
        r#"<h1>Users</h1><p class="lede">People who can sign in, and the tags that decide which private tunnels they reach.</p>
{err}<div class="spaced">{list}</div>
<div class="section" id="add"><h2>Add a user</h2></div>
<div class="card form">{form_error}<form method="post" action="/users">{csrf}
<label for="ue">Email</label><input id="ue" type="email" name="email" value="{email}"{email_invalid} required>
<label for="un">Name</label><input id="un" name="display_name" value="{name}" maxlength="100">
<label for="ur">Role</label><select id="ur" name="role"><option value="member">Member</option><option value="admin"{admin_selected}>Administrator</option></select>
<label for="up">Password (empty = generate one)</label><input id="up" type="password" name="password" autocomplete="new-password" minlength="{min}"{password_invalid}>
<button class="btn primary">Add user</button></form>
<p class="note">They replace a password you set here when they first sign in. With a single sign-on provider, they can sign in with that instead.</p></div>{registry}"#,
        registry = picker::registry(app, user),
        list = table(&[Text("User"), Text("Role"), Text("Tags"), Text("Status"), Text("Last sign-in"), Actions], &rows, "No users yet. Add the first one below."),
        err = alert(error),
        form_error = form_alert(form_error),
        email = typed(|f| &f.email),
        name = typed(|f| &f.display_name),
        admin_selected = if admin_role { " selected" } else { "" },
        email_invalid = invalid(form_error.is_some() && !bad_password),
        password_invalid = invalid(bad_password),
        csrf = user.csrf_field(),
        min = MIN_PASSWORD_CHARS,
    );
    page(&title_of("Users", form_error.is_some()), Some(user), &body)
}

pub async fn users(AdminUser(user): AdminUser, State(app): State<AppState>) -> Response {
    users_page(&user, &app, None, None)
}

#[derive(Deserialize)]
pub struct NewUserForm {
    email: String,
    #[serde(default)]
    display_name: String,
    role: String,
    #[serde(default)]
    password: String,
}

pub async fn create_user(State(app): State<AppState>, Posted(user, f): Posted<NewUserForm>) -> Response {
    let role = Role::parse(&f.role).unwrap_or(Role::Member);
    let password = (!f.password.is_empty()).then_some(f.password.as_str());
    match app.control.create_user(&user.who, &f.email, &f.display_name, role, password).await {
        Ok((u, Some(generated))) => shown_once(
            &user,
            &format!("Password for {}", u.email),
            "Give it to them over a channel you trust. They must replace it when they first sign in.",
            &generated,
            &invitation(&app, &u.email, &generated),
            "/users",
        ),
        Ok(_) => done("/users", Done::UserAdded),
        Err(e) => (StatusCode::BAD_REQUEST, users_page(&user, &app, None, Some((&f, &e.message)))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct UserActionForm {
    action: String,
    #[serde(default)]
    tags: String,
}

pub async fn update_user(State(app): State<AppState>, Path(id): Path<String>, Posted(user, f): Posted<UserActionForm>) -> Response {
    let (result, what) = match f.action.as_str() {
        "reset" => match app.control.reset_password(&user.who, &id).await {
            Ok(password) => {
                let email = app.control.user(&user.who, &id).map(|u| u.email).unwrap_or_default();
                return shown_once(
                    &user,
                    &format!("New password for {email}"),
                    "Their sessions have ended and their API tokens are revoked. They must replace this password when they next sign in.",
                    &password,
                    &invitation(&app, &email, &password),
                    "/users",
                );
            }
            Err(e) => return (StatusCode::BAD_REQUEST, users_page(&user, &app, Some(&e.message), None)).into_response(),
        },
        "revoke-tokens" => (app.control.revoke_tokens(&user.who, &id).map(drop), Done::TokensRevoked),
        "tags" => (app.control.set_user_tags(&user.who, &id, &[f.tags]).map(drop), Done::TagsSaved),
        "admin" => (app.control.update_user(&user.who, &id, Some(Role::Admin), None).map(drop), Done::RoleChanged),
        "member" => (app.control.update_user(&user.who, &id, Some(Role::Member), None).map(drop), Done::RoleChanged),
        "disable" => (app.control.update_user(&user.who, &id, None, Some(true)).map(drop), Done::UserDisabled),
        "enable" => (app.control.update_user(&user.who, &id, None, Some(false)).map(drop), Done::UserEnabled),
        _ => return failed(&user, StatusCode::BAD_REQUEST, "/users", "Users", "That isn't something that can be done to a user."),
    };
    match result {
        Ok(()) => done("/users", what),
        Err(e) => (StatusCode::BAD_REQUEST, users_page(&user, &app, Some(&e.message), None)).into_response(),
    }
}

/// Without scripts, a user's Edit link opens this page of checkboxes.
pub async fn user_tags_page(AdminUser(user): AdminUser, State(app): State<AppState>, Path(id): Path<String>) -> Response {
    let Some(u) = app.control.user(&user.who, &id) else {
        return not_there(&user, "/users", "Users", "There is no user with that id.");
    };
    let all: Vec<(String, String)> = app.control.tags(&user.who).into_iter().map(|t| (t.name, t.description)).collect();
    let boxes = if all.is_empty() {
        r#"<p class="note">There are no tags yet: create them under <a href="/tags">Tags</a>.</p>"#.to_string()
    } else {
        picker::fieldset("Tags", &all, &u.tags, None)
    };
    let body = format!(
        r#"{back}<div class="head"><div><div class="eyebrow">User</div><h1>Tags of <em>{email}</em></h1></div></div>
<div class="card form"><form method="post" action="/users/{id}/tags">{csrf}<input type="hidden" name="base" value="{base}">
{boxes}<button class="btn primary">Save</button></form></div>"#,
        back = back("/users", "Users"),
        email = esc(&u.email),
        id = esc(&u.id),
        csrf = user.csrf_field(),
        base = esc(&u.tags.join(" ")),
    );
    page("User tags", Some(&user), &body)
}

/// Saves a user's tags from the picker or the page above: only what changed since it was shown.
pub async fn user_tags(State(app): State<AppState>, Path(id): Path<String>, Posted(user, fields): Posted<Fields>) -> Response {
    let form = match Submitted::parse(fields) {
        Ok(f) => f,
        Err(e) => return (StatusCode::BAD_REQUEST, users_page(&user, &app, Some(&e), None)).into_response(),
    };
    if let Err(e) = form.create_missing(&app, &user.who) {
        return (StatusCode::BAD_REQUEST, users_page(&user, &app, Some(&e), None)).into_response();
    }
    let result = match form.change() {
        Some((add, remove)) => app.control.change_user_tags(&user.who, &id, &add, &remove),
        None => app.control.set_user_tags(&user.who, &id, &form.want),
    };
    match result {
        Ok(_) => done("/users", Done::TagsSaved),
        Err(e) => (StatusCode::BAD_REQUEST, users_page(&user, &app, Some(&e.message), None)).into_response(),
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
            let back = safe_path(Some(&q.back)).unwrap_or("/");
            Redirect::to(&format!("{callback}&return={}", url::encode(back))).into_response()
        }
        TunnelSignIn::NotFound => {
            let body = format!(r#"<div class="auth"><h1>Not found</h1><p class="lede">There is no private tunnel at <code>{}</code>.</p></div>"#, esc(&q.host));
            (StatusCode::NOT_FOUND, page("Private tunnel", Some(&user), &body)).into_response()
        }
        TunnelSignIn::Denied => {
            let body = format!(
                r#"<div class="auth"><div class="eyebrow">Private tunnel</div><h1>No <em>access</em></h1>
<p class="lede">You're signed in as {email}, but you don't have access to <code>{host}</code>. Ask its owner or an administrator.</p>
<form class="spaced" method="post" action="/logout">{csrf}<input type="hidden" name="next" value="{here}"><button class="btn">Switch account</button></form></div>"#,
                email = esc(&me.email),
                host = esc(&q.host),
                csrf = user.csrf_field(),
                here = esc(&format!("/auth/tunnel?host={}&state={}&return={}", url::encode(&q.host), url::encode(&q.state), url::encode(&q.back))),
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
        let body = r#"<h1>Use your <em>account</em></h1><p class="lede">You are signed in with an admin token. Sign in with your user account to enroll your own machine, or create an enrollment token under <a href="/machines">Machines</a>.</p>"#;
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
<div class="card"><div class="stat"><div class="k">Code</div><div class="v sm"><code>{code}</code></div></div>
<form method="post" action="/cli">{csrf}<input type="hidden" name="code" value="{code}">
<p class="note">Its private tunnels are for you alone until it shares one with a tag you hold (<code>magicpipes add --tag</code>).</p>
<div class="row"><button class="btn primary" name="answer" value="approve">Approve</button><button class="btn danger" name="answer" value="deny">Deny</button></div></form></div>
<p class="note">Only approve a request you just started yourself: an approved machine acts as you and can publish tunnels in your name.</p></div>"#,
        name = esc(&req.agent_name),
        ago = req.age_secs,
        client = esc(&req.client.to_string()),
        code = esc(&req.user_code),
        csrf = user.csrf_field(),
    );
    page("Approve a machine", Some(&user), &body)
}

#[derive(Deserialize)]
pub struct DeviceAnswer {
    #[serde(default)]
    code: String,
    #[serde(default)]
    answer: String,
}

pub async fn answer_device(State(app): State<AppState>, Posted(user, f): Posted<DeviceAnswer>) -> Response {
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

// ---- tags ----------------------------------------------------------------------------------

/// What deleting a tag does, in the words of the question asked first.
fn tag_reach(people: usize, tunnels: usize) -> String {
    let (who, what) = (count(people, "person", "people"), count(tunnels, "private tunnel", "private tunnels"));
    match (people, tunnels) {
        (0, 0) => "Nobody holds it, and no private tunnel relies on it.".to_string(),
        (_, 0) => format!("It leaves {who}."),
        (0, _) => format!("It leaves {what}, which stop admitting people through it."),
        _ => format!("It leaves {who} and {what}, which stop admitting people through it."),
    }
}

/// `error`: about the list. `attempt`: the form that came back, and why.
fn tags_page(user: &UiUser, app: &AppState, error: Option<&str>, attempt: Option<(&TagForm, &str)>) -> Response {
    let users = app.control.users(&user.who);
    let reach = app.control.private_reach(&user.who);
    let mut rows = String::new();
    for t in app.control.tags(&user.who) {
        let holders = users.iter().filter(|u| u.tags.contains(&t.name)).count();
        let tunnels = reach.by_tag.get(&t.name).copied().unwrap_or(0);
        let (state, flip, label, ask) = if t.access {
            let ask = (tunnels > 0).then(|| format!("Turn off access for {}? {} stop admitting people through it.", t.name, count(tunnels, "private tunnel", "private tunnels")));
            (r#"<span class="status ok">grants access</span>"#, "off", "Turn off", ask)
        } else {
            (r#"<span class="when">label only</span>"#, "on", "Turn on", None)
        };
        rows.push_str(&format!(
            r#"<tr><td class="wrap"><code>{name}</code></td><td class="wrap">{description}</td><td>{state} <form class="inline" method="post" action="/tags/access"{ask}>{csrf}<input type="hidden" name="name" value="{name}"><input type="hidden" name="access" value="{flip}"><button class="btn small ghost" aria-label="{label} {name}">{label}</button></form></td><td>{created}</td><td class="num"><form method="post" action="/tags/delete" data-confirm="Delete {name}? {effect}">{csrf}<input type="hidden" name="name" value="{name}"><button class="btn danger small" aria-label="Delete {name}">Delete</button></form></td></tr>"#,
            name = esc(&t.name),
            description = esc(&t.description),
            ask = ask.map(|q| format!(r#" data-confirm="{}""#, esc(&q))).unwrap_or_default(),
            effect = esc(&tag_reach(holders, tunnels)),
            created = when(&t.created_at),
            csrf = user.csrf_field(),
        ));
    }
    let form_error = attempt.map(|(_, m)| m);
    let body = format!(
        r#"<h1>Tags</h1><p class="lede">Tags decide who can open which private tunnel.</p>
<details class="more"><summary>How access works</summary><div>
<p>A person can open a private tunnel when they share a tag with it that grants access. A tag that doesn't is only a label. Matching is exact.</p>
<p>Everyone also holds a personal tag (<code>user:…</code>), which the server puts on the tunnels of their machines. That's how people reach their own tunnels, and adding someone's personal tag to a tunnel shares it with just them.</p>
<p>Deleting a tag removes it from everyone and everything at once.</p></div></details>
{err}<div class="spaced">{list}</div>
<div class="section"><h2>Create a tag</h2></div>
<div class="card form">{form_error}<form method="post" action="/tags">{csrf}
<label for="tn">Name</label><input id="tn" name="name" placeholder="team:dev" maxlength="64" value="{name}"{name_invalid} required>
<label for="td">Description</label><input id="td" name="description" maxlength="200" value="{description}">
<label><input type="checkbox" name="access" value="on"{access}> Grants access: people and private tunnels sharing it connect</label>
<button class="btn primary">Create tag</button></form>
<p class="note">Lowercase <code>key</code> or <code>key:value</code> with a-z, 0-9 and <code>._-</code>; <code>user:</code> is for personal tags. Example tags: {examples}</p></div>"#,
        list = table(&[Text("Tag"), Text("Description"), Text("Access"), Text("Created"), Actions], &rows, "No tags yet. Create the first one below."),
        err = alert(error),
        form_error = form_alert(form_error),
        name = esc(attempt.map_or("", |(f, _)| &f.name)),
        description = esc(attempt.map_or("", |(f, _)| &f.description)),
        name_invalid = invalid(form_error.is_some()),
        access = if attempt.is_none_or(|(f, _)| f.access.as_deref() == Some("on")) { " checked" } else { "" },
        csrf = user.csrf_field(),
        examples = chips(&["team:dev".into(), "contractor:acme".into()]),
    );
    page(&title_of("Tags", form_error.is_some()), Some(user), &body)
}

pub async fn tags(AdminUser(user): AdminUser, State(app): State<AppState>) -> Response {
    tags_page(&user, &app, None, None)
}

#[derive(Deserialize)]
pub struct TagForm {
    name: String,
    #[serde(default)]
    description: String,
    /// `on` or absent (an unchecked box), or `off`.
    access: Option<String>,
}

pub async fn create_tag(State(app): State<AppState>, Posted(user, f): Posted<TagForm>) -> Response {
    match app.control.create_tag(&user.who, &f.name, &f.description, f.access.as_deref() == Some("on")) {
        Ok(_) => done("/tags", Done::TagCreated),
        Err(e) => (StatusCode::BAD_REQUEST, tags_page(&user, &app, None, Some((&f, &e.message)))).into_response(),
    }
}

pub async fn delete_tag(State(app): State<AppState>, Posted(user, f): Posted<TagForm>) -> Response {
    outcome(&user, app.control.delete_tag(&user.who, &f.name), "/tags", "Tags", Done::TagDeleted, "That tag is already gone.")
}

pub async fn tag_access(State(app): State<AppState>, Posted(user, f): Posted<TagForm>) -> Response {
    let on = f.access.as_deref() == Some("on");
    match app.control.set_tag_access(&user.who, &f.name, on) {
        Ok(true) => done("/tags", if on { Done::AccessOn } else { Done::AccessOff }),
        Ok(false) => failed(&user, StatusCode::NOT_FOUND, "/tags", "Tags", "That tag is already gone."),
        Err(e) => (StatusCode::FORBIDDEN, tags_page(&user, &app, Some(&e.message), None)).into_response(),
    }
}

// ---- hostnames ---------------------------------------------------------------------------------

/// `error`: about the list. `attempt`: the form that came back, and why.
fn hostnames_page(user: &UiUser, app: &AppState, error: Option<&str>, attempt: Option<(&HostnameForm, &str)>) -> Response {
    let assigned = attempt.map_or("", |(f, _)| f.assign.as_str());
    let selected = |value: String| if value == assigned { " selected" } else { "" };
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
            csrf = user.csrf_field(),
        ));
    }
    let users: String = app
        .control
        .users(&user.who)
        .iter()
        .filter(|u| !u.disabled)
        .map(|u| format!(r#"<option value="user:{}"{}>{} (their machines)</option>"#, esc(&u.id), selected(format!("user:{}", u.id)), esc(&u.email)))
        .collect();
    let agents: String = app
        .control
        .agents(&user.who)
        .iter()
        .filter(|a| a.owner_user_id.is_none())
        .map(|a| format!(r#"<option value="agent:{}"{}>{} (service agent)</option>"#, esc(&a.id), selected(format!("agent:{}", a.id)), esc(&a.name)))
        .collect();
    let form_error = attempt.map(|(_, m)| m);
    let body = format!(
        r#"<h1>Hostnames</h1><p class="lede">Your own domains, outside <code>{base}</code>, each served by one person's machines or one service agent.</p>
{err}<div class="spaced">{list}</div>
<div class="section"><h2>Register a hostname</h2></div>
<div class="card form">{form_error}<form method="post" action="/hostnames">{csrf}
<label for="hn">Hostname</label><input id="hn" name="hostname" placeholder="shop.example.com" maxlength="253" value="{typed_host}"{host_invalid} required>
<label for="ha">Served by</label><select id="ha" name="assign"{assign_invalid} required><option value="">Choose…</option>{users}{agents}</select>
<button class="btn primary">Register</button></form>
<p class="note">One exact name, no wildcards, with its DNS pointing at this server. Its certificate is ordered as soon as you register it, so it can be ready before traffic moves over. Then serve a tunnel on it with <code>magicpipes add PORT --hostname NAME</code>. Removing it deletes that tunnel.</p></div>"#,
        base = esc(&app.control.config().base_domain),
        list = table(&[Text("Hostname"), Text("Served by"), Text("Tunnel"), Text("TLS"), Text("Registered"), Actions], &rows, "No custom hostnames yet. Register one below, or use names under the base domain."),
        err = alert(error),
        form_error = form_alert(form_error),
        typed_host = esc(attempt.map_or("", |(f, _)| &f.hostname)),
        host_invalid = invalid(form_error.is_some() && !assigned.is_empty()),
        assign_invalid = invalid(form_error.is_some() && assigned.is_empty()),
        csrf = user.csrf_field(),
    );
    page(&title_of("Hostnames", form_error.is_some()), Some(user), &body)
}

pub async fn hostnames(AdminUser(user): AdminUser, State(app): State<AppState>) -> Response {
    hostnames_page(&user, &app, None, None)
}

#[derive(Deserialize)]
pub struct HostnameForm {
    hostname: String,
    /// `user:<id>` or `agent:<id>`.
    #[serde(default)]
    assign: String,
}

pub async fn create_hostname(State(app): State<AppState>, Posted(user, f): Posted<HostnameForm>) -> Response {
    let (owner, agent) = match f.assign.split_once(':') {
        Some(("user", id)) => (Some(id), None),
        Some(("agent", id)) => (None, Some(id)),
        _ => (None, None),
    };
    match app.control.create_hostname(&user.who, &f.hostname, owner, agent) {
        Ok(_) => done("/hostnames", Done::HostnameRegistered),
        Err(e) => (StatusCode::BAD_REQUEST, hostnames_page(&user, &app, None, Some((&f, &e.message)))).into_response(),
    }
}

pub async fn delete_hostname(State(app): State<AppState>, Posted(user, f): Posted<HostnameForm>) -> Response {
    outcome(&user, app.control.delete_hostname(&user.who, &f.hostname), "/hostnames", "Hostnames", Done::HostnameRemoved, "That hostname is already gone.")
}

// ---- audit log -------------------------------------------------------------------------------

pub async fn audit(AdminUser(user): AdminUser, State(app): State<AppState>) -> Response {
    let Ok(entries) = app.control.audit_entries(&user.who, 200) else {
        return failed(&user, StatusCode::INTERNAL_SERVER_ERROR, "/", "Tunnels", "The audit log can't be read right now. The server's log says why.");
    };
    let users = app.control.users(&user.who);
    let name = |id: &str| users.iter().find(|u| u.id == id).map(|u| u.email.clone()).unwrap_or_else(|| id.to_string());
    let mut rows = String::new();
    for e in &entries {
        rows.push_str(&format!(
            r#"<tr><td>{at}</td><td>{actor}</td><td><code>{action}</code></td><td class="wrap"><code>{resource}</code></td><td class="wrap">{detail}</td></tr>"#,
            at = when(&e.at),
            actor = esc(&name(&e.actor)),
            action = esc(&e.action),
            resource = esc(&e.resource),
            detail = esc(&e.detail),
        ));
    }
    let body = format!(
        r#"<h1>Audit log</h1><p class="lede">Sign-ins, account changes and management actions, newest first. Kept for {days} days.</p>
<div class="spaced">{list}</div>"#,
        days = app.control.config().users.audit_retention_days,
        list = table(&[Text("When"), Text("Who"), Text("Action"), Text("On"), Text("Detail")], &rows, "Nothing recorded yet."),
    );
    page("Audit log", Some(&user), &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deleting_a_tag_says_what_it_leaves() {
        assert_eq!(tag_reach(0, 0), "Nobody holds it, and no private tunnel relies on it.");
        assert_eq!(tag_reach(1, 0), "It leaves 1 person.");
        assert_eq!(tag_reach(0, 2), "It leaves 2 private tunnels, which stop admitting people through it.");
        assert_eq!(tag_reach(3, 1), "It leaves 3 people and 1 private tunnel, which stop admitting people through it.");
    }
}
