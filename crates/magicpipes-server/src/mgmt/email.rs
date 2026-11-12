//! Pages for email: asking for a sign-in link and using one, accepting an invitation, confirming
//! your address, and the mail server on the Settings page. The decisions are in `control::email`.
//!
//! A code arrives in the address's fragment, which only the browser sees. `ui.js` moves it into the
//! form's field and hides the field; without scripts, it's pasted from the message. So opening a link
//! changes nothing, whoever or whatever opens it: a mail scanner can't use one up, and only a
//! form that's submitted can.

use std::net::IpAddr;

use axum::Form;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use http::{HeaderMap, StatusCode, header};
use serde::Deserialize;

use super::extract::{AdminPosted, AdminUser, NoFields, Posted, UiUser};
use super::html::{alert, back, esc, form_alert, invalid, title_of};
use super::oidc::{attempt_cookie, redirect_uri};
use super::ui::{Done, cross_site, done, done_url, failed, leaving_page, logged_in_to, login_page, page};
use super::{AppState, ClientIp, Rejected};
use crate::authz::Role;
use crate::config::SmtpTls;
use crate::control::{AcceptError, INVITATION_DAYS, LinkError, MIN_PASSWORD_CHARS, NewSmtp, OpenInvitation, SIGN_IN_LINK_MINUTES, SignInError, SmtpView};
use crate::oidc::ATTEMPT_COOKIE_MAX_AGE;

/// The field for a code.
const CODE_FIELD: &str = r#"<div data-code-field><label for="code">Code from the email</label><input id="code" name="code" autocomplete="off" spellcheck="false" maxlength="128" required data-code></div>"#;

fn hidden_code(code: &str) -> String {
    format!(r#"<input type="hidden" name="code" value="{}">"#, esc(code.trim()))
}

pub(super) fn client_of(client: Option<axum::Extension<ClientIp>>) -> Option<IpAddr> {
    client.map(|c| c.0.0)
}

/// A bad code counts against the client, as any bad credential does. `true`: it's over the limit.
pub(super) fn over_limit_after_a_bad_code(app: &AppState, client: Option<IpAddr>) -> bool {
    matches!(app.check_credential(Err::<(), ()>(()), client), Err(Rejected::RateLimited))
}

pub(super) const TOO_MANY: &str = "Too many failed attempts. Try again later.";
pub(super) const FROM_ELSEWHERE: &str = "Use this from its own page, not from another site.";
pub(super) const WENT_WRONG: &str = "Something went wrong. Try again.";

// ---- asking for a sign-in link -------------------------------------------------------------------

fn ask_page(error: Option<&str>) -> Response {
    let body = format!(
        r#"{back}<div class="auth"><h1>Sign in by <em>email</em></h1><p class="lede">If you've forgotten your password, a link can get you back in.</p>
<div class="card">{err}<form method="post" action="/login/email"><label for="e">Email</label><input id="e" type="email" name="email" maxlength="254" autocomplete="username" autofocus required>
<button class="btn primary block">Email me a link</button></form></div></div>"#,
        back = back("/login", "Sign in"),
        err = alert(error),
    );
    page(&title_of("Sign in by email", error.is_some()), None, &body)
}

pub async fn ask_form(State(app): State<AppState>) -> Response {
    if !app.control.mail_on() {
        return Redirect::to("/login").into_response();
    }
    ask_page(None)
}

#[derive(Deserialize)]
pub struct AskForm {
    #[serde(default)]
    email: String,
}

/// The same answer in every case, in the same time: see `control::email`.
pub async fn ask(State(app): State<AppState>, client: Option<axum::Extension<ClientIp>>, headers: HeaderMap, Form(f): Form<AskForm>) -> Response {
    if !app.control.mail_on() {
        return Redirect::to("/login").into_response();
    }
    // Another site's form would fill someone's inbox from their own browser.
    if cross_site(&headers) {
        return (StatusCode::FORBIDDEN, ask_page(Some(FROM_ELSEWHERE))).into_response();
    }
    if app.control.request_sign_in_link(&f.email, client_of(client)).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, ask_page(Some("Too many requests from here. Try again later."))).into_response();
    }
    let address: String = f.email.trim().chars().take(254).collect();
    let body = format!(
        r#"<div class="auth"><h1>Check your <em>email</em></h1><p class="lede">If {address} has an account with a password and a confirmed address, a link is on its way. It works once, for {SIGN_IN_LINK_MINUTES} minutes.</p>
<p class="note">If you sign in with a provider, use its button on the <a href="/login">sign-in page</a> instead. If nothing arrives, ask an administrator.</p></div>"#,
        address = esc(&address),
    );
    page("Check your email", None, &body)
}

// ---- using a sign-in link ------------------------------------------------------------------------

/// `code`: one that's still good, which needn't be asked for again. `second`: the account takes a
/// sign-in code too.
fn link_page(error: Option<&str>, code: Option<&str>, choosing_password: bool, second: bool) -> Response {
    let second_field = if second {
        format!(
            r#"<label for="lk">Code from your authenticator app</label><input id="lk" name="second" autocomplete="one-time-code" spellcheck="false" maxlength="40" required{}>
<p class="note">Or one of your recovery codes.</p>"#,
            if error.is_some_and(|e| e.contains("code")) { invalid(true) } else { " autofocus" }
        )
    } else {
        String::new()
    };
    let body = format!(
        r#"<div class="auth"><h1>Sign <em>in</em></h1><p class="lede">You asked for this link by email. It works once.</p>
<div class="card">{err}<form method="post" action="/login/link">{code}{second_field}
<details class="more"{open}><summary>Forgot your password? Choose a new one</summary><div>
<label for="ln">New password</label><input id="ln" type="password" name="new" autocomplete="new-password" minlength="{MIN_PASSWORD_CHARS}">
<label for="lr">Repeat it</label><input id="lr" type="password" name="repeat" autocomplete="new-password" minlength="{MIN_PASSWORD_CHARS}">
<p>At least {MIN_PASSWORD_CHARS} characters. This signs you out everywhere else.</p></div></details>
<button class="btn primary block spaced">Sign in</button></form></div></div>"#,
        err = form_alert(error),
        code = code.map_or(CODE_FIELD.to_string(), hidden_code),
        open = if choosing_password { " open" } else { "" },
    );
    page(&title_of("Sign in", error.is_some()), None, &body)
}

pub async fn link_form(State(app): State<AppState>) -> Response {
    if app.control.proxy_auth().is_some() {
        return Redirect::to("/").into_response();
    }
    link_page(None, None, false, false)
}

#[derive(Deserialize)]
pub struct LinkForm {
    #[serde(default)]
    code: String,
    #[serde(default)]
    new: String,
    #[serde(default)]
    repeat: String,
    /// A sign-in code, for an account that takes one.
    #[serde(default)]
    second: String,
}

pub async fn use_link(State(app): State<AppState>, client: Option<axum::Extension<ClientIp>>, headers: HeaderMap, Form(f): Form<LinkForm>) -> Response {
    if app.control.proxy_auth().is_some() {
        return Redirect::to("/").into_response();
    }
    // Another site's form could sign this browser in to the attacker's account.
    if cross_site(&headers) {
        return (StatusCode::FORBIDDEN, link_page(Some(FROM_ELSEWHERE), None, false, false)).into_response();
    }
    let client = client_of(client);
    let second = (!f.second.trim().is_empty()).then_some(f.second.as_str());
    if f.new != f.repeat {
        return (StatusCode::BAD_REQUEST, link_page(Some("The new passwords don't match."), Some(&f.code), true, second.is_some())).into_response();
    }
    let new_password = (!f.new.is_empty()).then_some(f.new.as_str());
    let choosing = new_password.is_some();
    match app.control.use_sign_in_link(&f.code, new_password, second).await {
        Ok(login) => {
            let landing = if new_password.is_some() { done_url("/", Done::PasswordChanged) } else { "/".to_string() };
            logged_in_to(&app, login, None, &landing)
        }
        Err(LinkError::Invalid) => {
            if over_limit_after_a_bad_code(&app, client) {
                return (StatusCode::TOO_MANY_REQUESTS, link_page(Some(TOO_MANY), None, false, false)).into_response();
            }
            (StatusCode::UNAUTHORIZED, link_page(Some("That link has expired or was already used. Ask for a new one on the sign-in page."), None, false, false)).into_response()
        }
        Err(LinkError::Password(m)) => (StatusCode::BAD_REQUEST, link_page(Some(&m), Some(&f.code), true, second.is_some())).into_response(),
        Err(LinkError::MustChoosePassword) => {
            let msg = "An administrator set your password, so choose your own to finish signing in.";
            (StatusCode::BAD_REQUEST, link_page(Some(msg), Some(&f.code), true, second.is_some())).into_response()
        }
        Err(LinkError::NeedsCode) => {
            let msg = if choosing {
                "Your account takes a code from your authenticator app too. Enter it, and your new password again."
            } else {
                "Your account takes a code from your authenticator app too."
            };
            (StatusCode::BAD_REQUEST, link_page(Some(msg), Some(&f.code), choosing, true)).into_response()
        }
        Err(LinkError::WrongCode) => {
            if over_limit_after_a_bad_code(&app, client) {
                return (StatusCode::TOO_MANY_REQUESTS, link_page(Some(TOO_MANY), Some(&f.code), choosing, true)).into_response();
            }
            let msg = "That code isn't right. Enter the one your app shows now, or an unused recovery code.";
            (StatusCode::UNAUTHORIZED, link_page(Some(msg), Some(&f.code), choosing, true)).into_response()
        }
        Err(LinkError::CodeThrottled) => {
            let msg = "Too many wrong codes for this account. Try again in 15 minutes; the link works until it expires.";
            (StatusCode::TOO_MANY_REQUESTS, link_page(Some(msg), Some(&f.code), choosing, true)).into_response()
        }
        Err(LinkError::Internal) => (StatusCode::INTERNAL_SERVER_ERROR, link_page(Some(WENT_WRONG), Some(&f.code), false, second.is_some())).into_response(),
    }
}

// ---- accepting an invitation ---------------------------------------------------------------------

fn invitation_form_page(error: Option<&str>) -> Response {
    let body = format!(
        r#"<div class="auth"><h1>Your <em>invitation</em></h1><p class="lede">Opening it doesn't use it up. You'll choose how to sign in next.</p>
<div class="card">{err}<form method="post" action="/invite">{CODE_FIELD}
<button class="btn primary block spaced">Open invitation</button></form></div></div>"#,
        err = form_alert(error),
    );
    page(&title_of("Your invitation", error.is_some()), None, &body)
}

const INVITATION_GONE: &str = "That invitation has expired or was already used. Ask an administrator for a new one.";

fn invitation_gone(app: &AppState, client: Option<IpAddr>) -> Response {
    if over_limit_after_a_bad_code(app, client) {
        return (StatusCode::TOO_MANY_REQUESTS, invitation_form_page(Some(TOO_MANY))).into_response();
    }
    (StatusCode::UNAUTHORIZED, invitation_form_page(Some(INVITATION_GONE))).into_response()
}

pub async fn invitation_form(State(app): State<AppState>) -> Response {
    if app.control.proxy_auth().is_some() {
        return Redirect::to("/").into_response();
    }
    invitation_form_page(None)
}

/// What an opened invitation offers: every provider, then a password.
fn invitation_page(app: &AppState, code: &str, invitation: &OpenInvitation, name: &str, error: Option<&str>) -> Response {
    let hidden = hidden_code(code);
    let providers: String = app
        .control
        .oidc_providers()
        .iter()
        .map(|p| format!(r#"<form method="post" action="/invite/provider/{id}">{hidden}<button class="btn block sso">Continue with {label}</button></form>"#, id = esc(&p.id), label = esc(&p.label)))
        .collect();
    let or = if providers.is_empty() { "" } else { r#"<p class="note or">or</p>"# };
    let role = if invitation.role == Role::Admin { "an administrator" } else { "a member" };
    let body = format!(
        r#"<div class="auth"><h1>Join <em>MagicPipes</em></h1><p class="lede">{by} invited you to join as {role}.</p>
<div class="card">{err}{providers}{or}<form method="post" action="/invite/accept">{hidden}
<label for="ie">Email</label><input id="ie" type="email" name="username" value="{email}" autocomplete="username" readonly>
<label for="in">Your name</label><input id="in" name="display_name" value="{name}" maxlength="100" autocomplete="name">
<label for="ip">Choose a password</label><input id="ip" type="password" name="password" autocomplete="new-password" minlength="{MIN_PASSWORD_CHARS}"{bad_password} required>
<label for="ir">Repeat it</label><input id="ir" type="password" name="repeat" autocomplete="new-password" minlength="{MIN_PASSWORD_CHARS}" required>
<button class="btn primary block spaced">Create account</button></form></div>
<p class="note">At least {MIN_PASSWORD_CHARS} characters. A long phrase is easier to remember than a short jumble.</p></div>"#,
        by = esc(&invitation.invited_by),
        email = esc(&invitation.email),
        err = form_alert(error),
        name = esc(name),
        bad_password = invalid(error.is_some()),
    );
    page(&title_of("Join MagicPipes", error.is_some()), None, &body)
}

#[derive(Deserialize)]
pub struct CodeForm {
    #[serde(default)]
    code: String,
}

/// Shows what a code opens. Doesn't use it up.
pub async fn open_invitation(State(app): State<AppState>, client: Option<axum::Extension<ClientIp>>, headers: HeaderMap, Form(f): Form<CodeForm>) -> Response {
    if app.control.proxy_auth().is_some() {
        return Redirect::to("/").into_response();
    }
    if cross_site(&headers) {
        return (StatusCode::FORBIDDEN, invitation_form_page(Some(FROM_ELSEWHERE))).into_response();
    }
    match app.control.open_invitation(&f.code) {
        Some(invitation) => invitation_page(&app, &f.code, &invitation, &invitation.display_name, None),
        None => invitation_gone(&app, client_of(client)),
    }
}

#[derive(Deserialize)]
pub struct AcceptForm {
    #[serde(default)]
    code: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    repeat: String,
}

pub async fn accept_invitation(State(app): State<AppState>, client: Option<axum::Extension<ClientIp>>, headers: HeaderMap, Form(f): Form<AcceptForm>) -> Response {
    if app.control.proxy_auth().is_some() {
        return Redirect::to("/").into_response();
    }
    // Another site's form could sign this browser in to an account the attacker invited.
    if cross_site(&headers) {
        return (StatusCode::FORBIDDEN, invitation_form_page(Some(FROM_ELSEWHERE))).into_response();
    }
    let client = client_of(client);
    let Some(invitation) = app.control.open_invitation(&f.code) else { return invitation_gone(&app, client) };
    let again = |message: &str| (StatusCode::BAD_REQUEST, invitation_page(&app, &f.code, &invitation, &f.display_name, Some(message))).into_response();
    if f.password != f.repeat {
        return again("The passwords don't match.");
    }
    match app.control.accept_invitation(&f.code, &f.display_name, &f.password).await {
        Ok(login) => logged_in_to(&app, login, None, &done_url("/", Done::Welcome)),
        Err(AcceptError::Gone) => invitation_gone(&app, client),
        Err(AcceptError::Password(m)) => again(&m),
        Err(AcceptError::AccountExists) => (StatusCode::CONFLICT, login_page(&app, Some("That address already has an account. Sign in instead."), false, None)).into_response(),
        Err(AcceptError::Full) => again("This server has as many accounts as it can hold. Ask an administrator."),
        Err(AcceptError::Internal) => again(WENT_WRONG),
    }
}

/// Leaves for a provider to accept an invitation with it. This answers a form, so the browser moves
/// on from a page, since `form-action 'self'` would stop a redirect to another site.
pub async fn invitation_provider(State(app): State<AppState>, Path(id): Path<String>, client: Option<axum::Extension<ClientIp>>, headers: HeaderMap, Form(f): Form<CodeForm>) -> Response {
    if app.control.proxy_auth().is_some() {
        return Redirect::to("/").into_response();
    }
    if cross_site(&headers) {
        return (StatusCode::FORBIDDEN, invitation_form_page(Some(FROM_ELSEWHERE))).into_response();
    }
    let client = client_of(client);
    let Some(invitation) = app.control.open_invitation(&f.code) else { return invitation_gone(&app, client) };
    let again = |status: StatusCode, message: &str| (status, invitation_page(&app, &f.code, &invitation, &invitation.display_name, Some(message))).into_response();
    let Some(provider) = app.control.oidc_provider(&id) else { return again(StatusCode::NOT_FOUND, "That sign-in method doesn't exist.") };
    match app.control.oidc_start_invited(&provider, &f.code, &redirect_uri(&app, &id)).await {
        Ok((url, cookie)) => {
            let mut resp = leaving_page(&url, &provider.label);
            resp.headers_mut().insert(header::SET_COOKIE, attempt_cookie(&cookie, ATTEMPT_COOKIE_MAX_AGE));
            resp
        }
        Err(SignInError::InvitationGone) => invitation_gone(&app, client),
        Err(_) => again(StatusCode::BAD_GATEWAY, &format!("{} can't be reached right now. Try again in a moment.", provider.label)),
    }
}

/// What the Users page tells someone about an invitation they're about to send.
pub(super) fn invitation_note() -> String {
    format!("They choose a password or a sign-in provider from the link, which works once, for {INVITATION_DAYS} days.")
}

// ---- confirming your address ---------------------------------------------------------------------

/// On the account page: only for someone who'd need it and can get it.
pub(super) fn confirm_panel(app: &AppState, user: &UiUser) -> String {
    let Some(me) = &user.user else { return String::new() };
    if me.email_verified || !me.has_password || !app.control.mail_on() {
        return String::new();
    }
    format!(
        r#"<div class="card panel spaced"><div><h2>Confirm your address</h2><p>Nothing shows that {} is yours yet. Once it does, you can get a sign-in link if you forget your password.</p></div>
<form method="post" action="/account/address">{}<button class="btn">Email me a link</button></form></div>"#,
        esc(&me.email),
        user.csrf_field()
    )
}

pub async fn request_confirmation(State(app): State<AppState>, Posted(user, _): Posted<NoFields>) -> Response {
    match app.control.request_address_confirmation(&user.who).await {
        Ok(()) => done("/account", Done::ConfirmationSent),
        Err(e) => failed(&user, StatusCode::BAD_GATEWAY, "/account", "Account", &e.message),
    }
}

fn confirm_page(user: &UiUser, error: Option<&str>) -> Response {
    let body = format!(
        r#"{back}<div class="auth"><h1>Confirm your <em>address</em></h1><p class="lede">This shows that {email} is yours. It's the address you'd get a sign-in link at.</p>
<div class="card">{err}<form method="post" action="/account/address/confirm">{csrf}{CODE_FIELD}
<button class="btn primary block spaced">Confirm</button></form></div></div>"#,
        back = back("/account", "Account"),
        email = esc(user.user.as_ref().map_or("", |u| u.email.as_str())),
        err = form_alert(error),
        csrf = user.csrf_field(),
    );
    page(&title_of("Confirm your address", error.is_some()), Some(user), &body)
}

pub async fn confirm_form(user: UiUser) -> Response {
    if user.user.is_none() {
        return Redirect::to("/account").into_response();
    }
    confirm_page(&user, None)
}

pub async fn confirm(State(app): State<AppState>, Posted(user, f): Posted<CodeForm>) -> Response {
    match app.control.confirm_address(&user.who, &f.code) {
        Ok(true) => done("/account", Done::AddressConfirmed),
        Ok(false) => (StatusCode::BAD_REQUEST, confirm_page(&user, Some("That link has expired, was already used, or is for another account. Sign in to the account it was sent for, or ask for a new one."))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, confirm_page(&user, Some(&e.message))).into_response(),
    }
}

// ---- the mail server on the Settings page --------------------------------------------------------

fn security_label(tls: SmtpTls) -> &'static str {
    match tls {
        SmtpTls::Starttls => "STARTTLS",
        SmtpTls::Implicit => "TLS",
        SmtpTls::None => "no encryption",
    }
}

/// Its part of the Settings page.
pub(super) fn section(user: &UiUser, app: &AppState) -> String {
    let heading = r#"<div class="section" id="email"><h2>Email</h2></div>"#;
    if app.control.proxy_auth().is_some() {
        return format!(r#"{heading}<p class="note below-section">This server signs people in through its proxy (<code>[proxy_auth]</code>), so it has no use for email.</p>"#);
    }
    let Ok(view) = app.control.smtp_settings(&user.who) else {
        return format!(r#"{heading}<p class="note below-section">The email settings can't be read right now. The server's log says why.</p>"#);
    };
    let Some(view) = view else {
        return format!(
            r#"{heading}<div class="card panel"><div><p>Invite people by email, and let them get a sign-in link if they forget a password.</p></div><a class="btn" href="/settings/email">Set up email</a></div>"#
        );
    };
    let c = &view.config;
    let summary = format!("<code>{}:{}</code> · {} · from <code>{}</code>", esc(c.host.trim()), c.port_number(), security_label(c.tls_mode()), esc(&c.from));
    let trouble = if view.available { "" } else { r#"<p><span class="status bad">Its password can't be read</span></p>"# };
    let actions = if view.from_file {
        r#"<span class="sub">in the configuration file</span>"#.to_string()
    } else {
        format!(
            r#"<div class="row"><a class="btn small" href="/settings/email">Edit</a><form class="inline" method="post" action="/settings/email/delete" data-confirm="Remove the mail server? People can't get sign-in links, and you can't send invitations. Invitations already sent still work.">{csrf}<button class="btn danger small">Remove</button></form></div>"#,
            csrf = user.csrf_field()
        )
    };
    let test = if view.available {
        format!(
            r#"<div class="card form spaced"><form method="post" action="/settings/email/test">{csrf}<label for="tm">Send a test message to</label><input id="tm" type="email" name="to" value="{me}" required>
<button class="btn spaced">Send test message</button></form></div>"#,
            csrf = user.csrf_field(),
            me = esc(user.user.as_ref().map_or("", |u| u.email.as_str())),
        )
    } else {
        String::new()
    };
    format!(r#"{heading}<div class="card panel"><div><p class="wrap">{summary}</p>{trouble}</div>{actions}</div>{test}"#)
}

#[derive(Deserialize, Default)]
pub struct EmailForm {
    #[serde(default)]
    host: String,
    #[serde(default)]
    tls: String,
    #[serde(default)]
    port: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    from: String,
}

impl EmailForm {
    fn of(view: &SmtpView) -> Self {
        let c = &view.config;
        Self {
            host: c.host.clone(),
            tls: c.tls_mode().as_str().to_string(),
            port: c.port_number().to_string(),
            username: c.username.clone().unwrap_or_default(),
            password: String::new(),
            from: c.from.clone(),
        }
    }
}

/// The form. A password that was typed isn't sent back, and one that's saved can't be shown.
fn email_page(user: &UiUser, typed: &EmailForm, saved: bool, error: Option<&str>) -> Response {
    let option = |value: &str, label: &str| format!(r#"<option value="{value}"{}>{label}</option>"#, if typed.tls == value { " selected" } else { "" });
    let about = |words: &[&str]| error.is_some_and(|e| words.iter().any(|w| e.contains(w)));
    let (bad_from, bad_login) = (about(&["send from"]), about(&["username", "password", "Password", "auth", "credentials"]));
    let body = format!(
        r#"{back}<h1>Email</h1><p class="lede">Use the SMTP settings from your mail provider or your own mail server.</p>
<div class="card form spaced">{err}<form method="post" action="/settings/email">{csrf}
<label for="mh">Mail server</label><input id="mh" name="host" placeholder="smtp.example.com" value="{host}" maxlength="253" spellcheck="false"{bad_host} required>
<label for="mt">Security</label><select id="mt" name="tls">{starttls}{implicit}{none}</select>
<label for="mp">Port</label><input id="mp" name="port" inputmode="numeric" placeholder="The usual one for that security" value="{port}" maxlength="5">
<label for="mu">Username</label><input id="mu" name="username" value="{username}" maxlength="512" autocomplete="off" spellcheck="false"{bad_login}>
<label for="ms">Password</label><input id="ms" type="password" name="password" maxlength="4096" autocomplete="new-password">
<p class="note">{password_note}</p>
<label for="mf">Send from</label><input id="mf" name="from" placeholder="MagicPipes &lt;magicpipes@example.com&gt;" value="{from}" maxlength="320" spellcheck="false"{bad_from} required>
<button class="btn primary">Check and save</button></form>
<p class="note">Saving connects and signs in first, so a wrong address or password shows up now. Only a test message shows whether mail arrives. Without encryption, nothing can sign in.</p></div>"#,
        back = back("/settings", "Settings"),
        err = form_alert(error),
        csrf = user.csrf_field(),
        host = esc(&typed.host),
        bad_host = invalid(error.is_some() && !bad_from && !bad_login),
        starttls = option("starttls", "STARTTLS (usually port 587)"),
        implicit = option("implicit", "TLS (usually port 465)"),
        none = option("none", "None, for a relay on a network you trust"),
        port = esc(&typed.port),
        username = esc(&typed.username),
        bad_login = invalid(bad_login),
        password_note = if saved { "Leave it empty to keep the current one, which can't be shown." } else { "Kept in a file that only this server can read, never in its database." },
        from = esc(&typed.from),
        bad_from = invalid(bad_from),
    );
    page(&title_of("Email", error.is_some()), Some(user), &body)
}

#[allow(clippy::result_large_err)] // responses are returned by value on purpose
fn editable_view(user: &UiUser, app: &AppState) -> Result<Option<SmtpView>, Response> {
    match app.control.smtp_settings(&user.who) {
        Ok(Some(v)) if v.from_file => Err(Redirect::to("/settings").into_response()),
        Ok(view) => Ok(view),
        Err(e) => Err(failed(user, StatusCode::INTERNAL_SERVER_ERROR, "/settings", "Settings", &e.message)),
    }
}

pub async fn email_form(AdminUser(user): AdminUser, State(app): State<AppState>) -> Response {
    if app.control.proxy_auth().is_some() {
        return Redirect::to("/settings").into_response();
    }
    match editable_view(&user, &app) {
        Ok(Some(view)) => email_page(&user, &EmailForm::of(&view), true, None),
        Ok(None) => email_page(&user, &EmailForm { tls: "starttls".into(), ..EmailForm::default() }, false, None),
        Err(resp) => resp,
    }
}

pub async fn save_email(State(app): State<AppState>, AdminPosted(user, f): AdminPosted<EmailForm>) -> Response {
    if app.control.proxy_auth().is_some() {
        return Redirect::to("/settings").into_response();
    }
    let view = match editable_view(&user, &app) {
        Ok(view) => view,
        Err(resp) => return resp,
    };
    let refused = |message: &str| (StatusCode::BAD_REQUEST, email_page(&user, &f, view.is_some(), Some(message))).into_response();
    let Some(tls) = SmtpTls::parse(&f.tls) else { return refused("Choose a kind of security.") };
    let port = match f.port.trim() {
        "" => None,
        port => match port.parse::<u16>() {
            Ok(port) if port > 0 => Some(port),
            _ => return refused("The port must be a number from 1 to 65535."),
        },
    };
    let new = NewSmtp { host: &f.host, port, tls, username: &f.username, password: &f.password, from: &f.from };
    match app.control.set_smtp(&user.who, new).await {
        Ok(()) => done("/settings", Done::EmailSaved),
        Err(e) => refused(&e.message),
    }
}

pub async fn delete_email(State(app): State<AppState>, AdminPosted(user, _): AdminPosted<NoFields>) -> Response {
    match app.control.delete_smtp(&user.who) {
        Ok(_) => done("/settings", Done::EmailRemoved),
        Err(e) => failed(&user, StatusCode::BAD_REQUEST, "/settings", "Settings", &e.message),
    }
}

#[derive(Deserialize)]
pub struct TestForm {
    #[serde(default)]
    to: String,
}

pub async fn test_email(State(app): State<AppState>, AdminPosted(user, f): AdminPosted<TestForm>) -> Response {
    match app.control.send_test_message(&user.who, &f.to).await {
        Ok(()) => done("/settings", Done::TestMessageSent),
        Err(e) => failed(&user, StatusCode::BAD_GATEWAY, "/settings", "Settings", &e.message),
    }
}
