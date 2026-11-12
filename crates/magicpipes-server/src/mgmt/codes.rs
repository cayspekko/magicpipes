//! Pages for sign-in codes: the step after a password, and setting them up, making new recovery
//! codes and turning them off from the Account page. The decisions are in `control::totp`.

use axum::Form;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use magicpipes_core::url;
use serde::Deserialize;

use super::accounts::shown_once;
use super::email::{FROM_ELSEWHERE, TOO_MANY, WENT_WRONG, client_of, over_limit_after_a_bad_code};
use super::extract::{Posted, UiUser};
use super::html::{count, esc, form_alert, invalid, title_of, when};
use super::ui::{Done, cross_site, done, done_url, logged_in_to, login_page, page};
use super::{AppState, ClientIp};
use crate::control::{CodeError, TotpSetup, UserView};
use crate::totp;
use crate::tunnel_auth::{cookie, safe_path};

/// The note a right password gives, until a code finishes the sign-in. `__Host-`, like the session
/// cookie; `Strict`, since only our own form sends it back.
const CODE_COOKIE: &str = "__Host-mp_code";
const CODE_COOKIE_SECS: i64 = 5 * 60;

fn code_cookie(value: &str, max_age: i64) -> HeaderValue {
    HeaderValue::from_str(&format!("{CODE_COOKIE}={value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={max_age}")).expect("cookie is ASCII")
}

fn next_field(next: Option<&str>) -> String {
    safe_path(next).map(|n| format!(r#"<input type="hidden" name="next" value="{}">"#, esc(n))).unwrap_or_default()
}

// ---- after the password --------------------------------------------------------------------------

/// After a right password, on to the code, keeping where to go next.
pub(super) fn ask_for_code(pending: &str, next: Option<&str>) -> Response {
    let to = match safe_path(next) {
        Some(n) => format!("/login/code?next={}", url::encode(n)),
        None => "/login/code".to_string(),
    };
    let mut resp = Redirect::to(&to).into_response();
    resp.headers_mut().insert(header::SET_COOKIE, code_cookie(pending, CODE_COOKIE_SECS));
    resp
}

/// `recovery`: what went wrong was about a recovery code, so that form is the one open.
fn code_page(error: Option<&str>, next: Option<&str>, recovery: bool) -> Response {
    let next = next_field(next);
    let body = format!(
        r#"<div class="auth"><h1>Enter a <em>code</em></h1><p class="lede">From the authenticator app you set up for this account.</p>
<div class="card">{err}<form method="post" action="/login/code">{next}<label for="k">Code</label><input id="k" name="code" inputmode="numeric" autocomplete="one-time-code" spellcheck="false" maxlength="12" required{app_autofocus}{app_invalid}>
<button class="btn primary block">Sign in</button></form>
<details class="more"{open}><summary>Use a recovery code</summary><div><form method="post" action="/login/code">{next}<label for="rc">Recovery code</label><input id="rc" name="code" autocomplete="off" spellcheck="false" maxlength="40" required{recovery_invalid}>
<button class="btn block">Sign in</button></form></div></details></div>
<p class="note">Each recovery code works once. <a href="/login">Start over</a></p></div>"#,
        err = form_alert(error),
        open = if recovery { " open" } else { "" },
        // A field that's wrong takes the focus itself.
        app_autofocus = if error.is_some() { "" } else { " autofocus" },
        app_invalid = invalid(error.is_some() && !recovery),
        recovery_invalid = invalid(error.is_some() && recovery),
    );
    page(&title_of("Enter a code", error.is_some()), None, &body)
}

#[derive(Deserialize)]
pub struct NextQuery {
    next: Option<String>,
}

pub async fn code_form(headers: HeaderMap, axum::extract::Query(q): axum::extract::Query<NextQuery>) -> Response {
    // Without the note from a password, there's nothing a code could finish.
    if cookie(&headers, CODE_COOKIE).is_none() {
        return Redirect::to("/login").into_response();
    }
    code_page(None, q.next.as_deref(), false)
}

#[derive(Deserialize)]
pub struct CodeForm {
    #[serde(default)]
    code: String,
    next: Option<String>,
}

pub async fn use_code(State(app): State<AppState>, client: Option<axum::Extension<ClientIp>>, headers: HeaderMap, Form(f): Form<CodeForm>) -> Response {
    let next = f.next.as_deref();
    let recovery = !totp::is_app_code(&f.code);
    // Another site's form could finish a sign-in this browser started.
    if cross_site(&headers) {
        return (StatusCode::FORBIDDEN, code_page(Some(FROM_ELSEWHERE), next, recovery)).into_response();
    }
    let client = client_of(client);
    if app.password_blocked(client) {
        return (StatusCode::TOO_MANY_REQUESTS, code_page(Some(TOO_MANY), next, recovery)).into_response();
    }
    let start_over = |msg: &str| {
        let mut resp = (StatusCode::UNAUTHORIZED, login_page(&app, Some(msg), false, next)).into_response();
        resp.headers_mut().append(header::SET_COOKIE, code_cookie("", 0));
        resp
    };
    let Some(pending) = cookie(&headers, CODE_COOKIE) else {
        return start_over("That took too long. Sign in again.");
    };
    match app.control.finish_with_code(pending, &f.code).await {
        Ok((login, used_recovery)) => {
            let landing = if used_recovery { done_url("/", Done::RecoveryCodeUsed) } else { "/".to_string() };
            let mut resp = logged_in_to(&app, login, next, &landing);
            resp.headers_mut().append(header::SET_COOKIE, code_cookie("", 0));
            resp
        }
        Err(CodeError::Wrong) => {
            if over_limit_after_a_bad_code(&app, client) {
                return (StatusCode::TOO_MANY_REQUESTS, code_page(Some(TOO_MANY), next, recovery)).into_response();
            }
            let msg = if recovery {
                "That isn't one of your recovery codes, or it was used already."
            } else {
                "That code isn't right. Enter the one your app shows now."
            };
            (StatusCode::UNAUTHORIZED, code_page(Some(msg), next, recovery)).into_response()
        }
        Err(CodeError::Throttled) => {
            let msg = "Too many wrong codes for this account. Try again in 15 minutes.";
            (StatusCode::TOO_MANY_REQUESTS, code_page(Some(msg), next, recovery)).into_response()
        }
        Err(CodeError::Expired) => start_over("That took too long, or the account changed meanwhile. Sign in again."),
        Err(CodeError::Internal) => (StatusCode::INTERNAL_SERVER_ERROR, code_page(Some(WENT_WRONG), next, recovery)).into_response(),
    }
}

// ---- on the Account page -------------------------------------------------------------------------

/// The Account page's panel, for someone with a password.
pub(super) fn panel(user: &UiUser, app: &AppState, me: &UserView) -> String {
    if !me.has_password || user.through_proxy() {
        return String::new();
    }
    let (said, button) = match app.control.totp_status(&user.who) {
        Some(on) => (format!("On since {}. {} left.", when(&on.since), recovery_left(on.recovery_left)), "Manage"),
        None => ("Off. Turn them on to need a code from an authenticator app after your password.".to_string(), "Set up"),
    };
    format!(r#"<div class="card panel spaced"><div><h2>Sign-in codes</h2><p>{said}</p></div><a class="btn" href="/account/codes">{button}</a></div>"#)
}

/// A message from the control plane as a sentence on a page: "the password is not correct" reads
/// "The password is not correct."
fn sentence(message: &str) -> String {
    let mut chars = message.chars();
    let Some(first) = chars.next() else { return String::new() };
    let end = if message.ends_with(['.', '?', '!']) { "" } else { "." };
    format!("{}{}{end}", first.to_uppercase(), chars.as_str())
}

fn recovery_left(n: i64) -> String {
    count(usize::try_from(n).unwrap_or(0), "recovery code", "recovery codes")
}

/// Setting up, with `setup`'s key; `error` and which field it's about.
fn setup_page(user: &UiUser, setup: &TotpSetup, error: Option<&str>) -> Response {
    let bad_password = error.is_some_and(|m| m.contains("password"));
    let error = error.map(sentence);
    let error = error.as_deref();
    let qr = totp::qr_svg(&setup.uri).unwrap_or_default();
    // In groups of four, as apps show it.
    let key: Vec<String> = setup.key.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect();
    let body = format!(
        r#"<div class="auth"><div class="eyebrow">Account</div><h1>Set up <em>sign-in codes</em></h1>
<p class="lede">Scan this with an authenticator app, such as 1Password, Google Authenticator or Microsoft Authenticator, then enter the code it shows.</p>
<div class="card">{err}<div role="img" aria-label="QR code for an authenticator app. To type the key instead, open Can't scan it.">{qr}</div>
<details class="more"><summary>Can't scan it?</summary><div><p>On this device, <a href="{uri}">open it in your app</a>. Or type this key, time-based, with 6 digits every 30 seconds:</p><p><code class="key">{key}</code></p></div></details>
<form method="post" action="/account/codes" class="spaced">{csrf}<input type="hidden" name="key" value="{sealed}">
<label for="kc">Code from the app</label><input id="kc" name="code" inputmode="numeric" autocomplete="one-time-code" spellcheck="false" maxlength="12" required{code_invalid}>
<label for="kp">Your password</label><input id="kp" type="password" name="password" autocomplete="current-password" required{password_invalid}>
<button class="btn primary block">Turn on</button></form></div>
<p class="note">Next come recovery codes, for when you don't have the app. Turning codes on signs you out on other devices.</p></div>"#,
        err = form_alert(error),
        uri = esc(&setup.uri),
        key = esc(&key.join(" ")),
        csrf = user.csrf_field(),
        sealed = esc(&setup.sealed),
        code_invalid = invalid(error.is_some() && !bad_password),
        password_invalid = invalid(bad_password),
    );
    page(&title_of("Set up sign-in codes", error.is_some()), Some(user), &body)
}

/// When codes are on: new recovery codes, or turning them off. `error` is about `form`.
fn manage_page(user: &UiUser, app: &AppState, error: Option<(&str, &str)>) -> Response {
    let Some(on) = app.control.totp_status(&user.who) else { return Redirect::to("/account/codes").into_response() };
    let form = |action: &str, title: &str, said: &str, button: &str, danger: bool, confirm: &str| {
        let err = error.filter(|(f, _)| *f == action).map(|(_, m)| sentence(m));
        let err = err.as_deref();
        format!(
            r#"<div class="card">{alert}<h2>{title}</h2><p class="note">{said}</p><form method="post" action="/account/codes/{action}"{confirm}>{csrf}
<label for="p-{action}">Your password</label><input id="p-{action}" type="password" name="password" autocomplete="current-password" required{invalid}>
<button class="btn block{danger}">{button}</button></form></div>"#,
            alert = form_alert(err),
            csrf = user.csrf_field(),
            invalid = invalid(err.is_some()),
            danger = if danger { " danger" } else { "" },
            confirm = if confirm.is_empty() { String::new() } else { format!(r#" data-confirm="{}""#, esc(confirm)) },
        )
    };
    let body = format!(
        r#"<div class="auth"><div class="eyebrow">Account</div><h1>Sign-in <em>codes</em></h1><p class="lede">On since {since}. {left} left.</p>
{recovery}
{off}</div>"#,
        since = when(&on.since),
        left = recovery_left(on.recovery_left),
        recovery = form("recovery", "New recovery codes", "The ones you have now stop working.", "Make new recovery codes", false, ""),
        off = form("off", "Turn off", "Signing in will need only your password.", "Turn off", true, "Turn sign-in codes off? Signing in will need only your password."),
    );
    page(&title_of("Sign-in codes", error.is_some()), Some(user), &body)
}

pub async fn codes(user: UiUser, State(app): State<AppState>) -> Response {
    if app.control.totp_status(&user.who).is_some() {
        return manage_page(&user, &app, None);
    }
    match app.control.totp_setup(&user.who, None) {
        Ok(setup) => setup_page(&user, &setup, None),
        Err(_) => Redirect::to("/account").into_response(),
    }
}

#[derive(Deserialize)]
pub struct TurnOnForm {
    #[serde(default)]
    key: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    password: String,
}

pub async fn turn_on(State(app): State<AppState>, Posted(user, f): Posted<TurnOnForm>) -> Response {
    match app.control.turn_on_totp(&user.who, &f.key, &f.password, &f.code).await {
        Ok((login, recovery)) => {
            // Signed out everywhere, this session too: the new one goes with this page.
            let body = format!(
                r#"<div class="eyebrow spaced">Shown once</div><h1>Save your <em>recovery codes</em></h1>
<p class="lede">Each works once, in place of a code, if you lose the app. Keep them somewhere safe: they're not shown again.</p>
<pre class="term">{codes}</pre>
<a class="btn primary spaced" href="{to}">Continue</a>"#,
                codes = esc(&recovery.join("\n")),
                to = done_url("/account", Done::CodesOn),
            );
            let mut resp = page("Save your recovery codes", None, &body);
            let max_age = app.control.config().users.session_max_age_secs;
            resp.headers_mut().insert(header::SET_COOKIE, super::ui::session_cookie(&login.cookie, max_age));
            resp
        }
        Err(e) => match app.control.totp_setup(&user.who, Some(&f.key)) {
            // The same key, which the app may already have.
            Ok(setup) => (StatusCode::BAD_REQUEST, setup_page(&user, &setup, Some(&e.message))).into_response(),
            Err(_) => Redirect::to("/account").into_response(),
        },
    }
}

#[derive(Deserialize)]
pub struct PasswordOnly {
    #[serde(default)]
    password: String,
}

pub async fn new_recovery_codes(State(app): State<AppState>, Posted(user, f): Posted<PasswordOnly>) -> Response {
    match app.control.new_recovery_codes(&user.who, &f.password).await {
        Ok(recovery) => shown_once(
            &user,
            "New recovery codes",
            "Each works once, in place of a code, if you lose the app. The old ones no longer work.",
            &recovery.join("\n"),
            "",
            "/account",
        ),
        Err(e) => (StatusCode::BAD_REQUEST, manage_page(&user, &app, Some(("recovery", &e.message)))).into_response(),
    }
}

pub async fn turn_off(State(app): State<AppState>, Posted(user, f): Posted<PasswordOnly>) -> Response {
    match app.control.turn_off_totp(&user.who, &f.password).await {
        Ok(()) => done("/account", Done::CodesOff),
        Err(e) => (StatusCode::BAD_REQUEST, manage_page(&user, &app, Some(("off", &e.message)))).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_read_as_sentences() {
        assert_eq!(sentence("the password is not correct"), "The password is not correct.");
        assert_eq!(sentence("Already one."), "Already one.");
        assert_eq!(sentence(""), "");
    }
}
