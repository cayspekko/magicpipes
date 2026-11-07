//! Signing in through an OpenID Connect provider: leaving for it and coming back.

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use http::{HeaderValue, StatusCode, header};
use serde::Deserialize;

use super::ui::{logged_in, login_page, server_url};
use super::{AppState, ClientIp};
use crate::control::SignInError;
use crate::oidc::ATTEMPT_COOKIE_MAX_AGE;
use crate::tunnel_auth::{cookie, safe_path};

/// `__Host-`, like the session cookie: content on a tunnel subdomain can't set or shadow it.
/// `SameSite=Lax`: the way back from the provider is a navigation from another site.
const ATTEMPT_COOKIE: &str = "__Host-mp_oidc";

pub(super) fn attempt_cookie(value: &str, max_age: i64) -> HeaderValue {
    HeaderValue::from_str(&format!("{ATTEMPT_COOKIE}={value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age}")).expect("cookie is ASCII")
}

pub(super) fn redirect_uri(app: &AppState, id: &str) -> String {
    format!("{}/auth/oidc/{id}/callback", server_url(app))
}

#[derive(Deserialize)]
pub struct StartQuery {
    next: Option<String>,
}

/// Leaves for the provider. A plain link, so it's safe for another site to link here: all it can
/// do is start a sign-in that comes back to this browser's own cookie.
pub async fn start(State(app): State<AppState>, Path(id): Path<String>, Query(q): Query<StartQuery>) -> Response {
    let next = safe_path(q.next.as_deref());
    let Some(provider) = app.control.oidc_provider(&id) else {
        return (StatusCode::NOT_FOUND, login_page(&app, Some("That sign-in method doesn't exist."), false, next)).into_response();
    };
    match app.control.oidc_start(&provider, next, &redirect_uri(&app, &id)).await {
        Ok((url, cookie)) => {
            let mut resp = Redirect::to(&url).into_response();
            resp.headers_mut().insert(header::SET_COOKIE, attempt_cookie(&cookie, ATTEMPT_COOKIE_MAX_AGE));
            resp
        }
        Err(_) => {
            let msg = format!("{} can't be reached right now. Try again in a moment.", provider.label);
            (StatusCode::BAD_GATEWAY, login_page(&app, Some(&msg), false, next)).into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    iss: Option<String>,
}

/// The provider sends the browser back here. Every answer also ends the attempt.
pub async fn callback(
    State(app): State<AppState>,
    Path(id): Path<String>,
    client: Option<axum::Extension<ClientIp>>,
    headers: http::HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let mut resp = finish(&app, &id, client.map(|c| c.0.0), &headers, q).await;
    resp.headers_mut().append(header::SET_COOKIE, attempt_cookie("", 0));
    resp
}

async fn finish(app: &AppState, id: &str, client: Option<std::net::IpAddr>, headers: &http::HeaderMap, q: CallbackQuery) -> Response {
    let page = |status: StatusCode, msg: &str, next: Option<&str>| (status, login_page(app, Some(msg), false, next)).into_response();
    let expired = "That sign-in has expired. Try again.";
    let Some(provider) = app.control.oidc_provider(id) else { return page(StatusCode::NOT_FOUND, "That sign-in method doesn't exist.", None) };
    let attempt = cookie(headers, ATTEMPT_COOKIE).and_then(|c| app.control.oidc_attempt(&provider, c));
    let Some(attempt) = attempt else { return page(StatusCode::BAD_REQUEST, expired, None) };
    let next = safe_path(attempt.next.as_deref());
    let Some(state) = q.state.as_deref() else { return page(StatusCode::BAD_REQUEST, expired, next) };
    // A provider's error says nothing useful to the person, and it can be typed in by anyone.
    if q.error.is_some() {
        return page(StatusCode::BAD_REQUEST, "The sign-in was cancelled.", next);
    }
    let Some(code) = q.code.as_deref() else { return page(StatusCode::BAD_REQUEST, expired, next) };
    let too_many = "Too many failed attempts. Try again later.";
    // Each try costs a request to the provider.
    if app.password_blocked(client) {
        return page(StatusCode::TOO_MANY_REQUESTS, too_many, next);
    }
    match app.control.oidc_finish(&provider, &attempt, state, code, q.iss.as_deref(), &redirect_uri(app, id)).await {
        Ok(login) => logged_in(app, login, next),
        Err(SignInError::Expired) => page(StatusCode::BAD_REQUEST, expired, next),
        Err(SignInError::Refused) => {
            if app.check_credential(Err::<(), ()>(()), client).is_err_and(|r| matches!(r, super::Rejected::RateLimited)) {
                return page(StatusCode::TOO_MANY_REQUESTS, too_many, next);
            }
            page(StatusCode::UNAUTHORIZED, "The sign-in could not be completed. Try again.", next)
        }
        Err(SignInError::NotAllowed(Some(email))) => page(StatusCode::FORBIDDEN, &format!("{email} can't sign in here. Ask an administrator."), next),
        Err(SignInError::NotAllowed(None)) => {
            page(StatusCode::FORBIDDEN, &format!("{} didn't confirm an email address for this account, so it can't sign in here.", provider.label), next)
        }
        Err(SignInError::Unavailable) => page(StatusCode::BAD_GATEWAY, &format!("{} can't be reached right now. Try again in a moment.", provider.label), next),
        Err(SignInError::Busy) => page(StatusCode::SERVICE_UNAVAILABLE, "The server is busy. Try again in a moment.", next),
        Err(SignInError::InvitationGone) => page(StatusCode::BAD_REQUEST, "That invitation has expired or was already used. Ask an administrator for a new one.", next),
        Err(SignInError::AccountExists) => page(StatusCode::CONFLICT, "That address already has an account. Sign in instead.", next),
        Err(SignInError::IdentityTaken) => page(
            StatusCode::CONFLICT,
            &format!("That {} account already signs in to another account here. Open the invitation's link again, and use a different one or choose a password.", provider.label),
            next,
        ),
        Err(SignInError::Internal) => page(StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong. Try again.", next),
    }
}
