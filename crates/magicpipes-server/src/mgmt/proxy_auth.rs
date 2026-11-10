//! An authenticating proxy's word becomes a normal session, and stays the truth about it: every
//! page request must still name the session's user, so signing out at the proxy signs out here.
//! Agents and scripts have their own credentials, and an admin-token session is the way in when
//! the proxy is down or misconfigured, so neither depends on what the proxy says.

use axum::extract::{Query, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use http::{HeaderValue, Method, StatusCode, header};

use super::html::alert;
use super::ui::{LoginQuery, page, session_cookie};
use super::{AppState, PeerAddr, SESSION_COOKIE};
use crate::control::SignInError;
use crate::tunnel_auth::{cookie, safe_path};

/// Is this a page, the only thing a session is for?
fn is_a_page(path: &str) -> bool {
    !path.starts_with("/api/") && !matches!(path, "/healthz" | "/ui.js" | "/favicon.svg" | "/favicon.ico" | "/apple-touch-icon.png")
}

/// Where someone already signed in goes instead of the sign-in page. Asking for the admin token form
/// is the exception: that's how an administrator gets past a proxy that names someone else.
fn past_the_sign_in_page(req: &Request) -> Option<Response> {
    if req.method() != Method::GET || req.uri().path() != "/login" {
        return None;
    }
    let q = Query::<LoginQuery>::try_from_uri(req.uri()).ok()?;
    (q.method.as_deref() != Some("token")).then(|| Redirect::to(safe_path(q.next.as_deref()).unwrap_or("/")).into_response())
}

fn refused(status: StatusCode, title: &str, message: &str) -> Response {
    let body = format!(
        r#"<div class="auth"><h1>{title}</h1>{}<p class="note">Administrators can <a href="/login?method=token">use an admin token</a> instead.</p></div>"#,
        alert(Some(message))
    );
    (status, page(title, None, &body)).into_response()
}

pub async fn identify(State(app): State<AppState>, mut req: Request, next: Next) -> Response {
    let Some(proxy) = app.control.proxy_auth() else { return next.run(req).await };
    // The sign-in form takes an admin token, whoever the proxy says this is.
    let signing_in = req.method() == Method::POST && req.uri().path() == "/login";
    // `/metrics` is a page to a browser, and not to a scraper, which brings its own token.
    let scraping = req.uri().path() == "/metrics" && super::bearer_token(req.headers()).is_some();
    if !is_a_page(req.uri().path()) || signing_in || scraping {
        return next.run(req).await;
    }
    let held = cookie(req.headers(), SESSION_COOKIE).map(str::to_string);
    let session = held.as_deref().and_then(|c| app.control.session(c));
    if session.as_ref().is_some_and(|s| s.user.is_none()) {
        return next.run(req).await;
    }
    let peer = req.extensions().get::<PeerAddr>().map(|p| p.0.ip());
    let Ok(person) = proxy.person(req.headers(), peer).await else {
        // Not "nobody": a session survives a moment when the keys can't be fetched.
        return refused(StatusCode::BAD_GATEWAY, "Can't sign in", "The sign-in proxy's keys can't be fetched right now. Try again in a moment.");
    };

    // Whatever session comes with this request, it ends unless it's this person's.
    let end_session = |app: &AppState| {
        if let (Some(c), Some(s)) = (&held, &session) {
            app.control.logout(&s.who, c);
        }
    };
    let clearing = |mut resp: Response| {
        if held.is_some() {
            resp.headers_mut().append(header::SET_COOKIE, session_cookie("", 0));
        }
        resp
    };

    let Some(person) = person else {
        end_session(&app);
        req.headers_mut().remove(header::COOKIE);
        return clearing(next.run(req).await);
    };
    let current = session.as_ref().and_then(|s| s.user.as_ref()).map(|u| u.id.as_str());
    match app.control.proxy_sign_in(proxy, &person, current) {
        Ok(None) => match past_the_sign_in_page(&req) {
            Some(resp) => resp,
            None => next.run(req).await,
        },
        Ok(Some(login)) => {
            end_session(&app);
            if let Ok(v) = HeaderValue::from_str(&format!("{SESSION_COOKIE}={}", login.cookie)) {
                req.headers_mut().insert(header::COOKIE, v);
            }
            let mut resp = match past_the_sign_in_page(&req) {
                Some(resp) => resp,
                None => next.run(req).await,
            };
            resp.headers_mut().append(header::SET_COOKIE, session_cookie(&login.cookie, app.control.config().users.session_max_age_secs));
            resp
        }
        Err(SignInError::NotAllowed(email)) => {
            end_session(&app);
            // The sign-in page stays open, for an administrator's token.
            if req.uri().path() == "/login" {
                req.headers_mut().remove(header::COOKIE);
                return clearing(next.run(req).await);
            }
            let message = match email {
                Some(address) => format!("{address} can't sign in here. Ask an administrator."),
                None => "The sign-in proxy didn't confirm an email address for this account, so it can't sign in here. Ask an administrator.".to_string(),
            };
            clearing(refused(StatusCode::FORBIDDEN, "No access", &message))
        }
        Err(_) => refused(StatusCode::INTERNAL_SERVER_ERROR, "Can't sign in", "Something went wrong. Try again."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_pages_ask_who_someone_is() {
        for page in ["/", "/tags", "/login", "/cli", "/auth/tunnel", "/no/such/page"] {
            assert!(is_a_page(page), "{page}");
        }
        for other in ["/api/v1/agent/connect", "/api/v1/enroll", "/api/v1/tunnels", "/api/v1/device/poll", "/healthz", "/ui.js", "/favicon.ico"] {
            assert!(!is_a_page(other), "{other}");
        }
    }
}
