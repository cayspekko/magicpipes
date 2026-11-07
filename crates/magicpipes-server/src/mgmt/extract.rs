//! Who a UI request comes from, and what it may do. A handler says what it needs in its signature,
//! so a check can't be forgotten: [`UiUser`] to look, [`AdminUser`] to look at what only
//! administrators see, [`Posted`] and [`AdminPosted`] to change something.

use axum::extract::{FromRequest, FromRequestParts, RawForm, Request};
use axum::response::{IntoResponse, Redirect, Response};
use http::StatusCode;
use http::request::Parts;
use magicpipes_core::url;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::html::esc;
use super::ui::{Done, failed, page};
use super::{AppState, SESSION_COOKIE};
use crate::authz::Principal;
use crate::control::UserView;
use crate::tunnel_auth::cookie;

/// How someone gets out of a session.
pub(super) enum SignOut {
    Here,
    /// At the authenticating proxy that signed them in, at this address.
    AtProxy(String),
    /// At the authenticating proxy, at an address nobody configured. A session ended here would
    /// only start again at the next request.
    AtProxyElsewhere,
}

/// A signed-in UI session. Redirects to the sign-in page otherwise, and to the password page while
/// the user still has to replace a password an administrator set.
pub struct UiUser {
    pub(super) cookie: String,
    pub(super) who: Principal,
    pub(super) csrf: String,
    /// `None` for an admin-token session.
    pub(super) user: Option<UserView>,
    /// The address, for marking the current page.
    pub(super) path: String,
    /// What a change just did, from the address.
    pub(super) done: Option<&'static str>,
    pub(super) sign_out: SignOut,
}

impl FromRequestParts<AppState> for UiUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, app: &AppState) -> Result<Self, Self::Rejection> {
        // After signing in, the browser comes back to the page it asked for.
        let here = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let back = |to: &str| match here {
            "/" => Redirect::to(to).into_response(),
            _ => Redirect::to(&format!("{to}?next={}", url::encode(here))).into_response(),
        };
        let cookie = cookie(&parts.headers, SESSION_COOKIE).ok_or_else(|| back("/login"))?;
        let s = app.control.session(cookie).ok_or_else(|| back("/login"))?;
        let must_change = s.user.as_ref().is_some_and(|u| u.must_change_password);
        if must_change && !matches!(parts.uri.path(), "/password" | "/logout") {
            return Err(back("/password"));
        }
        let sign_out = match app.control.proxy_auth().filter(|_| s.user.is_some()) {
            None => SignOut::Here,
            Some(proxy) => proxy.sign_out_url.clone().map_or(SignOut::AtProxyElsewhere, SignOut::AtProxy),
        };
        Ok(UiUser {
            cookie: cookie.to_string(),
            who: s.who,
            csrf: s.csrf,
            user: s.user,
            sign_out,
            path: parts.uri.path().to_string(),
            done: Done::from_query(parts.uri.query()),
        })
    }
}

impl UiUser {
    /// The hidden field every form that changes something carries.
    pub(super) fn csrf_field(&self) -> String {
        format!(r#"<input type="hidden" name="csrf" value="{}">"#, esc(&self.csrf))
    }

    /// Did an authenticating proxy sign them in, so that its sessions and passwords aren't theirs to
    /// manage here?
    pub(super) fn through_proxy(&self) -> bool {
        !matches!(self.sign_out, SignOut::Here)
    }

    /// `self` if an administrator; anyone else goes to their own account page.
    #[allow(clippy::result_large_err)] // responses are returned by value on purpose
    fn admin_or_elsewhere(self) -> Result<Self, Response> {
        if self.who.is_admin() { Ok(self) } else { Err(Redirect::to("/account").into_response()) }
    }
}

/// A session of an administrator.
pub struct AdminUser(pub UiUser);

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, app: &AppState) -> Result<Self, Self::Rejection> {
        UiUser::from_request_parts(parts, app).await?.admin_or_elsewhere().map(AdminUser)
    }
}

#[derive(Deserialize, Default)]
struct CsrfField {
    #[serde(default)]
    csrf: String,
}

/// A form with nothing in it but the CSRF token.
#[derive(Deserialize)]
pub struct NoFields {}

/// A form's fields in order, for one that repeats a name.
pub type Fields = Vec<(String, String)>;

/// A form submitted from one of this user's pages, with its CSRF token checked. A token that is
/// missing, wrong or given twice never reaches the handler.
pub struct Posted<T>(pub UiUser, pub T);

impl<T: DeserializeOwned> FromRequest<AppState> for Posted<T> {
    type Rejection = Response;

    async fn from_request(req: Request, app: &AppState) -> Result<Self, Self::Rejection> {
        let (mut parts, body) = req.into_parts();
        let user = UiUser::from_request_parts(&mut parts, app).await?;
        let RawForm(raw) = RawForm::from_request(Request::from_parts(parts, body), app).await.map_err(IntoResponse::into_response)?;
        let token: CsrfField = serde_urlencoded::from_bytes(&raw).unwrap_or_default();
        if !magicpipes_core::secret::constant_time_eq(user.csrf.as_bytes(), token.csrf.as_bytes()) {
            let body = r#"<div class="auth"><h1>This page <em>expired</em></h1><p class="lede">Nothing was changed. Go back, reload the page and try again.</p></div>"#;
            return Err((StatusCode::FORBIDDEN, page("Page expired", Some(&user), body)).into_response());
        }
        match serde_urlencoded::from_bytes(&raw) {
            Ok(form) => Ok(Posted(user, form)),
            Err(_) => Err(failed(&user, StatusCode::BAD_REQUEST, "/", "Tunnels", "Nothing was changed: that form was incomplete. Go back, reload the page and try again.")),
        }
    }
}

/// As [`Posted`], from an administrator.
pub struct AdminPosted<T>(pub UiUser, pub T);

impl<T: DeserializeOwned> FromRequest<AppState> for AdminPosted<T> {
    type Rejection = Response;

    async fn from_request(req: Request, app: &AppState) -> Result<Self, Self::Rejection> {
        let Posted(user, form) = Posted::from_request(req, app).await?;
        Ok(AdminPosted(user.admin_or_elsewhere()?, form))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_form_is_read_as_the_extractor_reads_it() {
        #[derive(Deserialize, Debug, PartialEq)]
        struct Form {
            name: String,
            kept: Option<String>,
        }
        let read = |s: &str| serde_urlencoded::from_bytes::<CsrfField>(s.as_bytes()).unwrap_or_default().csrf;
        assert_eq!(read("csrf=abc&name=x"), "abc");
        assert_eq!(read("name=x"), "", "no token");
        assert_eq!(read("csrf=abc&csrf=abc"), "", "a token given twice is no token");
        assert_eq!(read("name=x&tag=a&tag=b&csrf=abc"), "abc", "other names may repeat");

        // The token is one more field to the form it came with, and a form can ask for nothing.
        let form = serde_urlencoded::from_bytes::<Form>(b"csrf=abc&name=a+b%21").unwrap();
        assert_eq!(form, Form { name: "a b!".into(), kept: None });
        assert!(serde_urlencoded::from_bytes::<NoFields>(b"csrf=abc&x=y").is_ok());
        assert!(serde_urlencoded::from_bytes::<Form>(b"csrf=abc").is_err(), "a field it needs is missing");

        let fields = serde_urlencoded::from_bytes::<Fields>(b"tag=a&tag=b&csrf=c").unwrap();
        assert_eq!(fields.iter().filter(|(k, _)| k == "tag").count(), 2);
    }
}
