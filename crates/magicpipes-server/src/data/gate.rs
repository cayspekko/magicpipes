//! Signing in to private tunnels on their own hostnames (see [`crate::tunnel_auth`]).
//!
//! For a private route, [`check`] answers the reserved `/.magicpipes/` paths itself, admits a
//! request whose tunnel cookie names a user who may connect now, and otherwise sends a browser
//! to sign in (or answers `401 unauthenticated` to anything that isn't a browser navigation). A
//! signed-in user without access gets `403 forbidden`. Nothing here touches the database.

#![allow(clippy::result_large_err)] // responses are returned by value, as in `proxy`

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::ERROR_HEADER;
use magicpipes_core::{secret, unix_now};

use super::proxy::{ProxyBody, error_page};
use super::{DataPlane, Route, RouteTable, TunnelUser};
use crate::authz::{self, Action, Resource};
use crate::tunnel_auth::{CALLBACK_PATH, LOGOUT_PATH, STATE_COOKIE, TUNNEL_COOKIE, token_safe};

/// The value of cookie `name` in a request.
fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

/// Removes MagicPipes' own cookies before a request reaches the tunnel's application.
pub(super) fn strip_cookies(headers: &mut HeaderMap) {
    let kept: Vec<String> = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .map(str::trim)
        .filter(|kv| !kv.is_empty() && !kv.starts_with(&format!("{TUNNEL_COOKIE}=")) && !kv.starts_with(&format!("{STATE_COOKIE}=")))
        .map(str::to_string)
        .collect();
    headers.remove(header::COOKIE);
    if !kept.is_empty()
        && let Ok(v) = HeaderValue::from_str(&kept.join("; "))
    {
        headers.insert(header::COOKIE, v);
    }
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').filter_map(|kv| kv.split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| percent_decode(v))
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = b.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok()).and_then(|h| u8::from_str_radix(h, 16).ok());
        match (b[i], hex) {
            (b'%', Some(v)) => {
                out.push(v);
                i += 3;
            }
            (b'+', _) => {
                out.push(b' ');
                i += 1;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(super) fn percent_encode(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// A path to send the browser back to: on this host, never `//other` or a scheme.
fn safe_return(path: Option<String>) -> String {
    path.filter(|p| p.starts_with('/') && !p.starts_with("//") && !p.contains('\\') && p.len() < 2048 && !p.chars().any(char::is_control))
        .unwrap_or_else(|| "/".to_string())
}

fn set_cookie(resp: &mut Response<ProxyBody>, name: &str, value: &str, max_age: i64) {
    let c = format!("{name}={value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age}");
    if let Ok(v) = HeaderValue::from_str(&c) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
}

fn redirect(to: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, to)
        .header(header::CACHE_CONTROL, "no-store")
        .header(ERROR_HEADER, ErrorCode::Unauthenticated.as_str())
        .body(Full::new(Bytes::new()).map_err(|never| match never {}).boxed())
        .unwrap_or_else(|_| error_page(ErrorCode::BadUri, "Invalid address."))
}

/// A browser navigating to a page, which can be sent to sign in; anything else gets a 401.
fn is_navigation(req: &Request<Incoming>) -> bool {
    let accept = req.headers().get(header::ACCEPT).and_then(|v| v.to_str().ok()).unwrap_or("");
    matches!(*req.method(), Method::GET | Method::HEAD) && accept.contains("text/html")
}

/// A request admitted to a private tunnel: the user, and when their cookie was issued.
pub(super) struct Admitted {
    pub user: TunnelUser,
    pub user_id: String,
    pub issued_at: i64,
}

/// The user a request's tunnel cookie stands for, if it is valid and current.
fn cookie_user<'a>(dp: &DataPlane, table: &'a RouteTable, headers: &HeaderMap, host: &str) -> Option<(&'a TunnelUser, String, i64)> {
    let claims = dp.signer().verify_cookie(cookie(headers, TUNNEL_COOKIE)?, host)?;
    let user = table.users.get(&claims.user_id).filter(|u| claims.issued_at >= u.valid_after)?;
    Some((user, claims.user_id, claims.issued_at))
}

fn may_connect(route: &Route, user: &TunnelUser) -> bool {
    authz::authorize(&user.principal, Action::Connect, Resource::Tunnel(&route.access.authz))
}

/// Whether an admitted user may still use the tunnel at `host` in the current table (for
/// long-lived connections after a change).
pub(super) fn still_admitted(table: &RouteTable, host: &str, user_id: &str, issued_at: i64) -> bool {
    match (table.by_host.get(host), table.users.get(user_id)) {
        (Some(route), Some(user)) => issued_at >= user.valid_after && may_connect(route, user),
        _ => false,
    }
}

/// Outcome for a request to a private tunnel: who it is forwarded as, or the response MagicPipes
/// gives instead.
pub(super) fn check(dp: &DataPlane, req: &Request<Incoming>, host: &str, route: &Route) -> Result<Admitted, Response<ProxyBody>> {
    let path = req.uri().path();
    let query = req.uri().query().unwrap_or("");
    if path == CALLBACK_PATH {
        return Err(callback(dp, req.headers(), query, host));
    }
    if path == LOGOUT_PATH {
        let mut resp = error_page(ErrorCode::Unauthenticated, "You are signed out of this tunnel.");
        *resp.status_mut() = StatusCode::OK;
        set_cookie(&mut resp, TUNNEL_COOKIE, "", 0);
        return Err(resp);
    }
    let table = dp.table();
    if let Some((user, user_id, issued_at)) = cookie_user(dp, &table, req.headers(), host) {
        if may_connect(route, user) {
            return Ok(Admitted { user: user.clone(), user_id, issued_at });
        }
        let msg = format!(
            "You're signed in as {}, but you don't have access to {host}. Ask its owner or an administrator.",
            user.email
        );
        let mut resp = error_page(ErrorCode::Forbidden, &msg);
        // A way to sign in as someone else.
        set_cookie(&mut resp, TUNNEL_COOKIE, "", 0);
        return Err(resp);
    }
    if !is_navigation(req) {
        return Err(error_page(ErrorCode::Unauthenticated, "Sign in to use this tunnel."));
    }
    let nonce = secret::random_string(24);
    let back = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let to = format!(
        "{}/auth/tunnel?host={}&state={nonce}&return={}",
        dp.settings.management_url,
        percent_encode(host),
        percent_encode(back)
    );
    let mut resp = redirect(&to);
    set_cookie(&mut resp, STATE_COOKIE, &nonce, 600);
    Err(resp)
}

/// `/.magicpipes/callback?code=…&return=…`: turns a sign-in code into the tunnel cookie.
fn callback(dp: &DataPlane, headers: &HeaderMap, query: &str, host: &str) -> Response<ProxyBody> {
    let bad = || error_page(ErrorCode::Unauthenticated, "This sign-in link is invalid or has expired. Open the tunnel's address again.");
    let Some(claims) = query_param(query, "code").and_then(|c| dp.signer().verify_code(&c, host)) else { return bad() };
    // Only the browser that started the sign-in may finish it, and only once.
    let state = cookie(headers, STATE_COOKIE).filter(|s| token_safe(s));
    if state != Some(claims.nonce.as_str()) || claims.issued_at > unix_now() + 5 || !dp.use_code(&claims.nonce) {
        return bad();
    }
    let mut resp = redirect(&safe_return(query_param(query, "return")));
    resp.headers_mut().remove(ERROR_HEADER);
    let ttl = dp.settings.tunnel_cookie_ttl_secs;
    set_cookie(&mut resp, TUNNEL_COOKIE, &dp.signer().cookie(&claims.user_id, host, ttl), ttl);
    set_cookie(&mut resp, STATE_COOKIE, "", 0);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies_and_return_paths() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("a=1; __Host-mp_tunnel=secret; b=2"));
        h.append(header::COOKIE, HeaderValue::from_static("__Host-mp_state=n"));
        assert_eq!(cookie(&h, TUNNEL_COOKIE), Some("secret"));
        strip_cookies(&mut h);
        assert_eq!(h.get(header::COOKIE).unwrap(), "a=1; b=2");
        let mut only_ours = HeaderMap::new();
        only_ours.insert(header::COOKIE, HeaderValue::from_static("__Host-mp_tunnel=x"));
        strip_cookies(&mut only_ours);
        assert!(only_ours.get(header::COOKIE).is_none());

        assert_eq!(safe_return(Some("/a?b=c".into())), "/a?b=c");
        for bad in ["//evil.example/", "https://evil.example/", "/\\evil", "", "a"] {
            assert_eq!(safe_return(Some(bad.into())), "/", "{bad}");
        }
        assert_eq!(query_param("x=1&return=%2Fa%3Fb%3Dc", "return").as_deref(), Some("/a?b=c"));
        assert_eq!(percent_decode(&percent_encode("/p?q=1 2&r")), "/p?q=1 2&r");
    }
}
