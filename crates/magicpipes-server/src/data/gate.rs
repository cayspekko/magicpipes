//! Signing in to private tunnels on their own hostnames (see [`crate::tunnel_auth`]).
//!
//! For a private route, [`reserved`] answers the `/.magicpipes/` paths itself, and [`check`]
//! admits a request whose tunnel cookie names a user who may connect now, and otherwise sends a
//! browser to sign in (or answers `401 unauthenticated` to anything that isn't a browser
//! navigation). A signed-in user without access gets `403 forbidden`. Nothing here touches the
//! database.

#![allow(clippy::result_large_err)] // responses are returned by value, as in `proxy`

use std::net::IpAddr;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::ERROR_HEADER;
use magicpipes_core::{secret, unix_now, url};

use super::proxy::{ProxyBody, error_page};
use super::{DataPlane, Route, RouteTable, TunnelUser};
use crate::authz::{self, Action, Principal, Resource};
use crate::tunnel_auth::{CALLBACK_PATH, CALLBACK_SCRIPT_PATH, LOGOUT_PATH, RESERVED_PREFIX, STATE_COOKIE, TUNNEL_COOKIE, cookie, safe_path, token_safe};

/// Largest body the code exchange accepts.
const MAX_EXCHANGE_BODY: usize = 4096;
const EXCHANGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The state cookie of one sign-in attempt. Each attempt has its own, so tabs that sign in at
/// the same time don't overwrite each other's.
fn state_cookie(nonce: &str) -> String {
    format!("{STATE_COOKIE}{nonce}")
}

/// Removes MagicPipes' own cookies before a request reaches the tunnel's application. A request
/// without any keeps its headers as they came. Works on bytes: another cookie that isn't valid
/// text must not hide ours.
pub(super) fn strip_cookies(headers: &mut HeaderMap) {
    let ours = |kv: &[u8]| (kv.starts_with(TUNNEL_COOKIE.as_bytes()) && kv.get(TUNNEL_COOKIE.len()) == Some(&b'=')) || kv.starts_with(STATE_COOKIE.as_bytes());
    let cookies = |h: &HeaderMap| -> Vec<Vec<u8>> {
        h.get_all(header::COOKIE).iter().flat_map(|v| v.as_bytes().split(|b| *b == b';')).map(|kv| kv.trim_ascii().to_vec()).collect()
    };
    let all = cookies(headers);
    if !all.iter().any(|kv| ours(kv)) {
        return;
    }
    let kept: Vec<Vec<u8>> = all.into_iter().filter(|kv| !kv.is_empty() && !ours(kv)).collect();
    headers.remove(header::COOKIE);
    if !kept.is_empty()
        && let Ok(v) = HeaderValue::from_bytes(&kept.join(&b"; "[..]))
    {
        headers.insert(header::COOKIE, v);
    }
}

/// Takes `Domain` off an application's cookies where it would reach beyond its own tunnel, to other
/// tunnels and the management host (`shared`). The cookie then belongs to the tunnel's hostname.
/// A custom hostname's own domain, or its own hostname, is left alone.
pub(super) fn keep_cookies_to_the_tunnel(headers: &mut HeaderMap, shared: &[String]) {
    if shared.is_empty() || !headers.contains_key(header::SET_COOKIE) {
        return;
    }
    let cleaned: Vec<HeaderValue> = headers.get_all(header::SET_COOKIE).iter().map(|c| without_shared_domain(c, shared)).collect();
    headers.remove(header::SET_COOKIE);
    for cookie in cleaned {
        headers.append(header::SET_COOKIE, cookie);
    }
}

fn without_shared_domain(cookie: &HeaderValue, shared: &[String]) -> HeaderValue {
    let reaches_shared = |attribute: &[u8]| {
        let mut parts = attribute.splitn(2, |b| *b == b'=');
        let (Some(name), Some(value)) = (parts.next(), parts.next()) else { return false };
        if !name.trim_ascii().eq_ignore_ascii_case(b"domain") {
            return false;
        }
        let value = String::from_utf8_lossy(value).trim().trim_matches('.').to_ascii_lowercase();
        !value.is_empty() && shared.iter().any(|host| *host == value || host.ends_with(&format!(".{value}")))
    };
    // The first part is the cookie's name and value, even if it's called `domain`.
    let parts: Vec<&[u8]> = cookie.as_bytes().split(|b| *b == b';').collect();
    if !parts.iter().skip(1).any(|a| reaches_shared(a)) {
        return cookie.clone();
    }
    let kept: Vec<&[u8]> = parts.iter().enumerate().filter(|(i, a)| *i == 0 || !reaches_shared(a)).map(|(_, a)| a.trim_ascii()).collect();
    HeaderValue::from_bytes(&kept.join(&b"; "[..])).unwrap_or_else(|_| cookie.clone())
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').filter_map(|kv| kv.split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| url::decode_form(v))
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

/// Whether a long-lived connection to `tunnel` may go on in the current table: `who` is the user
/// admitted to it, or `None` for an anonymous client of a public tunnel.
pub(super) fn still_admitted(table: &RouteTable, host: &str, tunnel: &str, who: Option<&Admitted>, client: IpAddr) -> bool {
    let Some(route) = table.by_host.get(host).filter(|r| r.tunnel_id == tunnel) else { return false };
    match who {
        None => route.access.admits(&Principal::Anonymous, client),
        Some(a) => table.users.get(&a.user_id).is_some_and(|user| a.issued_at >= user.valid_after && may_connect(route, user)),
    }
}

/// Outcome for a request to a private tunnel: who it is forwarded as, or the response MagicPipes
/// gives instead.
pub(super) fn check(dp: &DataPlane, req: &Request<Incoming>, host: &str, route: &Route) -> Result<Admitted, Response<ProxyBody>> {
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
        url::encode(host),
        url::encode(back)
    );
    let mut resp = redirect(&to);
    set_cookie(&mut resp, &state_cookie(&nonce), "1", 600);
    Err(resp)
}

/// The `/.magicpipes/` paths of a private tunnel host, which MagicPipes answers itself:
///
/// * `GET /.magicpipes/callback#code=…&return=…`: where the management host sends a browser
///   after sign-in. The code is in the fragment, so it never reaches a server, a log or the
///   history; the page's script clears it and posts it back to this host.
/// * `POST /.magicpipes/callback`: exchanges the code for the tunnel cookie.
/// * `/.magicpipes/logout`: forgets the tunnel cookie.
pub(super) async fn reserved(dp: &DataPlane, req: Request<Incoming>, host: &str) -> Response<ProxyBody> {
    match (req.method().clone(), req.uri().path()) {
        (Method::GET | Method::HEAD, CALLBACK_PATH) => callback_page(),
        (Method::GET | Method::HEAD, CALLBACK_SCRIPT_PATH) => callback_script(),
        (Method::POST, CALLBACK_PATH) => exchange(dp, req, host).await,
        (_, LOGOUT_PATH) => {
            let mut resp = error_page(ErrorCode::Unauthenticated, "You are signed out of this tunnel.");
            *resp.status_mut() = StatusCode::OK;
            set_cookie(&mut resp, TUNNEL_COOKIE, "", 0);
            resp
        }
        (_, path) => {
            debug_assert!(path.starts_with(RESERVED_PREFIX));
            error_page(ErrorCode::NotFound, "There is nothing here.")
        }
    }
}

/// Our own pages on a tunnel host: only our script, and requests back to this host.
fn own_page(content_type: &'static str, body: &'static str) -> Response<ProxyBody> {
    Response::builder()
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        )
        .body(Full::new(Bytes::from_static(body.as_bytes())).map_err(|never| match never {}).boxed())
        .unwrap_or_else(|_| error_page(ErrorCode::Internal, "Something went wrong."))
}

fn callback_page() -> Response<ProxyBody> {
    own_page(
        "text/html; charset=utf-8",
        concat!(
            r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>Signing in…</title><script src="/.magicpipes/callback.js" defer></script><style>"#,
            magicpipes_core::theme_palette!(),
            r#"body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--ink);font:15px/1.55 var(--sans)}main{padding:24px 16px;max-width:30em}</style></head>
<body><main><p id="msg">Signing you in…</p><noscript><p>Signing in to a private tunnel needs JavaScript.</p></noscript></main></body></html>"#,
        ),
    )
}

fn callback_script() -> Response<ProxyBody> {
    own_page(
        "text/javascript; charset=utf-8",
        r#"(() => {
  const params = new URLSearchParams(location.hash.slice(1));
  // The code is single-use; keep it out of the history either way.
  history.replaceState(null, "", location.pathname);
  const say = (m) => { document.getElementById("msg").textContent = m; };
  const again = "This sign-in link is invalid or has expired. Open the tunnel's address again.";
  if (!params.get("code")) { say(again); return; }
  fetch("/.magicpipes/callback", {
    method: "POST",
    credentials: "same-origin",
    body: new URLSearchParams({ code: params.get("code"), return: params.get("return") || "/" }),
  })
    .then(async (r) => {
      const d = await r.json().catch(() => ({}));
      if (r.ok && typeof d.to === "string" && d.to.startsWith("/")) location.replace(d.to);
      else say((d.error && d.error.message) || again);
    })
    .catch(() => say("Couldn't finish signing in. Reload the page to try again."));
})();
"#,
    )
}

fn json(status: StatusCode, value: &serde_json::Value) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::from(value.to_string())).map_err(|never| match never {}).boxed())
        .unwrap_or_else(|_| error_page(ErrorCode::Internal, "Something went wrong."))
}

/// `POST /.magicpipes/callback` with `code` and `return`: the browser that started the sign-in
/// (its state cookie matches the code's nonce) gets the tunnel cookie, once.
async fn exchange(dp: &DataPlane, req: Request<Incoming>, host: &str) -> Response<ProxyBody> {
    let bad = |message: &str| {
        let mut resp = json(StatusCode::UNAUTHORIZED, &serde_json::json!({ "error": { "code": ErrorCode::Unauthenticated.as_str(), "message": message } }));
        if let Ok(v) = HeaderValue::from_str(ErrorCode::Unauthenticated.as_str()) {
            resp.headers_mut().insert(ERROR_HEADER, v);
        }
        resp
    };
    let expired = "This sign-in link is invalid or has expired. Open the tunnel's address again.";
    let headers = req.headers().clone();
    let body = http_body_util::Limited::new(req.into_body(), MAX_EXCHANGE_BODY);
    let body = match tokio::time::timeout(EXCHANGE_TIMEOUT, body.collect()).await {
        Ok(Ok(b)) => b.to_bytes(),
        _ => return bad("The sign-in request was incomplete. Reload the page to try again."),
    };
    let form = String::from_utf8_lossy(&body);
    let Some(claims) = query_param(&form, "code").and_then(|c| dp.signer().verify_code(&c, host)) else { return bad(expired) };
    let state = state_cookie(&claims.nonce);
    let started_here = token_safe(&claims.nonce) && cookie(&headers, &state).is_some();
    // Only the browser that started the sign-in may finish it, and only once.
    if !started_here || claims.issued_at > unix_now() + 5 || !dp.use_code(&claims.user_id, &claims.nonce) {
        return bad(expired);
    }
    let back = query_param(&form, "return");
    let mut resp = json(StatusCode::OK, &serde_json::json!({ "to": safe_path(back.as_deref()).unwrap_or("/") }));
    let ttl = dp.settings.tunnel_cookie_ttl_secs;
    set_cookie(&mut resp, TUNNEL_COOKIE, &dp.signer().cookie(&claims.user_id, host, ttl), ttl);
    set_cookie(&mut resp, &state, "", 0);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies_and_query_values() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("a=1; __Host-mp_tunnel=secret; b=2"));
        h.append(header::COOKIE, HeaderValue::from_static("__Host-mp_state_n1=1; __Host-mp_state_n2=1"));
        assert_eq!(cookie(&h, TUNNEL_COOKIE), Some("secret"));
        strip_cookies(&mut h);
        assert_eq!(h.get(header::COOKIE).unwrap(), "a=1; b=2");
        let mut only_ours = HeaderMap::new();
        only_ours.insert(header::COOKIE, HeaderValue::from_static("__Host-mp_tunnel=x"));
        strip_cookies(&mut only_ours);
        assert!(only_ours.get(header::COOKIE).is_none());
        // Another cookie that isn't valid text doesn't hide ours, and stays as it was.
        let mut odd = HeaderMap::new();
        odd.insert(header::COOKIE, HeaderValue::from_bytes(b"caf\xc3\xa9=1; __Host-mp_tunnel=secret").unwrap());
        strip_cookies(&mut odd);
        assert_eq!(odd.get(header::COOKIE).unwrap().as_bytes(), b"caf\xc3\xa9=1");
        // Without any of ours, a request's cookies are left exactly as they came.
        let mut theirs = HeaderMap::new();
        theirs.append(header::COOKIE, HeaderValue::from_static("a=1"));
        theirs.append(header::COOKIE, HeaderValue::from_static("__Host-mp_tunnel_x=2;b=3"));
        strip_cookies(&mut theirs);
        assert_eq!(theirs.get_all(header::COOKIE).iter().count(), 2);

        assert_eq!(query_param("x=1&return=%2Fa%3Fb%3Dc", "return").as_deref(), Some("/a?b=c"));
    }

    #[test]
    fn cookies_stay_on_their_tunnel() {
        let shared = ["t.example.com".to_string(), "example.com".to_string()];
        let clean = |cookie: &'static str| {
            let mut h = HeaderMap::new();
            h.append(header::SET_COOKIE, HeaderValue::from_static(cookie));
            keep_cookies_to_the_tunnel(&mut h, &shared);
            h.get(header::SET_COOKIE).unwrap().to_str().unwrap().to_string()
        };
        // The base domain, the management host, and anything above them.
        assert_eq!(clean("a=1; Path=/; Domain=t.example.com; HttpOnly"), "a=1; Path=/; HttpOnly");
        assert_eq!(clean("a=1; domain=.T.Example.Com"), "a=1");
        assert_eq!(clean("a=1;DOMAIN = example.com ;Secure"), "a=1; Secure");
        assert_eq!(clean("a=1; Domain=com"), "a=1");
        // Its own hostname, or a custom hostname's own domain, reach nothing shared.
        for kept in ["a=1; Domain=app.t.example.com", "a=1; Domain=shop.example.org", "a=1; Path=/", "domain=example.com"] {
            assert_eq!(clean(kept), kept);
        }

        // Several cookies stay several.
        let mut h = HeaderMap::new();
        h.append(header::SET_COOKIE, HeaderValue::from_static("a=1; Domain=example.com"));
        h.append(header::SET_COOKIE, HeaderValue::from_static("b=2"));
        keep_cookies_to_the_tunnel(&mut h, &shared);
        assert_eq!(h.get_all(header::SET_COOKIE).iter().map(|v| v.to_str().unwrap()).collect::<Vec<_>>(), ["a=1", "b=2"]);

        // `public.allow_cookie_domain`.
        let mut h = HeaderMap::new();
        h.append(header::SET_COOKIE, HeaderValue::from_static("a=1; Domain=example.com"));
        keep_cookies_to_the_tunnel(&mut h, &[]);
        assert_eq!(h.get(header::SET_COOKIE).unwrap(), "a=1; Domain=example.com");
    }

    #[test]
    fn one_user_cannot_use_up_sign_ins() {
        let cfg: crate::config::Config =
            toml::from_str("base_domain = \"t.test\"\n[management]\nhostname = \"m.t.test\"\n[tls]\nmode = \"dev-ca\"").unwrap();
        let settings = super::super::ProxySettings::from_config(&cfg, crate::tunnel_auth::Signer::for_tests());
        let dp = DataPlane::new(settings, tokio_util::sync::CancellationToken::new());
        assert!(dp.use_code("us_a", "n0"));
        assert!(!dp.use_code("us_a", "n0"), "a code works once");
        let mut taken = 1;
        while dp.use_code("us_a", &format!("n{taken}")) {
            taken += 1;
        }
        assert!(taken < 100, "each user has a bounded share");
        assert!(dp.use_code("us_b", "n0"), "others still sign in");
    }
}
