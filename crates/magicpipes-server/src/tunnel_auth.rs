//! Signed codes and cookies that let a signed-in user into a private tunnel's hostname, shared
//! by the management listener (which issues codes) and the data plane (which turns a code into
//! a cookie and checks the cookie on every request).
//!
//! The management cookie never leaves the management host, so a tunnel host gets its own:
//!
//! 1. The tunnel host sets `__Host-mp_state` (a nonce) and sends the browser to
//!    `/auth/tunnel?host=…&state=…` on the management host.
//! 2. There, a signed-in user who may connect gets a code, valid for 60 s and bound to the host
//!    and the nonce, and is sent to `https://<host>/.magicpipes/callback?code=…`.
//! 3. The tunnel host accepts the code once, only with the matching state cookie, and sets
//!    `__Host-mp_tunnel`: the user and host, signed, until the session's maximum age.
//!
//! Every request then rechecks the cookie against the current users and tags, so revoking access
//! takes effect at once. Tokens are `kind~user~host~nonce~issued~expires~hmac` with an
//! HMAC-SHA256 over the rest, keyed by `data_dir/session-key` (0600, created on first start).

use std::path::Path;

use hmac::{KeyInit, Mac};
use magicpipes_core::{secret, unix_now};
use sha2::Sha256;

pub const TUNNEL_COOKIE: &str = "__Host-mp_tunnel";
pub const STATE_COOKIE: &str = "__Host-mp_state";
/// Paths on every private tunnel host that MagicPipes answers itself.
pub const CALLBACK_PATH: &str = "/.magicpipes/callback";
pub const LOGOUT_PATH: &str = "/.magicpipes/logout";
pub const CODE_TTL_SECS: i64 = 60;

#[derive(Clone)]
pub struct Signer {
    key: Vec<u8>,
}

/// What a valid token says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    pub user_id: String,
    pub nonce: String,
    pub issued_at: i64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Code,
    Cookie,
}

impl Kind {
    fn tag(self) -> &'static str {
        match self {
            Kind::Code => "c",
            Kind::Cookie => "t",
        }
    }
}

impl Signer {
    /// Reads `data_dir/session-key`, creating it on first start.
    pub fn load_or_create(data_dir: &Path) -> anyhow::Result<Self> {
        let path = data_dir.join("session-key");
        let key = match std::fs::read_to_string(&path) {
            Ok(k) => k.trim().to_string(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let k = secret::random_string(64);
                crate::certs::write_private(&path, format!("{k}\n").as_bytes())?;
                k
            }
            Err(e) => return Err(anyhow::anyhow!("reading {}: {e}", path.display())),
        };
        anyhow::ensure!(key.len() >= 32, "{} is too short; delete it to create a new one", path.display());
        Ok(Self { key: key.into_bytes() })
    }

    #[cfg(test)]
    pub fn for_tests() -> Self {
        Self { key: secret::random_string(64).into_bytes() }
    }

    fn mac(&self, payload: &str) -> String {
        let mut m = <hmac::Hmac<Sha256> as KeyInit>::new_from_slice(&self.key).expect("HMAC takes any key length");
        m.update(payload.as_bytes());
        m.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }

    fn issue(&self, kind: Kind, user_id: &str, host: &str, nonce: &str, ttl_secs: i64) -> String {
        let now = unix_now();
        let payload = format!("{}~{user_id}~{host}~{nonce}~{now}~{}", kind.tag(), now + ttl_secs);
        let mac = self.mac(&payload);
        format!("{payload}~{mac}")
    }

    /// A one-time code for `host`, bound to the browser's state nonce.
    pub fn code(&self, user_id: &str, host: &str, nonce: &str) -> String {
        self.issue(Kind::Code, user_id, host, nonce, CODE_TTL_SECS)
    }

    /// The cookie for `host`.
    pub fn cookie(&self, user_id: &str, host: &str, ttl_secs: i64) -> String {
        self.issue(Kind::Cookie, user_id, host, "-", ttl_secs)
    }

    fn verify(&self, kind: Kind, token: &str, host: &str) -> Option<Claims> {
        let (payload, mac) = token.rsplit_once('~')?;
        if !secret::constant_time_eq(self.mac(payload).as_bytes(), mac.as_bytes()) {
            return None;
        }
        let parts: Vec<&str> = payload.split('~').collect();
        let [k, user, h, nonce, issued, expires] = parts.as_slice() else { return None };
        let (issued, expires): (i64, i64) = (issued.parse().ok()?, expires.parse().ok()?);
        let ok = *k == kind.tag() && h.eq_ignore_ascii_case(host) && expires >= unix_now() && user.starts_with("us_");
        ok.then(|| Claims { user_id: user.to_string(), nonce: nonce.to_string(), issued_at: issued })
    }

    pub fn verify_code(&self, token: &str, host: &str) -> Option<Claims> {
        self.verify(Kind::Code, token, host)
    }

    pub fn verify_cookie(&self, token: &str, host: &str) -> Option<Claims> {
        self.verify(Kind::Cookie, token, host)
    }
}

/// A user id or nonce safe to put in a token.
pub fn token_safe(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_bound_to_kind_host_and_key() {
        let s = Signer::for_tests();
        let code = s.code("us_ann", "app.t.test", "nonce1");
        let c = s.verify_code(&code, "APP.t.test").unwrap();
        assert_eq!((c.user_id.as_str(), c.nonce.as_str()), ("us_ann", "nonce1"));
        assert!(s.verify_code(&code, "other.t.test").is_none(), "another host");
        assert!(s.verify_cookie(&code, "app.t.test").is_none(), "a code is not a cookie");
        assert!(Signer::for_tests().verify_code(&code, "app.t.test").is_none(), "another key");
        let forged = code.replace("us_ann", "us_bob");
        assert!(s.verify_code(&forged, "app.t.test").is_none(), "tampered");
        let expired = s.issue(Kind::Cookie, "us_ann", "app.t.test", "-", -1);
        assert!(s.verify_cookie(&expired, "app.t.test").is_none());
        let cookie = s.cookie("us_ann", "app.t.test", 3600);
        assert_eq!(s.verify_cookie(&cookie, "app.t.test").unwrap().user_id, "us_ann");
        assert!(s.verify_cookie("garbage", "app.t.test").is_none());
        assert!(token_safe("us_Ab1-x") && !token_safe("a~b") && !token_safe(""));
    }

    #[test]
    fn the_key_survives_restarts() {
        let dir = std::env::temp_dir().join(format!("mp-key-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let a = Signer::load_or_create(&dir).unwrap();
        let b = Signer::load_or_create(&dir).unwrap();
        assert!(b.verify_cookie(&a.cookie("us_x", "h.t", 60), "h.t").is_some());
        std::fs::remove_dir_all(dir).ok();
    }
}
