//! Signed codes and cookies that let a signed-in user into a private tunnel's hostname, shared
//! by the management listener (which issues codes) and the data plane (which turns a code into
//! a cookie and checks the cookie on every request).
//!
//! The management cookie never leaves the management host, so a tunnel host gets its own:
//!
//! 1. The tunnel host sets `__Host-mp_state_<nonce>` and sends the browser to
//!    `/auth/tunnel?host=…&state=<nonce>` on the management host.
//! 2. There, a signed-in user who may connect gets a code, valid for 60 s and bound to the host
//!    and the nonce, and is sent to `https://<host>/.magicpipes/callback#code=…`. The code is in
//!    the fragment, so no server, log or Referer sees it. Sign-in forms never redirect there
//!    directly: browsers apply `form-action 'self'` to a form's redirects, so the management
//!    host answers a sign-in with a page that moves on by itself.
//! 3. The callback page's script posts the code to its own host, which accepts it once, only
//!    with the matching state cookie, and sets `__Host-mp_tunnel`: the user and host, signed,
//!    until the session's maximum age.
//!
//! Every request then rechecks the cookie against the current users and tags, so revoking access
//! takes effect at once. Tokens are `kind~user~host~nonce~issued~expires~hmac` with an
//! HMAC-SHA256 over the rest, keyed by `data_dir/session-key` (0600, created on first start).
//!
//! `magicpipes connect` holds a third kind, a connect pass: the user, bound to the management
//! host, which the CLI presents for each connection and the data plane checks the same way.

use std::path::Path;

use hmac::{KeyInit, Mac};
use magicpipes_core::{secret, unix_now};
use sha2::Sha256;

pub const TUNNEL_COOKIE: &str = "__Host-mp_tunnel";
/// Prefix of the per-attempt state cookies, `__Host-mp_state_<nonce>`.
pub const STATE_COOKIE: &str = "__Host-mp_state_";
/// Paths on every private tunnel host that MagicPipes answers itself.
pub const RESERVED_PREFIX: &str = "/.magicpipes/";
pub const CALLBACK_PATH: &str = "/.magicpipes/callback";
pub const CALLBACK_SCRIPT_PATH: &str = "/.magicpipes/callback.js";
pub const LOGOUT_PATH: &str = "/.magicpipes/logout";
pub const CODE_TTL_SECS: i64 = 60;
/// The longest path [`safe_path`] accepts. Also what makes a sign-in's destination fit the attempt
/// cookie, which browsers limit to about 4 KiB.
const MAX_PATH: usize = 2048;

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
    Pass,
}

impl Kind {
    fn tag(self) -> &'static str {
        match self {
            Kind::Code => "c",
            Kind::Cookie => "t",
            Kind::Pass => "p",
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

    /// The key for what's kept encrypted at rest, derived so it's never the signing key itself.
    fn sealing_key(&self) -> ring::aead::LessSafeKey {
        use sha2::Digest;
        let derived = Sha256::new().chain_update(b"magicpipes provider tokens\0").chain_update(&self.key).finalize();
        ring::aead::LessSafeKey::new(ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &derived).expect("a 256-bit key"))
    }

    /// Encrypts something kept at rest, such as a provider's tokens for a session (AES-256-GCM,
    /// a random nonce first), so that a copy of the database alone can't use it.
    pub fn encrypt(&self, plain: &[u8]) -> Vec<u8> {
        use ring::rand::SecureRandom;
        let mut nonce = [0u8; ring::aead::NONCE_LEN];
        ring::rand::SystemRandom::new().fill(&mut nonce).expect("the system's randomness");
        let mut sealed = plain.to_vec();
        self.sealing_key()
            .seal_in_place_append_tag(ring::aead::Nonce::assume_unique_for_key(nonce), ring::aead::Aad::from(b"tokens"), &mut sealed)
            .expect("sealing fits in memory");
        [nonce.as_slice(), &sealed].concat()
    }

    /// What [`Self::encrypt`] sealed; `None` if it's been changed, or was sealed with another key.
    pub fn decrypt(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        let (nonce, rest) = sealed.split_at_checked(ring::aead::NONCE_LEN)?;
        let nonce = ring::aead::Nonce::try_assume_unique_for_key(nonce).ok()?;
        let mut buf = rest.to_vec();
        let plain = self.sealing_key().open_in_place(nonce, ring::aead::Aad::from(b"tokens"), &mut buf).ok()?;
        Some(plain.to_vec())
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

    /// `payload`, signed. It must start with its own kind and may not contain anything a cookie
    /// can't hold.
    pub fn seal(&self, payload: &str) -> String {
        format!("{payload}~{}", self.mac(payload))
    }

    /// What [`Signer::seal`] was given, if the signature is good.
    pub fn open<'a>(&self, sealed: &'a str) -> Option<&'a str> {
        let (payload, mac) = sealed.rsplit_once('~')?;
        secret::constant_time_eq(self.mac(payload).as_bytes(), mac.as_bytes()).then_some(payload)
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

    /// A connect pass for `magicpipes connect`, bound to the management host. Each is distinct.
    pub fn pass(&self, user_id: &str, management_host: &str, ttl_secs: i64) -> String {
        self.issue(Kind::Pass, user_id, management_host, &secret::random_string(16), ttl_secs)
    }

    pub fn verify_pass(&self, token: &str, management_host: &str) -> Option<Claims> {
        self.verify(Kind::Pass, token, management_host)
    }
}

/// A user id or nonce safe to put in a token.
pub fn token_safe(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A place to send a browser next, only if it stays on this host: a path, never `//host`, `/\\host`
/// (browsers read that the same way) or a scheme. Browsers drop tabs and newlines before they parse
/// an address, so control characters are out too.
pub fn safe_path(path: Option<&str>) -> Option<&str> {
    path.filter(|p| p.starts_with('/') && !p.starts_with("//") && !p.contains('\\') && p.len() <= MAX_PATH && !p.chars().any(char::is_control))
}

/// The value of cookie `name` in a request.
pub fn cookie<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_is_kept_encrypted_opens_only_unchanged_and_with_its_key() {
        let s = Signer::for_tests();
        let sealed = s.encrypt(b"refresh token");
        assert_eq!(s.decrypt(&sealed).as_deref(), Some(b"refresh token".as_slice()));
        assert_ne!(s.encrypt(b"refresh token"), sealed, "a fresh nonce each time");
        assert!(!sealed.windows(7).any(|w| w == b"refresh"), "not in the clear");
        let mut changed = sealed.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert_eq!(s.decrypt(&changed), None);
        assert_eq!(Signer::for_tests().decrypt(&sealed), None, "another server's key");
        assert_eq!(s.decrypt(&sealed[..5]), None);
    }

    #[test]
    fn a_browser_is_only_sent_to_paths_on_this_host() {
        for ok in ["/", "/a?b=c", "/a/b#c", "/%5Cevil", "/.magicpipes/x"] {
            assert_eq!(safe_path(Some(ok)), Some(ok));
        }
        for bad in ["", "a", "//evil.example/", "https://evil.example/", "/\\evil", "\\\\evil", "/a\\b", "/\t/evil.example", "/a\nb", " /a"] {
            assert_eq!(safe_path(Some(bad)), None, "{bad:?}");
        }
        assert_eq!(safe_path(None), None);
        let at_limit = format!("/{}", "a".repeat(MAX_PATH - 1));
        assert!(safe_path(Some(&at_limit)).is_some());
        assert_eq!(safe_path(Some(&format!("{at_limit}a"))), None);
    }

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
        let pass = s.pass("us_ann", "m.t.test", 3600);
        assert_eq!(s.verify_pass(&pass, "m.t.test").unwrap().user_id, "us_ann");
        assert_ne!(pass, s.pass("us_ann", "m.t.test", 3600), "each pass is distinct");
        assert!(s.verify_cookie(&pass, "m.t.test").is_none(), "a pass is not a cookie");
        assert!(s.verify_pass(&s.cookie("us_ann", "m.t.test", 3600), "m.t.test").is_none(), "a cookie is not a pass");
        assert!(s.verify_pass(&pass, "other.t.test").is_none(), "another server");
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
