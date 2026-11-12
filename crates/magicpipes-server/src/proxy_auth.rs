//! Signing in through an authenticating proxy (`docs/USERS.md`, "Authenticating proxy"): who a
//! request says it's from, believed or not. What becomes of that is in `control::oidc` (the account)
//! and `mgmt::proxy_auth` (the session).
//!
//! A value is believed only if it can't have come from the client: a signed token, or a header from
//! a `trusted_proxies` address that also carries the shared secret. Anything else counts as no
//! identity at all, and so does a header sent more than once, since a client's copy can sit next to
//! the proxy's if the proxy adds its own instead of replacing it.

use std::net::IpAddr;

use anyhow::Context;
use http::{HeaderMap, HeaderName};
use magicpipes_core::secret;

use crate::config::{ProxyAuthConfig, ProxyAuthMode};
use crate::forwarded::TrustedProxies;
use crate::oidc::{AssertionChecker, Person};

/// The issuer of identities from plain headers, which name no issuer of their own.
const PLAIN_HEADERS_ISSUER: &str = "proxy";
/// As for a token's `sub`.
const MAX_SUBJECT: usize = 255;
/// Short enough to guess, it isn't a secret.
const MIN_SECRET: usize = 16;

enum Method {
    Token { header: HeaderName, checker: AssertionChecker },
    Headers { user_header: HeaderName, secret_header: HeaderName, groups_header: Option<HeaderName>, secret: String, trusted: TrustedProxies, trust_email: bool },
}

pub struct ProxyAuth {
    /// The issuer part of the identities this proxy vouches for.
    pub issuer: String,
    pub allow_unverified_admin: bool,
    pub auto_create: bool,
    pub sign_out_url: Option<String>,
    method: Method,
}

/// The keys that sign the proxy's tokens can't be fetched, so nothing can be said about a token.
#[derive(Debug)]
pub struct KeysUnavailable;

/// The one value of a header, if it's sent exactly once.
fn single<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        tracing::debug!(header = %name, "ignoring a header sent more than once");
        return None;
    }
    value.to_str().ok()
}

/// The person a plain header names. A username is an identity, but only an address can reach an
/// account that isn't linked to it yet, and only if the proxy's addresses are trusted.
fn named_person(value: &str, trust_email: bool) -> Option<Person> {
    let subject = value.trim().to_lowercase();
    if subject.is_empty() || subject.len() > MAX_SUBJECT || subject.chars().any(char::is_control) {
        return None;
    }
    let verified_email = (trust_email && subject.contains('@')).then(|| subject.clone());
    Some(Person { subject, verified_email, ..Person::default() })
}

/// A groups header's list, as the claim `groups`: comma-separated names, trimmed.
fn groups(value: &str) -> crate::oidc::Claims {
    use crate::oidc::{MAX_CLAIM_LEN, MAX_CLAIM_VALUES};
    let names: Vec<String> = value
        .split(',')
        .map(str::trim)
        .filter(|g| !g.is_empty() && g.len() <= MAX_CLAIM_LEN && !g.chars().any(char::is_control))
        .take(MAX_CLAIM_VALUES)
        .map(str::to_string)
        .collect();
    if names.is_empty() { Default::default() } else { [("groups".to_string(), names)].into_iter().collect() }
}

impl ProxyAuth {
    /// Reads the shared secret. A missing file is a configuration mistake worth stopping for.
    pub fn load(cfg: &ProxyAuthConfig, trusted: TrustedProxies) -> anyhow::Result<Self> {
        let header = |value: &Option<String>| -> anyhow::Result<HeaderName> {
            let raw = value.as_deref().context("a header is missing")?;
            Ok(HeaderName::from_bytes(raw.trim().as_bytes())?)
        };
        let (issuer, method) = match cfg.mode {
            ProxyAuthMode::Jwt => {
                let issuer = cfg.issuer.clone().context("issuer is missing")?;
                let jwks_url = cfg.jwks_url.as_deref().context("jwks_url is missing")?;
                let audience = cfg.audience.as_deref().context("audience is missing")?;
                let checker = AssertionChecker::new(jwks_url, &issuer, audience, cfg.trust_email);
                (issuer, Method::Token { header: header(&cfg.jwt_header)?, checker })
            }
            ProxyAuthMode::Headers => {
                let file = cfg.secret_file.as_ref().context("secret_file is missing")?;
                let secret = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?.trim().to_string();
                anyhow::ensure!(secret.len() >= MIN_SECRET, "{} must hold at least {MIN_SECRET} characters", file.display());
                let groups_header = cfg.groups_header.as_ref().map(|_| header(&cfg.groups_header)).transpose()?;
                let method = Method::Headers { user_header: header(&cfg.user_header)?, secret_header: header(&cfg.secret_header)?, groups_header, secret, trusted, trust_email: cfg.trust_email };
                (PLAIN_HEADERS_ISSUER.to_string(), method)
            }
        };
        Ok(Self { issuer, allow_unverified_admin: cfg.allow_unverified_admin, auto_create: cfg.auto_create, sign_out_url: cfg.sign_out_url.clone(), method })
    }

    /// Who the proxy says this request is from; `None` if it says nobody that can be believed.
    /// `peer`: the address of the connection this request came in on.
    pub async fn person(&self, headers: &HeaderMap, peer: Option<IpAddr>) -> Result<Option<Person>, KeysUnavailable> {
        match &self.method {
            Method::Token { header, checker } => {
                let Some(value) = single(headers, header) else { return Ok(None) };
                checker.person(value.strip_prefix("Bearer ").unwrap_or(value).trim()).await.map_err(|e| {
                    tracing::warn!(error = %format!("{e:#}"), "can't fetch the keys that sign the authenticating proxy's tokens");
                    KeysUnavailable
                })
            }
            Method::Headers { user_header, secret_header, groups_header, secret, trusted, trust_email } => {
                let from_proxy = peer.is_some_and(|ip| trusted.trusts(ip.to_canonical()));
                let knows_secret = single(headers, secret_header).is_some_and(|s| secret::constant_time_eq(s.as_bytes(), secret.as_bytes()));
                if !from_proxy || !knows_secret {
                    if headers.contains_key(user_header) {
                        tracing::debug!(from_proxy, knows_secret, "ignoring identity headers");
                    }
                    return Ok(None);
                }
                let groups = groups_header.as_ref().and_then(|h| single(headers, h)).map(groups).unwrap_or_default();
                Ok(single(headers, user_header).and_then(|v| named_person(v, *trust_email)).map(|p| Person { claims: groups, ..p }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "a-long-enough-shared-secret";

    fn proxy(trust_email: bool) -> ProxyAuth {
        ProxyAuth {
            issuer: PLAIN_HEADERS_ISSUER.into(),
            allow_unverified_admin: false,
            auto_create: false,
            sign_out_url: None,
            method: Method::Headers {
                user_header: HeaderName::from_static("x-forwarded-email"),
                secret_header: HeaderName::from_static("x-proxy-secret"),
                groups_header: Some(HeaderName::from_static("x-forwarded-groups")),
                secret: SECRET.into(),
                trusted: TrustedProxies::new(magicpipes_core::cidr::parse_list(&["10.0.0.1/32".to_string()]).unwrap()),
                trust_email,
            },
        }
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, v.parse().unwrap());
        }
        h
    }

    #[tokio::test]
    async fn plain_headers_need_the_proxys_address_and_the_secret() {
        let p = proxy(true);
        let from_proxy = Some("10.0.0.1".parse().unwrap());
        let who = |h: HeaderMap, peer: Option<IpAddr>| {
            let p = &p;
            async move { p.person(&h, peer).await.unwrap().map(|person| person.subject) }
        };
        let good = [("x-forwarded-email", "Ann@Example.com"), ("x-proxy-secret", SECRET)];
        assert_eq!(who(headers(&good), from_proxy).await.as_deref(), Some("ann@example.com"));
        assert_eq!(who(headers(&good), Some("::ffff:10.0.0.1".parse().unwrap())).await.as_deref(), Some("ann@example.com"), "the same address, as IPv6");

        assert_eq!(who(headers(&good), Some("10.0.0.2".parse().unwrap())).await, None, "from anyone else");
        assert_eq!(who(headers(&good), None).await, None, "from nowhere known");
        assert_eq!(who(headers(&[("x-forwarded-email", "ann@example.com")]), from_proxy).await, None, "no secret");
        assert_eq!(who(headers(&[("x-forwarded-email", "ann@example.com"), ("x-proxy-secret", "wrong")]), from_proxy).await, None);
        assert_eq!(who(headers(&[("x-proxy-secret", SECRET)]), from_proxy).await, None, "nobody named");
        // A client's own header beside the proxy's: there's no telling which is which.
        assert_eq!(who(headers(&[("x-forwarded-email", "evil@example.com"), ("x-forwarded-email", "ann@example.com"), ("x-proxy-secret", SECRET)]), from_proxy).await, None);
        assert_eq!(who(headers(&[("x-forwarded-email", "ann@example.com"), ("x-proxy-secret", SECRET), ("x-proxy-secret", SECRET)]), from_proxy).await, None);
    }

    #[tokio::test]
    async fn groups_come_only_with_a_person_the_proxy_named() {
        let p = proxy(true);
        let from_proxy = Some("10.0.0.1".parse().unwrap());
        let named = headers(&[("x-forwarded-email", "ann@example.com"), ("x-proxy-secret", SECRET), ("x-forwarded-groups", " eng , ops,,eng-leads ")]);
        let person = p.person(&named, from_proxy).await.unwrap().unwrap();
        assert_eq!(person.claims.get("groups"), Some(&vec!["eng".to_string(), "ops".to_string(), "eng-leads".to_string()]));
        let forged = headers(&[("x-forwarded-email", "ann@example.com"), ("x-forwarded-groups", "admins")]);
        assert!(p.person(&forged, from_proxy).await.unwrap().is_none(), "without the secret, nobody, and no groups");
        let none = headers(&[("x-forwarded-email", "ann@example.com"), ("x-proxy-secret", SECRET)]);
        assert!(p.person(&none, from_proxy).await.unwrap().unwrap().claims.is_empty());
    }

    #[test]
    fn a_named_person_is_only_as_verified_as_the_settings_say() {
        let person = named_person(" Ann@Example.com ", true).unwrap();
        assert_eq!(person.subject, "ann@example.com");
        assert_eq!(person.verified_email.as_deref(), Some("ann@example.com"));
        assert!(!person.vouched_for, "a plain header can't say anyone verified it");
        assert_eq!(named_person("ann@example.com", false).unwrap().verified_email, None);
        let username = named_person("ann", true).unwrap();
        assert_eq!((username.subject.as_str(), username.verified_email), ("ann", None), "an identity, without an address");
        for bad in ["", "   ", "a\u{7f}b", &"a".repeat(MAX_SUBJECT + 1)] {
            assert!(named_person(bad, true).is_none(), "{bad}");
        }
    }

    #[test]
    fn a_secret_must_be_worth_keeping() {
        let dir = std::env::temp_dir().join(format!("mp-proxy-{}", secret::random_string(12)));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("secret");
        let cfg = |path: &std::path::Path| ProxyAuthConfig {
            mode: ProxyAuthMode::Headers,
            jwt_header: None,
            jwks_url: None,
            issuer: None,
            audience: None,
            user_header: Some("X-Forwarded-Email".into()),
            secret_header: Some("X-Proxy-Secret".into()),
            secret_file: Some(path.to_path_buf()),
            groups_header: None,
            trust_email: false,
            allow_unverified_admin: false,
            auto_create: false,
            sign_out_url: None,
        };
        assert!(ProxyAuth::load(&cfg(&file), TrustedProxies::default()).is_err(), "no file");
        std::fs::write(&file, "short\n").unwrap();
        assert!(ProxyAuth::load(&cfg(&file), TrustedProxies::default()).is_err());
        std::fs::write(&file, format!("{SECRET}\n")).unwrap();
        let loaded = ProxyAuth::load(&cfg(&file), TrustedProxies::default()).unwrap();
        assert_eq!(loaded.issuer, PLAIN_HEADERS_ISSUER);
        std::fs::remove_dir_all(&dir).ok();
    }
}
