//! OpenID Connect sign-in: the protocol side (`docs/USERS.md`, "SSO (OIDC)").
//!
//! The authorization code flow with PKCE (S256). What a browser must remember between leaving
//! for the provider and coming back ([`Attempt`]) lives in a signed, short-lived cookie, so a
//! flood of abandoned sign-ins uses no memory here. ID tokens are checked with `ring` directly:
//! RS256 and ES256 only, so `none` and HMAC tokens can never be accepted.
//!
//! Provider metadata (discovery and keys) is fetched on first use, so a provider that is down
//! doesn't stop the server, and cached. Accounts are decided in `control::oidc`.

use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{Method, Request, Uri, header};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use magicpipes_core::{secret, unix_now, url};
use ring::signature;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::{OidcConfig, ProviderKind};
use crate::tunnel_auth::Signer;

/// One request to a provider, from connecting to the last byte. Several fit in the management
/// listener's request deadline.
const HTTP_TIMEOUT: Duration = Duration::from_secs(4);
/// Providers answer with small JSON documents.
const MAX_RESPONSE: usize = 256 * 1024;
const MAX_KEYS: usize = 64;
/// Metadata older than this is refetched; if that fails, the old copy keeps working.
const METADATA_MAX_AGE: Duration = Duration::from_secs(3600);
/// With metadata in hand, fetch at most this often, however many tokens name an unknown key.
const REFRESH_SPACING: Duration = Duration::from_secs(60);
/// With none, a provider that is down is asked at most this often.
const RETRY_SPACING: Duration = Duration::from_secs(5);
/// How long a browser may take at the provider.
const ATTEMPT_TTL_SECS: i64 = 600;
/// Allowed difference between our clock and the provider's.
const CLOCK_SKEW_SECS: i64 = 60;
/// OpenID Connect Core: a `sub` is at most 255 ASCII characters.
const MAX_SUBJECT: usize = 255;

pub const ATTEMPT_COOKIE_MAX_AGE: i64 = ATTEMPT_TTL_SECS;

/// Is this URL allowed for a provider? HTTPS, or plain HTTP to this machine only (a local test
/// provider).
pub fn allowed_url(url: &str) -> bool {
    let Ok(uri) = url.parse::<Uri>() else { return false };
    let local = matches!(uri.host(), Some("127.0.0.1" | "localhost" | "[::1]"));
    uri.host().is_some() && (uri.scheme_str() == Some("https") || (uri.scheme_str() == Some("http") && local))
}

#[derive(Debug, Clone, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    userinfo_endpoint: Option<String>,
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
    id_token_signing_alg_values_supported: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    n: Option<String>,
    e: Option<String>,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

struct Metadata {
    discovery: Discovery,
    keys: Vec<Jwk>,
}

struct Cache<T> {
    latest: Option<(Arc<T>, Instant)>,
    last_attempt: Option<Instant>,
}

/// Something a provider publishes: fetched on first use and then kept, so one that is down doesn't
/// stop the server, and never fetched more often than the spacings above, whatever tokens say.
struct Published<T> {
    cache: Mutex<Cache<T>>,
    /// One fetch at a time.
    fetching: tokio::sync::Mutex<()>,
}

impl<T> Published<T> {
    fn new() -> Self {
        Self { cache: Mutex::new(Cache { latest: None, last_attempt: None }), fetching: tokio::sync::Mutex::new(()) }
    }

    /// The cached copy, fetched with `fetch` if it's missing, old, or `refresh` asks for a newer one.
    /// `from` names the source in the log.
    async fn get(&self, refresh: bool, from: &str, fetch: impl Future<Output = anyhow::Result<T>>) -> anyhow::Result<Arc<T>> {
        let fresh = |c: &Cache<T>| c.latest.as_ref().filter(|(_, at)| !refresh && at.elapsed() < METADATA_MAX_AGE).map(|(v, _)| v.clone());
        if let Some(v) = fresh(&self.cache.lock().unwrap()) {
            return Ok(v);
        }
        let _one_at_a_time = self.fetching.lock().await;
        let held = {
            let mut cache = self.cache.lock().unwrap();
            // Someone else may have just fetched it.
            if let Some(v) = fresh(&cache) {
                return Ok(v);
            }
            let held = cache.latest.as_ref().map(|(v, _)| v.clone());
            let spacing = if held.is_some() { REFRESH_SPACING } else { RETRY_SPACING };
            if cache.last_attempt.is_some_and(|t| t.elapsed() < spacing) {
                return held.ok_or_else(|| anyhow!("the provider could not be reached a moment ago"));
            }
            cache.last_attempt = Some(Instant::now());
            held
        };
        match fetch.await {
            Ok(v) => {
                let v = Arc::new(v);
                self.cache.lock().unwrap().latest = Some((v.clone(), Instant::now()));
                Ok(v)
            }
            Err(e) => match held {
                Some(old) => {
                    tracing::warn!(from, error = %format!("{e:#}"), "could not refresh what a sign-in provider publishes; keeping the old copy");
                    Ok(old)
                }
                None => Err(e),
            },
        }
    }
}

pub struct Provider {
    pub id: String,
    pub kind: ProviderKind,
    pub label: String,
    pub issuer: String,
    pub link_by_email: bool,
    client_id: String,
    /// Take this provider's addresses without its word that they're verified.
    trust_email: bool,
    /// Those addresses may also reach administrators' accounts.
    pub allow_unverified_admin: bool,
    client_secret: String,
    metadata: Published<Metadata>,
}

/// What a browser carries to the provider and back, in a signed cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    pub provider: String,
    pub state: String,
    nonce: String,
    verifier: String,
    /// The path to continue to afterwards. Unchecked: callers pass it through `safe_path`.
    pub next: Option<String>,
}

impl Attempt {
    pub fn new(provider: &str, next: Option<&str>) -> Self {
        Self {
            provider: provider.to_string(),
            state: secret::random_string(32),
            nonce: secret::random_string(32),
            verifier: secret::random_string(64),
            next: next.map(str::to_string),
        }
    }

    pub fn seal(&self, signer: &Signer) -> String {
        let next = URL_SAFE_NO_PAD.encode(self.next.as_deref().unwrap_or(""));
        let expires = unix_now() + ATTEMPT_TTL_SECS;
        signer.seal(&format!("o~{expires}~{}~{}~{}~{}~{next}", self.provider, self.state, self.nonce, self.verifier))
    }

    pub fn open(signer: &Signer, cookie: &str) -> Option<Self> {
        let payload = signer.open(cookie)?;
        let parts: Vec<&str> = payload.split('~').collect();
        let ["o", expires, provider, state, nonce, verifier, next] = parts.as_slice() else { return None };
        if expires.parse::<i64>().ok()? < unix_now() {
            return None;
        }
        let next = String::from_utf8(URL_SAFE_NO_PAD.decode(next).ok()?).ok()?;
        Some(Self {
            provider: provider.to_string(),
            state: state.to_string(),
            nonce: nonce.to_string(),
            verifier: verifier.to_string(),
            next: (!next.is_empty()).then_some(next),
        })
    }
}

/// What the provider says about the person, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub subject: String,
    /// An address the provider says it verified, or any it gives if it's trusted (`trust_email`);
    /// lowercased by the caller.
    pub verified_email: Option<String>,
    /// The provider itself said that address is verified.
    pub vouched_for: bool,
    pub name: String,
}

#[derive(Deserialize)]
struct RawClaims {
    #[serde(default)]
    sub: String,
    email: Option<String>,
    email_verified: Option<serde_json::Value>,
    name: Option<String>,
}

impl RawClaims {
    fn into_person(self, trust_email: bool) -> Person {
        // Some providers send the string "true".
        let vouched_for = matches!(&self.email_verified, Some(serde_json::Value::Bool(true))) || self.email_verified.as_ref().and_then(|v| v.as_str()) == Some("true");
        Person { subject: self.sub, verified_email: self.email.filter(|_| vouched_for || trust_email), vouched_for, name: self.name.unwrap_or_default() }
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
    access_token: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum TokenError {
    /// No key in the set matches: the provider may have rotated its keys.
    UnknownKey,
    Invalid(&'static str),
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

impl Provider {
    /// Reads the client secret. A missing file is a configuration mistake worth stopping for.
    pub fn load(cfg: &OidcConfig) -> anyhow::Result<Self> {
        let secret = std::fs::read_to_string(&cfg.client_secret_file).with_context(|| format!("reading {}", cfg.client_secret_file.display()))?;
        let client_secret = secret.trim().to_string();
        anyhow::ensure!(!client_secret.is_empty(), "{} is empty", cfg.client_secret_file.display());
        Ok(Self {
            id: cfg.id.clone(),
            kind: cfg.kind,
            label: cfg.label.clone(),
            issuer: cfg.issuer.clone(),
            link_by_email: cfg.link_by_email,
            client_id: cfg.client_id.clone(),
            trust_email: cfg.trust_email,
            allow_unverified_admin: cfg.allow_unverified_admin,
            client_secret,
            metadata: Published::new(),
        })
    }

    async fn fetch_metadata(&self) -> anyhow::Result<Metadata> {
        let discovery = fetch_discovery(&self.issuer).await?;
        if discovery.issuer != self.issuer {
            bail!("the provider calls itself {}, not {}", discovery.issuer, self.issuer);
        }
        let keys = fetch_keys(&discovery.jwks_uri).await?;
        Ok(Metadata { discovery, keys })
    }

    /// The cached metadata, fetched if it's missing, old, or `refresh` asks for newer keys.
    async fn metadata(&self, refresh: bool) -> anyhow::Result<Arc<Metadata>> {
        self.metadata.get(refresh, &self.id, self.fetch_metadata()).await
    }

    /// Where to send the browser for this attempt.
    pub async fn authorization_url(&self, attempt: &Attempt, redirect_uri: &str) -> anyhow::Result<String> {
        if self.kind == ProviderKind::Github {
            return Ok(crate::github::authorization_url(&self.issuer, &self.client_id, redirect_uri, &attempt.state, &pkce_challenge(&attempt.verifier)));
        }
        let m = self.metadata(false).await?;
        let endpoint = &m.discovery.authorization_endpoint;
        let sep = if endpoint.contains('?') { '&' } else { '?' };
        Ok(format!(
            "{endpoint}{sep}response_type=code&scope=openid%20email%20profile&client_id={}&redirect_uri={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
            url::encode(&self.client_id),
            url::encode(redirect_uri),
            attempt.state,
            attempt.nonce,
            pkce_challenge(&attempt.verifier),
        ))
    }

    /// Trades the code for tokens and returns the verified person.
    pub async fn finish(&self, attempt: &Attempt, code: &str, redirect_uri: &str) -> anyhow::Result<Person> {
        if self.kind == ProviderKind::Github {
            return crate::github::person(&self.issuer, &self.client_id, &self.client_secret, code, redirect_uri, &attempt.verifier).await;
        }
        let m = self.metadata(false).await?;
        let mut body = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&code_verifier={}",
            url::encode(code),
            url::encode(redirect_uri),
            url::encode(&attempt.verifier),
        );
        // `client_secret_basic` is the default when a provider doesn't list its methods.
        let basic = m.discovery.token_endpoint_auth_methods_supported.as_ref().is_none_or(|l| l.iter().any(|a| a == "client_secret_basic"));
        let auth = if basic {
            let pair = format!("{}:{}", url::encode(&self.client_id), url::encode(&self.client_secret));
            Some(format!("Basic {}", STANDARD.encode(pair)))
        } else {
            body.push_str(&format!("&client_id={}&client_secret={}", url::encode(&self.client_id), url::encode(&self.client_secret)));
            None
        };
        let bytes = request(Method::POST, &m.discovery.token_endpoint, auth.as_deref(), Some(body)).await.context("token request")?;
        let tokens: TokenResponse = serde_json::from_slice(&bytes).context("token response")?;
        let id_token = tokens.id_token.ok_or_else(|| anyhow!("the token response has no ID token"))?;

        let now = unix_now();
        let claims = match verify_id_token(&id_token, &m.keys, &self.issuer, &self.client_id, &attempt.nonce, now) {
            Err(TokenError::UnknownKey) => {
                let newer = self.metadata(true).await?;
                verify_id_token(&id_token, &newer.keys, &self.issuer, &self.client_id, &attempt.nonce, now)
            }
            other => other,
        };
        let mut person = claims.map_err(|e| anyhow!("ID token refused: {e:?}"))?.into_person(self.trust_email);

        // Providers may keep the email for the UserInfo endpoint (OpenID Connect Core 5.3).
        if person.verified_email.is_none()
            && let (Some(endpoint), Some(access)) = (&m.discovery.userinfo_endpoint, &tokens.access_token)
        {
            let info: RawClaims = get_json(endpoint, Some(&format!("Bearer {access}"))).await.context("userinfo")?;
            if info.sub != person.subject {
                bail!("UserInfo describes someone else");
            }
            let info = info.into_person(self.trust_email);
            person.verified_email = info.verified_email;
            person.vouched_for = info.vouched_for;
            if person.name.is_empty() {
                person.name = info.name;
            }
        }
        Ok(person)
    }
}

async fn fetch_discovery(issuer: &str) -> anyhow::Result<Discovery> {
    let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    let discovery: Discovery = get_json(&url, None).await.context("discovery")?;
    let endpoints = [&discovery.authorization_endpoint, &discovery.token_endpoint, &discovery.jwks_uri];
    if let Some(bad) = endpoints.into_iter().chain(discovery.userinfo_endpoint.as_ref()).find(|u| !allowed_url(u)) {
        bail!("the provider's endpoint {bad} isn't HTTPS");
    }
    Ok(discovery)
}

async fn fetch_keys(url: &str) -> anyhow::Result<Vec<Jwk>> {
    let set: JwkSet = get_json(url, None).await.context("keys")?;
    if set.keys.len() > MAX_KEYS {
        bail!("the provider publishes {} keys", set.keys.len());
    }
    Ok(set.keys)
}

/// Can tokens signed by this provider be checked here? Only RS256 and ES256 can.
fn signs_usably(discovery: &Discovery, keys: &[Jwk]) -> bool {
    let usable_alg = |a: &str| matches!(a, "RS256" | "ES256");
    let offered = discovery.id_token_signing_alg_values_supported.as_ref().is_none_or(|l| l.iter().any(|a| usable_alg(a)));
    offered
        && keys.iter().any(|k| {
            k.usage.as_deref().is_none_or(|u| u == "sig")
                && k.alg.as_deref().is_none_or(usable_alg)
                && ((k.kty == "RSA" && k.n.is_some() && k.e.is_some()) || (k.kty == "EC" && k.crv.as_deref() == Some("P-256") && k.x.is_some() && k.y.is_some()))
        })
}

/// What an administrator typed for a provider, without a trailing slash or the discovery path.
fn entered_issuer(entered: &str) -> &str {
    let entered = entered.trim().trim_end_matches('/');
    entered.strip_suffix("/.well-known/openid-configuration").unwrap_or(entered).trim_end_matches('/')
}

/// Asks a provider about itself before an administrator adds it, and says what's wrong if it
/// can't be used. Returns its issuer exactly as it states it, which tokens must then match.
pub async fn discover(entered: &str) -> anyhow::Result<String> {
    let entered = entered_issuer(entered);
    if !allowed_url(entered) {
        bail!("the address must be an https:// URL");
    }
    let discovery = fetch_discovery(entered).await?;
    if discovery.issuer.trim_end_matches('/') != entered {
        if discovery.issuer.len() > 2048 {
            bail!("the provider calls itself something else");
        }
        bail!("the provider calls itself {}. Enter that address", discovery.issuer);
    }
    let keys = fetch_keys(&discovery.jwks_uri).await?;
    if !signs_usably(&discovery, &keys) {
        bail!("the provider publishes no RS256 or ES256 signing key. In authentik, choose a Signing Key on the provider: without one it signs with the client secret, which isn't accepted here");
    }
    Ok(discovery.issuer)
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn names(&self, who: &str) -> bool {
        match self {
            Audience::One(a) => a == who,
            Audience::Many(l) => l.iter().any(|a| a == who),
        }
    }

    fn several(&self) -> bool {
        matches!(self, Audience::Many(l) if l.len() > 1)
    }
}

/// What every signed token here has to say.
#[derive(Deserialize)]
struct Checked {
    iss: String,
    aud: Audience,
    azp: Option<String>,
    exp: i64,
    iat: Option<i64>,
    nbf: Option<i64>,
    nonce: Option<String>,
}

/// The claims of a token signed by one of `keys`, not looked at yet.
fn signed_claims(token: &str, keys: &[Jwk]) -> Result<Vec<u8>, TokenError> {
    #[derive(Deserialize)]
    struct Header {
        alg: String,
        kid: Option<String>,
    }

    let decode = |part: &str| URL_SAFE_NO_PAD.decode(part).map_err(|_| TokenError::Invalid("not base64url"));
    let parts: Vec<&str> = token.split('.').collect();
    let [header, payload, sig] = parts.as_slice() else { return Err(TokenError::Invalid("not a JWS")) };
    let head: Header = serde_json::from_slice(&decode(header)?).map_err(|_| TokenError::Invalid("bad header"))?;
    let sig = decode(sig)?;
    let signed = &token.as_bytes()[..header.len() + 1 + payload.len()];

    let usable = |k: &&Jwk| {
        k.usage.as_deref().is_none_or(|u| u == "sig")
            && k.alg.as_deref().is_none_or(|a| a == head.alg)
            && head.kid.as_ref().is_none_or(|kid| k.kid.as_ref() == Some(kid))
    };
    let verified = match head.alg.as_str() {
        "RS256" => {
            let mut found = false;
            let mut good = false;
            for k in keys.iter().filter(usable).filter(|k| k.kty == "RSA") {
                let (Some(n), Some(e)) = (&k.n, &k.e) else { continue };
                let (n, e) = (decode(n)?, decode(e)?);
                found = true;
                let key = signature::RsaPublicKeyComponents { n: &n, e: &e };
                good = key.verify(&signature::RSA_PKCS1_2048_8192_SHA256, signed, &sig).is_ok();
                if good {
                    break;
                }
            }
            found.then_some(good)
        }
        "ES256" => {
            let mut found = false;
            let mut good = false;
            for k in keys.iter().filter(usable).filter(|k| k.kty == "EC" && k.crv.as_deref() == Some("P-256")) {
                let (Some(x), Some(y)) = (&k.x, &k.y) else { continue };
                let (x, y) = (decode(x)?, decode(y)?);
                if x.len() != 32 || y.len() != 32 {
                    continue;
                }
                found = true;
                let point = [&[4u8][..], &x, &y].concat();
                good = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &point).verify(signed, &sig).is_ok();
                if good {
                    break;
                }
            }
            found.then_some(good)
        }
        // Never `none` or a shared-secret algorithm.
        _ => return Err(TokenError::Invalid("algorithm")),
    };
    match verified {
        None => return Err(TokenError::UnknownKey),
        Some(false) => return Err(TokenError::Invalid("signature")),
        Some(true) => {}
    }
    decode(payload)
}

/// Checks what any token has to say: who issued it, for whom, and that it's valid now.
fn checked_claims(body: &[u8], issuer: &str, audience: &str, now: i64) -> Result<Checked, TokenError> {
    let checked: Checked = serde_json::from_slice(body).map_err(|_| TokenError::Invalid("bad claims"))?;
    if checked.iss != issuer {
        return Err(TokenError::Invalid("issuer"));
    }
    if !checked.aud.names(audience) {
        return Err(TokenError::Invalid("audience"));
    }
    if checked.exp <= now - CLOCK_SKEW_SECS {
        return Err(TokenError::Invalid("expired"));
    }
    if checked.iat.is_some_and(|iat| iat > now + CLOCK_SKEW_SECS) {
        return Err(TokenError::Invalid("issued in the future"));
    }
    if checked.nbf.is_some_and(|nbf| nbf > now + CLOCK_SKEW_SECS) {
        return Err(TokenError::Invalid("not valid yet"));
    }
    Ok(checked)
}

fn person_claims(body: &[u8]) -> Result<RawClaims, TokenError> {
    let claims: RawClaims = serde_json::from_slice(body).map_err(|_| TokenError::Invalid("bad claims"))?;
    if claims.sub.is_empty() || claims.sub.len() > MAX_SUBJECT {
        return Err(TokenError::Invalid("subject"));
    }
    Ok(claims)
}

/// Checks an ID token: one this server asked a provider for, so it also carries our nonce.
fn verify_id_token(token: &str, keys: &[Jwk], issuer: &str, client_id: &str, nonce: &str, now: i64) -> Result<RawClaims, TokenError> {
    let body = signed_claims(token, keys)?;
    let checked = checked_claims(&body, issuer, client_id, now)?;
    let azp_ok = match &checked.azp {
        Some(azp) => azp == client_id,
        None => !checked.aud.several(),
    };
    if !azp_ok {
        return Err(TokenError::Invalid("audience"));
    }
    if !checked.nonce.as_deref().is_some_and(|n| secret::constant_time_eq(n.as_bytes(), nonce.as_bytes())) {
        return Err(TokenError::Invalid("nonce"));
    }
    person_claims(&body)
}

/// Checks a token an authenticating proxy forwarded. This server didn't ask for it, so there's no
/// nonce, and it needn't be the proxy's only audience.
fn verify_assertion(token: &str, keys: &[Jwk], issuer: &str, audience: &str, now: i64) -> Result<RawClaims, TokenError> {
    let body = signed_claims(token, keys)?;
    checked_claims(&body, issuer, audience, now)?;
    person_claims(&body)
}

/// Checks the tokens an authenticating proxy forwards (`[proxy_auth]`, mode `jwt`), with the keys
/// its configuration points at.
pub struct AssertionChecker {
    jwks_url: String,
    issuer: String,
    audience: String,
    trust_email: bool,
    keys: Published<Vec<Jwk>>,
}

impl AssertionChecker {
    pub fn new(jwks_url: &str, issuer: &str, audience: &str, trust_email: bool) -> Self {
        Self { jwks_url: jwks_url.to_string(), issuer: issuer.to_string(), audience: audience.to_string(), trust_email, keys: Published::new() }
    }

    /// The person in a token, or `None` if it doesn't pass. `Err`: the keys can't be fetched, so
    /// nothing can be said about it.
    pub async fn person(&self, token: &str) -> anyhow::Result<Option<Person>> {
        let keys = self.keys.get(false, "proxy_auth", fetch_keys(&self.jwks_url)).await?;
        let now = unix_now();
        let claims = match verify_assertion(token, &keys, &self.issuer, &self.audience, now) {
            Err(TokenError::UnknownKey) => {
                let newer = self.keys.get(true, "proxy_auth", fetch_keys(&self.jwks_url)).await?;
                verify_assertion(token, &newer, &self.issuer, &self.audience, now)
            }
            other => other,
        };
        Ok(match claims {
            Ok(c) => Some(c.into_person(self.trust_email)),
            Err(e) => {
                tracing::debug!(error = ?e, "ignoring a token that doesn't pass");
                None
            }
        })
    }
}

// ---- a small HTTP client ---------------------------------------------------------------------

fn tls_config() -> anyhow::Result<Arc<ClientConfig>> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    if let Some(c) = CONFIG.get() {
        return Ok(c.clone());
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(CONFIG.get_or_init(|| Arc::new(cfg)).clone())
}

pub(crate) async fn get_json<T: DeserializeOwned>(url: &str, auth: Option<&str>) -> anyhow::Result<T> {
    let bytes = request(Method::GET, url, auth, None).await?;
    serde_json::from_slice(&bytes).context("invalid JSON")
}

/// One request and its whole answer (at most [`MAX_RESPONSE`] bytes), within [`HTTP_TIMEOUT`].
/// Redirects are not followed.
pub(crate) async fn request(method: Method, url: &str, auth: Option<&str>, form: Option<String>) -> anyhow::Result<Bytes> {
    if !allowed_url(url) {
        bail!("refusing to talk to {url}");
    }
    tokio::time::timeout(HTTP_TIMEOUT, send(method, url, auth, form)).await.map_err(|_| anyhow!("timed out"))?
}

async fn send(method: Method, url: &str, auth: Option<&str>, form: Option<String>) -> anyhow::Result<Bytes> {
    let uri: Uri = url.parse()?;
    let host = uri.host().ok_or_else(|| anyhow!("no host"))?;
    let tls = uri.scheme_str() == Some("https");
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let path = uri.path_and_query().map_or("/", |p| p.as_str());
    let authority = uri.authority().ok_or_else(|| anyhow!("no host"))?.as_str();

    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, authority)
        .header(header::ACCEPT, "application/json")
        .header(header::USER_AGENT, "magicpipesd")
        .header(header::CONNECTION, "close");
    if let Some(a) = auth {
        b = b.header(header::AUTHORIZATION, a);
    }
    if form.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    }
    let req = b.body(Full::new(Bytes::from(form.unwrap_or_default())))?;

    let tcp = TcpStream::connect((bare, port)).await.with_context(|| format!("connecting to {authority}"))?;
    let resp = if tls {
        let name = ServerName::try_from(bare.to_string()).map_err(|_| anyhow!("invalid host name"))?;
        let stream = TlsConnector::from(tls_config()?).connect(name, tcp).await.with_context(|| format!("TLS with {authority}"))?;
        exchange(TokioIo::new(stream), req).await?
    } else {
        exchange(TokioIo::new(tcp), req).await?
    };
    Ok(resp)
}

async fn exchange<I>(io: I, req: Request<Full<Bytes>>) -> anyhow::Result<Bytes>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    let driver = tokio::spawn(conn);
    let result = async {
        let resp = sender.send_request(req).await?;
        let status = resp.status();
        let body = Limited::new(resp.into_body(), MAX_RESPONSE).collect().await.map_err(|e| anyhow!("reading the answer: {e}"))?.to_bytes();
        // An error body can quote what we sent, so it never reaches a log.
        anyhow::ensure!(status.is_success(), "the provider answered {status}");
        Ok(body)
    }
    .await;
    driver.abort();
    result
}

#[cfg(test)]
mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    use super::*;

    const ISS: &str = "https://login.example.com";
    const CLIENT: &str = "client-1";
    const NONCE: &str = "nonce-1";
    const NOW: i64 = 1_800_000_000;

    fn claims() -> serde_json::Value {
        serde_json::json!({ "iss": ISS, "aud": CLIENT, "sub": "subject-1", "exp": NOW + 300, "iat": NOW, "nonce": NONCE, "email": "Ann@Example.com", "email_verified": true, "name": "Ann" })
    }

    struct Key {
        pair: EcdsaKeyPair,
        rng: SystemRandom,
    }

    impl Key {
        fn new() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
            Self { pair: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap(), rng }
        }

        fn jwk(&self, kid: &str) -> Jwk {
            let point = self.pair.public_key().as_ref();
            Jwk {
                kty: "EC".into(),
                kid: Some(kid.into()),
                alg: None,
                usage: Some("sig".into()),
                n: None,
                e: None,
                crv: Some("P-256".into()),
                x: Some(URL_SAFE_NO_PAD.encode(&point[1..33])),
                y: Some(URL_SAFE_NO_PAD.encode(&point[33..65])),
            }
        }

        fn sign(&self, header: serde_json::Value, claims: &serde_json::Value) -> String {
            let msg = format!("{}.{}", URL_SAFE_NO_PAD.encode(header.to_string()), URL_SAFE_NO_PAD.encode(claims.to_string()));
            let sig = self.pair.sign(&self.rng, msg.as_bytes()).unwrap();
            format!("{msg}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
        }

        fn token(&self, claims: &serde_json::Value) -> String {
            self.sign(serde_json::json!({ "alg": "ES256", "kid": "k1" }), claims)
        }
    }

    fn verify(token: &str, keys: &[Jwk]) -> Result<RawClaims, TokenError> {
        verify_id_token(token, keys, ISS, CLIENT, NONCE, NOW)
    }

    fn refusal(token: &str, keys: &[Jwk]) -> TokenError {
        verify(token, keys).err().expect("refused")
    }

    #[test]
    fn id_tokens_are_checked() {
        let key = Key::new();
        let keys = [key.jwk("k1")];
        let good = verify(&key.token(&claims()), &keys).unwrap().into_person(false);
        assert_eq!(good.subject, "subject-1");
        assert_eq!(good.verified_email.as_deref(), Some("Ann@Example.com"));

        let with = |field: &str, value: serde_json::Value| {
            let mut c = claims();
            c[field] = value;
            key.token(&c)
        };
        assert_eq!(refusal(&with("iss", "https://other.example.com".into()), &keys), TokenError::Invalid("issuer"));
        assert_eq!(refusal(&with("aud", "someone-else".into()), &keys), TokenError::Invalid("audience"));
        assert_eq!(refusal(&with("aud", serde_json::json!(["someone-else"])), &keys), TokenError::Invalid("audience"));
        assert_eq!(refusal(&with("aud", serde_json::json!([CLIENT, "someone-else"])), &keys), TokenError::Invalid("audience"), "several audiences need azp");
        assert_eq!(refusal(&with("azp", "someone-else".into()), &keys), TokenError::Invalid("audience"));
        assert_eq!(refusal(&with("exp", (NOW - 3600).into()), &keys), TokenError::Invalid("expired"));
        assert_eq!(refusal(&with("iat", (NOW + 3600).into()), &keys), TokenError::Invalid("issued in the future"));
        assert_eq!(refusal(&with("nonce", "another".into()), &keys), TokenError::Invalid("nonce"));
        assert_eq!(refusal(&with("sub", "".into()), &keys), TokenError::Invalid("subject"));
        assert_eq!(refusal(&with("sub", "x".repeat(256).into()), &keys), TokenError::Invalid("subject"));
        let mut no_nonce = claims();
        no_nonce.as_object_mut().unwrap().remove("nonce");
        assert_eq!(refusal(&key.token(&no_nonce), &keys), TokenError::Invalid("nonce"));
        assert!(verify(&with("aud", serde_json::json!([CLIENT])), &keys).is_ok());
        let mut c = claims();
        c["aud"] = serde_json::json!([CLIENT, "someone-else"]);
        c["azp"] = CLIENT.into();
        assert!(verify(&key.token(&c), &keys).is_ok());
    }

    #[test]
    fn a_proxys_tokens_are_checked_without_the_parts_it_cant_know() {
        let key = Key::new();
        let keys = [key.jwk("k1")];
        let check = |token: &str| verify_assertion(token, &keys, ISS, CLIENT, NOW);
        let mut claims = claims();
        claims.as_object_mut().unwrap().remove("nonce");
        assert_eq!(check(&key.token(&claims)).unwrap().sub, "subject-1", "no nonce: this server didn't ask for it");

        let with = |field: &str, value: serde_json::Value| {
            let mut c = claims.clone();
            c[field] = value;
            key.token(&c)
        };
        assert!(check(&with("aud", serde_json::json!(["other", CLIENT]))).is_ok(), "one of several audiences, as Cloudflare sends");
        assert!(check(&with("azp", "the-proxys-own-client".into())).is_ok());
        assert_eq!(check(&with("aud", "other".into())).err(), Some(TokenError::Invalid("audience")));
        assert_eq!(check(&with("iss", "https://other.example.com".into())).err(), Some(TokenError::Invalid("issuer")));
        assert_eq!(check(&with("exp", (NOW - 3600).into())).err(), Some(TokenError::Invalid("expired")));
        assert_eq!(check(&with("nbf", (NOW + 3600).into())).err(), Some(TokenError::Invalid("not valid yet")));
        assert!(check(&with("nbf", NOW.into())).is_ok());
        assert_eq!(check(&with("sub", "".into())).err(), Some(TokenError::Invalid("subject")));
        assert_eq!(check(&Key::new().token(&claims)).err(), Some(TokenError::Invalid("signature")));
        let unsigned = format!("{}.{}.", URL_SAFE_NO_PAD.encode(r#"{"alg":"none","kid":"k1"}"#), URL_SAFE_NO_PAD.encode(claims.to_string()));
        assert_eq!(check(&unsigned).err(), Some(TokenError::Invalid("algorithm")));
        assert!(verify_id_token(&key.token(&claims), &keys, ISS, CLIENT, NONCE, NOW).is_err(), "without a nonce it can't pass as an ID token");
    }

    #[test]
    fn only_real_signatures_count() {
        let key = Key::new();
        let keys = [key.jwk("k1")];
        // Signed by someone else, under the same key id.
        assert_eq!(refusal(&Key::new().token(&claims()), &keys), TokenError::Invalid("signature"));
        // The claims were changed after signing.
        let token = key.token(&claims());
        let parts: Vec<&str> = token.split('.').collect();
        let mut forged = claims();
        forged["sub"] = "admin".into();
        let forged = format!("{}.{}.{}", parts[0], URL_SAFE_NO_PAD.encode(forged.to_string()), parts[2]);
        assert_eq!(refusal(&forged, &keys), TokenError::Invalid("signature"));
        // No signature at all, or an algorithm that doesn't use the provider's key.
        for alg in ["none", "HS256", "RS384"] {
            let unsigned = format!("{}.{}.", URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"{alg}","kid":"k1"}}"#)), URL_SAFE_NO_PAD.encode(claims().to_string()));
            assert_eq!(refusal(&unsigned, &keys), TokenError::Invalid("algorithm"), "{alg}");
        }
        // A key we don't know yet: worth fetching the set again.
        assert_eq!(refusal(&key.sign(serde_json::json!({ "alg": "ES256", "kid": "k2" }), &claims()), &keys), TokenError::UnknownKey);
        // A key meant for encryption, or for another algorithm, doesn't verify anything.
        let mut enc = key.jwk("k1");
        enc.usage = Some("enc".into());
        assert_eq!(refusal(&key.token(&claims()), &[enc]), TokenError::UnknownKey);
        let mut rs = key.jwk("k1");
        rs.alg = Some("RS256".into());
        assert_eq!(refusal(&key.token(&claims()), &[rs]), TokenError::UnknownKey);
        // A token without a key id is tried against the keys that fit.
        assert!(verify(&key.sign(serde_json::json!({ "alg": "ES256" }), &claims()), &[Key::new().jwk("other"), key.jwk("k1")]).is_ok());
        // Rubbish doesn't panic.
        for bad in ["", "a", "a.b", "a.b.c", "..", "e30.e30.e30", "é.é.é"] {
            assert!(verify(bad, &keys).is_err(), "{bad}");
        }
    }

    #[test]
    fn rsa_signatures_verify() {
        // A key made for this test with `openssl genrsa 2048`, and a token it signed.
        let n = "w0o2GNMgEB7nGr18_xWbcssoO_lHcpPE3rA94fwOn_Fk-PHrr6-G4sedHhtKhTC9all_3yTB06s8N45eDHT8er2czOPPNMMqXWQXZrQaPpUk6hExDXDNceeAeviEselEQj8_71RcjdjRJVyy7A-yBLVmcstpKbU-EoFisF3GZOdSlbZWk67ajM7OE3ka98PVRojRy2Xgge5OKONLZyGoyPfn7fW42jq4DxmuTI1gHI4M2O7ONJLkfozeaqqHykd4m8-7zahkx8G_15ScGfrYlZwFhJTrGoLPr_YxTl0ii_TqWu8lTdEf2WkmyjmC9tbJrXYSBLbjE1Y2UxP6S83U4w";
        let key = Jwk { kty: "RSA".into(), kid: Some("r1".into()), alg: None, usage: None, n: Some(n.into()), e: Some("AQAB".into()), crv: None, x: None, y: None };
        let token = "eyJhbGciOiJSUzI1NiIsImtpZCI6InIxIn0.eyJpc3MiOiJodHRwczovL2xvZ2luLmV4YW1wbGUuY29tIiwiYXVkIjoiY2xpZW50LTEiLCJzdWIiOiJzdWJqZWN0LTEiLCJleHAiOjE4MDAwMDAzMDAsImlhdCI6MTgwMDAwMDAwMCwibm9uY2UiOiJub25jZS0xIn0.ofHNdSEpHmKJ4fNlvU5t8Rg3Eqp4KP2faVYcUgmFJpxrQN8zBhZLj3-62DtmoIDFxGHJykYL5vQRgG6eRTF2YdiroBWD9NeKa10ejSkH1d3ZK07Z2bNz5Q5llnUI-nyzaBIXR-XPkP6uiUELWj7Jsj7nZvh3RYEzfh1K6z9MUp2MKEYADdQqqWdSp0xIa8dildvxmfMHRTR88lKUnn6DI9IsXCFYepjBr0VyL6dH5lIDds1vh3gdyJwXddv97p9mlYk5Q72CBotoNg1OJG6akJ_2M83pTXJDVDhjKCJa0MbyL6Xx83QEbpW_ehJ5xi2qjO6R-L1l0Rpu1vCi49aArA";
        assert_eq!(verify(token, std::slice::from_ref(&key)).unwrap().sub, "subject-1");
        let (signed, _) = token.rsplit_once('.').unwrap();
        let other = format!("{signed}.{}", URL_SAFE_NO_PAD.encode([7u8; 256]));
        assert_eq!(verify(&other, std::slice::from_ref(&key)).err(), Some(TokenError::Invalid("signature")));
        // Short keys are refused, whatever they signed.
        let short = Jwk { n: Some(URL_SAFE_NO_PAD.encode([0xc5u8; 128])), ..key };
        assert_eq!(verify(token, &[short]).err(), Some(TokenError::Invalid("signature")));
    }

    #[test]
    fn attempts_survive_only_intact() {
        let signer = Signer::for_tests();
        let a = Attempt::new("google", Some("/auth/tunnel?host=a&state=b"));
        let cookie = a.seal(&signer);
        assert!(cookie.bytes().all(|b| b.is_ascii_graphic() && !b";,\"\\".contains(&b)), "{cookie}");
        assert_eq!(Attempt::open(&signer, &cookie), Some(a));
        assert!(Attempt::open(&Signer::for_tests(), &cookie).is_none(), "another key");
        assert!(Attempt::open(&signer, &cookie.replace("google", "evil")).is_none(), "tampered");
        assert!(Attempt::open(&signer, "garbage").is_none());
        let none = Attempt::new("google", None);
        assert_eq!(Attempt::open(&signer, &none.seal(&signer)).unwrap().next, None);
        // A token of another kind signed with the same key isn't an attempt.
        assert!(Attempt::open(&signer, &signer.cookie("us_x", "h.t", 60)).is_none());
        let expired = signer.seal("o~1~google~s~n~v~");
        assert!(Attempt::open(&signer, &expired).is_none());
    }

    #[test]
    fn the_longest_destination_fits_a_browsers_cookie_limit() {
        let signer = Signer::for_tests();
        let longest = format!("/{}", "a".repeat(2047));
        assert!(crate::tunnel_auth::safe_path(Some(&longest)).is_some());
        let cookie = Attempt::new(&"p".repeat(40), Some(&longest)).seal(&signer);
        assert!(format!("__Host-mp_oidc={cookie}").len() < 4096, "{}", cookie.len());
        assert_eq!(Attempt::open(&signer, &cookie).unwrap().next.as_deref(), Some(longest.as_str()));
    }

    #[test]
    fn trusting_a_provider_takes_addresses_it_does_not_vouch_for() {
        let raw = |verified: serde_json::Value| -> RawClaims { serde_json::from_value(serde_json::json!({ "sub": "s", "email": "a@example.com", "email_verified": verified })).unwrap() };
        assert_eq!(raw(false.into()).into_person(false).verified_email, None);
        assert_eq!(raw(serde_json::Value::Null).into_person(false).verified_email, None);
        assert_eq!(raw(true.into()).into_person(false).verified_email.as_deref(), Some("a@example.com"));
        assert_eq!(raw("true".into()).into_person(false).verified_email.as_deref(), Some("a@example.com"));
        assert_eq!(raw(false.into()).into_person(true).verified_email.as_deref(), Some("a@example.com"));
        assert!(!raw(false.into()).into_person(true).vouched_for, "trusted isn't the same as verified");
        assert!(raw(true.into()).into_person(true).vouched_for);
        assert_eq!(raw(serde_json::Value::Null).into_person(true).verified_email.as_deref(), Some("a@example.com"));
        let none: RawClaims = serde_json::from_value(serde_json::json!({ "sub": "s" })).unwrap();
        assert_eq!(none.into_person(true).verified_email, None, "no address to trust");
    }

    #[test]
    fn what_was_typed_becomes_a_provider_address() {
        for typed in ["https://a.example.com/o/x", "https://a.example.com/o/x/", " https://a.example.com/o/x/.well-known/openid-configuration ", "https://a.example.com/o/x/.well-known/openid-configuration/"] {
            assert_eq!(entered_issuer(typed), "https://a.example.com/o/x", "{typed}");
        }
    }

    #[test]
    fn only_keys_that_can_be_checked_here_count() {
        let discovery = |algs: Option<&[&str]>| Discovery {
            issuer: ISS.into(),
            authorization_endpoint: String::new(),
            token_endpoint: String::new(),
            jwks_uri: String::new(),
            userinfo_endpoint: None,
            token_endpoint_auth_methods_supported: None,
            id_token_signing_alg_values_supported: algs.map(|l| l.iter().map(|a| a.to_string()).collect()),
        };
        let key = |v: serde_json::Value| -> Jwk { serde_json::from_value(v).unwrap() };
        let rsa = key(serde_json::json!({ "kty": "RSA", "alg": "RS256", "use": "sig", "n": "AQAB", "e": "AQAB" }));
        let p256 = key(serde_json::json!({ "kty": "EC", "crv": "P-256", "x": "AA", "y": "AA" }));
        let p384 = key(serde_json::json!({ "kty": "EC", "crv": "P-384", "alg": "ES384", "x": "AA", "y": "AA" }));
        let encryption = key(serde_json::json!({ "kty": "RSA", "use": "enc", "n": "AQAB", "e": "AQAB" }));

        assert!(signs_usably(&discovery(None), std::slice::from_ref(&rsa)));
        assert!(signs_usably(&discovery(Some(&["RS256"])), std::slice::from_ref(&rsa)));
        assert!(signs_usably(&discovery(Some(&["ES256", "ES384"])), &[p384.clone(), p256]));
        // authentik without a signing key: HS256, and nothing published.
        assert!(!signs_usably(&discovery(Some(&["HS256"])), &[]));
        assert!(!signs_usably(&discovery(None), &[]));
        assert!(!signs_usably(&discovery(Some(&["HS256"])), &[rsa]), "keys it doesn't sign tokens with");
        assert!(!signs_usably(&discovery(None), &[p384, encryption]));
    }

    #[test]
    fn pkce_matches_the_rfc() {
        // RFC 7636, appendix B.
        assert_eq!(pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn provider_urls_are_https_or_local() {
        for ok in ["https://accounts.google.com", "https://a.example.com/realms/x", "http://127.0.0.1:9000", "http://localhost:9000/x", "http://[::1]:9000"] {
            assert!(allowed_url(ok), "{ok}");
        }
        for bad in ["http://accounts.google.com", "http://127.0.0.1.example.com", "ftp://example.com", "accounts.google.com", "", "https://"] {
            assert!(!allowed_url(bad), "{bad}");
        }
    }
}
