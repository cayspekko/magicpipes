//! `magicpipesd.toml` configuration. Every field except `base_domain` and
//! `management.hostname` has a default.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use magicpipes_core::cidr;
use serde::{Deserialize, Serialize};

use crate::forwarded::TrustedProxies;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Tunnels are served as `<name>.<base_domain>`; `*.<base_domain>` must resolve to this host.
    pub base_domain: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default)]
    pub public: PublicConfig,
    pub management: ManagementConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub agents: AgentsConfig,
    #[serde(default)]
    pub ports: PortsConfig,
    #[serde(default)]
    pub users: UsersConfig,
    #[serde(default)]
    pub monitoring: MonitoringConfig,
    /// Addresses (CIDR) of reverse proxies or load balancers in front of magicpipesd, such as
    /// HAProxy. Only these may name the client: X-Forwarded-For on the HTTPS listeners (used for
    /// login rate limits and passed on to tunnels) and PROXY headers on port tunnels.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Sign-in through an authenticating proxy in front of the management host. Off unless present.
    #[serde(default)]
    pub proxy_auth: Option<ProxyAuthConfig>,
    /// The mail server for invitations and sign-in links. Off unless present here or on the
    /// Settings page.
    #[serde(default)]
    pub smtp: Option<SmtpConfig>,
    /// The SSH gateway (`ssh -J`). Off unless present.
    #[serde(default)]
    pub ssh: Option<SshConfig>,
    /// Sign-in with OpenID Connect providers; one button each on the sign-in page.
    #[serde(default)]
    pub oidc: Vec<OidcConfig>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProxyAuthMode {
    /// The proxy forwards a signed token, which is checked here. A forged request can't make one.
    Jwt,
    /// The proxy names the user in a plain header, believed only from `trusted_proxies` and with
    /// a shared secret.
    Headers,
}

/// An authenticating proxy, such as oauth2-proxy, Authelia, Pomerium or Cloudflare Access, that
/// signs people in and tells this server who they are (`[proxy_auth]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyAuthConfig {
    pub mode: ProxyAuthMode,
    /// `jwt`: the header holding the token, such as `Cf-Access-Jwt-Assertion`.
    pub jwt_header: Option<String>,
    /// `jwt`: where the proxy publishes the keys that sign its tokens.
    pub jwks_url: Option<String>,
    /// `jwt`: the token's `iss`, exactly.
    pub issuer: Option<String>,
    /// `jwt`: a value of the token's `aud`.
    pub audience: Option<String>,
    /// `headers`: the header naming the user, such as `X-Forwarded-Email`.
    pub user_header: Option<String>,
    /// `headers`: the header the proxy adds with the shared secret.
    pub secret_header: Option<String>,
    /// `headers`: a file holding that secret.
    pub secret_file: Option<PathBuf>,
    /// `headers`: the header listing the user's groups, comma-separated, such as
    /// `X-Forwarded-Groups`, for tag rules (the claim `groups`). In `jwt` mode the token's own
    /// claims are used.
    pub groups_header: Option<String>,
    /// Accept the proxy's email addresses even when nothing says they were verified. Off by
    /// default: anyone who can choose their address behind the proxy could then claim one here.
    #[serde(default)]
    pub trust_email: bool,
    /// With `trust_email`: let such an address reach an administrator's account, through
    /// `bootstrap_admins` or an existing account. Off by default, so that trusting a proxy's
    /// addresses can't hand out administrators.
    #[serde(default)]
    pub allow_unverified_admin: bool,
    /// Someone new whose address is accepted gets a member account. Off by default: an
    /// administrator creates accounts first, or `users.allowed_email_domains` covers them.
    #[serde(default)]
    pub auto_create: bool,
    /// Where "Sign out" leads, such as `https://auth.example.com/logout`. Without it there's no
    /// such button: signing out here alone would only sign you straight back in.
    pub sign_out_url: Option<String>,
}

/// Headers that mean something else to this server or to HTTP.
const RESERVED_HEADERS: [&str; 6] = ["cookie", "host", "content-length", "transfer-encoding", "connection", "x-forwarded-for"];

impl ProxyAuthConfig {
    fn header(what: &str, value: &Option<String>) -> Result<http::HeaderName, String> {
        let raw = value.as_deref().ok_or_else(|| format!("{what} is required in this mode"))?;
        let name = http::HeaderName::from_bytes(raw.trim().as_bytes()).map_err(|_| format!("{what}: '{raw}' is not a header name"))?;
        if RESERVED_HEADERS.contains(&name.as_str()) || name.as_str().starts_with("x-magicpipes-") {
            return Err(format!("{what}: '{raw}' already means something else"));
        }
        Ok(name)
    }

    fn check(&self) -> Result<(), String> {
        let unused = |what: &str, value: bool| if value { Err(format!("{what} doesn't apply in this mode")) } else { Ok(()) };
        match self.mode {
            ProxyAuthMode::Jwt => {
                Self::header("jwt_header", &self.jwt_header)?;
                if !self.jwks_url.as_deref().is_some_and(crate::oidc::allowed_url) {
                    return Err("jwks_url must be an https:// URL".into());
                }
                if self.issuer.as_deref().is_none_or(|i| i.trim().is_empty() || i.len() > 2048) {
                    return Err("issuer is required, at most 2048 characters".into());
                }
                if self.audience.as_deref().is_none_or(|a| a.trim().is_empty() || a.len() > 2048) {
                    return Err("audience is required, at most 2048 characters".into());
                }
                unused("user_header", self.user_header.is_some())?;
                unused("secret_header", self.secret_header.is_some())?;
                unused("secret_file", self.secret_file.is_some())?;
                unused("groups_header", self.groups_header.is_some())?;
            }
            ProxyAuthMode::Headers => {
                let user = Self::header("user_header", &self.user_header)?;
                let secret = Self::header("secret_header", &self.secret_header)?;
                if user == http::header::AUTHORIZATION || secret == http::header::AUTHORIZATION {
                    return Err("user_header and secret_header can't be Authorization, which applications use".into());
                }
                if user == secret {
                    return Err("user_header and secret_header must differ".into());
                }
                if self.groups_header.is_some() {
                    let groups = Self::header("groups_header", &self.groups_header)?;
                    if groups == http::header::AUTHORIZATION || groups == user || groups == secret {
                        return Err("groups_header must differ from user_header, secret_header and Authorization".into());
                    }
                }
                if self.secret_file.is_none() {
                    return Err("secret_file is required in this mode".into());
                }
                unused("jwt_header", self.jwt_header.is_some())?;
                unused("jwks_url", self.jwks_url.is_some())?;
                unused("issuer", self.issuer.is_some())?;
                unused("audience", self.audience.is_some())?;
                // A plain header can't say an address was verified, so nothing would ever match.
                if self.auto_create && !self.trust_email {
                    return Err("auto_create needs trust_email in this mode".into());
                }
            }
        }
        if self.allow_unverified_admin && !self.trust_email {
            return Err("unverified addresses can only reach administrators' accounts behind a proxy whose addresses are trusted".into());
        }
        if self.sign_out_url.as_deref().is_some_and(|u| !crate::oidc::allowed_url(u)) {
            return Err("sign_out_url must be an https:// URL".into());
        }
        Ok(())
    }

    /// The headers that say who someone is, which never reach a tunnel's application. Except
    /// `Authorization`: there, an application's own credentials would be lost.
    pub fn identity_headers(&self) -> Vec<http::HeaderName> {
        [&self.jwt_header, &self.user_header, &self.secret_header, &self.groups_header]
            .into_iter()
            .flatten()
            .filter_map(|h| http::HeaderName::from_bytes(h.trim().as_bytes()).ok())
            .filter(|h| *h != http::header::AUTHORIZATION)
            .collect()
    }
}

/// How a connection to the mail server is protected.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SmtpTls {
    /// Upgrade with STARTTLS, and send nothing to a server that doesn't offer it.
    Starttls,
    /// TLS from the first byte.
    Implicit,
    /// None at all, for a relay on this machine or a network you trust.
    None,
}

impl SmtpTls {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Starttls => "starttls",
            Self::Implicit => "implicit",
            Self::None => "none",
        }
    }

    pub fn usual_port(self) -> u16 {
        match self {
            Self::Starttls => 587,
            Self::Implicit => 465,
            Self::None => 25,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "starttls" => Some(Self::Starttls),
            "implicit" => Some(Self::Implicit),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// Where this server sends email (`[smtp]`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SmtpConfig {
    pub host: String,
    /// Default: 587 with STARTTLS, 465 with implicit TLS, 25 with none.
    pub port: Option<u16>,
    /// Default: `implicit` on port 465, otherwise `starttls`.
    pub tls: Option<SmtpTls>,
    pub username: Option<String>,
    /// A file holding the password that goes with `username`.
    pub password_file: Option<PathBuf>,
    /// Who messages come from, such as `MagicPipes <magicpipes@example.com>`.
    pub from: String,
    /// PEM certificates to trust as well as the public CAs, for a mail server with a private CA.
    pub ca_file: Option<PathBuf>,
}

impl SmtpConfig {
    pub fn tls_mode(&self) -> SmtpTls {
        self.tls.unwrap_or(if self.port == Some(465) { SmtpTls::Implicit } else { SmtpTls::Starttls })
    }

    pub fn port_number(&self) -> u16 {
        self.port.unwrap_or(self.tls_mode().usual_port())
    }

    /// The checks every mail server passes, from the configuration file or the Settings page.
    pub fn check(&self) -> Result<(), String> {
        let host = self.host.trim();
        if host.is_empty() || host.len() > 253 || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b"-.:_".contains(&b)) {
            return Err(format!("'{host}' is not a host name"));
        }
        if self.port == Some(0) {
            return Err("the port can't be 0".into());
        }
        if self.from.parse::<lettre::message::Mailbox>().is_err() {
            return Err(format!("'{}' is not an address to send from, such as MagicPipes <magicpipes@example.com>", self.from));
        }
        match (&self.username, &self.password_file) {
            (Some(name), Some(_)) => {
                if name.trim().is_empty() || name.len() > 512 || name.chars().any(char::is_control) {
                    return Err("that username can't be used".into());
                }
                if self.tls_mode() == SmtpTls::None {
                    return Err("a password is never sent without encryption, so a username needs STARTTLS or implicit TLS".into());
                }
            }
            (None, None) => {}
            _ => return Err("a username and a password go together".into()),
        }
        Ok(())
    }
}

/// What a sign-in provider speaks.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKind {
    #[default]
    Oidc,
    /// GitHub or GitHub Enterprise Server: OAuth 2, not OpenID Connect.
    Github,
}

impl ProviderKind {
    pub fn is_oidc(&self) -> bool {
        *self == Self::Oidc
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Github => "github",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "oidc" => Some(Self::Oidc),
            "github" => Some(Self::Github),
            _ => None,
        }
    }
}

/// One sign-in provider (`[[oidc]]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// Lowercase letters, digits and dashes; part of the callback URL registered at the provider.
    pub id: String,
    /// `github` for GitHub or a GitHub Enterprise Server, whose `issuer` is its address, such as
    /// `https://github.com`.
    #[serde(default, skip_serializing_if = "ProviderKind::is_oidc")]
    pub kind: ProviderKind,
    /// The button says "Continue with <label>".
    pub label: String,
    /// The provider's issuer URL, exactly as it states it in its discovery document.
    pub issuer: String,
    pub client_id: String,
    pub client_secret_file: PathBuf,
    /// A first sign-in whose verified email matches an existing user signs in as that user.
    /// Off by default: only for a provider that doesn't let people change or reuse an address.
    #[serde(default)]
    pub link_by_email: bool,
    /// With `trust_email`: let an address the provider didn't verify reach an administrator's
    /// account, through `bootstrap_admins` or `link_by_email`. Off by default, so that trusting a
    /// provider's addresses can't hand out administrators.
    #[serde(default)]
    pub allow_unverified_admin: bool,
    /// Accept this provider's email addresses even when it doesn't say it verified them. Off by
    /// default: anyone who can choose their address there could then claim one here.
    #[serde(default)]
    pub trust_email: bool,
    /// What a sign-in asks for. Empty: `openid email profile`. Add `groups` for a provider that
    /// only sends groups when asked, or `offline_access` for one that only gives a refresh token
    /// then. OpenID Connect providers only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// The sign-in page goes straight to this provider. At most one provider.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub auto_redirect: bool,
    /// Signing out here also signs out at the provider, if it says where (`end_session_endpoint`).
    /// Off by default: that also signs people out of everything else using it. OpenID Connect
    /// providers only.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sign_out: bool,
}

/// What a sign-in asks for when nothing says otherwise.
pub const DEFAULT_SCOPES: [&str; 3] = ["openid", "email", "profile"];
const MAX_SCOPES: usize = 20;

/// Scopes as typed (space- or comma-separated), checked: `openid` among them, each a scope token
/// (RFC 6749 3.3). The default comes back empty.
pub fn clean_scopes(raw: &str) -> Result<Vec<String>, String> {
    let mut scopes: Vec<String> = Vec::new();
    for s in raw.split([' ', ',', '\n', '\t']).map(str::trim).filter(|s| !s.is_empty()) {
        if s.len() > 100 || !s.bytes().all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b)) {
            return Err(format!("'{s}' isn't a scope"));
        }
        if !scopes.iter().any(|x| x == s) {
            scopes.push(s.to_string());
        }
    }
    if scopes.len() > MAX_SCOPES {
        return Err(format!("at most {MAX_SCOPES} scopes"));
    }
    if !scopes.iter().any(|s| s == "openid") {
        return Err("the scopes must include openid".into());
    }
    Ok(if scopes == DEFAULT_SCOPES { Vec::new() } else { scopes })
}

impl OidcConfig {
    /// The scopes a sign-in asks for.
    pub fn scopes(&self) -> Vec<String> {
        if self.scopes.is_empty() { DEFAULT_SCOPES.iter().map(|s| s.to_string()).collect() } else { self.scopes.clone() }
    }

    /// The checks every provider passes, from the configuration file or the Settings page.
    pub fn check(&self) -> Result<(), String> {
        if self.id.is_empty() || self.id.len() > 40 || !self.id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return Err(format!("the id '{}' may only use lowercase letters, digits and dashes, at most 40", self.id));
        }
        if self.label.trim().is_empty() || self.label.len() > 60 {
            return Err("the label is required, at most 60 characters".into());
        }
        if self.client_id.trim().is_empty() || self.client_id.len() > 512 {
            return Err("the client ID is required, at most 512 characters".into());
        }
        if self.issuer.len() > 2048 || !crate::oidc::allowed_url(&self.issuer) {
            return Err("the issuer must be an https:// URL".into());
        }
        if self.allow_unverified_admin && !self.trust_email {
            return Err("unverified addresses can only reach administrators' accounts on a provider whose addresses are trusted".into());
        }
        if self.kind == ProviderKind::Github && self.trust_email {
            return Err("GitHub says which addresses it verified, so trust_email doesn't apply".into());
        }
        if self.kind == ProviderKind::Github && (!self.scopes.is_empty() || self.sign_out) {
            return Err("GitHub's scopes follow tag rules, and it has no sign-out to send people to, so scopes and sign_out don't apply".into());
        }
        if !self.scopes.is_empty() {
            clean_scopes(&self.scopes.join(" "))?;
        }
        Ok(())
    }
}

/// An address in `bootstrap_admins`, lowercased.
pub fn clean_bootstrap_admin(raw: &str) -> Result<String, String> {
    let e = raw.trim().to_lowercase();
    if e.len() > 254 || !e.contains('@') {
        return Err(format!("'{e}' is not an email address"));
    }
    Ok(e)
}

/// A domain in `allowed_email_domains`, lowercased.
pub fn clean_email_domain(raw: &str) -> Result<String, String> {
    let d = raw.trim().to_lowercase();
    if d.is_empty() || d.len() > 253 || d.contains('@') || d.contains('*') {
        return Err(format!("'{d}' is not a domain"));
    }
    Ok(d)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PublicConfig {
    pub https_listen: SocketAddr,
    /// Plain HTTP: ACME HTTP-01 challenges and redirects to HTTPS.
    pub http_listen: Option<SocketAddr>,
    /// Port shown in public URLs. Defaults to the `https_listen` port (omitted when 443).
    pub url_port: Option<u16>,
    pub max_connections: usize,
    /// Open connections per client address (per /64 for IPv6). Trusted proxies are exempt.
    pub max_connections_per_client: usize,
    pub header_read_timeout_secs: u64,
    /// Time allowed for the local application to start answering a request, counted from the
    /// end of the request body (or from the last chunk of a body still being uploaded).
    pub upstream_response_timeout_secs: u64,
    /// Upgraded (WebSocket) connections are closed after this long without traffic.
    pub websocket_idle_timeout_secs: u64,
    /// Connections from `trusted_proxies` start with a PROXY protocol header (a TCP load
    /// balancer passing TLS through, such as HAProxy with `send-proxy-v2`).
    pub proxy_protocol: bool,
    /// Close a connection after this long with no byte moving in either direction, so stalled
    /// uploads and downloads give their place back. Off by default: an application that holds a
    /// response open without sending anything (long polling, server-sent events) would be cut off.
    pub body_idle_timeout_secs: Option<u64>,
    /// Let applications set cookies for the whole base domain. Off by default: such a cookie goes
    /// to every other tunnel and the management host, so one tunnel could log visitors in to
    /// another as someone else, or lock them out with oversized headers.
    pub allow_cookie_domain: bool,
}

impl Default for PublicConfig {
    fn default() -> Self {
        Self {
            https_listen: "0.0.0.0:443".parse().unwrap(),
            http_listen: Some("0.0.0.0:80".parse().unwrap()),
            url_port: None,
            max_connections: 10_000,
            max_connections_per_client: 64,
            header_read_timeout_secs: 30,
            upstream_response_timeout_secs: 60,
            websocket_idle_timeout_secs: 600,
            proxy_protocol: false,
            body_idle_timeout_secs: None,
            allow_cookie_domain: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementConfig {
    #[serde(default = "default_mgmt_listen")]
    pub listen: SocketAddr,
    /// Hostname of the management UI/API and agent endpoint, e.g. `example.com`.
    pub hostname: String,
    /// Optional externally provisioned certificate for the management hostname.
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    /// Like `public.proxy_protocol`, for the management listener.
    #[serde(default)]
    pub proxy_protocol: bool,
    /// Open connections, while they are HTTP: an agent's session gives its place back once it has
    /// authenticated and upgraded.
    #[serde(default = "default_mgmt_max_connections")]
    pub max_connections: usize,
    /// Open connections per client address (per /64 for IPv6). Trusted proxies are exempt.
    #[serde(default = "default_mgmt_max_per_client")]
    pub max_connections_per_client: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TlsMode {
    /// Per-hostname certificates from an ACME CA (HTTP-01 challenge on `http_listen`).
    Acme,
    /// A certificate/key pair (typically a wildcard) provisioned externally.
    Files,
    /// A local development CA generated in `data_dir`. Never use in production.
    DevCa,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TlsConfig {
    pub mode: TlsMode,
    /// `letsencrypt`, `letsencrypt-staging` or a directory URL.
    pub acme_directory: String,
    pub acme_email: Option<String>,
    /// Extra root certificate (PEM) to trust when talking to the ACME server (e.g. Pebble).
    pub acme_ca_root: Option<PathBuf>,
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    /// Upper bound for a single certificate order.
    pub issuance_timeout_secs: u64,
    /// After a failed order, don't retry the same hostname for this long (CA rate limits).
    pub failure_backoff_secs: u64,
    /// Your own certificates, for the names they cover, whatever the mode. Last: in TOML a table
    /// can't come before plain values.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<CertFiles>,
}

/// A certificate kept in files, which another tool may renew.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertFiles {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            mode: TlsMode::Acme,
            acme_directory: "letsencrypt".into(),
            acme_email: None,
            acme_ca_root: None,
            cert_file: None,
            key_file: None,
            issuance_timeout_secs: 120,
            failure_backoff_secs: 300,
            certificates: Vec::new(),
        }
    }
}

impl TlsConfig {
    pub fn acme_directory_url(&self) -> String {
        match self.acme_directory.as_str() {
            "letsencrypt" => instant_acme::LetsEncrypt::Production.url().to_string(),
            "letsencrypt-staging" => instant_acme::LetsEncrypt::Staging.url().to_string(),
            other => other.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AgentsConfig {
    /// Sessions without a ping for this long are dropped.
    pub session_timeout_secs: u64,
    pub max_tunnels_per_agent: usize,
    /// TCP/UDP ports one agent may hold, so one agent cannot take the whole `[ports] range`.
    pub max_ports_per_agent: usize,
    /// With ACME, new HTTPS hostnames (certificate orders) one agent may add per 24 hours, so
    /// one agent cannot use up the CA's limits for everyone.
    pub max_new_certificates_per_day: usize,
    /// Lifetime of enrollment tokens created by `magicpipesd enroll` / the UI.
    pub enrollment_ttl_secs: u64,
    /// Connections one agent may hold at once (1 to 8): each carries up to 224 streams, and may
    /// have up to 128 MiB of data on its way to the server. An agent asking for more goes on with
    /// these.
    pub max_connections: usize,
}

impl Default for AgentsConfig {
    fn default() -> Self {
        Self {
            session_timeout_secs: 45,
            max_tunnels_per_agent: 50,
            max_ports_per_agent: 10,
            max_new_certificates_per_day: 20,
            enrollment_ttl_secs: 3600,
            max_connections: 4,
        }
    }
}

/// History and alerts (the Health page).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MonitoringConfig {
    /// Days of 5-minute history kept in the database, 1 to 30. The last 24 hours are also in
    /// memory.
    pub history_days: u32,
    /// The server checks each tunnel's app on its own, through its machine, unless the agent
    /// turned it off for that tunnel (`add --no-check`).
    pub synthetics: bool,
    /// Seconds between two checks of a tunnel, 10 to 3600.
    pub check_interval_secs: u64,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self { history_days: 7, synthetics: true, check_interval_secs: 60 }
    }
}

/// User accounts (docs/USERS.md). Administrators create them in the UI or API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UsersConfig {
    /// How long a UI login lasts.
    pub session_max_age_secs: u64,
    /// How long audit log entries are kept.
    pub audit_retention_days: u64,
    /// May members' machines create public tunnels?
    pub members_can_publish: bool,
    /// Verified emails that get a new administrator account at their first single sign-on.
    pub bootstrap_admins: Vec<String>,
    /// Verified emails in these domains get a new member account at their first single sign-on.
    /// Empty: nobody does.
    pub allowed_email_domains: Vec<String>,
    /// Machines a member may enroll for themself, counting tokens not used yet, since limits per
    /// agent would otherwise multiply with every machine. 0: no limit. Administrators aren't limited.
    pub max_agents_per_user: usize,
    /// How often a single sign-on's session is checked with its provider, through the refresh token
    /// it gave: a refusal ends the session, and an answer updates tag rules. 0: never.
    pub sso_recheck_secs: u64,
}

impl Default for UsersConfig {
    fn default() -> Self {
        Self {
            session_max_age_secs: 12 * 3600,
            audit_retention_days: 90,
            members_can_publish: true,
            bootstrap_admins: Vec::new(),
            allowed_email_domains: Vec::new(),
            max_agents_per_user: 25,
            sso_recheck_secs: 3600,
        }
    }
}

/// The SSH gateway: a jump host for `magicpipes add 22 --ssh` tunnels (`[ssh]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshConfig {
    /// Where it listens, e.g. `"0.0.0.0:2222"`.
    pub listen: SocketAddr,
    /// Host in the commands people are shown. Defaults to `management.hostname`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_host: Option<String>,
    /// Port in those commands, if a router or container maps it. Defaults to the one in `listen`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_port: Option<u16>,
    /// Connections from `trusted_proxies` start with a PROXY protocol header (v1 or v2).
    #[serde(default)]
    pub proxy_protocol: bool,
    /// Open connections to the gateway.
    #[serde(default = "default_ssh_connections")]
    pub max_connections: usize,
    /// Open connections per client (see `forwarded::client_key`).
    #[serde(default = "default_ssh_connections_per_client")]
    pub max_connections_per_client: usize,
}

fn default_ssh_connections() -> usize {
    1024
}

fn default_ssh_connections_per_client() -> usize {
    32
}

/// Raw TCP and UDP port tunnels (`magicpipes add 5432 --tcp`). Off unless `range` is set.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PortsConfig {
    /// Ports handed out to tunnels, e.g. `"65500-65535"`. Each is used for TCP and for UDP.
    pub range: Option<String>,
    /// Address the port listeners bind to.
    pub bind: IpAddr,
    /// Host shown in `tcp://` and `udp://` URLs. Defaults to `management.hostname`.
    pub public_host: Option<String>,
    /// TCP connections from `trusted_proxies` start with a PROXY protocol header (v1 or v2),
    /// which carries the real client address for allow-lists.
    pub proxy_protocol: bool,
    /// Open TCP connections across all port tunnels.
    pub max_connections: usize,
    /// Close a TCP connection after this long with no byte moving in either direction. Off by
    /// default: plenty of protocols keep a quiet connection open on purpose.
    pub tcp_idle_timeout_secs: Option<u64>,
    /// A UDP client is forgotten after this long without datagrams in either direction.
    pub udp_idle_timeout_secs: u64,
    /// UDP clients tracked at once per tunnel; datagrams from further clients are dropped.
    pub udp_max_flows: usize,
}

impl Default for PortsConfig {
    fn default() -> Self {
        Self {
            range: None,
            bind: IpAddr::from([0, 0, 0, 0]),
            public_host: None,
            proxy_protocol: false,
            max_connections: 10_000,
            tcp_idle_timeout_secs: None,
            udp_idle_timeout_secs: 60,
            udp_max_flows: 128,
        }
    }
}

/// An inclusive range of public ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub first: u16,
    pub last: u16,
}

impl PortRange {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let (a, b) = s.split_once('-').unwrap_or((s, s));
        let num = |v: &str| v.trim().parse::<u16>().ok().filter(|p| *p > 0);
        match (num(a), num(b)) {
            (Some(first), Some(last)) if first <= last => Ok(Self { first, last }),
            _ => bail!("ports.range must look like \"65500-65535\" (ports 1-65535, first <= last)"),
        }
    }

    pub fn contains(&self, port: u16) -> bool {
        (self.first..=self.last).contains(&port)
    }

    pub fn len(&self) -> usize {
        usize::from(self.last - self.first) + 1
    }
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/magicpipes")
}

fn default_mgmt_listen() -> SocketAddr {
    "0.0.0.0:8443".parse().unwrap()
}

fn default_mgmt_max_connections() -> usize {
    1024
}

fn default_mgmt_max_per_client() -> usize {
    64
}

/// An optional timeout in seconds, for which 0 also means off.
pub fn optional_secs(secs: Option<u64>) -> Option<Duration> {
    secs.filter(|s| *s > 0).map(Duration::from_secs)
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let mut cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        if cfg.data_dir.is_relative() {
            let base = path.parent().unwrap_or(Path::new("."));
            cfg.data_dir = base.join(&cfg.data_dir);
        }
        cfg.validate()?;
        Ok(cfg)
    }

    pub(crate) fn validate(&mut self) -> anyhow::Result<()> {
        for e in &mut self.users.bootstrap_admins {
            *e = clean_bootstrap_admin(e).map_err(|m| anyhow::anyhow!("users.bootstrap_admins: {m}"))?;
        }
        for d in &mut self.users.allowed_email_domains {
            *d = clean_email_domain(d).map_err(|m| anyhow::anyhow!("users.allowed_email_domains: {m}"))?;
        }
        for (i, p) in self.oidc.iter().enumerate() {
            p.check().map_err(|m| anyhow::anyhow!("oidc '{}': {m}", p.id))?;
            if self.oidc[..i].iter().any(|o| o.id == p.id) {
                bail!("oidc.id: '{}' is used twice", p.id);
            }
        }
        if self.oidc.iter().filter(|p| p.auto_redirect).count() > 1 {
            bail!("oidc: auto_redirect can be on for one provider at most");
        }
        if self.users.sso_recheck_secs != 0 && !(10..=86_400).contains(&self.users.sso_recheck_secs) {
            bail!("users.sso_recheck_secs must be 0 (never) or between 10 and 86400");
        }
        self.base_domain = self.base_domain.trim().trim_end_matches('.').to_ascii_lowercase();
        self.management.hostname = self.management.hostname.trim().to_ascii_lowercase();
        if self.base_domain.is_empty() || (!self.base_domain.contains('.') && self.base_domain != "localhost") {
            bail!("base_domain must be a domain such as t.example.com");
        }
        if self.management.cert_file.is_some() != self.management.key_file.is_some() {
            bail!("management.cert_file and management.key_file must be set together");
        }
        if !(1..=30).contains(&self.monitoring.history_days) {
            bail!("monitoring.history_days must be between 1 and 30");
        }
        if !(10..=3600).contains(&self.monitoring.check_interval_secs) {
            bail!("monitoring.check_interval_secs must be between 10 and 3600");
        }
        if !(1..=magicpipes_core::proto::MAX_CONNECTIONS).contains(&self.agents.max_connections) {
            bail!("agents.max_connections must be between 1 and {}", magicpipes_core::proto::MAX_CONNECTIONS);
        }
        if self.tls.mode == TlsMode::Files && (self.tls.cert_file.is_none() || self.tls.key_file.is_none()) {
            bail!("tls.mode = \"files\" requires tls.cert_file and tls.key_file");
        }
        if self.tls.mode == TlsMode::Acme && self.public.http_listen.is_none() {
            bail!("tls.mode = \"acme\" requires public.http_listen for HTTP-01 challenges");
        }
        if let Some(r) = &self.ports.range {
            PortRange::parse(r)?;
        }
        let trusted = cidr::parse_list(&self.trusted_proxies).map_err(|e| anyhow::anyhow!("trusted_proxies: {e}"))?;
        let proxied = self.public.proxy_protocol || self.management.proxy_protocol || self.ports.proxy_protocol;
        if proxied && trusted.is_empty() {
            bail!("proxy_protocol requires trusted_proxies (the load balancer's addresses)");
        }
        if let Some(s) = &self.smtp {
            s.check().map_err(|m| anyhow::anyhow!("smtp: {m}"))?;
        }
        if let Some(p) = &self.proxy_auth {
            p.check().map_err(|m| anyhow::anyhow!("proxy_auth: {m}"))?;
            if p.mode == ProxyAuthMode::Headers {
                if trusted.is_empty() {
                    bail!("proxy_auth: plain headers are only believed from trusted_proxies, so that needs the proxy's address");
                }
                if self.management.proxy_protocol {
                    bail!("proxy_auth: plain headers need to see the proxy's own address, so management.proxy_protocol must be off");
                }
            }
        }
        Ok(())
    }

    /// This configuration as a file `load` reads back.
    pub fn to_toml(&self) -> anyhow::Result<String> {
        toml::to_string_pretty(self).context("writing the configuration as TOML")
    }

    /// This server's own address, for links in email and for `magicpipes login`. Always from here,
    /// never a request's `Host`.
    pub fn management_url(&self) -> String {
        match self.management.listen.port() {
            443 => format!("https://{}", self.management.hostname),
            port => format!("https://{}:{port}", self.management.hostname),
        }
    }

    pub fn trusted_proxies(&self) -> TrustedProxies {
        TrustedProxies::new(cidr::parse_list(&self.trusted_proxies).unwrap_or_default())
    }

    /// The configured port range, or `None` when port tunnels are off.
    pub fn port_range(&self) -> Option<PortRange> {
        self.ports.range.as_deref().and_then(|r| PortRange::parse(r).ok())
    }

    /// `tcp://host:port` or `udp://host:port`.
    pub fn port_url(&self, kind: magicpipes_core::proto::Kind, port: u16) -> String {
        let host = self.ports.public_host.as_deref().unwrap_or(&self.management.hostname);
        let host = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
        format!("{kind}://{host}:{port}")
    }

    /// Where people reach the SSH gateway, as `ssh -J` wants it: `host`, or `host:port` unless the
    /// port is 22.
    pub fn ssh_address(&self) -> Option<String> {
        let ssh = self.ssh.as_ref()?;
        let host = ssh.public_host.as_deref().unwrap_or(&self.management.hostname);
        let host = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
        Some(match ssh.public_port.unwrap_or(ssh.listen.port()) {
            22 => host,
            port => format!("{host}:{port}"),
        })
    }

    pub fn url_port(&self) -> u16 {
        self.public.url_port.unwrap_or(self.public.https_listen.port())
    }

    pub fn hostname_for(&self, name: &str) -> String {
        format!("{name}.{}", self.base_domain)
    }

    pub fn public_url(&self, hostname: &str) -> String {
        match self.url_port() {
            443 => format!("https://{hostname}"),
            port => format!("https://{hostname}:{port}"),
        }
    }

    pub fn session_timeout(&self) -> Duration {
        Duration::from_secs(self.agents.session_timeout_secs)
    }
}

/// Configuration template printed by `magicpipesd init-config`.
pub const EXAMPLE: &str = include_str!("../../../magicpipesd.example.toml");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_ranges() {
        assert_eq!(PortRange::parse("65500-65535").unwrap(), PortRange { first: 65500, last: 65535 });
        assert_eq!(PortRange::parse("7000").unwrap().len(), 1);
        for bad in ["", "0-10", "10-5", "a-b", "1-70000"] {
            assert!(PortRange::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn single_sign_on_settings() {
        let load = |extra: &str| {
            let mut c: Config = toml::from_str(&format!("base_domain = \"t.example.com\"\n[management]\nhostname = \"example.com\"\n{extra}")).unwrap();
            c.validate().map(|_| c)
        };
        let provider = |id: &str, issuer: &str| format!("[[oidc]]\nid = \"{id}\"\nlabel = \"L\"\nissuer = \"{issuer}\"\nclient_id = \"c\"\nclient_secret_file = \"/s\"\n");
        let google = provider("google", "https://accounts.google.com");

        // Trusting addresses has to come first; the rest can't be switched on by accident.
        let unverified = |extra: &str| load(&format!("{google}{extra}allow_unverified_admin = true\n"));
        assert!(unverified("").is_err());
        assert!(unverified("trust_email = true\n").is_ok());

        let c = load(&format!("[users]\nbootstrap_admins = [\" Ann@Example.com \"]\nallowed_email_domains = [\"Example.COM\"]\n{google}")).unwrap();
        assert_eq!(c.users.bootstrap_admins, ["ann@example.com"]);
        assert_eq!(c.users.allowed_email_domains, ["example.com"]);
        assert!(!c.oidc[0].link_by_email, "linking by email is off unless asked for");
        assert!(load(&provider("local", "http://127.0.0.1:9000")).is_ok());

        assert!(load(&provider("Has Space", "https://a.example.com")).is_err());
        assert!(load(&provider("x", "http://idp.example.com")).is_err(), "not over plain HTTP");
        assert!(load(&format!("{google}{google}")).is_err(), "the same id twice");
        assert!(load("[users]\nbootstrap_admins = [\"nobody\"]").is_err());
        assert!(load("[users]\nallowed_email_domains = [\"*.example.com\"]").is_err(), "no wildcards");
        assert!(load("[users]\nallowed_email_domains = [\"a@example.com\"]").is_err());
        assert!(!c.oidc[0].trust_email && !c.oidc[0].allow_unverified_admin, "trusting addresses is off unless asked for");
        assert_eq!(c.oidc[0].kind, ProviderKind::Oidc, "as it was before providers had a kind");

        let github = format!("{}kind = \"github\"\n", provider("github", "https://github.com"));
        assert_eq!(load(&github).unwrap().oidc[0].kind, ProviderKind::Github);
        assert!(load(&format!("{github}trust_email = true\n")).is_err(), "it says which it verified");

        // Scopes, going straight to a provider, signing out there, and re-checks.
        assert_eq!(c.oidc[0].scopes(), ["openid", "email", "profile"], "the default");
        let scoped = load(&format!("{google}scopes = [\"openid\", \"groups\", \"offline_access\"]\nauto_redirect = true\nsign_out = true\n")).unwrap();
        assert_eq!((scoped.oidc[0].scopes(), scoped.oidc[0].auto_redirect, scoped.oidc[0].sign_out), (vec!["openid".into(), "groups".into(), "offline_access".into()], true, true));
        assert!(load(&format!("{google}scopes = [\"email\"]\n")).is_err(), "openid is required");
        assert!(load(&format!("{github}scopes = [\"openid\", \"read:org\"]\n")).is_err(), "GitHub's follow rules");
        assert!(load(&format!("{github}sign_out = true\n")).is_err());
        let two = format!("{google}auto_redirect = true\n{}auto_redirect = true\n", provider("other", "https://other.example.com"));
        assert!(load(&two).is_err(), "straight to one provider at most");
        assert_eq!(c.users.sso_recheck_secs, 3600);
        assert!(load("[users]\nsso_recheck_secs = 0").is_ok(), "never");
        assert!(load("[users]\nsso_recheck_secs = 5").is_err());
    }

    #[test]
    fn scopes_are_scope_tokens_with_openid() {
        assert_eq!(clean_scopes("openid email profile").unwrap(), Vec::<String>::new(), "the default is kept as none");
        assert_eq!(clean_scopes(" openid,groups\noffline_access groups ").unwrap(), ["openid", "groups", "offline_access"]);
        assert_eq!(clean_scopes("openid api://abc/read").unwrap(), ["openid", "api://abc/read"]);
        let too_many = format!("openid {}", (0..MAX_SCOPES).map(|i| format!("s{i}")).collect::<Vec<_>>().join(" "));
        for bad in ["", "email", "openid \"quoted\"", "openid back\\slash", &too_many] {
            assert!(clean_scopes(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn authenticating_proxy_settings() {
        let load = |text: &str| {
            let mut c: Config = toml::from_str(&format!("base_domain = \"t.example.com\"\ntrusted_proxies = [\"10.0.0.1/32\"]\n[management]\nhostname = \"example.com\"\n[proxy_auth]\n{text}")).unwrap();
            c.validate().map(|_| c).map_err(|e| e.to_string())
        };
        let jwt = "mode = \"jwt\"\njwt_header = \"Cf-Access-Jwt-Assertion\"\njwks_url = \"https://t.example.com/certs\"\nissuer = \"https://t.example.com\"\naudience = \"a\"\n";
        let plain = "mode = \"headers\"\nuser_header = \"X-Forwarded-Email\"\nsecret_header = \"X-Proxy-Secret\"\nsecret_file = \"/s\"\n";
        let c = load(jwt).unwrap();
        let p = c.proxy_auth.as_ref().unwrap();
        assert!(!p.trust_email && !p.allow_unverified_admin && !p.auto_create, "off unless asked for");
        assert_eq!(p.identity_headers(), ["cf-access-jwt-assertion"]);
        assert_eq!(load(plain).unwrap().proxy_auth.unwrap().identity_headers(), ["x-forwarded-email", "x-proxy-secret"]);

        // oauth2-proxy can hand over the ID token as a bearer token, but that header isn't ours to strip.
        let bearer = jwt.replace("Cf-Access-Jwt-Assertion", "Authorization");
        assert!(load(&bearer).unwrap().proxy_auth.unwrap().identity_headers().is_empty());
        assert!(load(&plain.replace("X-Proxy-Secret", "Authorization")).is_err());

        for broken in [
            jwt.replace("jwks_url = \"https://t.example.com/certs\"\n", ""),
            jwt.replace("https://t.example.com/certs", "http://t.example.com/certs"),
            jwt.replace("audience = \"a\"\n", ""),
            jwt.replace("issuer = \"https://t.example.com\"\n", ""),
            jwt.replace("Cf-Access-Jwt-Assertion", "Cookie"),
            jwt.replace("Cf-Access-Jwt-Assertion", "not a header"),
            format!("{jwt}secret_file = \"/s\"\n"),
            format!("{jwt}allow_unverified_admin = true\n"),
            format!("{jwt}sign_out_url = \"http://auth.example.com/logout\"\n"),
            plain.replace("secret_file = \"/s\"\n", ""),
            plain.replace("X-Proxy-Secret", "X-Forwarded-Email"),
            plain.replace("X-Forwarded-Email", "X-MagicPipes-User"),
            format!("{plain}auto_create = true\n"),
            format!("{plain}issuer = \"x\"\n"),
        ] {
            assert!(load(&broken).is_err(), "{broken}");
        }
        assert!(load(&format!("{plain}trust_email = true\nauto_create = true\n")).is_ok());
        assert!(load(&format!("{jwt}auto_create = true\n")).is_ok(), "a token can say an address was verified");

        // Plain headers need to know the proxy's own address.
        let mut alone: Config = toml::from_str(&format!("base_domain = \"t.example.com\"\n[management]\nhostname = \"example.com\"\n[proxy_auth]\n{plain}")).unwrap();
        assert!(alone.validate().unwrap_err().to_string().contains("trusted_proxies"));
        let mut behind: Config = toml::from_str(&format!("base_domain = \"t.example.com\"\ntrusted_proxies = [\"10.0.0.1/32\"]\n[management]\nhostname = \"example.com\"\nproxy_protocol = true\n[proxy_auth]\n{plain}")).unwrap();
        assert!(behind.validate().unwrap_err().to_string().contains("proxy_protocol"));
    }

    #[test]
    fn a_written_configuration_reads_back_the_same() {
        let full = r#"base_domain = "t.example.com"
data_dir = "/data"
trusted_proxies = ["172.23.0.0/16"]
[public]
https_listen = "0.0.0.0:8443"
url_port = 443
proxy_protocol = true
body_idle_timeout_secs = 90
allow_cookie_domain = true
[management]
listen = "0.0.0.0:443"
hostname = "example.com"
proxy_protocol = true
max_connections = 100
max_connections_per_client = 10
[tls]
mode = "dev-ca"
[ports]
range = "65500-65535"
tcp_idle_timeout_secs = 600
[users]
bootstrap_admins = ["ann@example.com"]
allowed_email_domains = ["example.com"]
max_agents_per_user = 3
[proxy_auth]
mode = "jwt"
jwt_header = "Cf-Access-Jwt-Assertion"
jwks_url = "https://team.example.com/certs"
issuer = "https://team.example.com"
audience = "aud-1"
trust_email = true
auto_create = true
sign_out_url = "https://team.example.com/logout"
[[oidc]]
id = "authentik"
label = "authentik"
issuer = "https://auth.example.com/application/o/mp/"
client_id = "c"
client_secret_file = "/data/oidc-secrets/authentik"
trust_email = true
allow_unverified_admin = true
[[oidc]]
id = "github"
kind = "github"
label = "GitHub"
issuer = "https://github.com"
client_id = "g"
client_secret_file = "/data/oidc-secrets/github"
[smtp]
host = "smtp.example.com"
username = "magicpipes@example.com"
password_file = "/data/smtp-password"
from = "MagicPipes <magicpipes@example.com>"
[[tls.certificates]]
cert_file = "/etc/magicpipes/shop.crt"
key_file = "/etc/magicpipes/shop.key"
[[tls.certificates]]
cert_file = "/data/provided-certs/abc.crt"
key_file = "/data/provided-certs/abc.key"
"#;
        for text in [full, "base_domain = \"t.example.com\"\n[management]\nhostname = \"example.com\"\n"] {
            let mut first: Config = toml::from_str(text).unwrap();
            first.validate().unwrap();
            let written = first.to_toml().unwrap();
            let mut second: Config = toml::from_str(&written).unwrap_or_else(|e| panic!("{e}\n{written}"));
            second.validate().unwrap();
            assert_eq!(second.to_toml().unwrap(), written);
        }
        let mut c: Config = toml::from_str(full).unwrap();
        c.validate().unwrap();
        let written = c.to_toml().unwrap();
        assert_eq!(c.tls.certificates.len(), 2);
        for line in ["kind = \"github\"", "[[tls.certificates]]", "cert_file = \"/data/provided-certs/abc.crt\"", "client_secret_file = \"/data/oidc-secrets/authentik\"", "trust_email = true", "allow_unverified_admin = true", "body_idle_timeout_secs = 90", "allow_cookie_domain = true", "max_connections = 100", "max_connections_per_client = 10", "tcp_idle_timeout_secs = 600", "max_agents_per_user = 3", "jwks_url = \"https://team.example.com/certs\"", "auto_create = true", "sign_out_url = \"https://team.example.com/logout\"", "[smtp]", "password_file = \"/data/smtp-password\""] {
            assert!(written.contains(line), "{line} in {written}");
        }
        assert_eq!(written.matches("kind = ").count(), 1, "a provider that speaks OpenID Connect doesn't say so: {written}");
    }
}
