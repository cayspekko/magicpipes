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
    /// Addresses (CIDR) of reverse proxies or load balancers in front of magicpipesd, such as
    /// HAProxy. Only these may name the client: X-Forwarded-For on the HTTPS listeners (used for
    /// login rate limits and passed on to tunnels) and PROXY headers on port tunnels.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Sign-in with OpenID Connect providers; one button each on the sign-in page.
    #[serde(default)]
    pub oidc: Vec<OidcConfig>,
}

/// One OpenID Connect provider (`[[oidc]]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// Lowercase letters, digits and dashes; part of the callback URL registered at the provider.
    pub id: String,
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
    /// Accept this provider's email addresses even when it doesn't say it verified them. Off by
    /// default: anyone who can choose their address there could then claim one here.
    #[serde(default)]
    pub trust_email: bool,
}

impl OidcConfig {
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
}

impl Default for PublicConfig {
    fn default() -> Self {
        Self {
            https_listen: "0.0.0.0:443".parse().unwrap(),
            http_listen: Some("0.0.0.0:80".parse().unwrap()),
            url_port: None,
            max_connections: 10_000,
            max_connections_per_client: 256,
            header_read_timeout_secs: 30,
            upstream_response_timeout_secs: 60,
            websocket_idle_timeout_secs: 600,
            proxy_protocol: false,
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
}

impl Default for AgentsConfig {
    fn default() -> Self {
        Self {
            session_timeout_secs: 45,
            max_tunnels_per_agent: 50,
            max_ports_per_agent: 10,
            max_new_certificates_per_day: 20,
            enrollment_ttl_secs: 3600,
        }
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
}

impl Default for UsersConfig {
    fn default() -> Self {
        Self {
            session_max_age_secs: 12 * 3600,
            audit_retention_days: 90,
            members_can_publish: true,
            bootstrap_admins: Vec::new(),
            allowed_email_domains: Vec::new(),
        }
    }
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
        self.base_domain = self.base_domain.trim().trim_end_matches('.').to_ascii_lowercase();
        self.management.hostname = self.management.hostname.trim().to_ascii_lowercase();
        if self.base_domain.is_empty() || (!self.base_domain.contains('.') && self.base_domain != "localhost") {
            bail!("base_domain must be a domain such as t.example.com");
        }
        if self.management.cert_file.is_some() != self.management.key_file.is_some() {
            bail!("management.cert_file and management.key_file must be set together");
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
        Ok(())
    }

    /// This configuration as a file `load` reads back.
    pub fn to_toml(&self) -> anyhow::Result<String> {
        toml::to_string_pretty(self).context("writing the configuration as TOML")
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
        assert!(!c.oidc[0].trust_email, "trusting addresses is off unless asked for");
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
[management]
listen = "0.0.0.0:443"
hostname = "example.com"
proxy_protocol = true
[tls]
mode = "dev-ca"
[ports]
range = "65500-65535"
[users]
bootstrap_admins = ["ann@example.com"]
allowed_email_domains = ["example.com"]
[[oidc]]
id = "authentik"
label = "authentik"
issuer = "https://auth.example.com/application/o/mp/"
client_id = "c"
client_secret_file = "/data/oidc-secrets/authentik"
trust_email = true
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
        assert!(written.contains("client_secret_file = \"/data/oidc-secrets/authentik\"") && written.contains("trust_email = true"), "{written}");
    }
}
