//! `magicpipesd.toml` configuration. Every field except `base_domain` and
//! `management.hostname` has a default.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
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
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PublicConfig {
    pub https_listen: SocketAddr,
    /// Plain HTTP: ACME HTTP-01 challenges and redirects to HTTPS.
    pub http_listen: Option<SocketAddr>,
    /// Port shown in public URLs. Defaults to the `https_listen` port (omitted when 443).
    pub url_port: Option<u16>,
    pub max_connections: usize,
    pub header_read_timeout_secs: u64,
    /// Time allowed for the local application to start answering a request.
    pub upstream_response_timeout_secs: u64,
    /// Upgraded (WebSocket) connections are closed after this long without traffic.
    pub websocket_idle_timeout_secs: u64,
}

impl Default for PublicConfig {
    fn default() -> Self {
        Self {
            https_listen: "0.0.0.0:443".parse().unwrap(),
            http_listen: Some("0.0.0.0:80".parse().unwrap()),
            url_port: None,
            max_connections: 10_000,
            header_read_timeout_secs: 30,
            upstream_response_timeout_secs: 60,
            websocket_idle_timeout_secs: 600,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementConfig {
    #[serde(default = "default_mgmt_listen")]
    pub listen: SocketAddr,
    /// Hostname of the management UI/API and agent endpoint, e.g. `example.com`.
    pub hostname: String,
    /// Optional externally provisioned certificate for the management hostname.
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TlsMode {
    /// Per-hostname certificates from an ACME CA (HTTP-01 challenge on `http_listen`).
    Acme,
    /// A certificate/key pair (typically a wildcard) provisioned externally.
    Files,
    /// A local development CA generated in `data_dir`. Never use in production.
    DevCa,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AgentsConfig {
    /// Sessions without a ping for this long are dropped.
    pub session_timeout_secs: u64,
    pub max_tunnels_per_agent: usize,
    /// Lifetime of enrollment tokens created by `magicpipesd enroll` / the UI.
    pub enrollment_ttl_secs: u64,
}

impl Default for AgentsConfig {
    fn default() -> Self {
        Self { session_timeout_secs: 45, max_tunnels_per_agent: 50, enrollment_ttl_secs: 3600 }
    }
}

/// Raw TCP and UDP port tunnels (`magicpipes add 5432 --tcp`). Off unless `range` is set.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PortsConfig {
    /// Ports handed out to tunnels, e.g. `"65500-65535"`. Each is used for TCP and for UDP.
    pub range: Option<String>,
    /// Address the port listeners bind to.
    pub bind: IpAddr,
    /// Host shown in `tcp://` and `udp://` URLs. Defaults to `management.hostname`.
    pub public_host: Option<String>,
    /// TCP connections start with a PROXY protocol header (v1 or v2) from a load balancer such as
    /// HAProxy, which carries the real client address. Only enable this behind such a proxy.
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

    fn validate(&mut self) -> anyhow::Result<()> {
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
        Ok(())
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
}
