//! Local files under `$MAGICPIPES_HOME` (default `~/.magicpipes`, mode 0700):
//!
//! | file          | contents                                         |
//! |---------------|--------------------------------------------------|
//! | `config.json` | server URL, agent credentials, extra CA (0600)   |
//! | `tunnels.json`| tunnels this agent serves (0600)                 |
//! | `agent.sock`  | IPC socket (0600, peer uid checked; `MAGICPIPES_SOCKET` overrides) |
//! | `agent.lock`  | exclusive lock held by the running agent         |
//! | `agent.pid`   | pid of the running agent                         |
//! | `agent.log`   | background agent log                             |

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

pub fn home() -> PathBuf {
    if let Some(h) = std::env::var_os("MAGICPIPES_HOME") {
        return PathBuf::from(h);
    }
    let base = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    base.join(".magicpipes")
}

pub fn ensure_home() -> anyhow::Result<PathBuf> {
    let h = home();
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&h).with_context(|| format!("creating {}", h.display()))?;
    // Tighten permissions if the directory already existed.
    std::fs::set_permissions(&h, std::fs::Permissions::from_mode(0o700))?;
    Ok(h)
}

/// IPC socket path. `MAGICPIPES_SOCKET` overrides it, e.g. when `MAGICPIPES_HOME` is so deep
/// that the path exceeds the ~104-byte Unix socket limit.
pub fn socket_path() -> PathBuf {
    match std::env::var_os("MAGICPIPES_SOCKET") {
        Some(p) => PathBuf::from(p),
        None => home().join("agent.sock"),
    }
}
pub fn lock_path() -> PathBuf {
    home().join("agent.lock")
}
pub fn pid_path() -> PathBuf {
    home().join("agent.pid")
}
pub fn log_path() -> PathBuf {
    home().join("agent.log")
}
fn config_path() -> PathBuf {
    home().join("config.json")
}
pub fn tunnels_path() -> PathBuf {
    home().join("tunnels.json")
}

/// Atomically writes a file with mode 0600.
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(tmp, path)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Management URL, e.g. `https://example.com:8443`.
    pub server: String,
    pub agent_id: String,
    pub agent_token: String,
    pub base_domain: String,
    /// Additional trusted root (PEM), e.g. a development CA. Public CAs are always trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_cert_pem: Option<String>,
}

impl AgentConfig {
    pub fn load() -> anyhow::Result<Option<Self>> {
        match std::fs::read_to_string(config_path()) {
            Ok(text) => Ok(Some(serde_json::from_str(&text).context("parsing config.json")?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).context("reading config.json"),
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        ensure_home()?;
        write_private(&config_path(), serde_json::to_string_pretty(self)?.as_bytes())?;
        Ok(())
    }
}

/// A tunnel served by this machine's agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalTunnel {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub public_url: String,
    /// Local host the agent connects to (`127.0.0.1`, `::1`, ...).
    pub host: String,
    pub port: u16,
    pub created_at: i64,
}

impl LocalTunnel {
    pub fn target(&self) -> String {
        target_url(&self.host, self.port)
    }
}

pub fn target_url(host: &str, port: u16) -> String {
    if host.contains(':') { format!("http://[{host}]:{port}") } else { format!("http://{host}:{port}") }
}

pub fn load_tunnels() -> anyhow::Result<Vec<LocalTunnel>> {
    match std::fs::read_to_string(tunnels_path()) {
        Ok(text) => Ok(serde_json::from_str(&text).context("parsing tunnels.json")?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e).context("reading tunnels.json"),
    }
}

pub fn save_tunnels(tunnels: &[LocalTunnel]) -> anyhow::Result<()> {
    ensure_home()?;
    write_private(&tunnels_path(), serde_json::to_string_pretty(tunnels)?.as_bytes())?;
    Ok(())
}
