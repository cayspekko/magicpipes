//! Local files under `$MAGICPIPES_HOME` (default `~/.magicpipes`, or `%USERPROFILE%\.magicpipes`
//! on Windows; mode 0700 on Unix):
//!
//! | file          | contents                                         |
//! |---------------|--------------------------------------------------|
//! | `config.json` | server URL, agent credentials, extra CA (0600)   |
//! | `tunnels.json`| tunnels this agent serves (0600)                 |
//! | `agent.sock`  | IPC socket on Unix (0600, peer uid checked; `MAGICPIPES_SOCKET` overrides; a named pipe on Windows) |
//! | `agent.lock`  | exclusive lock held by the running agent         |
//! | `agent.pid`   | pid of the running agent                         |
//! | `agent.log`   | background agent log                             |

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

pub fn home() -> PathBuf {
    if let Some(h) = std::env::var_os("MAGICPIPES_HOME") {
        return PathBuf::from(h);
    }
    let base = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join(".magicpipes")
}

pub fn ensure_home() -> anyhow::Result<PathBuf> {
    let h = home();
    crate::platform::create_private_dir(&h).with_context(|| format!("creating {}", h.display()))?;
    Ok(h)
}

/// IPC socket path. `MAGICPIPES_SOCKET` overrides it, e.g. when `MAGICPIPES_HOME` is so deep
/// that the path exceeds the ~104-byte Unix socket limit. (Windows uses a named pipe instead.)
#[cfg(unix)]
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

/// Atomically writes a file readable only by the current user (mode 0600 on Unix).
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = crate::platform::private_options().write(true).create(true).truncate(true).open(&tmp)?;
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
    #[serde(flatten)]
    pub target: Target,
    pub created_at: i64,
}

/// Where a tunnel's data streams go.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Target {
    /// A local TCP service; `host` is `127.0.0.1`, `::1` or the `--host` given.
    Tcp { host: String, port: u16 },
    /// A directory served by the agent's built-in file server (`--serve`); `serve` is canonical.
    Static { serve: PathBuf, list: bool },
}

impl Target {
    /// Shown to users and stored on the server for display.
    pub fn describe(&self) -> String {
        match self {
            Target::Tcp { host, port } => target_url(host, *port),
            Target::Static { serve, .. } => format!("static:{}", display_path(serve)),
        }
    }

    /// Whether both point at the same place (a static tunnel's listing flag may differ).
    pub fn same_destination(&self, other: &Target) -> bool {
        match (self, other) {
            (Target::Tcp { host: h1, port: p1 }, Target::Tcp { host: h2, port: p2 }) => h1 == h2 && p1 == p2,
            (Target::Static { serve: a, .. }, Target::Static { serve: b, .. }) => a == b,
            _ => false,
        }
    }
}

/// A path without the `\\?\` prefix that canonicalization adds on Windows.
pub fn display_path(p: &Path) -> String {
    let s = p.display().to_string();
    s.strip_prefix(r"\\?\").map(str::to_string).unwrap_or(s)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnels_json_round_trips_and_reads_older_files() {
        let old = r#"[{"id":"tn_1","name":"a","hostname":"a.t.test","public_url":"https://a.t.test","host":"127.0.0.1","port":8080,"created_at":1}]"#;
        let list: Vec<LocalTunnel> = serde_json::from_str(old).unwrap();
        assert_eq!(list[0].target, Target::Tcp { host: "127.0.0.1".into(), port: 8080 });
        assert_eq!(list[0].target.describe(), "http://127.0.0.1:8080");

        let t = LocalTunnel { target: Target::Static { serve: "/srv/site".into(), list: false }, ..list[0].clone() };
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!((json["serve"].as_str(), json["list"].as_bool(), json.get("port")), (Some("/srv/site"), Some(false), None));
        assert_eq!(serde_json::from_value::<LocalTunnel>(json).unwrap(), t);
        assert_eq!(t.target.describe(), "static:/srv/site");
    }
}
