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
use magicpipes_core::proto::Kind;
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
    // A fresh file (O_EXCL, which also refuses a symlink), so a leftover temp file can't lend
    // its permissions.
    let _ = std::fs::remove_file(&tmp);
    let mut f = crate::platform::private_options().write(true).create_new(true).open(&tmp)?;
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
    /// How the tunnel is reached publicly (absent in files from before port tunnels: `http`).
    #[serde(default, skip_serializing_if = "Kind::is_http")]
    pub kind: Kind,
    /// Port tunnels: the public port the server assigned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_port: Option<u16>,
    /// Port tunnels: client networks allowed to connect (canonical CIDRs); empty = anyone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
}

impl LocalTunnel {
    /// The local target as shown to users, e.g. `http://127.0.0.1:8080` or `tcp://127.0.0.1:5432`.
    pub fn describe(&self) -> String {
        self.target.describe(self.kind)
    }

    /// What the server stores and shows its administrators (see [`Target::server_description`]).
    pub fn server_description(&self) -> String {
        self.target.server_description(self.kind)
    }

    /// The URL to share (see [`Target::share_url`]).
    pub fn share_url(&self) -> String {
        self.target.share_url(&self.public_url)
    }
}

/// Where a tunnel's data streams go.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Target {
    /// A local port; `host` is `127.0.0.1`, `::1` or the `--host` given. TCP, except for a UDP
    /// tunnel, whose datagrams go to this UDP port.
    Port { host: String, port: u16 },
    /// A directory served by the agent's built-in file server (`--serve`); `serve` is canonical.
    Static { serve: PathBuf, list: bool },
    /// A web terminal (`--shell`): each browser session runs `shell` (argv) in a new pty in `cwd`.
    /// Read-only unless `writable`, which requires `key` (it travels in the URL fragment).
    Shell {
        shell: Vec<String>,
        cwd: PathBuf,
        writable: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key: Option<String>,
        max_clients: u16,
    },
}

impl Target {
    /// Shown to the local user; `kind` picks the scheme of a port.
    pub fn describe(&self, kind: Kind) -> String {
        match self {
            Target::Port { host, port } if kind.is_http() => target_url(host, *port),
            Target::Port { host, port } => address(kind.as_str(), host, *port),
            Target::Static { serve, .. } => format!("static:{}", display_path(serve)),
            Target::Shell { shell, writable, .. } => {
                format!("shell:{} ({})", command_line(shell), if *writable { "read-write" } else { "read-only" })
            }
        }
    }

    /// The URL to share: the public URL, plus the write key in the fragment for a writable shell.
    /// Like [`Target::describe`], minus local details the server operator has no need for: a
    /// shell's arguments (which may hold secrets) and the folder's full path (which names the
    /// local user).
    pub fn server_description(&self, kind: Kind) -> String {
        match self {
            Target::Static { serve, .. } => {
                format!("static:{}", serve.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| display_path(serve)))
            }
            Target::Shell { shell, writable, .. } => {
                format!("shell:{} ({})", program_name(shell), if *writable { "read-write" } else { "read-only" })
            }
            Target::Port { .. } => self.describe(kind),
        }
    }

    pub fn share_url(&self, public_url: &str) -> String {
        match self {
            Target::Shell { key: Some(key), writable: true, .. } => format!("{}/#k={key}", public_url.trim_end_matches('/')),
            _ => public_url.to_string(),
        }
    }

    /// Whether both point at the same place (a static tunnel's listing flag, or a shell's access
    /// settings, may differ).
    pub fn same_destination(&self, other: &Target) -> bool {
        match (self, other) {
            (Target::Port { host: h1, port: p1 }, Target::Port { host: h2, port: p2 }) => h1 == h2 && p1 == p2,
            (Target::Static { serve: a, .. }, Target::Static { serve: b, .. }) => a == b,
            (Target::Shell { shell: a, cwd: ca, .. }, Target::Shell { shell: b, cwd: cb, .. }) => a == b && ca == cb,
            _ => false,
        }
    }
}

/// A command as one line, quoting words that contain spaces or quotes.
pub fn command_line(argv: &[String]) -> String {
    let word = |w: &String| {
        if !w.is_empty() && !w.contains([' ', '\t', '"', '\'']) { w.clone() } else { format!("'{}'", w.replace('\'', "'\\''")) }
    };
    argv.iter().map(word).collect::<Vec<_>>().join(" ")
}

/// A command's program, without its directory: `zsh` for `/bin/zsh -l`.
pub fn program_name(argv: &[String]) -> String {
    let first = argv.first().map(String::as_str).unwrap_or("shell");
    first.rsplit(['/', '\\']).next().filter(|s| !s.is_empty()).unwrap_or(first).to_string()
}

/// A path without the `\\?\` prefix that canonicalization adds on Windows.
pub fn display_path(p: &Path) -> String {
    let s = p.display().to_string();
    s.strip_prefix(r"\\?\").map(str::to_string).unwrap_or(s)
}

pub fn target_url(host: &str, port: u16) -> String {
    address("http", host, port)
}

/// `scheme://host:port`, with IPv6 hosts in brackets.
pub fn address(scheme: &str, host: &str, port: u16) -> String {
    if host.contains(':') { format!("{scheme}://[{host}]:{port}") } else { format!("{scheme}://{host}:{port}") }
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
        assert_eq!(list[0].target, Target::Port { host: "127.0.0.1".into(), port: 8080 });
        assert_eq!((list[0].kind, list[0].describe()), (Kind::Http, "http://127.0.0.1:8080".to_string()));

        let t = LocalTunnel { target: Target::Static { serve: "/srv/site".into(), list: false }, ..list[0].clone() };
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!((json["serve"].as_str(), json["list"].as_bool(), json.get("port")), (Some("/srv/site"), Some(false), None));
        assert_eq!(serde_json::from_value::<LocalTunnel>(json).unwrap(), t);
        assert_eq!(t.describe(), "static:/srv/site");

        let shell = Target::Shell { shell: vec!["htop".into()], cwd: "/home/u".into(), writable: true, key: Some("k1".into()), max_clients: 5 };
        let t = LocalTunnel { target: shell, ..list[0].clone() };
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["shell"][0], "htop");
        assert_eq!(serde_json::from_value::<LocalTunnel>(json).unwrap(), t);
        assert_eq!(t.describe(), "shell:htop (read-write)");
        let secret = Target::Shell { shell: vec!["/usr/bin/psql".into(), "postgres://u:pw@db".into()], cwd: "/".into(), writable: false, key: None, max_clients: 1 };
        assert_eq!(secret.server_description(Kind::Http), "shell:psql (read-only)");
        let site = Target::Static { serve: "/home/alice/site".into(), list: true };
        assert_eq!(site.server_description(Kind::Http), "static:site");
        assert_eq!(t.target.share_url("https://a.t.test"), "https://a.t.test/#k=k1");

        let udp = LocalTunnel {
            target: Target::Port { host: "::1".into(), port: 53 },
            kind: Kind::Udp,
            public_port: Some(65501),
            allow: vec!["10.0.0.0/8".into()],
            ..list[0].clone()
        };
        let json = serde_json::to_value(&udp).unwrap();
        assert_eq!((json["kind"].as_str(), json["public_port"].as_u64()), (Some("udp"), Some(65501)));
        assert_eq!(serde_json::from_value::<LocalTunnel>(json).unwrap(), udp);
        assert_eq!(udp.describe(), "udp://[::1]:53");
        assert!(serde_json::to_value(&list[0]).unwrap().get("kind").is_none(), "HTTP tunnels keep the old file format");
    }

    #[test]
    fn command_lines_quote_where_needed() {
        let argv: Vec<String> = ["tail", "-f", "my log.txt", "it's"].map(String::from).to_vec();
        assert_eq!(command_line(&argv), r"tail -f 'my log.txt' 'it'\''s'");
    }
}
