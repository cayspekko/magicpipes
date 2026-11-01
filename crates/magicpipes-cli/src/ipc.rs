//! Local CLI <-> agent protocol over a Unix domain socket (a named pipe on Windows).
//!
//! One request per connection: the CLI writes a single JSON line ([`IpcRequest`]); the agent
//! answers with zero or more [`IpcEvent::Step`] lines followed by exactly one terminal
//! [`IpcEvent::Ok`] or [`IpcEvent::Error`] line, then closes the connection.

use magicpipes_core::error::ErrorCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

pub const MAX_LINE: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IpcRequest {
    Add(AddRequest),
    Remove { selector: String, force: bool },
    List,
    Status,
    /// Stop the agent. With `if_idle`, only if it serves no tunnels and runs no operations.
    Shutdown { if_idle: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddRequest {
    /// Local port; absent when serving a directory or a shell.
    pub port: Option<u16>,
    /// Directory for the built-in file server (absolute, resolved by the CLI).
    #[serde(default)]
    pub serve: Option<std::path::PathBuf>,
    /// With `serve`: list directory contents.
    #[serde(default)]
    pub list: bool,
    /// Web terminal: the command to run (argv, never empty; the CLI fills in the login shell).
    #[serde(default)]
    pub shell: Option<Vec<String>>,
    /// With `shell`: working directory (absolute, from the CLI).
    #[serde(default)]
    pub cwd: Option<std::path::PathBuf>,
    /// With `shell`: allow typing (needs the secret key from the share URL).
    #[serde(default)]
    pub writable: bool,
    /// With `shell`: concurrent sessions allowed.
    #[serde(default)]
    pub max_clients: Option<u16>,
    /// `tcp` or `udp` for a raw public port instead of an HTTPS hostname.
    #[serde(default)]
    pub kind: magicpipes_core::proto::Kind,
    /// Port tunnels: a specific public port.
    #[serde(default)]
    pub remote_port: Option<u16>,
    /// Port tunnels: client networks allowed to connect.
    #[serde(default)]
    pub allow: Vec<String>,
    pub host: Option<String>,
    pub name: Option<String>,
    pub probe_path: String,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    Local,
    Connect,
    Register,
    Tls,
    /// Port tunnels: the server opens a stream to the local service through the agent.
    Check,
    Probe,
}

impl Step {
    pub fn label(self) -> &'static str {
        match self {
            Step::Local => "Checking local service...",
            Step::Connect => "Connecting to server...",
            Step::Register => "Registering tunnel...",
            Step::Tls => "Checking HTTPS certificate...",
            Step::Check => "Checking tunnel...",
            Step::Probe => "Verifying public endpoint...",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Running,
    Done,
    Failed,
    /// Did not pass, but does not fail the operation (e.g. a public port this machine can't reach).
    Warned,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum IpcEvent {
    Step { step: Step, state: StepState },
    Ok { data: Value },
    Error(ErrorInfo),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorInfo {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<Step>,
}

impl ErrorInfo {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::wire(code.as_str(), message)
    }
    /// A code received from the server or the agent, passed through even if this build does not
    /// know it.
    pub fn wire(code: &str, message: impl Into<String>) -> Self {
        Self { code: code.into(), message: message.into(), step: None }
    }
    pub fn is(&self, code: ErrorCode) -> bool {
        self.code == code.as_str()
    }
    pub fn at(mut self, step: Step) -> Self {
        self.step = Some(step);
        self
    }
}

impl std::fmt::Display for ErrorInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ErrorInfo {}

pub async fn write_line<T: Serialize>(w: &mut (impl AsyncWriteExt + Unpin), v: &T) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(v)?;
    line.push(b'\n');
    w.write_all(&line).await
}

/// Sends a request and feeds step events to `on_step`; returns the terminal result.
pub async fn call(
    stream: impl AsyncRead + AsyncWrite,
    req: &IpcRequest,
    mut on_step: impl FnMut(Step, StepState),
) -> Result<Value, ErrorInfo> {
    let (r, mut w) = tokio::io::split(stream);
    write_line(&mut w, req).await.map_err(|e| ErrorInfo::new(ErrorCode::AgentUnavailable, format!("talking to agent: {e}")))?;
    let mut lines = BufReader::new(r).lines();
    loop {
        let line = match lines.next_line().await {
            Ok(Some(l)) => l,
            Ok(None) => return Err(ErrorInfo::new(ErrorCode::AgentUnavailable, "agent closed the connection unexpectedly")),
            Err(e) => return Err(ErrorInfo::new(ErrorCode::AgentUnavailable, format!("reading from agent: {e}"))),
        };
        match serde_json::from_str::<IpcEvent>(&line) {
            Ok(IpcEvent::Step { step, state }) => on_step(step, state),
            Ok(IpcEvent::Ok { data }) => return Ok(data),
            Ok(IpcEvent::Error(e)) => return Err(e),
            Err(e) => return Err(ErrorInfo::new(ErrorCode::AgentProtocol, format!("invalid agent response: {e}"))),
        }
    }
}
