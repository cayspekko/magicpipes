//! Local CLI <-> agent protocol over a Unix domain socket (a named pipe on Windows).
//!
//! One request per connection: the CLI writes a single JSON line ([`IpcRequest`]); the agent
//! answers with zero or more [`IpcEvent::Step`] lines followed by exactly one terminal
//! [`IpcEvent::Ok`] or [`IpcEvent::Error`] line, then closes the connection.

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
    /// Local port; absent when serving a directory.
    pub port: Option<u16>,
    /// Directory for the built-in file server (absolute, resolved by the CLI).
    #[serde(default)]
    pub serve: Option<std::path::PathBuf>,
    /// With `serve`: list directory contents.
    #[serde(default)]
    pub list: bool,
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
    Probe,
}

impl Step {
    pub fn label(self) -> &'static str {
        match self {
            Step::Local => "Checking local service...",
            Step::Connect => "Connecting to server...",
            Step::Register => "Registering tunnel...",
            Step::Tls => "Checking HTTPS certificate...",
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
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self { code: code.into(), message: message.into(), step: None }
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
    write_line(&mut w, req).await.map_err(|e| ErrorInfo::new("agent_unavailable", format!("talking to agent: {e}")))?;
    let mut lines = BufReader::new(r).lines();
    loop {
        let line = match lines.next_line().await {
            Ok(Some(l)) => l,
            Ok(None) => return Err(ErrorInfo::new("agent_unavailable", "agent closed the connection unexpectedly")),
            Err(e) => return Err(ErrorInfo::new("agent_unavailable", format!("reading from agent: {e}"))),
        };
        match serde_json::from_str::<IpcEvent>(&line) {
            Ok(IpcEvent::Step { step, state }) => on_step(step, state),
            Ok(IpcEvent::Ok { data }) => return Ok(data),
            Ok(IpcEvent::Error(e)) => return Err(e),
            Err(e) => return Err(ErrorInfo::new("agent_protocol", format!("invalid agent response: {e}"))),
        }
    }
}
