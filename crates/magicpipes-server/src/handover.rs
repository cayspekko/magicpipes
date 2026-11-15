//! Moving to a new version of the server without downtime, on Linux and macOS.
//!
//! The running server (the old process) is asked to by `magicpipesd --upgrade`, the Settings page
//! or `SIGUSR2` (`systemctl reload`). It then:
//!
//! 1. runs the new binary's `--version`, which must work;
//! 2. backs up the database into `<data_dir>/backups`;
//! 3. has the new binary migrate a copy of it (`magicpipesd rehearse`), and read the configuration;
//! 4. starts the new binary with its listening sockets ([`magicpipes_core::fds`]), so none is ever
//!    closed, and waits until it says it's ready over a socket of their own ([`SOCKET_ENV`]);
//! 5. stops accepting connections, finishes the requests under way on those it has, and asks each
//!    agent to connect again ([`ServerOpen::Reconnect`](magicpipes_core::proto::ServerOpen)),
//!    which reaches the new process; an agent before protocol 12 is closed once its connection is
//!    idle, and reconnects. Meanwhile the new process holds requests for those agents' tunnels
//!    until they arrive (`[upgrades] hold_secs`);
//! 6. waits for what's left on its agent connections, up to `[upgrades] drain_secs`, then exits.
//!
//! Under systemd (`Type=notify`, `NotifyAccess=all`), the new process names itself the service's
//! main process before the old one exits. A failure before step 5 leaves the old process serving
//! as before. What can't move between processes starts over: pending sign-ins, rate-limit counts,
//! the last day of history kept in memory (the database keeps the 5-minute rollups), and UDP flows.
//! Progress is kept in `<data_dir>/upgrade-status.json` ([`Status`]), which the Settings page and
//! `magicpipesd --upgrade` follow.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use magicpipes_core::{secret, unix_now, upgrade};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::control::ControlPlane;

/// Names the socket the old process listens on for the new one; set only for the new one.
pub const SOCKET_ENV: &str = "MAGICPIPESD_HANDOVER";
const STATUS_FILE: &str = "upgrade-status.json";
const REQUEST_FILE: &str = "upgrade-request.json";
const PID_FILE: &str = "magicpipesd.pid";
const BACKUPS: &str = "backups";
const KEEP_BACKUPS: usize = 5;
/// How long the old process waits for the new one to connect, and then to be ready (its
/// migrations, certificates and listeners).
const HELLO_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(unix)]
const READY_TIMEOUT: Duration = Duration::from_secs(180);
const REHEARSE_TIMEOUT: Duration = Duration::from_secs(300);
/// A request file older than this is left over, not a request.
#[cfg(unix)]
const REQUEST_FRESH_SECS: i64 = 600;
/// After asking an agent to reconnect, how long before its idle connections here are closed
/// anyway: by then it has connected to the new process, or it reconnects when they close.
const RECONNECT_GRACE: Duration = Duration::from_secs(2);
/// The longest line on the handover socket.
const MAX_LINE: u64 = 1024 * 1024;

/// What the steps are called, in order, for the Settings page and `--upgrade`.
pub const STEPS: [&str; 7] = [
    "Downloading the new version",
    "Checking the new binary",
    "Backing up the database",
    "Trying the new version on a copy of the database",
    "Starting the new version",
    "Moving machines to it",
    "Finishing requests under way",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Running,
    Done,
    Failed,
}

/// The last handover, as it went.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub id: String,
    pub state: State,
    /// The step under way, or the last one reached ([`STEPS`]).
    pub step: usize,
    /// The version handing over, and the one taking over once known.
    pub from: String,
    #[serde(default)]
    pub to: Option<String>,
    /// Why it failed, or what's worth knowing once it's done.
    #[serde(default)]
    pub message: Option<String>,
    /// The backup taken in step 2.
    #[serde(default)]
    pub backup: Option<String>,
    /// The process serving once it's done.
    #[serde(default)]
    pub pid: Option<u32>,
    pub started_at: i64,
    #[serde(default)]
    pub finished_at: Option<i64>,
}

/// The first step, when the server downloads the new version itself (the Settings page).
pub fn downloading(data_dir: &Path, id: &str, to: &str) {
    let status = Status {
        id: id.into(),
        state: State::Running,
        step: 0,
        from: magicpipes_core::VERSION.into(),
        to: Some(to.into()),
        message: None,
        backup: None,
        pid: None,
        started_at: unix_now(),
        finished_at: None,
    };
    write_status(data_dir, &status);
}

/// The download, or what came before the handover, failed.
pub fn failed_before(data_dir: &Path, id: &str, to: &str, why: &str) {
    let mut status = read_status(data_dir).filter(|s| s.id == id).unwrap_or(Status {
        id: id.into(),
        state: State::Failed,
        step: 0,
        from: magicpipes_core::VERSION.into(),
        to: Some(to.into()),
        message: None,
        backup: None,
        pid: None,
        started_at: unix_now(),
        finished_at: None,
    });
    status.state = State::Failed;
    status.message = Some(why.into());
    status.finished_at = Some(unix_now());
    write_status(data_dir, &status);
}

/// Whether a handover is under way, as the status file says: one that's been running for an
/// hour is taken to have stopped with its process.
pub fn under_way(data_dir: &Path) -> bool {
    read_status(data_dir).is_some_and(|s| s.state == State::Running && unix_now() - s.started_at < 3600)
}

pub fn read_status(data_dir: &Path) -> Option<Status> {
    serde_json::from_slice(&std::fs::read(data_dir.join(STATUS_FILE)).ok()?).ok()
}

fn write_status(data_dir: &Path, status: &Status) {
    match serde_json::to_vec_pretty(status) {
        Ok(json) => {
            if let Err(e) = crate::certs::write_private(&data_dir.join(STATUS_FILE), &json) {
                tracing::warn!(error = %e, "couldn't write the upgrade's status");
            }
        }
        Err(e) => tracing::warn!(error = %e, "couldn't write the upgrade's status"),
    }
}

/// The running server, for `magicpipesd --upgrade`: written once it serves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Running {
    pub pid: u32,
    /// Its binary.
    pub exe: Option<PathBuf>,
    pub version: String,
}

pub fn write_pid(data_dir: &Path) {
    let running = Running { pid: std::process::id(), exe: upgrade::exe().map(Path::to_path_buf), version: magicpipes_core::VERSION.into() };
    if let Ok(json) = serde_json::to_vec(&running)
        && let Err(e) = crate::certs::write_private(&data_dir.join(PID_FILE), &json)
    {
        tracing::warn!(error = %e, "couldn't write the pid file");
    }
}

pub fn read_pid(data_dir: &Path) -> Option<Running> {
    serde_json::from_slice(&std::fs::read(data_dir.join(PID_FILE)).ok()?).ok()
}

/// At exit: the pid file goes, unless a newer process has written its own.
pub fn remove_pid(data_dir: &Path) {
    if read_pid(data_dir).is_some_and(|r| r.pid == std::process::id()) {
        let _ = std::fs::remove_file(data_dir.join(PID_FILE));
    }
}

/// What `magicpipesd --upgrade` asks of the running server before it signals it: names the
/// handover, so it can follow the status. Not secret, so readable by the server's user even when
/// root wrote it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestFile {
    pub id: String,
    #[serde(default)]
    pub to: Option<String>,
    pub at: i64,
}

pub fn write_request(data_dir: &Path, req: &RequestFile) -> std::io::Result<()> {
    let path = data_dir.join(REQUEST_FILE);
    std::fs::write(&path, serde_json::to_vec(req).map_err(std::io::Error::other)?)?;
    #[cfg(unix)]
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o644))?;
    Ok(())
}

#[cfg(unix)]
fn take_request(data_dir: &Path) -> Option<RequestFile> {
    let path = data_dir.join(REQUEST_FILE);
    let req: Option<RequestFile> = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok());
    let _ = std::fs::remove_file(&path);
    req.filter(|r| unix_now() - r.at < REQUEST_FRESH_SECS)
}

/// A handover someone asked for.
#[derive(Debug, Clone)]
pub struct Ask {
    pub id: String,
    /// The version expected, if the asker knows.
    pub to: Option<String>,
}

impl Ask {
    pub fn new(to: Option<String>) -> Self {
        Self { id: secret::random_string(12), to }
    }

    /// For `SIGUSR2`: what `magicpipesd --upgrade` wrote, if it did.
    #[cfg(unix)]
    pub fn from_signal(data_dir: &Path) -> Self {
        match take_request(data_dir) {
            Some(r) => Self { id: r.id, to: r.to },
            None => Self::new(None),
        }
    }
}

/// Why this server can't hand over to a new version without downtime, if it can't.
pub fn blocker() -> Option<String> {
    if !cfg!(unix) {
        return Some("a handover without downtime needs Linux or macOS; on Windows, restart the service once the new binary is in place".into());
    }
    if upgrade::in_container() {
        return Some("it runs in a container, which goes when its first process does: pull the new image and recreate the container".into());
    }
    if under_systemd() && std::env::var_os("NOTIFY_SOCKET").is_none() {
        return Some(
            "systemd runs it with Type=simple, and would stop the new process with the old one: set Type=notify and NotifyAccess=all in its unit (README \"systemd\")"
                .into(),
        );
    }
    if under_launchd() {
        return Some("launchd runs it, which can't follow a new process: restart the service once the new binary is in place".into());
    }
    None
}

/// Whether launchd started this process as a job: then launchd is its parent. (Apps pass the
/// variable on to everything they start, so it alone says nothing.)
fn under_launchd() -> bool {
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("XPC_SERVICE_NAME").is_some_and(|v| v != "0") && std::os::unix::process::parent_id() == 1
    }
    #[cfg(not(target_os = "macos"))]
    false
}

/// Whether systemd started this process as a service's main process.
fn under_systemd() -> bool {
    if std::env::var_os("INVOCATION_ID").is_none() {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        // Other processes can inherit INVOCATION_ID: what counts is systemd being the parent.
        let parent = std::os::unix::process::parent_id();
        std::fs::read_to_string(format!("/proc/{parent}/comm")).is_ok_and(|c| c.trim() == "systemd")
    }
    #[cfg(not(target_os = "linux"))]
    false
}

/// Tells systemd something (`sd_notify`), if it's listening. Nothing otherwise.
pub fn notify(message: &str) {
    #[cfg(unix)]
    {
        let Some(path) = std::env::var_os("NOTIFY_SOCKET") else { return };
        let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() else { return };
        let bytes = std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str());
        let sent = match bytes.split_first() {
            #[cfg(target_os = "linux")]
            Some((b'@', name)) => {
                use std::os::linux::net::SocketAddrExt;
                std::os::unix::net::SocketAddr::from_abstract_name(name).and_then(|a| sock.send_to_addr(message.as_bytes(), &a))
            }
            _ => sock.send_to(message.as_bytes(), &path),
        };
        if let Err(e) = sent {
            tracing::warn!(error = %e, "couldn't tell systemd");
        }
    }
    #[cfg(not(unix))]
    let _ = message;
}

/// One line on the handover socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Message {
    /// New to old: it's running.
    Hello { pid: u32, version: String },
    /// Old to new: the agents connected to it, whose tunnels' requests wait for them.
    Agents { agents: Vec<String> },
    /// New to old: it accepts connections now.
    Ready,
    /// New to old: it stops, and why.
    Failed { why: String },
    /// Old to new: it no longer accepts; the new one starts its own background work.
    Go,
    /// Old to new: it's about to exit.
    Exiting,
    /// New to old: it's the service's main process now.
    Bye,
}

/// The handover socket. Windows has no handover (`blocker`): there, nothing makes one, and
/// connecting fails.
#[cfg(unix)]
type Stream = tokio::net::UnixStream;
#[cfg(not(unix))]
type Stream = tokio::io::DuplexStream;

async fn connect(path: &Path) -> std::io::Result<Stream> {
    #[cfg(unix)]
    {
        tokio::net::UnixStream::connect(path).await
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(std::io::Error::other("a handover needs Linux or macOS"))
    }
}

struct Line {
    reader: BufReader<tokio::io::ReadHalf<Stream>>,
    writer: tokio::io::WriteHalf<Stream>,
}

impl Line {
    fn new(stream: Stream) -> Self {
        let (r, w) = tokio::io::split(stream);
        Self { reader: BufReader::new(r), writer: w }
    }

    async fn send(&mut self, m: &Message) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(m).map_err(std::io::Error::other)?;
        line.push(b'\n');
        self.writer.write_all(&line).await
    }

    /// The next message; `None` once the other side has gone.
    async fn recv(&mut self) -> Option<Message> {
        let mut line = String::new();
        let n = tokio::io::AsyncReadExt::take(&mut self.reader, MAX_LINE).read_line(&mut line).await.ok()?;
        if n == 0 {
            return None;
        }
        serde_json::from_str(&line).ok()
    }
}

// ---- the new process ---------------------------------------------------------------------

/// A process started by an older one handing over to it.
pub struct Joining {
    line: Line,
    /// The agents connected to the old process.
    pub agents: HashSet<String>,
}

/// If an older process started this one to hand over to it: connects to it, and learns which
/// agents are coming. Call before binding anything.
pub async fn join(socket: Option<PathBuf>) -> anyhow::Result<Option<Joining>> {
    let Some(path) = socket else { return Ok(None) };
    let stream = tokio::time::timeout(HELLO_TIMEOUT, connect(&path))
        .await
        .map_err(|_| anyhow::anyhow!("the older process didn't answer at {}", path.display()))??;
    let mut line = Line::new(stream);
    line.send(&Message::Hello { pid: std::process::id(), version: magicpipes_core::VERSION.into() }).await?;
    match tokio::time::timeout(HELLO_TIMEOUT, line.recv()).await {
        Ok(Some(Message::Agents { agents })) => Ok(Some(Joining { line, agents: agents.into_iter().collect() })),
        _ => anyhow::bail!("the older process didn't say which agents to expect"),
    }
}

impl Joining {
    /// Says it's ready, and waits until the old process has stopped accepting: then this one
    /// starts its background work. If the old one has gone, it goes on anyway.
    pub async fn ready(&mut self) {
        if self.line.send(&Message::Ready).await.is_err() {
            return;
        }
        loop {
            match self.line.recv().await {
                Some(Message::Go) | None => return,
                Some(_) => {}
            }
        }
    }

    pub async fn failed(mut self, why: String) {
        let _ = self.line.send(&Message::Failed { why }).await;
    }

    /// Becomes the service's main process when the old one says it's leaving.
    pub fn take_over(mut self) {
        tokio::spawn(async move {
            loop {
                match self.line.recv().await {
                    Some(Message::Exiting) => {
                        notify(&format!("MAINPID={}\nREADY=1", std::process::id()));
                        let _ = self.line.send(&Message::Bye).await;
                    }
                    None => return,
                    Some(_) => {}
                }
            }
        });
    }
}

// ---- the old process ---------------------------------------------------------------------

/// What the running server hands over.
pub struct Old {
    pub data_dir: PathBuf,
    pub config_path: PathBuf,
    pub control: Arc<ControlPlane>,
    /// Its open ports and the listeners `main` serves, by name: other descriptors for their
    /// sockets, which a new process takes over.
    #[cfg(unix)]
    pub data: Arc<crate::data::DataPlane>,
    #[cfg(unix)]
    pub listeners: Vec<(String, std::os::fd::OwnedFd)>,
    pub busy: AtomicBool,
}

/// A new process that's ready to take over.
pub struct Handing {
    line: Line,
    child: tokio::process::Child,
    status: Status,
    socket: PathBuf,
}

impl Old {
    fn update(&self, status: &mut Status, step: usize) {
        status.step = step;
        write_status(&self.data_dir, status);
        tracing::info!(step = STEPS[step], "upgrade");
    }

    fn fail(&self, mut status: Status, why: String) -> String {
        tracing::error!(why = %why, "the upgrade stopped; this version carries on");
        status.state = State::Failed;
        status.message = Some(why.clone());
        status.finished_at = Some(unix_now());
        write_status(&self.data_dir, &status);
        why
    }

    /// Steps 1 to 4: the new binary at this one's path, checked, tried on a copy of the
    /// database, and started with the listeners, ready to take over. On failure, it's stopped,
    /// the status says why, and this server carries on as before.
    pub async fn prepare(&self, ask: &Ask) -> Result<Handing, String> {
        if self.busy.swap(true, Ordering::SeqCst) {
            return Err("an upgrade is already under way".into());
        }
        let result = self.prepare_once(ask).await;
        if result.is_err() {
            self.busy.store(false, Ordering::SeqCst);
        }
        result
    }

    async fn prepare_once(&self, ask: &Ask) -> Result<Handing, String> {
        let mut status = Status {
            id: ask.id.clone(),
            state: State::Running,
            step: 1,
            from: magicpipes_core::VERSION.into(),
            to: ask.to.clone(),
            message: None,
            backup: None,
            pid: None,
            started_at: unix_now(),
            finished_at: None,
        };
        if let Some(why) = blocker() {
            return Err(self.fail(status, format!("this server can't hand over without downtime: {why}")));
        }
        let Some(exe) = upgrade::exe().map(Path::to_path_buf) else {
            return Err(self.fail(status, "this server doesn't know where its binary is".into()));
        };
        self.update(&mut status, 1);
        let tested = {
            let exe = exe.clone();
            tokio::task::spawn_blocking(move || upgrade::self_test(&exe, "magicpipesd")).await
        };
        match tested {
            Ok(Ok(said)) => status.to = said.split_whitespace().nth(1).map(str::to_string).or(status.to),
            Ok(Err(e)) => return Err(self.fail(status, e.message)),
            Err(e) => return Err(self.fail(status, e.to_string())),
        }

        self.update(&mut status, 2);
        match self.backup().await {
            Ok(path) => status.backup = Some(path.display().to_string()),
            Err(e) => return Err(self.fail(status, format!("backing up the database: {e}"))),
        }

        self.update(&mut status, 3);
        if let Err(e) = self.rehearse(&exe).await {
            return Err(self.fail(status, e));
        }

        self.update(&mut status, 4);
        match self.start_new(&exe).await {
            Ok((line, child, socket)) => Ok(Handing { line, child, status, socket }),
            Err(e) => Err(self.fail(status, e)),
        }
    }

    /// A copy of the database in `<data_dir>/backups`, keeping the newest few.
    async fn backup(&self) -> anyhow::Result<PathBuf> {
        let dir = self.data_dir.join(BACKUPS);
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(&dir)?;
        let stamp = magicpipes_core::rfc3339(unix_now()).replace(['-', ':'], "").replace('T', "-").trim_end_matches('Z').to_string();
        let path = dir.join(format!("magicpipes-{}-{stamp}.db", magicpipes_core::VERSION));
        let (control, to) = (self.control.clone(), path.clone());
        tokio::task::spawn_blocking(move || control.copy_database(&to)).await??;
        let mut kept: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(&dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".db"))
            .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
            .collect();
        kept.sort();
        let extra = kept.len().saturating_sub(KEEP_BACKUPS);
        for (_, old) in kept.into_iter().take(extra) {
            let _ = std::fs::remove_file(old);
        }
        Ok(path)
    }

    /// Has the new binary read the configuration and migrate a copy of the database.
    async fn rehearse(&self, exe: &Path) -> Result<(), String> {
        let copy = self.data_dir.join("rehearsal.db");
        let remove = || {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                let mut name = copy.as_os_str().to_owned();
                name.push(suffix);
                let _ = std::fs::remove_file(PathBuf::from(name));
            }
        };
        remove();
        let (control, to) = (self.control.clone(), copy.clone());
        match tokio::task::spawn_blocking(move || control.copy_database(&to)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(format!("copying the database: {e:#}")),
            Err(e) => return Err(e.to_string()),
        }
        let run = tokio::process::Command::new(exe)
            .arg("--config")
            .arg(&self.config_path)
            .arg("rehearse")
            .arg("--database")
            .arg(&copy)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .output();
        let result = match tokio::time::timeout(REHEARSE_TIMEOUT, run).await {
            Err(_) => Err("the new version didn't finish migrating a copy of the database in time".to_string()),
            Ok(Err(e)) => Err(format!("running the new version: {e}")),
            Ok(Ok(out)) if out.status.success() => Ok(()),
            Ok(Ok(out)) => {
                let said = String::from_utf8_lossy(&out.stderr);
                let last = said.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").trim();
                let last: String = last.chars().take(500).collect();
                Err(format!("the new version refused this server's configuration or database: {last}"))
            }
        };
        remove();
        result
    }

    /// Step 4: starts `exe` with the listeners, and waits until it's ready.
    async fn start_new(&self, exe: &Path) -> Result<(Line, tokio::process::Child, PathBuf), String> {
        #[cfg(not(unix))]
        {
            let _ = exe;
            Err("a handover needs Linux or macOS".into())
        }
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let socket = self.data_dir.join(format!("handover-{}.sock", std::process::id()));
            let _ = std::fs::remove_file(&socket);
            let listener = tokio::net::UnixListener::bind(&socket).map_err(|e| format!("listening on {}: {e}", socket.display()))?;
            let mut fds: Vec<(String, std::os::fd::RawFd)> = self.listeners.iter().map(|(n, fd)| (n.clone(), fd.as_raw_fd())).collect();
            fds.extend(self.data.port_fds());
            let mut cmd = std::process::Command::new(exe);
            cmd.arg("--config").arg(&self.config_path).arg("run").env(SOCKET_ENV, &socket).stdin(std::process::Stdio::null());
            magicpipes_core::fds::pass(&mut cmd, &fds);
            // Killed if this stops halfway (the task preparing it aborted); `finish` lets it go.
            let mut child = tokio::process::Command::from(cmd).kill_on_drop(true).spawn().map_err(|e| format!("starting the new version: {e}"))?;
            let pid = child.id().unwrap_or(0);
            tracing::info!(pid, sockets = fds.len(), "started the new version");
            let result = self.await_ready(&listener, &mut child).await;
            let _ = std::fs::remove_file(&socket);
            match result {
                Ok(line) => Ok((line, child, socket)),
                Err(why) => {
                    let _ = child.start_kill();
                    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
                    Err(why)
                }
            }
        }
    }

    #[cfg(unix)]
    async fn await_ready(&self, listener: &tokio::net::UnixListener, child: &mut tokio::process::Child) -> Result<Line, String> {
        let gone = |status: std::io::Result<std::process::ExitStatus>| match status {
            Ok(s) => format!("the new version stopped ({s}) before it was ready; its log says why"),
            Err(e) => format!("the new version stopped before it was ready: {e}"),
        };
        let stream = tokio::select! {
            accepted = tokio::time::timeout(HELLO_TIMEOUT, listener.accept()) => match accepted {
                Ok(Ok((s, _))) => s,
                Ok(Err(e)) => return Err(format!("the new version couldn't connect: {e}")),
                Err(_) => return Err("the new version didn't start in time".into()),
            },
            status = child.wait() => return Err(gone(status)),
        };
        let mut line = Line::new(stream);
        match tokio::time::timeout(HELLO_TIMEOUT, line.recv()).await {
            Ok(Some(Message::Hello { version, .. })) => tracing::info!(%version, "the new version is starting"),
            _ => return Err("the new version didn't say hello".into()),
        }
        let agents: Vec<String> = self.control.connected_agents().into_iter().collect();
        line.send(&Message::Agents { agents }).await.map_err(|e| format!("talking to the new version: {e}"))?;
        tokio::select! {
            said = tokio::time::timeout(READY_TIMEOUT, line.recv()) => match said {
                Ok(Some(Message::Ready)) => Ok(line),
                Ok(Some(Message::Failed { why })) => Err(format!("the new version couldn't start: {why}")),
                Ok(_) => Err("the new version stopped before it was ready; its log says why".into()),
                Err(_) => Err("the new version wasn't ready in time".into()),
            },
            status = child.wait() => Err(gone(status)),
        }
    }
}

impl Old {
    /// Step 6: closes agent connections as they go idle (after giving those asked to reconnect
    /// at `asked` a moment), and waits for this server's other connections to finish, up to
    /// `drain`; then closes what's left.
    pub async fn drain(&self, asked: std::time::Instant, tracker: &tokio_util::task::TaskTracker, drain: Duration) {
        let deadline = tokio::time::Instant::now() + drain;
        loop {
            let left = self.control.close_idle_sessions(asked, RECONNECT_GRACE);
            if left == 0 && tracker.is_empty() {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!(agent_connections = left, connections = tracker.len(), "closing what's still open after upgrades.drain_secs");
                self.control.close_sessions();
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

impl Handing {
    /// The new process may start its background work: this one has stopped accepting.
    pub async fn go(&mut self, old: &Old) {
        old.update(&mut self.status, 5);
        if self.line.send(&Message::Go).await.is_err() {
            tracing::error!("the new version went away after it was ready");
        }
    }

    pub fn finishing(&mut self, old: &Old) {
        old.update(&mut self.status, 6);
    }

    /// Says it's done, waits for the new process to become the service's main one, and lets go
    /// of it.
    pub async fn finish(self, old: &Old) {
        let Handing { mut line, mut child, mut status, socket } = self;
        let alive = matches!(child.try_wait(), Ok(None));
        status.state = if alive { State::Done } else { State::Failed };
        status.pid = child.id();
        status.finished_at = Some(unix_now());
        if !alive {
            status.message = Some("the new version stopped after it took over; its log says why".into());
        }
        write_status(&old.data_dir, &status);
        if line.send(&Message::Exiting).await.is_ok() {
            let _ = tokio::time::timeout(Duration::from_secs(5), async {
                while let Some(m) = line.recv().await {
                    if m == Message::Bye {
                        return;
                    }
                }
            })
            .await;
        }
        // Said by the main process too, which systemd believes whatever its NotifyAccess.
        if let Some(pid) = status.pid.filter(|_| alive) {
            notify(&format!("MAINPID={pid}"));
        }
        let _ = std::fs::remove_file(&socket);
        tracing::info!(pid = ?status.pid, "handed over to the new version; exiting");
        // It's killed when dropped, which is for a handover that stops halfway; this one carries on.
        std::mem::forget(child);
    }
}

/// Runs `magicpipesd rehearse`: reads the configuration (done by the caller) and migrates the
/// database copy at `database`.
pub fn rehearse(database: &Path) -> anyhow::Result<()> {
    let store = crate::store::Store::open(database)?;
    println!("migrated a copy of the database to version {}", store.schema_version()?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_are_one_json_line_each() {
        let m = Message::Agents { agents: vec!["ag_1".into()] };
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, r#"{"type":"agents","agents":["ag_1"]}"#);
        assert_eq!(serde_json::from_str::<Message>(&json).unwrap(), m);
        assert_eq!(serde_json::to_string(&Message::Go).unwrap(), r#"{"type":"go"}"#);
    }

    #[cfg(unix)]
    #[test]
    fn a_request_file_is_taken_once_and_only_while_fresh() {
        let dir = std::env::temp_dir().join(format!("mp-handover-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        write_request(&dir, &RequestFile { id: "abc".into(), to: Some("9.9.9".into()), at: unix_now() }).unwrap();
        let ask = Ask::from_signal(&dir);
        assert_eq!((ask.id.as_str(), ask.to.as_deref()), ("abc", Some("9.9.9")));
        assert_ne!(Ask::from_signal(&dir).id, "abc", "taken once");
        write_request(&dir, &RequestFile { id: "old".into(), to: None, at: unix_now() - REQUEST_FRESH_SECS }).unwrap();
        assert_ne!(Ask::from_signal(&dir).id, "old", "a leftover isn't a request");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_status_and_pid_files_round_trip() {
        let dir = std::env::temp_dir().join(format!("mp-handover-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let s = Status { id: "x".into(), state: State::Done, step: 5, from: "0.1.0".into(), to: Some("0.2.0".into()), message: None, backup: None, pid: Some(7), started_at: 1, finished_at: Some(2) };
        write_status(&dir, &s);
        assert_eq!(read_status(&dir), Some(s));
        write_pid(&dir);
        assert_eq!(read_pid(&dir).map(|r| r.pid), Some(std::process::id()));
        remove_pid(&dir);
        assert!(read_pid(&dir).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}
