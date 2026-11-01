//! One web terminal session: a WebSocket on one side, a fresh pty running the command on the
//! other.
//!
//! The browser speaks first, with `{"type":"hello","key":…,"cols":…,"rows":…}`; after that,
//! binary messages are keyboard input and `{"type":"resize",…}` resizes the pty. The agent sends
//! `{"type":"ready","writable":…}`, then binary output, and ends with one of `exit`, `error` or
//! `ended` before closing. pty reads, writes and the exit wait are blocking calls, so each runs
//! on its own thread and talks to the session through bounded channels: a viewer that stops
//! reading pauses the program's output instead of buffering it.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use magicpipes_core::error::ErrorCode;
use portable_pty::{ChildKiller, CommandBuilder, ExitStatus, MasterPty, PtySize, native_pty_system};
use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use super::Terminal;

const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Keeps idle sessions alive through the server's WebSocket idle timeout and proxies.
const PING_EVERY: Duration = Duration::from_secs(30);
/// After the program exits, output still in flight is forwarded for this long.
const DRAIN: Duration = Duration::from_millis(300);
/// A program that ignores SIGHUP gets SIGKILL after this long.
pub const KILL_GRACE: Duration = Duration::from_secs(2);
/// Output is coalesced into WebSocket messages of at most this size.
const MAX_CHUNK: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Control {
    Hello {
        #[serde(default)]
        key: Option<String>,
        cols: u16,
        rows: u16,
    },
    Resize {
        cols: u16,
        rows: u16,
    },
}

fn size(cols: u16, rows: u16) -> PtySize {
    PtySize { cols: cols.clamp(2, 500), rows: rows.clamp(2, 300), pixel_width: 0, pixel_height: 0 }
}

pub async fn run<S>(mut ws: WebSocketStream<S>, term: Arc<Terminal>, peer: String)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hello = match tokio::time::timeout(HELLO_TIMEOUT, ws.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => serde_json::from_str::<Control>(&t).ok(),
        _ => None,
    };
    let Some(Control::Hello { key, cols, rows }) = hello else {
        return finish(ws, json!({ "type": "error", "code": ErrorCode::Protocol.as_str(), "message": "expected a hello message" })).await;
    };
    let writable = match (&term.key, key) {
        (None, _) => false,
        (Some(want), Some(given)) if magicpipes_core::secret::constant_time_eq(want.as_bytes(), given.as_bytes()) => true,
        (Some(_), _) => {
            tracing::info!(peer = %peer, "web terminal refused: missing or wrong key");
            let message = "This terminal needs its full link, including the secret after #k=. Ask whoever shared it.";
            return finish(ws, json!({ "type": "error", "code": "key", "message": message })).await;
        }
    };
    let Some(_slot) = Slot::take(&term.sessions, term.max_clients) else {
        let message = format!("This terminal already has {} open sessions. Try again later.", term.max_clients);
        return finish(ws, json!({ "type": "error", "code": ErrorCode::Busy.as_str(), "message": message })).await;
    };
    let mut pty = match Pty::spawn(&term, size(cols, rows)) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "web terminal could not start the program");
            let message = format!("Could not start {}: {e:#}", crate::state::command_line(&term.command));
            return finish(ws, json!({ "type": "error", "code": ErrorCode::SpawnFailed.as_str(), "message": message })).await;
        }
    };
    let mode = if writable { "read-write" } else { "read-only" };
    tracing::info!(peer = %peer, mode, pid = pty.pid, "web terminal session started");
    let outcome = pump(&mut ws, &mut pty, &term, writable).await;
    let last = match &outcome {
        Outcome::Exited(status) => Some(exit_message(status)),
        Outcome::Ended => Some(json!({ "type": "ended", "message": "The terminal was stopped or its settings changed." })),
        Outcome::ClientGone => None,
    };
    tracing::info!(peer = %peer, mode, pid = pty.pid, "web terminal session ended");
    pty.stop();
    if let Some(msg) = last {
        finish(ws, msg).await;
    }
}

enum Outcome {
    Exited(ExitStatus),
    /// The tunnel was removed or changed.
    Ended,
    ClientGone,
}

async fn pump<S>(ws: &mut WebSocketStream<S>, pty: &mut Pty, term: &Terminal, writable: bool) -> Outcome
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if send(ws, json!({ "type": "ready", "writable": writable })).await.is_err() {
        return Outcome::ClientGone;
    }
    let mut ping = tokio::time::interval(PING_EVERY);
    ping.tick().await;
    let mut exited: Option<ExitStatus> = None;
    let drain = tokio::time::sleep(Duration::MAX);
    tokio::pin!(drain);
    loop {
        tokio::select! {
            _ = term.ended.cancelled() => return Outcome::Ended,
            msg = ws.next() => match msg {
                Some(Ok(Message::Binary(data))) if writable => {
                    // Dropped rather than awaited when the program is not reading its input, so
                    // its output keeps flowing.
                    let _ = pty.input.try_send(data.to_vec());
                }
                Some(Ok(Message::Text(t))) => {
                    if let Ok(Control::Resize { cols, rows }) = serde_json::from_str(&t) {
                        let _ = pty.master.resize(size(cols, rows));
                    }
                }
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return Outcome::ClientGone,
                Some(Ok(_)) => {}
            },
            chunk = pty.output.recv() => match chunk {
                Some(mut data) => {
                    while data.len() < MAX_CHUNK {
                        match pty.output.try_recv() {
                            Ok(more) => data.extend_from_slice(&more),
                            Err(_) => break,
                        }
                    }
                    if ws.send(Message::Binary(data.into())).await.is_err() {
                        return Outcome::ClientGone;
                    }
                }
                // Every holder of the pty is gone: the program has exited (or is about to).
                None => {
                    let status = match exited.take() {
                        Some(s) => s,
                        None => match tokio::time::timeout(KILL_GRACE, &mut pty.exit).await {
                            Ok(status) => {
                                pty.reaped = true;
                                status.unwrap_or_else(|_| ExitStatus::with_exit_code(1))
                            }
                            Err(_) => ExitStatus::with_exit_code(1),
                        },
                    };
                    return Outcome::Exited(status);
                }
            },
            status = &mut pty.exit, if !pty.reaped => {
                pty.reaped = true;
                // Output may still be in flight, and a background process may keep the pty open
                // forever (or ConPTY may never report EOF): forward what arrives briefly, then stop.
                exited = Some(status.unwrap_or_else(|_| ExitStatus::with_exit_code(1)));
                drain.as_mut().reset(tokio::time::Instant::now() + DRAIN);
            }
            _ = &mut drain, if exited.is_some() => {
                return Outcome::Exited(exited.take().unwrap_or_else(|| ExitStatus::with_exit_code(1)));
            }
            _ = ping.tick() => {
                if ws.send(Message::Ping(Default::default())).await.is_err() {
                    return Outcome::ClientGone;
                }
            }
        }
    }
}

fn exit_message(status: &ExitStatus) -> serde_json::Value {
    json!({ "type": "exit", "code": status.exit_code(), "signal": status.signal() })
}

async fn send<S>(ws: &mut WebSocketStream<S>, msg: serde_json::Value) -> Result<(), ()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ws.send(Message::Text(msg.to_string().into())).await.map_err(|_| ())
}

/// Sends a last message and closes the WebSocket.
async fn finish<S>(mut ws: WebSocketStream<S>, msg: serde_json::Value)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = send(&mut ws, msg).await;
        let _ = ws.close(None).await;
    })
    .await;
}

/// A counted place among a tunnel's `max_clients` sessions, released on drop.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(count: &Arc<AtomicUsize>, max: u16) -> Option<Self> {
        count.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| (n < usize::from(max)).then_some(n + 1)).ok()?;
        Some(Self(count.clone()))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A running program in a pty, with its blocking I/O on threads.
struct Pty {
    master: Box<dyn MasterPty + Send>,
    killer: Box<dyn ChildKiller + Send + Sync>,
    pid: Option<u32>,
    output: mpsc::Receiver<Vec<u8>>,
    input: mpsc::Sender<Vec<u8>>,
    exit: oneshot::Receiver<ExitStatus>,
    /// `exit` has completed (it must not be polled again).
    reaped: bool,
}

impl Pty {
    fn spawn(term: &Terminal, size: PtySize) -> anyhow::Result<Self> {
        let pair = native_pty_system().openpty(size)?;
        let mut cmd = CommandBuilder::from_argv(term.command.iter().map(OsString::from).collect());
        cmd.cwd(&term.cwd);
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        let mut child = pair.slave.spawn_command(cmd)?;
        // Only the program may hold the pty's other end, so that reads see EOF when it exits.
        drop(pair.slave);
        let killer = child.clone_killer();
        let pid = child.process_id();
        let mut reader = pair.master.try_clone_reader()?;
        let mut writer = pair.master.take_writer()?;

        let (out_tx, output) = mpsc::channel::<Vec<u8>>(32);
        std::thread::Builder::new().name("pty-read".into()).spawn(move || {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        })?;
        let (input, mut in_rx) = mpsc::channel::<Vec<u8>>(256);
        std::thread::Builder::new().name("pty-write".into()).spawn(move || {
            while let Some(data) = in_rx.blocking_recv() {
                if writer.write_all(&data).and_then(|()| writer.flush()).is_err() {
                    break;
                }
            }
        })?;
        let (exit_tx, exit) = oneshot::channel();
        std::thread::Builder::new().name("pty-wait".into()).spawn(move || {
            let status = child.wait().unwrap_or_else(|_| ExitStatus::with_exit_code(1));
            let _ = exit_tx.send(status);
        })?;
        Ok(Self { master: pair.master, killer, pid, output, input, exit, reaped: false })
    }

    /// Ends the program: SIGHUP (as when a terminal closes), then SIGKILL if it is still running
    /// after a grace period. On Windows the kill is immediate. Dropping the master afterwards
    /// closes the pty.
    fn stop(self) {
        let Pty { master, mut killer, pid, exit, reaped, .. } = self;
        if reaped {
            return;
        }
        let _ = killer.kill();
        tokio::spawn(async move {
            if tokio::time::timeout(KILL_GRACE, exit).await.is_err() {
                #[cfg(unix)]
                if let Some(pid) = pid.and_then(|p| i32::try_from(p).ok()) {
                    // SAFETY: plain syscalls on a pid we spawned and have not reaped (the wait
                    // thread is still blocked on it, so the pid cannot have been reused). The
                    // pty made it a session and process-group leader, so `-pid` also reaches
                    // jobs it started that ignored SIGHUP.
                    unsafe {
                        libc::kill(-pid, libc::SIGKILL);
                        libc::kill(pid, libc::SIGKILL);
                    }
                }
                #[cfg(not(unix))]
                let _ = pid;
            }
            drop(master);
        });
    }
}
