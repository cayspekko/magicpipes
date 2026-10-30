//! Operating-system specifics: local IPC transport, detaching the agent, private files,
//! termination signals and the hostname.
//!
//! * Unix: IPC over a Unix domain socket (mode 0600 inside a 0700 directory, peer uid checked);
//!   the agent is detached with `setsid()`.
//! * Windows: IPC over a named pipe derived from `MAGICPIPES_HOME` (local clients only, default
//!   pipe ACL: the creating user, SYSTEM and Administrators); the agent is started as a
//!   detached process without a console.

use std::fs::OpenOptions;
use std::io;
use std::path::Path;
use std::process::Command;

/// Open options for files that only the current user may read (mode 0600 on Unix; files under
/// the user profile are private by default on Windows).
pub fn private_options() -> OpenOptions {
    #[allow(unused_mut)]
    let mut o = OpenOptions::new();
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o
}

/// Creates `dir` (and parents) accessible only by the current user.
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        // Tighten permissions if the directory already existed.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)
}

/// Makes `cmd` start detached from the caller's terminal/console, so it survives the CLI.
pub fn detach(cmd: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid() is async-signal-safe and is the only call between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
}

/// Resolves on a termination request other than Ctrl+C (SIGTERM on Unix; never on Windows,
/// where a detached agent is stopped over IPC).
pub async fn terminate() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    }
    #[cfg(not(unix))]
    std::future::pending::<()>().await
}

pub fn hostname() -> String {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: buf is valid for buf.len() bytes; gethostname NUL-terminates on success.
        let ok = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) } == 0;
        let len = buf.iter().position(|&b| b == 0).unwrap_or(0);
        if ok && len > 0 {
            return String::from_utf8_lossy(&buf[..len]).into_owned();
        }
    }
    #[cfg(windows)]
    if let Ok(name) = std::env::var("COMPUTERNAME")
        && !name.is_empty()
    {
        return name;
    }
    "agent".into()
}

#[cfg(unix)]
pub use unix_ipc::*;
#[cfg(windows)]
pub use windows_ipc::*;

#[cfg(unix)]
mod unix_ipc {
    use std::io;
    use std::os::unix::fs::PermissionsExt;

    use anyhow::{Context, bail};
    use tokio::net::{UnixListener, UnixStream};

    use crate::state;

    pub type IpcClient = UnixStream;
    pub type IpcConn = UnixStream;

    pub async fn ipc_connect() -> Option<IpcClient> {
        UnixStream::connect(state::socket_path()).await.ok()
    }

    pub struct IpcListener {
        inner: UnixListener,
        uid: u32,
    }

    impl IpcListener {
        /// Binds the agent socket. The caller must hold the agent lock, which proves any
        /// existing socket file is stale.
        pub fn bind() -> anyhow::Result<Self> {
            let sock = state::socket_path();
            if sock.as_os_str().len() > 100 {
                bail!("socket path {} is too long; set MAGICPIPES_SOCKET (or MAGICPIPES_HOME) to a shorter path", sock.display());
            }
            let _ = std::fs::remove_file(&sock);
            let inner = UnixListener::bind(&sock).with_context(|| format!("binding {}", sock.display()))?;
            std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
            // SAFETY: getuid has no preconditions.
            Ok(Self { inner, uid: unsafe { libc::getuid() } })
        }

        /// Next connection from the same user. Connections from other users are dropped
        /// (defense in depth on top of the 0700 directory and 0600 socket).
        pub async fn accept(&mut self) -> io::Result<IpcConn> {
            loop {
                let (stream, _) = self.inner.accept().await?;
                match stream.peer_cred() {
                    Ok(c) if c.uid() == self.uid => return Ok(stream),
                    Ok(c) => tracing::warn!(uid = c.uid(), "rejected IPC connection from another user"),
                    // The peer already hung up (e.g. a CLI liveness check).
                    Err(_) => {}
                }
            }
        }
    }

    pub fn cleanup_ipc() {
        let _ = std::fs::remove_file(state::socket_path());
    }
}

#[cfg(windows)]
mod windows_ipc {
    use std::io;
    use std::time::Duration;

    use anyhow::Context;
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions};

    use crate::state;

    pub type IpcClient = NamedPipeClient;
    pub type IpcConn = NamedPipeServer;

    const ERROR_PIPE_BUSY: i32 = 231;

    /// `\\.\pipe\magicpipes-<hash of MAGICPIPES_HOME>`, or `MAGICPIPES_SOCKET` if set.
    pub fn ipc_name() -> String {
        if let Ok(name) = std::env::var("MAGICPIPES_SOCKET") {
            return name;
        }
        let home = state::home().display().to_string().to_lowercase();
        format!(r"\\.\pipe\magicpipes-{}", &magicpipes_core::secret::sha256_hex(&home)[..16])
    }

    pub async fn ipc_connect() -> Option<IpcClient> {
        let name = ipc_name();
        for _ in 0..20 {
            match ClientOptions::new().open(&name) {
                Ok(c) => return Some(c),
                // All instances are momentarily in use: the agent creates a new one right away.
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => tokio::time::sleep(Duration::from_millis(50)).await,
                Err(_) => return None,
            }
        }
        None
    }

    pub struct IpcListener {
        name: String,
        next: NamedPipeServer,
    }

    impl IpcListener {
        pub fn bind() -> anyhow::Result<Self> {
            let name = ipc_name();
            // first_pipe_instance fails if another process already owns this pipe name.
            let next = ServerOptions::new()
                .first_pipe_instance(true)
                .reject_remote_clients(true)
                .create(&name)
                .with_context(|| format!("creating named pipe {name}"))?;
            Ok(Self { name, next })
        }

        pub async fn accept(&mut self) -> io::Result<IpcConn> {
            self.next.connect().await?;
            let fresh = ServerOptions::new().reject_remote_clients(true).create(&self.name)?;
            Ok(std::mem::replace(&mut self.next, fresh))
        }
    }

    pub fn cleanup_ipc() {}
}
