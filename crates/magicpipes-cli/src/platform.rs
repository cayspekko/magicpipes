//! Operating-system specifics: local IPC transport, detaching the agent, private files,
//! termination signals and the hostname.
//!
//! * Unix: IPC over a Unix domain socket (mode 0600 inside a 0700 directory, peer uid checked);
//!   the agent is detached with `setsid()`.
//! * Windows: IPC over a named pipe derived from `MAGICPIPES_HOME` (local clients only, default
//!   pipe ACL: the creating user, SYSTEM and Administrators); the agent is started as a
//!   detached process without a console.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
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

/// Opens `relative` beneath `root`, one component at a time and following no symlink, so a path
/// checked a moment ago can't be swapped for one that leads somewhere else: the open fails
/// instead. A FIFO doesn't block the open.
///
/// On Windows only the last component is checked this way (symlinks there need privileges, and
/// std has no `NtCreateFile`-relative open).
#[cfg(unix)]
pub fn open_beneath(root: &Path, relative: &Path) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;

    let mut at = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY).open(root)?;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a plain relative path"));
        };
        let name = CString::new(name.as_bytes())?;
        // SAFETY: `at` is an open descriptor and `name` is NUL-terminated.
        let fd = unsafe { libc::openat(at.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat just returned this descriptor, and nothing else owns it.
        at = unsafe { File::from_raw_fd(fd) };
    }
    Ok(at)
}

#[cfg(windows)]
pub fn open_beneath(root: &Path, relative: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    // Directories can only be opened with BACKUP_SEMANTICS; OPEN_REPARSE_POINT doesn't follow a
    // link in the last component, which is then refused below.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let file = OpenOptions::new().read(true).custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).open(root.join(relative))?;
    if !relative.as_os_str().is_empty() && file.metadata()?.file_type().is_symlink() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "a link"));
    }
    Ok(file)
}

/// A path that reaches the file `file` has open, whatever has happened to its name since, for
/// libraries that only take paths. `None` where there is no such path.
pub fn handle_path(file: &File) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    return Some(PathBuf::from(format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(file))));
    #[cfg(all(unix, not(target_os = "linux")))]
    return Some(PathBuf::from(format!("/dev/fd/{}", std::os::fd::AsRawFd::as_raw_fd(file))));
    #[cfg(not(unix))]
    {
        let _ = file;
        None
    }
}

/// Makes `cmd` start detached from the caller's terminal/console, so it survives the CLI, and
/// keeps it from holding on to the CLI's own stdio (see `disinherit_std_handles`).
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
        disinherit_std_handles();
    }
}

/// Windows creates child processes with handle inheritance enabled, so a long-lived agent would
/// otherwise inherit this CLI's stdin/stdout/stderr and keep them open after the CLI exits: in
/// `magicpipes add 8080 --json | jq`, `jq` would never see end-of-file. The child still gets the
/// stdio handles set on its `Command`; only the CLI's own handles stop being inheritable.
#[cfg(windows)]
fn disinherit_std_handles() {
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(which: u32) -> *mut c_void;
        fn SetHandleInformation(handle: *mut c_void, mask: u32, flags: u32) -> i32;
    }
    const STD_INPUT_HANDLE: u32 = -10i32 as u32;
    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
    const STD_ERROR_HANDLE: u32 = -12i32 as u32;
    const HANDLE_FLAG_INHERIT: u32 = 0x1;
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: plain Win32 calls on the process's own standard handles; failures (no handle,
        // invalid handle) are harmless and ignored.
        unsafe {
            let h = GetStdHandle(which);
            if !h.is_null() && h as isize != -1 {
                SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);
            }
        }
    }
}

/// Resolves on Ctrl+C. If the handler cannot be installed (e.g. a detached process without a
/// console), never resolves instead of reporting an interrupt that did not happen.
pub async fn interrupt() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await
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

/// Opens `url` in the user's browser, best effort: errors are ignored, because the URL is also
/// printed. `url` is built by the CLI itself (never taken from the server as is).
pub fn open_url(url: &str) {
    if std::env::var_os("MAGICPIPES_NO_BROWSER").is_some() {
        return;
    }
    #[cfg(target_os = "macos")]
    let mut cmd = Command::new("open");
    #[cfg(windows)]
    let mut cmd = {
        let mut c = Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler");
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = Command::new("xdg-open");
    cmd.arg(url).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    if let Ok(mut child) = cmd.spawn() {
        // Reap it in the background so it doesn't linger as a zombie.
        std::thread::spawn(move || child.wait());
    }
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

#[cfg(target_os = "linux")]
const TCP_NOTSENT_LOWAT: libc::c_int = libc::TCP_NOTSENT_LOWAT;
// <netinet/tcp.h>; the libc crate doesn't have it for macOS.
#[cfg(target_os = "macos")]
const TCP_NOTSENT_LOWAT: libc::c_int = 0x201;

/// Asks the kernel to keep at most `bytes` of this connection's data waiting to be sent, beyond
/// what is on its way. An optimization: where it isn't available, the connection just queues more.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn limit_send_queue(tcp: &tokio::net::TcpStream, bytes: u32) {
    use std::os::fd::AsRawFd;
    let value = bytes as libc::c_int;
    let size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let (fd, ptr) = (tcp.as_raw_fd(), (&raw const value).cast());
    if unsafe { libc::setsockopt(fd, libc::IPPROTO_TCP, TCP_NOTSENT_LOWAT, ptr, size) } != 0 {
        tracing::debug!(error = %std::io::Error::last_os_error(), "could not limit a connection's send queue");
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn limit_send_queue(_tcp: &tokio::net::TcpStream, _bytes: u32) {}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use std::os::fd::AsRawFd;

    use super::*;

    #[tokio::test]
    async fn a_connections_send_queue_can_be_limited() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp = tokio::net::TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        limit_send_queue(&tcp, 128 * 1024);
        let (mut value, mut size) = (0 as libc::c_int, std::mem::size_of::<libc::c_int>() as libc::socklen_t);
        let (fd, ptr) = (tcp.as_raw_fd(), (&raw mut value).cast());
        assert_eq!(unsafe { libc::getsockopt(fd, libc::IPPROTO_TCP, TCP_NOTSENT_LOWAT, ptr, &mut size) }, 0);
        assert_eq!(value, 128 * 1024);
    }
}
