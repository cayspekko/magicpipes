//! Checks a Unix socket before it becomes a tunnel's target (`add --unix`).
//!
//! A tunnel connects as the agent's user, so a socket's file permissions, which are its access
//! control, say nothing about who reaches it through the tunnel. For most sockets that's the point:
//! an application behind `gunicorn.sock` has its own idea of who may do what. For some, it hands over
//! the machine, or the user's keys, so those need saying twice. The list can't be complete, and the
//! README says what's left to the person publishing one.

use std::path::{Path, PathBuf};
use std::time::Duration;

use magicpipes_core::error::ErrorCode;

use crate::ipc::ErrorInfo;
use crate::platform;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Sockets that run containers or virtual machines, which is as good as root on this machine.
const CONTAINER_SOCKETS: [&str; 10] = [
    "docker.sock",
    "dockershim.sock",
    "cri-dockerd.sock",
    "podman.sock",
    "containerd.sock",
    "crio.sock",
    "libvirt-sock",
    "libvirt-admin-sock",
    "virtqemud-sock",
    "snapd.socket",
];

/// What a socket would give whoever opens the tunnel, if it's one of the kinds that shouldn't be
/// published by accident. `path` is canonical.
fn sensitive_socket(path: &Path) -> Option<&'static str> {
    let canonical = |p: PathBuf| std::fs::canonicalize(&p).unwrap_or(p);
    if path.starts_with(canonical(crate::state::home())) {
        return Some("control of this agent");
    }
    #[cfg(unix)]
    if path == canonical(crate::state::socket_path()) {
        return Some("control of this agent");
    }
    if std::env::var_os("SSH_AUTH_SOCK").is_some_and(|agent| path == canonical(PathBuf::from(agent))) {
        return Some("the use of your SSH keys");
    }
    let name = path.file_name()?.to_str()?;
    let in_a_folder = |matches: &dyn Fn(&str) -> bool| path.parent().into_iter().flat_map(Path::components).any(|c| c.as_os_str().to_str().is_some_and(matches));
    if CONTAINER_SOCKETS.contains(&name) || in_a_folder(&|d| matches!(d, "lxd" | "incus" | "k3s")) {
        return Some("control of this machine's containers, and so of this machine");
    }
    if name == "system_bus_socket" || name == "bus" || in_a_folder(&|d| matches!(d, "systemd" | "dbus")) {
        return Some("control of this machine's services");
    }
    // OpenSSH's agent, macOS's and GNOME's copies of it, GnuPG's, and SSH's shared connections.
    let ssh_agent = name.starts_with("ssh-agent")
        || name.starts_with("S.gpg-agent")
        || (name.starts_with("agent.") && in_a_folder(&|d| d.starts_with("ssh-")))
        || (name == "Listeners" && in_a_folder(&|d| d.starts_with("com.apple.launchd.")))
        || (name == "ssh" && in_a_folder(&|d| matches!(d, "keyring" | "gcr")))
        || in_a_folder(&|d| matches!(d, ".ssh" | ".gnupg"));
    if ssh_agent {
        return Some("the use of your SSH or GPG keys");
    }
    if in_a_folder(&|d| d.starts_with("tmux-") || d == "screens" || d == "screen") {
        return Some("a terminal session of yours");
    }
    None
}

/// Validates a socket for `--unix`. `path` is kept as it was given (absolute, from the CLI), not
/// with its links resolved: a deploy that points `current` at a new release shouldn't break a tunnel
/// to `current/app.sock`.
pub async fn check(path: &Path, allow_sensitive: bool) -> Result<PathBuf, ErrorInfo> {
    let invalid = |m: String| ErrorInfo::new(ErrorCode::InvalidSocket, m);
    let unreachable = |m: String| ErrorInfo::new(ErrorCode::LocalUnreachable, m);
    let shown = path.display();
    if !platform::UNIX_SOCKETS {
        return Err(ErrorInfo::new(ErrorCode::Unsupported, "Unix sockets aren't supported on this system"));
    }
    if !path.is_absolute() {
        return Err(invalid(format!("{shown} is not an absolute path")));
    }
    let meta = tokio::fs::metadata(path).await.map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => unreachable(format!("there is no socket at {shown}. Start your application first")),
        _ => unreachable(format!("cannot use {shown}: {e}")),
    })?;
    if !platform::is_socket(&meta) {
        return Err(invalid(format!("{shown} is not a Unix socket")));
    }
    // Before connecting: merely connecting to a socket can make its service do something.
    if !allow_sensitive
        && let Some(what) = sensitive_socket(&tokio::fs::canonicalize(path).await.unwrap_or_else(|_| path.to_path_buf()))
    {
        return Err(invalid(format!("{shown} would give whoever opens this tunnel {what}, whatever its file permissions say. Pass --allow-sensitive-socket if you really mean this one")));
    }
    match tokio::time::timeout(CONNECT_TIMEOUT, platform::unix_connect(path)).await {
        Ok(Ok(_)) => Ok(path.to_path_buf()),
        Ok(Err(e)) => Err(unreachable(match e.kind() {
            std::io::ErrorKind::ConnectionRefused => format!("nothing is accepting connections on unix:{shown}. Start your application first"),
            std::io::ErrorKind::PermissionDenied => format!("this agent's user may not connect to {shown}: the socket's permissions decide that"),
            _ => format!("cannot connect to {shown}: {e}"),
        })),
        Err(_) => Err(unreachable(format!("{shown} did not accept a connection within {}s", CONNECT_TIMEOUT.as_secs()))),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn sockets_that_hand_over_the_machine_or_your_keys_are_named() {
        for (path, what) in [
            ("/var/run/docker.sock", "containers"),
            ("/run/user/1000/podman/podman.sock", "containers"),
            ("/run/containerd/containerd.sock", "containers"),
            ("/var/run/libvirt/libvirt-sock", "containers"),
            ("/var/snap/lxd/common/lxd/unix.socket", "containers"),
            ("/run/snapd.socket", "containers"),
            ("/run/dbus/system_bus_socket", "services"),
            ("/run/user/1000/bus", "services"),
            ("/run/systemd/private", "services"),
            ("/tmp/ssh-XXXXabcd/agent.1234", "keys"),
            ("/private/tmp/com.apple.launchd.abcd/Listeners", "keys"),
            ("/run/user/1000/keyring/ssh", "keys"),
            ("/run/user/1000/gnupg/S.gpg-agent", "keys"),
            ("/home/ann/.ssh/cm-github", "keys"),
            ("/home/ann/.gnupg/S.gpg-agent.ssh", "keys"),
            ("/home/ann/ssh-agent.sock", "keys"),
            ("/tmp/tmux-1000/default", "terminal"),
            ("/run/screen/S-ann/1234.pts-0", "terminal"),
        ] {
            let said = sensitive_socket(Path::new(path)).unwrap_or_else(|| panic!("{path} isn't refused"));
            assert!(said.contains(what), "{path}: {said}");
        }
    }

    #[test]
    fn ordinary_sockets_are_nobodys_business() {
        for path in [
            "/run/gunicorn.sock",
            "/srv/app/releases/42/tmp/puma.sock",
            "/var/run/nginx.sock",
            "/home/ann/project/app.sock",
            "/var/run/postgresql/.s.PGSQL.5432",
            "/tmp/agent.1234",
            "/tmp/my-docker.sock.bak",
        ] {
            assert_eq!(sensitive_socket(Path::new(path)), None, "{path}");
        }
    }

    #[test]
    fn this_agents_own_files_are_named() {
        let own = std::fs::canonicalize(crate::state::home()).unwrap_or_else(|_| crate::state::home());
        assert!(sensitive_socket(&own.join("agent.sock")).is_some_and(|s| s.contains("this agent")));
    }

    #[tokio::test]
    async fn a_socket_has_to_be_there_and_be_a_socket() {
        let dir = std::env::temp_dir().join(format!("mp-unix-{}", magicpipes_core::secret::random_string(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let code = |r: Result<PathBuf, ErrorInfo>| r.err().map(|e| e.code);

        assert_eq!(code(check(Path::new("relative.sock"), false).await).as_deref(), Some("invalid_socket"));
        assert_eq!(code(check(&dir.join("missing.sock"), false).await).as_deref(), Some("local_unreachable"));
        let file = dir.join("file");
        std::fs::write(&file, "not a socket").unwrap();
        assert_eq!(code(check(&file, false).await).as_deref(), Some("invalid_socket"));
        assert_eq!(code(check(&dir, false).await).as_deref(), Some("invalid_socket"), "a folder isn't one either");

        let path = dir.join("a.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        assert_eq!(check(&path, false).await.unwrap(), path);

        // The path stays as given, so a deploy can point a link at a new release.
        let link = dir.join("current.sock");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(check(&link, false).await.unwrap(), link);

        // A socket file with nothing behind it, as an application leaves when it crashes.
        drop(listener);
        let e = check(&path, false).await.unwrap_err();
        assert!(e.code == "local_unreachable" && e.message.contains("Start your application"), "{e:?}");

        // Refused by what it is, and before it's connected to.
        let docker = dir.join("docker.sock");
        let listener = tokio::net::UnixListener::bind(&docker).unwrap();
        let e = check(&docker, false).await.unwrap_err();
        assert!(e.code == "invalid_socket" && e.message.contains("--allow-sensitive-socket") && e.message.contains("containers"), "{e:?}");
        assert_eq!(check(&docker, true).await.unwrap(), docker);
        drop(listener);

        // Followed through a link, whatever the link is called.
        let inner = dir.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        let _listener = tokio::net::UnixListener::bind(inner.join("docker.sock")).unwrap();
        let innocent = dir.join("innocent.sock");
        std::os::unix::fs::symlink(inner.join("docker.sock"), &innocent).unwrap();
        assert_eq!(code(check(&innocent, false).await).as_deref(), Some("invalid_socket"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
