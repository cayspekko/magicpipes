//! Handing open sockets and files to a new process, on Unix: the server's listeners when it hands
//! over to a new version, and the agent's lock and command socket when a new agent takes over. A
//! listening socket handed on is never closed, so no connection is refused while it changes hands.
//!
//! The parent names each descriptor in [`ENV`] (`name=fd,…`) and clears close-on-exec on just
//! those, in the child, between fork and exec. The child calls [`adopt_from_env`] first thing in
//! `main`, before any thread starts or any file opens, then [`take`]s each by name.

use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::Mutex;

pub const ENV: &str = "MAGICPIPES_INHERITED_FDS";

static INHERITED: Mutex<Option<HashMap<String, OwnedFd>>> = Mutex::new(None);

/// Makes the process `cmd` starts inherit each `(name, fd)` at the same number, and tells it
/// which is which.
pub fn pass(cmd: &mut Command, fds: &[(String, RawFd)]) {
    let list = fds.iter().map(|(name, fd)| format!("{name}={fd}")).collect::<Vec<_>>().join(",");
    cmd.env(ENV, list);
    let raw: Vec<RawFd> = fds.iter().map(|(_, fd)| *fd).collect();
    // SAFETY: runs in the child between fork and exec, calling only fcntl, which is
    // async-signal-safe, on descriptors the parent holds open across the spawn.
    unsafe {
        cmd.pre_exec(move || {
            for fd in &raw {
                if libc::fcntl(*fd, libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

/// Adopts what [`pass`] handed this process, and forgets the variable so nothing this process
/// starts sees it. Call once, first thing in `main`, while it has one thread.
pub fn adopt_from_env() {
    let Some(list) = std::env::var_os(ENV) else { return };
    // SAFETY: `main` calls this before starting any thread, so nothing reads the environment
    // concurrently.
    unsafe { std::env::remove_var(ENV) };
    let mut adopted = HashMap::new();
    for item in list.to_string_lossy().split(',').filter(|s| !s.is_empty()) {
        let Some((name, fd)) = item.split_once('=') else { continue };
        let Ok(fd) = fd.parse::<RawFd>() else { continue };
        if fd < 3 || !valid_name(name) || adopted.contains_key(name) {
            continue;
        }
        // SAFETY: F_GETFD only asks whether the number is an open descriptor.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
            continue;
        }
        // SAFETY: the parent opened this descriptor for us and named it; nothing else in this
        // process knows the number, since nothing has run yet.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        // Not to be passed on by accident, to whatever this process starts.
        // SAFETY: setting close-on-exec on a descriptor this process now owns.
        unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
        adopted.insert(name.to_string(), owned);
    }
    *INHERITED.lock().unwrap_or_else(|e| e.into_inner()) = Some(adopted);
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 32 && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b':' || b == b'-')
}

/// Whether this process was handed anything.
pub fn handed_over() -> bool {
    INHERITED.lock().unwrap_or_else(|e| e.into_inner()).as_ref().is_some_and(|m| !m.is_empty())
}

/// The descriptor handed over as `name`, once.
pub fn take(name: &str) -> Option<OwnedFd> {
    INHERITED.lock().unwrap_or_else(|e| e.into_inner()).as_mut()?.remove(name)
}

/// Every descriptor handed over whose name starts with `prefix`, with the rest of its name.
pub fn take_prefixed(prefix: &str) -> Vec<(String, OwnedFd)> {
    let mut guard = INHERITED.lock().unwrap_or_else(|e| e.into_inner());
    let Some(map) = guard.as_mut() else { return Vec::new() };
    let names: Vec<String> = map.keys().filter(|k| k.starts_with(prefix)).cloned().collect();
    names.into_iter().filter_map(|n| map.remove(&n).map(|fd| (n[prefix.len()..].to_string(), fd))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_short_and_plain() {
        for ok in ["mgmt", "tcp:65500", "udp:1", "ipc", "lock"] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in ["", "Mgmt", "a b", "a=b", "a,b", &"x".repeat(33)] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn a_child_inherits_exactly_what_was_passed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let other = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fd = listener.as_raw_fd();
        let mut cmd = Command::new("/bin/sh");
        // The child sees the passed descriptor open and the other one closed.
        cmd.arg("-c").arg(format!("[ -e /dev/fd/{fd} ] && [ ! -e /dev/fd/{} ] && echo \"$MAGICPIPES_INHERITED_FDS\"", other.as_raw_fd()));
        pass(&mut cmd, &[("mgmt".into(), fd)]);
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "{out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), format!("mgmt={fd}"));
        // The parent's own copy keeps close-on-exec.
        // SAFETY: reading the flags of a descriptor this test owns.
        assert_ne!(unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC, 0);
    }
}
