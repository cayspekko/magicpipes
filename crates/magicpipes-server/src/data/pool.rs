//! Idle HTTP/1.1 connections to agents, kept for the next request to the same tunnel.
//!
//! Without them every request opens a stream, and the agent a TCP connection to the
//! application, which costs a round trip and, under load, the agent's local ports (each closed
//! connection waits a minute before its port is free again). A connection is reused only on the
//! same agent session and tunnel version ([`super::Route::version`]) it was opened on, so a changed
//! target or a reconnected agent always gets fresh ones, while changes to other tunnels cost
//! nothing.
//!
//! Bounded: at most [`MAX_IDLE_PER_TUNNEL`] per tunnel and [`MAX_IDLE`] in total, each for at
//! most [`IDLE_TIMEOUT`]. Idle connections hold a place in their session's stream budget (not a
//! client's), and give it up when a session needs a stream ([`Pool::evict`], through
//! `DataPlane::with_room`).
//!
//! A connection whose response is under way holds its stream too, and comes back once the
//! response has been read to the end, a moment after the client has it: under load, half a
//! session's streams can be in that state while nothing is idle. So each one is counted on its
//! session ([`MuxHandle::lend`], [`MuxHandle::came_back`]), and a request that finds the budget
//! full and nothing idle waits for one to come back ([`MuxHandle::wait_for_return`], at most
//! [`RETURN_WAIT`]) rather than being refused.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hyper::client::conn::http1::SendRequest;
use magicpipes_core::mux::{MAX_DATA_STREAMS, MuxHandle};

/// How long an idle connection is kept. Shorter than most applications' own keep-alive (often
/// 5 s or more), so an application rarely closes one just as it is reused.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(4);
/// As many as can be in flight. With fewer, a busy tunnel closes connections only to open them
/// again for the next request, until the agent runs out of local ports.
pub const MAX_IDLE_PER_TUNNEL: usize = MAX_DATA_STREAMS;
pub const MAX_IDLE: usize = 4096;
/// How long a request waits for a connection to come back when its session's streams are all in
/// use and none is idle. One comes back within milliseconds of its response; a session full of
/// long downloads refuses after this.
pub const RETURN_WAIT: Duration = Duration::from_secs(1);

struct Idle<B> {
    sender: SendRequest<B>,
    session: MuxHandle,
    version: u64,
    since: Instant,
}

impl<B> Idle<B> {
    fn usable(&self, session: &MuxHandle, version: u64) -> bool {
        self.version == version
            && self.session.same_session(session)
            && !self.session.is_closed()
            && self.since.elapsed() < IDLE_TIMEOUT
            && self.sender.is_ready()
    }
}

pub struct Pool<B> {
    /// Per tunnel id, most recently returned last.
    idle: Mutex<HashMap<String, Vec<Idle<B>>>>,
}

impl<B> Default for Pool<B> {
    fn default() -> Self {
        Self { idle: Mutex::default() }
    }
}

impl<B> Pool<B> {
    /// A ready connection to `tunnel` on `session`, if one is idle. Stale ones met on the way
    /// are dropped, which closes them.
    pub fn take(&self, tunnel: &str, session: &MuxHandle, version: u64) -> Option<SendRequest<B>> {
        let mut idle = self.idle.lock().unwrap();
        let list = idle.get_mut(tunnel)?;
        let found = loop {
            match list.pop() {
                Some(c) if c.usable(session, version) => break Some(c.sender),
                Some(_) => {}
                None => break None,
            }
        };
        if list.is_empty() {
            idle.remove(tunnel);
        }
        found
    }

    /// Keeps a connection for the next request, unless the pool is full.
    pub fn put(&self, tunnel: &str, session: MuxHandle, version: u64, sender: SendRequest<B>) {
        let mut idle = self.idle.lock().unwrap();
        let total: usize = idle.values().map(Vec::len).sum();
        let list = idle.entry(tunnel.to_string()).or_default();
        if total >= MAX_IDLE || list.len() >= MAX_IDLE_PER_TUNNEL {
            return;
        }
        list.push(Idle { sender, session, version, since: Instant::now() });
    }

    /// Closes the oldest idle connection on `session`, to free its stream for another request.
    /// `false` if there was none.
    pub fn evict(&self, session: &MuxHandle) -> bool {
        let mut idle = self.idle.lock().unwrap();
        let oldest = idle
            .iter()
            .flat_map(|(tunnel, list)| list.iter().enumerate().map(move |(i, c)| (tunnel, i, c)))
            .filter(|(_, _, c)| c.session.same_session(session))
            .min_by_key(|(_, _, c)| c.since)
            .map(|(tunnel, i, _)| (tunnel.clone(), i));
        let Some((tunnel, i)) = oldest else { return false };
        if let Some(list) = idle.get_mut(&tunnel) {
            list.remove(i);
            if list.is_empty() {
                idle.remove(&tunnel);
            }
        }
        true
    }

    /// Drops connections idle for longer than [`IDLE_TIMEOUT`], or no longer usable.
    pub fn sweep(&self) {
        let mut idle = self.idle.lock().unwrap();
        idle.retain(|_, list| {
            list.retain(|c| c.since.elapsed() < IDLE_TIMEOUT && !c.session.is_closed() && !c.sender.is_closed());
            !list.is_empty()
        });
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.idle.lock().unwrap().values().map(Vec::len).sum()
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http_body_util::Empty;
    use hyper_util::rt::TokioIo;
    use magicpipes_core::mux::{self, Mode};
    use tokio::io::DuplexStream;

    use super::*;

    /// A connected client connection; the peer end is returned so the connection stays open.
    async fn connection() -> (SendRequest<Empty<Bytes>>, DuplexStream) {
        let (io, peer) = tokio::io::duplex(1024);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await.unwrap();
        tokio::spawn(conn);
        // As in the proxy, which pools a connection once it is ready for the next request.
        sender.ready().await.unwrap();
        (sender, peer)
    }

    fn session() -> (MuxHandle, MuxHandle) {
        let (a, b) = tokio::io::duplex(1024);
        (mux::spawn(a, Mode::Server).0, mux::spawn(b, Mode::Client).0)
    }

    #[tokio::test]
    async fn reuse_stays_on_its_session_and_version() {
        let pool = Pool::default();
        let ((s1, _p1), (s2, _p2)) = (session(), session());
        let mut peers = Vec::new();
        let mut put = |tunnel: &str, s: &MuxHandle, version: u64, c: (SendRequest<Empty<Bytes>>, DuplexStream)| {
            peers.push(c.1);
            pool.put(tunnel, s.clone(), version, c.0);
        };
        put("tn_a", &s1, 1, connection().await);
        assert!(pool.take("tn_a", &s2, 1).is_none(), "another session (a reconnected agent)");
        put("tn_a", &s1, 1, connection().await);
        assert!(pool.take("tn_a", &s1, 2).is_none(), "another version of the tunnel (a changed target)");
        put("tn_a", &s1, 1, connection().await);
        assert!(pool.take("tn_b", &s1, 1).is_none(), "another tunnel");
        assert!(pool.take("tn_a", &s1, 1).is_some());
        assert_eq!(pool.len(), 0);

        // Bounded per tunnel; an idle connection makes room for a session that needs a stream.
        for _ in 0..MAX_IDLE_PER_TUNNEL + 3 {
            put("tn_a", &s1, 1, connection().await);
        }
        assert_eq!(pool.len(), MAX_IDLE_PER_TUNNEL);
        assert!(!pool.evict(&s2), "nothing idle on that session");
        assert!(pool.evict(&s1));
        assert_eq!(pool.len(), MAX_IDLE_PER_TUNNEL - 1);

        // A connection the application closed is never handed out.
        let (sender, peer) = connection().await;
        pool.put("tn_c", s1.clone(), 1, sender);
        drop(peer);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(pool.take("tn_c", &s1, 1).is_none());
        pool.sweep();
        assert_eq!(pool.len(), MAX_IDLE_PER_TUNNEL - 1);
    }

}
