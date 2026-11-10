//! Agent sessions: attaching, detaching, liveness and shutdown. An agent may hold several
//! connections at once (protocol 9), each a session of its own, which together are its [`Link`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

use magicpipes_core::mux::MuxHandle;
use magicpipes_core::proto::{self, ServerOpen};
use magicpipes_core::unix_now;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{ControlPlane, Link, OrLog, Session};

/// How often the server times a round trip on each agent connection, and how long it waits.
pub(super) const PING_EVERY: Duration = Duration::from_secs(15);
const PING_TIMEOUT: Duration = Duration::from_secs(5);
/// The protocol from which an agent answers a stream it doesn't know, rather than dropping it.
const ANSWERS_UNKNOWN_STREAMS: u32 = 2;

/// What became of a new connection.
#[derive(Debug, PartialEq, Eq)]
pub enum Attached {
    /// It serves the agent now, as this connection.
    Yes(u64),
    /// The agent was revoked after it authenticated.
    Revoked,
    /// The agent's run already has as many as `agents.max_connections` allows.
    Full,
}

impl ControlPlane {
    pub(super) fn reap_sessions(&self) {
        let timeout = self.cfg.session_timeout();
        let st = self.state.lock().unwrap();
        for (agent, link) in &st.sessions {
            for s in &link.lanes {
                if s.last_ping.elapsed() > timeout || s.handle.is_closed() {
                    tracing::info!(agent = %agent, conn_id = s.conn_id, "dropping unresponsive agent connection");
                    s.handle.close();
                }
            }
        }
        // Detach happens in the gateway when the session task observes the close.
    }

    /// Times a round trip on each agent connection. See [`ping`].
    pub(super) fn ping_agents(&self) {
        let st = self.state.lock().unwrap();
        for s in st.sessions.values().flat_map(|l| &l.lanes) {
            if s.protocol >= ANSWERS_UNKNOWN_STREAMS && !s.handle.is_closed() {
                tokio::spawn(ping(s.handle.clone(), s.round_trip.clone()));
            }
        }
    }

    /// Whether another connection from the agent's run `instance` would fit: checked before the
    /// upgrade, so the agent gets an answer it can act on instead of a connection that closes.
    pub fn has_room(&self, agent_id: &str, instance: Option<&str>) -> bool {
        let st = self.state.lock().unwrap();
        match (st.sessions.get(agent_id), instance) {
            (Some(link), Some(i)) if link.instance.as_deref() == Some(i) => link.lanes.len() < self.cfg.agents.max_connections,
            _ => true,
        }
    }

    /// Attaches a freshly authenticated agent connection. One from the same run of the agent
    /// (`instance`) joins its others; any other replaces them (the newest wins, e.g. after a
    /// network change or a restart). The caller closes the connection unless it's attached.
    pub fn attach_session(&self, agent_id: &str, handle: MuxHandle, remote: SocketAddr, protocol: u32, instance: Option<String>) -> Attached {
        let mut st = self.state.lock().unwrap();
        // Checked under the state lock, which `revoke_agent` also holds while deleting.
        if !self.store.agent_exists(agent_id).or_log().unwrap_or(false) || !st.dir.agent_active(agent_id) {
            return Attached::Revoked;
        }
        st.next_conn_id += 1;
        let conn_id = st.next_conn_id;
        let round_trip = Arc::new(AtomicU64::new(0));
        let session = |handle| Session { conn_id, handle, connected_at: unix_now(), remote, protocol, last_ping: Instant::now(), round_trip: round_trip.clone() };
        let connections = match st.sessions.get_mut(agent_id) {
            Some(link) if instance.is_some() && link.instance == instance => {
                if link.lanes.len() >= self.cfg.agents.max_connections {
                    return Attached::Full;
                }
                // Clients' shares and returning connections count across the run's connections.
                let handle = handle.join(&link.first().handle);
                link.lanes.push(session(handle));
                link.lanes.len()
            }
            _ => {
                let link = Link { instance, lanes: vec![session(handle)] };
                if let Some(old) = st.sessions.insert(agent_id.to_string(), link) {
                    old.close();
                }
                1
            }
        };
        self.publish(&st);
        let handle = st.sessions.get(agent_id).and_then(|l| l.lanes.last()).map(|s| s.handle.clone());
        drop(st);
        // Its first round trip, so it's known before the next round of pings.
        if let Some(handle) = handle.filter(|_| protocol >= ANSWERS_UNKNOWN_STREAMS) {
            tokio::spawn(ping(handle, round_trip));
        }
        self.store.touch_agent(agent_id).or_log();
        tracing::info!(agent = %agent_id, %remote, conn_id, protocol, connections, "agent connected");
        Attached::Yes(conn_id)
    }

    pub fn detach_session(&self, agent_id: &str, conn_id: u64) {
        let mut st = self.state.lock().unwrap();
        let Some(link) = st.sessions.get_mut(agent_id) else { return };
        let Some(i) = link.lanes.iter().position(|s| s.conn_id == conn_id) else { return };
        link.lanes.remove(i);
        let left = link.lanes.len();
        if left == 0 {
            st.sessions.remove(agent_id);
            tracing::info!(agent = %agent_id, conn_id, "agent disconnected");
        } else {
            tracing::info!(agent = %agent_id, conn_id, connections = left, "agent connection closed");
        }
        self.publish(&st);
    }

    pub fn touch(&self, agent_id: &str, conn_id: u64) {
        let mut st = self.state.lock().unwrap();
        if let Some(s) = st.sessions.get_mut(agent_id).and_then(|l| l.lanes.iter_mut().find(|s| s.conn_id == conn_id)) {
            s.last_ping = Instant::now();
        }
    }

    /// Closes all agent sessions (graceful shutdown).
    pub fn close_sessions(&self) {
        for link in self.state.lock().unwrap().sessions.values() {
            link.close();
        }
    }
}

/// Times a round trip on an agent connection, and keeps it in `round_trip`: a stream the agent
/// answers at once ([`ServerOpen::Ping`]; one from before that answers it as unsupported, which
/// times it as well). It waits behind the connection's other traffic, so it shows a link that's
/// slow or full, not just far. A control stream ([`MuxHandle::open`]): the agent's data budget
/// doesn't hold it up.
async fn ping(handle: MuxHandle, round_trip: Arc<AtomicU64>) {
    let started = Instant::now();
    let answered = async {
        let mut s = handle.open(PING_TIMEOUT).await.ok()?;
        proto::write_frame(&mut s, &ServerOpen::Ping).await.ok()?;
        s.read_u8().await.ok()?;
        let took = started.elapsed();
        let _ = s.shutdown().await;
        Some(took)
    };
    let took = tokio::time::timeout(PING_TIMEOUT, answered).await.ok().flatten();
    let micros = took.map_or(0, |t| u64::try_from(t.as_micros()).unwrap_or(u64::MAX).max(1));
    round_trip.store(micros, Relaxed);
}
