//! Agent sessions: attaching, detaching, liveness and shutdown.

use std::net::SocketAddr;
use std::time::Instant;

use magicpipes_core::mux::MuxHandle;
use magicpipes_core::unix_now;

use super::{ControlPlane, Session};

impl ControlPlane {
    pub(super) fn reap_sessions(&self) {
        let timeout = self.cfg.session_timeout();
        let st = self.state.lock().unwrap();
        for (agent, s) in &st.sessions {
            if s.last_ping.elapsed() > timeout || s.handle.is_closed() {
                tracing::info!(agent = %agent, "dropping unresponsive agent session");
                s.handle.close();
            }
        }
        // Detach happens in the gateway when the session task observes the close.
    }

    /// Attaches a freshly authenticated agent session. A previous session of the same agent is
    /// closed (the newest connection wins, e.g. after a network change). Returns `None` if the
    /// agent was revoked after it authenticated.
    pub fn attach_session(&self, agent_id: &str, handle: MuxHandle, remote: SocketAddr, protocol: u32) -> Option<u64> {
        let mut st = self.state.lock().unwrap();
        // Checked under the state lock, which `revoke_agent` also holds while deleting.
        if !self.store.agent_exists(agent_id).unwrap_or(false) {
            return None;
        }
        st.next_conn_id += 1;
        let conn_id = st.next_conn_id;
        let session = Session { conn_id, handle, connected_at: unix_now(), remote, protocol, last_ping: Instant::now() };
        if let Some(old) = st.sessions.insert(agent_id.to_string(), session) {
            old.handle.close();
        }
        self.publish(&st);
        drop(st);
        let _ = self.store.touch_agent(agent_id);
        tracing::info!(agent = %agent_id, %remote, conn_id, protocol, "agent connected");
        Some(conn_id)
    }

    pub fn detach_session(&self, agent_id: &str, conn_id: u64) {
        let mut st = self.state.lock().unwrap();
        if st.sessions.get(agent_id).is_some_and(|s| s.conn_id == conn_id) {
            st.sessions.remove(agent_id);
            self.publish(&st);
            tracing::info!(agent = %agent_id, conn_id, "agent disconnected");
        }
    }

    pub fn touch(&self, agent_id: &str, conn_id: u64) {
        let mut st = self.state.lock().unwrap();
        if let Some(s) = st.sessions.get_mut(agent_id).filter(|s| s.conn_id == conn_id) {
            s.last_ping = Instant::now();
        }
    }

    /// Closes all agent sessions (graceful shutdown).
    pub fn close_sessions(&self) {
        for s in self.state.lock().unwrap().sessions.values() {
            s.handle.close();
        }
    }
}
