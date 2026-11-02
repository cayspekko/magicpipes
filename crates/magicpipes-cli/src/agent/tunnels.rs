//! The agent's tunnel table: which tunnel ids it serves and where their local targets are.
//! This is the *only* source of local destinations — the server can name a tunnel id, never
//! an address, so a compromised or misbehaving server cannot make the agent dial elsewhere.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio_util::sync::CancellationToken;

use magicpipes_core::proto::Kind;

use crate::state::{self, LocalTunnel, Target};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Registration {
    /// Not (yet) confirmed by the server on the current session.
    Pending,
    Registered,
    /// The server rejected the registration on the last attempt.
    Failed,
}

struct Entry {
    tunnel: LocalTunnel,
    registration: Registration,
    last_error: Option<String>,
    /// Data streams that reached the local target (used by the readiness probe).
    streams_ok: Arc<AtomicU64>,
    /// Cancelled when the tunnel is removed or its target changes, ending long-lived sessions
    /// (web terminals) that were opened under the old settings.
    ended: CancellationToken,
    /// Open web terminal sessions.
    sessions: Arc<AtomicUsize>,
    /// The agent refuses to serve what the server made of this tunnel (see [`Tunnels::withdraw`]).
    withdrawn: bool,
}

impl Entry {
    fn new(tunnel: LocalTunnel, registration: Registration) -> Self {
        Self {
            tunnel,
            registration,
            last_error: None,
            streams_ok: Arc::default(),
            ended: CancellationToken::new(),
            sessions: Arc::default(),
            withdrawn: false,
        }
    }
}

/// What a data stream needs to serve a tunnel.
pub struct Route {
    pub kind: Kind,
    pub target: Target,
    pub streams_ok: Arc<AtomicU64>,
    pub ended: CancellationToken,
    pub sessions: Arc<AtomicUsize>,
}

#[derive(Default)]
pub struct Tunnels {
    map: Mutex<HashMap<String, Entry>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TunnelSnapshot {
    #[serde(flatten)]
    pub tunnel: LocalTunnel,
    pub registration: Registration,
    pub last_error: Option<String>,
}

impl Tunnels {
    pub fn load() -> anyhow::Result<Arc<Self>> {
        let me = Arc::new(Self::default());
        {
            let mut map = me.map.lock().unwrap();
            for t in state::load_tunnels()? {
                map.insert(t.id.clone(), Entry::new(t, Registration::Pending));
            }
        }
        Ok(me)
    }

    fn persist(map: &HashMap<String, Entry>) {
        let mut list: Vec<LocalTunnel> = map.values().map(|e| e.tunnel.clone()).collect();
        list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.name.cmp(&b.name)));
        if let Err(e) = state::save_tunnels(&list) {
            tracing::error!(error = %e, "could not persist tunnels.json");
        }
    }

    pub fn upsert(&self, t: LocalTunnel, registration: Registration) {
        let mut map = self.map.lock().unwrap();
        match map.get_mut(&t.id) {
            Some(e) => {
                if (&e.tunnel.target, e.tunnel.kind) != (&t.target, t.kind) {
                    e.ended.cancel();
                    e.ended = CancellationToken::new();
                }
                e.tunnel = t;
                e.registration = registration;
                e.last_error = None;
                e.withdrawn = false;
            }
            None => {
                map.insert(t.id.clone(), Entry::new(t, registration));
            }
        }
        Self::persist(&map);
    }

    /// Ends everything running for every tunnel (web terminal programs), keeping the tunnels.
    pub fn end_all(&self) {
        for e in self.map.lock().unwrap().values() {
            e.ended.cancel();
        }
    }

    pub fn remove(&self, id: &str) -> Option<LocalTunnel> {
        let mut map = self.map.lock().unwrap();
        let removed = map.remove(id).map(|e| {
            e.ended.cancel();
            e.tunnel
        });
        if removed.is_some() {
            Self::persist(&map);
        }
        removed
    }

    pub fn set_registration(&self, id: &str, r: Registration, error: Option<String>) {
        if let Some(e) = self.map.lock().unwrap().get_mut(id) {
            e.registration = r;
            e.last_error = error;
        }
    }

    /// Stops serving a tunnel the server registered differently from what was asked (public
    /// instead of private, HTTPS instead of a raw port), whether or not the server then removed
    /// it. It stays in the table, failed, until it is added again.
    pub fn withdraw(&self, id: &str, error: String) {
        if let Some(e) = self.map.lock().unwrap().get_mut(id) {
            e.registration = Registration::Failed;
            e.last_error = Some(error);
            e.withdrawn = true;
            e.ended.cancel();
            e.ended = CancellationToken::new();
        }
    }

    pub fn mark_all_pending(&self) {
        for e in self.map.lock().unwrap().values_mut() {
            e.registration = Registration::Pending;
        }
    }

    pub fn list(&self) -> Vec<LocalTunnel> {
        let mut v: Vec<_> = self.map.lock().unwrap().values().map(|e| e.tunnel.clone()).collect();
        v.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.name.cmp(&b.name)));
        v
    }

    pub fn snapshots(&self) -> Vec<TunnelSnapshot> {
        let mut v: Vec<_> = self
            .map
            .lock()
            .unwrap()
            .values()
            .map(|e| TunnelSnapshot { tunnel: e.tunnel.clone(), registration: e.registration, last_error: e.last_error.clone() })
            .collect();
        v.sort_by_key(|s| s.tunnel.created_at);
        v
    }

    pub fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }

    /// Local destination for a data stream; none for a withdrawn tunnel.
    pub fn route(&self, id: &str) -> Option<Route> {
        let map = self.map.lock().unwrap();
        map.get(id).filter(|e| !e.withdrawn).map(|e| Route {
            kind: e.tunnel.kind,
            target: e.tunnel.target.clone(),
            streams_ok: e.streams_ok.clone(),
            ended: e.ended.clone(),
            sessions: e.sessions.clone(),
        })
    }

    pub fn streams_ok(&self, id: &str) -> u64 {
        self.map.lock().unwrap().get(id).map(|e| e.streams_ok.load(Ordering::Relaxed)).unwrap_or(0)
    }

    pub fn find(&self, pred: impl Fn(&LocalTunnel) -> bool) -> Option<LocalTunnel> {
        self.map.lock().unwrap().values().map(|e| &e.tunnel).find(|t| pred(t)).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn withdrawn_tunnels_are_not_served() {
        let json = r#"{"id":"tn_1","name":"a","hostname":"a.t.test","public_url":"https://a.t.test","host":"127.0.0.1","port":8080,"created_at":1}"#;
        let t: LocalTunnel = serde_json::from_str(json).unwrap();
        let tunnels = Tunnels::default();
        // Inserted directly: `upsert` would write the real ~/.magicpipes/tunnels.json.
        tunnels.map.lock().unwrap().insert(t.id.clone(), Entry::new(t, Registration::Registered));
        let ended = tunnels.route("tn_1").expect("served").ended;
        tunnels.withdraw("tn_1", "the server no longer supports private tunnels".into());
        assert!(tunnels.route("tn_1").is_none());
        assert!(ended.is_cancelled(), "what was running for it ends");
        assert_eq!(tunnels.snapshots()[0].registration, Registration::Failed);
    }
}
