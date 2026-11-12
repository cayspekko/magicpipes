//! Serves the declared tunnels (`crate::declared`). Once connected, the agent removes the tunnels it
//! served that aren't declared any more, then adds each declared one as `magicpipes add` would,
//! trying again with a growing wait while it fails: in a pod, the app may still be starting, or the
//! server may not be reachable yet. After that the session keeps them, as it keeps any tunnel.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::ops::Agent;
use crate::declared::Declared;
use crate::ipc::IpcEvent;

/// The longest wait between two tries at one tunnel.
const MAX_WAIT: Duration = Duration::from_secs(30);

/// Where each declared tunnel stands, for the readiness endpoint.
pub struct Declarations {
    items: Vec<Item>,
}

struct Item {
    label: String,
    /// `None` once it was added; before, why the last try failed (an error code), if one did.
    waiting: Mutex<Option<Option<String>>>,
}

impl Declarations {
    /// The declared tunnels' labels, and for those not added yet, why (an error code, if a try failed).
    pub fn waiting(&self) -> Vec<(String, Option<String>)> {
        self.items
            .iter()
            .filter_map(|i| i.waiting.lock().unwrap_or_else(|e| e.into_inner()).clone().map(|why| (i.label.clone(), why)))
            .collect()
    }

    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.items.iter().map(|i| i.label.as_str())
    }
}

/// Starts serving `declared`, in the background.
pub fn spawn(agent: Arc<Agent>, declared: Vec<Declared>, shutdown: CancellationToken) -> Arc<Declarations> {
    let state = Arc::new(Declarations { items: declared.iter().map(|d| Item { label: d.label.clone(), waiting: Mutex::new(Some(None)) }).collect() });
    let me = state.clone();
    tokio::spawn(async move {
        // Removing needs the server, and so does everything after it.
        while agent.session.wait_connected(Duration::from_secs(30)).await.is_err() {
            if shutdown.is_cancelled() {
                return;
            }
        }
        for t in agent.tunnels.list() {
            let declared_here = declared.iter().any(|d| d.label == t.name || (t.custom_hostname && d.label == t.hostname));
            if !declared_here {
                match agent.remove(&t.id, false).await {
                    Ok(_) => tracing::info!(tunnel = %t.name, "removed a tunnel that isn't declared any more"),
                    Err(e) => tracing::warn!(tunnel = %t.name, error = %e.message, "couldn't remove a tunnel that isn't declared any more"),
                }
            }
        }
        for (i, d) in declared.into_iter().enumerate() {
            let (agent, me, shutdown) = (agent.clone(), me.clone(), shutdown.clone());
            tokio::spawn(async move { keep_trying(&agent, &me.items[i], d, &shutdown).await });
        }
    });
    state
}

async fn keep_trying(agent: &Arc<Agent>, item: &Item, d: Declared, shutdown: &CancellationToken) {
    let mut wait = Duration::from_secs(1);
    loop {
        // `add` reports its steps as it goes; nobody is watching them here.
        let (tx, mut rx) = mpsc::channel::<IpcEvent>(16);
        let req = d.req.clone();
        let add = async move { agent.add(req, &tx).await };
        let drain = async { while rx.recv().await.is_some() {} };
        let (result, ()) = tokio::join!(add, drain);
        match result {
            Ok(_) => {
                *item.waiting.lock().unwrap_or_else(|e| e.into_inner()) = None;
                tracing::info!(tunnel = %d.label, "declared tunnel ready");
                return;
            }
            Err(e) => {
                tracing::warn!(tunnel = %d.label, code = %e.code, error = %e.message, retry_in = ?wait, "declared tunnel not ready");
                *item.waiting.lock().unwrap_or_else(|e| e.into_inner()) = Some(Some(e.code.clone()));
            }
        }
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(wait) => {}
        }
        wait = (wait * 2).min(MAX_WAIT);
    }
}
