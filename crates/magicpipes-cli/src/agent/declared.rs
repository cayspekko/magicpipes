//! Serves the declared tunnels: those `MAGICPIPES_TUNNELS` names (`crate::declared`), and those the
//! cluster's Ingress objects ask for (`agent::ingress`), which come and go while the agent runs.
//! Each is added as `magicpipes add` would, trying again with a growing wait while it fails: in a
//! pod, the app may still be starting, or the server may not be reachable yet. After that the
//! session keeps it, as it keeps any tunnel. Once everything declared is known, the agent removes
//! the tunnels it served that aren't declared any more.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::ops::Agent;
use crate::ipc::{AddRequest, IpcEvent};

/// The longest wait between two tries at one tunnel.
const MAX_WAIT: Duration = Duration::from_secs(30);

/// Where a declaration came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// `MAGICPIPES_TUNNELS` or its file, for the agent's whole run.
    Environment,
    /// An Ingress object, as `namespace/name`.
    Ingress(String),
}

/// The tunnels the agent is declared to serve, by label (a `--name`, or a `--hostname`).
pub struct Declarations {
    agent: Arc<Agent>,
    shutdown: CancellationToken,
    items: Mutex<BTreeMap<String, Item>>,
    /// Everything declared is known: false until the Ingress watcher's first list is in.
    settled: std::sync::atomic::AtomicBool,
}

struct Item {
    req: AddRequest,
    source: Source,
    /// `None` once it was added; before, why the last try failed (an error code), if one did.
    waiting: Arc<Mutex<Option<Option<String>>>>,
    /// Ends its tries when it changes or goes.
    stop: CancellationToken,
}

/// Two requests ask for the same thing.
fn same(a: &AddRequest, b: &AddRequest) -> bool {
    serde_json::to_value(a).ok() == serde_json::to_value(b).ok()
}

impl Declarations {
    /// `settled`: nothing more is to come than what's declared at the start.
    pub fn new(agent: Arc<Agent>, shutdown: CancellationToken, settled: bool) -> Arc<Self> {
        Arc::new(Self { agent, shutdown, items: Mutex::default(), settled: settled.into() })
    }

    /// Everything declared is known now.
    pub fn settle(&self) {
        self.settled.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether everything declared is known: until then the agent isn't ready.
    pub fn settled(&self) -> bool {
        self.settled.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn items(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Item>> {
        self.items.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Serves `req` as `label`: a new tunnel, or a changed one, tried until it works. The same
    /// request again changes nothing.
    pub fn set(&self, label: &str, req: AddRequest, source: Source) {
        let mut items = self.items();
        if items.get(label).is_some_and(|i| same(&i.req, &req) && i.source == source) {
            return;
        }
        if let Some(old) = items.remove(label) {
            old.stop.cancel();
        }
        let waiting = Arc::new(Mutex::new(Some(None)));
        let stop = self.shutdown.child_token();
        let task = (self.agent.clone(), label.to_string(), req.clone(), waiting.clone(), stop.clone());
        items.insert(label.to_string(), Item { req, source, waiting, stop });
        tokio::spawn(async move {
            let (agent, label, req, waiting, stop) = task;
            keep_trying(&agent, &label, req, &waiting, &stop).await;
        });
    }

    /// Stops serving `label`, and removes its tunnel.
    pub async fn unset(&self, label: &str) {
        let Some(item) = self.items().remove(label) else { return };
        item.stop.cancel();
        if let Some(t) = self.agent.tunnels.find(|t| t.name == label || (t.custom_hostname && t.hostname == label)) {
            match self.agent.remove(&t.id, false).await {
                Ok(_) => tracing::info!(tunnel = %label, "removed a tunnel that isn't declared any more"),
                Err(e) => tracing::warn!(tunnel = %label, error = %e.message, "couldn't remove a tunnel that isn't declared any more"),
            }
        }
    }

    /// Who declared `label`, if anyone has.
    pub fn source_of(&self, label: &str) -> Option<Source> {
        self.items().get(label).map(|i| i.source.clone())
    }

    /// The labels `source` declared.
    pub fn labels_from(&self, source: &Source) -> Vec<String> {
        self.items().iter().filter(|(_, i)| i.source == *source).map(|(l, _)| l.clone()).collect()
    }

    /// Removes the tunnels the agent served that nothing declares: once at the start, when
    /// everything declared is known.
    pub async fn remove_others(&self) {
        let declared: Vec<String> = self.items().keys().cloned().collect();
        for t in self.agent.tunnels.list() {
            if !declared.iter().any(|l| *l == t.name || (t.custom_hostname && *l == t.hostname)) {
                match self.agent.remove(&t.id, false).await {
                    Ok(_) => tracing::info!(tunnel = %t.name, "removed a tunnel that isn't declared any more"),
                    Err(e) => tracing::warn!(tunnel = %t.name, error = %e.message, "couldn't remove a tunnel that isn't declared any more"),
                }
            }
        }
    }

    /// The declared tunnels' labels, and for those not added yet, why (an error code, if a try failed).
    pub fn waiting(&self) -> Vec<(String, Option<String>)> {
        self.items()
            .iter()
            .filter_map(|(label, i)| i.waiting.lock().unwrap_or_else(|e| e.into_inner()).clone().map(|why| (label.clone(), why)))
            .collect()
    }

    pub fn labels(&self) -> Vec<String> {
        self.items().keys().cloned().collect()
    }
}

/// Serves the environment's declarations: once connected, adds them, and unless an Ingress watcher
/// still has its own to add (`more_coming`), removes the tunnels nothing declares.
pub fn start(declarations: &Arc<Declarations>, declared: Vec<crate::declared::Declared>, more_coming: bool) {
    for d in declared {
        declarations.set(&d.label, d.req, Source::Environment);
    }
    if more_coming {
        return;
    }
    let me = declarations.clone();
    tokio::spawn(async move {
        // Removing needs the server.
        while me.agent.session.wait_connected(Duration::from_secs(30)).await.is_err() {
            if me.shutdown.is_cancelled() {
                return;
            }
        }
        me.remove_others().await;
    });
}

async fn keep_trying(agent: &Arc<Agent>, label: &str, req: AddRequest, waiting: &Mutex<Option<Option<String>>>, stop: &CancellationToken) {
    let mut wait = Duration::from_secs(1);
    loop {
        // `add` reports its steps as it goes; nobody is watching them here.
        let (tx, mut rx) = mpsc::channel::<IpcEvent>(16);
        let attempt = req.clone();
        let add = async move { agent.add(attempt, &tx).await };
        let drain = async { while rx.recv().await.is_some() {} };
        let result = tokio::select! {
            _ = stop.cancelled() => return,
            (result, ()) = async { tokio::join!(add, drain) } => result,
        };
        match result {
            Ok(_) => {
                *waiting.lock().unwrap_or_else(|e| e.into_inner()) = None;
                tracing::info!(tunnel = %label, "declared tunnel ready");
                return;
            }
            Err(e) => {
                tracing::warn!(tunnel = %label, code = %e.code, error = %e.message, retry_in = ?wait, "declared tunnel not ready");
                *waiting.lock().unwrap_or_else(|e| e.into_inner()) = Some(Some(e.code.clone()));
            }
        }
        tokio::select! {
            _ = stop.cancelled() => return,
            _ = tokio::time::sleep(wait) => {}
        }
        wait = (wait * 2).min(MAX_WAIT);
    }
}
