//! `MAGICPIPES_INGRESS_CLASS`: the gateway agent serves the cluster's Ingress objects of that class
//! (`spec.ingressClassName`, or the older `kubernetes.io/ingress.class` annotation) as tunnels, and
//! keeps them in step as the objects change. There's no separate controller: the agent watches the
//! API itself (`agent::kube`) and declares each tunnel as `MAGICPIPES_TUNNELS` would
//! (`agent::declared`).
//!
//! A tunnel sends a whole hostname to one backend, so each rule is one tunnel:
//!
//! * its host is `<name>.<base domain>` (a tunnel name) or a custom hostname an administrator gave
//!   this machine; without a host, the `magicpipes.io/name` annotation names it;
//! * it has one path, `/` (or none), whose backend is a Service in the Ingress's namespace, by port
//!   number or name. The agent reaches it at its cluster IP (a headless one at
//!   `<service>.<namespace>.svc`), and checks the Service again every minute.
//!
//! Annotations: `magicpipes.io/visibility` (`public` or `private`), `magicpipes.io/tags` (a
//! comma-separated list; private), `magicpipes.io/check-path`, and `magicpipes.io/checks: off`.
//! What can't be served is logged, once per change. Once a rule's tunnel works, the Ingress's
//! status says where (`status.loadBalancer.ingress[].hostname`), which `kubectl get ingress` shows.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use super::declared::{Declarations, Source};
use super::kube::{Ingress, Kube, KubeError, Service};
use super::ops::Agent;
use crate::ipc::AddRequest;

pub const CLASS_ENV: &str = "MAGICPIPES_INGRESS_CLASS";
pub const NAMESPACE_ENV: &str = "MAGICPIPES_INGRESS_NAMESPACE";
/// Tunnels the agent serves for Ingress objects; past this, the rest are refused.
const MAX_TUNNELS: usize = 200;
/// Ingress objects of the class kept in memory.
const MAX_INGRESSES: usize = 2000;
const ANNOTATION: &str = "magicpipes.io/";
const LEGACY_CLASS: &str = "kubernetes.io/ingress.class";
/// How often Services are looked up again, and statuses brought up to date.
const RESYNC: Duration = Duration::from_secs(60);
const STATUS_EVERY: Duration = Duration::from_secs(10);

/// What to watch, from the environment.
#[derive(Debug, Clone)]
pub struct Settings {
    pub class: String,
    pub namespace: Option<String>,
}

impl Settings {
    /// `None` without `MAGICPIPES_INGRESS_CLASS`.
    pub fn from_env() -> Result<Option<Self>, String> {
        let Ok(class) = std::env::var(CLASS_ENV) else { return Ok(None) };
        let class = class.trim().to_string();
        if class.is_empty() {
            return Ok(None);
        }
        let namespace = std::env::var(NAMESPACE_ENV).ok().map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
        if !is_dns_label(&class) || namespace.as_deref().is_some_and(|n| !is_dns_label(n)) {
            return Err(format!("{CLASS_ENV} and {NAMESPACE_ENV} must be names such as `magicpipes`"));
        }
        Ok(Some(Self { class, namespace }))
    }

    fn path(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("/apis/networking.k8s.io/v1/namespaces/{ns}/ingresses"),
            None => "/apis/networking.k8s.io/v1/ingresses".to_string(),
        }
    }
}

fn is_dns_label(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') && !s.starts_with('-') && !s.ends_with('-')
}

/// Is it one of ours?
fn ours(ing: &Ingress, class: &str) -> bool {
    match &ing.spec.class {
        Some(c) => c == class,
        None => ing.metadata.annotations.get(LEGACY_CLASS).is_some_and(|c| c == class),
    }
}

/// Where a rule's traffic goes: a Service in the Ingress's namespace, and its port.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Want {
    /// `--name` (a label of the base domain) or `--hostname`.
    address: Address,
    service: String,
    port: Port,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Address {
    Name(String),
    Hostname(String),
}

impl Address {
    fn label(&self) -> &str {
        match self {
            Address::Name(n) | Address::Hostname(n) => n,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Port {
    Number(u16),
    Name(String),
}

/// What each of an Ingress's rules asks for, or why it can't be served (with the host it's about).
fn wants(ing: &Ingress, base_domain: &str) -> Vec<Result<Want, (String, String)>> {
    let named = ing.metadata.annotations.get(&format!("{ANNOTATION}name")).cloned();
    let mut out = Vec::new();
    let backend_of = |b: &super::kube::Backend| -> Result<(String, Port), String> {
        let s = b.service.as_ref().ok_or("its backend isn't a Service")?;
        let port = match (&s.port.number, &s.port.name) {
            (Some(n), _) if *n > 0 => Port::Number(*n),
            (_, Some(n)) if !n.is_empty() => Port::Name(n.clone()),
            _ => return Err("its backend names no port".into()),
        };
        Ok((s.name.clone(), port))
    };
    let unnamed = |named: &Option<String>| named.clone().map(Address::Name).ok_or_else(|| "it has no host; give it one, or a magicpipes.io/name annotation".to_string());
    if ing.spec.rules.is_empty() {
        if let Some(b) = &ing.spec.default_backend {
            let r = unnamed(&named).and_then(|address| backend_of(b).map(|(service, port)| Want { address, service, port }));
            out.push(r.map_err(|why| (String::new(), why)));
        }
        return out;
    }
    for rule in &ing.spec.rules {
        let host = rule.host.as_deref().unwrap_or("").trim().trim_end_matches('.').to_ascii_lowercase();
        let address = if host.is_empty() {
            unnamed(&named)
        } else if host.starts_with("*.") {
            Err("wildcard hosts aren't served".into())
        } else {
            match host.strip_suffix(&format!(".{base_domain}")) {
                Some(label) if label.contains('.') => Err(format!("only one label can come before {base_domain}")),
                Some(label) => Ok(Address::Name(label.to_string())),
                None => Ok(Address::Hostname(host.clone())),
            }
        };
        let paths = rule.http.as_ref().map(|h| h.paths.as_slice()).unwrap_or_default();
        let backend = match paths {
            [one] if one.path.as_deref().is_none_or(|p| p.is_empty() || p == "/") => backend_of(&one.backend),
            [] => ing.spec.default_backend.as_ref().ok_or_else(|| "it has no path and no default backend".to_string()).and_then(backend_of),
            _ => Err("a tunnel sends a whole hostname to one backend: give the host one path, /".into()),
        };
        let r = address.and_then(|address| backend.map(|(service, port)| Want { address, service, port }));
        if let Ok(w) = &r
            && out.iter().any(|o: &Result<Want, (String, String)>| o.as_ref().is_ok_and(|x| x.address == w.address))
        {
            out.push(Err((host, "the same host is in another rule".into())));
            continue;
        }
        out.push(r.map_err(|why| (host, why)));
    }
    out
}

/// The `add` arguments for a rule, once its Service is known: its cluster IP, or for a headless
/// one, its name in the cluster's DNS.
fn words(ing: &Ingress, want: &Want, svc: &Service) -> Result<Vec<String>, String> {
    let port = match &want.port {
        Port::Number(n) => *n,
        Port::Name(name) => svc.spec.ports.iter().find(|p| p.name.as_deref() == Some(name)).map(|p| p.port).ok_or_else(|| format!("service {} has no port named {name}", want.service))?,
    };
    let host = match svc.spec.cluster_ip.as_deref() {
        Some(ip) if !ip.is_empty() && ip != "None" => ip.to_string(),
        _ => format!("{}.{}.svc", want.service, ing.metadata.namespace),
    };
    let mut w = vec![port.to_string(), "--host".into(), host];
    match &want.address {
        Address::Name(n) => w.extend(["--name".into(), n.clone()]),
        Address::Hostname(h) => w.extend(["--hostname".into(), h.clone()]),
    }
    let note = |key: &str| ing.metadata.annotations.get(&format!("{ANNOTATION}{key}")).map(|v| v.trim().to_string());
    match note("visibility").as_deref() {
        None => {}
        Some("public") => w.push("--public".into()),
        Some("private") => w.push("--private".into()),
        Some(other) => return Err(format!("magicpipes.io/visibility is '{other}', not public or private")),
    }
    if let Some(tags) = note("tags").filter(|t| !t.is_empty()) {
        w.extend(["--tag".into(), tags]);
    }
    if let Some(path) = note("check-path") {
        w.extend(["--probe-path".into(), path]);
    }
    match note("checks").as_deref() {
        None | Some("on") => {}
        Some("off") => w.push("--no-check".into()),
        Some(other) => return Err(format!("magicpipes.io/checks is '{other}', not on or off")),
    }
    Ok(w)
}

/// One Ingress's tunnels, as declared, or why each rule can't be.
type Resolved = Vec<Result<(String, AddRequest), (String, String)>>;

struct Watcher {
    kube: Kube,
    settings: Settings,
    base_domain: String,
    agent: Arc<Agent>,
    declarations: Arc<Declarations>,
    /// Ours, by `namespace/name`.
    ingresses: BTreeMap<String, Ingress>,
    resolved: BTreeMap<String, Resolved>,
    /// What was last logged as refused, so a change is logged once.
    said: BTreeMap<String, Vec<(String, String)>>,
    /// The hostnames each Ingress's status last got.
    status: BTreeMap<String, Vec<String>>,
}

fn key(ing: &Ingress) -> String {
    format!("{}/{}", ing.metadata.namespace, ing.metadata.name)
}

/// Starts serving the Ingress objects of `settings.class`, in the background. Once the first list
/// is in, it removes the tunnels nothing declares.
pub fn spawn(settings: Settings, kube: Kube, agent: Arc<Agent>, declarations: Arc<Declarations>, base_domain: String, shutdown: CancellationToken) {
    let w = Watcher { kube, settings, base_domain, agent, declarations, ingresses: BTreeMap::new(), resolved: BTreeMap::new(), said: BTreeMap::new(), status: BTreeMap::new() };
    tokio::spawn(async move { w.run(shutdown).await });
}

impl Watcher {
    async fn run(mut self, shutdown: CancellationToken) {
        let mut first = true;
        let mut wait = Duration::from_secs(1);
        let path = self.settings.path();
        loop {
            // A full list, then changes from where it left off; a list again when the server has
            // forgotten that point (410) or something went wrong.
            let listed = tokio::select! {
                _ = shutdown.cancelled() => return,
                l = self.kube.list::<Ingress>(&path) => l,
            };
            let (items, mut version) = match listed {
                Ok(l) => l,
                Err(e) => {
                    tracing::warn!(error = %e, retry_in = ?wait, "couldn't list Ingress objects");
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = tokio::time::sleep(wait) => {}
                    }
                    wait = (wait * 2).min(Duration::from_secs(30));
                    continue;
                }
            };
            wait = Duration::from_secs(1);
            self.ingresses = items.into_iter().filter(|i| ours(i, &self.settings.class)).take(MAX_INGRESSES).map(|i| (key(&i), i)).collect();
            self.resolved.clear();
            self.apply().await;
            self.declarations.settle();
            if first {
                first = false;
                // Removing needs the server.
                while self.agent.session.wait_connected(Duration::from_secs(30)).await.is_err() {
                    if shutdown.is_cancelled() {
                        return;
                    }
                }
                self.declarations.remove_others().await;
            }
            let mut resync = tokio::time::interval(RESYNC);
            resync.reset();
            let mut status = tokio::time::interval(STATUS_EVERY);
            'watching: loop {
                let mut watch = match self.kube.watch(&path, &version).await {
                    Ok(w) => w,
                    Err(e) if e.status == Some(http::StatusCode::GONE) => break 'watching,
                    Err(e) => {
                        tracing::warn!(error = %e, "couldn't watch Ingress objects");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        break 'watching;
                    }
                };
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = resync.tick() => {
                            self.resolved.clear();
                            self.apply().await;
                        }
                        _ = status.tick() => self.update_status().await,
                        event = watch.next() => match event {
                            Ok(Some(ev)) => match ev.kind.as_str() {
                                "ADDED" | "MODIFIED" | "DELETED" => {
                                    let Ok(ing) = serde_json::from_value::<Ingress>(ev.object) else { continue };
                                    version = ing.metadata.resource_version.clone();
                                    let k = key(&ing);
                                    let keep = ev.kind != "DELETED" && ours(&ing, &self.settings.class);
                                    let changed = match keep {
                                        true if self.ingresses.get(&k) != Some(&ing) && (self.ingresses.contains_key(&k) || self.ingresses.len() < MAX_INGRESSES) => {
                                            self.ingresses.insert(k.clone(), ing);
                                            true
                                        }
                                        true => false,
                                        false => self.ingresses.remove(&k).is_some(),
                                    };
                                    if changed {
                                        self.resolved.remove(&k);
                                        self.status.remove(&k);
                                        self.apply().await;
                                    }
                                }
                                "BOOKMARK" => {
                                    if let Some(v) = ev.object["metadata"]["resourceVersion"].as_str() {
                                        version = v.to_string();
                                    }
                                }
                                // Usually 410: the server no longer has that version.
                                _ => break 'watching,
                            },
                            // The server ended this watch; another goes on from the same point.
                            Ok(None) => continue 'watching,
                            Err(e) => {
                                tracing::warn!(error = %e, "the Ingress watch broke off");
                                break 'watching;
                            }
                        },
                    }
                }
            }
        }
    }

    /// Declares what the Ingress objects ask for now, and takes back what they no longer do.
    async fn apply(&mut self) {
        let keys: Vec<String> = self.ingresses.keys().cloned().collect();
        for k in &keys {
            if !self.resolved.contains_key(k) {
                let resolved = self.resolve(&self.ingresses[k]).await;
                self.resolved.insert(k.clone(), resolved);
            }
        }
        self.resolved.retain(|k, _| self.ingresses.contains_key(k));
        let mut serving = 0usize;
        let mut wanted: BTreeMap<String, String> = BTreeMap::new();
        for (k, resolved) in &self.resolved {
            let mut refused: Vec<(String, String)> = Vec::new();
            let source = Source::Ingress(k.clone());
            for r in resolved {
                match r {
                    Err(e) => refused.push(e.clone()),
                    Ok((label, req)) => {
                        // The environment's lines first, then the first Ingress by name.
                        let taken = match self.declarations.source_of(label) {
                            Some(Source::Environment) => Some("it's declared in MAGICPIPES_TUNNELS".to_string()),
                            _ => wanted.get(label).filter(|owner| *owner != k).map(|owner| format!("Ingress {owner} serves it")),
                        };
                        if let Some(why) = taken {
                            refused.push((label.clone(), why));
                        } else if serving >= MAX_TUNNELS {
                            refused.push((label.clone(), format!("this agent serves at most {MAX_TUNNELS} tunnels for Ingress objects")));
                        } else {
                            serving += 1;
                            wanted.insert(label.clone(), k.clone());
                            self.declarations.set(label, req.clone(), source.clone());
                        }
                    }
                }
            }
            if self.said.get(k) != Some(&refused) {
                for (host, why) in &refused {
                    tracing::warn!(ingress = %k, host = %host, %why, "can't serve this Ingress rule");
                }
                self.said.insert(k.clone(), refused);
            }
        }
        self.said.retain(|k, _| self.resolved.contains_key(k));
        // What an Ingress declared before and doesn't now.
        for k in self.ingress_sources() {
            for label in self.declarations.labels_from(&Source::Ingress(k.clone())) {
                if wanted.get(&label) != Some(&k) {
                    self.declarations.unset(&label).await;
                }
            }
        }
    }

    /// The Ingress objects that have declared something: those known now, and those gone since.
    fn ingress_sources(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.ingresses.keys().cloned().collect();
        for label in self.declarations.labels() {
            if let Some(Source::Ingress(k)) = self.declarations.source_of(&label)
                && !keys.contains(&k)
            {
                keys.push(k);
            }
        }
        keys
    }

    async fn resolve(&self, ing: &Ingress) -> Resolved {
        let mut services: BTreeMap<String, Result<Service, KubeError>> = BTreeMap::new();
        let mut out = Vec::new();
        for want in wants(ing, &self.base_domain) {
            let want = match want {
                Ok(w) => w,
                Err(e) => {
                    out.push(Err(e));
                    continue;
                }
            };
            let host = want.address.label().to_string();
            if !services.contains_key(&want.service) {
                let path = format!("/api/v1/namespaces/{}/services/{}", ing.metadata.namespace, magicpipes_core::url::encode(&want.service));
                services.insert(want.service.clone(), self.kube.get::<Service>(&path).await);
            }
            let r = match &services[&want.service] {
                Ok(svc) => words(ing, &want, svc).and_then(|w| crate::declared::declare(w).map(|d| (d.label, d.req))),
                Err(e) if e.status == Some(http::StatusCode::NOT_FOUND) => Err(format!("there's no service {} in {}", want.service, ing.metadata.namespace)),
                Err(e) => Err(format!("couldn't read service {}: {e}", want.service)),
            };
            out.push(r.map_err(|why| (host, why)));
        }
        out
    }

    /// Writes each Ingress's public hostnames, once its tunnels work, to its status.
    async fn update_status(&mut self) {
        let waiting: Vec<String> = self.declarations.waiting().into_iter().map(|(l, _)| l).collect();
        let keys: Vec<String> = self.ingresses.keys().cloned().collect();
        for k in keys {
            let source = Source::Ingress(k.clone());
            let mut hosts: Vec<String> = self
                .declarations
                .labels_from(&source)
                .into_iter()
                .filter(|l| !waiting.contains(l))
                .filter_map(|l| self.agent.tunnels.find(|t| t.name == l || (t.custom_hostname && t.hostname == l)).map(|t| t.hostname))
                .collect();
            hosts.sort();
            if self.status.get(&k) == Some(&hosts) {
                continue;
            }
            let Some(ing) = self.ingresses.get(&k) else { continue };
            let path = format!("/apis/networking.k8s.io/v1/namespaces/{}/ingresses/{}/status", ing.metadata.namespace, magicpipes_core::url::encode(&ing.metadata.name));
            let entries: Vec<serde_json::Value> = hosts.iter().map(|h| serde_json::json!({ "hostname": h })).collect();
            let patch = serde_json::json!({ "status": { "loadBalancer": { "ingress": entries } } });
            match self.kube.merge_patch(&path, &patch).await {
                Ok(()) => tracing::info!(ingress = %k, hosts = ?hosts, "Ingress status updated"),
                // Without the permission, it's said once, and not tried again until it changes.
                Err(e) => tracing::warn!(ingress = %k, error = %e, "couldn't update the Ingress's status (it needs patch on ingresses/status)"),
            }
            self.status.insert(k, hosts);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ingress(json: &str) -> Ingress {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn rules_become_tunnels_or_say_why_not() {
        let ing = ingress(
            r#"{"metadata":{"name":"shop","namespace":"web","annotations":{"magicpipes.io/tags":"team:ops","magicpipes.io/checks":"off"}},"spec":{"ingressClassName":"magicpipes","rules":[
            {"host":"shop.t.example.com","http":{"paths":[{"path":"/","pathType":"Prefix","backend":{"service":{"name":"front","port":{"name":"http"}}}}]}},
            {"host":"Shop.Example.org.","http":{"paths":[{"backend":{"service":{"name":"front","port":{"number":8080}}}}]}},
            {"host":"a.b.t.example.com","http":{"paths":[{"path":"/","backend":{"service":{"name":"x","port":{"number":1}}}}]}},
            {"host":"two.t.example.com","http":{"paths":[{"path":"/","backend":{"service":{"name":"x","port":{"number":1}}}},{"path":"/api","backend":{"service":{"name":"y","port":{"number":2}}}}]}},
            {"host":"*.t.example.com","http":{"paths":[{"path":"/","backend":{"service":{"name":"x","port":{"number":1}}}}]}},
            {"http":{"paths":[{"path":"/","backend":{"service":{"name":"x","port":{"number":1}}}}]}},
            {"host":"shop.t.example.com","http":{"paths":[{"path":"/","backend":{"service":{"name":"x","port":{"number":1}}}}]}}
            ]}}"#,
        );
        assert!(ours(&ing, "magicpipes") && !ours(&ing, "nginx"));
        let w = wants(&ing, "t.example.com");
        assert_eq!(w[0], Ok(Want { address: Address::Name("shop".into()), service: "front".into(), port: Port::Name("http".into()) }));
        assert_eq!(w[1], Ok(Want { address: Address::Hostname("shop.example.org".into()), service: "front".into(), port: Port::Number(8080) }));
        let why = |i: usize| w[i].clone().unwrap_err().1;
        assert!(why(2).contains("only one label"), "{}", why(2));
        assert!(why(3).contains("one path"), "{}", why(3));
        assert!(why(4).contains("wildcard"), "{}", why(4));
        assert!(why(5).contains("magicpipes.io/name"), "{}", why(5));
        assert!(why(6).contains("same host"), "{}", why(6));

        // A Service's cluster IP and named port, or a headless one by name.
        let svc: Service = serde_json::from_str(r#"{"spec":{"clusterIP":"10.0.0.7","ports":[{"name":"http","port":80}]}}"#).unwrap();
        let first = w[0].clone().unwrap();
        assert_eq!(words(&ing, &first, &svc).unwrap(), ["80", "--host", "10.0.0.7", "--name", "shop", "--tag", "team:ops", "--no-check"]);
        let headless: Service = serde_json::from_str(r#"{"spec":{"clusterIP":"None","ports":[{"name":"http","port":80}]}}"#).unwrap();
        assert_eq!(words(&ing, &first, &headless).unwrap()[2], "front.web.svc");
        let unnamed: Service = serde_json::from_str(r#"{"spec":{"clusterIP":"10.0.0.7","ports":[{"port":80}]}}"#).unwrap();
        assert!(words(&ing, &first, &unnamed).unwrap_err().contains("no port named http"));
        // The words are an `add` that checks out.
        let d = crate::declared::declare(words(&ing, &first, &svc).unwrap()).unwrap();
        assert_eq!((d.label.as_str(), d.req.port, d.req.host.as_deref(), d.req.no_check), ("shop", Some(80), Some("10.0.0.7"), true));
    }

    #[test]
    fn a_default_backend_needs_a_name_and_annotations_are_checked() {
        let bare = ingress(r#"{"metadata":{"name":"d","namespace":"n"},"spec":{"defaultBackend":{"service":{"name":"s","port":{"number":80}}}}}"#);
        assert!(wants(&bare, "t.test")[0].clone().unwrap_err().1.contains("magicpipes.io/name"));
        let named = ingress(r#"{"metadata":{"name":"d","namespace":"n","annotations":{"magicpipes.io/name":"docs","magicpipes.io/visibility":"sideways","kubernetes.io/ingress.class":"magicpipes"}},"spec":{"defaultBackend":{"service":{"name":"s","port":{"number":80}}}}}"#);
        assert!(ours(&named, "magicpipes"), "the older annotation");
        let want = wants(&named, "t.test")[0].clone().unwrap();
        assert_eq!(want.address, Address::Name("docs".into()));
        let svc: Service = serde_json::from_str(r#"{"spec":{"clusterIP":"10.0.0.8"}}"#).unwrap();
        assert!(words(&named, &want, &svc).unwrap_err().contains("not public or private"));
        assert!(Settings::from_env().is_ok());
        assert!(is_dns_label("magicpipes") && !is_dns_label("Magic Pipes") && !is_dns_label("-x"));
    }
}
