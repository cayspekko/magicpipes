//! A minimal Kubernetes API client, for the Ingress watcher (`agent::ingress`): the few calls it
//! makes, over the agent's own HTTPS stack, as the pod's service account. It trusts only the
//! cluster's CA and parses only the fields it uses, so an object it doesn't understand is skipped,
//! never a reason to stop.
//!
//! In a pod, the API is at `KUBERNETES_SERVICE_HOST:KUBERNETES_SERVICE_PORT`, and the token and CA
//! are in `/var/run/secrets/kubernetes.io/serviceaccount` (`MAGICPIPES_KUBE_DIR` names another
//! folder, for tests or running outside the cluster). The token is read again for every request,
//! since the kubelet replaces it as it expires.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use bytes::{Bytes, BytesMut};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use rustls::ClientConfig;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde::Deserialize;
use serde::de::DeserializeOwned;

pub const KUBE_DIR_ENV: &str = "MAGICPIPES_KUBE_DIR";
const SERVICE_ACCOUNT_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
/// A list answer bigger than this is a mistake, or a cluster too big for one gateway.
const MAX_LIST: usize = 16 * 1024 * 1024;
/// One watch event; Ingress objects are small.
const MAX_EVENT: usize = 1024 * 1024;
/// Gets and patches.
const MAX_ANSWER: usize = 256 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// The server ends a watch after this long, and the watcher starts another.
pub const WATCH_SECS: u64 = 290;

pub struct Kube {
    host: String,
    port: u16,
    tls: Arc<ClientConfig>,
    token: PathBuf,
}

/// A refusal from the API server: its status code and what it said.
#[derive(Debug)]
pub struct KubeError {
    pub status: Option<StatusCode>,
    pub message: String,
}

impl std::fmt::Display for KubeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.status {
            Some(s) => write!(f, "{} ({s})", self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl From<anyhow::Error> for KubeError {
    fn from(e: anyhow::Error) -> Self {
        Self { status: None, message: format!("{e:#}") }
    }
}

impl Kube {
    /// The API of the cluster this pod runs in.
    pub fn in_cluster() -> anyhow::Result<Self> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST").context("KUBERNETES_SERVICE_HOST isn't set: is this running in a Kubernetes pod?")?;
        let port: u16 = std::env::var("KUBERNETES_SERVICE_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(443);
        let dir = std::env::var_os(KUBE_DIR_ENV).map_or_else(|| PathBuf::from(SERVICE_ACCOUNT_DIR), PathBuf::from);
        let ca = std::fs::read_to_string(dir.join("ca.crt")).with_context(|| format!("reading {}", dir.join("ca.crt").display()))?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(ca.as_bytes()) {
            roots.add(cert.map_err(|e| anyhow!("the cluster's CA certificate: {e}"))?)?;
        }
        if roots.is_empty() {
            bail!("{} holds no certificate", dir.join("ca.crt").display());
        }
        let mut tls = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self { host: host.trim_start_matches('[').trim_end_matches(']').to_string(), port, tls: Arc::new(tls), token: dir.join("token") })
    }

    async fn send(&self, method: Method, path: &str, patch: Option<&serde_json::Value>) -> Result<hyper::Response<Incoming>, KubeError> {
        let token = std::fs::read_to_string(&self.token).with_context(|| format!("reading {}", self.token.display()))?;
        let stream = crate::https::connect(&self.host, self.port, &self.tls, None).await?;
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header(http::header::HOST, crate::https::host_header(&self.host, self.port))
            .header(http::header::USER_AGENT, crate::https::USER_AGENT)
            .header(http::header::ACCEPT, "application/json")
            .header(http::header::AUTHORIZATION, format!("Bearer {}", token.trim()));
        let req = match patch {
            Some(body) => req.header(http::header::CONTENT_TYPE, "application/merge-patch+json").body(Full::new(Bytes::from(serde_json::to_vec(body).map_err(anyhow::Error::from)?))),
            None => req.body(Full::new(Bytes::new())),
        }
        .map_err(anyhow::Error::from)?;
        let resp = crate::https::send(stream, req).await?;
        if resp.status().is_success() {
            return Ok(resp);
        }
        let status = resp.status();
        let said = read_at_most(resp, MAX_ANSWER).await.ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
        let message = said.as_ref().and_then(|v| v["message"].as_str()).unwrap_or("the API server refused").to_string();
        Err(KubeError { status: Some(status), message })
    }

    /// A GET that answers JSON, at most `limit` bytes of it.
    async fn get_at_most<T: DeserializeOwned>(&self, path: &str, limit: usize) -> Result<T, KubeError> {
        let exchange = async {
            let resp = self.send(Method::GET, path, None).await?;
            let body = read_at_most(resp, limit).await?;
            serde_json::from_slice(&body).map_err(|e| KubeError { status: None, message: format!("an answer that isn't what was asked for: {e}") })
        };
        tokio::time::timeout(REQUEST_TIMEOUT, exchange).await.map_err(|_| KubeError { status: None, message: "the API server didn't answer in time".into() })?
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, KubeError> {
        self.get_at_most(path, MAX_ANSWER).await
    }

    /// Every object at `path`, a page at a time, and the version to watch from.
    pub async fn list<T: DeserializeOwned>(&self, path: &str) -> Result<(Vec<T>, String), KubeError> {
        let mut items = Vec::new();
        let mut cont = String::new();
        loop {
            let sep = if path.contains('?') { '&' } else { '?' };
            let page_path = if cont.is_empty() { format!("{path}{sep}limit=500") } else { format!("{path}{sep}limit=500&continue={}", magicpipes_core::url::encode(&cont)) };
            let page: List<T> = self.get_at_most(&page_path, MAX_LIST).await?;
            items.extend(page.items);
            if page.metadata.cont.is_empty() {
                return Ok((items, page.metadata.resource_version));
            }
            cont = page.metadata.cont;
        }
    }

    /// Changes at `path` from `version` on, until the server ends the watch (after [`WATCH_SECS`]).
    pub async fn watch(&self, path: &str, version: &str) -> Result<Watch, KubeError> {
        let sep = if path.contains('?') { '&' } else { '?' };
        let path = format!("{path}{sep}watch=1&allowWatchBookmarks=true&timeoutSeconds={WATCH_SECS}&resourceVersion={}", magicpipes_core::url::encode(version));
        let resp = tokio::time::timeout(REQUEST_TIMEOUT, self.send(Method::GET, &path, None))
            .await
            .map_err(|_| KubeError { status: None, message: "the API server didn't answer in time".into() })??;
        Ok(Watch { body: resp.into_body(), buf: BytesMut::new() })
    }

    /// A JSON merge patch.
    pub async fn merge_patch(&self, path: &str, patch: &serde_json::Value) -> Result<(), KubeError> {
        let exchange = async {
            let resp = self.send(Method::PATCH, path, Some(patch)).await?;
            read_at_most(resp, MAX_ANSWER).await?;
            Ok(())
        };
        tokio::time::timeout(REQUEST_TIMEOUT, exchange).await.map_err(|_| KubeError { status: None, message: "the API server didn't answer in time".into() })?
    }
}

async fn read_at_most(resp: hyper::Response<Incoming>, limit: usize) -> anyhow::Result<Bytes> {
    let body = http_body_util::Limited::new(resp.into_body(), limit);
    Ok(body.collect().await.map_err(|e| anyhow!("reading the API server's answer: {e}"))?.to_bytes())
}

/// A watch's events, one JSON line each.
pub struct Watch {
    body: Incoming,
    buf: BytesMut,
}

impl Watch {
    /// The next event; `None` when the server ended the watch.
    pub async fn next(&mut self) -> Result<Option<WatchEvent>, KubeError> {
        loop {
            if let Some(at) = self.buf.iter().position(|b| *b == b'\n') {
                let line = self.buf.split_to(at + 1);
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                return serde_json::from_slice(&line).map(Some).map_err(|e| KubeError { status: None, message: format!("a watch event that isn't one: {e}") });
            }
            if self.buf.len() > MAX_EVENT {
                return Err(KubeError { status: None, message: format!("a watch event longer than {} KiB", MAX_EVENT / 1024) });
            }
            // The server sends at least a bookmark now and then; past its own timeout, it's gone.
            let frame = tokio::time::timeout(Duration::from_secs(WATCH_SECS + 60), self.body.frame()).await;
            match frame {
                Err(_) => return Err(KubeError { status: None, message: "the watch went quiet".into() }),
                Ok(None) => return Ok(None),
                Ok(Some(Err(e))) => return Err(KubeError { status: None, message: format!("the watch broke off: {e}") }),
                Ok(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        self.buf.extend_from_slice(&data);
                    }
                }
            }
        }
    }
}

// ---- the objects, as far as they're used ------------------------------------------------------

#[derive(Debug, Deserialize)]
struct List<T> {
    #[serde(default = "Vec::new")]
    items: Vec<T>,
    #[serde(default)]
    metadata: ListMeta,
}

#[derive(Debug, Default, Deserialize)]
struct ListMeta {
    #[serde(default, rename = "resourceVersion")]
    resource_version: String,
    #[serde(default, rename = "continue")]
    cont: String,
}

#[derive(Debug, Deserialize)]
pub struct WatchEvent {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub object: serde_json::Value,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ObjectMeta {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub uid: String,
    #[serde(default, rename = "resourceVersion")]
    pub resource_version: String,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Ingress {
    #[serde(default)]
    pub metadata: ObjectMeta,
    #[serde(default)]
    pub spec: IngressSpec,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct IngressSpec {
    #[serde(default, rename = "ingressClassName")]
    pub class: Option<String>,
    #[serde(default, rename = "defaultBackend")]
    pub default_backend: Option<Backend>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub http: Option<HttpRule>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct HttpRule {
    #[serde(default)]
    pub paths: Vec<HttpPath>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct HttpPath {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub backend: Backend,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Backend {
    #[serde(default)]
    pub service: Option<ServiceBackend>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ServiceBackend {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub port: ServicePort,
}

/// A Service's port, by number or by name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ServicePort {
    #[serde(default)]
    pub number: Option<u16>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Service {
    #[serde(default)]
    pub spec: ServiceSpec,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ServiceSpec {
    #[serde(default, rename = "clusterIP")]
    pub cluster_ip: Option<String>,
    #[serde(default)]
    pub ports: Vec<ServicePortSpec>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ServicePortSpec {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub port: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn objects_read_with_only_what_is_used() {
        let ing: Ingress = serde_json::from_str(
            r#"{"apiVersion":"networking.k8s.io/v1","kind":"Ingress","metadata":{"name":"shop","namespace":"web","uid":"u1","resourceVersion":"7","annotations":{"magicpipes.io/visibility":"public"},"labels":{"a":"b"}},
            "spec":{"ingressClassName":"magicpipes","tls":[{"hosts":["x"]}],"rules":[{"host":"shop.t.example.com","http":{"paths":[{"path":"/","pathType":"Prefix","backend":{"service":{"name":"front","port":{"name":"http"}}}}]}}]},"status":{}}"#,
        )
        .unwrap();
        assert_eq!((ing.metadata.name.as_str(), ing.metadata.namespace.as_str(), ing.spec.class.as_deref()), ("shop", "web", Some("magicpipes")));
        let backend = ing.spec.rules[0].http.as_ref().unwrap().paths[0].backend.service.clone().unwrap();
        assert_eq!((backend.name.as_str(), backend.port.name.as_deref(), backend.port.number), ("front", Some("http"), None));
        let empty: Ingress = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, Ingress::default(), "nothing is required");
        let svc: Service = serde_json::from_str(r#"{"spec":{"clusterIP":"10.0.0.7","ports":[{"name":"http","port":80,"targetPort":8080}]}}"#).unwrap();
        assert_eq!((svc.spec.cluster_ip.as_deref(), svc.spec.ports[0].port), (Some("10.0.0.7"), 80));
    }
}
