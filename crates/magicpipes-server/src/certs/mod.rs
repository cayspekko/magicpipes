//! Certificate management (control plane) and the TLS certificate resolver (read by ingress).
//!
//! The control plane calls [`CertManager::ensure`] for every hostname it is willing to serve
//! (registered tunnels and the management hostname). Nothing is issued on demand for arbitrary
//! SNI names, so an attacker cannot make the server request certificates. Issued certificates
//! are cached on disk and installed into the [`CertResolver`], which the TLS acceptors consult
//! for every handshake without touching the control plane.

mod acme;
mod devca;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use magicpipes_core::unix_now;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::{Semaphore, watch};
use tokio_util::sync::CancellationToken;

use crate::config::{TlsConfig, TlsMode};

pub use acme::Http01Challenges;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertStatus {
    Pending,
    Ready,
    Failed(String),
}

impl CertStatus {
    pub fn label(&self) -> &'static str {
        match self {
            CertStatus::Pending => "pending",
            CertStatus::Ready => "ready",
            CertStatus::Failed(_) => "failed",
        }
    }
}

// ---- resolver ----------------------------------------------------------------------------

/// SNI -> certificate lookup. Exact names first, then single-label wildcards.
#[derive(Default, Debug)]
pub struct CertResolver {
    exact: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    wildcard: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}

impl CertResolver {
    pub fn insert(&self, name: &str, key: Arc<CertifiedKey>) {
        let name = name.to_ascii_lowercase();
        if let Some(suffix) = name.strip_prefix("*.") {
            self.wildcard.write().unwrap().insert(suffix.to_string(), key);
        } else {
            self.exact.write().unwrap().insert(name, key);
        }
    }

    pub fn lookup(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let host = host.to_ascii_lowercase();
        if let Some(k) = self.exact.read().unwrap().get(&host) {
            return Some(k.clone());
        }
        let (_, parent) = host.split_once('.')?;
        self.wildcard.read().unwrap().get(parent).cloned()
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.lookup(hello.server_name()?)
    }
}

/// Answers for one hostname only. The management listener uses this: the shared resolver also
/// holds every tunnel's certificate, and the management UI must not be reachable under a
/// tunnel's hostname (its session cookie would then belong to the tunnel's origin).
#[derive(Debug)]
pub struct SingleHost {
    pub host: String,
    pub inner: Arc<CertResolver>,
}

impl ResolvesServerCert for SingleHost {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name()?;
        if name.eq_ignore_ascii_case(&self.host) { self.inner.lookup(&self.host) } else { None }
    }
}

pub fn server_config(resolver: Arc<dyn ResolvesServerCert>) -> Arc<rustls::ServerConfig> {
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

// ---- PEM helpers -------------------------------------------------------------------------

pub struct LoadedCert {
    pub key: Arc<CertifiedKey>,
    pub names: Vec<String>,
    pub not_before: i64,
    pub not_after: i64,
}

pub fn load_pem(chain_pem: &[u8], key_pem: &[u8]) -> anyhow::Result<LoadedCert> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(chain_pem)
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow!("invalid certificate PEM: {e}"))?;
    let leaf = chain.first().ok_or_else(|| anyhow!("certificate PEM contains no certificate"))?;
    let key_der = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| anyhow!("invalid private key PEM: {e}"))?;
    let signing = rustls::crypto::ring::sign::any_supported_type(&key_der).context("unsupported private key")?;
    let (_, x509) = x509_parser::parse_x509_certificate(leaf).map_err(|e| anyhow!("invalid certificate: {e}"))?;
    let mut names = Vec::new();
    if let Ok(Some(san)) = x509.subject_alternative_name() {
        for n in &san.value.general_names {
            if let x509_parser::extensions::GeneralName::DNSName(d) = n {
                names.push(d.to_ascii_lowercase());
            }
        }
    }
    let validity = x509.validity();
    Ok(LoadedCert {
        key: Arc::new(CertifiedKey::new(chain.clone(), signing)),
        names,
        not_before: validity.not_before.timestamp(),
        not_after: validity.not_after.timestamp(),
    })
}

fn covers(names: &[String], host: &str) -> bool {
    names.iter().any(|n| {
        n == host || n.strip_prefix("*.").is_some_and(|s| host.split_once('.').is_some_and(|(_, p)| p == s))
    })
}

/// Writes a file readable only by the owner (mode 0600 on Unix).
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    // A fresh file (O_EXCL, which also refuses a symlink), so a leftover temp file can't lend
    // its permissions.
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(tmp, path)
}

// ---- manager -----------------------------------------------------------------------------

struct HostCert {
    status: watch::Sender<CertStatus>,
    not_before: i64,
    not_after: i64,
    issuing: bool,
    failed_at: Option<Instant>,
}

pub struct CertManager {
    cfg: TlsConfig,
    dir: PathBuf,
    resolver: Arc<CertResolver>,
    hosts: Mutex<HashMap<String, HostCert>>,
    challenges: Arc<Http01Challenges>,
    acme: acme::AcmeClient,
    devca: Option<devca::DevCa>,
    /// Limits concurrent orders (CA rate limits, resource use).
    order_slots: Semaphore,
    /// Names covered by `tls.mode = "files"`.
    static_names: Vec<String>,
}

impl CertManager {
    /// `domains`: the names certificates may be issued for (base domain, management hostname).
    pub fn new(cfg: &TlsConfig, data_dir: &Path, domains: &[&str]) -> anyhow::Result<Arc<Self>> {
        let dir = data_dir.join("certs");
        std::fs::create_dir_all(&dir)?;
        let resolver = Arc::new(CertResolver::default());
        let mut static_names = Vec::new();
        let devca = match cfg.mode {
            TlsMode::DevCa => Some(devca::DevCa::load_or_create(&data_dir.join("dev-ca"), domains)?),
            _ => None,
        };
        if cfg.mode == TlsMode::Files {
            let (c, k) = (cfg.cert_file.as_ref().unwrap(), cfg.key_file.as_ref().unwrap());
            let loaded = load_pem(&std::fs::read(c).with_context(|| format!("reading {}", c.display()))?, &std::fs::read(k).with_context(|| format!("reading {}", k.display()))?)?;
            for n in &loaded.names {
                resolver.insert(n, loaded.key.clone());
            }
            tracing::info!(names = ?loaded.names, "loaded certificate from files");
            static_names = loaded.names;
        }
        let challenges = Arc::new(Http01Challenges::default());
        let acme = acme::AcmeClient::new(cfg, data_dir, challenges.clone());
        let mgr = Arc::new(Self {
            cfg: cfg.clone(),
            dir,
            resolver,
            hosts: Mutex::new(HashMap::new()),
            challenges,
            acme,
            devca,
            order_slots: Semaphore::new(2),
            static_names,
        });
        if cfg.mode == TlsMode::Acme {
            mgr.load_cache();
        }
        Ok(mgr)
    }

    pub fn resolver(&self) -> Arc<CertResolver> {
        self.resolver.clone()
    }

    pub fn challenges(&self) -> Arc<Http01Challenges> {
        self.challenges.clone()
    }

    pub fn dev_ca_path(&self) -> Option<PathBuf> {
        self.devca.as_ref().map(|d| d.ca_path())
    }

    fn cache_paths(&self, host: &str) -> (PathBuf, PathBuf) {
        (self.dir.join(format!("{host}.crt")), self.dir.join(format!("{host}.key")))
    }

    fn load_cache(&self) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else { return };
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().and_then(|s| s.to_str()) != Some("crt") {
                continue;
            }
            let Some(host) = path.file_stem().and_then(|s| s.to_str()).map(str::to_string) else { continue };
            let (crt, key) = self.cache_paths(&host);
            match std::fs::read(&crt).and_then(|c| Ok((c, std::fs::read(&key)?))) {
                Ok((c, k)) => match load_pem(&c, &k) {
                    Ok(l) if l.not_after > unix_now() && covers(&l.names, &host) => {
                        self.install(&host, l);
                    }
                    Ok(_) => tracing::info!(%host, "cached certificate expired or mismatched; will reissue"),
                    Err(err) => tracing::warn!(%host, %err, "ignoring unreadable cached certificate"),
                },
                Err(err) => tracing::warn!(%host, %err, "ignoring unreadable cached certificate"),
            }
        }
    }

    fn install(&self, host: &str, cert: LoadedCert) {
        self.resolver.insert(host, cert.key.clone());
        let mut hosts = self.hosts.lock().unwrap();
        let entry = hosts.entry(host.to_string()).or_insert_with(|| HostCert {
            status: watch::channel(CertStatus::Pending).0,
            not_before: 0,
            not_after: 0,
            issuing: false,
            failed_at: None,
        });
        entry.not_before = cert.not_before;
        entry.not_after = cert.not_after;
        entry.issuing = false;
        entry.failed_at = None;
        entry.status.send_replace(CertStatus::Ready);
    }

    pub fn status(&self, host: &str) -> CertStatus {
        if self.cfg.mode == TlsMode::Files {
            return self.files_status(host);
        }
        self.hosts.lock().unwrap().get(host).map(|h| h.status.borrow().clone()).unwrap_or(CertStatus::Pending)
    }

    fn files_status(&self, host: &str) -> CertStatus {
        if covers(&self.static_names, host) {
            CertStatus::Ready
        } else {
            CertStatus::Failed(format!("the configured certificate does not cover {host}"))
        }
    }

    /// Makes sure a certificate for `host` exists or is being obtained. Never blocks.
    pub fn ensure(self: &Arc<Self>, host: &str) {
        if self.cfg.mode == TlsMode::Files {
            return;
        }
        let backoff = Duration::from_secs(self.cfg.failure_backoff_secs);
        let mut hosts = self.hosts.lock().unwrap();
        let entry = hosts.entry(host.to_string()).or_insert_with(|| HostCert {
            status: watch::channel(CertStatus::Pending).0,
            not_before: 0,
            not_after: 0,
            issuing: false,
            failed_at: None,
        });
        let needs = match &*entry.status.borrow() {
            CertStatus::Ready => needs_renewal(entry.not_before, entry.not_after),
            CertStatus::Pending => true,
            CertStatus::Failed(_) => entry.failed_at.is_none_or(|t| t.elapsed() >= backoff),
        };
        if !needs || entry.issuing {
            return;
        }
        entry.issuing = true;
        if !matches!(*entry.status.borrow(), CertStatus::Ready) {
            entry.status.send_replace(CertStatus::Pending);
        }
        drop(hosts);
        let me = self.clone();
        let host = host.to_string();
        tokio::spawn(async move { me.issue(host).await });
    }

    async fn issue(self: Arc<Self>, host: String) {
        let _slot = self.order_slots.acquire().await;
        let timeout = Duration::from_secs(self.cfg.issuance_timeout_secs);
        tracing::info!(%host, mode = ?self.cfg.mode, "obtaining certificate");
        let result = match (&self.devca, self.cfg.mode) {
            (Some(ca), _) => ca.issue(&host),
            (None, TlsMode::Acme) => match tokio::time::timeout(timeout, self.acme.order(&host)).await {
                Ok(r) => r,
                Err(_) => Err(anyhow!("timed out after {}s waiting for the ACME server", timeout.as_secs())),
            },
            _ => Err(anyhow!("no certificate source configured")),
        };
        let loaded = result.and_then(|(chain, key)| {
            let l = load_pem(chain.as_bytes(), key.as_bytes())?;
            if self.devca.is_none() {
                let (crt_path, key_path) = self.cache_paths(&host);
                write_private(&key_path, key.as_bytes())?;
                write_private(&crt_path, chain.as_bytes())?;
            }
            Ok(l)
        });
        match loaded {
            Ok(l) => {
                tracing::info!(%host, not_after = %magicpipes_core::rfc3339(l.not_after), "certificate ready");
                self.install(&host, l);
            }
            Err(err) => {
                let msg = format!("{err:#}");
                tracing::warn!(%host, error = %msg, "certificate provisioning failed");
                let mut hosts = self.hosts.lock().unwrap();
                if let Some(e) = hosts.get_mut(&host) {
                    e.issuing = false;
                    e.failed_at = Some(Instant::now());
                    // Keep serving a still-valid certificate if a renewal failed.
                    if !(matches!(*e.status.borrow(), CertStatus::Ready) && e.not_after > unix_now()) {
                        e.status.send_replace(CertStatus::Failed(msg));
                    }
                }
            }
        }
    }

    /// Waits until the certificate for `host` is ready or has failed, at most `timeout`.
    pub async fn wait(self: &Arc<Self>, host: &str, timeout: Duration) -> CertStatus {
        if self.cfg.mode == TlsMode::Files {
            return self.files_status(host);
        }
        self.ensure(host);
        let mut rx = match self.hosts.lock().unwrap().get(host) {
            Some(h) => h.status.subscribe(),
            None => return CertStatus::Pending,
        };
        let res = tokio::time::timeout(timeout, rx.wait_for(|s| *s != CertStatus::Pending)).await;
        match res {
            Ok(Ok(s)) => s.clone(),
            _ => CertStatus::Pending,
        }
    }

    /// Periodically renews certificates that passed two thirds of their lifetime.
    pub fn spawn_renewal(self: &Arc<Self>, shutdown: CancellationToken) {
        let me = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(3600));
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tick.tick() => {}
                }
                let due: Vec<String> = me
                    .hosts
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(_, h)| matches!(*h.status.borrow(), CertStatus::Ready) && needs_renewal(h.not_before, h.not_after))
                    .map(|(k, _)| k.clone())
                    .collect();
                for host in due {
                    tracing::info!(%host, "renewing certificate");
                    me.ensure(&host);
                }
            }
        });
    }
}

fn needs_renewal(not_before: i64, not_after: i64) -> bool {
    let lifetime = (not_after - not_before).max(0);
    unix_now() >= not_after - lifetime / 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage() {
        let names = vec!["*.t.example.com".to_string(), "example.com".to_string()];
        assert!(covers(&names, "a.t.example.com"));
        assert!(!covers(&names, "a.b.t.example.com"));
        assert!(covers(&names, "example.com"));
        assert!(!covers(&names, "t.example.com"));
    }
}
