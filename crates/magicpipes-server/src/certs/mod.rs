//! Certificate management (control plane) and the TLS certificate resolver (read by ingress).
//!
//! The control plane calls [`CertManager::ensure`] for every hostname it is willing to serve
//! (registered tunnels and the management hostname). Nothing is issued on demand for arbitrary
//! SNI names, so an attacker cannot make the server request certificates. Issued certificates
//! are cached on disk and installed into the [`CertResolver`], which the TLS acceptors consult
//! for every handshake without touching the control plane. Certificates people bring themselves
//! are in [`provided`]. A name under a `[[tls.authorities]]` domain gets its certificate from
//! that [`authority`], whatever the mode. Under a `[tls.dns01]` domain, a name shares that domain's
//! one certificate for `D` and `*.D`, ordered through DNS-01 and answered by [`dns`].

mod acme;
pub(crate) mod devca;
mod provided;

mod authority;
pub(crate) mod dns;

use std::collections::{HashMap, HashSet};
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
pub use provided::{AddError, ProvidedCert};

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

/// SNI -> certificate lookup. Exact names first, then single-label wildcards. Certificates people
/// brought go before any others.
#[derive(Default, Debug)]
pub struct CertResolver {
    exact: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    wildcard: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    provided: RwLock<provided::NameMap>,
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

    fn remove(&self, name: &str) {
        let name = name.to_ascii_lowercase();
        match name.strip_prefix("*.") {
            // A domain's wildcard certificate covers the domain itself too.
            Some(domain) => {
                self.wildcard.write().unwrap().remove(domain);
                self.exact.write().unwrap().remove(domain);
            }
            None => {
                self.exact.write().unwrap().remove(&name);
            }
        }
    }

    /// What the public listener serves.
    pub fn lookup(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let host = host.to_ascii_lowercase();
        self.provided.read().unwrap().get(&host).or_else(|| self.issued(&host))
    }

    /// Without what people brought, for the management listener.
    pub fn lookup_issued(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        self.issued(&host.to_ascii_lowercase())
    }

    fn issued(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        if let Some(k) = self.exact.read().unwrap().get(host) {
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
/// tunnel's hostname (its session cookie would then belong to the tunnel's origin). It never uses
/// a certificate people brought: a bad one must not lock anyone out of the page that removes it.
#[derive(Debug)]
pub struct SingleHost {
    pub host: String,
    pub inner: Arc<CertResolver>,
}

impl ResolvesServerCert for SingleHost {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name()?;
        if name.eq_ignore_ascii_case(&self.host) { self.inner.lookup_issued(&self.host) } else { None }
    }
}

/// The public listener when the management host shares it: the management hostname gets what
/// [`SingleHost`] gives it (never a certificate people brought), and every other name the tunnels'.
/// Which of the two serves the connection afterwards follows the same name.
#[derive(Debug)]
pub struct WithManagement {
    pub management: Arc<SingleHost>,
    pub tunnels: Arc<CertResolver>,
}

impl ResolvesServerCert for WithManagement {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if hello.server_name()?.eq_ignore_ascii_case(&self.management.host) { self.management.resolve(hello) } else { self.tunnels.resolve(hello) }
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
    // Without the parser's words: they can quote a line of the key.
    let key_der = PrivateKeyDer::from_pem_slice(key_pem).map_err(|_| anyhow!("invalid private key PEM"))?;
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

pub fn covers(names: &[String], host: &str) -> bool {
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
    /// Since when no tunnel uses this hostname (see [`CertManager::set_wanted`]).
    unwanted_since: Option<Instant>,
}

impl HostCert {
    fn new() -> Self {
        Self { status: watch::channel(CertStatus::Pending).0, not_before: 0, not_after: 0, issuing: false, failed_at: None, unwanted_since: None }
    }
}

/// `[tls.dns01]` as the Settings page shows it.
#[derive(Debug, Clone)]
pub struct Dns01View {
    pub domains: Vec<Dns01Domain>,
    pub zone: Option<String>,
    pub nameserver: String,
    pub listen: String,
}

#[derive(Debug, Clone)]
pub struct Dns01Domain {
    pub domain: String,
    /// `_acme-challenge.<domain>`, which must lead to this server.
    pub challenge_name: String,
    /// With a zone: what `challenge_name` is a CNAME to.
    pub cname: Option<String>,
    /// Of its certificate for `domain` and `*.domain`; none until a name under it is used.
    pub status: Option<CertStatus>,
    pub not_after: Option<String>,
}

/// Where the CAs the server makes for `[[tls.authorities]]` are kept, one directory per domain.
pub const AUTHORITIES_DIR: &str = "authorities";

/// A `[[tls.authorities]]` CA, for people to install on their devices.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuthorityView {
    pub domain: String,
    /// Made by this server (else brought by its administrator).
    pub made_here: bool,
    pub not_after: String,
    /// SHA-256 of its certificate, `AB:CD:…`.
    pub fingerprint: String,
    /// Its certificate, and any above it (PEM).
    pub pem: String,
}

/// A hostname no tunnel uses is no longer renewed, and is forgotten (resolver, cache) after this
/// long, so a tunnel removed and added again soon keeps its certificate.
const FORGET_UNWANTED_AFTER: Duration = Duration::from_secs(7 * 24 * 3600);
/// How soon a certificate file another tool renewed is used.
const PROVIDED_FILES_CHECK: Duration = Duration::from_secs(300);

pub struct CertManager {
    cfg: TlsConfig,
    dir: PathBuf,
    resolver: Arc<CertResolver>,
    hosts: Mutex<HashMap<String, HostCert>>,
    challenges: Arc<Http01Challenges>,
    acme: acme::AcmeClient,
    devca: Option<devca::DevCa>,
    /// `[[tls.authorities]]`, by domain.
    authorities: Vec<authority::Authority>,
    /// The DNS-01 challenges the responder answers (`[tls.dns01]`).
    dns: Option<Arc<dns::DnsChallenges>>,
    /// Limits concurrent orders (CA rate limits, resource use).
    order_slots: Semaphore,
    /// Names covered by `tls.mode = "files"`.
    static_names: Vec<String>,
    /// Certificates people brought; a later one overrules an earlier one. See [`provided`].
    provided: Mutex<Vec<provided::Entry>>,
    provided_dir: PathBuf,
    /// The server's own names, which these never apply to.
    own_names: Vec<String>,
}

impl CertManager {
    /// `domains`: the server's own names, which certificates may be issued for (base domain,
    /// management hostname).
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
        let mut authorities = Vec::new();
        for a in &cfg.authorities {
            let ca = match (&a.cert_file, &a.key_file) {
                (Some(c), Some(k)) => authority::Authority::load(c, k, &a.domain),
                _ => authority::Authority::load_or_create(&data_dir.join(AUTHORITIES_DIR).join(&a.domain), &format!("MagicPipes CA for {}", a.domain), &[&a.domain]),
            };
            authorities.push(ca.with_context(|| format!("tls.authorities '{}'", a.domain))?);
        }
        let provided_dir = data_dir.join(provided::DIR);
        let provided = Mutex::new(provided::load_all(&cfg.certificates, &provided_dir)?);
        let challenges = Arc::new(Http01Challenges::default());
        let dns = cfg.dns01.as_ref().map(|d| Arc::new(dns::DnsChallenges::new(&d.domains, d.zone.as_deref(), d.nameserver.as_deref().unwrap_or_default())));
        let acme = acme::AcmeClient::new(cfg, data_dir, challenges.clone(), dns.clone());
        let mgr = Arc::new(Self {
            cfg: cfg.clone(),
            dir,
            resolver,
            hosts: Mutex::new(HashMap::new()),
            challenges,
            acme,
            devca,
            authorities,
            dns,
            order_slots: Semaphore::new(2),
            static_names,
            provided,
            provided_dir,
            own_names: domains.iter().map(|d| d.to_ascii_lowercase()).collect(),
        });
        mgr.install_provided();
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

    /// The authority that issues `host`'s certificate, if one does.
    fn authority(&self, host: &str) -> Option<&authority::Authority> {
        let domain = self.cfg.authority_for(host)?;
        self.authorities.iter().find(|a| a.domain == domain)
    }

    /// Whether this server issues `host`'s certificate itself, from one of its authorities.
    pub fn issued_here(&self, host: &str) -> bool {
        self.authority(host).is_some()
    }

    /// The domain of the authority whose certificate `host` gets, if it gets one of theirs and not
    /// one people brought. `*.exhub.internal`: the names under it.
    pub fn authority_of(&self, host: &str) -> Option<String> {
        if self.provided_covers(host) {
            return None;
        }
        self.authority(host).map(|a| a.domain.clone())
    }

    /// The certificate of the authority for `domain` (and any above it), PEM.
    pub fn authority_pem(&self, domain: &str) -> Option<String> {
        self.authorities.iter().find(|a| a.domain == domain).map(|a| a.chain_pem.clone())
    }

    /// The `[[tls.authorities]]`, for the pages that let people install them.
    pub fn authorities(&self) -> Vec<AuthorityView> {
        self.authorities
            .iter()
            .map(|a| AuthorityView {
                domain: a.domain.clone(),
                made_here: a.made_at.is_some(),
                not_after: magicpipes_core::rfc3339(a.not_after),
                fingerprint: a.fingerprint.clone(),
                pem: a.chain_pem.clone(),
            })
            .collect()
    }

    /// The DNS-01 responder's challenges, if `[tls.dns01]` is set.
    pub fn dns_challenges(&self) -> Option<Arc<dns::DnsChallenges>> {
        self.dns.clone()
    }

    /// Which certificate `host` gets from here: its own, or under a `[tls.dns01]` domain, that
    /// domain's `*.D` (which covers `D` too). An authority comes first.
    fn key(&self, host: &str) -> String {
        match self.cfg.dns01_domain_for(host) {
            Some(d) if self.authority(host).is_none() => format!("*.{d}"),
            _ => host.to_string(),
        }
    }

    /// Whether a new tunnel on `host` costs a certificate order of its own, from an ACME CA that
    /// limits them: not when an authority here issues it, or a DNS-01 wildcard covers it.
    pub fn orders_its_own(&self, host: &str) -> bool {
        self.cfg.mode == TlsMode::Acme && !self.issued_here(host) && self.key(host) == host
    }

    /// `[tls.dns01]`, for the page that says which records to add and how each domain is doing.
    pub fn dns01(&self) -> Option<Dns01View> {
        let cfg = self.cfg.dns01.as_ref()?;
        let records = self.dns.as_ref()?.records();
        let domains = cfg
            .domains
            .iter()
            .zip(records)
            .map(|(d, (name, cname))| {
                let key = format!("*.{d}");
                let found = self.hosts.lock().unwrap().get(&key).map(|h| (h.status.borrow().clone(), h.not_after));
                let not_after = found.as_ref().map_or(0, |f| f.1);
                Dns01Domain { domain: d.clone(), challenge_name: name, cname, status: found.map(|f| f.0), not_after: (not_after > 0).then(|| magicpipes_core::rfc3339(not_after)) }
            })
            .collect();
        Some(Dns01View { domains, zone: cfg.zone.clone(), nameserver: cfg.nameserver.clone().unwrap_or_default(), listen: cfg.listen.to_string() })
    }

    /// Whether `host` has a certificate only from `tls.mode = "files"`: one another tool keeps.
    fn kept_in_files(&self, host: &str) -> bool {
        self.cfg.mode == TlsMode::Files && !self.issued_here(host)
    }

    /// `*.example.com` is kept as `_.example.com`: no hostname has an underscore, and Windows
    /// refuses a `*` in a file name.
    fn cache_paths(&self, key: &str) -> (PathBuf, PathBuf) {
        let stem = key.replace('*', "_");
        (self.dir.join(format!("{stem}.crt")), self.dir.join(format!("{stem}.key")))
    }

    fn load_cache(&self) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else { return };
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().and_then(|s| s.to_str()) != Some("crt") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else { continue };
            let host = match stem.strip_prefix("_.") {
                Some(domain) => format!("*.{domain}"),
                None => stem.to_string(),
            };
            // Issued here now, which takes no time; or a DNS-01 wildcard covers it now.
            if self.issued_here(&host) || self.key(&host) != host {
                continue;
            }
            let (crt, key) = self.cache_paths(&host);
            match std::fs::read(&crt).and_then(|c| Ok((c, std::fs::read(&key)?))) {
                Ok((c, k)) => match load_pem(&c, &k) {
                    Ok(l) if l.not_after > unix_now() && covers(&l.names, &host) => {
                        self.install(&host, l);
                    }
                    Ok(_) => {
                        // Reissued if a tunnel still uses the name; otherwise nobody needs it.
                        tracing::info!(%host, "removing an expired or mismatched cached certificate");
                        let _ = std::fs::remove_file(&crt);
                        let _ = std::fs::remove_file(&key);
                    }
                    Err(err) => tracing::warn!(%host, %err, "ignoring unreadable cached certificate"),
                },
                Err(err) => tracing::warn!(%host, %err, "ignoring unreadable cached certificate"),
            }
        }
    }

    fn install(&self, host: &str, cert: LoadedCert) {
        self.resolver.insert(host, cert.key.clone());
        // `D` and `*.D` share one certificate.
        if let Some(domain) = host.strip_prefix("*.") {
            self.resolver.insert(domain, cert.key.clone());
        }
        let mut hosts = self.hosts.lock().unwrap();
        let entry = hosts.entry(host.to_string()).or_insert_with(HostCert::new);
        entry.not_before = cert.not_before;
        entry.not_after = cert.not_after;
        entry.issuing = false;
        entry.failed_at = None;
        entry.status.send_replace(CertStatus::Ready);
    }

    pub fn status(&self, host: &str) -> CertStatus {
        if let Some(status) = self.provided_status(host) {
            return status;
        }
        if self.kept_in_files(host) {
            return self.files_status(host);
        }
        self.hosts.lock().unwrap().get(&self.key(host)).map(|h| h.status.borrow().clone()).unwrap_or(CertStatus::Pending)
    }

    /// Until when the certificate `host` gets is valid (Unix time), if it has one: the one
    /// [`status`](Self::status) judges. `None` for `tls.mode = "files"`, which another tool renews.
    pub fn not_after(&self, host: &str) -> Option<i64> {
        if let Some(t) = self.provided_not_after(host) {
            return Some(t);
        }
        if self.kept_in_files(host) {
            return None;
        }
        self.hosts.lock().unwrap().get(&self.key(host)).map(|h| h.not_after).filter(|t| *t > 0)
    }

    fn files_status(&self, host: &str) -> CertStatus {
        if covers(&self.static_names, host) {
            CertStatus::Ready
        } else {
            CertStatus::Failed(format!("the configured certificate does not cover {host}"))
        }
    }

    /// Makes sure a certificate for `host` exists or is being obtained. Never blocks. A name someone
    /// brought a certificate for is only noted, so it's ordered if that certificate goes away.
    pub fn ensure(self: &Arc<Self>, host: &str) {
        if self.kept_in_files(host) {
            return;
        }
        let covered = self.provided_covers(host);
        let host = self.key(host);
        let backoff = Duration::from_secs(self.cfg.failure_backoff_secs);
        let mut hosts = self.hosts.lock().unwrap();
        let entry = hosts.entry(host.clone()).or_insert_with(HostCert::new);
        if covered {
            return;
        }
        let retry = entry.failed_at.is_none_or(|t| t.elapsed() >= backoff);
        let needs = match &*entry.status.borrow() {
            CertStatus::Ready => needs_renewal(entry.not_before, entry.not_after) && retry,
            CertStatus::Pending => true,
            CertStatus::Failed(_) => retry,
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
        tokio::spawn(async move { me.issue(host).await });
    }

    async fn issue(self: Arc<Self>, host: String) {
        let _slot = self.order_slots.acquire().await;
        let timeout = Duration::from_secs(self.cfg.issuance_timeout_secs);
        let authority = self.authority(&host);
        tracing::info!(%host, mode = ?self.cfg.mode, authority = authority.map(|a| a.domain.as_str()), "obtaining certificate");
        let result = match (authority, &self.devca, self.cfg.mode) {
            (Some(ca), ..) => ca.issue(&host),
            (None, Some(ca), _) => ca.issue(&host),
            (None, None, TlsMode::Acme) => {
                let order = async {
                    match host.strip_prefix("*.") {
                        Some(domain) => self.acme.order_wildcard(domain).await,
                        None => self.acme.order(&host).await,
                    }
                };
                match tokio::time::timeout(timeout, order).await {
                    Ok(r) => r,
                    Err(_) => Err(anyhow!("timed out after {}s waiting for the ACME server", timeout.as_secs())),
                }
            }
            _ => Err(anyhow!("no certificate source configured")),
        };
        // Only what an ACME CA issued is kept: an authority here issues again at once.
        let keep = authority.is_none() && self.devca.is_none();
        let loaded = result.and_then(|(chain, key)| {
            let l = load_pem(chain.as_bytes(), key.as_bytes())?;
            if keep {
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
        if let Some(status) = self.provided_status(host) {
            return status;
        }
        if self.kept_in_files(host) {
            return self.files_status(host);
        }
        self.ensure(host);
        let mut rx = match self.hosts.lock().unwrap().get(&self.key(host)) {
            Some(h) => h.status.subscribe(),
            None => return CertStatus::Pending,
        };
        let res = tokio::time::timeout(timeout, rx.wait_for(|s| *s != CertStatus::Pending)).await;
        match res {
            Ok(Ok(s)) => s.clone(),
            _ => CertStatus::Pending,
        }
    }

    /// The hostnames the control plane serves now (its tunnels and the management hostname);
    /// called on every publish. Others are no longer renewed, and are forgotten after a while.
    pub fn set_wanted(&self, wanted: &HashSet<&str>) {
        let wanted: HashSet<String> = wanted.iter().map(|h| self.key(h)).collect();
        for (host, h) in self.hosts.lock().unwrap().iter_mut() {
            if wanted.contains(host) {
                h.unwanted_since = None;
            } else if h.unwanted_since.is_none() {
                h.unwanted_since = Some(Instant::now());
            }
        }
    }

    /// Forgets hostnames unused for `forget_after`; returns the wanted ones due for renewal.
    fn maintain(&self, forget_after: Duration) -> Vec<String> {
        let mut hosts = self.hosts.lock().unwrap();
        let stale: Vec<String> = hosts
            .iter()
            .filter(|(_, h)| !h.issuing && h.unwanted_since.is_some_and(|t| t.elapsed() >= forget_after))
            .map(|(k, _)| k.clone())
            .collect();
        for host in stale {
            tracing::info!(%host, "forgetting the certificate of a hostname no tunnel uses");
            hosts.remove(&host);
            self.resolver.remove(&host);
            let (crt, key) = self.cache_paths(&host);
            let _ = std::fs::remove_file(crt);
            let _ = std::fs::remove_file(key);
        }
        hosts
            .iter()
            .filter(|(_, h)| h.unwanted_since.is_none() && matches!(*h.status.borrow(), CertStatus::Ready) && needs_renewal(h.not_before, h.not_after))
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Starts certificates for wanted hostnames waiting on one, now that fewer names are covered
    /// by certificates people brought.
    fn ensure_pending(self: &Arc<Self>) {
        let pending: Vec<String> = {
            let hosts = self.hosts.lock().unwrap();
            hosts.iter().filter(|(_, h)| h.unwanted_since.is_none() && !h.issuing && matches!(*h.status.borrow(), CertStatus::Pending)).map(|(k, _)| k.clone()).collect()
        };
        for host in pending {
            self.ensure(&host);
        }
    }

    /// Periodically renews certificates that passed two thirds of their lifetime, forgets those of
    /// hostnames no tunnel has used for a week, and picks up certificate files that changed.
    pub fn spawn_renewal(self: &Arc<Self>, shutdown: CancellationToken) {
        let me = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(3600));
            let mut files = tokio::time::interval(PROVIDED_FILES_CHECK);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = files.tick() => me.reload_provided_files(),
                    _ = tick.tick() => {
                        for host in me.maintain(FORGET_UNWANTED_AFTER) {
                            // Yours to renew, for a name someone brought a certificate for.
                            if !me.provided_covers(&host) {
                                tracing::info!(%host, "renewing certificate");
                                me.ensure(&host);
                            }
                        }
                    }
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

    /// A certificate for `names`, as an ACME CA would have issued it, cached under `stem`.
    fn cache(dir: &Path, stem: &str, names: &[&str]) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap().self_signed(&key).unwrap();
        std::fs::create_dir_all(dir.join("certs")).unwrap();
        std::fs::write(dir.join(format!("certs/{stem}.crt")), cert.pem()).unwrap();
        std::fs::write(dir.join(format!("certs/{stem}.key")), key.serialize_pem()).unwrap();
    }

    #[tokio::test]
    async fn names_under_a_dns01_domain_share_its_wildcard_certificate() {
        let dir = std::env::temp_dir().join(format!("mp-certs-{}", magicpipes_core::secret::random_string(8)));
        cache(&dir, "_.t.test", &["t.test", "*.t.test"]);
        cache(&dir, "old.t.test", &["old.t.test"]);
        cache(&dir, "a.b.t.test", &["a.b.t.test"]);
        let cfg: TlsConfig = toml::from_str("mode = \"acme\"\n[dns01]\ndomains = [\"t.test\"]\nnameserver = \"ns.t.test\"").unwrap();
        let certs = CertManager::new(&cfg, &dir, &["t.test"]).unwrap();
        for (host, key) in [("x.t.test", "*.t.test"), ("t.test", "*.t.test"), ("*.t.test", "*.t.test"), ("a.b.t.test", "a.b.t.test"), ("other.test", "other.test")] {
            assert_eq!(certs.key(host), key, "{host}");
        }
        assert!(!certs.orders_its_own("new.t.test") && certs.orders_its_own("a.b.t.test") && certs.orders_its_own("other.test"));
        // The cached wildcard serves the domain and every name one label under it; the per-name
        // certificate it replaces isn't loaded, and a deeper name keeps its own.
        let wildcard = certs.resolver.lookup("anything.t.test").expect("the wildcard");
        assert!(Arc::ptr_eq(&wildcard, &certs.resolver.lookup("old.t.test").unwrap()));
        assert!(Arc::ptr_eq(&wildcard, &certs.resolver.lookup("t.test").unwrap()));
        assert!(!Arc::ptr_eq(&wildcard, &certs.resolver.lookup("a.b.t.test").unwrap()));
        assert_eq!((certs.status("new.t.test"), certs.status("t.test")), (CertStatus::Ready, CertStatus::Ready));
        assert!(certs.not_after("new.t.test").is_some());
        assert!(certs.cache_paths("*.t.test").0.ends_with("certs/_.t.test.crt"));
        // Forgotten when nothing under it is wanted.
        certs.set_wanted(&HashSet::from(["a.b.t.test"]));
        certs.maintain(Duration::ZERO);
        assert!(certs.resolver.lookup("x.t.test").is_none() && certs.resolver.lookup("t.test").is_none());
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn unused_hostnames_are_forgotten() {
        let dir = std::env::temp_dir().join(format!("mp-certs-{}", magicpipes_core::secret::random_string(8)));
        let cfg: TlsConfig = toml::from_str("mode = \"dev-ca\"").unwrap();
        let certs = CertManager::new(&cfg, &dir, &["t.test"]).unwrap();
        for h in ["a.t.test", "b.t.test"] {
            assert_eq!(certs.wait(h, Duration::from_secs(10)).await, CertStatus::Ready);
        }
        certs.set_wanted(&HashSet::from(["a.t.test"]));
        assert!(certs.maintain(Duration::from_secs(3600)).is_empty(), "nothing is due, and b's grace period runs");
        assert_eq!(certs.status("b.t.test"), CertStatus::Ready);
        certs.maintain(Duration::ZERO);
        assert_eq!(certs.status("b.t.test"), CertStatus::Pending);
        assert!(certs.resolver.lookup("b.t.test").is_none() && certs.resolver.lookup("a.t.test").is_some());
        std::fs::remove_dir_all(dir).ok();
    }
}
