//! Certificates people bring themselves: from `[[tls.certificates]]` in the configuration file, or
//! added on the Settings page and kept in `<data_dir>/provided-certs/` (0600 in 0700), never in the
//! database.
//!
//! On the public listener they win over the usual source (ACME, the development CA or
//! `tls.cert_file`), and a name one covers is never ordered. They never apply to the server's own
//! names (`domains` in [`CertManager::new`]), so a bad one can't lock an administrator out of the
//! page that would remove it. Nothing renews them: changed files are picked up, and what's about to
//! expire is shown to administrators.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, anyhow};
use magicpipes_core::{rfc3339, unix_now};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};

use super::{CertManager, CertStatus, LoadedCert, covers, load_pem, write_private};
use crate::config::CertFiles;

/// In `data_dir`.
pub(super) const DIR: &str = "provided-certs";
/// How many may be added on the Settings page, and how many the configuration file may list.
const MAX_CERTIFICATES: usize = 64;
const MAX_PEM: usize = 64 * 1024;
/// A certificate counts as expiring soon this long before its end, or in the last third of a shorter
/// life.
const SOON_SECS: i64 = 30 * 24 * 3600;

/// One certificate, as the Settings page shows it.
#[derive(Debug, Clone)]
pub struct ProvidedCert {
    pub id: String,
    /// Its DNS names. Empty: its files have never been readable.
    pub names: Vec<String>,
    pub not_before: i64,
    pub not_after: i64,
    /// In the configuration file: it can't be removed on the page.
    pub from_file: bool,
    /// Why its files can't be used. If it was loaded before that, it stays in use.
    pub problem: Option<String>,
}

impl ProvidedCert {
    pub fn expired(&self) -> bool {
        self.not_after <= unix_now()
    }

    pub fn not_valid_yet(&self) -> bool {
        self.not_before > unix_now()
    }

    pub fn expires_soon(&self) -> bool {
        let lifetime = (self.not_after - self.not_before).max(0);
        unix_now() >= self.not_after - SOON_SECS.min(lifetime / 3)
    }
}

/// Why a certificate wasn't added.
pub enum AddError {
    /// What to say to the administrator. Never quotes the key.
    Invalid(String),
    Storage(anyhow::Error),
}

type Stamp = (Option<SystemTime>, u64, Option<SystemTime>, u64);

pub(super) struct Entry {
    view: ProvidedCert,
    key: Option<Arc<CertifiedKey>>,
    cert_file: PathBuf,
    key_file: PathBuf,
    /// What the files looked like when they were last read, to notice a change.
    stamp: Option<Stamp>,
}

/// Names to certificates, replaced whole when anything changes.
#[derive(Default, Debug)]
pub(super) struct NameMap {
    exact: HashMap<String, Arc<CertifiedKey>>,
    wildcard: HashMap<String, Arc<CertifiedKey>>,
}

impl NameMap {
    /// `host` is lowercase.
    pub(super) fn get(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        if let Some(k) = self.exact.get(host) {
            return Some(k.clone());
        }
        self.wildcard.get(host.split_once('.')?.1).cloned()
    }

    /// Later entries win, as in [`serving`].
    fn of(entries: &[Entry]) -> Self {
        let mut map = Self::default();
        for e in entries {
            let Some(key) = &e.key else { continue };
            for name in &e.view.names {
                match name.strip_prefix("*.") {
                    Some(parent) => map.wildcard.insert(parent.to_string(), key.clone()),
                    None => map.exact.insert(name.clone(), key.clone()),
                };
            }
        }
        map
    }
}

/// The order in which entries overrule each other: the configuration file over the page, then
/// whatever lasts longest.
fn sort(entries: &mut [Entry]) {
    entries.sort_by_key(|e| (e.view.from_file, e.view.not_after));
}

/// The entry whose certificate a handshake for `host` gets; the same choice as [`NameMap`].
fn serving<'a>(entries: &'a [Entry], host: &str) -> Option<&'a Entry> {
    let loaded = || entries.iter().rev().filter(|e| e.key.is_some());
    loaded().find(|e| e.view.names.iter().any(|n| n == host)).or_else(|| loaded().find(|e| covers(&e.view.names, host)))
}

fn id_of(loaded: &LoadedCert) -> String {
    let digest = Sha256::digest(loaded.key.cert.first().map_or(&[][..], |c| c.as_ref()));
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// Reads a certificate and its key. What it returns is shown to administrators, and never quotes
/// the key.
fn parse(chain: &[u8], key: &[u8]) -> Result<LoadedCert, String> {
    if chain.len() > MAX_PEM || key.len() > MAX_PEM {
        return Err("That's too long for a certificate and its key.".into());
    }
    let certs = CertificateDer::pem_slice_iter(chain).collect::<Result<Vec<_>, _>>().map_err(|_| "The certificate isn't valid PEM text.".to_string())?;
    if certs.is_empty() {
        return Err("There's no certificate there. It starts with -----BEGIN CERTIFICATE-----.".into());
    }
    if PrivateKeyDer::from_pem_slice(key).is_err() {
        return Err("The private key isn't PEM text the server can read. It can't have a passphrase.".into());
    }
    let loaded = load_pem(chain, key).map_err(|e| format!("That can't be used: {e:#}"))?;
    if let Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::KeyMismatch)) = loaded.key.keys_match() {
        return Err("That private key doesn't belong to the first certificate. Your own certificate goes first, then its intermediates.".into());
    }
    if loaded.names.is_empty() {
        return Err("That certificate names no hostnames: it has no DNS names in its subject alternative names.".into());
    }
    Ok(loaded)
}

fn stamp_of(cert_file: &Path, key_file: &Path) -> std::io::Result<Stamp> {
    let (c, k) = (std::fs::metadata(cert_file)?, std::fs::metadata(key_file)?);
    Ok((c.modified().ok(), c.len(), k.modified().ok(), k.len()))
}

fn view_of(loaded: &LoadedCert, from_file: bool) -> ProvidedCert {
    ProvidedCert { id: id_of(loaded), names: loaded.names.clone(), not_before: loaded.not_before, not_after: loaded.not_after, from_file, problem: None }
}

fn saved_paths(dir: &Path, id: &str) -> (PathBuf, PathBuf) {
    (dir.join(format!("{id}.crt")), dir.join(format!("{id}.key")))
}

/// What's on the Settings page. One that can't be read stays listed, so it can be removed, and costs
/// nothing else.
fn load_saved(dir: &Path) -> Vec<Entry> {
    let Ok(listing) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut entries = Vec::new();
    for path in listing.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "crt")).take(MAX_CERTIFICATES * 2) {
        let Some(id) = path.file_stem().and_then(|s| s.to_str()).map(str::to_string) else { continue };
        let (cert_file, key_file) = saved_paths(dir, &id);
        let read = std::fs::read(&cert_file).and_then(|c| Ok((c, std::fs::read(&key_file)?))).map_err(|e| format!("Its files can't be read: {e}"));
        let entry = match read.and_then(|(c, k)| parse(&c, &k)) {
            Ok(loaded) => Entry { view: view_of(&loaded, false), key: Some(loaded.key), cert_file, key_file, stamp: None },
            Err(problem) => {
                tracing::error!(certificate = %id, %problem, "a certificate added on the Settings page is off");
                let view = ProvidedCert { id, names: Vec::new(), not_before: 0, not_after: 0, from_file: false, problem: Some(problem) };
                Entry { view, key: None, cert_file, key_file, stamp: None }
            }
        };
        entries.push(entry);
    }
    entries
}

/// Everything at startup. A file the configuration names that can't be used stops the server, as a
/// configuration mistake; one that has expired doesn't, and shows up as failed.
pub(super) fn load_all(files: &[CertFiles], dir: &Path) -> anyhow::Result<Vec<Entry>> {
    anyhow::ensure!(files.len() <= MAX_CERTIFICATES, "tls.certificates: at most {MAX_CERTIFICATES} certificates");
    let mut entries = load_saved(dir);
    for f in files {
        let read = |p: &Path| std::fs::read(p).with_context(|| format!("reading {}", p.display()));
        let (chain, key) = (read(&f.cert_file)?, read(&f.key_file)?);
        let loaded = parse(&chain, &key).map_err(|m| anyhow!("tls.certificates: {}: {m}", f.cert_file.display()))?;
        let view = view_of(&loaded, true);
        if view.expired() {
            tracing::warn!(certificate = %f.cert_file.display(), "this certificate has expired");
        }
        // A server started from a generated configuration finds the same one in both places.
        entries.retain(|e| e.view.id != view.id);
        let stamp = stamp_of(&f.cert_file, &f.key_file).ok();
        entries.push(Entry { view, key: Some(loaded.key), cert_file: f.cert_file.clone(), key_file: f.key_file.clone(), stamp });
    }
    sort(&mut entries);
    Ok(entries)
}

impl CertManager {
    fn publish_provided(&self, entries: &[Entry]) {
        *self.resolver.provided.write().unwrap() = NameMap::of(entries);
    }

    /// Puts what's loaded in effect at startup.
    pub(super) fn install_provided(&self) {
        self.publish_provided(&self.provided.lock().unwrap());
    }

    pub fn provided_list(&self) -> Vec<ProvidedCert> {
        self.provided.lock().unwrap().iter().map(|e| e.view.clone()).collect()
    }

    /// The certificate `host` gets if it's one people brought; `None` if the usual source serves it.
    pub(super) fn provided_status(&self, host: &str) -> Option<CertStatus> {
        if self.own_names.iter().any(|n| n == host) {
            return None;
        }
        let entries = self.provided.lock().unwrap();
        let view = &serving(&entries, host)?.view;
        Some(if view.expired() {
            CertStatus::Failed(format!("the certificate provided for {host} expired on {}", rfc3339(view.not_after)))
        } else if view.not_valid_yet() {
            CertStatus::Failed(format!("the certificate provided for {host} isn't valid until {}", rfc3339(view.not_before)))
        } else {
            CertStatus::Ready
        })
    }

    /// Until when the certificate `host` gets is valid, if it's one people brought.
    pub(super) fn provided_not_after(&self, host: &str) -> Option<i64> {
        if self.own_names.iter().any(|n| n == host) {
            return None;
        }
        serving(&self.provided.lock().unwrap(), host).map(|e| e.view.not_after)
    }

    pub fn provided_covers(&self, host: &str) -> bool {
        self.provided_status(host).is_some()
    }

    /// Adds a certificate, in use at once. The same one again is no change.
    pub fn add_provided(&self, chain: &str, key: &str) -> Result<ProvidedCert, AddError> {
        let invalid = |m: String| AddError::Invalid(m);
        // Browsers send a text box's lines with CRLF.
        let clean = |text: &str| format!("{}\n", text.replace("\r\n", "\n").trim());
        let (chain, key) = (clean(chain), clean(key));
        if chain.contains("PRIVATE KEY") {
            return Err(invalid("The certificate box must hold only certificates, and there's a key in it. The key has a box of its own.".into()));
        }
        let loaded = parse(chain.as_bytes(), key.as_bytes()).map_err(invalid)?;
        let view = view_of(&loaded, false);
        if view.expired() {
            return Err(invalid(format!("That certificate expired on {}.", rfc3339(view.not_after))));
        }
        if view.not_valid_yet() {
            return Err(invalid(format!("That certificate isn't valid until {}.", rfc3339(view.not_before))));
        }
        {
            let entries = self.provided.lock().unwrap();
            if entries.iter().any(|e| e.view.from_file && e.view.id == view.id) {
                return Err(invalid("That certificate is in the configuration file already.".into()));
            }
            if entries.iter().filter(|e| !e.view.from_file && e.view.id != view.id).count() >= MAX_CERTIFICATES {
                return Err(invalid(format!("There are {MAX_CERTIFICATES} certificates already. Remove one first.")));
            }
        }
        // Outside the lock: these wait for the disk, and status checks wait for the lock.
        let (cert_file, key_file) = saved_paths(&self.provided_dir, &view.id);
        self.save_provided(&cert_file, &key_file, &chain, &key).map_err(AddError::Storage)?;
        let mut entries = self.provided.lock().unwrap();
        entries.retain(|e| e.view.id != view.id);
        entries.push(Entry { view: view.clone(), key: Some(loaded.key), cert_file, key_file, stamp: None });
        sort(&mut entries);
        self.publish_provided(&entries);
        tracing::info!(certificate = %view.id, names = ?view.names, "certificate added");
        Ok(view)
    }

    fn save_provided(&self, cert_file: &Path, key_file: &Path, chain: &str, key: &str) -> anyhow::Result<()> {
        let mut dir = std::fs::DirBuilder::new();
        dir.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut dir, 0o700);
        dir.create(&self.provided_dir).with_context(|| format!("creating {}", self.provided_dir.display()))?;
        // The certificate last: it's what marks a pair as there at the next start.
        write_private(key_file, key.as_bytes()).with_context(|| format!("writing {}", key_file.display()))?;
        write_private(cert_file, chain.as_bytes()).with_context(|| format!("writing {}", cert_file.display()))
    }

    /// Removes a certificate added on the Settings page; `false` if there's no such one. Its names
    /// go back to the usual source at once.
    pub fn remove_provided(self: &Arc<Self>, id: &str) -> anyhow::Result<bool> {
        let files = self.provided.lock().unwrap().iter().find(|e| !e.view.from_file && e.view.id == id).map(|e| (e.cert_file.clone(), e.key_file.clone()));
        let Some((cert_file, key_file)) = files else { return Ok(false) };
        for file in [&cert_file, &key_file] {
            if let Err(e) = std::fs::remove_file(file)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                return Err(e).with_context(|| format!("removing {}", file.display()));
            }
        }
        {
            let mut entries = self.provided.lock().unwrap();
            entries.retain(|e| e.view.id != id);
            self.publish_provided(&entries);
        }
        tracing::info!(certificate = %id, "certificate removed");
        self.ensure_pending();
        Ok(true)
    }

    /// The files of what was added on the Settings page, for the generated configuration.
    pub fn saved_provided_files(&self) -> Vec<CertFiles> {
        let entries = self.provided.lock().unwrap();
        entries.iter().filter(|e| !e.view.from_file && e.key.is_some()).map(|e| CertFiles { cert_file: e.cert_file.clone(), key_file: e.key_file.clone() }).collect()
    }

    /// Picks up files in the configuration that changed, as when another tool renews them. Files
    /// that can't be used (yet: the key may not be written) leave the loaded certificate in use.
    pub(super) fn reload_provided_files(self: &Arc<Self>) {
        let watched: Vec<(PathBuf, PathBuf, Option<Stamp>)> =
            self.provided.lock().unwrap().iter().filter(|e| e.view.from_file).map(|e| (e.cert_file.clone(), e.key_file.clone(), e.stamp)).collect();
        let mut changed = false;
        for (cert_file, key_file, seen) in watched {
            let now = stamp_of(&cert_file, &key_file);
            if now.as_ref().ok() == seen.as_ref() {
                continue;
            }
            let read = now.map_err(|e| format!("Its files can't be read: {e}")).and_then(|stamp| {
                let bytes = std::fs::read(&cert_file).and_then(|c| Ok((c, std::fs::read(&key_file)?))).map_err(|e| format!("Its files can't be read: {e}"))?;
                Ok((parse(&bytes.0, &bytes.1)?, stamp))
            });
            let mut entries = self.provided.lock().unwrap();
            let Some(entry) = entries.iter_mut().find(|e| e.view.from_file && e.cert_file == cert_file) else { continue };
            match read {
                Ok((loaded, stamp)) => {
                    tracing::info!(certificate = %cert_file.display(), not_after = %rfc3339(loaded.not_after), "certificate files changed; using them now");
                    entry.view = view_of(&loaded, true);
                    entry.key = Some(loaded.key);
                    entry.stamp = Some(stamp);
                    changed = true;
                }
                Err(problem) => {
                    if entry.view.problem.as_ref() != Some(&problem) {
                        tracing::warn!(certificate = %cert_file.display(), %problem, "certificate files changed but can't be used; keeping the one loaded");
                    }
                    entry.view.problem = Some(problem);
                }
            }
        }
        if changed {
            {
                let mut entries = self.provided.lock().unwrap();
                sort(&mut entries);
                self.publish_provided(&entries);
            }
            self.ensure_pending();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::time::Duration;

    use rcgen::{CertificateParams, KeyPair};
    use time::OffsetDateTime;

    use super::*;
    use crate::config::TlsConfig;

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("mp-provided-{}", magicpipes_core::secret::random_string(8)))
    }

    /// `(chain, key)` valid for a year from a day ago, unless `shape` says otherwise.
    fn pair_with(names: &[&str], shape: impl FnOnce(&mut CertificateParams)) -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
        params.not_before = OffsetDateTime::now_utc() - time::Duration::days(1);
        params.not_after = OffsetDateTime::now_utc() + time::Duration::days(365);
        shape(&mut params);
        (params.self_signed(&key).unwrap().pem(), key.serialize_pem())
    }

    fn pair(names: &[&str]) -> (String, String) {
        pair_with(names, |_| {})
    }

    fn manager(dir: &Path, files: Vec<CertFiles>) -> anyhow::Result<Arc<CertManager>> {
        let cfg = TlsConfig { mode: crate::config::TlsMode::DevCa, certificates: files, ..TlsConfig::default() };
        CertManager::new(&cfg, dir, &["t.test", "manage.t.test"])
    }

    fn added(certs: &CertManager, pair: &(String, String)) -> ProvidedCert {
        certs.add_provided(&pair.0, &pair.1).unwrap_or_else(|e| match e {
            AddError::Invalid(m) => panic!("{m}"),
            AddError::Storage(e) => panic!("{e:#}"),
        })
    }

    fn refusal(certs: &CertManager, chain: &str, key: &str) -> String {
        match certs.add_provided(chain, key) {
            Err(AddError::Invalid(m)) => m,
            Err(AddError::Storage(e)) => panic!("{e:#}"),
            Ok(_) => panic!("it was added"),
        }
    }

    /// The certificate a handshake for `host` would get on the public listener.
    fn served(certs: &CertManager, host: &str) -> Option<Vec<u8>> {
        certs.resolver.lookup(host).map(|k| k.cert[0].as_ref().to_vec())
    }

    fn leaf(chain: &str) -> Vec<u8> {
        CertificateDer::pem_slice_iter(chain.as_bytes()).next().unwrap().unwrap().as_ref().to_vec()
    }

    #[tokio::test]
    async fn a_provided_certificate_wins_over_the_usual_source_and_goes_back_to_it() {
        let dir = temp_dir();
        let certs = manager(&dir, Vec::new()).unwrap();
        assert_eq!(certs.wait("shop.t.test", Duration::from_secs(10)).await, CertStatus::Ready);
        let issued = served(&certs, "shop.t.test").unwrap();

        let (chain, key) = pair(&["shop.t.test", "*.eu.t.test"]);
        let view = added(&certs, &(chain.clone(), key.clone()));
        assert_eq!(view.names, ["shop.t.test", "*.eu.t.test"]);
        assert_eq!(served(&certs, "SHOP.t.test").unwrap(), leaf(&chain), "over a certificate already issued");
        assert_eq!(served(&certs, "new.eu.t.test").unwrap(), leaf(&chain));
        assert!(served(&certs, "a.b.eu.t.test").is_none(), "a wildcard covers one label");

        // A covered name is never ordered, however often it's asked for.
        certs.ensure("new.eu.t.test");
        assert_eq!(certs.status("new.eu.t.test"), CertStatus::Ready);
        assert_eq!(certs.wait("new.eu.t.test", Duration::from_secs(10)).await, CertStatus::Ready);
        assert!(!certs.hosts.lock().unwrap().get("new.eu.t.test").unwrap().issuing);

        // Removing it hands every name back, without anyone asking again.
        assert!(certs.remove_provided(&view.id).unwrap());
        assert_eq!(served(&certs, "shop.t.test").unwrap(), issued);
        assert_eq!(certs.wait("new.eu.t.test", Duration::from_secs(10)).await, CertStatus::Ready);
        assert_ne!(served(&certs, "new.eu.t.test").unwrap(), leaf(&chain));
        assert!(!certs.remove_provided(&view.id).unwrap(), "already gone");
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn the_servers_own_names_keep_what_they_have() {
        let dir = temp_dir();
        let certs = manager(&dir, Vec::new()).unwrap();
        assert_eq!(certs.wait("manage.t.test", Duration::from_secs(10)).await, CertStatus::Ready);
        let own = certs.resolver.lookup_issued("manage.t.test").unwrap().cert[0].as_ref().to_vec();

        added(&certs, &pair(&["*.t.test", "t.test", "manage.t.test"]));

        // What the management listener asks for, and what decides whether its name gets ordered.
        assert_eq!(certs.resolver.lookup_issued("manage.t.test").unwrap().cert[0].as_ref(), own.as_slice());
        assert!(!certs.provided_covers("manage.t.test") && !certs.provided_covers("t.test"));
        assert_eq!(certs.status("manage.t.test"), CertStatus::Ready);
        assert!(certs.provided_covers("app.t.test"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn what_cant_be_used_is_refused_and_says_why() {
        let dir = temp_dir();
        let certs = manager(&dir, Vec::new()).unwrap();
        let (chain, key) = pair(&["shop.example.org"]);
        let (_, other_key) = pair(&["shop.example.org"]);

        assert!(refusal(&certs, "", &key).contains("no certificate"));
        assert!(refusal(&certs, "not a certificate", &key).contains("no certificate"));
        assert!(refusal(&certs, &key, &key).contains("key in it"), "the key pasted in both boxes");
        assert!(refusal(&certs, &format!("{chain}{key}"), &key).contains("key in it"), "a combined file");
        assert!(refusal(&certs, &chain, "").contains("private key"));
        assert!(refusal(&certs, &chain, "-----BEGIN ENCRYPTED PRIVATE KEY-----\nabc\n-----END ENCRYPTED PRIVATE KEY-----\n").contains("passphrase"));
        assert!(refusal(&certs, &chain, &other_key).contains("doesn't belong"));
        assert!(refusal(&certs, &"x".repeat(MAX_PEM + 1), &key).contains("too long"));

        let unnamed = pair(&[]);
        assert!(refusal(&certs, &unnamed.0, &unnamed.1).contains("no hostnames"));
        let expired = pair_with(&["a.example.org"], |p| {
            p.not_before = OffsetDateTime::now_utc() - time::Duration::days(30);
            p.not_after = OffsetDateTime::now_utc() - time::Duration::days(1);
        });
        assert!(refusal(&certs, &expired.0, &expired.1).contains("expired"));
        let later = pair_with(&["a.example.org"], |p| {
            p.not_before = OffsetDateTime::now_utc() + time::Duration::days(1);
            p.not_after = OffsetDateTime::now_utc() + time::Duration::days(30);
        });
        assert!(refusal(&certs, &later.0, &later.1).contains("isn't valid until"));

        // A message never quotes what was pasted as a key.
        let noisy = "-----BEGIN PRIVATE KEY-----\nSECRETSECRET\n-----BEGIN NONSENSE-----\n";
        assert!(!refusal(&certs, &chain, noisy).contains("SECRETSECRET"));

        assert!(certs.provided_list().is_empty() && !dir.join(DIR).exists(), "nothing was stored");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn what_a_browser_sends_works_and_the_same_one_twice_is_one() {
        let dir = temp_dir();
        let certs = manager(&dir, Vec::new()).unwrap();
        let (chain, key) = pair(&["shop.example.org"]);
        let first = certs.add_provided(&chain.replace('\n', "\r\n"), &format!("\r\n  {}  \r\n", key.replace('\n', "\r\n")));
        let Ok(first) = first else { panic!("text from a form should work") };
        assert_eq!(added(&certs, &(chain, key)).id, first.id);
        assert_eq!(certs.provided_list().len(), 1);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn what_was_added_survives_a_restart_and_only_its_owner_can_read_it() {
        let dir = temp_dir();
        let (chain, key) = pair(&["shop.example.org"]);
        let view = added(&manager(&dir, Vec::new()).unwrap(), &(chain.clone(), key));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            let (crt, k) = saved_paths(&dir.join(DIR), &view.id);
            assert_eq!((mode(dir.join(DIR)), mode(crt), mode(k)), (0o700, 0o600, 0o600));
        }

        let again = manager(&dir, Vec::new()).unwrap();
        assert_eq!(served(&again, "shop.example.org").unwrap(), leaf(&chain));
        assert_eq!(again.status("shop.example.org"), CertStatus::Ready);
        assert_eq!(again.saved_provided_files().len(), 1, "it's in the generated configuration");

        // Damaged files cost that certificate and nothing else, and it can still be removed.
        let (crt, _) = saved_paths(&dir.join(DIR), &view.id);
        std::fs::write(&crt, "garbage").unwrap();
        let damaged = manager(&dir, Vec::new()).unwrap();
        let list = damaged.provided_list();
        assert!(list.len() == 1 && list[0].names.is_empty() && list[0].problem.is_some(), "{list:?}");
        assert!(served(&damaged, "shop.example.org").is_none() && !damaged.provided_covers("shop.example.org"));
        assert!(damaged.remove_provided(&view.id).unwrap());
        assert!(!crt.exists());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn there_is_a_limit_on_what_can_be_added() {
        let dir = temp_dir();
        let certs = manager(&dir, Vec::new()).unwrap();
        for i in 0..MAX_CERTIFICATES {
            added(&certs, &pair(&[&format!("a{i}.example.org")]));
        }
        let one_more = pair(&["more.example.org"]);
        assert!(refusal(&certs, &one_more.0, &one_more.1).contains("Remove one first"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn the_longest_lived_certificate_wins_and_the_status_says_which() {
        let dir = temp_dir();
        let certs = manager(&dir, Vec::new()).unwrap();
        let short = pair_with(&["shop.example.org"], |p| p.not_after = OffsetDateTime::now_utc() + time::Duration::days(10));
        let long = pair(&["shop.example.org"]);
        added(&certs, &long);
        added(&certs, &short);
        assert_eq!(served(&certs, "shop.example.org").unwrap(), leaf(&long.0));

        // An exact name goes before a wildcard, however long that lasts.
        let wider = pair_with(&["*.example.org"], |p| p.not_after = OffsetDateTime::now_utc() + time::Duration::days(800));
        added(&certs, &wider);
        assert_eq!(served(&certs, "shop.example.org").unwrap(), leaf(&long.0));
        assert_eq!(served(&certs, "other.example.org").unwrap(), leaf(&wider.0));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn expiry_shows_before_and_after() {
        let view = |not_before: i64, not_after: i64| ProvidedCert { id: String::new(), names: Vec::new(), not_before, not_after, from_file: false, problem: None };
        let (now, day) = (unix_now(), 24 * 3600);
        let year = view(now - day, now + 365 * day);
        assert!(!year.expired() && !year.expires_soon() && !year.not_valid_yet());
        assert!(view(now - 300 * day, now + 20 * day).expires_soon());
        assert!(!view(now - day, now + 20 * day).expires_soon(), "a short life isn't always ending");
        assert!(view(now - 20 * day, now + 2 * day).expires_soon());
        assert!(view(now - 2 * day, now - day).expired());
        assert!(view(now + day, now + 2 * day).not_valid_yet());

        let dir = temp_dir();
        let cert_file = dir.join("expired.crt");
        let key_file = dir.join("expired.key");
        std::fs::create_dir_all(&dir).unwrap();
        let expired = pair_with(&["old.example.org"], |p| {
            p.not_before = OffsetDateTime::now_utc() - time::Duration::days(30);
            p.not_after = OffsetDateTime::now_utc() - time::Duration::days(1);
        });
        std::fs::write(&cert_file, &expired.0).unwrap();
        std::fs::write(&key_file, &expired.1).unwrap();
        let certs = manager(&dir, vec![CertFiles { cert_file, key_file }]).unwrap();
        assert!(matches!(certs.status("old.example.org"), CertStatus::Failed(m) if m.contains("expired")));
        certs.ensure("old.example.org");
        assert!(!certs.hosts.lock().unwrap().get("old.example.org").unwrap().issuing, "it stays yours to replace");
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn files_in_the_configuration_are_watched() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_file, key_file) = (dir.join("shop.crt"), dir.join("shop.key"));
        let write = |p: &(String, String)| {
            std::fs::write(&cert_file, &p.0).unwrap();
            std::fs::write(&key_file, &p.1).unwrap();
        };

        let missing = manager(&dir, vec![CertFiles { cert_file: cert_file.clone(), key_file: key_file.clone() }]);
        assert!(missing.is_err(), "a mistake in the configuration stops the server");

        let first = pair(&["shop.example.org"]);
        write(&first);
        let certs = manager(&dir, vec![CertFiles { cert_file: cert_file.clone(), key_file: key_file.clone() }]).unwrap();
        let listed = certs.provided_list();
        assert!(listed[0].from_file);
        assert!(!certs.remove_provided(&listed[0].id).unwrap() && cert_file.exists(), "not removable from the page");
        assert!(certs.saved_provided_files().is_empty(), "the configuration has it already");
        assert_eq!(served(&certs, "shop.example.org").unwrap(), leaf(&first.0));

        // Half a renewal (a new certificate, the old key) changes nothing until it's whole.
        let second = pair(&["shop.example.org", "new.example.org"]);
        std::fs::write(&cert_file, &second.0).unwrap();
        certs.reload_provided_files();
        assert_eq!(served(&certs, "shop.example.org").unwrap(), leaf(&first.0));
        assert!(certs.provided_list()[0].problem.as_deref().is_some_and(|m| m.contains("doesn't belong")));

        write(&second);
        certs.reload_provided_files();
        assert_eq!(served(&certs, "new.example.org").unwrap(), leaf(&second.0));
        assert!(certs.provided_list()[0].problem.is_none());

        // A file that vanished leaves the loaded one in use.
        std::fs::remove_file(&key_file).unwrap();
        certs.reload_provided_files();
        assert_eq!(served(&certs, "new.example.org").unwrap(), leaf(&second.0));
        assert!(certs.provided_list()[0].problem.as_deref().is_some_and(|m| m.contains("can't be read")));
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn a_name_no_longer_covered_is_ordered_if_something_wants_it() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_file, key_file) = (dir.join("shop.crt"), dir.join("shop.key"));
        let both = pair(&["keep.t.test", "drop.t.test", "gone.t.test"]);
        std::fs::write(&cert_file, &both.0).unwrap();
        std::fs::write(&key_file, &both.1).unwrap();
        let certs = manager(&dir, vec![CertFiles { cert_file: cert_file.clone(), key_file: key_file.clone() }]).unwrap();
        for host in ["drop.t.test", "gone.t.test"] {
            certs.ensure(host);
        }
        certs.set_wanted(&HashSet::from(["drop.t.test"]));

        let fewer = pair(&["keep.t.test"]);
        std::fs::write(&cert_file, &fewer.0).unwrap();
        std::fs::write(&key_file, &fewer.1).unwrap();
        certs.reload_provided_files();
        assert_eq!(certs.wait("drop.t.test", Duration::from_secs(10)).await, CertStatus::Ready);
        assert_eq!(certs.hosts.lock().unwrap().get("gone.t.test").unwrap().status.borrow().clone(), CertStatus::Pending, "nothing wants this one");
        std::fs::remove_dir_all(dir).ok();
    }
}
