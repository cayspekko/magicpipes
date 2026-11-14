//! Upgrading a binary in place: reading the release source, downloading this platform's binary,
//! checking it, and putting it where this one is. Both binaries use it for `--upgrade`; how the
//! running process then hands over to the new one is theirs (`magicpipesd`'s `handover`, the
//! agent's take-over).
//!
//! Everything a release says is believed only once [`release::verify`] has: the manifest carries
//! the SHA-256 of each binary, so where the binary comes from doesn't matter. A source may be
//! `http://` (a mirror on a closed network), but a redirect never goes from `https` to `http`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Uri, header};
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;

use crate::error::ErrorCode;
use crate::release::{self, Manifest, ReleaseFile, Untrusted, Version};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// For the manifest and its signature, whole.
const SMALL_TIMEOUT: Duration = Duration::from_secs(30);
/// For a binary: the longest wait for its next piece, and for all of it.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_REDIRECTS: usize = 5;
/// The longest `--version` of a new binary may take.
const SELF_TEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Why an upgrade (or the check before one) stopped, with the code scripts read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeError {
    pub code: ErrorCode,
    pub message: String,
}

impl UpgradeError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    fn unreachable(what: &str, e: impl std::fmt::Display) -> Self {
        Self::new(ErrorCode::ReleaseUnreachable, format!("{what}: {e}"))
    }
}

impl std::fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<Untrusted> for UpgradeError {
    fn from(u: Untrusted) -> Self {
        let code = if u == Untrusted::NoKeys { ErrorCode::UpgradeNotPossible } else { ErrorCode::ReleaseInvalid };
        Self::new(code, u.to_string())
    }
}

/// The release source as configured, ending in `/`.
pub fn source_url(configured: Option<&str>) -> String {
    let s = configured.map(str::trim).filter(|s| !s.is_empty()).unwrap_or(release::DEFAULT_SOURCE);
    if s.ends_with('/') { s.to_string() } else { format!("{s}/") }
}

/// What the source offers, checked: its manifest, if one of this build's keys signed it.
pub async fn latest(source: &str) -> Result<Manifest, UpgradeError> {
    let keys = release::trusted_keys();
    if keys.is_empty() {
        return Err(Untrusted::NoKeys.into());
    }
    let base = source_url(Some(source));
    let manifest = fetch_small(&format!("{base}{}", release::MANIFEST)).await?;
    let signature = fetch_small(&format!("{base}{}", release::SIGNATURE)).await?;
    Ok(release::verify(&manifest, &signature, &keys)?)
}

/// What [`latest`] means for this binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Offer {
    /// A newer version, with this platform's `binary` in it.
    Newer(Manifest),
    /// Nothing newer than this build.
    UpToDate(Manifest),
    /// A newer version, without a binary for this platform.
    NotForThisPlatform(Manifest),
}

impl Offer {
    pub fn of(manifest: Manifest, binary: &str) -> Self {
        let newer = manifest.parsed_version().is_some_and(|v| v > Version::current());
        match (newer, manifest.file(binary).is_some()) {
            (false, _) => Offer::UpToDate(manifest),
            (true, true) => Offer::Newer(manifest),
            (true, false) => Offer::NotForThisPlatform(manifest),
        }
    }

    pub fn manifest(&self) -> &Manifest {
        match self {
            Offer::Newer(m) | Offer::UpToDate(m) | Offer::NotForThisPlatform(m) => m,
        }
    }
}

/// The whole of a small file (a manifest or a signature).
async fn fetch_small(url: &str) -> Result<Bytes, UpgradeError> {
    let fetch = async {
        let (resp, _conn) = get(url).await?;
        if !resp.status().is_success() {
            return Err(UpgradeError::unreachable(url, format!("answered {}", resp.status())));
        }
        let body = http_body_util::Limited::new(resp.into_body(), release::MAX_MANIFEST as usize);
        body.collect().await.map(|b| b.to_bytes()).map_err(|e| UpgradeError::unreachable(url, e))
    };
    tokio::time::timeout(SMALL_TIMEOUT, fetch).await.map_err(|_| UpgradeError::unreachable(url, "no answer in time"))?
}

/// Downloads `file` to `to`, checking its size and SHA-256 as it goes; `to` is removed unless it
/// all matched. Executable for its owner.
pub async fn download(file: &ReleaseFile, to: &Path) -> Result<(), UpgradeError> {
    if file.size > release::MAX_BINARY {
        return Err(UpgradeError::new(ErrorCode::ReleaseInvalid, format!("the release says its binary is {} bytes, more than any can be", file.size)));
    }
    let result = tokio::time::timeout(DOWNLOAD_TIMEOUT, download_to(file, to)).await.unwrap_or_else(|_| Err(UpgradeError::unreachable(&file.url, "the download took too long")));
    if result.is_err() {
        let _ = std::fs::remove_file(to);
    }
    result
}

async fn download_to(file: &ReleaseFile, to: &Path) -> Result<(), UpgradeError> {
    let (resp, _conn) = get(&file.url).await?;
    if !resp.status().is_success() {
        return Err(UpgradeError::unreachable(&file.url, format!("answered {}", resp.status())));
    }
    let local = |e: std::io::Error| UpgradeError::new(ErrorCode::UpgradeNotPossible, format!("writing {}: {e}", to.display()));
    let mut out = new_executable(to).map_err(local)?;
    let mut hash = Sha256::new();
    let mut size: u64 = 0;
    let mut body = resp.into_body();
    loop {
        let frame = match tokio::time::timeout(IDLE_TIMEOUT, body.frame()).await {
            Err(_) => return Err(UpgradeError::unreachable(&file.url, "the download stalled")),
            Ok(None) => break,
            Ok(Some(Err(e))) => return Err(UpgradeError::unreachable(&file.url, e)),
            Ok(Some(Ok(frame))) => frame,
        };
        let Ok(data) = frame.into_data() else { continue };
        size += data.len() as u64;
        if size > file.size {
            return Err(UpgradeError::new(ErrorCode::ReleaseInvalid, "the binary is bigger than the release says"));
        }
        hash.update(&data);
        out.write_all(&data).map_err(local)?;
    }
    out.sync_all().map_err(local)?;
    let digest: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
    if size != file.size || !crate::secret::constant_time_eq(digest.as_bytes(), file.sha256.to_ascii_lowercase().as_bytes()) {
        return Err(UpgradeError::new(ErrorCode::ReleaseInvalid, "the binary doesn't match the checksum its release signed; nothing was installed"));
    }
    Ok(())
}

fn new_executable(path: &Path) -> std::io::Result<std::fs::File> {
    let _ = std::fs::remove_file(path);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o700);
    o.open(path)
}

/// Drives one request's connection; aborted when dropped, once the body has been read.
#[derive(Debug)]
struct Connection(tokio::task::JoinHandle<()>);

impl Drop for Connection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// `GET url`, following redirects (never from `https` to `http`).
async fn get(url: &str) -> Result<(hyper::Response<Incoming>, Connection), UpgradeError> {
    let mut url = url.to_string();
    let mut secure = false;
    for _ in 0..=MAX_REDIRECTS {
        let uri: Uri = url.parse().map_err(|e| UpgradeError::unreachable(&url, e))?;
        let tls = uses_tls(uri.scheme_str(), secure).map_err(|why| UpgradeError::unreachable(&url, why))?;
        secure |= tls;
        let (resp, conn) = tokio::time::timeout(SMALL_TIMEOUT, send(&uri, tls)).await.map_err(|_| UpgradeError::unreachable(&url, "no answer in time"))??;
        if resp.status().is_redirection()
            && let Some(location) = resp.headers().get(header::LOCATION).and_then(|v| v.to_str().ok())
        {
            url = if location.starts_with('/') {
                format!("{}://{}{location}", uri.scheme_str().unwrap_or("https"), uri.authority().map_or("", |a| a.as_str()))
            } else {
                location.to_string()
            };
            continue;
        }
        return Ok((resp, conn));
    }
    Err(UpgradeError::unreachable(&url, "too many redirects"))
}

/// Whether a request to an address with `scheme` goes over TLS, `secure` once one has: then
/// never again without.
fn uses_tls(scheme: Option<&str>, secure: bool) -> Result<bool, &'static str> {
    match scheme {
        Some("https") => Ok(true),
        Some("http") if !secure => Ok(false),
        Some("http") => Err("refusing a redirect from https to http"),
        _ => Err("not an http or https address"),
    }
}

async fn send(uri: &Uri, tls: bool) -> Result<(hyper::Response<Incoming>, Connection), UpgradeError> {
    let url = uri.to_string();
    let host = uri.host().ok_or_else(|| UpgradeError::unreachable(&url, "no host"))?;
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let authority = uri.authority().map_or(bare, |a| a.as_str());
    let path = uri.path_and_query().map_or("/", |p| p.as_str());
    let req = Request::get(path)
        .header(header::HOST, authority)
        .header(header::USER_AGENT, concat!("magicpipes/", env!("CARGO_PKG_VERSION")))
        .header(header::ACCEPT, "*/*")
        .header(header::CONNECTION, "close")
        .body(Empty::<Bytes>::new())
        .map_err(|e| UpgradeError::unreachable(&url, e))?;
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((bare, port)))
        .await
        .map_err(|_| UpgradeError::unreachable(&url, "timed out connecting"))?
        .map_err(|e| UpgradeError::unreachable(&url, e))?;
    let _ = tcp.set_nodelay(true);
    if tls {
        let name = rustls_pki_types::ServerName::try_from(bare.to_string()).map_err(|_| UpgradeError::unreachable(&url, "not a host name"))?;
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, tokio_rustls::TlsConnector::from(tls_config()).connect(name, tcp))
            .await
            .map_err(|_| UpgradeError::unreachable(&url, "TLS handshake timed out"))?
            .map_err(|e| UpgradeError::unreachable(&url, e))?;
        exchange(TokioIo::new(stream), req, &url).await
    } else {
        exchange(TokioIo::new(tcp), req, &url).await
    }
}

async fn exchange<I>(io: I, req: Request<Empty<Bytes>>, url: &str) -> Result<(hyper::Response<Incoming>, Connection), UpgradeError>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.map_err(|e| UpgradeError::unreachable(url, e))?;
    let conn = Connection(tokio::spawn(async move {
        let _ = conn.await;
    }));
    let resp = sender.send_request(req).await.map_err(|e| UpgradeError::unreachable(url, e))?;
    Ok((resp, conn))
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("ring supports the default protocol versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(cfg)
        })
        .clone()
}

// ---- putting a binary in place -------------------------------------------------------------

static EXE: OnceLock<Option<PathBuf>> = OnceLock::new();

/// This binary's path, as it was when the process started: call [`remember_exe`] first thing,
/// since once an upgrade has replaced the file, the system may name the old one as deleted.
pub fn exe() -> Option<&'static Path> {
    EXE.get_or_init(find_exe).as_deref()
}

/// Notes this binary's path while it's still the one running.
pub fn remember_exe() {
    let _ = exe();
}

fn find_exe() -> Option<PathBuf> {
    let p = std::env::current_exe().ok()?;
    // Through a symlink (Homebrew's `bin/`, say) to the file itself, whose path says who owns it.
    Some(std::fs::canonicalize(&p).unwrap_or(p))
}

/// Why this binary can't replace itself, if it can't: the caller says so instead of trying.
pub fn cannot_replace(exe: &Path) -> Option<String> {
    if release::TARGET.is_none() {
        return Some("there are no releases for this platform; build it from source".into());
    }
    if release::trusted_keys().is_empty() {
        return Some("this build trusts no release key, so it can't check a release; install a release build".into());
    }
    if in_container() {
        return Some("it runs in a container, whose image is the thing to upgrade: pull the new image and recreate the container".into());
    }
    if let Some(manager) = package_manager(exe) {
        return Some(format!("{manager} installed it; upgrade it with {manager}"));
    }
    let dir = exe.parent()?;
    let probe = dir.join(format!(".magicpipes-upgrade-{}", crate::secret::random_string(8)));
    match std::fs::OpenOptions::new().write(true).create_new(true).open(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            None
        }
        Err(e) => Some(format!("it can't write to {} ({e}); run the upgrade as a user who can, such as with sudo", dir.display())),
    }
}

/// Whether this process runs in a container, as best it can tell.
pub fn in_container() -> bool {
    Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists() || std::env::var_os("KUBERNETES_SERVICE_HOST").is_some() || (cfg!(unix) && std::process::id() == 1)
}

/// The package manager that owns a binary at `exe`, judged from where it is.
pub fn package_manager(exe: &Path) -> Option<&'static str> {
    let p = exe.to_string_lossy();
    if p.contains("/nix/store/") {
        Some("Nix")
    } else if p.contains("/Cellar/") || p.contains("/homebrew/") || p.contains("/linuxbrew/") {
        Some("Homebrew")
    } else if p.starts_with("/snap/") {
        Some("snap")
    } else if ["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"].iter().any(|d| p.starts_with(d)) {
        Some("the system's package manager")
    } else {
        None
    }
}

/// Where a new binary waits beside `exe` before it takes its place, and where the one it replaced
/// is kept.
pub fn staged_path(exe: &Path) -> PathBuf {
    sibling(exe, "new")
}

pub fn kept_path(exe: &Path) -> PathBuf {
    sibling(exe, "old")
}

fn sibling(exe: &Path, what: &str) -> PathBuf {
    let name = exe.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    // Windows runs a program by its extension, so the extension stays last.
    let name = match name.strip_suffix(".exe") {
        Some(stem) => format!("{stem}.{what}.exe"),
        None => format!("{name}.{what}"),
    };
    exe.with_file_name(name)
}

/// Runs `path --version`, which must answer with `binary`'s name: a binary that doesn't run here
/// (another platform, a broken download) stops the upgrade before it takes anyone's place.
pub fn self_test(path: &Path, binary: &str) -> Result<String, UpgradeError> {
    let failed = |why: String| UpgradeError::new(ErrorCode::UpgradeFailed, format!("the new binary didn't run: {why}"));
    let mut child = std::process::Command::new(path)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| failed(e.to_string()))?;
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(status)) => return Err(failed(format!("`--version` exited with {status}"))),
            Ok(None) if started.elapsed() > SELF_TEST_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(failed("`--version` didn't finish".into()));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(failed(e.to_string())),
        }
    }
    let mut out = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = std::io::Read::read_to_string(&mut std::io::Read::take(&mut stdout, 4096), &mut out);
    }
    let out = out.trim().to_string();
    if !out.starts_with(binary) {
        return Err(failed(format!("`--version` said '{out}', not {binary}")));
    }
    Ok(out)
}

/// Puts `staged` in place of `exe`, keeping the binary it replaces at [`kept_path`]. The path
/// never lacks a binary: on Unix the new one is renamed over the old, which a running process
/// keeps using; on Windows the running binary is renamed aside first, which Windows allows.
pub fn swap(exe: &Path, staged: &Path) -> std::io::Result<()> {
    let kept = kept_path(exe);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(exe)?.permissions().mode() & 0o7777;
        std::fs::set_permissions(staged, std::fs::Permissions::from_mode(mode | 0o100))?;
        // Kept as a second name for the old file, then the new file takes the first.
        let linking = sibling(exe, "old-link");
        let _ = std::fs::remove_file(&linking);
        if std::fs::hard_link(exe, &linking).is_err() {
            std::fs::copy(exe, &linking)?;
        }
        std::fs::rename(&linking, &kept)?;
        std::fs::rename(staged, exe)
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::remove_file(&kept);
        std::fs::rename(exe, &kept)?;
        match std::fs::rename(staged, exe) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = std::fs::rename(&kept, exe);
                Err(e)
            }
        }
    }
}

/// Puts the kept binary back in place of `exe`, keeping the one it replaces in its place, so a
/// second roll back undoes the first. `false` if there's none.
pub fn roll_back(exe: &Path) -> std::io::Result<bool> {
    let kept = kept_path(exe);
    if !kept.exists() {
        return Ok(false);
    }
    let staged = staged_path(exe);
    let _ = std::fs::remove_file(&staged);
    std::fs::copy(&kept, &staged)?;
    swap(exe, &staged)?;
    Ok(true)
}

/// Downloads this platform's `binary` from `manifest` beside `exe`, checks it, runs it, and puts
/// it in place. Returns what its `--version` said. The binary it replaced is kept for
/// [`roll_back`].
pub async fn install(manifest: &Manifest, binary: &str, exe: &Path) -> Result<String, UpgradeError> {
    if let Some(why) = cannot_replace(exe) {
        return Err(UpgradeError::new(ErrorCode::UpgradeNotPossible, format!("can't upgrade {}: {why}", exe.display())));
    }
    let file = manifest
        .file(binary)
        .ok_or_else(|| UpgradeError::new(ErrorCode::UpgradeNotPossible, format!("release {} has no {binary} for {}", manifest.version, release::TARGET.unwrap_or("this platform"))))?;
    let staged = staged_path(exe);
    download(file, &staged).await?;
    let (staged_for_test, binary_name) = (staged.clone(), binary.to_string());
    let tested = tokio::task::spawn_blocking(move || self_test(&staged_for_test, &binary_name))
        .await
        .map_err(|e| UpgradeError::new(ErrorCode::UpgradeFailed, e.to_string()))
        .and_then(|r| r);
    let said = match tested {
        Ok(said) => said,
        Err(e) => {
            let _ = std::fs::remove_file(&staged);
            return Err(e);
        }
    };
    let (exe_owned, staged_owned) = (exe.to_path_buf(), staged.clone());
    let swapped = tokio::task::spawn_blocking(move || swap(&exe_owned, &staged_owned)).await.map_err(std::io::Error::other).and_then(|r| r);
    if let Err(e) = swapped {
        let _ = std::fs::remove_file(&staged);
        return Err(UpgradeError::new(ErrorCode::UpgradeNotPossible, format!("putting the new binary in place of {}: {e}", exe.display())));
    }
    Ok(said)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("mp-upgrade-{}", crate::secret::random_string(8)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn staged_and_kept_binaries_sit_beside_it_and_keep_windows_extensions() {
        assert_eq!(staged_path(Path::new("/opt/mp/magicpipesd")), Path::new("/opt/mp/magicpipesd.new"));
        assert_eq!(kept_path(Path::new("/opt/mp/magicpipesd")), Path::new("/opt/mp/magicpipesd.old"));
        assert_eq!(staged_path(Path::new("C:/mp/magicpipes.exe")), Path::new("C:/mp/magicpipes.new.exe"));
    }

    #[test]
    fn package_managers_are_known_by_where_they_put_binaries() {
        assert_eq!(package_manager(Path::new("/nix/store/abc-magicpipes/bin/magicpipes")), Some("Nix"));
        assert_eq!(package_manager(Path::new("/opt/homebrew/Cellar/magicpipes/0.1.1/bin/magicpipes")), Some("Homebrew"));
        assert_eq!(package_manager(Path::new("/usr/bin/magicpipesd")), Some("the system's package manager"));
        assert_eq!(package_manager(Path::new("/usr/local/bin/magicpipesd")), None);
        assert_eq!(package_manager(Path::new("/home/ann/bin/magicpipes")), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_swap_keeps_the_old_binary_and_rolls_back_to_it() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir();
        let exe = d.join("magicpipes");
        std::fs::write(&exe, b"old").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let staged = staged_path(&exe);
        std::fs::write(&staged, b"new").unwrap();

        swap(&exe, &staged).unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"new");
        assert_eq!(std::fs::read(kept_path(&exe)).unwrap(), b"old");
        assert!(!staged.exists());
        assert_eq!(std::fs::metadata(&exe).unwrap().permissions().mode() & 0o777, 0o755, "the new one gets the old one's mode");

        // A second upgrade keeps the one it replaced, not the first.
        std::fs::write(&staged, b"newer").unwrap();
        swap(&exe, &staged).unwrap();
        assert_eq!(std::fs::read(kept_path(&exe)).unwrap(), b"new");

        assert!(roll_back(&exe).unwrap());
        assert_eq!(std::fs::read(&exe).unwrap(), b"new");
        assert_eq!(std::fs::read(kept_path(&exe)).unwrap(), b"newer", "kept, to roll forward again");
        assert!(roll_back(&exe).unwrap());
        assert_eq!(std::fs::read(&exe).unwrap(), b"newer");
        std::fs::remove_file(kept_path(&exe)).unwrap();
        assert!(!roll_back(&exe).unwrap(), "nothing to roll back to");
        std::fs::remove_dir_all(&d).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_new_binary_must_run_and_name_itself() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir();
        let script = |name: &str, body: &str| {
            let p = d.join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        };
        assert_eq!(self_test(&script("good", "echo magicpipes 9.9.9"), "magicpipes").unwrap(), "magicpipes 9.9.9");
        for (name, body) in [("other", "echo something 1.0.0"), ("fails", "exit 3"), ("garbage", "\x7fELF")] {
            let e = self_test(&script(name, body), "magicpipes").unwrap_err();
            assert_eq!(e.code, ErrorCode::UpgradeFailed, "{name}: {e}");
        }
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn offers_say_whether_to_upgrade() {
        let m = |v: &str, target: &str| Manifest {
            version: v.into(),
            notes: None,
            security: false,
            files: vec![ReleaseFile { target: target.into(), binary: "magicpipes".into(), url: "u".into(), sha256: "s".into(), size: 1 }],
        };
        let here = release::TARGET.unwrap_or("none");
        assert!(matches!(Offer::of(m("999.0.0", here), "magicpipes"), Offer::Newer(_)) || release::TARGET.is_none());
        assert!(matches!(Offer::of(m("999.0.0", "elsewhere"), "magicpipes"), Offer::NotForThisPlatform(_)));
        assert!(matches!(Offer::of(m("999.0.0", here), "magicpipesd"), Offer::NotForThisPlatform(_)));
        assert!(matches!(Offer::of(m(crate::VERSION, here), "magicpipes"), Offer::UpToDate(_)));
        assert!(matches!(Offer::of(m("0.0.1", here), "magicpipes"), Offer::UpToDate(_)));
    }

    /// A path, the status it answers, its headers and its body.
    type Answer = (&'static str, http::StatusCode, Vec<(&'static str, String)>, Vec<u8>);

    /// A tiny HTTP server for one test: answers each path from `files`, or redirects.
    async fn serve(files: Vec<Answer>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let files = Arc::new(files);
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                let files = files.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let files = files.clone();
                        async move {
                            let found = files.iter().find(|(p, ..)| *p == req.uri().path());
                            let mut resp = hyper::Response::new(http_body_util::Full::new(Bytes::from(found.map(|f| f.3.clone()).unwrap_or_default())));
                            *resp.status_mut() = found.map_or(http::StatusCode::NOT_FOUND, |f| f.1);
                            for (k, v) in found.map(|f| f.2.clone()).unwrap_or_default() {
                                resp.headers_mut().insert(k, v.parse().unwrap());
                            }
                            Ok::<_, std::convert::Infallible>(resp)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tcp), svc).await;
                });
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn downloads_follow_redirects_and_must_match_their_checksum() {
        let body = b"#!/bin/sh\necho magicpipes 9.9.9\n".to_vec();
        let digest: String = Sha256::digest(&body).iter().map(|b| format!("{b:02x}")).collect();
        let base = serve(vec![
            ("/bin", http::StatusCode::FOUND, vec![("location", "/files/bin".into())], vec![]),
            ("/files/bin", http::StatusCode::OK, vec![], body.clone()),
        ])
        .await;
        let d = dir();
        let file = |sha256: &str, size: usize| ReleaseFile { target: "t".into(), binary: "magicpipes".into(), url: format!("{base}/bin"), sha256: sha256.into(), size: size as u64 };

        let to = d.join("ok");
        download(&file(&digest, body.len()), &to).await.unwrap();
        assert_eq!(std::fs::read(&to).unwrap(), body);

        for (name, f) in [("wrong-sum", file(&"0".repeat(64), body.len())), ("too-small", file(&digest, body.len() - 1)), ("too-big", file(&digest, body.len() + 1))] {
            let to = d.join(name);
            let e = download(&f, &to).await.unwrap_err();
            assert_eq!(e.code, ErrorCode::ReleaseInvalid, "{name}: {e}");
            assert!(!to.exists(), "{name}: nothing is left behind");
        }
        let missing = ReleaseFile { url: format!("{base}/nothing"), ..file(&digest, body.len()) };
        assert_eq!(download(&missing, &d.join("missing")).await.unwrap_err().code, ErrorCode::ReleaseUnreachable);
        std::fs::remove_dir_all(&d).ok();
    }

    #[tokio::test]
    async fn redirects_never_go_from_https_to_http() {
        assert_eq!(uses_tls(Some("https"), false), Ok(true));
        assert_eq!(uses_tls(Some("http"), false), Ok(false), "a source on a closed network");
        assert!(uses_tls(Some("http"), true).is_err(), "once https, always");
        assert_eq!(uses_tls(Some("https"), true), Ok(true));
        assert!(uses_tls(Some("ftp"), false).is_err());
        assert_eq!(get("ftp://example.com/x").await.unwrap_err().code, ErrorCode::ReleaseUnreachable);
    }
}
