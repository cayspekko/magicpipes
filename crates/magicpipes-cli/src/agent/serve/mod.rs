//! Built-in static file server for `magicpipes add --serve <dir>`.
//!
//! It runs inside the agent: each data stream of a static tunnel is served directly by hyper, so
//! no local port is opened. tower-http's `ServeFile` produces the file responses (`Range`,
//! `Last-Modified`/`If-Modified-Since`, `HEAD`); this module decides *which* file, and is strict
//! about it because the directory is exposed to the internet:
//!
//! - Read-only: GET and HEAD, plus POST on a listed directory to download a selection as a
//!   `.tar.gz` (the POST only carries the names; nothing is ever written).
//! - Hidden entries (names starting with `.`) are neither listed, served nor archived.
//! - The path is decoded segment by segment; `.`/`..`, backslashes, NUL and (on Windows) `:` are
//!   refused, and the canonical result must lie inside the canonical root, so symlinks that point
//!   outside the root are refused (and not listed). That result is then opened one component at a
//!   time without following anything ([`open_servable`]), and only the open file is used: someone
//!   who can write to the directory can't swap in a symlink between the check and the read.
//! - HTML, SVG and XML can't run scripts on the tunnel's origin unless the tunnel was added with
//!   `--site`: a file in a shared folder shouldn't be able to read the rest of it, with a signed-in
//!   visitor's session, and send it elsewhere.
//! - A directory's `index.html` is served either way. Directories without one are listed, and can
//!   be downloaded as an archive, only when listing is on (`--no-list` turns both off).
//!
//! * `kinds` — file kinds: icons, open-in-browser vs download, `Content-Type`.
//! * `listing` — the directory page.
//! * `archive` — streamed `.tar.gz` downloads.

mod archive;
mod kinds;
mod listing;

use std::convert::Infallible;
use std::fs::{File, Metadata};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response, StatusCode, header};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use magicpipes_core::error::ErrorCode;
use magicpipes_core::url;
use tokio::io::{AsyncRead, AsyncWrite};
use tower_http::services::ServeFile;

use listing::{Entry, Page};

use crate::ipc::ErrorInfo;

pub(super) type Body = UnsyncBoxBody<Bytes, std::io::Error>;

/// Entries beyond this are left out of a listing (and counted in a note).
const MAX_LISTED: usize = 5000;
/// Largest accepted selection form (names of the entries to archive).
const MAX_FORM: usize = 1024 * 1024;
/// What a file that could run scripts gets without `--site`. Scripts and forms stay off; its own
/// styles and images still load, with the visitor's session on a private tunnel.
const NO_SCRIPTS: &str = "sandbox allow-same-origin allow-downloads allow-popups allow-popups-to-escape-sandbox";

pub struct Site {
    /// Canonical path of the served directory.
    pub root: PathBuf,
    pub list: bool,
    /// Pages may run scripts (`--site`).
    pub scripts: bool,
}

/// What publishing `root` would give away, if it's somewhere nobody means to publish whole: the
/// filesystem, a home folder, a hidden folder in one (`~/.ssh`), or anything holding this agent's
/// credentials. Hidden names are never served, but plenty of secrets don't have one.
fn sensitive_root(root: &Path) -> Option<&'static str> {
    if root.parent().is_none() {
        return Some("the whole filesystem");
    }
    let state = std::fs::canonicalize(crate::state::home()).unwrap_or_else(|_| crate::state::home());
    if state.starts_with(root) || root.starts_with(&state) {
        return Some("this agent's credentials");
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).and_then(|h| std::fs::canonicalize(h).ok())?;
    if home.starts_with(root) {
        return Some("your whole home folder");
    }
    let hidden = root.strip_prefix(&home).ok()?.components().any(|c| c.as_os_str().to_string_lossy().starts_with('.'));
    hidden.then_some("a hidden folder in your home folder")
}

/// Validates a directory for `--serve` and returns its canonical path.
pub async fn check_root(dir: &Path, allow_sensitive: bool) -> Result<PathBuf, ErrorInfo> {
    let bad = |m: String| ErrorInfo::new(ErrorCode::InvalidDirectory, m);
    let root = tokio::fs::canonicalize(dir).await.map_err(|e| bad(format!("cannot serve {}: {e}", dir.display())))?;
    let meta = tokio::fs::metadata(&root).await.map_err(|e| bad(format!("cannot serve {}: {e}", dir.display())))?;
    if !meta.is_dir() {
        return Err(bad(format!("{} is not a directory", dir.display())));
    }
    let _ = tokio::fs::read_dir(&root).await.map_err(|e| bad(format!("cannot read {}: {e}", dir.display())))?;
    if !allow_sensitive
        && let Some(what) = sensitive_root(&root)
    {
        return Err(bad(format!(
            "{} would publish {what}. Serve a folder inside it, or pass --allow-sensitive-root if you really mean this one",
            dir.display()
        )));
    }
    Ok(root)
}

/// Serves HTTP/1.1 on one data stream until the peer closes it.
pub async fn serve<S>(stream: S, site: Arc<Site>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req| {
        let site = site.clone();
        async move { Ok::<_, Infallible>(handle(&site, req).await) }
    });
    let conn = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(30))
        .serve_connection(TokioIo::new(stream), service);
    if let Err(e) = conn.await {
        tracing::debug!(error = %e, "static file connection ended");
    }
}

async fn handle(site: &Site, req: Request<Incoming>) -> Response<Body> {
    let method = req.method().clone();
    if method != Method::GET && method != Method::HEAD && method != Method::POST {
        return method_not_allowed();
    }
    let Some(segments) = parse_path(req.uri().path()) else { return not_found() };
    let requested: PathBuf = segments.iter().fold(site.root.clone(), |p, s| p.join(s));
    let Some(opened) = open(&site.root, requested).await else { return not_found() };
    let query = req.uri().query().unwrap_or("").to_string();
    if opened.meta.is_file() {
        if method == Method::POST {
            return method_not_allowed();
        }
        let name = segments.last().map(String::as_str).unwrap_or("");
        return file(&opened, name, has_flag(&query, "download"), site.scripts, req).await;
    }
    if !req.uri().path().ends_with('/') {
        // Built from the validated segments, never the raw path, so it cannot become `//host`.
        let mut location = encode_path(&segments);
        location.push('/');
        if !query.is_empty() {
            location.push('?');
            location.push_str(&query);
        }
        return redirect(&location);
    }
    if let Some(index) = open(&site.root, opened.path.join("index.html")).await
        && index.meta.is_file()
    {
        if method == Method::POST {
            return method_not_allowed();
        }
        return file(&index, "index.html", false, site.scripts, req).await;
    }
    if !site.list {
        return if method == Method::POST { method_not_allowed() } else { not_found() };
    }
    let site_name = site_name(&site.root);
    let folder = segments.last().cloned().unwrap_or(site_name.clone());
    if method == Method::POST {
        let names = match selection(req).await {
            Ok(n) if !n.is_empty() => n,
            Ok(_) => return text(StatusCode::BAD_REQUEST, "nothing selected\n"),
            Err((status, msg)) => return text(status, msg),
        };
        return archive_response(&site.root, opened.path, &folder, names);
    }
    let path = opened.path.clone();
    // Not an empty listing: that would say there's nothing here.
    let Ok((entries, omitted)) = read_entries(&site.root, opened).await else {
        return text(StatusCode::INTERNAL_SERVER_ERROR, "this folder can't be read right now\n");
    };
    if has_flag(&query, "archive") {
        let names = entries.into_iter().map(|e| e.name).collect();
        return archive_response(&site.root, path, &folder, names);
    }
    let nonce = magicpipes_core::secret::random_string(22);
    let html = listing::render(&Page { site: &site_name, segments: &segments, entries: &entries, omitted, nonce: &nonce });
    let mut resp = Response::new(full(html));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    let csp = format!(
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-{nonce}'; img-src 'self' data:; \
         form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    );
    if let Ok(v) = HeaderValue::from_str(&csp) {
        h.insert(header::CONTENT_SECURITY_POLICY, v);
    }
    resp
}

/// The name shown for the served directory (its folder name).
fn site_name(root: &Path) -> String {
    root.file_name().and_then(|n| n.to_str()).filter(|n| !n.is_empty()).unwrap_or("files").to_string()
}

/// Whether a query string contains `key` (with or without a value).
fn has_flag(query: &str, key: &str) -> bool {
    query.split('&').any(|p| p.split('=').next() == Some(key))
}

/// Reads the `f` fields of a posted selection form; the status and message for an error.
async fn selection(req: Request<Incoming>) -> Result<Vec<String>, (StatusCode, &'static str)> {
    let body = Limited::new(req.into_body(), MAX_FORM)
        .collect()
        .await
        .map_err(|_| (StatusCode::PAYLOAD_TOO_LARGE, "selection too large\n"))?
        .to_bytes();
    let body = std::str::from_utf8(&body).map_err(|_| (StatusCode::BAD_REQUEST, "invalid form\n"))?;
    parse_selection(body)
}

/// The distinct `f` fields of a selection form, in order.
fn parse_selection(body: &str) -> Result<Vec<String>, (StatusCode, &'static str)> {
    let (mut names, mut seen) = (Vec::new(), std::collections::HashSet::new());
    for pair in body.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k != "f" {
            continue;
        }
        match url::decode(&v.replace('+', " ")) {
            Some(name) if servable_name(&name) => {
                if seen.insert(name.clone()) {
                    names.push(name);
                }
            }
            _ => return Err((StatusCode::BAD_REQUEST, "invalid file name in selection\n")),
        }
        // A listing shows at most this many entries to pick from.
        if names.len() > MAX_LISTED {
            return Err((StatusCode::PAYLOAD_TOO_LARGE, "too many files selected\n"));
        }
    }
    Ok(names)
}

fn archive_response(root: &Path, dir: PathBuf, folder: &str, names: Vec<String>) -> Response<Body> {
    let Some(body) = archive::stream(root.to_path_buf(), dir, names) else {
        return text(StatusCode::SERVICE_UNAVAILABLE, "too many downloads in progress; try again shortly\n");
    };
    let body = body.boxed_unsync();
    let mut resp = Response::new(body);
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/gzip"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    if let Ok(v) = HeaderValue::from_str(&attachment(&format!("{folder}.tar.gz"))) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    resp
}

/// `Content-Disposition: attachment` with an ASCII fallback and the exact UTF-8 name.
fn attachment(name: &str) -> String {
    let ascii: String = name.chars().map(|c| if c.is_ascii_graphic() && c != '"' && c != '\\' || c == ' ' { c } else { '_' }).collect();
    format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{}", url::encode(name))
}

/// Servable entries of a directory, folders first, then by name. One blocking call for the whole
/// listing, instead of a hand-off to another thread for each file system call.
async fn read_entries(root: &Path, dir: Opened) -> std::io::Result<(Vec<Entry>, usize)> {
    let root = root.to_path_buf();
    tokio::task::spawn_blocking(move || list_entries(&root, &dir)).await.unwrap_or_else(|e| Err(std::io::Error::other(e)))
}

fn list_entries(root: &Path, dir: &Opened) -> std::io::Result<(Vec<Entry>, usize)> {
    let mut entries = Vec::new();
    let mut omitted = 0usize;
    let rd = dir.read_dir().inspect_err(|e| tracing::warn!(path = %dir.path.display(), error = %e, "could not list a served folder"))?;
    for e in rd.flatten() {
        let Ok(name) = e.file_name().into_string() else { continue };
        if !servable_name(&name) {
            continue;
        }
        // Only counted from here on, so a huge folder costs no more than the entries shown.
        if entries.len() == MAX_LISTED {
            omitted += 1;
            continue;
        }
        // Follow symlinks only when they stay inside the root, exactly like serving does.
        let Ok(real) = std::fs::canonicalize(dir.path.join(&name)) else { continue };
        if !servable_path(root, &real) {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&real) else { continue };
        if !meta.is_dir() && !meta.is_file() {
            continue;
        }
        let modified = meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64);
        entries.push(Entry { name, dir: meta.is_dir(), size: meta.len(), modified });
    }
    entries.sort_by(|a, b| b.dir.cmp(&a.dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    Ok((entries, omitted))
}

/// Splits and percent-decodes a request path; `None` if any segment is not servable.
fn parse_path(raw: &str) -> Option<Vec<String>> {
    raw.split('/').filter(|s| !s.is_empty()).map(|s| url::decode(s).filter(|s| servable_name(s))).collect()
}

/// Whether a single file name may be served or listed.
fn servable_name(name: &str) -> bool {
    let windows_special = cfg!(windows) && name.contains(':');
    !(name.is_empty() || name.starts_with('.') || name.contains(['/', '\\', '\0']) || windows_special)
}

fn encode_path(segments: &[String]) -> String {
    segments.iter().fold(String::new(), |mut p, s| {
        p.push('/');
        p.push_str(&url::encode(s));
        p
    })
}

/// A file or directory to serve, open. Its name may point elsewhere by now; the handle can't.
pub(super) struct Opened {
    /// The canonical path it was opened at.
    pub path: PathBuf,
    file: File,
    pub meta: Metadata,
}

impl Opened {
    /// A path to the open file or directory itself.
    fn handle(&self) -> PathBuf {
        crate::platform::handle_path(&self.file).unwrap_or_else(|| self.path.clone())
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    /// By path, not through the handle: on macOS 15 a directory reads as empty through `/dev/fd`.
    /// That's as safe, because whoever uses an entry opens it with [`open_servable`] or checks it
    /// with [`servable_path`], so a folder swapped for a link meanwhile can't show what's outside.
    pub fn read_dir(&self) -> std::io::Result<std::fs::ReadDir> {
        std::fs::read_dir(&self.path)
    }
}

/// Resolves `path` and opens what it leads to; `None` unless that is a regular file or directory,
/// inside the root and servable (see [`servable_path`]). Resolving first keeps symlinks inside the
/// root working; opening the real path follows nothing, so a component swapped for a symlink
/// since then makes the open fail, instead of leaving the root.
pub(super) fn open_servable(root: &Path, path: &Path) -> Option<Opened> {
    let real = std::fs::canonicalize(path).ok()?;
    if !servable_path(root, &real) {
        return None;
    }
    let file = crate::platform::open_beneath(root, real.strip_prefix(root).ok()?).ok()?;
    let meta = file.metadata().ok()?;
    (meta.is_file() || meta.is_dir()).then_some(Opened { path: real, file, meta })
}

async fn open(root: &Path, path: PathBuf) -> Option<Opened> {
    let root = root.to_path_buf();
    tokio::task::spawn_blocking(move || open_servable(&root, &path)).await.ok()?
}

/// Whether a canonical path lies inside `root` with every component servable. Checking the
/// resolved path, not just the requested one, keeps hidden entries hidden behind a symlink
/// (`notes.txt -> .env`) and behind Windows short names (`GIT~1` for `.git`).
fn servable_path(root: &Path, real: &Path) -> bool {
    real.strip_prefix(root).is_ok_and(|rel| {
        rel.components().all(|c| matches!(c, std::path::Component::Normal(n) if n.to_str().is_some_and(servable_name)))
    })
}

async fn file(opened: &Opened, name: &str, download: bool, scripts: bool, req: Request<Incoming>) -> Response<Body> {
    let mime = kinds::content_type(name);
    match ServeFile::new_with_mime(opened.handle(), &mime).try_call(req).await {
        Ok(resp) => {
            let mut resp = resp.map(|b| b.boxed_unsync());
            let h = resp.headers_mut();
            h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
            if !scripts && kinds::can_run_scripts(&mime) {
                h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(NO_SCRIPTS));
            }
            if download && let Ok(v) = HeaderValue::from_str(&attachment(name)) {
                h.insert(header::CONTENT_DISPOSITION, v);
            }
            resp
        }
        Err(e) => {
            tracing::warn!(path = %opened.path.display(), error = %e, "could not serve file");
            text(StatusCode::INTERNAL_SERVER_ERROR, "could not read file\n")
        }
    }
}

fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64 / 1024.0;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    format!("{v:.1} {}", UNITS[unit])
}

pub(super) fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

pub(super) fn full(body: impl Into<Bytes>) -> Body {
    Full::new(body.into()).map_err(|never| match never {}).boxed_unsync()
}

pub(super) fn text(status: StatusCode, body: &'static str) -> Response<Body> {
    let mut resp = Response::new(full(body));
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    resp
}

pub(super) fn method_not_allowed() -> Response<Body> {
    let mut resp = text(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n");
    resp.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
    resp
}

pub(super) fn not_found() -> Response<Body> {
    text(StatusCode::NOT_FOUND, "not found\n")
}

fn redirect(location: &str) -> Response<Body> {
    let mut resp = text(StatusCode::MOVED_PERMANENTLY, "moved\n");
    if let Ok(v) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_decoded_and_filtered() {
        assert_eq!(parse_path("/"), Some(vec![]));
        assert_eq!(parse_path("//a//b%20c/"), Some(vec!["a".into(), "b c".into()]));
        assert_eq!(parse_path("/caf%C3%A9.txt"), Some(vec!["café.txt".into()]));
        for bad in ["/..", "/a/../b", "/%2e%2e/x", "/.env", "/a/.git/config", "/a%2Fb", "/a%5Cb", "/a%00", "/%zz", "/%C3", "/%"] {
            assert_eq!(parse_path(bad), None, "{bad}");
        }
    }

    #[test]
    fn selections_are_distinct_and_bounded() {
        assert_eq!(parse_selection("f=a&x=1&f=b+c&f=a").unwrap(), ["a", "b c"]);
        assert!(parse_selection("f=.env").is_err());
        // About a megabyte of distinct names: refused at once rather than compared pairwise.
        let many: String = (0..140_000).map(|i| format!("f={i}&")).collect();
        let started = std::time::Instant::now();
        assert_eq!(parse_selection(&many).unwrap_err().0, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinks_to_hidden_entries_stay_hidden() {
        let dir = std::env::temp_dir().join(format!("mp-serve-{}", magicpipes_core::secret::random_string(8)));
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::write(dir.join(".env"), "secret").unwrap();
        std::fs::write(dir.join("ok.txt"), "fine").unwrap();
        std::os::unix::fs::symlink(".env", dir.join("notes.txt")).unwrap();
        std::os::unix::fs::symlink(".git", dir.join("repo")).unwrap();
        std::os::unix::fs::symlink("ok.txt", dir.join("alias.txt")).unwrap();
        let root = std::fs::canonicalize(&dir).unwrap();
        assert!(open_servable(&root, &root.join("ok.txt")).is_some());
        assert!(open_servable(&root, &root.join("alias.txt")).is_some());
        assert!(open_servable(&root, &root.join("notes.txt")).is_none());
        assert!(open_servable(&root, &root.join("repo")).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Someone who can write to the served folder flips a name between a file and a symlink while
    /// it is being requested. Whatever they manage, what gets read is never the outside file.
    #[cfg(unix)]
    #[test]
    fn swapping_in_a_symlink_never_leaves_the_root() {
        use std::os::unix::fs::symlink;
        use std::sync::atomic::{AtomicBool, Ordering};

        let dir = std::env::temp_dir().join(format!("mp-serve-{}", magicpipes_core::secret::random_string(8)));
        let site = dir.join("site");
        std::fs::create_dir_all(site.join("sub")).unwrap();
        std::fs::write(dir.join("secret.txt"), "SECRET").unwrap();
        let root = std::fs::canonicalize(&site).unwrap();
        let (real_file, real_sub) = (root.join("a.txt"), root.join("sub"));
        std::fs::write(&real_file, "fine").unwrap();
        std::fs::write(real_sub.join("b.txt"), "fine").unwrap();
        let outside = std::fs::canonicalize(&dir).unwrap();
        std::fs::create_dir_all(outside.join("elsewhere")).unwrap();
        std::fs::write(outside.join("elsewhere/b.txt"), "SECRET").unwrap();
        std::fs::write(outside.join("elsewhere/only-outside.txt"), "SECRET").unwrap();

        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let swapper = {
            let (stop, real_file, real_sub, outside) = (stop.clone(), real_file.clone(), real_sub.clone(), outside.clone());
            std::thread::spawn(move || {
                let (file2, sub2) = (real_file.with_extension("new"), real_sub.with_extension("new"));
                let (keep_file, keep_sub) = (real_file.with_extension("keep"), real_sub.with_extension("keep"));
                while !stop.load(Ordering::Relaxed) {
                    // Swap a file for a link out, and a directory on the path for a link out.
                    symlink(outside.join("secret.txt"), &file2).unwrap();
                    std::fs::rename(&real_file, &keep_file).unwrap();
                    std::fs::rename(&file2, &real_file).unwrap();
                    symlink(outside.join("elsewhere"), &sub2).unwrap();
                    std::fs::rename(&real_sub, &keep_sub).unwrap();
                    std::fs::rename(&sub2, &real_sub).unwrap();
                    std::thread::yield_now();
                    std::fs::remove_file(&real_file).unwrap();
                    std::fs::rename(&keep_file, &real_file).unwrap();
                    std::fs::remove_file(&real_sub).unwrap();
                    std::fs::rename(&keep_sub, &real_sub).unwrap();
                    std::thread::yield_now();
                }
            })
        };
        let (mut served, mut listed, mut archived) = (0, 0, 0);
        for i in 0..4000 {
            let path = if i % 2 == 0 { real_file.clone() } else { real_sub.join("b.txt") };
            if let Some(opened) = open_servable(&root, &path)
                && let Ok(body) = std::fs::read_to_string(opened.handle())
            {
                assert_ne!(body, "SECRET", "read a file outside the root through {}", path.display());
                served += 1;
            }
            // A folder's listing and its download read it by path, and check every entry.
            if i % 16 == 0 {
                if let Some(opened) = open_servable(&root, &real_sub)
                    && let Ok((entries, _)) = list_entries(&root, &opened)
                {
                    assert!(entries.iter().all(|e| e.name != "only-outside.txt"), "listed a file outside the root");
                    listed += 1;
                }
                let mut tar = tar::Builder::new(Vec::new());
                // It may stop when a name changes under it, which ends the download. It's what got
                // in before that counts.
                archived += usize::from(archive::add(&mut tar, &root, &real_sub, Path::new("sub")).is_ok());
                let bytes = tar.into_inner().unwrap();
                let contains = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
                assert!(!contains(b"only-outside.txt") && !contains(b"SECRET"), "archived a file outside the root");
            }
        }
        stop.store(true, Ordering::Relaxed);
        swapper.join().unwrap();
        assert!(served > 0 && listed > 0 && archived > 0, "the checks don't simply refuse everything");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A folder is read by its path, so it can be swapped for a link between being opened and being
    /// listed. Each entry's own check is what keeps that from showing anything outside.
    #[cfg(unix)]
    #[test]
    fn a_folder_swapped_for_a_link_lists_nothing_from_outside() {
        let dir = std::env::temp_dir().join(format!("mp-serve-{}", magicpipes_core::secret::random_string(8)));
        let site = dir.join("site");
        std::fs::create_dir_all(site.join("sub")).unwrap();
        std::fs::create_dir_all(dir.join("elsewhere")).unwrap();
        std::fs::write(dir.join("elsewhere/only-outside.txt"), "SECRET").unwrap();
        let (root, outside) = (std::fs::canonicalize(&site).unwrap(), std::fs::canonicalize(dir.join("elsewhere")).unwrap());
        let opened = open_servable(&root, &root.join("sub")).unwrap();

        std::fs::rename(root.join("sub"), root.join("was-sub")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("sub")).unwrap();

        let (entries, omitted) = list_entries(&root, &opened).unwrap();
        assert!(entries.is_empty() && omitted == 0, "{:?}", entries.iter().map(|e| &e.name).collect::<Vec<_>>());
        std::fs::remove_dir_all(dir).ok();
    }

    /// Not on Windows, where an open folder can't be removed.
    #[cfg(unix)]
    #[test]
    fn a_folder_that_cant_be_read_doesnt_look_empty() {
        let dir = std::env::temp_dir().join(format!("mp-serve-{}", magicpipes_core::secret::random_string(8)));
        let site = dir.join("site");
        std::fs::create_dir_all(site.join("sub")).unwrap();
        let root = std::fs::canonicalize(&site).unwrap();
        let opened = open_servable(&root, &root.join("sub")).unwrap();
        // Gone since it was opened: nothing can be said about what's in it.
        std::fs::remove_dir(root.join("sub")).unwrap();
        assert!(list_entries(&root, &opened).is_err(), "this mustn't read as a folder with nothing in it");
        std::fs::remove_dir_all(dir).ok();
    }

    /// A FIFO in a served folder neither blocks the server nor gets served.
    #[cfg(unix)]
    #[test]
    fn only_files_and_directories_are_opened() {
        let dir = std::env::temp_dir().join(format!("mp-serve-{}", magicpipes_core::secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let root = std::fs::canonicalize(&dir).unwrap();
        let fifo = std::ffi::CString::new(root.join("pipe").to_str().unwrap()).unwrap();
        // SAFETY: a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(open_servable(&root, &root.join("pipe")).is_none());
        assert!(open_servable(&root, &root).is_some_and(|o| o.meta.is_dir()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn folders_nobody_means_to_publish_are_recognized() {
        assert!(sensitive_root(Path::new("/")).is_some());
        let state = std::fs::canonicalize(crate::state::home()).unwrap_or_else(|_| crate::state::home());
        assert!(sensitive_root(&state).is_some(), "the agent's own state");
        assert!(sensitive_root(&state.join("inside")).is_some());
        if let Some(home) = std::env::var_os("HOME").and_then(|h| std::fs::canonicalize(h).ok()) {
            assert!(sensitive_root(&home).is_some());
            assert!(sensitive_root(&home.join(".ssh")).is_some());
            assert!(sensitive_root(&home.join(".config/app")).is_some());
            assert_eq!(sensitive_root(&home.join("project/dist")), None);
        }
    }

    #[test]
    fn encoding_round_trips() {
        let name = "a b&c/é?#%.txt";
        assert_eq!(url::decode(&url::encode(name)).as_deref(), Some(name));
        assert_eq!(encode_path(&["x y".into(), "z".into()]), "/x%20y/z");
    }

    #[test]
    fn sizes_and_escaping() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1536), "1.5 KiB");
        assert_eq!(human_size(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(esc(r#"<a href="x">'&"#), "&lt;a href=&quot;x&quot;&gt;&#39;&amp;");
    }
}
