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
//!   outside the root are refused (and not listed).
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
use std::fmt::Write as _;
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
use tokio::io::{AsyncRead, AsyncWrite};
use tower_http::services::ServeFile;

use listing::{Entry, Page};

use crate::ipc::ErrorInfo;

pub(super) type Body = UnsyncBoxBody<Bytes, std::io::Error>;

/// Entries beyond this are left out of a listing (and counted in a note).
const MAX_LISTED: usize = 5000;
/// Largest accepted selection form (names of the entries to archive).
const MAX_FORM: usize = 1024 * 1024;

pub struct Site {
    /// Canonical path of the served directory.
    pub root: PathBuf,
    pub list: bool,
}

/// Validates a directory for `--serve` and returns its canonical path.
pub async fn check_root(dir: &Path) -> Result<PathBuf, ErrorInfo> {
    let bad = |m: String| ErrorInfo::new(ErrorCode::InvalidDirectory, m);
    let root = tokio::fs::canonicalize(dir).await.map_err(|e| bad(format!("cannot serve {}: {e}", dir.display())))?;
    let meta = tokio::fs::metadata(&root).await.map_err(|e| bad(format!("cannot serve {}: {e}", dir.display())))?;
    if !meta.is_dir() {
        return Err(bad(format!("{} is not a directory", dir.display())));
    }
    let _ = tokio::fs::read_dir(&root).await.map_err(|e| bad(format!("cannot read {}: {e}", dir.display())))?;
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
    let Some(path) = contain(&site.root, &requested).await else { return not_found() };
    let Ok(meta) = tokio::fs::metadata(&path).await else { return not_found() };
    let query = req.uri().query().unwrap_or("").to_string();
    if meta.is_file() {
        if method == Method::POST {
            return method_not_allowed();
        }
        let name = segments.last().map(String::as_str).unwrap_or("");
        return file(&path, name, has_flag(&query, "download"), req).await;
    }
    if !meta.is_dir() {
        return not_found();
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
    if let Some(index) = contain(&site.root, &path.join("index.html")).await
        && tokio::fs::metadata(&index).await.is_ok_and(|m| m.is_file())
    {
        if method == Method::POST {
            return method_not_allowed();
        }
        return file(&index, "index.html", false, req).await;
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
            Err(resp) => return resp,
        };
        return archive_response(&site.root, path, &folder, names);
    }
    if has_flag(&query, "archive") {
        let names = read_entries(&site.root, &path).await.0.into_iter().map(|e| e.name).collect();
        return archive_response(&site.root, path, &folder, names);
    }
    let (entries, omitted) = read_entries(&site.root, &path).await;
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

/// Reads the `f` fields of a posted selection form.
async fn selection(req: Request<Incoming>) -> Result<Vec<String>, Response<Body>> {
    let body = Limited::new(req.into_body(), MAX_FORM)
        .collect()
        .await
        .map_err(|_| text(StatusCode::PAYLOAD_TOO_LARGE, "selection too large\n"))?
        .to_bytes();
    let body = std::str::from_utf8(&body).map_err(|_| text(StatusCode::BAD_REQUEST, "invalid form\n"))?;
    let mut names = Vec::new();
    for pair in body.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k != "f" {
            continue;
        }
        match percent_decode(&v.replace('+', " ")) {
            Some(name) if servable_name(&name) => {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
            _ => return Err(text(StatusCode::BAD_REQUEST, "invalid file name in selection\n")),
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
    format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{}", percent_encode(name))
}

/// Servable entries of a directory, folders first, then by name.
async fn read_entries(root: &Path, dir: &Path) -> (Vec<Entry>, usize) {
    let mut entries = Vec::new();
    let mut omitted = 0usize;
    let Ok(mut rd) = tokio::fs::read_dir(dir).await else { return (entries, 0) };
    while let Ok(Some(e)) = rd.next_entry().await {
        let Ok(name) = e.file_name().into_string() else { continue };
        if !servable_name(&name) {
            continue;
        }
        // Follow symlinks only when they stay inside the root, exactly like serving does.
        let Some(real) = contain(root, &e.path()).await else { continue };
        let Ok(meta) = tokio::fs::metadata(&real).await else { continue };
        if !meta.is_dir() && !meta.is_file() {
            continue;
        }
        if entries.len() == MAX_LISTED {
            omitted += 1;
            continue;
        }
        let modified = meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64);
        entries.push(Entry { name, dir: meta.is_dir(), size: meta.len(), modified });
    }
    entries.sort_by(|a, b| b.dir.cmp(&a.dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    (entries, omitted)
}

/// Splits and percent-decodes a request path; `None` if any segment is not servable.
fn parse_path(raw: &str) -> Option<Vec<String>> {
    raw.split('/').filter(|s| !s.is_empty()).map(|s| percent_decode(s).filter(|s| servable_name(s))).collect()
}

/// Whether a single file name may be served or listed.
fn servable_name(name: &str) -> bool {
    let windows_special = cfg!(windows) && name.contains(':');
    !(name.is_empty() || name.starts_with('.') || name.contains(['/', '\\', '\0']) || windows_special)
}

fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn encode_path(segments: &[String]) -> String {
    segments.iter().fold(String::new(), |mut p, s| {
        p.push('/');
        p.push_str(&percent_encode(s));
        p
    })
}

/// Resolves symlinks; `None` unless the result exists and is servable (see [`servable_path`]).
async fn contain(root: &Path, path: &Path) -> Option<PathBuf> {
    let real = tokio::fs::canonicalize(path).await.ok()?;
    servable_path(root, &real).then_some(real)
}

/// Whether a canonical path lies inside `root` with every component servable. Checking the
/// resolved path, not just the requested one, keeps hidden entries hidden behind a symlink
/// (`notes.txt -> .env`) and behind Windows short names (`GIT~1` for `.git`).
fn servable_path(root: &Path, real: &Path) -> bool {
    real.strip_prefix(root).is_ok_and(|rel| {
        rel.components().all(|c| matches!(c, std::path::Component::Normal(n) if n.to_str().is_some_and(servable_name)))
    })
}

async fn file(path: &Path, name: &str, download: bool, req: Request<Incoming>) -> Response<Body> {
    match ServeFile::new_with_mime(path, &kinds::content_type(name)).try_call(req).await {
        Ok(resp) => {
            let mut resp = resp.map(|b| b.boxed_unsync());
            let h = resp.headers_mut();
            h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
            if download && let Ok(v) = HeaderValue::from_str(&attachment(name)) {
                h.insert(header::CONTENT_DISPOSITION, v);
            }
            resp
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "could not serve file");
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
        assert!(contain(&root, &root.join("ok.txt")).await.is_some());
        assert!(contain(&root, &root.join("alias.txt")).await.is_some());
        assert!(contain(&root, &root.join("notes.txt")).await.is_none());
        assert!(contain(&root, &root.join("repo")).await.is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn encoding_round_trips() {
        let name = "a b&c/é?#%.txt";
        assert_eq!(percent_decode(&percent_encode(name)).as_deref(), Some(name));
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
