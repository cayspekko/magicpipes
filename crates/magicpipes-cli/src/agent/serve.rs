//! Built-in static file server for `magicpipes add --serve <dir>`.
//!
//! It runs inside the agent: each data stream of a static tunnel is served directly by hyper, so
//! no local port is opened. tower-http's `ServeFile` produces the file responses (content type,
//! `Range`, `Last-Modified`/`If-Modified-Since`, `HEAD`); this module decides *which* file, and is
//! strict about it because the directory is exposed to the internet:
//!
//! - GET and HEAD only; nothing is ever written.
//! - Hidden entries (names starting with `.`) are neither listed nor served.
//! - The path is decoded segment by segment; `.`/`..`, backslashes, NUL and (on Windows) `:` are
//!   refused, and the canonical result must lie inside the canonical root, so symlinks that point
//!   outside the root are refused (and not listed).
//! - Directory listing can be turned off; a directory's `index.html` is served either way.

use std::convert::Infallible;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response, StatusCode, header};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tower_http::services::ServeFile;

use crate::ipc::ErrorInfo;

type Body = UnsyncBoxBody<Bytes, std::io::Error>;

/// Entries beyond this are left out of a listing (and counted in a note).
const MAX_LISTED: usize = 5000;

pub struct Site {
    /// Canonical path of the served directory.
    pub root: PathBuf,
    pub list: bool,
}

/// Validates a directory for `--serve` and returns its canonical path.
pub async fn check_root(dir: &Path) -> Result<PathBuf, ErrorInfo> {
    let bad = |m: String| ErrorInfo::new("invalid_directory", m);
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
    if req.method() != Method::GET && req.method() != Method::HEAD {
        let mut resp = text(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n");
        resp.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return resp;
    }
    let Some(segments) = parse_path(req.uri().path()) else { return not_found() };
    let requested: PathBuf = segments.iter().fold(site.root.clone(), |p, s| p.join(s));
    let Some(path) = contain(&site.root, &requested).await else { return not_found() };
    let Ok(meta) = tokio::fs::metadata(&path).await else { return not_found() };
    if meta.is_file() {
        return file(&path, req).await;
    }
    if !meta.is_dir() {
        return not_found();
    }
    if !req.uri().path().ends_with('/') {
        // Built from the validated segments, never the raw path, so it cannot become `//host`.
        let mut location = encode_path(&segments);
        location.push('/');
        if let Some(q) = req.uri().query() {
            location.push('?');
            location.push_str(q);
        }
        return redirect(&location);
    }
    if let Some(index) = contain(&site.root, &path.join("index.html")).await
        && tokio::fs::metadata(&index).await.is_ok_and(|m| m.is_file())
    {
        return file(&index, req).await;
    }
    if site.list {
        return listing(&site.root, &path, &segments).await;
    }
    not_found()
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

/// Resolves symlinks; `None` unless the result exists and lies inside `root`.
async fn contain(root: &Path, path: &Path) -> Option<PathBuf> {
    let real = tokio::fs::canonicalize(path).await.ok()?;
    real.starts_with(root).then_some(real)
}

async fn file(path: &Path, req: Request<Incoming>) -> Response<Body> {
    match ServeFile::new(path).try_call(req).await {
        Ok(resp) => {
            let mut resp = resp.map(|b| b.boxed_unsync());
            resp.headers_mut().insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
            resp
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "could not serve file");
            text(StatusCode::INTERNAL_SERVER_ERROR, "could not read file\n")
        }
    }
}

struct Entry {
    name: String,
    dir: bool,
    size: u64,
    modified: Option<i64>,
}

async fn listing(root: &Path, dir: &Path, segments: &[String]) -> Response<Body> {
    let Ok(mut rd) = tokio::fs::read_dir(dir).await else { return not_found() };
    let mut entries = Vec::new();
    let mut omitted = 0usize;
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

    let title = format!("{}/", encode_display(segments));
    let mut rows = String::new();
    if !segments.is_empty() {
        rows.push_str(r#"<tr><td><a href="../">../</a></td><td></td><td></td></tr>"#);
    }
    for e in &entries {
        let slash = if e.dir { "/" } else { "" };
        let size = if e.dir { String::new() } else { human_size(e.size) };
        let modified = e.modified.map(|m| magicpipes_core::rfc3339(m).replace('T', " ")).unwrap_or_default();
        let _ = write!(
            rows,
            r#"<tr><td><a href="{href}{slash}">{name}{slash}</a></td><td class="num">{size}</td><td>{modified}</td></tr>"#,
            href = percent_encode(&e.name),
            name = esc(&e.name),
        );
    }
    let note = if omitted > 0 { format!("<p>{omitted} more entries not shown.</p>") } else { String::new() };
    let html = format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Index of {title}</title>
<style>
:root {{ color-scheme: light dark; --fg: #1d1d1f; --muted: #6e6e73; --line: #e5e5ea; --bg: #fff; --link: #0057b8; }}
@media (prefers-color-scheme: dark) {{ :root {{ --fg: #f2f2f7; --muted: #98989d; --line: #2c2c2e; --bg: #111; --link: #6cb4ff; }} }}
body {{ margin: 0; padding: 24px 16px; background: var(--bg); color: var(--fg); font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }}
main {{ max-width: 960px; margin: 0 auto; }}
h1 {{ font-size: 18px; font-weight: 600; margin: 0 0 16px; word-break: break-all; }}
table {{ width: 100%; border-collapse: collapse; }}
td {{ padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }}
td:first-child {{ word-break: break-all; }}
td:not(:first-child) {{ color: var(--muted); white-space: nowrap; font-variant-numeric: tabular-nums; }}
.num {{ text-align: right; }}
a {{ color: var(--link); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
footer {{ margin-top: 16px; color: var(--muted); font-size: 13px; }}
</style></head>
<body><main><h1>Index of {title}</h1><table>{rows}</table>{note}<footer>Served by MagicPipes</footer></main></body></html>
"#
    );
    let mut resp = Response::new(full(html));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'"));
    resp
}

fn encode_display(segments: &[String]) -> String {
    segments.iter().fold(String::new(), |mut p, s| {
        p.push('/');
        p.push_str(&esc(s));
        p
    })
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

fn esc(s: &str) -> String {
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

fn full(body: impl Into<Bytes>) -> Body {
    Full::new(body.into()).map_err(|never| match never {}).boxed_unsync()
}

fn text(status: StatusCode, body: &'static str) -> Response<Body> {
    let mut resp = Response::new(full(body));
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    resp
}

fn not_found() -> Response<Body> {
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
