//! Web terminal for `magicpipes add --shell [-- program args...]`, in the spirit of ttyd.
//!
//! Like `--serve`, it runs inside the agent: each data stream of a shell tunnel is served by
//! hyper, so no local port is opened. `GET /` is the terminal page (xterm.js, vendored under
//! `assets/`), which opens a WebSocket on `/ws`. Every WebSocket session starts its own copy of
//! the command in a new pty (portable-pty; ConPTY on Windows), and the copy is killed when the
//! session ends.
//!
//! Access, enforced here rather than in the page:
//! - Read-only by default: input from the browser is dropped. Resizing is allowed, since every
//!   viewer has their own copy of the program.
//! - A writable tunnel (`--write`) has a secret key, which the CLI prints in the URL fragment
//!   (`#k=…`). Browsers never send fragments in requests, so the key only reaches the agent
//!   inside the WebSocket. Every session must present it; without it nothing is started.
//! - Cross-origin WebSockets are refused (`Origin` must match `Host`).
//! - At most `max_clients` sessions at once. Removing the tunnel, or re-adding it with other
//!   settings, ends its sessions.
//!
//! * `page` — the terminal page.
//! * `session` — one WebSocket session and its pty.

mod page;
mod session;

pub use session::KILL_GRACE;

use std::convert::Infallible;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use flate2::Compression;
use flate2::write::GzEncoder;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, header};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use tokio_util::sync::CancellationToken;

use super::serve::{Body, full, method_not_allowed, not_found, text};
use crate::ipc::ErrorInfo;

/// Largest message accepted from the browser (input or control).
const MAX_MESSAGE: usize = 1024 * 1024;
pub const DEFAULT_MAX_CLIENTS: u16 = 5;

/// Validates a `--shell` command before the tunnel is registered: the working directory exists
/// and the program can be found (on the agent's `PATH`, as it will be run).
pub fn check(command: &[String], cwd: &Path) -> Result<(), ErrorInfo> {
    let Some(program) = command.first().filter(|p| !p.is_empty()) else {
        return Err(ErrorInfo::new("invalid_command", "no program given"));
    };
    if !cwd.is_dir() {
        return Err(ErrorInfo::new("invalid_command", format!("working directory {} does not exist", cwd.display())));
    }
    if find_program(program, cwd).is_none() {
        return Err(ErrorInfo::new("invalid_command", format!("program '{program}' was not found on the PATH")));
    }
    Ok(())
}

fn find_program(program: &str, cwd: &Path) -> Option<PathBuf> {
    let exts: Vec<String> = if cfg!(windows) {
        let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
        std::iter::once(String::new()).chain(pathext.split(';').filter(|e| !e.is_empty()).map(str::to_string)).collect()
    } else {
        vec![String::new()]
    };
    let candidates = |base: PathBuf| exts.iter().map(move |e| PathBuf::from(format!("{}{e}", base.display())));
    if program.contains('/') || (cfg!(windows) && program.contains('\\')) {
        return candidates(cwd.join(program)).find(|p| p.is_file());
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).flat_map(|dir| candidates(dir.join(program))).find(|p| p.is_file())
}

pub struct Terminal {
    /// argv of the program each session runs.
    pub command: Vec<String>,
    pub cwd: PathBuf,
    /// Present only for writable tunnels: sessions that present it may type.
    pub key: Option<String>,
    pub max_clients: u16,
    /// Open sessions of this tunnel.
    pub sessions: Arc<AtomicUsize>,
    /// Cancelled when the tunnel is removed or re-added with other settings.
    pub ended: CancellationToken,
}

impl Terminal {
    /// Short name for titles: the program's file name.
    fn program(&self) -> String {
        crate::state::program_name(&self.command)
    }
}

/// Serves HTTP/1.1 (with WebSocket upgrades) on one data stream until the peer closes it.
pub async fn serve<S>(stream: S, term: Arc<Terminal>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req| {
        let term = term.clone();
        async move { Ok::<_, Infallible>(handle(term, req)) }
    });
    let conn = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(30))
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades();
    if let Err(e) = conn.await {
        tracing::debug!(error = %e, "web terminal connection ended");
    }
}

fn handle(term: Arc<Terminal>, req: Request<Incoming>) -> Response<Body> {
    let path = req.uri().path();
    if path == "/ws" {
        return upgrade(term, req);
    }
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return method_not_allowed();
    }
    match path {
        "/" => page_response(&term),
        "/assets/xterm.mjs" => asset(&req, &XTERM_JS, "text/javascript; charset=utf-8"),
        "/assets/addon-fit.mjs" => asset(&req, &FIT_JS, "text/javascript; charset=utf-8"),
        "/assets/addon-unicode11.mjs" => asset(&req, &UNICODE11_JS, "text/javascript; charset=utf-8"),
        "/assets/xterm.css" => asset(&req, &XTERM_CSS, "text/css; charset=utf-8"),
        "/assets/symbols-nerd-font-mono.woff2" => asset(&req, &SYMBOLS_FONT, "font/woff2"),
        _ => not_found(),
    }
}

fn page_response(term: &Terminal) -> Response<Body> {
    let nonce = magicpipes_core::secret::random_string(22);
    let html = page::render(&page::Page {
        program: &term.program(),
        // Anyone with the link sees this page, key or not: arguments may hold secrets.
        command: &term.program(),
        needs_key: term.key.is_some(),
        nonce: &nonce,
    });
    let mut resp = Response::new(full(html));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    // 'self' covers the vendored modules the inline module imports.
    let csp = format!(
        "default-src 'none'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; font-src 'self'; \
         connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    );
    if let Ok(v) = HeaderValue::from_str(&csp) {
        h.insert(header::CONTENT_SECURITY_POLICY, v);
    }
    resp
}

/// A vendored file. Text is gzip-compressed once on first use; fonts (WOFF2) already are.
struct Asset {
    raw: &'static [u8],
    compress: bool,
    gzip: OnceLock<Bytes>,
}

impl Asset {
    const fn new(raw: &'static [u8]) -> Self {
        Self { raw, compress: true, gzip: OnceLock::new() }
    }

    const fn compressed(raw: &'static [u8]) -> Self {
        Self { raw, compress: false, gzip: OnceLock::new() }
    }

    fn gzip(&self) -> Bytes {
        self.gzip
            .get_or_init(|| {
                let mut enc = GzEncoder::new(Vec::new(), Compression::best());
                let _ = enc.write_all(self.raw);
                enc.finish().map(Bytes::from).unwrap_or_default()
            })
            .clone()
    }
}

static XTERM_JS: Asset = Asset::new(include_bytes!("assets/xterm.mjs"));
static FIT_JS: Asset = Asset::new(include_bytes!("assets/addon-fit.mjs"));
static UNICODE11_JS: Asset = Asset::new(include_bytes!("assets/addon-unicode11.mjs"));
static XTERM_CSS: Asset = Asset::new(include_bytes!("assets/xterm.css"));
/// Nerd Font icons (private-use code points), a fallback after the viewer's own monospace font.
static SYMBOLS_FONT: Asset = Asset::compressed(include_bytes!("assets/symbols-nerd-font-mono.woff2"));

fn asset(req: &Request<Incoming>, asset: &Asset, content_type: &'static str) -> Response<Body> {
    let gzip = asset.compress && accepts_gzip(req.headers());
    let body = if gzip { asset.gzip() } else { Bytes::from_static(asset.raw) };
    let mut resp = Response::new(full(if req.method() == Method::HEAD { Bytes::new() } else { body.clone() }));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=86400"));
    h.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    if gzip {
        h.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    }
    resp
}

fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|e| {
            let mut parts = e.split(';');
            let name = parts.next().unwrap_or("").trim();
            let q = parts.find_map(|p| p.trim().strip_prefix("q=")).and_then(|q| q.trim().parse::<f32>().ok()).unwrap_or(1.0);
            name.eq_ignore_ascii_case("gzip") && q > 0.0
        })
}

/// Answers the WebSocket handshake and runs the session on the upgraded connection.
fn upgrade(term: Arc<Terminal>, mut req: Request<Incoming>) -> Response<Body> {
    let h = req.headers();
    let token = |name: header::HeaderName, want: &str| {
        h.get_all(name).iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(',')).any(|t| t.trim().eq_ignore_ascii_case(want))
    };
    let websocket = req.method() == Method::GET
        && token(header::UPGRADE, "websocket")
        && token(header::CONNECTION, "upgrade")
        && h.get(header::SEC_WEBSOCKET_VERSION).is_some_and(|v| v == "13");
    let Some(key) = h.get(header::SEC_WEBSOCKET_KEY).filter(|_| websocket) else {
        return text(StatusCode::BAD_REQUEST, "expected a WebSocket upgrade\n");
    };
    if !same_origin(h) {
        return text(StatusCode::FORBIDDEN, "cross-origin WebSocket refused\n");
    }
    let accept = derive_accept_key(key.as_bytes());
    // The whole chain: with a proxy in front of magicpipesd the visitor is not the last hop.
    let peer = h.get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let on_upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                let config = WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE)).max_frame_size(Some(MAX_MESSAGE));
                let ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, Some(config)).await;
                session::run(ws, term, peer).await;
            }
            Err(e) => tracing::debug!(error = %e, "web terminal upgrade failed"),
        }
    });
    let mut resp = Response::new(full(Bytes::new()));
    *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    let h = resp.headers_mut();
    h.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    h.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    if let Ok(v) = HeaderValue::from_str(&accept) {
        h.insert(header::SEC_WEBSOCKET_ACCEPT, v);
    }
    resp
}

/// Whether a browser's `Origin` is exactly this page's origin: `https`, the same host and the
/// same port (tunnels are always served over HTTPS, so another scheme or port, such as a port
/// tunnel on the same hostname, is another origin). Requests without `Origin` are not from a
/// browser page and cannot ride on a visitor's session, so they pass.
fn same_origin(h: &HeaderMap) -> bool {
    let Some(origin) = h.get(header::ORIGIN) else { return true };
    // `host[:port]`, lowercase, with the default HTTPS port dropped.
    let authority = |v: &str| {
        let v = v.trim().to_ascii_lowercase();
        v.strip_suffix(":443").map(str::to_string).unwrap_or(v)
    };
    let origin = origin.to_str().ok().and_then(|o| o.strip_prefix("https://")).filter(|a| !a.is_empty() && !a.contains('/')).map(authority);
    let target = h.get(header::HOST).and_then(|v| v.to_str().ok()).map(authority);
    matches!((origin, target), (Some(o), Some(t)) if o == t)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn origins() {
        assert!(same_origin(&headers(&[("host", "dev.example.com")])));
        assert!(same_origin(&headers(&[("host", "dev.example.com"), ("origin", "https://dev.example.com")])));
        assert!(same_origin(&headers(&[("host", "dev.example.com:443"), ("origin", "https://DEV.example.com")])));
        assert!(!same_origin(&headers(&[("host", "dev.example.com"), ("origin", "https://evil.example")])));
        assert!(!same_origin(&headers(&[("host", "dev.example.com"), ("origin", "null")])));
        assert!(!same_origin(&headers(&[("origin", "https://dev.example.com")])));
        assert!(same_origin(&headers(&[("host", "dev.example.com:8443"), ("origin", "https://dev.example.com:8443")])));
        assert!(!same_origin(&headers(&[("host", "dev.example.com"), ("origin", "http://dev.example.com")])), "scheme");
        assert!(!same_origin(&headers(&[("host", "dev.example.com"), ("origin", "https://dev.example.com:65500")])), "port");
        assert!(!same_origin(&headers(&[("host", "dev.example.com:8443"), ("origin", "https://dev.example.com")])), "port");
    }

    #[test]
    fn gzip_negotiation() {
        assert!(accepts_gzip(&headers(&[("accept-encoding", "gzip, deflate, br")])));
        assert!(accepts_gzip(&headers(&[("accept-encoding", "br;q=1.0, gzip;q=0.8")])));
        assert!(!accepts_gzip(&headers(&[("accept-encoding", "gzip;q=0")])));
        assert!(!accepts_gzip(&headers(&[("accept-encoding", "br")])));
        assert!(!accepts_gzip(&headers(&[])));
    }

    #[test]
    fn program_names() {
        let term = |argv: &[&str]| Terminal {
            command: argv.iter().map(|s| s.to_string()).collect(),
            cwd: PathBuf::new(),
            key: None,
            max_clients: 1,
            sessions: Arc::default(),
            ended: CancellationToken::new(),
        };
        assert_eq!(term(&["/bin/zsh", "-l"]).program(), "zsh");
        assert_eq!(term(&[r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"]).program(), "powershell.exe");
        assert_eq!(term(&["htop"]).program(), "htop");
    }
}
