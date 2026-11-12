//! `magicpipes probe`: checks the public address of each tunnel you manage from this computer, the
//! way a visitor reaches it, and tells the server (`POST /api/v1/probes`). Run from outside the
//! server's network, it sees what the server's own checks can't: DNS, firewalls, a proxy in front,
//! and the certificate visitors get. Two failures in a row open an "Unreachable from outside" alert.
//!
//! An HTTP tunnel gets `GET <check path>` at its address, and any answer counts, as with the
//! server's checks: a private tunnel's way to sign in is an answer. A TCP port counts once it
//! connects. Other tunnels are reached through the management address or the SSH gateway, not an
//! address of their own, and tunnels with checks off (`add --no-check`) are left alone. One pass a
//! run: schedule it.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::StreamExt;
use http::{Method, Request, Uri, header};
use http_body_util::Full;
use magicpipes_core::error::ErrorCode;
use rustls::ClientConfig;
use serde::Serialize;
use serde_json::{Value, json};

use crate::connect::error_from;
use crate::https;
use crate::ipc::ErrorInfo;
use crate::state::AgentConfig;

/// Tunnels checked at once.
const AT_ONCE: usize = 16;
/// All of one check.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// Results in one report; the server takes up to 200.
const REPORT_BATCH: usize = 100;
/// The list of tunnels, a few hundred bytes each.
const MAX_LIST: usize = 8 * 1024 * 1024;

pub struct Options {
    pub tunnels: Vec<String>,
    pub server: Option<String>,
    pub ca_cert: Option<PathBuf>,
    pub api_token: Option<String>,
    pub no_report: bool,
    pub json: bool,
    pub quiet: bool,
}

/// A tunnel to check, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    id: String,
    name: String,
    /// What's shown: the address, with the path checked.
    url: String,
    how: How,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum How {
    Http { host: String, port: u16, path: String },
    Tcp { host: String, port: u16 },
}

#[derive(Debug, Serialize)]
struct Found {
    tunnel_id: String,
    name: String,
    url: String,
    ok: bool,
    /// What answered, or what went wrong.
    said: String,
}

/// How a run went: `Ok(true)` when every check passed.
pub async fn run(o: Options) -> Result<bool, ErrorInfo> {
    let config = |e: String| ErrorInfo::new(ErrorCode::ConfigError, e);
    let enrolled = AgentConfig::load().map_err(|e| config(format!("{e:#}")))?;
    let server = match (&o.server, &enrolled) {
        (Some(s), _) => s.trim().trim_end_matches('/').to_string(),
        (None, Some(c)) => c.server.clone(),
        (None, None) => return Err(ErrorInfo::new(ErrorCode::NotLoggedIn, "say which server with --server https://<server>")),
    };
    https::parse_server(&server).map_err(|e| ErrorInfo::new(ErrorCode::InvalidServer, e.to_string()))?;
    let ca_pem = match &o.ca_cert {
        Some(p) => Some(std::fs::read_to_string(p).map_err(|e| config(format!("reading {}: {e}", p.display())))?),
        None => enrolled.filter(|c| c.server == server).and_then(|c| c.ca_cert_pem),
    };
    let tls = https::tls_config(ca_pem.as_deref()).map_err(|e| config(format!("{e:#}")))?;
    let Some(token) = o.api_token.as_deref().map(str::trim).filter(|t| !t.is_empty()) else {
        return Err(ErrorInfo::new(
            ErrorCode::NotLoggedIn,
            "pass an API token from your Account page, in MAGICPIPES_API_TOKEN or with --api-token-file",
        ));
    };

    let (status, list) = https::call_reading(&server, Method::GET, "/api/v1/tunnels", &tls, Some(token), None, MAX_LIST).await.map_err(|e| crate::unreachable_server(&e))?;
    if !status.is_success() {
        return Err(error_from(status, &list, "the server refused the API token"));
    }
    let tunnels = list["tunnels"].as_array().ok_or_else(|| ErrorInfo::new(ErrorCode::Protocol, "unexpected answer to the list of tunnels"))?;
    let mut targets = Vec::new();
    for asked in &o.tunnels {
        if !tunnels.iter().any(|t| t["name"].as_str() == Some(asked.trim())) {
            return Err(ErrorInfo::new(ErrorCode::NotFound, format!("you don't manage a tunnel named '{}'", asked.trim())));
        }
    }
    for t in tunnels {
        let name = t["name"].as_str().unwrap_or_default();
        if o.tunnels.is_empty() || o.tunnels.iter().any(|a| a.trim() == name) {
            targets.extend(target(t));
        }
    }
    if targets.is_empty() {
        if o.json {
            crate::print_json(&json!({ "results": [], "reported": false }));
        } else if !o.quiet {
            eprintln!("Nothing to check: only HTTP tunnels and public TCP ports have addresses of their own, and tunnels added with --no-check are left alone.");
        }
        return Ok(true);
    }

    let tls_ref = &tls;
    let mut found: Vec<Found> = futures_util::stream::iter(targets)
        .map(|t| async move {
            let said = tokio::time::timeout(PROBE_TIMEOUT, check(&t.how, tls_ref)).await.unwrap_or_else(|_| Err(format!("no answer within {} seconds", PROBE_TIMEOUT.as_secs())));
            let (ok, said) = match said {
                Ok(s) => (true, s),
                Err(s) => (false, s),
            };
            Found { tunnel_id: t.id, name: t.name, url: t.url, ok, said }
        })
        .buffer_unordered(AT_ONCE)
        .collect()
        .await;
    found.sort_by(|a, b| a.name.cmp(&b.name));

    let reported = if o.no_report { false } else { report(&server, &tls, token, &found).await? };
    let failed = found.iter().filter(|f| !f.ok).count();
    let total = found.len();
    let error = (failed > 0).then(|| {
        ErrorInfo::new(ErrorCode::ProbeFailed, format!("{failed} of {} couldn't be reached from here", count(total, "tunnel", "tunnels")))
    });
    if o.json {
        let mut v = json!({ "results": found, "reported": reported });
        if let Some(e) = &error {
            v["error"] = json!(e);
        }
        crate::print_json(&v);
        return Ok(failed == 0);
    }
    let width = found.iter().map(|f| f.name.len()).max().unwrap_or(0);
    for f in found.iter().filter(|f| !o.quiet || !f.ok) {
        let state = if f.ok { "passed" } else { "FAILED" };
        println!("{:width$}  {state}  {}  {}", f.name, f.url, f.said);
    }
    if !o.quiet && reported {
        eprintln!("\nReported to {server}.");
    }
    if let Some(e) = error {
        eprintln!("\nError: {}", e.message);
    }
    Ok(failed == 0)
}

fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// How to check a tunnel from the API's list, if it has an address of its own and checks on.
fn target(t: &Value) -> Option<Target> {
    if t["checks"].as_bool() == Some(false) {
        return None;
    }
    let id = t["id"].as_str()?.to_string();
    let name = t["name"].as_str()?.to_string();
    let public: Uri = t["public_url"].as_str()?.parse().ok()?;
    let host = public.host()?.trim_start_matches('[').trim_end_matches(']').to_string();
    match t["kind"].as_str()? {
        "http" if public.scheme_str() == Some("https") => {
            let port = public.port_u16().unwrap_or(443);
            let path = t["check_path"].as_str().filter(|p| p.starts_with('/')).unwrap_or("/").to_string();
            let url = format!("{}{path}", t["public_url"].as_str()?.trim_end_matches('/'));
            Some(Target { id, name, url, how: How::Http { host, port, path } })
        }
        "tcp" if t["public_port"].as_u64().is_some() => {
            let port = public.port_u16()?;
            Some(Target { id, name, url: t["public_url"].as_str()?.to_string(), how: How::Tcp { host, port } })
        }
        _ => None,
    }
}

/// One check: what answered, or why nothing did.
async fn check(how: &How, tls: &Arc<ClientConfig>) -> Result<String, String> {
    let start = Instant::now();
    let ms = |start: Instant| start.elapsed().as_millis();
    match how {
        How::Http { host, port, path } => {
            let stream = https::connect(host, *port, tls, None).await.map_err(|e| format!("{e:#}"))?;
            let req = Request::get(path.as_str())
                .header(header::HOST, https::host_header(host, *port))
                .header(header::USER_AGENT, concat!("magicpipes-probe/", env!("CARGO_PKG_VERSION")))
                .body(Full::new(Bytes::new()))
                .map_err(|e| e.to_string())?;
            let resp = https::send(stream, req).await.map_err(|e| format!("{e:#}"))?;
            Ok(format!("HTTP {} in {} ms", resp.status().as_u16(), ms(start)))
        }
        How::Tcp { host, port } => {
            let tcp = tokio::net::TcpStream::connect((host.as_str(), *port)).await.map_err(|e| format!("connecting to {host}:{port}: {e}"))?;
            drop(tcp);
            Ok(format!("connected in {} ms", ms(start)))
        }
    }
}

/// Tells the server, in batches. `false` from a server too old to take reports.
async fn report(server: &str, tls: &Arc<ClientConfig>, token: &str, found: &[Found]) -> Result<bool, ErrorInfo> {
    for batch in found.chunks(REPORT_BATCH) {
        let results: Vec<Value> = batch.iter().map(|f| json!({ "tunnel": f.tunnel_id, "ok": f.ok, "said": f.said })).collect();
        let (status, v) = https::call(server, Method::POST, "/api/v1/probes", tls, Some(token), Some(&json!({ "results": results })))
            .await
            .map_err(|e| crate::unreachable_server(&e))?;
        if matches!(status.as_u16(), 404 | 405) {
            eprintln!("This server doesn't take reports from magicpipes probe; it needs a newer magicpipesd.");
            return Ok(false);
        }
        if !status.is_success() {
            return Err(error_from(status, &v, "the server refused the report"));
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnels_with_an_address_of_their_own_are_checked() {
        let http = json!({ "id": "tn_1", "name": "web", "kind": "http", "public_url": "https://web.example.com", "check_path": "/healthz", "checks": true });
        assert_eq!(
            target(&http),
            Some(Target {
                id: "tn_1".into(),
                name: "web".into(),
                url: "https://web.example.com/healthz".into(),
                how: How::Http { host: "web.example.com".into(), port: 443, path: "/healthz".into() },
            })
        );
        let on_a_port = json!({ "id": "tn_2", "name": "web2", "kind": "http", "public_url": "https://web2.example.com:8443", "checks": true });
        assert_eq!(target(&on_a_port).map(|t| t.how), Some(How::Http { host: "web2.example.com".into(), port: 8443, path: "/".into() }));
        let tcp = json!({ "id": "tn_3", "name": "db", "kind": "tcp", "public_url": "tcp://example.com:65500", "public_port": 65500, "checks": true });
        assert_eq!(target(&tcp).map(|t| t.how), Some(How::Tcp { host: "example.com".into(), port: 65500 }));
        for skipped in [
            json!({ "id": "tn_4", "name": "off", "kind": "http", "public_url": "https://off.example.com", "checks": false }),
            json!({ "id": "tn_5", "name": "db", "kind": "tcp", "public_url": "magicpipes connect db", "checks": true }),
            json!({ "id": "tn_6", "name": "dns", "kind": "udp", "public_url": "udp://example.com:65501", "public_port": 65501, "checks": true }),
            json!({ "id": "tn_7", "name": "box", "kind": "ssh", "public_url": "ssh -J example.com box", "checks": true }),
            json!({ "id": "tn_8", "name": "desk", "kind": "rdp", "public_url": "https://example.com:8443/desktop/desk", "checks": true }),
        ] {
            assert_eq!(target(&skipped), None, "{skipped}");
        }
    }

    #[tokio::test]
    async fn a_port_that_refuses_fails_and_says_so() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let tls = https::tls_config(None).unwrap();
        let said = check(&How::Tcp { host: "127.0.0.1".into(), port }, &tls).await.unwrap_err();
        assert!(said.starts_with(&format!("connecting to 127.0.0.1:{port}: ")), "{said}");
    }
}
