//! End-to-end readiness probe through the real public HTTPS path.
//!
//! The probe is a GET on the public URL carrying a random nonce. It succeeds only if
//! 1. TLS verifies for the public hostname,
//! 2. the response has `x-magicpipes-probe-ack: <tunnel id> <nonce>` — which the server adds only
//!    to responses it received from this tunnel's upstream (and strips from application
//!    responses), and has no `x-magicpipes-error` header, and
//! 3. this agent saw a data stream for the tunnel reach the local target meanwhile.
//!
//! Any application status (200, 401, 404, 405, ...) counts: transport readiness is the goal,
//! not application health. If the application accepts the connection but sends no HTTP
//! response, the probe retries as a WebSocket upgrade (for WebSocket-only servers); a `101`
//! carrying the acknowledgement counts as well.

use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::{Request, header};
use http_body_util::Full;
use magicpipes_core::proto::{ERROR_HEADER, PROBE_ACK_HEADER, PROBE_HEADER};
use rustls::ClientConfig;

use super::tunnels::Tunnels;
use crate::https;
use crate::state::LocalTunnel;

/// Testing/advanced knob: connect probes to this IP instead of resolving the public hostname.
pub const PROBE_ADDR_ENV: &str = "MAGICPIPES_PROBE_ADDR";

pub async fn probe(t: &LocalTunnel, path: &str, tls: &Arc<ClientConfig>, tunnels: &Tunnels) -> Result<u16, String> {
    match probe_once(t, path, tls, tunnels, false).await {
        // The application accepted the connection but sent no HTTP response: it may be a
        // WebSocket-only server. Retry as a WebSocket upgrade, which such servers answer.
        Err(ProbeError { app_closed: true, .. }) => probe_once(t, path, tls, tunnels, true).await.map_err(|e| e.message),
        r => r.map_err(|e| e.message),
    }
}

struct ProbeError {
    message: String,
    app_closed: bool,
}

impl From<String> for ProbeError {
    fn from(message: String) -> Self {
        Self { message, app_closed: false }
    }
}

async fn probe_once(t: &LocalTunnel, path: &str, tls: &Arc<ClientConfig>, tunnels: &Tunnels, websocket: bool) -> Result<u16, ProbeError> {
    let (host, port) = https::parse_server(&t.public_url).map_err(|e| e.to_string())?;
    let addr: Option<IpAddr> = std::env::var(PROBE_ADDR_ENV).ok().and_then(|v| v.parse().ok());
    let stream = https::connect(&host, port, tls, addr)
        .await
        .map_err(|e| format!("could not reach {}: {e:#}", t.public_url))?;
    let nonce = magicpipes_core::secret::random_string(24);
    let before = tunnels.streams_ok(&t.id);
    let path = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };
    let mut req = Request::get(path.as_str())
        .header(header::HOST, https::host_header(&host, port))
        .header(header::USER_AGENT, concat!("magicpipes-probe/", env!("CARGO_PKG_VERSION")))
        .header(PROBE_HEADER, &nonce);
    if websocket {
        req = req
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, "websocket")
            .header(header::SEC_WEBSOCKET_VERSION, "13")
            .header(header::SEC_WEBSOCKET_KEY, websocket_key());
    }
    let req = req.body(Full::new(Bytes::new())).map_err(|e| e.to_string())?;
    let resp = tokio::time::timeout(std::time::Duration::from_secs(15), https::send(stream, req))
        .await
        .map_err(|_| "public endpoint did not respond within 15s".to_string())?
        .map_err(|e| format!("request to public endpoint failed: {e:#}"))?;
    let status = resp.status().as_u16();
    if let Some(code) = resp.headers().get(ERROR_HEADER).and_then(|v| v.to_str().ok()) {
        let message = match code {
            "local_unreachable" => "the server reached the agent, but the local application refused the connection".into(),
            "upstream_error" => "the local application accepted the connection but sent no valid HTTP response".into(),
            "agent_offline" | "agent_unavailable" => "the server does not see this agent as connected".into(),
            "tunnel_not_found" => "the server does not route this hostname (yet)".into(),
            other => format!("the server answered with error '{other}' (HTTP {status})"),
        };
        return Err(ProbeError { message, app_closed: code == "upstream_error" });
    }
    let expected = format!("{} {nonce}", t.id);
    let ack = resp.headers().get(PROBE_ACK_HEADER).and_then(|v| v.to_str().ok());
    if ack != Some(expected.as_str()) {
        return Err(format!(
            "{} answered (HTTP {status}) but not through this tunnel; check that DNS for the hostname points at the MagicPipes server",
            t.public_url
        )
        .into());
    }
    if tunnels.streams_ok(&t.id) <= before {
        return Err("probe response was not served through this agent".to_string().into());
    }
    Ok(status)
}

/// A random `Sec-WebSocket-Key`: base64 of 16 random bytes.
fn websocket_key() -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut raw = [0u8; 18]; // 16 random bytes + 2 zero bytes for padding arithmetic
    raw[..8].copy_from_slice(&magicpipes_core::secret::random_u64().to_le_bytes());
    raw[8..16].copy_from_slice(&magicpipes_core::secret::random_u64().to_le_bytes());
    let mut out = String::with_capacity(24);
    for chunk in raw.chunks(3) {
        let n = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        for i in (0..4).rev() {
            out.push(B64[((n >> (6 * i)) & 63) as usize] as char);
        }
    }
    out.truncate(22);
    out.push_str("==");
    out
}
