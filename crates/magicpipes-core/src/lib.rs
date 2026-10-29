//! Code shared by `magicpipesd` (server) and `magicpipes` (CLI + local agent).
//!
//! * [`proto`] — the agent <-> server wire protocol (RPC frames and data-stream headers).
//! * [`mux`] — a small driver that runs a yamux session on a Tokio task.
//! * [`names`] — tunnel name validation and random name generation.
//! * [`secret`] — token generation, hashing and constant-time comparison.

pub mod mux;
pub mod names;
pub mod proto;
pub mod secret;

/// Seconds since the Unix epoch.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Formats a Unix timestamp as RFC 3339 (UTC).
pub fn rfc3339(ts: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(ts)
        .ok()
        .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
        .unwrap_or_default()
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
