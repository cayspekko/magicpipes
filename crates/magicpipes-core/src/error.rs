//! Error codes: the snake_case strings in `--json` errors, API errors, RPC errors and the
//! `x-magicpipes-error` header of pages the server generates.
//!
//! The strings are a stable machine interface (scripts, `skills/magicpipes`): add new codes, never
//! rename or remove one. Peers may send codes this build does not know, so wire types keep the
//! code as a string and [`ErrorCode::parse`] returns `None` for unknown ones.

use std::fmt;

macro_rules! codes {
    ($($(#[$doc:meta])* $variant:ident = $s:literal, http $status:literal, exit $exit:literal;)*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum ErrorCode {
            $($(#[$doc])* $variant,)*
        }

        impl ErrorCode {
            pub const ALL: &[ErrorCode] = &[$(ErrorCode::$variant,)*];

            pub fn as_str(self) -> &'static str {
                match self {
                    $(ErrorCode::$variant => $s,)*
                }
            }

            pub fn parse(s: &str) -> Option<Self> {
                match s {
                    $($s => Some(ErrorCode::$variant),)*
                    _ => None,
                }
            }

            /// HTTP status for API errors and server-generated pages.
            pub fn http_status(self) -> u16 {
                match self {
                    $(ErrorCode::$variant => $status,)*
                }
            }

            /// CLI process exit status (see the README).
            pub fn exit_code(self) -> u8 {
                match self {
                    $(ErrorCode::$variant => $exit,)*
                }
            }
        }
    };
}

codes! {
    // ---- general -----------------------------------------------------------------------------
    /// An unexpected failure; details are in the log.
    Internal = "internal", http 500, exit 1;
    /// Malformed request (API, RPC or IPC).
    InvalidRequest = "invalid_request", http 400, exit 1;
    /// The agent could not parse a CLI request (IPC).
    BadRequest = "bad_request", http 400, exit 1;
    /// An unexpected answer from the other side.
    Protocol = "protocol", http 502, exit 1;
    /// The peer does not support this request; it needs a newer version.
    Unsupported = "unsupported", http 501, exit 6;
    /// The local agent is busy with a conflicting operation.
    Busy = "busy", http 409, exit 1;

    // ---- credentials -------------------------------------------------------------------------
    NotLoggedIn = "not_logged_in", http 401, exit 3;
    /// Missing or invalid credentials (admin token, agent token).
    Unauthorized = "unauthorized", http 401, exit 3;
    InvalidEnrollmentToken = "invalid_enrollment_token", http 401, exit 3;
    /// Too many failed attempts from this client.
    RateLimited = "rate_limited", http 429, exit 1;
    /// Authenticated, but not allowed to do this.
    Forbidden = "forbidden", http 403, exit 3;
    /// Sign in first (private tunnels).
    Unauthenticated = "unauthenticated", http 401, exit 3;
    ConfigError = "config_error", http 500, exit 3;

    // ---- local targets -----------------------------------------------------------------------
    /// Nothing answered at the tunnel's local target.
    LocalUnreachable = "local_unreachable", http 502, exit 4;
    InvalidPort = "invalid_port", http 400, exit 4;
    InvalidHost = "invalid_host", http 400, exit 4;
    InvalidDirectory = "invalid_directory", http 400, exit 4;
    InvalidCommand = "invalid_command", http 400, exit 4;
    /// The web terminal could not start its program.
    SpawnFailed = "spawn_failed", http 500, exit 4;

    // ---- reaching the server or the agent ----------------------------------------------------
    InvalidServer = "invalid_server", http 400, exit 1;
    ServerUnreachable = "server_unreachable", http 502, exit 5;
    /// The server: the tunnel's agent has no session, or a stream to it failed.
    /// The CLI: talking to the local agent failed.
    AgentUnavailable = "agent_unavailable", http 502, exit 5;
    AgentStartFailed = "agent_start_failed", http 500, exit 5;
    AgentNotRunning = "agent_not_running", http 502, exit 5;
    AgentProtocol = "agent_protocol", http 502, exit 5;
    /// The agent (or the running local agent) is older than the other side requires.
    AgentOutdated = "agent_outdated", http 502, exit 5;

    // ---- naming and the registry -------------------------------------------------------------
    /// A local tunnel with this name already forwards somewhere else.
    NameConflict = "name_conflict", http 409, exit 6;
    /// Another agent owns this name.
    NameTaken = "name_taken", http 409, exit 6;
    /// Another account already logs in with this email.
    EmailTaken = "email_taken", http 409, exit 6;
    /// Not a registered access tag.
    TagUnknown = "tag_unknown", http 400, exit 6;
    /// This agent may not create public tunnels.
    PublicNotAllowed = "public_not_allowed", http 403, exit 6;
    InvalidName = "invalid_name", http 400, exit 6;
    InvalidCidr = "invalid_cidr", http 400, exit 6;
    /// A per-agent quota (tunnels, ports, new certificates).
    LimitReached = "limit_reached", http 409, exit 6;
    NotFound = "not_found", http 404, exit 6;
    PortUnavailable = "port_unavailable", http 409, exit 6;
    KindMismatch = "kind_mismatch", http 409, exit 6;
    PortsDisabled = "ports_disabled", http 409, exit 6;
    /// The server is older than this request requires.
    ServerOutdated = "server_outdated", http 501, exit 6;

    // ---- certificates and readiness ----------------------------------------------------------
    TlsFailed = "tls_failed", http 502, exit 7;
    TlsTimeout = "tls_timeout", http 504, exit 7;
    ProbeFailed = "probe_failed", http 502, exit 8;

    // ---- public traffic (server-generated pages) ---------------------------------------------
    TunnelNotFound = "tunnel_not_found", http 404, exit 1;
    AgentOffline = "agent_offline", http 502, exit 1;
    /// The agent session has no stream left for public traffic.
    AgentBusy = "agent_busy", http 503, exit 1;
    TunnelInactive = "tunnel_inactive", http 502, exit 1;
    UpstreamError = "upstream_error", http 502, exit 1;
    UpstreamTimeout = "upstream_timeout", http 504, exit 1;
    BadUpstream = "bad_upstream", http 502, exit 1;
    BadHost = "bad_host", http 400, exit 1;
    BadUri = "bad_uri", http 400, exit 1;
    MisdirectedRequest = "misdirected_request", http 421, exit 1;
    MethodNotAllowed = "method_not_allowed", http 405, exit 1;
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Exit status for a code from any source; unknown codes (from a newer peer) are 1.
pub fn exit_code(code: &str) -> u8 {
    ErrorCode::parse(code).map_or(1, ErrorCode::exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip_and_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for c in ErrorCode::ALL {
            assert!(seen.insert(c.as_str()), "duplicate {c}");
            assert_eq!(ErrorCode::parse(c.as_str()), Some(*c));
            assert!(c.as_str().bytes().all(|b| b.is_ascii_lowercase() || b == b'_'), "{c}");
            assert!((400..600).contains(&c.http_status()), "{c}");
        }
        assert_eq!(ErrorCode::parse("from_a_newer_peer"), None);
        assert_eq!(exit_code("from_a_newer_peer"), 1);
    }

    #[test]
    fn exit_codes_match_the_documented_table() {
        // The CLI's exit statuses are an API (README "JSON output and exit codes").
        let table: &[(u8, &[&str])] = &[
            (3, &["not_logged_in", "unauthorized", "invalid_enrollment_token", "config_error", "forbidden", "unauthenticated"]),
            (4, &["local_unreachable", "invalid_port", "invalid_host", "invalid_directory", "invalid_command", "spawn_failed"]),
            (5, &["server_unreachable", "agent_unavailable", "agent_start_failed", "agent_not_running", "agent_protocol", "agent_outdated"]),
            (6, &["name_conflict", "name_taken", "email_taken", "tag_unknown", "public_not_allowed", "invalid_name", "limit_reached", "not_found", "port_unavailable", "kind_mismatch",
                  "ports_disabled", "server_outdated", "invalid_cidr", "unsupported"]),
            (7, &["tls_failed", "tls_timeout"]),
            (8, &["probe_failed"]),
        ];
        for c in ErrorCode::ALL {
            let want = table.iter().find(|(_, codes)| codes.contains(&c.as_str())).map_or(1, |(e, _)| *e);
            assert_eq!(c.exit_code(), want, "{c}");
        }
    }
}
