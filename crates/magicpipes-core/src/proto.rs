//! Agent <-> server wire protocol.
//!
//! The agent opens an HTTPS connection to the management listener and sends
//!
//! ```text
//! GET /api/v1/agent/connect HTTP/1.1
//! Authorization: Bearer <agent token>
//! Connection: Upgrade
//! Upgrade: magicpipes-mux/1
//! X-MagicPipes-Protocol: 2
//! ```
//!
//! After `101 Switching Protocols` the connection carries a yamux session (agent = client,
//! server = server). Both the request and the `101` response carry [`PROTOCOL_HEADER`], so each
//! side knows what the other understands before it sends anything; a peer that omits it speaks
//! version 1. Two kinds of streams exist:
//!
//! * **Agent-opened streams are RPCs.** The agent writes one [`Request`] frame, the server answers
//!   with one [`Response`] frame and both sides close the stream.
//! * **Server-opened streams are pushes or data.** The server writes one [`ServerOpen`] frame.
//!   For [`ServerOpen::Data`] the agent connects to the tunnel's local target and writes a single
//!   [`StreamStatus`] byte; after [`StreamStatus::Ok`] the stream is a raw, bidirectional byte
//!   pipe to the local application. [`ServerOpen::Datagram`] is the same for one UDP client,
//!   except that after `Ok` both directions carry datagrams framed by [`write_datagram`] (a
//!   big-endian `u16` length, then the payload).
//!
//! Frames are a big-endian `u32` length followed by a JSON document, capped at [`MAX_FRAME`].

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::ErrorCode;

pub const UPGRADE_PROTOCOL: &str = "magicpipes-mux/1";
pub const AGENT_CONNECT_PATH: &str = "/api/v1/agent/connect";
/// `magicpipes connect`: `GET` this plus a tunnel's name, with a connect pass as the bearer token.
/// Without an upgrade the answer says what the tunnel is; with [`CONNECT_PROTOCOL`] the connection
/// becomes the tunnel's: raw bytes for TCP, [`write_datagram`] frames both ways for UDP.
pub const CONNECT_PATH: &str = "/api/v1/connect/";
pub const CONNECT_PROTOCOL: &str = "magicpipes-connect/1";

/// Header on the agent's upgrade request and the server's `101` response: the sender's
/// protocol version.
pub const PROTOCOL_HEADER: &str = "x-magicpipes-protocol";
/// The protocol version this build speaks. Bump it when a peer needs to know about a new
/// request, stream type or field before using it, and say here what the version adds.
///
/// * 1: everything before the handshake (no header).
/// * 2: the handshake. An unknown request is answered with the error code `unsupported`, and an
///   unknown server-opened stream with [`StreamStatus::Unsupported`], instead of being dropped.
/// * 3: private tunnels. [`RegisterTunnel`] carries `visibility` and `tags`, and
///   [`TunnelInfo`] echoes them.
/// * 4: custom hostnames. [`RegisterTunnel`] carries `hostname`; an older server would ignore
///   it and serve the tunnel at `<name>.<base_domain>`.
/// * 5: SSH tunnels. [`RegisterTunnel`] may carry the kind [`Kind::Ssh`], which an older server
///   can't read, so the agent checks this version first.
/// * 6: private TCP and UDP tunnels, which people reach with `magicpipes connect`. An older server
///   refuses them, or ignores `visibility` and opens a public port, so the agent checks this first.
/// * 7: RDP tunnels. [`RegisterTunnel`] may carry the kind [`Kind::Rdp`], which an older server
///   can't read, so the agent checks this version first.
/// * 8: VNC tunnels: the kind [`Kind::Vnc`], checked the same way.
/// * 9: several connections per agent. Each carries [`INSTANCE_HEADER`], and the server keeps an
///   instance's connections together (up to [`MAX_CONNECTIONS`]) instead of the newest replacing
///   the others, as an older server does: so the agent opens more than one only once it knows.
/// * 10: after [`StreamStatus::LocalUnreachable`], an [`Unreachable`] frame saying why. An older
///   server closes the stream after the status byte and never reads it; the agent sends it only to
///   a server at [`REASONS_PROTOCOL`] or newer anyway.
/// * 11: replicas. [`TunnelInfo`] says when other runs of the machine may serve the tunnel too
///   (`replicas`), so a readiness probe through it may reach one of them; the agent then takes the
///   server's acknowledgement as enough. An older server never says so, and an older agent
///   ignores it and waits for a probe that may never reach it, so replicas need agents at 11.
pub const PROTOCOL_VERSION: u32 = 11;

/// The first protocol version whose servers read why the app couldn't be reached.
pub const REASONS_PROTOCOL: u32 = 10;

/// The first protocol version that keeps an agent's connections together.
pub const CONNECTIONS_PROTOCOL: u32 = 9;

/// Header on each of an agent's connection requests: the same random id for every connection of
/// one run of the agent (protocol 9). Connections with another, or none, replace them.
pub const INSTANCE_HEADER: &str = "x-magicpipes-instance";

/// Most connections one agent may hold at once.
pub const MAX_CONNECTIONS: usize = 8;

/// Whether `id` can be an [`INSTANCE_HEADER`] value: 16 to 64 letters, digits, `-` or `_`.
pub fn valid_instance(id: &str) -> bool {
    (16..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The peer's version from a [`PROTOCOL_HEADER`] value; a missing or unreadable value is 1.
pub fn peer_protocol(value: Option<&str>) -> u32 {
    value.and_then(|v| v.trim().parse().ok()).filter(|v| *v >= 1).unwrap_or(1)
}

/// Header carrying a readiness-probe nonce on a public request.
pub const PROBE_HEADER: &str = "x-magicpipes-probe";
/// Response header set by the server only when the response came from the tunnel upstream.
/// Value: `<tunnel id> <nonce>`.
pub const PROBE_ACK_HEADER: &str = "x-magicpipes-probe-ack";
/// Response header set on every response generated by MagicPipes itself (never the application).
pub const ERROR_HEADER: &str = "x-magicpipes-error";

pub const MAX_FRAME: usize = 64 * 1024;

/// The agent's one-byte answer on a server-opened data stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamStatus {
    /// Connected to the local target; the stream now carries its bytes (or datagrams).
    Ok,
    /// The local target refused or did not answer the connection.
    LocalUnreachable,
    /// The agent does not know (or no longer serves) the requested tunnel.
    UnknownTunnel,
    /// The agent could not read the stream's [`ServerOpen`] header: the server is newer.
    /// Protocol 2 and later.
    Unsupported,
}

impl StreamStatus {
    pub fn byte(self) -> u8 {
        match self {
            StreamStatus::Ok => 0,
            StreamStatus::LocalUnreachable => 1,
            StreamStatus::UnknownTunnel => 2,
            StreamStatus::Unsupported => 3,
        }
    }

    /// `None` for a byte this build does not know.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(StreamStatus::Ok),
            1 => Some(StreamStatus::LocalUnreachable),
            2 => Some(StreamStatus::UnknownTunnel),
            3 => Some(StreamStatus::Unsupported),
            _ => None,
        }
    }

    pub async fn write<W: AsyncWrite + Unpin>(self, w: &mut W) -> std::io::Result<()> {
        w.write_all(&[self.byte()]).await
    }
}

/// How a tunnel is reached publicly (the server's concern; the agent's local target is separate).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A hostname under the base domain, with TLS on the public HTTPS port.
    #[default]
    Http,
    /// A raw TCP port from the server's port range.
    Tcp,
    /// A UDP port from the server's port range.
    Udp,
    /// A name on the server's SSH gateway (`ssh -J`). Protocol 5.
    Ssh,
    /// A remote desktop: a machine's RDP port, opened in the browser through the server, or with
    /// `magicpipes connect` for a native client. Protocol 7.
    Rdp,
    /// A remote desktop over VNC: a machine's VNC port, opened in the browser (noVNC) through the
    /// server, or with `magicpipes connect` for a native viewer. Protocol 8.
    Vnc,
}

impl Kind {
    pub fn is_http(&self) -> bool {
        *self == Kind::Http
    }

    /// Does it take a port from the server's port range?
    pub fn has_port(&self) -> bool {
        matches!(self, Kind::Tcp | Kind::Udp)
    }

    /// Is it a remote desktop, opened in the browser from the management site?
    pub fn is_desktop(&self) -> bool {
        matches!(self, Kind::Rdp | Kind::Vnc)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Http => "http",
            Kind::Tcp => "tcp",
            Kind::Udp => "udp",
            Kind::Ssh => "ssh",
            Kind::Rdp => "rdp",
            Kind::Vnc => "vnc",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "http" => Some(Kind::Http),
            "tcp" => Some(Kind::Tcp),
            "udp" => Some(Kind::Udp),
            "ssh" => Some(Kind::Ssh),
            "rdp" => Some(Kind::Rdp),
            "vnc" => Some(Kind::Vnc),
            _ => None,
        }
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Who may reach a tunnel.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    /// Anyone with the address (network allow-lists still apply).
    #[default]
    Public,
    /// Only people who share a tag with it that grants access (its owner through their personal
    /// tag), after signing in.
    Private,
}

impl Visibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Visibility::Public => "public",
            Visibility::Private => "private",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "public" => Some(Visibility::Public),
            "private" => Some(Visibility::Private),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Liveness check; also refreshes the server's last-seen timestamp for the agent.
    Ping,
    /// Create or re-attach a tunnel owned by this agent. Idempotent: an existing tunnel with the
    /// same `id` (or, if `id` is absent, the same `name`) owned by this agent is returned as is.
    Register(RegisterTunnel),
    /// Delete a tunnel owned by this agent.
    Unregister { id: String },
    /// Wait (up to `wait_ms`) until the certificate for `hostname` is no longer pending.
    CertStatus { hostname: String, wait_ms: u64 },
    /// Readiness check for a port tunnel: the server opens a data stream to this agent for the
    /// tunnel and answers [`Response::Ok`] once the agent reports [`StreamStatus::Ok`].
    Check { id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterTunnel {
    /// Previously assigned id (when restoring after a reconnect).
    pub id: Option<String>,
    /// Requested name (the first DNS label of the public hostname).
    pub name: Option<String>,
    /// Human-readable description of the local target, e.g. `http://127.0.0.1:8080`.
    /// Informational only: the server never dials it.
    pub target: String,
    /// Absent (`http`) for agents and servers that predate port tunnels. A server that does not
    /// know this field ignores it, so the agent checks [`TunnelInfo::kind`] in the answer.
    #[serde(default, skip_serializing_if = "Kind::is_http")]
    pub kind: Kind,
    /// Port tunnels: a specific public port from the server's range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<u16>,
    /// Port tunnels: client networks allowed to connect (CIDRs or addresses); empty = anyone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Protocol 3. `None`: the agent's default for a new tunnel, and no change for an existing
    /// one (older agents never send it). `Some`: `tags` is the full new value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<Visibility>,
    /// Private tunnels: tags to share it with, from the ones the agent publishes with. The
    /// server adds the owner's personal tag.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Protocol 4: a custom hostname (an administrator assigned it to this machine) instead
    /// of `<name>.<base_domain>`. Fixed when the tunnel is created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Whether the server checks the tunnel's app on its own, once a minute (`add --no-check`
    /// turns it off). `None`: no change, and on for a new tunnel. A server that doesn't know it
    /// ignores it, and checks nothing anyway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checks: Option<bool>,
    /// HTTP tunnels: the path those checks request (`add --probe-path`). `None`: no change, and
    /// `/` for a new tunnel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Pong,
    Tunnel(TunnelInfo),
    Ok,
    Cert(CertState),
    Error(ErrorBody),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelInfo {
    pub id: String,
    pub name: String,
    pub hostname: String,
    /// `https://…`, `tcp://host:port` / `udp://host:port` for port tunnels, or the `ssh -J` command
    /// for an SSH tunnel.
    pub public_url: String,
    /// `true` if this call created the tunnel, `false` if it already existed.
    pub created: bool,
    #[serde(default)]
    pub kind: Kind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_port: Option<u16>,
    /// Protocol 3; servers before it omit it (and every tunnel of theirs is public).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<Visibility>,
    /// The tunnel's tags, its owner's personal tag included.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Those of `tags` that grant access, when it was registered.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub access: Vec<String>,
    /// The owner's personal tag; absent for a service agent's tunnel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_tag: Option<String>,
    /// Other runs of the machine may serve it too (replicas, protocol 11): a request through it
    /// may reach any of them.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub replicas: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CertState {
    Pending,
    Ready,
    Failed { message: String },
}

/// An error answer. `code` stays a string on the wire: a newer peer may send codes this build
/// does not know.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

impl ErrorBody {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code: code.as_str().to_string(), message: message.into() }
    }

    pub fn is(&self, code: ErrorCode) -> bool {
        self.code == code.as_str()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServerOpen {
    /// A public connection for `tunnel_id`; followed by raw bytes after the agent's status byte.
    /// `peer` is the client's address on port tunnels (for the agent's log).
    Data {
        tunnel_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer: Option<String>,
    },
    /// One UDP client of `tunnel_id`; followed by framed datagrams after the status byte.
    Datagram {
        tunnel_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer: Option<String>,
    },
    /// The tunnel was deleted on the server (e.g. by an administrator).
    TunnelRemoved { tunnel_id: String },
    /// Answered with a status byte at once, so the server can time a round trip on this
    /// connection. An agent before this answers [`StreamStatus::Unsupported`], which times it too.
    Ping,
}

/// Body of `POST /api/v1/enroll`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub enrollment_token: String,
    pub agent_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub agent_id: String,
    pub agent_token: String,
    pub base_domain: String,
}

/// Why an agent couldn't reach a tunnel's app (protocol 10), sent as a frame after
/// [`StreamStatus::LocalUnreachable`]. For the tunnel's owner: the server shows it in checks and
/// alerts, never to a visitor, since `detail` can name local addresses and paths.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Unreachable {
    pub reason: UnreachableReason,
    /// What the agent saw, such as `connection refused by 127.0.0.1:8080`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnreachableReason {
    /// Nothing accepts connections there.
    Refused,
    /// No connection within the agent's time limit.
    TimedOut,
    /// No such socket, or the name doesn't resolve.
    NotFound,
    /// The agent's user may not connect.
    Permission,
    /// An HTTPS app (`--local-https`) showed a certificate other than the one kept.
    CertificateChanged,
    /// An HTTPS app's TLS failed otherwise.
    Tls,
    /// Anything else, including a reason from a newer agent.
    #[serde(other)]
    Other,
}

/// Reads an agent's [`Unreachable`] after its status byte, if it sends one: an older agent closes
/// the stream instead, so this returns `None` at once rather than waiting.
pub async fn read_unreachable<R: AsyncRead + Unpin>(r: &mut R) -> Option<Unreachable> {
    tokio::time::timeout(std::time::Duration::from_secs(2), read_frame(r)).await.ok().and_then(Result::ok)
}

pub async fn write_frame<W, T>(w: &mut W, value: &T) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(value)?;
    if body.len() > MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
    buf.extend_from_slice(&body);
    w.write_all(&buf).await?;
    w.flush().await
}

/// Largest datagram a [`ServerOpen::Datagram`] stream carries (the UDP payload limit).
pub const MAX_DATAGRAM: usize = u16::MAX as usize;

/// Writes one datagram on a [`ServerOpen::Datagram`] stream.
pub async fn write_datagram<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
    let len = u16::try_from(payload.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "datagram too large"))?;
    let mut buf = Vec::with_capacity(2 + payload.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(payload);
    w.write_all(&buf).await?;
    w.flush().await
}

/// Reads one datagram into `buf` (resized to fit); `Ok(false)` at a clean end of stream.
pub async fn read_datagram<R: AsyncRead + Unpin>(r: &mut R, buf: &mut Vec<u8>) -> std::io::Result<bool> {
    let mut len = [0u8; 2];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(false),
        Err(e) => return Err(e),
    }
    buf.resize(u16::from_be_bytes(len) as usize, 0);
    r.read_exact(buf).await?;
    Ok(true)
}

/// Reads exactly one frame; never consumes bytes beyond it.
pub async fn read_frame<R, T>(r: &mut R) -> std::io::Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    Ok(serde_json::from_slice(&read_frame_bytes(r).await?)?)
}

/// Reads one frame's JSON body without parsing it, so a caller can tell a request it does not
/// understand (it parses as JSON, not as the expected type) from a broken stream.
pub async fn read_frame_bytes<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_roundtrip_does_not_overread() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &ServerOpen::Data { tunnel_id: "tn_1".into(), peer: None }).await.unwrap();
        buf.extend_from_slice(b"GET / HTTP/1.1\r\n");
        let mut r = &buf[..];
        let open: ServerOpen = read_frame(&mut r).await.unwrap();
        assert_eq!(open, ServerOpen::Data { tunnel_id: "tn_1".into(), peer: None });
        assert_eq!(r, b"GET / HTTP/1.1\r\n");
    }

    #[tokio::test]
    async fn datagrams_keep_their_boundaries() {
        let mut buf = Vec::new();
        for d in [&b"one"[..], b"", b"three"] {
            write_datagram(&mut buf, d).await.unwrap();
        }
        let mut r = &buf[..];
        let mut got = Vec::new();
        let mut d = Vec::new();
        while read_datagram(&mut r, &mut d).await.unwrap() {
            got.push(d.clone());
        }
        assert_eq!(got, [b"one".to_vec(), vec![], b"three".to_vec()]);
        assert!(write_datagram(&mut Vec::new(), &vec![0; MAX_DATAGRAM + 1]).await.is_err());
    }

    #[test]
    fn instance_ids_are_plain_and_bounded() {
        assert!(valid_instance(&"a".repeat(16)) && valid_instance("Zq-_09azAZqqqqqqqqqqqqqqqqqq"));
        assert!(!valid_instance(&"a".repeat(15)) && !valid_instance(&"a".repeat(65)));
        assert!(!valid_instance("aaaaaaaaaaaaaaaa\n") && !valid_instance("aaaaaaaa aaaaaaaa") && !valid_instance("aaaaaaaaaaaaaaaa;"));
    }

    #[test]
    fn old_peers_still_parse() {
        // A register request from an agent that predates port tunnels is an HTTP tunnel.
        let r: Request = serde_json::from_str(r#"{"op":"register","id":null,"name":"a","target":"x"}"#).unwrap();
        assert!(matches!(r, Request::Register(RegisterTunnel { kind: Kind::Http, remote_port: None, .. })));
        // An answer from a server that predates port tunnels says http, whatever was asked.
        let t: TunnelInfo = serde_json::from_str(r#"{"id":"tn","name":"a","hostname":"a.t","public_url":"https://a.t","created":true}"#).unwrap();
        assert_eq!((t.kind, t.public_port), (Kind::Http, None));
        // Before protocol 3: no visibility either way, so a new agent can tell it wasn't honored.
        assert!(t.visibility.is_none() && t.tags.is_empty());
        // Before protocol 11: no replicas, so a probe must reach the agent that sent it.
        assert!(!t.replicas);
        let with: TunnelInfo = serde_json::from_str(r#"{"id":"tn","name":"a","hostname":"a.t","public_url":"https://a.t","created":true,"replicas":true}"#).unwrap();
        assert!(with.replicas);
        assert!(!serde_json::to_string(&t).unwrap().contains("replicas"), "said only when true");
        let r: Request = serde_json::from_str(r#"{"op":"register","id":null,"name":"a","target":"x"}"#).unwrap();
        assert!(matches!(r, Request::Register(RegisterTunnel { visibility: None, .. })));
        let r = Request::Register(RegisterTunnel {
            id: None,
            name: None,
            target: "x".into(),
            kind: Kind::Http,
            remote_port: None,
            allow: vec![],
            visibility: Some(Visibility::Private),
            tags: vec!["dev".into()],
            hostname: None,
            checks: None,
            check_path: None,
        });
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""visibility":"private""#) && json.contains(r#""tags":["dev"]"#), "{json}");
        assert!(!json.contains("check"), "an older server is sent nothing it doesn't know: {json}");
        // Checks: an older agent never sends these, which changes nothing; an older server ignores them.
        assert!(matches!(r_register(r#"{"op":"register","id":null,"name":"a","target":"x"}"#), RegisterTunnel { checks: None, check_path: None, .. }));
        let r = r_register(r#"{"op":"register","id":null,"name":"a","target":"x","checks":false,"check_path":"/health"}"#);
        assert_eq!((r.checks, r.check_path.as_deref()), (Some(false), Some("/health")));
        // Protocol 5: an older peer can't read this kind, so the agent checks the version first.
        let r: Request = serde_json::from_str(r#"{"op":"register","id":null,"name":"a","target":"x","kind":"ssh"}"#).unwrap();
        assert!(matches!(r, Request::Register(RegisterTunnel { kind: Kind::Ssh, .. })));
        assert!(serde_json::to_string(&Kind::Ssh).unwrap() == r#""ssh""# && Kind::parse("ssh") == Some(Kind::Ssh) && !Kind::Ssh.has_port() && !Kind::Ssh.is_http());
        // Protocol 6: a private port tunnel is a port kind with a visibility, and an answer
        // without a public port. An agent before it never sends one, and keeps an allow-list.
        let r: Request = serde_json::from_str(r#"{"op":"register","id":null,"name":"db","target":"x","kind":"tcp","visibility":"private","tags":["dev"]}"#).unwrap();
        assert!(matches!(r, Request::Register(RegisterTunnel { kind: Kind::Tcp, visibility: Some(Visibility::Private), remote_port: None, .. })));
        let t: TunnelInfo =
            serde_json::from_str(r#"{"id":"tn","name":"db","hostname":"db.t","public_url":"magicpipes connect db","created":true,"kind":"tcp","visibility":"private"}"#).unwrap();
        assert_eq!((t.kind, t.public_port, t.visibility), (Kind::Tcp, None, Some(Visibility::Private)));
        // Protocol 7: like SSH, an older peer can't read this kind.
        let r: Request = serde_json::from_str(r#"{"op":"register","id":null,"name":"pc","target":"x","kind":"rdp"}"#).unwrap();
        assert!(matches!(r, Request::Register(RegisterTunnel { kind: Kind::Rdp, .. })));
        assert!(serde_json::to_string(&Kind::Rdp).unwrap() == r#""rdp""# && Kind::parse("rdp") == Some(Kind::Rdp) && !Kind::Rdp.has_port() && !Kind::Rdp.is_http());
        // A ping the server times: plain, so that an agent which doesn't know it answers at once.
        assert_eq!(serde_json::to_string(&ServerOpen::Ping).unwrap(), r#"{"kind":"ping"}"#);
        assert_eq!(serde_json::from_str::<ServerOpen>(r#"{"kind":"ping"}"#).unwrap(), ServerOpen::Ping);
        // Protocol 10: why the app couldn't be reached, and a reason from a newer agent is "other".
        let u: Unreachable = serde_json::from_str(r#"{"reason":"refused","detail":"connection refused by 127.0.0.1:8080"}"#).unwrap();
        assert_eq!(u.reason, UnreachableReason::Refused);
        let u: Unreachable = serde_json::from_str(r#"{"reason":"from_the_future"}"#).unwrap();
        assert_eq!((u.reason, u.detail.as_str()), (UnreachableReason::Other, ""));
        // Protocol 8: the same for VNC.
        let r: Request = serde_json::from_str(r#"{"op":"register","id":null,"name":"pi","target":"x","kind":"vnc"}"#).unwrap();
        assert!(matches!(r, Request::Register(RegisterTunnel { kind: Kind::Vnc, .. })));
        assert!(serde_json::to_string(&Kind::Vnc).unwrap() == r#""vnc""# && Kind::parse("vnc") == Some(Kind::Vnc) && !Kind::Vnc.has_port() && Kind::Vnc.is_desktop());
    }

    fn r_register(json: &str) -> RegisterTunnel {
        match serde_json::from_str::<Request>(json).unwrap() {
            Request::Register(r) => r,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn protocol_versions_and_stream_status() {
        assert_eq!(peer_protocol(None), 1);
        assert_eq!(peer_protocol(Some("2")), 2);
        assert_eq!(peer_protocol(Some(" 7 ")), 7);
        assert_eq!(peer_protocol(Some("0")), 1);
        assert_eq!(peer_protocol(Some("two")), 1);
        // The bytes are on the wire: old agents send 0..=2.
        for (s, b) in [(StreamStatus::Ok, 0), (StreamStatus::LocalUnreachable, 1), (StreamStatus::UnknownTunnel, 2), (StreamStatus::Unsupported, 3)] {
            assert_eq!(s.byte(), b);
            assert_eq!(StreamStatus::from_byte(b), Some(s));
        }
        assert_eq!(StreamStatus::from_byte(200), None);
        // A request from a newer agent is still JSON, so the server can answer `unsupported`.
        assert!(serde_json::from_str::<Request>(r#"{"op":"from_the_future"}"#).is_err());
        assert!(serde_json::from_str::<serde_json::Value>(r#"{"op":"from_the_future"}"#).is_ok());
    }

    #[tokio::test]
    async fn oversized_frame_rejected() {
        let mut buf = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        buf.extend(std::iter::repeat_n(b' ', 16));
        let mut r = &buf[..];
        assert!(read_frame::<_, Request>(&mut r).await.is_err());
    }
}
