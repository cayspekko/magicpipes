# MagicPipes architecture

This document records the design decisions behind Milestone 1, what is deliberately left out,
and how to run the production acceptance test.

## Topology

```text
 public client ──HTTPS/WSS :443──▶ magicpipesd ◀──HTTPS :8443 + Upgrade (outbound)── magicpipes agent ──TCP──▶ 127.0.0.1:8080
                                   │ data plane: TLS (SNI) → Host route → yamux stream ─┐             (one process per user/machine)
                                   │ control plane: registry, SQLite, certs, API/UI      │
                                   └─────────────────────────────────────────────────────┘
```

The agent always dials out. The server never connects into the private network; it only opens
streams *inside* the session the agent established.

## Library selection

| Concern | Choice | Why |
|---|---|---|
| Reverse proxy | **hyper 1.x** (+ hyper-util) | See below. |
| Multiplexing | **yamux 0.14** (libp2p) | Mature, very widely deployed, per-stream flow control (256 KiB window, auto-tuned) gives real backpressure; optimistic stream open (no extra round trip). |
| Agent transport | HTTPS + `Upgrade: magicpipes-mux/1` | Shares port 8443 with the API, goes through ordinary TLS terminators and firewalls, authenticated with a bearer token before the upgrade. WebSocket framing would only add overhead under yamux. |
| TLS | rustls 0.23 (ring provider) | Memory-safe, dynamic `ResolvesServerCert` for per-hostname certificates; ring avoids a C/CMake toolchain dependency. |
| ACME | instant-acme 0.8 | Low-level async ACME client: lets us control which hostnames get ordered, report per-hostname readiness and back off on failure. `rustls-acme` manages a fixed domain list, which does not fit tunnels being created at runtime. |
| Management API/UI | axum 0.8 | Same hyper stack; server-rendered HTML, no frontend build. |
| Persistence | rusqlite (bundled SQLite) | One file, no service; used only by the control plane. |
| CLI | clap 4 | |

### Why not Pingora

Pingora (0.9) was evaluated first. Its upstream side is built around connecting to a
`SocketAddr` peer. The custom L4 hook (`PeerOptions::custom_l4`, trait `connectors::l4::Connect`)
has to return Pingora's own `l4::Stream`, which wraps TCP or Unix sockets. Carrying the
connection over a yamux stream inside an agent session would mean wrapping virtual streams in
socket abstractions, or a loopback socket per request. Pingora also runs its own server and
runtime model (`run_forever`), which makes sharing one Tokio runtime with the control plane,
the agent gateway and axum awkward. Its TLS integration targets static or callback certificates
through BoringSSL/OpenSSL, with rustls still maturing there. And it had six RustSec advisories
at the time of evaluation: two critical request-smuggling issues in March 2026, plus HTTP/2
issues in Oct 2026 fixed in 0.8.1.

With hyper, the upstream is simply `hyper::client::conn::http1::handshake(stream)` over the
yamux stream. That runs a fresh, correct HTTP/1.1 client per request, and `hyper::upgrade` on
both sides handles WebSockets. Header parsing, chunked coding and upgrades stay in hyper; the
proxy logic (≈300 lines) only routes and rewrites hop-by-hop and forwarding headers.

## Data plane vs control plane

* `magicpipes-server/src/data/` is the data plane: public listeners, `RouteTable` lookup, proxying
  and stream bridging. It reads an immutable `Arc<RouteTable>` snapshot (one read lock to clone
  an `Arc`). It never touches SQLite, the API, or the control plane's mutex.
* `magicpipes-server/src/control/` is the control plane: the registry (`registry.rs`: tunnels,
  ports, readiness checks), agent sessions (`sessions.rs`), validation, persistence, certificate
  readiness and views for the API/UI (`views.rs`). Every mutation writes SQLite and then
  *publishes* a whole new `RouteTable` to the data plane (`DataPlane::publish`). That is the only
  interface between the two planes.
* `authz.rs` holds the one access decision, `authorize(principal, action, resource)`, used by
  both planes. Principals are the admin token, agents and anonymous public clients; actions are
  discover, connect and manage. The control plane checks it for every registry operation and
  filters every view with it. Each route carries an `AccessPolicy` (network allow-list, then
  `authorize`), which the data plane checks per HTTP request, TCP connection and UDP flow.
  Users and tags extend the same table ([USERS.md](USERS.md)); a check never bypasses it.
* `control/directory.rs` keeps who owns which agent and which tags everyone holds in memory,
  reloaded (`ControlPlane::refresh`) after every change to users, tags or agents, which also
  republishes. Each `RouteTable` carries the active users with their current tags, so the data
  plane decides private-tunnel access without the database, and a revocation applies on the
  next request.
* Private tunnels (`data/gate.rs`, `tunnel_auth.rs`): the management cookie never leaves the
  management host, so a private tunnel's host gets its own signed cookie (`__Host-mp_tunnel`,
  HMAC-SHA256 with `data_dir/session-key`) through a redirect to `/auth/tunnel` and a one-time,
  60-second code bound to a state cookie. Every request rechecks the cookie against the current
  table; the proxy strips MagicPipes' cookies and adds `X-MagicPipes-User`. Upgraded connections
  watch the table's generation and close when their user loses access.
* `certs/` belongs to the control plane. The `CertResolver` it fills is read by the TLS
  acceptors in the handshake; issuance never happens on the request path, and only for
  hostnames the control plane authorized.
* `gateway.rs` authenticates agent connections (control plane), runs the session, and attaches
  it to the registry, which republishes routes that now point at the session.
* Per-route counters (`RouteStats`, atomics) are written by the data plane and read by the
  control plane for status display.

A slow database write or UI render holds only the control-plane mutex. Established streams hold
their own yamux stream and are not affected by later route changes.

The agent is split the same way: `agent/session.rs` (control: connect, authenticate, ping,
reconnect, RPCs, restoring registrations) and `agent/forward.rs` (data: stream header, connect
to local target, bidirectional copy). `agent/ops.rs` sits on top of both.

## Static file tunnels (`add --serve`)

A tunnel's local target is a TCP service, a directory or a program in a terminal
(`state::Target`). For a
directory, `agent/forward.rs` acknowledges the data stream with `StreamStatus::Ok` and hands it to
`agent/serve/`, which runs hyper's HTTP/1 server directly on the yamux stream: no local port,
and no server-side change (to the server it is an ordinary HTTP tunnel; the stored target string
is `static:<path>`). tower-http's `ServeFile` writes file responses (content type, ranges,
conditional requests); `serve/mod.rs` decides which file and enforces the safety rules: GET/HEAD
only, hidden names refused, segment-wise percent-decoding that rejects `.`/`..`, separators and
NUL, and the canonical path must stay inside the canonical root (so symlinks leaving the root
are refused and not listed). Trailing-slash redirects are built from the validated segments, so
a `//host` path cannot become an open redirect. The readiness probe works unchanged.

`serve/kinds.rs` maps names to a kind (icon, open-in-browser or download) and a `Content-Type`;
text and source files are served as `text/plain; charset=utf-8` so browsers display them. The
listing (`serve/listing.rs`) uses the shared theme from `magicpipes-core::theme`, the same
stylesheet and mark as the management UI, and works without JavaScript; its small inline
script is allowed by a per-response CSP nonce. Bulk downloads (`serve/archive.rs`) are a POST
of the selected names to the directory URL, or `?archive` for a whole folder: a blocking task
writes tar + gzip (pure Rust `tar`/`flate2`) into a bounded channel that is the response body,
so archives of any size stream with flat memory and pause when the client stops reading.

## Web terminal tunnels (`add --shell`)

The third local target is a program run in a pty (`Target::Shell`: argv, working directory,
writable flag, write key, session limit). Like static files it is served inside the agent
(`agent/shell/`): hyper on the data stream, with upgrades enabled. `GET /` is the terminal page
(shared theme, CSP nonce), `/assets/*` are the vendored xterm.js 6 modules and stylesheet
(compiled into the binary, gzip-compressed once on first use) and Symbols Nerd Font Mono (WOFF2,
a fallback after the viewer's monospace font, limited by `unicode-range` to the Nerd Font icon
code points so it is fetched only when one is drawn), and `/ws` is the WebSocket. The
server proxies it like any tunnel WebSocket, so it needs no change.

Each WebSocket session starts its own copy of the program (`portable-pty`: openpty on Unix,
ConPTY on Windows), the ttyd model. The browser opens with a JSON hello carrying the terminal
size and, for writable tunnels, the key read from the URL fragment; afterwards binary messages
are input and JSON messages resize. Output flows back as binary messages, coalesced up to
64 KiB. pty reads, writes and the exit wait are blocking, so each has a thread and a bounded
channel: a slow viewer pauses the program's output rather than growing a buffer, and input is
dropped (not queued) if the program stops reading. Access is decided in the agent, never in the
page: read-only sessions have their input discarded; on writable tunnels a session without the
key (constant-time comparison) is refused before anything is spawned; `Origin` must match
`Host`; `max_clients` bounds concurrent sessions. Pings every 30 s keep idle sessions under the
server's WebSocket idle timeout.

A session ends when the browser goes away, the program exits (output still in flight is
forwarded for 300 ms, since a background process may hold the pty open, and ConPTY reports no
EOF), or the tunnel is removed or re-added with other settings: every tunnel has a cancellation
token that `Tunnels::upsert`/`remove` cancel when its target changes. Ending sends SIGHUP (as
when a terminal closes; the kernel then hangs up the foreground job), then SIGKILL after 2 s;
on Windows the process is terminated.

## Port tunnels (`add --tcp`, `--udp`)

A tunnel has an ingress **kind** (`http`, `tcp`, `udp`; `RegisterTunnel.kind`, the `tunnels.kind`
column) next to its local target. Port tunnels get a `public_port` from `[ports] range` instead of
a routed hostname; their hostname row still exists (names are unique across kinds) but never gets
a certificate or an HTTP route.

* **Allocation** (control plane): a requested `--remote-port` or a free port picked from a random
  starting point. The data plane binds it *before* the tunnel is stored, so a port another
  program holds fails the registration (`port_unavailable`) or is skipped. SQLite enforces one
  tunnel per (kind, port).
* **Listeners** (data plane, `data/ports.rs`): `DataPlane::publish` diffs `RouteTable.by_port`
  against the bound listeners, binding new ports and closing removed ones. Each TCP connection
  or UDP client looks its route up again, so allow-list changes and agent reconnects apply at
  once. A port stays bound while its agent is offline; connections are then closed at once.
* **TCP**: one `ServerOpen::Data` stream per connection, piped after the agent's status byte. No
  idle timeout (database and SSH sessions are long-lived); TCP keepalive drops vanished clients.
  An optional PROXY protocol v1/v2 header (`proxy_protocol`) supplies the client address behind
  a TCP load balancer; it is read only from `trusted_proxies`.
* **UDP**: one `ServerOpen::Datagram` stream per client address ("flow"), carrying `u16`-length
  framed datagrams both ways; the agent relays them through a connected UDP socket of its own,
  so replies reach the right client. Flows end after `udp_idle_timeout_secs` and are capped per
  tunnel (`udp_max_flows`); a full flow queue drops datagrams, as a congested network would.
* **Allow-lists** (`--allow-cidr`) are validated by the CLI, the agent and the server, stored in
  canonical form and enforced by the server on every connection and flow.
* **Readiness**: the `Check` RPC makes the server open a data (or datagram) stream for the tunnel
  and report the agent's status byte, so a missing local service fails the `add`. For TCP the
  agent then connects to the public port and waits for that connection to arrive as a stream;
  failure there is a warning (`reachable: false`), because some networks cannot reach their own
  public address.
* **Compatibility**: an old server ignores `kind` and would create an HTTP tunnel, so the agent
  checks the kind echoed in `TunnelInfo` (absent = `http`) and fails with `server_outdated`.
  Old agents never send `kind` and keep getting HTTP tunnels.

Planned target and ingress kinds (Unix sockets, SSH gateway, browser desktop) are described in
[ROADMAP.md](ROADMAP.md).

## Wire protocol

Defined in `magicpipes-core/src/proto.rs`. It is a yamux session over the upgraded connection.

* **Handshake**: the agent's upgrade request and the server's `101` carry
  `X-MagicPipes-Protocol: <version>` (`PROTOCOL_VERSION`, now 2). A peer without the header is
  version 1. Each side knows the other's version before sending anything, so a new feature can
  be skipped or refused with `server_outdated` / `agent_outdated` instead of misbehaving. Bump
  the version when a peer must know about a new request, stream type or field before using it,
  and document what the version adds next to the constant. `GET /api/v1/agents` shows each
  connected agent's `protocol`, and `magicpipes status --json` shows `server_protocol`.
* **Unknown messages are answered, not dropped** (version 2): a request the server cannot parse
  gets the error code `unsupported`, and a server-opened stream the agent cannot parse gets the
  status byte `3` (unsupported). Version 1 peers dropped them, which looked like a dead peer.
* **Agent-opened stream = one RPC**: a length-prefixed JSON `Request` (`Ping`, `Register`,
  `Unregister`, `CertStatus`, `Check`), answered with one `Response`. A stream per call means no request
  ids and no head-of-line blocking between RPCs.
* **Server-opened stream = data or push**: a `ServerOpen` frame. For `Data { tunnel_id }` the
  agent looks the id up in **its own** table, connects to the local target and writes one status
  byte (`StreamStatus`: `0` ok, `1` local unreachable, `2` unknown tunnel, `3` unsupported), then
  raw bytes flow both ways.
  `Datagram { tunnel_id }` is the same for one UDP client, followed by `u16`-length framed
  datagrams. `TunnelRemoved` tells the agent an administrator deleted a tunnel.
* The status byte is read lazily by the server (`StatusPrefixed`): the HTTP request is written
  immediately, so a successful request costs no extra round trip, but local connection failures
  are still attributed exactly (`local_unreachable` vs `upstream_error` vs `agent_offline`).
* **Error codes** are one enum, `magicpipes_core::error::ErrorCode`, with each code's HTTP
  status (API errors and server-generated pages) and CLI exit code. On the wire the code stays
  a string, so codes from a newer peer pass through unchanged.

## Readiness

`magicpipes add` drives `LOCAL → CONNECTED → REGISTERED → TLS_READY → PROBING → READY`
(`agent/ops.rs`), all under one deadline. The probe goes through the real public path: DNS (or
`MAGICPIPES_PROBE_ADDR`), TLS verified for the public hostname, the public listener, routing,
the yamux stream, the agent, the local application. It is accepted only if:

1. the response carries `x-magicpipes-probe-ack: <tunnel id> <nonce>`. The server adds this only
   to responses that came from the tunnel's upstream, and strips any `x-magicpipes-*` header an
   application sets, so infrastructure errors and impostor servers cannot produce it;
2. there is no `x-magicpipes-error` header (always present on MagicPipes-generated responses);
3. the agent's per-tunnel counter of streams that reached the local target increased.

Port tunnels replace the last two steps with `CHECKED` (the server's `Check` RPC) and, for TCP,
a connection to the public port that must arrive back at the agent (a warning, not a failure).

## Agent process lifecycle

* The CLI checks `agent.sock`. If nothing answers, it spawns `magicpipes agent run --detached`
  (`std::process::Command`; the only code between fork and exec is `setsid()`), with stdio
  redirected to `agent.log`. No Tokio runtime is ever forked: the new process builds its own.
* The agent takes an exclusive `flock` on `agent.lock`. Concurrent spawns lose the lock and
  exit 0; every CLI then connects to the single winner. Holding the lock proves any existing
  socket file is stale, so it is removed and re-bound.
* IPC is newline-delimited JSON over a Unix socket: mode 0600, inside a 0700 directory, and the
  peer's uid is checked against the agent's. On Windows it is a named pipe named after a hash
  of `MAGICPIPES_HOME`, created as the first instance (so no other process can own the name),
  rejecting remote clients and using the default pipe ACL (the creating user, SYSTEM and
  Administrators). The agent is started with `DETACHED_PROCESS`. All OS-specific code lives in
  `magicpipes-cli/src/platform.rs`. Operations: add, remove, list, status, shutdown
  (`if_idle` variant used to clean up an agent a failed `add` started).
* Registration is serialized inside the agent, so concurrent `add`s of one port yield one
  tunnel.
* Agent state (`tunnels.json`) is written atomically (temp file plus rename, mode 0600).

## Lifecycle policies

* **Route removal** (agent `remove`, admin delete): new requests get 404 immediately. In-flight
  requests and WebSockets on that tunnel run to completion; the agent also stops accepting new
  streams for it.
* **Agent revocation** (admin): the agent row and its tunnels are deleted in one transaction,
  the routes are unpublished (404) and the live session is closed. The agent's reconnect gets
  401 and it reports `unauthorized`. `attach_session` re-checks the agent under the registry
  lock, so a connection that authenticated just before the revoke cannot attach after it.
* **Agent disconnect**: routes stay registered and answer `502 agent_offline`. The server drops
  sessions without a ping for `session_timeout_secs` (default 45 s; agents ping every 15 s).
* **Agent reconnect**: the newest session of an agent replaces the old one. The agent
  re-registers every local tunnel by id (idempotent). A tunnel deleted on the server meanwhile
  returns `not_found` and is dropped locally.
* **Server restart**: tunnels persist in SQLite and cached certificates in `data_dir/certs`.
  Agents reconnect with exponential backoff (0.5 s → 30 s, ±20% jitter).

## Security model (Milestone 1)

* Credentials:
  * **admin tokens**: API bearer tokens and a UI login; always valid, whatever else is
    configured (break-glass);
  * **user passwords**: Argon2id (19 MiB, 2 iterations, 1 lane), at most 4 hashed at once on
    the blocking pool; an unknown email is checked against a throwaway hash so it takes as long
    as a wrong password. Administrator-set passwords must be changed at first sign-in;
  * **user API tokens** `tok_<id>.mpu_<secret>`, acting as their user with the user's current
    role, at most 20 per user, optional expiry;
  * **single-use enrollment tokens** with an expiry;
  * **per-agent tokens** `ag_<id>.<secret>`.

  A UI login becomes an HttpOnly, Secure, SameSite=Strict `__Host-` session cookie plus a
  per-session CSRF token on every form. Sessions are rows in SQLite (hash of the cookie): they
  survive restarts, at most 20 per user, and end on logout, "sign out everywhere"
  (`users.sessions_valid_after`), a password change, or when the user is disabled.

  Tokens have ~256 bits of entropy (session cookies too; CSRF tokens and web terminal keys
  ~190) and are stored as SHA-256 digests, compared in constant time. Failed logins and
  enrollments are rate-limited per client (IPv6 per /64, at most 10,000 tracked); valid
  credentials are accepted even from a rate-limited client, so nobody can lock an admin out.
  Passwords can be guessed, so each account also has its own limit, checked *before* the
  password: after 10 failures in 15 minutes, one attempt per 10 seconds (at most 10,000
  accounts tracked). That slows guessing without letting anyone lock an account out.
* Roles: `admin` and `member`, checked only through `authz::authorize`. Users can't change their
  own role or status. The audit log (bounded: 90 days by default, at most 100,000 rows) records
  sign-ins, failed sign-ins, account changes, tunnel deletions, agent revocations and
  enrollment tokens.
* The management UI, API and agent endpoint answer only for `management.hostname`: its TLS
  listener has no certificate for other names and returns 421 for another `Host`. Tunnels share
  the parent domain, so serving the UI under a tunnel's name would hand its cookie to that
  tunnel's application.
* Client addresses come from the TCP peer unless it is in `trusted_proxies`; then from its
  PROXY header (listeners with `proxy_protocol = true`) or the right-most untrusted
  X-Forwarded-For entry. Tunnels receive `X-Forwarded-For` rewritten accordingly; `Forwarded`
  and `X-Real-IP` from untrusted peers are dropped.
* Data streams need no separate credential: the server opens them only on the authenticated
  session of the agent that owns the tunnel, and the agent only dials targets from its own table.
  The server can name a tunnel, never an address.
* Hostname ownership: names are unique, tied to one agent, validated (DNS label rules, reserved
  names, management hostname). Another agent cannot register or query them.
* Private HTTP tunnels admit their owner and users sharing one of their access tags (exact
  match), after signing in; administrators manage them but don't get in through their role.
  A tunnel's effective access is its requested tags limited to its agent's tags, and a personal
  agent's tags are limited to its owner's, so nobody can widen access by tagging their own
  machine. Visibility and access stored in a form that can't be read keep the tunnel private.
  Members enroll only their own machines, with tags they hold; an owner may remove tags from
  their machine but not add any.
* Port tunnels are open to anyone unless `--allow-cidr` is given (the CLI says so). The server
  enforces allow-lists on every connection, and an allow-list it cannot read keeps the tunnel
  unpublished (fail closed); behind a TCP proxy, only `proxy_protocol` with `trusted_proxies`
  makes the checked address the client's. Raw ports are bounded by `[ports] max_connections`
  (TCP), `udp_max_flows` per tunnel and `max_ports_per_agent`.
* No open proxy: `CONNECT` is refused, absolute-form URIs must match `Host`, and the TLS SNI must
  equal the `Host` header (421 otherwise). Unknown hostnames get no certificate at all, since
  certificates are never issued on demand from SNI.
* Bounded resources: connection semaphores per listener and per client address, header read
  and TLS handshake timeouts, a 15 s deadline and 64 KiB body limit for management requests,
  64 KiB control frames and IPC lines (5 s to send one), ≤256 concurrent streams per agent
  session of which public traffic may use 224 (64 per client), so pings and RPCs always get
  through; `max_tunnels_per_agent`, `max_new_certificates_per_day` per agent, at most two
  concurrent ACME orders, per-hostname failure backoff; at most 8 archive downloads at once
  per agent, each dropped after 60 s without reading.
* Secrets are never logged. The bootstrap admin token goes to a 0600 file, not to the log.
* The server sees only what it needs about local targets: the program name of a web terminal
  (not its arguments) and the folder name of a static site (not its path). The public terminal
  page shows the program name only. The write key moves from the link's fragment into the
  tab's `sessionStorage` and out of the address bar.
* The server terminates TLS, so its operator can see tunnel traffic, including a web terminal's
  write key. Run writable terminals only through a server you trust.
* `tls.mode = "dev-ca"` creates a CA name-constrained to `base_domain` and the management
  hostname, so trusting it cannot vouch for other sites (CAs created before this was added are
  unconstrained; delete `data_dir/dev-ca` to replace one).
* Public tunnels are anonymous by design; this is stated in the CLI output, the UI and the README.

## Known limitations

* **ACME** is covered by the default suite only through the failure test (unreachable CA →
  `tls_failed`). The success path is covered by the opt-in `acme_with_pebble` test, which needs
  Docker. On 2026-10-28 it passed against Pebble with real HTTP-01 validation: account
  registration, order, challenge served by `magicpipesd`, finalize, download, on-disk cache, no
  reissue after a restart. A validation failure (nothing listening on the challenge port) was
  reported as `tls_failed` with the CA's reason. Let's Encrypt itself has not been tried; run
  the acceptance test below once on a real domain.
* Per-hostname certificates, so the first `add` of a new name waits for one ACME order (a few
  seconds with Let's Encrypt). Wildcard certificates via DNS-01 are planned for a later
  milestone (Cloudflare integration); `tls.mode = "files"` covers wildcard certs today.
* Public side is HTTP/1.1 only (ALPN `http/1.1`); no HTTP/2 or HTTP/3 yet.
* One TCP connection per agent: yamux streams share it, so a lossy link causes head-of-line
  blocking across tunnels of that agent. UDP tunnels ride the same TCP connection, so they
  inherit its retransmissions and ordering (poor for VPNs and real-time media).
* At most 256 streams per agent session: HTTP requests in flight, TCP connections and UDP
  clients together.
* There is no body idle timeout for regular HTTP requests, only a time-to-first-response timeout.
  Upgraded (WebSocket) connections have an idle timeout.
* UI sessions live in memory; restarting the server logs administrators out.
* Read-only web terminals are anonymous: anyone with the link can hold one of its
  `--max-clients` sessions for as long as they keep the page open.
* Each agent session may buffer up to 128 MiB of yamux receive window, and UDP flow queues are
  bounded by datagram count (64 per flow), not bytes.
* Windows IPC relies on `first_pipe_instance` and the default pipe ACL. Another local user who
  creates the pipe name first could receive the CLI's requests; an explicit owner-only ACL and
  a server-owner check are still to do.
* Windows support is newer and less tested than Unix: it is covered by the CI smoke test on a
  Windows runner (login, `add`, a public request, `agent stop`), not by the full end-to-end
  suite, which is Unix-only. Files in `%USERPROFILE%\.magicpipes` rely on the profile's
  default ACL rather than explicit permissions.
* One server node, one agent per tunnel; no load balancing.
* The `Host` header is forwarded unchanged; dev servers with host allow-lists must allow the
  public hostname.

## Production acceptance test (real certificates)

On a server with `*.t.example.com` and `example.com` pointing at it, and ports 80/443/8443 open:

1. Start `magicpipesd` with `tls.mode = "acme"` and `acme_directory = "letsencrypt-staging"`.
2. On a machine behind NAT: `magicpipes login --server https://example.com:8443 --token ...`.
   Staging certificates are not publicly trusted, so for the staging run pass `--ca-cert` with
   the Let's Encrypt staging roots.
3. `python3 -m http.server 8080 & magicpipes add 8080 --json`. Expect exit 0 and a
   `public_url`.
4. `curl -v <public_url>` from a third network, then a WebSocket client (`websocat
   wss://<name>.t.example.com/`) against a local echo server registered with `magicpipes add`.
5. Check `data_dir/certs/<host>.crt`, restart `magicpipesd` and confirm no new order in the log.
6. Switch to `acme_directory = "letsencrypt"`, delete `data_dir/acme-account.json` and
   `data_dir/certs/`, rerun 2–4 without `--ca-cert`, and confirm a browser shows a valid
   certificate.
7. Break port 80 (firewall), `magicpipes add 9090 --name broken`: expect exit 7,
   `certificate provisioning failed`, and no URL printed.
