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
* `magicpipes-server/src/control/` is the control plane: the registry (tunnels, agent sessions),
  validation, persistence, certificate readiness and views for the API/UI. Every mutation
  writes SQLite and then *publishes* a whole new `RouteTable` to the data plane
  (`DataPlane::publish`). That is the only interface between the two planes.
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

## Wire protocol

Defined in `magicpipes-core/src/proto.rs`. It is a yamux session over the upgraded connection.

* **Agent-opened stream = one RPC**: a length-prefixed JSON `Request` (`Ping`, `Register`,
  `Unregister`, `CertStatus`), answered with one `Response`. A stream per call means no request
  ids and no head-of-line blocking between RPCs.
* **Server-opened stream = data or push**: a `ServerOpen` frame. For `Data { tunnel_id }` the
  agent looks the id up in **its own** table, connects to the local target and writes one status
  byte (`0` ok, `1` local unreachable, `2` unknown tunnel), then raw bytes flow both ways.
  `TunnelRemoved` tells the agent an administrator deleted a tunnel.
* The status byte is read lazily by the server (`StatusPrefixed`): the HTTP request is written
  immediately, so a successful request costs no extra round trip, but local connection failures
  are still attributed exactly (`local_unreachable` vs `upstream_error` vs `agent_offline`).

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

* Three separate credentials:
  * **admin tokens**: API bearer tokens, and the UI login, which becomes an HttpOnly, Secure,
    SameSite=Strict session cookie plus per-session CSRF tokens on every form;
  * **single-use enrollment tokens** with an expiry;
  * **per-agent tokens** `ag_<id>.<secret>`.

  All have ≥256 bits of entropy and are stored as SHA-256 digests, compared in constant time.
  Failed logins and enrollments are rate-limited per IP.
* Data streams need no separate credential: the server opens them only on the authenticated
  session of the agent that owns the tunnel, and the agent only dials targets from its own table.
  The server can name a tunnel, never an address.
* Hostname ownership: names are unique, tied to one agent, validated (DNS label rules, reserved
  names, management hostname). Another agent cannot register or query them.
* No open proxy: `CONNECT` is refused, absolute-form URIs must match `Host`, and the TLS SNI must
  equal the `Host` header (421 otherwise). Unknown hostnames get no certificate at all, since
  certificates are never issued on demand from SNI.
* Bounded resources: connection semaphores per listener, header read and TLS handshake
  timeouts, 64 KiB control frames and IPC lines, ≤256 concurrent streams per agent session,
  `max_tunnels_per_agent`, at most two concurrent ACME orders, per-hostname failure backoff.
* Secrets are never logged. The bootstrap admin token goes to a 0600 file, not to the log.
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
  blocking across tunnels of that agent.
* There is no body idle timeout for regular HTTP requests, only a time-to-first-response timeout.
  Upgraded (WebSocket) connections have an idle timeout.
* UI sessions live in memory; restarting the server logs administrators out.
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
