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
| Allocator (server, static Linux builds) | mimalloc, `secure` | musl's allocator takes a global lock; see "Threads and memory". |
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
yamux stream: a correct HTTP/1.1 client connection, which later requests reuse (see "Upstream
connection reuse"), and `hyper::upgrade` on both sides handles WebSockets. Header parsing, chunked coding and upgrades stay in hyper; the
proxy logic (≈300 lines) only routes and rewrites hop-by-hop and forwarding headers.

## Upstream connection reuse

An HTTP request goes over an HTTP/1.1 connection to the agent, which the agent connects to the
application. Opening one per request cost a stream round trip, a TCP connect and, under load,
the agent's local ports: every closed connection to the application holds its port for about a
minute, which capped one tunnel at roughly 470 new connections a second (the 2026-11-03
benchmark against kiku also showed half of Caddy's throughput). So `data/pool.rs` keeps idle
connections:

* A connection returns to the pool once its response has been read to the end; a response cut
  short, an error or a timeout closes it instead. hyper decides whether the connection can carry
  another request (`SendRequest::ready`), so `Connection: close` from the application is honored.
* A pooled connection is reused only for the same tunnel, on the same agent session and tunnel
  version (`Route::version`, bumped when the tunnel's settings change), so a reconnected agent or
  a re-registered target starts over, while changes to other tunnels cost nothing. Local settings
  the server never sees (a static site's `--no-list`) end the agent's HTTP and
  static-file streams for that tunnel (`Entry::ended`), so the server's next request opens a
  fresh one rather than reaching the old settings.
* If the application closed an idle connection just as it was taken, hyper hands the request
  back unsent (`try_send_request`) and it goes over a new connection; a request is never sent
  twice.
* Upgrades (WebSockets) and the agent's readiness probe get a connection of their own, as before:
  an upgrade keeps its stream, and the probe checks that the agent opened a stream for it.
* Requests from different visitors take turns on a connection, as behind any reverse proxy, so
  applications must not tie authentication to the TCP connection (NTLM-style).
* Bounds: at most 224 idle connections per tunnel (as many as can be in flight, or a busy tunnel
  closes connections only to reopen them, until the agent runs out of local ports) and 4096 in
  total, each idle for at most 4 s (shorter than most applications' keep-alive), swept every 2 s.
  Idle connections count toward the session's 224 data streams but not toward any client's 64; a
  request holds its client's place until its response body is done. When a session's streams are
  used up, idle connections on it are closed to make room, for pooled requests, WebSockets and
  port connections alike.

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

A slow database write or UI render holds only control-plane threads (see "Threads and memory").
Established streams hold their own yamux stream and are not affected by later route changes.

The agent is split the same way: `agent/session.rs` (control: connect, authenticate, ping,
reconnect, RPCs, restoring registrations) and `agent/forward.rs` (data: stream header, connect
to local target, bidirectional copy). `agent/ops.rs` sits on top of both.

## Threads and memory

The server has two Tokio runtimes (`main.rs`), because the control plane blocks: SQLite (with a
5 s busy timeout and, by default, an fsync per commit), the registry mutex, building route tables.

* **Traffic threads** (one per core) own every socket: listeners, TLS, public connections,
  management connections, and each agent's yamux session. Nothing on them waits on the database.
* **Control threads** (`CONTROL_THREADS`, 2) run management handlers, agent RPCs, certificate work
  and the control plane's timers. Writes go one at a time anyway, so more threads wouldn't speed
  them up, and they would compete with traffic for processor time.
* The crossings are few. `mgmt::serve_mgmt` runs each management request's handler on the control
  threads while its connection stays on the traffic threads. Control-plane code that creates
  something for the data plane (a port's listener, an agent's session) goes through
  `on_traffic_threads`, because a Tokio socket belongs to the runtime it was created on and a
  spawned task stays on it. A socket on the control threads would stop moving whenever they block.

Measured with 2 traffic threads, 1000 tunnels and 8 clients changing a tag in a loop, a tunnel on
Linux went from 696 to 67,600 requests a second, and from 23 ms to 0.2 ms at the median. Before
this split, a stuck database stopped all tunnels (`a_stuck_database_does_not_hold_up_tunnels`).

SQLite stays at `synchronous = FULL`: losing the last commits to a power failure could bring back
a revoked token, and with commits off the traffic threads their cost no longer reaches tunnels.

An agent's session is one TCP connection shared by all its streams, and three things decide how
well it carries them (`magicpipes-core/src/mux.rs`):

* **Batched writes** (`Batched`, 64 KiB per session). yamux writes a frame's header and body
  separately and flushes after each frame, which over TLS is two records and two system calls per
  frame. Frames are collected instead, and go out when yamux reads next, which it does only once it
  has nothing more to send. A full batch goes out at once.
* **64 KiB copy buffers** (`COPY_BUFFER`, per direction, so 128 KiB per bridged or forwarded
  connection instead of 16; at most about 29 MB per session on each end at 224 streams).
* **A limit on the kernel's send queue** (`SEND_QUEUE`, `TCP_NOTSENT_LOWAT`, 128 KiB; Linux on both
  ends, and macOS agents). Unlimited, it grows to about 4 MB, which on a slow link is seconds of a
  download that every other request on the session has to wait behind.

The server's static Linux builds use mimalloc rather than musl's allocator, which takes a global
lock around every allocation. In `secure` mode (guard pages and encoded free lists, since this
process faces the internet and holds C code; about 2% slower than without). It's musl only:
macOS's allocator measured the same, and it isn't for the agent, whose memory after load went from
6 MB to 130–460 MB with it, because the blocking threads of a static site's traffic leave their
heaps behind. On the server it costs memory too: about 30 MB idle instead of 10, and up to about
100 MB kept after heavy load instead of 10.

Measured on a 4-core Linux VM holding the client, server, agent and application, with static musl
binaries, so these numbers are only relative. [`scripts/bench`](../scripts/bench/README.md) repeats
these measurements. The last two rows shape the agent's connection with
`netem`, as a home or office uplink would:

| | Before | After |
|---|---|---|
| Small requests, 16 at once | 57,900/s | 74,700/s |
| Small requests, 150 at once | 78,300/s | 117,200/s |
| 64 KiB responses, 16 at once | 540 MB/s | 846 MB/s |
| One download | 834 MB/s | 1,264 MB/s |
| Two downloads, with small requests alongside at a median of 2 ms in both | 720 MB/s | 1,243 MB/s |
| Small request during a download, 100 Mbit/s, 20 ms round trip, median | about 290 ms | about 195 ms |
| Small request during a download, 20 Mbit/s, 30 ms round trip, median | about 750 ms | about 365 ms |

Downloads on those two links ran at the same speed before and after. What remains of the wait there
is the link's own queue, which a server can't shorten.

Measured, and not worth doing:

* LTO with one codegen unit: no change in throughput on macOS, though binaries are 23% smaller.
* A 64 KiB `BufReader` under TLS (slightly worse), TLS session resumption (about 7% on new
  connections) and fewer allocations in the proxy (they barely register in a profile).
* Batches or copy buffers under 64 KiB: they move less, and don't shorten a small request's wait
  during a download.
* A different `SEND_QUEUE`: anything from 32 to 256 KiB behaved the same.
* `sendfile`: impossible through TLS and yamux.

Known costs, left as they are for now:

* `publish` is linear in tunnels and users (6.8 ms at 10,000 tunnels), and a reconnecting agent
  publishes once per registration.
* A request over the stream budget gets a 503 at once, rather than waiting briefly for a stream.
* Static files hand off to the blocking pool for each read (`ServeFile`): about 20,000 small files
  a second on that VM, against 75,000 proxied requests.
* The UI has no compression or pagination, which starts to matter at thousands of tunnels (9 MB
  and 46 ms for the home page at 10,000).
* No HTTP/2 toward browsers, so they open several connections.
* A 64 KiB yamux frame size gave about 18% more on a Mac, and hasn't been measured on Linux.

## Management UI

Server-rendered pages (`mgmt/`) with one small script, which only enhances them. The aims are that
someone can always tell where they are, whether things are working, and what their last action did.

* **Where you are:** the navigation marks the current section (`aria-current`).
* **Whether things are working:** the home page leads with one line, such as "All 5 tunnels are
  healthy" or "1 machine offline · 1 certificate failed". A machine with no tunnels isn't a problem
  for being off. From nothing, it shows the three steps to a first tunnel instead.
* **What just happened:** a change redirects to `?done=<key>`, and that page shows the key's fixed
  message. Keys rather than text, so a link can't put words on the page; `ui.js` then drops it from
  the address, so reloading doesn't repeat it. This keeps the redirect after a POST that makes
  reloading safe, without a flash cookie to store.
* **What went wrong:** a form that fails comes back with what was typed (never a password), the
  message beside it, its field marked `aria-invalid` and focused, and "Error:" in the title.
* **Before anything that can't be undone:** a question that names the effect, in a dialog whose
  button says what it does (`ask` in `ui.js`). Cancel has the focus. Without scripts these go ahead
  straight away.
* **Tags** are small chips that wrap, in the shape the tag picker uses. A row of the Tunnels list
  shows three and "+N more" (a person's own access first), since seven once pushed the rest of the
  list off the page; the tunnel's page, Users and Machines show them all. To leave them room, the
  list puts a tunnel's local target under its machine, and mentions its certificate only when it
  isn't ready.
* **Words:** a *machine* is what people enroll and see; the *agent* is its background process; a
  *service agent* is a machine nobody owns. Tunnels and machines have a page each, like Tailscale's
  Machines or Pangolin's sites and resources. `/agents/...` form addresses and the API keep their
  names, since scripts rely on the API.

A handler says what it needs in its signature (`mgmt/extract.rs`), so a check can't be left out:
`UiUser` to look, `AdminUser` for what only administrators see, `Posted<T>` and `AdminPosted<T>` to
change something, which check the CSRF token before the handler runs. `authorize` still decides
what each one may do. Markup that pages share is in `mgmt/html.rs`, and `theme.rs` lists the few
type sizes and corner radii a new rule picks from. No management page uses a `style` attribute.

`ui.js` is served with a digest in its address and cached for good, so moving between pages doesn't
fetch it again, and a new version still arrives at once.

## Settings: the file, the database and the generated copy

Settings have two homes, because neither can hold everything:

* **The configuration file** holds what's needed before the database opens, or what could lock an
  administrator out of the page that would fix it: listeners, domains, the TLS mode, `data_dir`,
  trusted proxies. It's read once and never written; in Docker it's a read-only mount in a read-only
  container.
* **The database** holds what the Settings page changes: OpenID Connect providers and the two
  lists of who a first sign-in may create an account for (`control/settings.rs`). Certificates are
  the exception, kept only as files (below). A change is
  validated, saved and audited like any other, then the providers and lists in effect are replaced
  whole. There's no restart, and a sign-in under way keeps the provider it started with. This is
  management-side only: the data plane never sees any of it.

What's in effect is the two together. A file's provider wins over a saved one of the same id and is
locked on the page; lists are combined. The file can't be overruled, so someone who manages servers
declaratively stays in charge, and a generated file can start another server.

**`<data_dir>/magicpipesd.generated.toml`** is a copy of the settings in effect, written (0600,
atomically) at startup and after every change. It's output only: nothing reads it back, so it can't
disagree with what the server does, and a failed write is only logged. A round-trip test holds it to
parsing back to the same settings. The file name differs from the usual one so it can't overwrite a
configuration file kept in `data_dir`.

**Client secrets** must be readable, so they can't be digests. They're files under
`<data_dir>/oidc-secrets/` (0600 in 0700), like `session-key` and the file's own `client_secret_file`,
named by the provider's validated id. They're never shown again, and aren't in the database or the
generated copy. A saved provider whose secret can't be read is left out with an error in the log,
and the page says so; a file's provider with a missing secret stops startup, as a configuration
mistake.

**Certificates added on the page** are files under `<data_dir>/provided-certs/` (0600 in 0700), named
by a digest of the certificate, and the directory is the only record of them. A private key is never
shown again, and a form that fails doesn't give back a certificate box with a key pasted in it. The
generated copy names their files like any other `[[tls.certificates]]`. One that can't be read at
startup stays listed so it can be removed, and costs nothing else; one in the configuration file that
can't be read stops startup.

**Bounds:** 32 saved providers, 500 entries per list, and the request limits of the management
listener. Adding a provider asks it about itself first: at most two requests of 4 s and 256 KiB,
sharing the limit of 16 exchanges with sign-ins. Only administrators can trigger this, and the only
thing shown from the answer is the issuer it states, escaped and at most 2 KiB.

Provider ids and issuers can't be edited: the callback URL depends on the id, and identities on the
issuer, which is unique among saved providers for the same reason.

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

The check can't be separated from the read. `open_servable` resolves the path, then opens the real
path one component at a time from a descriptor of the root, with `O_NOFOLLOW` and `O_NONBLOCK`
(`platform::open_beneath`): a component swapped for a symlink since the check makes the open fail,
and a FIFO can't block it. File contents are read through the open handle: `ServeFile` only takes
paths, so it gets one that reaches the handle (`platform::handle_path`: `/proc/self/fd/N` on Linux,
`/dev/fd/N` on macOS). A folder is read by its path, because on macOS 15 it reads as empty through
`/dev/fd`. That gives nothing away, since a listing shows an entry only if its own resolved path is
inside the root, and a download opens each one with `open_servable`; a folder that can't be read
answers 500, never an empty listing. Windows has no such path and no relative open in std, so there
only the last component is protected (symlinks need privileges there). An archive entry is exactly the size in its header (`archive::exactly`): bytes appended while it's being read
would otherwise be read as further entries.

HTML, SVG and XML get `Content-Security-Policy: sandbox` without `allow-scripts` unless the tunnel
has `--site`, so a file in a shared folder can't read the rest of it with a visitor's session. It
keeps `allow-same-origin`, which with scripts off only means that a page's own styles and images
load with the session cookie, as a private tunnel needs. A `tunnels.json` from before `--site`
reads as `site: true`, so an upgrade doesn't break a site being served. `check_root` refuses folders
nobody usually means to publish whole unless `--allow-sensitive-root` is given.

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
`Host`; `max_clients` bounds the programs running at once, since a session's place is given back
only once its program has gone, and a tunnel starts at most 60 programs a minute, because each
visit runs the program and its login scripts and read-only visitors are anonymous. Pings every
30 s keep idle sessions under the server's WebSocket idle timeout.

A session ends when the browser goes away, the program exits (output still in flight is
forwarded for 300 ms, since a background process may hold the pty open, and ConPTY reports no
EOF), or the tunnel is removed or re-added with other settings: every tunnel has a cancellation
token that `Tunnels::upsert`/`remove` cancel when its target changes, which a viewer that stopped
reading can't hold up. Ending sends SIGHUP (as when a terminal closes; the kernel then hangs up the
foreground job), then SIGKILL after 2 s; on Windows the process is terminated.

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
  tunnel (`udp_max_flows`, of which one client address may hold an eighth); a full flow queue
  drops datagrams, as a congested network would.
* **Changes apply to open connections**: on every publish, open TCP connections and UDP flows
  check their tunnel again and close if it is gone or its allow-list no longer admits them. A
  port outside the current `[ports] range` is not opened (after the range is narrowed or
  removed), and the server logs it at startup.
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
  `X-MagicPipes-Protocol: <version>` (`PROTOCOL_VERSION`, now 4: 2 added the handshake and
  answers to unknown messages, 3 visibility and tags, 4 custom hostnames). A peer without the header is
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
  requests on that tunnel run to completion; the agent also stops accepting new streams for it.
* **Long-lived connections** (WebSockets, port connections) are checked again on every publish,
  public tunnels' included, and closed once the tunnel no longer admits them, for example when it
  turns private, or is removed. A removed tunnel's WebSockets get 2 s for the agent to end them
  first, so a web terminal can tell its viewers. Requests are short, and aren't interrupted.
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
* **Tag edits in the UI** send the tags the page showed (`base`) and the tags wanted; the
  control plane applies only the difference to what is stored now (`change_user_tags`,
  `change_agent_tags`, service agents only), reading and writing under the state lock. Personal
  tags never appear in the picker and survive every edit. Two administrators changing
  different tags of the same user at once both keep their change. The API's `PATCH … {tags}`
  still replaces the whole list. Tags an administrator makes up in the picker travel as
  `create` fields and are registered just before the change (`Submitted::create_missing`). The picker dialog (`mgmt/ui.js`) is an enhancement over a page
  of checkboxes at the same URL, so the UI still works without JavaScript; the tag registry
  reaches it as a JSON data block, which the CSP doesn't treat as a script.

## Security model (Milestone 1)

* Credentials:
  * **admin tokens**: API bearer tokens and a UI login; always valid, whatever else is
    configured (break-glass);
  * **user passwords**: Argon2id (19 MiB, 2 iterations, 1 lane), at most 4 hashed at once on
    the blocking pool; an unknown email is checked against a throwaway hash so it takes as long
    as a wrong password. Administrator-set passwords must be changed at first sign-in;
  * **single sign-on** with OpenID Connect providers (`oidc.rs`, `control/oidc.rs`,
    `mgmt/oidc.rs`): the authorization code flow with PKCE and an exact redirect URI. State,
    nonce, verifier and destination travel in a signed 10-minute `__Host-mp_oidc` cookie, so
    abandoned sign-ins cost the server nothing and a callback only works in the browser that
    left. ID tokens are verified with `ring`, RS256 and ES256 only, against the issuer, audience
    (`azp` too when there are several), expiry and nonce. Metadata is fetched on first use and
    kept for an hour, at most once a minute while it's in hand (every 5 s while it isn't). Each
    request to a provider has 4 s and 256 KiB, redirects aren't followed, at most 16 code
    exchanges run at once, and a failed exchange counts against the client's failure limit, which
    is checked before the next one. Providers must be HTTPS (plain HTTP to this machine only, for
    tests). GitHub (`github.rs`) is the same flow without the OpenID Connect parts: there's no ID
    token, so who someone is comes from its API over TLS with the token the code buys, which isn't
    kept. A provider's `kind` says which it speaks. This is control-plane work; nothing here is on
    the data path. Who gets in is described in the README: accounts are keyed by `(issuer, subject)`, and only a verified
    email (any address, on a provider an administrator marked `trust_email`) can create or link
    one;
  * **an authenticating proxy** (`proxy_auth.rs`, `mgmt/proxy_auth.rs`), if configured: a signed
    token, checked as an ID token is but without a nonce, or a plain header from a
    `trusted_proxies` address with a shared secret. A header sent twice counts as nobody. A layer
    in front of the page handlers turns that into a normal session, and every page request must
    keep naming the session's user, or the session ends. So passwords and providers aren't offered,
    whose sessions couldn't last; admin-token sessions don't depend on it. Accounts follow the
    same rules as single sign-on (`control/oidc.rs`). A refusal is only logged, since every page
    request would otherwise add to the audit log;
  * **user API tokens** `tok_<id>.mpu_<secret>`, acting as their user with the user's current
    role, at most 20 per user, optional expiry;
  * **single-use enrollment tokens** with an expiry;
  * **per-agent tokens** `ag_<id>.<secret>`.

  A UI login becomes an HttpOnly, Secure, SameSite=Lax `__Host-` session cookie plus a
  per-session CSRF token on every form (Lax, so a private tunnel on another site can send the
  browser here to sign in). The management CSP has `form-action 'self'`, which browsers apply to
  a form's redirects too, so a form never redirects off the management host: sign-in continues
  to a tunnel through a page that navigates on its own. It also allows `img-src 'self'`,
  for the favicons (`mgmt/assets/`). Sessions are rows in SQLite (hash of the cookie): they
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
  names, management hostname). Another agent cannot register or query them. A custom hostname
  (`add --hostname`) must first be registered by an administrator for one user's machines or one
  service agent (`control/hostnames.rs`, checked with `authorize` on `Resource::Hostname`; a
  personal agent asks as its owner, without an administrator's role). It is an exact name, not
  the management hostname, the base domain or a `<name>.<base_domain>` tunnel name, and with the
  development CA it must be under the base domain (the CA is name-constrained). Removing the
  registration deletes the tunnel on it.
* Private HTTP tunnels admit users who share a tag with them that grants access (exact match),
  after signing in, and nobody else: owners get in through their personal tag (`user:…`), which
  the server puts on every tunnel of their machines; administrators manage tunnels but don't
  get in through their role. Only administrators assign tags to people and service agents, and
  a tunnel can carry only ordinary tags its publisher holds (its owner's, or a service agent's
  own), checked on every registration that names tags, so nobody can widen access by tagging
  their own tunnel, and turning a tag's access on opens nothing to a group the owner isn't in.
  Anyone's personal tag may go on a tunnel, to share it with that person. Personal tags are
  random (`user:k8p4x2m9qa`), held only by their user, always grant access, and go only with the
  account. A tunnel's tags are its own: removing a tag from its owner doesn't unshare it. A tag the directory doesn't know grants nothing; a visibility stored in a form
  that can't be read keeps the tunnel private. Members enroll only their own machines, which
  have no tags of their own.
* A new port tunnel needs `--allow-cidr` or `--allow-any`, and re-adding keeps its list (the CLI
  decides this, so a modified one can still ask for an open port: it's a safeguard for its user, not
  a limit on them). UDP allow-lists aren't authentication, since a source address can be forged. The server
  enforces allow-lists on every connection, and an allow-list it cannot read keeps the tunnel
  unpublished (fail closed); behind a TCP proxy, only `proxy_protocol` with `trusted_proxies`
  makes the checked address the client's. Raw ports are bounded by `[ports] max_connections`
  (TCP), `udp_max_flows` per tunnel and `max_ports_per_agent`.
* No open proxy: `CONNECT` is refused, absolute-form URIs must match `Host`, and the TLS SNI must
  equal the `Host` header (421 otherwise). Unknown hostnames get no certificate at all, since
  certificates are never issued on demand from SNI.
* Bounded resources: connection semaphores per listener and per client address (held by the
  connection's task on every listener, and by a proxied WebSocket for as long as it lasts; an
  agent's authenticated session gives its place back once upgraded), header read
  and TLS handshake timeouts, a 15 s deadline and 64 KiB body limit for management requests,
  64 KiB control frames and IPC lines (5 s to send one), ≤256 concurrent streams per agent
  session of which public traffic may use 224 (64 streams or in-flight requests per client;
  idle pooled HTTP connections count toward the 224, see "Upstream connection reuse"), so pings and RPCs always get
  through; one 64 KiB write batch per session and 64 KiB copy buffers per direction per connection; `max_tunnels_per_agent`, `max_new_certificates_per_day` per agent, at most two
  concurrent ACME orders, per-hostname failure backoff (renewals included); at most 8 archive
  downloads at once per agent, each dropped after 30 s without reading or, after its first 30 s,
  when it averages under 16 KiB/s; at most 5000 names in a selection. Upgraded (WebSocket)
  connections keep their listener's connection slots until they close. Used private-tunnel
  sign-in codes are remembered per user (32 per minute each), so one account can't use up
  everyone's sign-ins; pending device logins are capped at 5 per address and 1000 in total, and
  a full table drops a waiting login of the address holding the most rather than refusing.
* Certificates: the control plane tells the certificate manager which hostnames it serves on
  every publish, registered custom hostnames included (with or without a tunnel). Others are no
  longer renewed, and are forgotten (resolver and cache) after a week, so a hostname removed and
  added again soon keeps its certificate. Registering a custom hostname orders its certificate
  at once, so it can be ready before traffic moves over. Your own certificates are bounded too: 64
  on the Settings page, 64 in the configuration file, 64 KiB of PEM each.
* Secrets are never logged. The bootstrap admin token goes to a 0600 file, not to the log.
* The server sees only what it needs about local targets: the program name of a web terminal
  (not its arguments) and the folder name of a static site (not its path). The public terminal
  page shows the program name only. The write key moves from the link's fragment into the
  tab's `sessionStorage` and out of the address bar.
* The server terminates TLS, so its operator can see tunnel traffic, including a web terminal's
  write key, and could use it, or add a script to the terminal's page. So `--write` means trusting
  the server with a shell as you, which the agent's other rules otherwise never do, and the CLI
  says so. Only end-to-end encryption would change that. Run writable terminals only through a
  server you trust.
* Cookies don't cross tunnels: `Domain` is taken off an application's cookie when it would reach
  the base domain or the management host (`public.allow_cookie_domain` turns this off), since one
  tunnel could otherwise log visitors in to another as someone else, or lock them out of the
  management UI with oversized headers. A Public Suffix List entry for a shared base domain makes
  browsers enforce the same thing.
* `tls.mode = "dev-ca"` creates a CA name-constrained to `base_domain` and the management
  hostname, so trusting it cannot vouch for other sites (CAs created before this was added are
  unconstrained; delete `data_dir/dev-ca` to replace one).
* Public tunnels are anonymous by design; this is stated in the CLI output, the UI and the README.
* The agent serves only what it added: when restoring after a reconnect, a tunnel the server
  registered differently (public instead of private, an HTTPS hostname instead of a raw port)
  is withdrawn locally, so its streams are refused even if removing it on the server fails.
* `POST /login` is refused when the browser says it came from another site (`Sec-Fetch-Site`,
  `Origin`), so a third-party page can't sign a browser into the attacker's account. An agent
  missing from the in-memory directory gets the narrowest enrollment settings (private only).

## Known limitations

* **ACME** is covered by the default suite only through the failure test (unreachable CA →
  `tls_failed`). The success path is covered by the opt-in `acme_with_pebble` test, which needs
  Docker. On 2026-10-28 it passed against Pebble with real HTTP-01 validation: account
  registration, order, challenge served by `magicpipesd`, finalize, download, on-disk cache, no
  reissue after a restart. A validation failure (nothing listening on the challenge port) was
  reported as `tls_failed` with the CA's reason. Let's Encrypt issues certificates for a live
  deployment too, but the acceptance test below hasn't been run from start to finish.
* Per-hostname certificates, so the first `add` of a new name waits for one ACME order (a few
  seconds with Let's Encrypt). Wildcard certificates via DNS-01 are planned for a later
  milestone (Cloudflare integration); `tls.mode = "files"` covers wildcard certs today.
* Your own certificates (`certs/provided.rs`) sit alongside the mode. They come from
  `[[tls.certificates]]` or the Settings page, go before the usual source in the public listener's
  resolver, and a name one covers is noted but never ordered, so removing the certificate can start
  an order at once. A handshake only reads a map that's replaced whole; files are read on the control
  threads, checked every 5 minutes for those in the configuration. When several cover a name, an
  exact name beats a wildcard, the configuration file beats the page, and then the one that lasts
  longest wins. One that has expired stays in use and shows as failed instead of falling back: it was
  chosen on purpose, and the usual source may be why it was needed. The server's own names never use
  them: the management listener asks `lookup_issued`, and neither status nor ordering counts them
  for those names. So a bad certificate pasted on the page can't lock anyone out of the page that
  removes it, the same reason listeners stay in the configuration file.
* Public side is HTTP/1.1 only (ALPN `http/1.1`); no HTTP/2 or HTTP/3 yet.
* One TCP connection per agent: yamux streams share it, so a lossy link causes head-of-line
  blocking across tunnels of that agent. UDP tunnels ride the same TCP connection, so they
  inherit its retransmissions and ordering (poor for VPNs and real-time media).
* At most 256 streams per agent session: HTTP requests in flight, TCP connections and UDP
  clients together.
* There is no body idle timeout for regular HTTP requests, only a time-to-first-response timeout,
  counted from the last request body chunk (so uploads can take as long as they keep moving).
  Upgraded (WebSocket) connections have an idle timeout.
* Read-only web terminals are anonymous: anyone with the link can hold one of its
  `--max-clients` sessions for as long as they keep the page open, and start up to 60 programs a
  minute.
* Four client addresses (or /64s) can hold all of an agent's 224 data streams, which
  `body_idle_timeout_secs` and `tcp_idle_timeout_secs` can only shorten.
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
