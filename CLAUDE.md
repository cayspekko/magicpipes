# MagicPipes: notes for coding agents

Self-hosted tunnels: `magicpipesd` (server, internet-facing) and `magicpipes` (CLI plus a
background agent on the user's machine). Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) before
changing behavior, and [docs/ROADMAP.md](docs/ROADMAP.md) before adding a feature.

```text
crates/magicpipes-core     wire protocol (proto.rs), yamux helpers, secrets, names, CIDR, theme, url
crates/magicpipes-server   magicpipesd: control/ (registry), data/ (proxy, ports), certs/, mgmt/, gateway.rs, store.rs
crates/magicpipes-cli      magicpipes: CLI (main.rs), client.rs, ipc.rs, platform.rs, agent/ (session, forward, ops, serve, shell, udp)
crates/magicpipes-bench    load generator and test application for scripts/bench; never shipped
```

## Before you say a change is done

```bash
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo deny check
```

- The toolchain is pinned to Rust 1.99 (workspace `rust-version`, CI, Dockerfile). Don't use
  newer language or library features.
- `tests/e2e.rs` runs a real server, agent and apps on localhost and is Unix-only. New
  user-visible behavior gets an e2e test; parsing and validation get unit tests next to the code.
- `scripts/smoke-test.sh <bin dir>` is the release smoke test (all platforms, including Windows).
  Extend it when you add a tunnel kind or CLI command.
- Changes to sign-in, cookies, redirects or CSPs: also run the ignored e2e test
  `browser_signs_in_to_private_tunnels` (headless Chrome via `scripts/browser-sign-in.mjs`;
  needs Chrome and Node 22+). The other e2e tests use a plain HTTP client, which applies neither
  CSP nor cookie rules.
- Changes to the data path (`data/`, `listen.rs`, `mux.rs`, `agent/forward.rs`, `agent/serve/`):
  also measure before and after with `scripts/bench`, as "Performance rules" describes.
- Changes to a page: also look at it in a browser, as "UI rules" describes.
- The code is hand-formatted at roughly 120 columns. Do not run `cargo fmt` over whole files; it
  rewrites hundreds of lines. Match the surrounding style instead.
- CI (`.github/workflows/ci.yml`) runs the three commands above plus a Windows clippy check.
  Report only results you actually ran or saw, and after pushing, look at the result: "passes
  locally" isn't CI passing.

## Architecture rules

These are load-bearing. Changing one is a design decision: update ARCHITECTURE.md in the same
change and say why.

- **The agent always dials out.** The server never connects into the user's network; it only
  opens streams inside the session the agent established.
- **The server names a tunnel, never an address.** `ServerOpen` carries a tunnel id; the agent
  looks it up in its own table and dials only targets the local user configured. Never add a
  message that lets the server choose a host, port, path or command on the agent's machine.
- **Data plane vs control plane** (server). `data/` reads an immutable `Arc<RouteTable>` snapshot
  and never touches SQLite, the API or the registry mutex. `control/` validates, persists, then
  publishes a whole new `RouteTable` (`DataPlane::publish`), which is the only interface between
  them. No database or ACME work on the request path. They also run on separate Tokio runtimes:
  control-plane code that creates a socket or task for the data plane goes through
  `on_traffic_threads`. The agent mirrors this:
  `agent/session.rs` (control), `agent/forward.rs` (data), `agent/ops.rs` on top.
- **One RPC per yamux stream**: a length-prefixed JSON `Request`, one `Response`. Server-opened
  streams start with a `ServerOpen` frame and a status byte.
- **Wire compatibility.** Old agents talk to new servers and the reverse. New fields in
  `proto.rs` are optional (`#[serde(default)]`, skip-serializing defaults); new enum variants or
  kinds must be detected and reported as `server_outdated` or `agent_outdated`, not misbehave.
  Before sending something an older peer can't understand, check its protocol version (the
  `X-MagicPipes-Protocol` handshake); bump `PROTOCOL_VERSION` and say what the new version adds.
  Keep the `old_peers_still_parse` tests passing and extend them.
- **Persistent formats are append-only.** SQLite schema changes go in a new entry at the end of
  `MIGRATIONS` in `store.rs` (never edit a shipped entry); add a test that migrates an old
  database. `~/.magicpipes/tunnels.json` and `config.json` must keep loading files written by
  older versions.
- **OS-specific code lives in `magicpipes-cli/src/platform.rs`** (sockets, pipes, process
  spawning, file permissions). Everything else stays portable across macOS, Linux and Windows.
- **Stable machine interfaces.** `--json` output fields, error codes (snake_case strings such as
  `local_unreachable`) and exit codes are an API used by scripts and by `skills/magicpipes`.
  Every code is a variant of `ErrorCode` in `magicpipes-core/src/error.rs`, with its HTTP status
  and exit code; don't write code strings by hand. Add, don't rename or remove; document new
  codes in the README.
- Workspace dependencies are declared once in the root `Cargo.toml` and used with
  `.workspace = true`. Shared logic goes in `magicpipes-core` only if both binaries need it.

## Security rules

Treat everything from the network as hostile: public clients, agents (authenticated but not
trusted with each other's tunnels), and, from the agent's side, the server.

- **Secrets**: generate with `magicpipes_core::secret` (≥192 bits of randomness), store only
  `sha256_hex` digests, compare with `secret::verify` / constant-time comparison. Never log a
  token, cookie, enrollment code or shell link key, and never put one in a URL query string
  (the web terminal key lives in the `#fragment`).
- **One authorization function**: every access decision (API, UI, agent RPCs, public traffic)
  goes through `authz::authorize(principal, action, resource)`; never compare owners inline.
  Refusals look like "not found" so callers learn nothing about other agents' tunnels. After
  any change to users, tags, roles or agents, call `ControlPlane::refresh` so the directory and
  the published routes (which private tunnels check per request) follow at once.
- **One access rule**: a private tunnel admits a user who shares a tag with it whose `access`
  is on, and nobody else; owners get in through their personal tag, never through an owner
  exception. Only administrators assign tags to people and service agents; a tunnel carries
  only ordinary tags its publisher holds (checked on every registration that names tags) and
  personal tags, which are held only by their own user and written to users only by the store. A
  private tunnel never falls back to public (the agent removes a tunnel the server didn't keep
  private).
- **Isolation between agents**: an agent manages only its own tunnels (`authorize`'s Manage
  rule). Hostnames and public ports are unique and owned by one agent.
- **Fail closed**: if a stored policy (allow-list, ownership, permission) cannot be read or
  parsed, deny and log. Never fall back to a default that means "anyone", such as an empty
  allow-list.
- **Bound everything**: every new buffer, queue, map, connection or stream needs a size limit
  and a timeout (see "Bounded resources" in ARCHITECTURE.md), including request bodies and
  per-client usage, not just connection counts. One public client or one agent must not be able
  to use up a resource shared with other tunnels or agents (yamux streams, ports, ACME orders,
  rate-limit state). No unbounded `read_to_end` or `Vec` growth from remote input.
- **No panics on remote input**: no `unwrap`, `expect`, slicing or unchecked arithmetic on data
  that came over a socket, a file the user didn't write, or an HTTP request.
- **HTML**: the management UI, file listings and the web terminal page are server-rendered;
  escape every interpolated value. Keep the CSPs tight; don't add inline event handlers or
  third-party origins. Vendored browser assets live in `magicpipes-core/assets/terminal/` with a README
  (source, version) and their license file, which `release.yml` must copy into archives.
- **Management UI**: state-changing requests need the session cookie *and* the CSRF token, so a
  handler takes `Posted<T>` or `AdminPosted<T>` (`mgmt/extract.rs`), never a bare `Form`. A
  form submission never redirects off the management host (browsers apply `form-action 'self'`
  to its redirects); continue with a page that navigates on its own. Never put a secret in a
  URL query string; a one-time code to another host goes in the fragment.
  Tunnel subdomains share the base domain with the management host, so the management listener
  answers only for `management.hostname` (`SingleHost` certificates, `require_host`), the
  cookie keeps its `__Host-` prefix, and its scope is never widened.
- **Client addresses** come from `forwarded::TrustedProxies` and `proxy_header::client_addr`,
  never straight from a header: a PROXY header or X-Forwarded-For is believed only from
  `trusted_proxies`. The server strips `x-magicpipes-*` headers from upstream responses.
- **Public traffic can't starve control traffic**: server-opened data streams go through
  `MuxHandle::open_data` (per-session and per-client budget); RPCs and pings use `open`.
- **Filesystem**: secrets and state under `~/.magicpipes` and the server `data_dir` are 0600 in
  0700 directories (written atomically). Static file serving must stay inside the served root,
  including through symlinks and archives.
- **Certificates** are only ordered for hostnames the control plane authorized, never on demand
  from SNI. Certificates people bring (`certs/provided.rs`) never apply to the server's own names,
  and their private keys are never shown again or quoted in a message.
- **Dependencies**: `cargo deny check` must pass. A new license in `deny.toml`, an advisory in
  `ignore`, a git or non-crates.io source, or a TLS stack other than rustls+ring is a policy
  change the owner must approve. Prefer the standard library or an existing dependency to a new
  crate.

## UI rules

The aim is simple elegance: anyone can tell where they are, whether things are working, what their
last action did and what to do next. "Management UI" in ARCHITECTURE.md has the reasoning. Layout
and colors follow the theme in `magicpipes-core/src/theme.rs`, whose tokens meet WCAG 2.2 AA in both
color schemes: check any new one (4.5:1 for text, 3:1 for field borders and focus outlines). Type
sizes and corner radii come from the short lists there, and styles from a class, never a `style`
attribute. Shared markup is in `mgmt/html.rs`; a list is `html::table`.

What a page says:

- **A change says what it did.** After a change, redirect with `ui::done` and a `Done` variant. An
  address only ever carries that key, never words of its own.
- **A failure says why, and keeps the form.** Show a form again with what was typed, never a
  password or other secret. Put `form_alert` at the top of that form, `invalid` on the field
  concerned and `title_of` on the page. Never `let _ =` a control-plane call.
- **Ask before anything that can't be undone** (`data-confirm`), and name the effect: "It leaves 3
  people and 2 private tunnels", not "Are you sure?". The dialog's button repeats the one pressed,
  so that one says what it does.
- **One word per thing.** A *machine* is what people enroll; the *agent* is the background process
  on it, and a *service agent* a machine nobody owns. *Sign in*, not log in. API paths and JSON
  fields keep their names.
- **A label says what's really counted.** "Couldn't reach app", not "App errors", because an app's
  own 500s aren't in that number. Say what period a number covers.
- **An empty page leads somewhere.** Give the next step, with the command to copy, not just "None
  yet".
- **One sentence under a heading.** Details go in a note beside the form, or a `details.more`.
- **Less is the default.** Say a thing once, and only when it helps someone decide: a certificate
  that's fine gets no word in the list, one in trouble does. No eyebrow repeating the heading, no
  Refresh button, no menu with one item in it.

How it holds up:

- **Design for real amounts of data.** Try every list with nothing, one, several and far too many
  items, and with the longest values allowed. A test with one tag per tunnel hid a table 1,606 px
  wide in a 1,030 px page.
- **A table has 1,030 px to spend.** Cells don't wrap by default, so every column takes from the
  others. Before adding one, put the fact under another column's main value (`.sub`), or leave it
  for the detail page.
- **What can grow must wrap, and has a floor.** Give a wrapping cell a `min-width`, or the table
  squeezes it to one word per line.
- **Tags are chips** (`html::chips`). A list that's for scanning shows a few and links to the rest
  (`tags_in_a_row`), and never hides just one; a page where you edit them shows them all.
- **Works at 320 px and without scripts.** Scripts only enhance; the pages stay usable without them.
  A wide table scrolls inside its own box, and the page itself never scrolls sideways.
- **For everyone:** keyboard reaches everything with a visible focus, targets are at least 24 px,
  color is never the only signal, headings don't skip levels, and changes made without a page load
  are announced (`role="status"`, or `role="alert"` for problems).

Before saying a UI change is done:

- **Look at it.** The e2e tests use a plain HTTP client and see no layout. Seed realistic data, then
  check light and dark at 1180, 1024 and 320 px. The built-in browser won't trust the dev CA, so save
  pages with `curl --cacert` and serve those from localhost.
- **Measure what you can't judge by eye:** a table's `scrollWidth` against its `clientWidth`, and
  every new color pair's contrast.
- **Use real input.** A script's `.click()` or `.focus()` doesn't trigger `:focus-visible` or the
  clipboard, so try focus and menus with real key presses.

## Performance rules

Everyone's tunnels share these threads, queues and connections, so slow code here is a bug in
someone else's traffic too. "Threads and memory" in ARCHITECTURE.md has the reasoning and numbers,
what has already been tried, and the costs left in place on purpose.

- **Nothing on the traffic threads waits.** No SQLite, registry mutex, file I/O or long CPU work in
  `data/`, the listeners or a session's driver. A lock there is brief and never held across an
  `.await`. Blocking work belongs on the control threads. In the agent, give a blocking job one
  `spawn_blocking`, not a `tokio::fs` call per step: each call is a hand-off to another thread.
- **A change to one tunnel costs the others nothing.** Anything later requests rely on is scoped to
  its tunnel (`Route::version`), not global. `publish` rebuilds the whole table under the registry
  lock, so a change publishes once, not once per item.
- **Limits match what can be in flight.** A pool or cache smaller than its peak throws away what it
  is about to need, and performance collapses instead of degrading: with 32 idle connections for
  224 possible streams, 150 requests in flight got 82 req/s, and 48,900 once the two matched. Test
  above a new limit, not just below it.
- **Data moves in large pieces.** Copy between a stream and a socket with
  `copy_bidirectional_with_sizes` and `COPY_BUFFER`, never the 8 KiB default. Write one message in
  one call, since over TLS each write is a record and a system call. `mux::spawn` already batches a
  session's writes, so don't wrap a session in another buffer.
- **Sockets are set up on purpose.** Every TCP socket gets `set_nodelay(true)`, and every connection
  that can carry a session gets `SEND_QUEUE`.
- **A session is one queue.** All of an agent's streams share one TCP connection, so bytes queued
  below yamux delay everyone's next request. Data waits per stream, where flow control applies.
- **The agent stays small.** It is a background process on someone else's machine: about 6 MB on
  Linux, and back there after load. The server may spend bounded memory for speed; the agent may
  not. Judge an allocator or a cache on memory after load and after idling, as well as on speed.
- **Durability isn't traded for speed.** SQLite stays at `synchronous = FULL`: a lost commit can
  bring back a revoked token, and traffic doesn't wait for commits anyway.
- **Measure data-path changes in release builds**, with `scripts/bench` (see its README), and report
  what got worse as well as better:
  - On static Linux too, not only macOS. musl's allocator was the biggest bottleneck on Linux, and
    a Mac doesn't have it.
  - Alternating builds (A, B, A, B, at least three rounds). Single runs vary by 10–20%.
  - More than throughput: small-request latency during a download, memory after load and after
    idling, and for anything touching a session, a shaped link (`netem`). Loopback hides queues.
- **Keep the gain with a test that needs no clock**: count writes, hold a lock, compare connection
  numbers (`frames_share_a_write_and_a_lone_frame_still_goes_out`,
  `a_stuck_database_does_not_hold_up_tunnels`, `pooled_connections_outlast_changes_to_other_tunnels`).
  Never assert a throughput number in a test.
- **No optimization without a measurement.** If a change doesn't show up in the numbers, the simpler
  code stays.

## Documentation

User-visible changes update `README.md`; design changes update `docs/ARCHITECTURE.md`; finished
or new roadmap items update `docs/ROADMAP.md`; new server settings go in
`magicpipesd.example.toml` and `docker/magicpipesd.toml`. CLI behavior an AI agent relies on is
described in `skills/magicpipes/SKILL.md`.
