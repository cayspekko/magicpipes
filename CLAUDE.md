# MagicPipes: notes for coding agents

Self-hosted tunnels: `magicpipesd` (server, internet-facing) and `magicpipes` (CLI plus a
background agent on the user's machine). Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) before
changing behavior, and [docs/ROADMAP.md](docs/ROADMAP.md) before adding a feature.

```text
crates/magicpipes-core     wire protocol (proto.rs), yamux helpers, secrets, names, CIDR, theme
crates/magicpipes-server   magicpipesd: control/ (registry), data/ (proxy, ports), certs/, mgmt/, gateway.rs, store.rs
crates/magicpipes-cli      magicpipes: CLI (main.rs), client.rs, ipc.rs, platform.rs, agent/ (session, forward, ops, serve, shell, udp)
```

## Before you say a change is done

```bash
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo deny check
```

- The toolchain is pinned to Rust 1.90 (workspace `rust-version`, CI, Dockerfile). Don't use
  newer language or library features.
- `tests/e2e.rs` runs a real server, agent and apps on localhost and is Unix-only. New
  user-visible behavior gets an e2e test; parsing and validation get unit tests next to the code.
- `scripts/smoke-test.sh <bin dir>` is the release smoke test (all platforms, including Windows).
  Extend it when you add a tunnel kind or CLI command.
- The code is hand-formatted at roughly 120 columns. Do not run `cargo fmt` over whole files; it
  rewrites hundreds of lines. Match the surrounding style instead.
- CI (`.github/workflows/ci.yml`) runs the three commands above plus a Windows clippy check.
  Report only results you actually ran or saw.

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
  them. No database or ACME work on the request path. The agent mirrors this:
  `agent/session.rs` (control), `agent/forward.rs` (data), `agent/ops.rs` on top.
- **One RPC per yamux stream**: a length-prefixed JSON `Request`, one `Response`. Server-opened
  streams start with a `ServerOpen` frame and a status byte.
- **Wire compatibility.** Old agents talk to new servers and the reverse. New fields in
  `proto.rs` are optional (`#[serde(default)]`, skip-serializing defaults); new enum variants or
  kinds must be detected and reported as `server_outdated` or `agent_outdated`, not misbehave.
  Keep the `old_peers_still_parse` tests passing and extend them.
- **Persistent formats are append-only.** SQLite schema changes go in a new entry at the end of
  `MIGRATIONS` in `store.rs` (never edit a shipped entry); add a test that migrates an old
  database. `~/.magicpipes/tunnels.json` and `config.json` must keep loading files written by
  older versions.
- **OS-specific code lives in `magicpipes-cli/src/platform.rs`** (sockets, pipes, process
  spawning, file permissions). Everything else stays portable across macOS, Linux and Windows.
- **Stable machine interfaces.** `--json` output fields, error codes (snake_case strings such as
  `local_unreachable`) and exit codes (`exit_code()` in the CLI `main.rs`) are an API used by
  scripts and by `skills/magicpipes`. Add, don't rename or remove; document new codes in the
  README and map them to an exit code.
- Workspace dependencies are declared once in the root `Cargo.toml` and used with
  `.workspace = true`. Shared logic goes in `magicpipes-core` only if both binaries need it.

## Security rules

Treat everything from the network as hostile: public clients, agents (authenticated but not
trusted with each other's tunnels), and, from the agent's side, the server.

- **Secrets**: generate with `magicpipes_core::secret` (≥192 bits of randomness), store only
  `sha256_hex` digests, compare with `secret::verify` / constant-time comparison. Never log a
  token, cookie, enrollment code or shell link key, and never put one in a URL query string
  (the web terminal key lives in the `#fragment`).
- **Isolation between agents**: every control-plane operation checks that the tunnel belongs
  to the calling agent. Hostnames and public ports are unique and owned by one agent.
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
  third-party origins. Vendored browser assets live in `agent/shell/assets/` with a README
  (source, version) and their license file, which `release.yml` must copy into archives.
- **Management UI**: state-changing requests need the session cookie *and* the CSRF token.
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
  from SNI.
- **Dependencies**: `cargo deny check` must pass. A new license in `deny.toml`, an advisory in
  `ignore`, a git or non-crates.io source, or a TLS stack other than rustls+ring is a policy
  change the owner must approve. Prefer the standard library or an existing dependency to a new
  crate.

## Documentation

User-visible changes update `README.md`; design changes update `docs/ARCHITECTURE.md`; finished
or new roadmap items update `docs/ROADMAP.md`; new server settings go in
`magicpipesd.example.toml` and `docker/magicpipesd.toml`. CLI behavior an AI agent relies on is
described in `skills/magicpipes/SKILL.md`.
