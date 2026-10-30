# MagicPipes

Self-hosted tunnels: expose an application on a private machine (behind NAT, a home router or a
firewall) at a public HTTPS URL with one command.

```console
$ magicpipes add 8080
Checking local service...     ✓
Connecting to server...       ✓
Registering tunnel...         ✓
Checking HTTPS certificate... ✓
Verifying public endpoint...  ✓

Tunnel ready

  Public: https://bright-otter.t.example.com
  Local:  http://127.0.0.1:8080
  Status: connected

Tunnel active in background. Anyone with the URL can reach it.
```

The command exits only after an HTTPS request to the public URL has gone through the tunnel to
your application. The tunnel then keeps running in a background agent after the CLI exits.

* **`magicpipesd`** runs on a public server: HTTPS reverse proxy, automatic certificates (ACME),
  agent endpoint, JSON API and a management UI.
* **`magicpipes`** runs on your machine: CLI plus one background agent that holds an outbound,
  authenticated connection to the server and forwards traffic to local ports.

Nothing listens for inbound connections on your machine. You don't configure a reverse proxy,
create per-app DNS records, or restart anything when you add a tunnel. HTTP/1.1 and WebSockets
both work.

> **Public means public.** Anyone who knows a tunnel URL can reach it. The random name is not
> access control. Put authentication in your application if it needs it.

---

## 1. Server setup

### Requirements

* A Linux (or macOS) host with a public IP and ports **80**, **443** and **8443** reachable.
* DNS (no per-tunnel records are ever needed):
  * `*.t.example.com  A  <server IP>` (wildcard for tunnels)
  * `example.com      A  <server IP>` (management hostname; any name works)

### Get the binaries

Prebuilt archives are attached to each
[GitHub release](https://github.com/cayspekko/magicpipes/releases). Each archive holds both
`magicpipes` and `magicpipesd`; checksums are in `SHA256SUMS`.

| Platform | Archive |
|---|---|
| macOS, Apple silicon | `magicpipes-<version>-aarch64-apple-darwin.tar.gz` |
| Windows x86-64 | `magicpipes-<version>-x86_64-pc-windows-msvc.zip` |
| Linux x86-64 (static) | `magicpipes-<version>-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 (static) | `magicpipes-<version>-aarch64-unknown-linux-musl.tar.gz` |

Or build from source:

```bash
cargo build --release
```

This produces `target/release/magicpipesd` and `target/release/magicpipes` (Rust 1.90+, no
system dependencies; SQLite is bundled).

### Configure and start

```bash
magicpipesd init-config > /etc/magicpipes/magicpipesd.toml   # then edit base_domain, hostname, acme_email
magicpipesd --config /etc/magicpipes/magicpipesd.toml
```

A minimal configuration:

```toml
base_domain = "t.example.com"
data_dir = "/var/lib/magicpipes"

[management]
hostname = "example.com"

[tls]
mode = "acme"                       # Let's Encrypt via HTTP-01 on port 80
acme_directory = "letsencrypt-staging"   # switch to "letsencrypt" once everything works
acme_email = "ops@example.com"
```

See [`magicpipesd.example.toml`](magicpipesd.example.toml) for every option (listen addresses,
timeouts, limits). Logging: `MAGICPIPESD_LOG=info` (or `RUST_LOG`). Config path can also come
from `MAGICPIPESD_CONFIG`.

**TLS modes**

| `tls.mode` | Use | Notes |
|---|---|---|
| `acme` (default) | Production | One certificate per tunnel hostname, issued when the tunnel is registered, cached in `data_dir/certs`, renewed after 2/3 of its lifetime. Needs port 80 for HTTP-01. Failed orders back off (`failure_backoff_secs`) to respect CA rate limits. |
| `files` | Bring your own (e.g. a wildcard cert from your existing tooling) | `tls.cert_file` / `tls.key_file`; must cover `*.<base_domain>`. |
| `dev-ca` | Local testing only | Generates a CA in `data_dir/dev-ca/ca.crt`; clients must trust it explicitly. |

The management listener uses the same certificate source for `management.hostname`, or
`management.cert_file` / `management.key_file` if set.

### Administrator bootstrap

On first start the server creates an admin token and writes it to `<data_dir>/admin-token`
(mode 0600). The token is never logged. Read it, keep it somewhere safe, delete the file.

```bash
cat /var/lib/magicpipes/admin-token        # first start
magicpipesd --config ... admin-token       # create another admin token
magicpipesd --config ... admin-token --rotate   # revoke all others
```

Log in to the UI at `https://example.com:8443` with that token.

### Docker

The [`Dockerfile`](Dockerfile) builds static musl binaries in `rust:1.90-alpine` and copies
them into a `FROM scratch` image (~30 MB). The image contains only both binaries, a CA bundle
(ACME has to verify the CA's HTTPS endpoint) and `/data`. It runs as UID 65532.

```bash
$EDITOR docker/magicpipesd.toml        # base_domain, management.hostname, acme_email
docker compose up -d --build
docker compose exec magicpipesd magicpipesd enroll        # enrollment token for `magicpipes login`
docker compose exec magicpipesd magicpipesd admin-token   # admin token for the UI/API
docker compose logs -f
```

[`docker-compose.yml`](docker-compose.yml) publishes 80, 443 and 8443 and keeps state in the
`magicpipes-data` volume. It hardens the container: read-only root, tmpfs `/tmp`, all
capabilities dropped, `no-new-privileges`. Binding 80/443 without root uses the
`net.ipv4.ip_unprivileged_port_start=0` sysctl, which applies only inside the container's
network namespace. There is no shell in the image, so `docker exec ... sh` and `cat` do not
work; use the `magicpipesd` subcommands above, or `docker compose cp` to copy files out.

### systemd

```ini
# /etc/systemd/system/magicpipesd.service
[Unit]
Description=MagicPipes server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/magicpipesd --config /etc/magicpipes/magicpipesd.toml
Restart=on-failure
User=magicpipes
AmbientCapabilities=CAP_NET_BIND_SERVICE
StateDirectory=magicpipes

[Install]
WantedBy=multi-user.target
```

The server shuts down gracefully on `SIGTERM`: it stops accepting connections, closes agent
sessions (agents reconnect when it is back) and gives in-flight requests up to 15 s.

---

## 2. Enroll a machine

Create a single-use enrollment token (valid 1 hour by default) on the server, or in the UI
("Create enrollment token"), or via `POST /api/v1/enrollments`:

```bash
magicpipesd --config /etc/magicpipes/magicpipesd.toml enroll
# magicpipes login --server https://example.com:8443 --token mpenr_...
```

Run the printed command on the application machine:

```bash
magicpipes login --server https://example.com:8443 --token mpenr_...
```

The enrollment token is exchanged for a long-lived **agent credential** stored in
`~/.magicpipes/config.json` (mode 0600). The server stores only a SHA-256 hash of it. To keep the
token out of shell history, pass it as `MAGICPIPES_TOKEN` or type it at the prompt. For a
`dev-ca` server, add `--ca-cert path/to/ca.crt`.

To revoke a machine (lost laptop, leaked credential), click **Revoke** next to the agent in the
UI or call `DELETE /api/v1/agents/{id}`. Its credential stops working at once, its live session
is closed and its tunnels are deleted. Enroll it again with a new token to bring it back.

---

## 3. Use tunnels

```bash
magicpipes add 8080                 # random name, e.g. https://bright-otter.t.example.com
magicpipes add 3000 --name myapp    # https://myapp.t.example.com
magicpipes add 5173 --json          # machine-readable output (see below)

magicpipes list                     # tunnels on this machine and their status
magicpipes status                   # login, agent and connection status
magicpipes remove myapp             # by name, id or local port

magicpipes agent status
magicpipes agent stop               # tunnels stay registered and resume on next start
magicpipes agent start
magicpipes agent run                # foreground (systemd, launchd, containers, debugging)
magicpipes agent logs [-f]
```

All tunnels on a machine share **one agent process** (per user). The first `add` starts it;
later commands reuse it. The agent restores all tunnels when it starts and reconnects with
backoff when the connection drops.

### `add` semantics

* The local service must already be accepting connections. The agent tries `127.0.0.1` and then
  `::1`; `--host` picks another local address.
* **Idempotent:** running `add <port>` again for a port that already has a tunnel returns the
  existing tunnel (`"created": false`) after re-verifying it. `add <port> --name X` reuses
  tunnel `X` if it already points at that port, and fails with `name_conflict` if it points
  elsewhere. A name owned by another agent fails with `name_taken`.
* Readiness: the command succeeds only after (1) the local port answers, (2) the agent is
  connected and authenticated, (3) the server has installed the route, (4) the certificate for
  the hostname is ready, and (5) an HTTPS request to the public URL came back from your
  application through this tunnel. The probe is `GET <--probe-path>` (default `/`); any
  application status (200, 401, 404, ...) counts. If the app accepts the connection but sends
  no HTTP response (WebSocket-only servers), the probe retries as a WebSocket upgrade.
* `--timeout` (default 120 s) bounds the whole operation, including certificate issuance. If it
  fails, nothing is printed on stdout except a JSON error with `--json`, the exit code is
  nonzero, a tunnel created by this command is removed again, other tunnels are not touched,
  and an agent started by this command exits if it has nothing else to do.
* A slow certificate (`tls_timeout`) does not stop the server: it keeps trying in the
  background, so rerunning `add` later usually succeeds at once.

### JSON output and exit codes

`--json` prints exactly one JSON document on stdout. Progress lines go to stderr (`-q` silences
them).

```json
{
  "id": "tn_abc123",
  "name": "bright-otter",
  "public_url": "https://bright-otter.t.example.com",
  "target": "http://127.0.0.1:8080",
  "status": "ready",
  "background": true,
  "created": true
}
```

On failure:

```json
{ "error": { "code": "tls_failed", "message": "certificate provisioning failed.\n...", "step": "tls" } }
```

| Exit | Codes | Meaning |
|---|---|---|
| 0 | | Success (for `add`: verified ready) |
| 1 | `internal`, ... | Unexpected error |
| 2 | | Invalid command-line usage |
| 3 | `not_logged_in`, `unauthorized`, `invalid_enrollment_token` | Enrollment or credentials |
| 4 | `local_unreachable`, `invalid_port`, `invalid_host` | Nothing listening locally |
| 5 | `server_unreachable`, `agent_start_failed`, `agent_not_running` | Cannot reach server or agent |
| 6 | `name_conflict`, `name_taken`, `invalid_name`, `limit_reached`, `not_found` | Naming/registry |
| 7 | `tls_failed`, `tls_timeout` | Certificate not ready |
| 8 | `probe_failed` | Public URL did not reach the application |

### Run the agent under a service manager

```ini
# ~/.config/systemd/user/magicpipes.service
[Service]
ExecStart=/usr/local/bin/magicpipes agent run
Restart=on-failure
[Install]
WantedBy=default.target
```

The CLI talks to whichever agent holds the lock: a supervised `agent run` and CLI-started
agents can't both run, because only one agent per `MAGICPIPES_HOME` can exist.

### Local files and environment

| | |
|---|---|
| `MAGICPIPES_HOME` | State directory (default `~/.magicpipes`, mode 0700): `config.json`, `tunnels.json`, `agent.sock`, `agent.lock`, `agent.pid`, `agent.log` |
| `MAGICPIPES_SOCKET` | IPC endpoint override: Unix socket path (limited to ~104 bytes), or a named pipe name (`\\.\pipe\...`) on Windows |
| `MAGICPIPES_TOKEN` | Enrollment token for `login` |
| `MAGICPIPES_LOG` | Agent log filter, e.g. `debug` |
| `MAGICPIPES_PROBE_ADDR` | Testing: connect readiness probes to this IP instead of resolving DNS |

---

## 4. Management API

All endpoints except `enroll` and the agent endpoint require `Authorization: Bearer <admin token>`.

| Method | Path | |
|---|---|---|
| GET | `/api/v1/status` | Server version, base domain, counts |
| GET | `/api/v1/tunnels` | `{"tunnels": [...]}` |
| GET | `/api/v1/tunnels/{id or name}` | One tunnel |
| DELETE | `/api/v1/tunnels/{id or name}` | 204; the owning agent is notified and stops serving it; 404 if absent |
| GET | `/api/v1/agents` | Enrolled agents and connection state |
| DELETE | `/api/v1/agents/{id}` | 204; revokes the credential, closes the session, deletes its tunnels; 404 if absent |
| POST | `/api/v1/enrollments` | 201 `{"enrollment_token", "expires_in_secs"}` |
| POST | `/api/v1/enroll` | Exchange an enrollment token for agent credentials (used by `login`) |
| GET | `/api/v1/agent/connect` | Agent transport (HTTP upgrade); not for humans |

Tunnel object: `id`, `name`, `hostname`, `public_url`, `target`, `agent_id`, `status`
(`connected` / `disconnected` / `error` = local app unreachable on the last request), `tls`
(`ready` / `pending` / `failed`), `tls_error`, `created_at`, `requests`, `upstream_errors`,
`last_request_at`. Errors: `{"error": {"code", "message"}}`.

Tunnels are created by agents, not through the API: the target is a port on the agent's
machine, and only the agent may decide what it connects to.

---

## 5. Troubleshooting

| Symptom | What to check |
|---|---|
| `local_unreachable` (exit 4) | Is the app running? `curl http://127.0.0.1:<port>`. If it only listens on another address, pass `--host`. |
| `server_unreachable` | `magicpipes status` shows the last connection error. Check that port 8443 is reachable and the server URL matches `management.hostname`. |
| `unauthorized` | The agent credential was revoked or the server database was reset: run `magicpipes login` again. |
| `tls_failed` | `ACME challenge could not be completed`: port 80 must reach `magicpipesd` for `<name>.<base_domain>` (wildcard DNS correct? firewall?). Look at the server log and the tunnel's `tls_error` in the UI/API. After a failure the hostname is not retried for `failure_backoff_secs`. |
| `tls_timeout` | The CA is slow. The order continues in the background; rerun `add` shortly. |
| `probe_failed` ... "not through this tunnel" | The public hostname resolves somewhere else: check the `*.<base_domain>` DNS record. |
| Browser shows a MagicPipes 502 page | `agent_offline`: the agent is stopped or disconnected (`magicpipes agent status`). `local_unreachable`: the agent is up but the app is down. |
| Dev servers reject the Host header (Vite: "Blocked request") | The original `Host` (the public hostname) is preserved. Allow it in the dev server (e.g. Vite `server.allowedHosts`). |
| Agent logs | `magicpipes agent logs -f`, or `magicpipes agent run` in the foreground with `MAGICPIPES_LOG=debug`. |

---

## 6. Development

```bash
cargo test --workspace     # unit tests + end-to-end tests (real processes, dev CA, loopback)
cargo clippy --workspace --all-targets
scripts/smoke-test.sh target/release   # quick end-to-end check of built binaries
```

### CI and releases

[`.github/workflows/release.yml`](.github/workflows/release.yml) runs on every push to `main`
and on pull requests:

1. clippy and the test suite on Linux and macOS;
2. a release build for each of the four targets above, each on its own OS (native ARM64
   runners for Linux ARM64);
3. `scripts/smoke-test.sh` against each build on that OS: real server with a dev CA, login,
   `add`, a public HTTPS request through the tunnel, `agent stop`.

To publish, create a GitHub release with a tag such as `v0.2.0` on a commit from `main`. The
same workflow then attaches the four archives and `SHA256SUMS` to the release. It refuses tags
that aren't on `main`, and warns if the tag doesn't match the `version` in `Cargo.toml` (bump
that first so `--version` is right). The toolchain is pinned to Rust 1.90.

The end-to-end tests in `crates/magicpipes-cli/tests/e2e.rs` start real `magicpipesd` and
`magicpipes` processes and cover HTTP, streaming, WebSockets, the UI, the API, agent and server
restarts, removal, concurrent startup, authentication failures and certificate failures. An
ACME test against [Pebble](https://github.com/letsencrypt/pebble), with real HTTP-01
validation, is ignored by default because it needs Docker; the doc comment on
`acme_with_pebble` has the setup commands.

Further reading:

* [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): design decisions, library choices, limitations,
  and the production acceptance test.
* [skills/magicpipes/SKILL.md](skills/magicpipes/SKILL.md): instructions for AI coding agents.

Workspace layout:

```text
crates/magicpipes-core     wire protocol, yamux driver, names, secrets
crates/magicpipes-server   magicpipesd: control/ (registry), data/ (proxy), certs/, mgmt/, gateway.rs
crates/magicpipes-cli      magicpipes: CLI commands, client.rs (agent lifecycle), agent/ (session, forward, ops)
```
