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
both work. `magicpipes add --serve <dir>` publishes a directory of files with a built-in web
server, `magicpipes add --shell` shares a terminal in the browser (like ttyd), and
`magicpipes add 5432 --tcp` (or `--udp`) publishes any service on a raw public port. See
[docs/ROADMAP.md](docs/ROADMAP.md) for what comes next (an SSH gateway, browser desktop).

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

**TCP and UDP ports** are off until you give the server a port range:

```toml
[ports]
range = "65500-65535"        # each port is usable for TCP and for UDP
# public_host = "example.com"  # host in tcp:// and udp:// URLs (default: management.hostname)
```

Every port in the range must reach `magicpipesd` from the internet, for both TCP and UDP (cloud
firewall, router forwarding). Ports are bound when a tunnel claims them, so the range may
overlap ports other programs use; those are skipped. Each agent may hold up to
`agents.max_ports_per_agent` ports (default 10).

**Behind a reverse proxy or load balancer**, list its addresses in `trusted_proxies` so the server
sees real client addresses (for login rate limits, per-client connection caps, `--allow-cidr`
and the `X-Forwarded-For` tunnels receive). A TCP load balancer that passes TLS through, such
as HAProxy in `mode tcp`, should send a PROXY header (`send-proxy-v2` on its `server` lines),
and the matching listeners need `proxy_protocol = true`:

```toml
trusted_proxies = ["172.16.0.0/12"]   # e.g. the Docker network HAProxy runs on

[public]
proxy_protocol = true
[management]
proxy_protocol = true
[ports]
proxy_protocol = true
```

Connections from addresses outside `trusted_proxies` still work, with the peer as the client
and its own forwarding headers dropped. Without `trusted_proxies`, every client behind the
proxy shares one address, so ten failed logins from anyone would rate-limit everyone's failed
attempts (valid tokens are always accepted).

### Administrator bootstrap

On first start the server creates an admin token and writes it to `<data_dir>/admin-token`
(mode 0600). The token is never logged. Read it, keep it somewhere safe, delete the file.

```bash
cat /var/lib/magicpipes/admin-token        # first start
magicpipesd --config ... admin-token       # create another admin token
magicpipesd --config ... admin-token --rotate   # revoke all others
```

Log in to the UI at `https://example.com:8443` with that token ("Use an admin token" on the
sign-in page). The admin token always works, whatever else is configured; keep it for
emergencies.

### Users

Under **Users**, administrators add people with an email address, a role and a password (or
let the server generate one, shown once). Everyone must replace a password set by an
administrator when they first sign in.

* **Roles**: *administrators* manage tunnels, agents, users, tags, enrollment tokens and the
  audit log; *members* manage their own account (password, API tokens, sessions) and their own
  machines and tunnels. Design: [docs/USERS.md](docs/USERS.md).
* **Access tags** (Tags page, e.g. `team:dev`): administrators create them and assign them to
  users. Someone reaches a private tunnel when they share one of its access tags, or own it.
  Matching is exact; nobody can give themselves a tag. Deleting a tag takes it away from
  everyone and everything at once.
* **Sign-in protection**: passwords are stored as Argon2id hashes and need at least 12
  characters. After 10 failed attempts within 15 minutes, an account accepts one attempt every
  10 seconds, right password or not; failed attempts also count against the client's address.
  A wrong password and an unknown email get the same answer.
* **Sessions** last `[users] session_max_age_secs` (12 hours) and survive server restarts.
  Changing your password, being disabled, or "Sign out everywhere" ends them.
* **API tokens** (Account page) act as their user with the user's current role:
  `Authorization: Bearer tok_…`. Disabling the user stops them.
* **Audit log**: sign-ins (including failed ones), account changes, deletions, revocations and
  enrollment tokens, kept for `[users] audit_retention_days` (90).

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

For TCP/UDP tunnels, publish the `[ports]` range too (commented out in the compose file). Docker
starts a proxy process per published port, so for a large range use `network_mode: host`
instead.

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

**With an account** (users, see "Users" above), run this on the machine and approve it in the
browser:

```bash
magicpipes login --server https://example.com:8443
```

The CLI prints a link and a code, and opens the server's page where you sign in, check that the
code matches, and pick which of your access tags the machine gets. The machine then belongs to
you: you manage it and its tunnels, and it never has more access tags than you hold. Without a
terminal, add `--browser` to wait for the approval anyway.

**With an enrollment token**: create a single-use token (valid 1 hour by default) on the server,
or in the UI ("Enroll a machine"), or via `POST /api/v1/enrollments`. Administrators choose who
the machine belongs to (nobody, for a *service agent*), its access tags and labels, and whether
its tunnels may be public:

```bash
magicpipesd --config /etc/magicpipes/magicpipesd.toml enroll
# magicpipes login --server https://example.com:8443 --token mpenr_...
```

Run the printed command on the application machine: (valid 1 hour by default) on the server, or in the UI
("Create enrollment token"), or via `POST /api/v1/enrollments`:

```bash
magicpipesd --config /etc/magicpipes/magicpipesd.toml enroll
# magicpipes login --server https://example.com:8443 --token mpenr_...
```

Run the printed command on the application machine:

```bash
magicpipes login --server https://example.com:8443 --token mpenr_...
```

Either way, the enrollment token is exchanged for a long-lived **agent credential** stored in
`~/.magicpipes/config.json` (mode 0600). The server stores only a SHA-256 hash of it. To keep the
token out of shell history, pass it as `MAGICPIPES_TOKEN` or type it at the prompt. For a
`dev-ca` server, add `--ca-cert path/to/ca.crt`.

To revoke a machine (lost laptop, leaked credential), click **Revoke** next to the agent in the
UI or call `DELETE /api/v1/agents/{id}` (administrators, or the machine's owner). Its credential stops working at once, its live session
is closed and its tunnels are deleted. Enroll it again with a new token to bring it back.

---

## 3. Use tunnels

### Public and private

A **public** tunnel is reachable by anyone who has its address. A **private** one asks people to
sign in to the management UI first, then lets in its owner and anyone who shares one of its
access tags. Machines enrolled before the server had user accounts make public tunnels, as
before; machines enrolled since make private ones unless asked otherwise.

```bash
magicpipes add 3000 --private                 # the owner, plus everyone who shares the machine's tags
magicpipes add 3000 --access team:dev         # narrower: only team:dev (the machine must have it)
magicpipes add 3000 --public                  # anyone; refused if the enrollment doesn't allow it
magicpipes add 3000 --label environment:staging   # metadata only, never used for access
```

* Opening a private tunnel in a browser without being signed in shows the sign-in page, then
  comes back to the same address. Signed in without a shared tag: an "access denied" page. API
  clients and scripts get `401 unauthenticated` or `403 forbidden` instead.
* The application receives `X-MagicPipes-User` (email) and `X-MagicPipes-User-Id` on every
  request; clients can't forge them. It never sees MagicPipes' own cookie.
* Taking a tag away, disabling a user or "Sign out everywhere" takes effect on the next request,
  and closes open WebSockets.
* `https://<tunnel>/.magicpipes/` is reserved on private tunnels (`/.magicpipes/logout` signs out
  of that tunnel).
* The readiness check of a private tunnel goes through the server to the local application
  (the public address would ask for a sign-in).
* TCP and UDP tunnels can't be private yet: a raw port can't show a sign-in page. Use
  `--allow-cidr` for them.
* The UI lists tunnels shared with you under **Shared with you**; `GET /api/v1/shared` too.

```bash
magicpipes add 8080                 # random name, e.g. https://bright-otter.t.example.com
magicpipes add 3000 --name myapp    # https://myapp.t.example.com
magicpipes add 5173 --json          # machine-readable output (see below)
magicpipes add --serve ./dist       # serve a directory with the built-in file server
magicpipes add --shell -- htop      # a terminal in the browser (read-only unless --write)
magicpipes add 5432 --tcp           # a raw TCP port, e.g. tcp://example.com:65507
magicpipes add 53 --udp             # a UDP port

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

### Serving a directory

`magicpipes add --serve <dir>` publishes a directory without running a web server yourself,
much like miniserve. The agent serves the files itself, so no local port is opened.

```console
$ magicpipes add --serve ./dist --name docs
Checking directory...         ✓
...
  Public: https://docs.t.example.com
  Serving: /home/me/project/dist
```

* Read-only: nothing can be uploaded or changed.
* A directory's `index.html` is served at its URL. Without one, the directory is shown as a
  listing in the MagicPipes look (light and dark), with file-type icons, sorting by name, size
  or date, and breadcrumbs.
* Clicking a file the browser can show (images, audio, video, PDF, text and source code, CSV)
  opens it in a new tab; anything else downloads. Source and config files (`.md`, `.rs`,
  `.toml`, `.ts`, ...) are served as UTF-8 plain text so they display instead of downloading.
  Every row also has a download button. `Range` requests (resumable downloads, video seeking)
  and `Last-Modified` work.
* **Bulk download:** tick files and folders (or select all) and download them as one `.tar.gz`,
  or use **Download folder**. The archive is streamed as it is built, so size is no problem; the
  browser just cannot show a percentage.
* `--no-list` turns listings and folder downloads off; files are then reachable only by exact
  path (and `index.html`).
* Hidden files and directories (names starting with `.`, such as `.env` or `.git`) are never
  listed, served or archived. Symlinks are followed only if they stay inside the served
  directory (folder symlinks are not followed into archives).
* Running `add --serve` again for the same directory returns the same tunnel, applying the new
  `--no-list` setting. `magicpipes remove <name>` stops serving it.

> Everything in the directory (except hidden entries) is public. Serve a dedicated build or
> export directory, not your home directory or a source checkout.

### Sharing a terminal

`magicpipes add --shell` puts a terminal on a public URL, like ttyd: your login shell, or any
program given after `--`. Each visitor gets **their own copy** of the program in a new
terminal, which is stopped when they close the tab. The page uses the MagicPipes look, and the
terminal resizes with the window.

```console
$ magicpipes add --shell --name top -- htop
Checking program...           ✓
...
  Public: https://top.t.example.com
  Shell:  htop (read-only)
  In:     /home/me/project
```

* **Read-only by default.** Visitors watch the program's output; the agent ignores their
  keystrokes. That suits dashboards and logs: `htop`, `btop`, `tail -f app.log`,
  `watch kubectl get pods`.
* **`--write` lets visitors type.** The URL then carries a secret: `https://name.t.example.com/#k=…`.
  Without the full link the page connects to nothing. The part after `#` is never sent in HTTP
  requests, so it does not appear in proxy or server logs. Anyone with the link can run commands
  as you, so share it like a password. Running the same `add` again prints the same link;
  `magicpipes remove <name>` revokes it, and re-adding without `--write` ends open sessions.
* The program runs in the directory where you ran `add`, with the agent's environment, plus
  `TERM=xterm-256color`. On Windows the default is PowerShell (ConPTY).
* Nerd Font icons (Starship, Powerlevel10k, `eza --icons`, …) render for every viewer: the
  page bundles the symbols-only Nerd Font and downloads it (1.2 MB, once) only when an icon is
  on screen. Emoji and CJK take two columns, as in current terminals.
* `--max-clients N` limits concurrent sessions (default 5).
* Running the same command from the same directory again returns the same tunnel. `list` shows
  it as `shell:htop (read-only)`; `list --json` includes the `share_url`.

> The MagicPipes server relays the terminal and can read it (it terminates TLS for every
> tunnel). Use your own SSH for anything the server operator should not see.

### TCP and UDP ports

For anything that is not HTTP (databases, SSH, game servers, MQTT, DNS), `--tcp` or `--udp`
gives the tunnel a port on the server instead of a hostname:

```console
$ magicpipes add 5432 --tcp --name db --allow-cidr 203.0.113.0/24
Checking local service...     ✓
Connecting to server...       ✓
Registering tunnel...         ✓
Checking tunnel...            ✓
Verifying public endpoint...  ✓

Tunnel ready

  Public: tcp://example.com:65507
  Local:  tcp://127.0.0.1:5432
  Status: connected
```

```bash
psql -h example.com -p 65507 -U me mydb
```

* **The port stays the same** for the tunnel: re-running `add`, restarting the agent or the
  server keeps it. `--remote-port N` asks for a specific port inside the server's range.
* **`--allow-cidr`** (repeatable: networks or single addresses) limits who can connect; other
  clients are disconnected at once. Without it the port is open to the whole internet, and
  only your service's own authentication protects it. The settings follow the latest `add`:
  re-adding without `--allow-cidr` removes the limit.
* **Readiness:** the server opens a connection to your service through the agent (so a service
  that is down fails the `add`), then this machine connects to the public port. If that last
  connection does not come through, `add` still succeeds but warns (`"reachable": false`): the
  server's firewall may not forward the port, or your network may be unable to reach its own
  public address.
* **UDP** has no connections, so `add --udp` cannot check the service end to end
  (`"verified": false`). Each client address gets its own path to your service; it is forgotten
  after a minute without datagrams. Fine for DNS, syslog, game servers and the like; a poor fit
  for VPNs such as WireGuard, which suffer when tunneled over TCP.
* While the agent is offline the port stays reserved: connections are accepted and closed.
* Traffic is not decrypted: the server sees only what your protocol sends (use TLS or SSH
  inside for anything private). Each agent connection carries at most 256 TCP connections and
  UDP clients at once.

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
| 3 | `not_logged_in`, `unauthorized`, `invalid_enrollment_token`, `config_error`, `forbidden`, `unauthenticated` | Enrollment, credentials or local configuration |
| 4 | `local_unreachable`, `invalid_port`, `invalid_host`, `invalid_directory`, `invalid_command`, `spawn_failed` | Nothing listening locally, `--serve` directory missing, or `--shell` program not found |
| 5 | `server_unreachable`, `agent_unavailable`, `agent_start_failed`, `agent_not_running`, `agent_protocol`, `agent_outdated` | Cannot reach server or agent, or the running agent is older than the CLI |
| 6 | `name_conflict`, `name_taken`, `email_taken`, `tag_unknown`, `public_not_allowed`, `invalid_name`, `limit_reached`, `not_found`, `port_unavailable`, `kind_mismatch`, `ports_disabled`, `server_outdated`, `unsupported`, `invalid_cidr` | Naming/registry, the server cannot give out that port, or the server needs a newer version |

`name_conflict`: one of your own tunnels already uses the name for another target. `name_taken`:
another machine's agent owns it. Codes are listed in `crates/magicpipes-core/src/error.rs`; new
ones may appear in later versions, so treat an unknown code like `internal`.
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

All endpoints except `enroll` and the agent endpoint require `Authorization: Bearer <token>`:
an admin token, or a user's API token, which can do what its user can do. Endpoints for
administrators answer `403 forbidden` to members.

| Method | Path | |
|---|---|---|
| GET | `/api/v1/status` | Server version, base domain, counts |
| GET | `/api/v1/tunnels` | `{"tunnels": [...]}` |
| GET | `/api/v1/tunnels/{id or name}` | One tunnel |
| DELETE | `/api/v1/tunnels/{id or name}` | 204; the owning agent is notified and stops serving it; 404 if absent |
| GET | `/api/v1/agents` | Enrolled agents and connection state |
| DELETE | `/api/v1/agents/{id}` | 204; revokes the credential, closes the session, deletes its tunnels; 404 if absent |
| POST | `/api/v1/enrollments` | 201 `{"enrollment_token", "expires_in_secs"}`; optional body `{"owner_user_id"?, "tags"?, "labels"?, "allow_public"?, "default_private"?}`. Members may enroll only their own machines, with tags they hold |
| POST | `/api/v1/enroll` | Exchange an enrollment token for agent credentials (used by `login`) |
| GET | `/api/v1/me` | `{"kind": "admin_token"}` or `{"kind": "user", "user": {...}}` |
| GET | `/api/v1/shared` | Tunnels you can reach but don't manage (`name`, `public_url`, `kind`, `visibility`, `owner_email`, `labels`) |
| PATCH | `/api/v1/agents/{id}` | `{"tags"?, "labels"?}`; owners may only remove tags |
| GET | `/api/v1/tags` | `{"tags": [{"name", "description", "created_at"}]}` (administrators) |
| POST | `/api/v1/tags` | 201; body `{"name", "description"?}` |
| DELETE | `/api/v1/tags/{name}` | 204; removes it from every user, agent and tunnel |
| POST | `/api/v1/device` | Starts a browser-approved `magicpipes login` (used by the CLI) |
| POST | `/api/v1/device/poll` | Its result: `pending`, `approved` (with `enrollment_token`), `denied` or `expired` |
| GET | `/api/v1/users` | `{"users": [...]}`: every account for administrators, your own for members |
| POST | `/api/v1/users` | 201 `{"user", "password"?}`; body `{"email", "display_name"?, "role"?, "password"?}`. Without `password` one is generated and returned once. `409 email_taken` if the email has an account |
| GET | `/api/v1/users/{id}` | One user |
| PATCH | `/api/v1/users/{id}` | `{"role"?: "admin" \| "member", "disabled"?: bool, "tags"?: [...]}`; role and status not for your own account |
| POST | `/api/v1/users/{id}/password` | `{"password"}`: a new generated password the user must change; ends their sessions |
| GET | `/api/v1/tokens` | Your API tokens (never their secrets) |
| POST | `/api/v1/tokens` | 201 `{"api_token", "token"}`; body `{"name", "expires_in_days"?}`; the secret is returned once; at most 20 per user |
| DELETE | `/api/v1/tokens/{id}` | 204 |
| GET | `/api/v1/audit?limit=N` | `{"entries": [{"at", "actor", "action", "resource", "detail"}]}`, newest first |
| GET | `/api/v1/agent/connect` | Agent transport (HTTP upgrade); not for humans |

User object: `id`, `email`, `display_name`, `role`, `disabled`, `must_change_password`, `tags`,
`created_at`, `last_login_at`.

Agent object: `id`, `name`, `connected`, `remote_addr`, `connected_at`, `protocol` (the connected
agent's protocol version), `owner_user_id`, `owner_email`, `tags` (in effect), `labels`,
`allow_public`, `default_private`, `last_seen_at`, `tunnels`, `created_at`.

Tunnel object: `id`, `name`, `hostname`, `public_url`, `target`, `agent_id`, `visibility`,
`access` (private: the tags in effect), `labels`, `status`
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

[`.github/workflows/release.yml`](.github/workflows/release.yml) runs only when a GitHub
release is published:

1. clippy and the test suite on Linux and macOS;
2. a release build for each of the four targets above, each on its own OS (native ARM64
   runners for Linux ARM64);
3. `scripts/smoke-test.sh` against each build on that OS: real server with a dev CA, login,
   `add`, a public HTTPS request through the tunnel, `agent stop`;
4. if every platform passed, the four archives and `SHA256SUMS` are attached to the release.

To publish, create a GitHub release with a tag such as `v0.2.0` on a commit from `main`. The
workflow refuses tags that aren't on `main`, and warns if the tag doesn't match the `version`
in `Cargo.toml` (bump that first so `--version` is right). The toolchain is pinned to Rust 1.90.
To check builds without releasing, run `cargo test --workspace` and `scripts/smoke-test.sh`
locally.

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
crates/magicpipes-cli      magicpipes: CLI commands, client.rs (agent lifecycle), agent/ (session, forward, ops, serve, shell)
```

## License

MIT ([LICENSE](LICENSE)). For the web terminal, the `magicpipes` binary embeds xterm.js and its
fit and unicode11 addons (MIT, © the xterm.js authors) and Symbols Nerd Font Mono from Nerd Fonts
(MIT, © Ryan L McIntyre); their licenses ship as `LICENSE-xterm.js`, `LICENSE-xterm-addon-fit`,
`LICENSE-xterm-addon-unicode11` and `LICENSE-nerd-fonts` in release archives.

Third-party Rust dependencies are checked by `cargo deny check` against [deny.toml](deny.toml)
(permissive licenses only, no known advisories, crates.io only); CI runs it on every push.
