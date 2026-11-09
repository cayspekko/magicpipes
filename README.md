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

  URL:    https://bright-otter.t.example.com
  Local:  http://127.0.0.1:8080

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
`magicpipes add 5432 --tcp --allow-cidr <network>` (or `--udp`) publishes any service on a raw
public port. See
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

**Your own certificates** work alongside any mode, for a name the usual source can't serve: an
internal name, one without port 80, a certificate from a company CA, or a wildcard you already have.
A name one covers uses it and is never ordered. Add one in either of two ways:

* On the **Settings** page, under **Certificates**: paste the certificate and its private key. They're
  kept in `data_dir/provided-certs` (0600), and in use at once.
* In the configuration file, when another tool renews it. Changed files are picked up within 5 minutes.
  Files that can't be used leave the loaded certificate in use, and the page says why.

  ```toml
  [[tls.certificates]]
  cert_file = "/etc/magicpipes/shop.crt"
  key_file = "/etc/magicpipes/shop.key"
  ```

Nothing renews these for you. The Settings page shows what's about to expire, and the home page warns
when one in use is within 30 days of it. An expired one stays in use and its tunnels show their
certificate as failed, until you replace or remove it; removing it hands its names back to the usual
source. The management hostname never uses one, so a bad certificate can't lock you out of the page
that fixes it: use `management.cert_file` for that.

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
trusted_proxies = ["172.23.0.2/32"]   # the proxy's own address

[public]
proxy_protocol = true
[management]
proxy_protocol = true
[ports]
proxy_protocol = true
```

List only the proxy itself, not its whole network: anything at a listed address can name any
client, and skips the per-client limits. In Docker, give the proxy a fixed address on its network.
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
magicpipesd --config ... admin-token --rotate   # revoke all others, and their UI sessions
```

Sign in to the UI at `https://example.com:8443` with that token ("Use an admin token" on the
sign-in page). The admin token always works, whatever else is configured; keep it for
emergencies.

### Users

Under **Users**, administrators add people with an email address, a role and a password (or
let the server generate one, shown once). Everyone must replace a password set by an
administrator when they first sign in. With a mail server, they're invited by email instead: see
[Email](#email).

* **Roles**: *administrators* manage tunnels, agents, users, tags, enrollment tokens and the
  audit log; *members* manage their own account (password, API tokens, sessions) and their own
  machines and tunnels. Design: [docs/USERS.md](docs/USERS.md).
* **Tags** (Tags page, e.g. `dev`): labels on people, service machines and tunnels.
  Administrators create them, assign them to people, and decide per tag whether it **grants
  access**. Someone can open a private tunnel when they and the tunnel share a tag that grants
  access; that is the only rule. Every account also gets a **personal tag** (`user:k8p4x2m9qa`,
  random; the UI shows the person), made with it and put on every tunnel of that person's
  machines, which is how owners get into their own tunnels. No one else can hold it and its
  access can't be turned off, but it can go on any tunnel to share that tunnel with one person
  (`--tag user:k8p4x2m9qa`). Other tags on a tunnel must be ones its owner holds
  (`magicpipes add 3000 --tag dev`), checked each time. A tunnel's tags are its own: taking `dev`
  away from someone doesn't unshare the tunnels they already shared with `dev`. A tag that
  doesn't grant access is just a label.
  Matching is exact; nobody can give themselves a tag. Deleting a tag takes it away from
  everyone and everything at once. In the UI, **Edit** next to a user's or a service agent's tags opens a
  picker: every tag as a pill grouped by key, a filter box (Enter picks the first match) and a
  tray of what will be added (green, `+`) or removed (red, `−`), with a warning when a removal
  closes private tunnels. Administrators can also type a tag that doesn't exist yet and create
  it there; it is registered (without a description) only when you save. Nothing changes until
  you save, and saving applies only those changes, so another administrator's edit made
  meanwhile is kept. Without JavaScript, Edit opens a page
  of checkboxes instead.
* **Sign-in protection**: passwords are stored as Argon2id hashes and need at least 12
  characters. After 10 failed attempts within 15 minutes, an account accepts one attempt every
  10 seconds, right password or not. An address with 10 failed attempts within 5 minutes
  (an IPv6 /64 counts as one) gets no password checked at all until it waits. A wrong password
  and an unknown email get the same answer. The sign-in form only accepts posts from its own
  page, so another site can't sign your browser into its account.
* **Single sign-on**: see below, or the **Settings** page.
* **Sessions** last `[users] session_max_age_secs` (12 hours) and survive server restarts.
  Changing your password, being disabled, or "Sign out everywhere" ends them. Signing out here
  doesn't sign you out at a single sign-on provider.
* **API tokens** (Account page) act as their user with the user's current role:
  `Authorization: Bearer tok_…`. Disabling the user stops them. "Reset password" revokes them, and
  so does "Revoke API tokens" on the Users page; signing out everywhere doesn't.
* **Audit log**: sign-ins (including failed ones), account changes, deletions, revocations and
  enrollment tokens, kept for `[users] audit_retention_days` (90).


### Settings for when you know what you're doing

The defaults are the safe ones. These turn something on, or tighten it further, on purpose:

| Setting | Default | What it does |
|---|---|---|
| `add --allow-any` | off | Opens a raw port to the whole internet |
| `add --site` | off | Lets HTML and SVG in a served folder run scripts |
| `add --allow-sensitive-root` | off | Serves a home folder, a hidden folder in it, or the filesystem root |
| `add --allow-sensitive-socket` | off | Publishes a Unix socket that usually hands over the machine or your keys, such as Docker's or your SSH agent's |
| `add --write` | off | Lets anyone with a terminal's link, and whoever controls the server, run commands as you |
| `[public] allow_cookie_domain` | off | Lets applications set cookies for the whole base domain, which reach other tunnels and the management host |
| `[[oidc]] trust_email` | off | Accepts addresses the provider didn't verify, which also name people to machines' browser terminals |
| `[[oidc]] allow_unverified_admin` | off | Lets those addresses reach administrators' accounts |
| `[[oidc]] link_by_email` | off | Lets a first sign-in use an existing account with the same address |
| `[proxy_auth] trust_email` | off | Accepts addresses nothing says were verified |
| `[proxy_auth] allow_unverified_admin` | off | Lets those addresses reach administrators' accounts |
| `[proxy_auth] auto_create` | off | Gives anyone new with an accepted address a member account |
| `[smtp] tls = "none"` | off | Sends mail unencrypted, for a relay on this machine or a network you trust. A password is never sent this way |
| `[smtp] ca_file` | none | Trusts a private CA for the mail server, as well as the public ones |
| `[public] body_idle_timeout_secs` | off | Closes a connection after this long with no byte moving; breaks long polling and server-sent events if set below their quiet periods |
| `[ports] tcp_idle_timeout_secs` | off | The same for raw TCP ports |
| `[public] max_connections_per_client` | 64 | Open HTTPS connections per client address |
| `[management] max_connections`, `max_connections_per_client` | 1024, 64 | The same for the management listener. An agent's session stops counting once it has signed in |
| `[ssh] max_connections`, `max_connections_per_client` | 1024, 32 | Open connections to the SSH gateway |
| `[users] max_agents_per_user` | 25 | Machines a member may enroll themself (0: no limit) |

### Single sign-on

People can sign in through any OpenID Connect provider: Google, Microsoft (directories and personal
accounts), GitLab, Okta, authentik, Keycloak, Authelia, Dex and others, and through GitHub. Each
provider adds a "Continue with ..." button to the sign-in page, next to the password form.

**On the Settings page** (administrators), choose **Add** and a kind of provider. The page says
what to do at the provider and shows the redirect URI to register:
`https://<management hostname>/auth/oidc/<id>/callback`, with the management port if it isn't 443.
Paste the client ID and secret, plus whatever else that kind of provider needs, such as authentik's
address and application slug. Everything else comes from the provider's discovery document.
**Check and add** asks the provider about itself first and says what's wrong, such as a wrong
address or no usable signing key (authentik needs a **Signing Key** chosen; RS256 and ES256 are
accepted). It takes effect at once, without a restart. A wrong client ID or secret only shows at
the first sign-in, so try it from a private window.

The issuer can't be edited, because accounts are tied to it. To change it, remove the provider and
add it again. Removing a provider keeps its people's accounts; the page warns if any of them would
lose their only way in.

**Who gets in.** Having an account at the provider isn't enough. Someone who has signed in here
before is recognized by the provider's subject id, so changing their address there changes
nothing here. A first sign-in needs an email the provider says it verified, and then one of:

* the address is listed under **New administrators**: a new administrator's account;
* the address's domain is listed under **New members** (exactly; no subdomains): a new member's
  account;
* an account with that address exists and the provider has "Let a first sign-in use an existing
  account" on: it signs in to that account, and only one identity per provider can do so.

These lists apply to every provider, so only add a provider you trust. Anyone else is told their
address can't sign in here. To let in one person with an address outside your domains, add them
under **Users** and turn on that linking option; only do so for a provider that doesn't let people
choose or reuse addresses (Google and most company directories are fine; check first for a
self-hosted one where people edit their own email).

**GitHub and other public services.** Anyone can have a Google or GitHub account, so signing in with
one creates nothing unless the rules above say so. GitHub works like the others on the Settings page,
with an OAuth App instead of a discovery document, and with GitHub Enterprise Server if you change its
address. Someone is recognized by their numeric GitHub id, and only an address GitHub says is verified
counts. An address stays verified there after someone leaves a company, so think before listing a
domain under **New members**, or linking accounts by address.

**Providers that don't verify addresses.** Microsoft Entra never states `email_verified`, and
authentik since 2025.10 says `false` by default, so new people can't get in until you turn on
**Trust this provider's email addresses** for that provider. With it on, **anyone who can choose
their address at the provider could use any address on your lists**, so stop people changing theirs
there first (in authentik, turn off **Allow users to change email**). An address the provider didn't
verify still can't become or take over an administrator, unless you also turn on **Let those
addresses reach administrators' accounts**: you need that if your own first sign-in comes through
such a provider.

The temporary password an administrator set stops working once its owner has signed in with
single sign-on, and no password change is asked for. A password the person chose keeps working.
If a provider goes away, an administrator can give its users a password with "Reset password",
which also revokes their API tokens.
The admin token works regardless.

**In the configuration file.** The same settings can go in `magicpipesd.toml`. They show on the
Settings page as locked, and a provider there wins over one of the same id on the page. Lists from
the file and the page are combined. A missing `client_secret_file` stops the server from starting.

```toml
[users]
bootstrap_admins = ["you@example.com"]
allowed_email_domains = ["example.com"]

[[oidc]]
id = "google"                              # part of the callback URL
label = "Google"                           # "Continue with Google"
issuer = "https://accounts.google.com"     # exactly as the provider states it
client_id = "1234.apps.googleusercontent.com"
client_secret_file = "/etc/magicpipes/google-secret"
# link_by_email = true
# trust_email = true
# allow_unverified_admin = true            # needs trust_email
```

GitHub isn't OpenID Connect, so it says so, and its issuer is its address:

```toml
[[oidc]]
id = "github"
kind = "github"
label = "GitHub"
issuer = "https://github.com"              # or a GitHub Enterprise Server's address
client_id = "Iv1.0123456789abcdef"
client_secret_file = "/etc/magicpipes/github-secret"
```

### Authenticating proxy

If the management host already sits behind something that signs people in (oauth2-proxy, Authelia,
authentik's outpost, Pomerium, Cloudflare Access, or Caddy or nginx with forward auth), it can tell
MagicPipes who they are, instead of a sign-in page here. It's off unless `[proxy_auth]` is set.

A **signed token** is the safer way, because a forged request can't make one:

```toml
[proxy_auth]
mode = "jwt"
jwt_header = "Cf-Access-Jwt-Assertion"     # or Authorization, for oauth2-proxy's bearer token
jwks_url = "https://team.cloudflareaccess.com/cdn-cgi/access/certs"
issuer = "https://team.cloudflareaccess.com"
audience = "your-application-audience"
```

**Plain headers** are for proxies that can't sign anything. They're believed only from an address
in `trusted_proxies` that also sends a shared secret of at least 16 characters, so configure the
proxy to add that header:

```toml
trusted_proxies = ["172.23.0.2/32"]   # at the top of the file: the proxy's own address

[proxy_auth]
mode = "headers"
user_header = "X-Forwarded-Email"
secret_header = "X-MagicPipes-Proxy-Secret"
secret_file = "/etc/magicpipes/proxy-secret"
```

The proxy must replace any copy of these headers a client sends. A header sent twice counts as
nobody, in case a client's copy is beside the proxy's.

**Who gets in** follows the single sign-on rules above: someone seen before is recognized by their
identity, and a first visit needs a verified address. A token says so with `email_verified`; for a
token that doesn't, and for plain headers, set `trust_email = true`, since the proxy is what checked
the address. Then an account an administrator created with that address, an address under **New
administrators**, or a domain under **New members** lets them in. `auto_create = true` also gives
anyone else with an accepted address a member account. An unverified address reaches an
administrator's account only with `allow_unverified_admin = true`, so you need that if your own
first sign-in comes through plain headers.

**How it behaves:**

* Every page request has to keep naming the same person. If it stops, or names someone else, the
  session ends, so signing out at the proxy signs out here.
* Passwords and sign-in providers aren't offered, since their sessions couldn't last. An admin token
  still works, at `/login?method=token`, for when the proxy is down or misconfigured.
* "Sign out" leads to `sign_out_url`, if you set it, such as `https://auth.example.com/logout`.
  Otherwise there's no such button, because signing out here alone would sign you straight back in.
* These headers never reach a tunnel's application, except `Authorization`, which may be the
  application's own.

**What the proxy needs.** It has to read HTTP, so it must terminate TLS for the management host and
connect to MagicPipes over HTTPS, keeping the `Host` header. A proxy that passes TLS through by SNI,
such as HAProxy in TCP mode, can't do this. For plain headers, `management.proxy_protocol` must be
off, so that the connection's address is the proxy's. Let these paths past the proxy's sign-in,
because agents and scripts have their own credentials: everything under `/api/`, plus `/healthz`.

Tunnels aren't covered: this signs people in to the management host, and private tunnels then work
as usual.

### Email

With a mail server, administrators can invite people by email, and people can get a link to sign in
if they forget their password. Set it up under **Settings → Email**, which connects and signs in
before saving, or in the configuration file, where it's then locked on the page:

```toml
[smtp]
host = "smtp.example.com"
username = "magicpipes@example.com"
password_file = "/etc/magicpipes/smtp-password"
from = "MagicPipes <magicpipes@example.com>"
# port = 587                               # the usual one: 587 with STARTTLS, 465 with TLS, 25 with none
# tls = "starttls"                         # or "implicit" (the default on port 465), or "none"
# ca_file = "/etc/magicpipes/smtp-ca.pem"  # a private CA, as well as the public ones
```

With STARTTLS or TLS, the certificate has to check out and nothing is sent otherwise: not the
password, not who the message is for. Messages link to `management.hostname`, never to whatever a
request's `Host` said. **Send a test message** on the Settings page shows whether mail arrives.

**Invitations.** On the Users page, **Send invitation** emails a link with the role and tags you
chose. It works once, for 7 days. Whoever opens it chooses a password or any sign-in provider, and
the account is created then. Having the link is the proof, so a provider's own idea of their address
doesn't matter and the account gets the invited address, verified. Pending invitations are listed on
the same page, where you can send one again (the old link stops working) or revoke it. One from an
administrator who is disabled or made a member ends with that. Adding someone with a password is
still there under **Set a password yourself instead**.

**Sign-in links.** **Forgot your password?** on the sign-in page emails a link that works once, for
15 minutes. Whoever uses it can also choose a new password, which ends their other sessions. A link
only goes to an account with a password and a confirmed address:

* An address an administrator typed in isn't confirmed, since it could be someone else's. A person
  confirms theirs from the Account page, and the link has to be opened while signed in to that account.
  Accepting an invitation confirms it, and so does signing in with a provider that verified it.
* An account that only signs in with a provider gets none, since a link would be a way around that
  provider's own checks, such as a second factor.

The page answers the same way in the same time whether or not an account exists: requests are only
queued there, and everything else happens in the background. Each address gets at most 3 links per 15
minutes, each client may ask 10 times an hour, and the server sends at most 500 messages an hour
(100 per administrator). A code stays out of every server's logs because it's in the link's `#fragment`,
and only pressing the page's button uses it, so a mail scanner opening the link changes nothing.
Without scripts, the page asks for the code, which the message also gives on its own line.

Behind an [authenticating proxy](#authenticating-proxy), none of this is offered: people sign in
there, and an administrator adding them is what lets them in.

### Settings and the generated configuration

Listeners, domains, TLS and other startup settings stay in your configuration file. Sign-in
providers, the mail server and the lists above can also be set on the Settings page, which keeps them
in the database, their client secrets in `<data_dir>/oidc-secrets/` and the mail server's password in
`<data_dir>/smtp-password` (mode 0600).

The settings in effect, from both places, are always on disk at
`<data_dir>/magicpipesd.generated.toml`, rewritten at startup and after every change. The Settings
page shows it and offers it as a download. It holds no secrets, only the paths of secret files, and
editing it does nothing. To start another server from it, copy it elsewhere, along with the secret
files, and pass it with `--config`; its providers are then locked on that server's Settings page.

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
code matches. The machine then belongs to you: you manage it and its tunnels, and it publishes
with your tags (it has none of its own). Without a terminal, add `--browser` to wait for the
approval anyway.

**With an enrollment token**: create a single-use token (valid 1 hour by default) on the server,
on the UI's Machines page ("Enroll a machine"), or via `POST /api/v1/enrollments`. Administrators choose who
the machine belongs to (nobody, for a *service agent*, which then gets tags of its own), and
whether its tunnels may be public:

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
token out of shell history and away from other programs on the machine, use `--token-file <file>`,
pass it as `MAGICPIPES_TOKEN` or type it at the prompt. For a
`dev-ca` server, add `--ca-cert path/to/ca.crt`.

To revoke a machine (lost laptop, leaked credential), click **Revoke** next to the agent in the
UI or call `DELETE /api/v1/agents/{id}` (administrators, or the machine's owner). Its credential stops working at once, its live session
is closed and its tunnels are deleted. Enroll it again with a new token to bring it back.

---

## 3. Use tunnels

### Public and private

A **public** tunnel is reachable by anyone who has its address. A **private** one asks people to
sign in to the management UI first, then lets in anyone who shares a tag with it that grants
access: its owner through their personal tag, and others through the tags it was given.
Machines enrolled before the server had user accounts make public tunnels; machines enrolled
since make private ones unless asked otherwise.

```bash
magicpipes add 3000 --private                 # only you (your personal tag)
magicpipes add 3000 --tag dev                 # you, and everyone with dev (you must hold it)
magicpipes add 3000 --tag user:k8p4x2m9qa     # you, and that one person (their personal tag)
magicpipes add 3000 --public                  # anyone; refused if the enrollment doesn't allow it
```

A private tunnel of a service agent carries only the tags given with `--tag` (from the agent's
own): without one, nobody can open it.

### Your own hostnames

Tunnels are `<name>.<base domain>` unless an administrator registers a hostname of your own
under **Hostnames** (or `POST /api/v1/hostnames`): an exact name such as `shop.example.com`
(a bare domain works too), for one person's machines or one service agent. Its DNS must point
at the server. The certificate is ordered as soon as it is registered.

```bash
magicpipes add 8000 --hostname shop.example.com             # only on a machine it was assigned to
magicpipes add 8000 --hostname shop.example.com --no-verify # register now; skip the certificate wait and public check
```

`--no-verify` is for moving a site over: register the tunnel while DNS (or a proxy in front)
still points at the old server, switch it, then run the same command without `--no-verify` to
check the public address. Removing the hostname's registration deletes its tunnel. Wildcards
aren't supported.

* Opening a private tunnel in a browser without being signed in shows the sign-in page, then
  comes back to the same address. Signed in without a shared tag: an "access denied" page. API
  clients and scripts get `401 unauthenticated` or `403 forbidden` instead.
* The application receives `X-MagicPipes-User` (email) and `X-MagicPipes-User-Id` on every
  request; clients can't forge them. It never sees MagicPipes' own cookie.
* Taking a tag away, disabling a user or "Sign out everywhere" takes effect on the next request,
  and closes open WebSockets.
* `https://<tunnel>/.magicpipes/` is reserved on private tunnels (`/.magicpipes/logout` signs out
  of that tunnel). Signing in to a private tunnel needs JavaScript: the one-time sign-in code
  travels in the URL fragment, where no server or log sees it, and a small page of MagicPipes'
  passes it on.
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
magicpipes add 5432 --tcp --allow-cidr 203.0.113.0/24   # a raw TCP port, for one network
magicpipes add 53 --udp --allow-any # a UDP port, open to anyone

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
  URL:    https://docs.t.example.com
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
  The check and the read can't be separated: someone who can write to the directory can't swap a
  file for a symlink at the right moment to leave it (on Windows, only the last part of the path is
  protected this way).
* **Pages can't run scripts unless you say so.** HTML, SVG and XML files open with scripts and
  forms turned off, so a file in a shared folder can't read the rest of it with a visitor's session
  and send it elsewhere. Their own styles and images still load. For a web app or a site you trust,
  add `--site`.
* **Some folders need `--allow-sensitive-root`:** the filesystem root, your home folder, a hidden
  folder in it (`~/.ssh`) and anything holding this agent's files, since plenty of secrets aren't
  in hidden files.
* Running `add --serve` again for the same directory returns the same tunnel, applying `--site`
  as given. `--list` or `--no-list` change the listing; with neither it stays as it was.
  `magicpipes remove <name>` stops serving it.

> Everything in the directory (except hidden entries) is public. Serve a dedicated build or
> export directory, not a source checkout.

### Sharing a terminal

`magicpipes add --shell` puts a terminal on a public URL, like ttyd: your login shell, or any
program given after `--`. Each visitor gets **their own copy** of the program in a new
terminal, which is stopped when they close the tab. The page uses the MagicPipes look, and the
terminal resizes with the window.

```console
$ magicpipes add --shell --name top -- htop
Checking program...           ✓
...
  URL:    https://top.t.example.com
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
* `--max-clients N` limits how many programs run at once (default 5): a session's place is given
  back only once its program has gone. A tunnel starts at most 60 programs a minute, so opening and
  closing sessions in a loop can't run them, and their login scripts, without limit.
* Running the same command from the same directory again returns the same tunnel. `list` shows
  it as `shell:htop (read-only)`; `list --json` includes the `share_url`.

> The MagicPipes server relays the terminal and can read it (it terminates TLS for every
> tunnel). With `--write` that includes the link's secret, so whoever controls the server can run
> commands as you. Only use `--write` through a server you trust, and your own SSH for anything the
> server operator should not see.

### Unix sockets

An application that listens on a Unix socket gets an address the same way, on macOS and Linux:

```console
$ magicpipes add --unix /run/app.sock --private --name app
Checking socket...            ✓
Connecting to server...       ✓
Registering tunnel...         ✓
Checking HTTPS certificate... ✓
Checking tunnel...            ✓

Tunnel ready

  URL:    https://app.mp.example.com
  Local:  unix:/run/app.sock
```

Everything else works as it does for a port: `--name`, `--private`, `--tag`, `--hostname`, re-running
the command, and `--tcp` for a raw port in front of a socket. `magicpipes remove` also takes the path.
UDP needs a port, and Windows isn't supported yet: `--unix` fails there with `unsupported`.

* **Connections reach the socket as you.** That's what the agent runs as, so the socket's file
  permissions say nothing about who gets through the tunnel, and whoever does gets anything the service
  behind it trusts your user for. A database that lets its local users in without a password (peer
  authentication) lets them in too. So think about `--private`, or `--allow-cidr` with `--tcp`.
* **Some sockets need `--allow-sensitive-socket`**, because publishing one usually hands over more
  than anyone means to: Docker, Podman, containerd and other container or virtual machine engines
  (root on the machine, in effect), the system's services (D-Bus, systemd), your SSH or GPG agent,
  SSH's shared connections, tmux and screen sessions, and this agent's own socket. They're recognized
  by name and place, through any links, so this can't catch everything: it's a seatbelt, not a
  promise. Think of it before publishing a socket you don't know.
* **The path is kept as you gave it** (made absolute), and links are followed each time it connects. A
  deploy can point `current` at a new release under a running tunnel. A connection already open keeps
  going until the old release stops, as it would with a port.
* **Your server sees only the file's name** (`unix:app.sock`), since the full path can name you.
* **The application may restart.** A new socket file at the same path just works. While nothing
  answers, the tunnel says `local_unreachable`, as it does for a port.

Socket paths are limited to about 100 bytes by the operating system.

### SSH

With `[ssh]` in the server's configuration, a machine's sshd can be reached through the server, from
anywhere, with nothing else opened to the internet:

```console
$ magicpipes add 22 --ssh --name dev-box --tag team:dev
Checking local service...     ✓
Connecting to server...       ✓
Registering tunnel...         ✓
Checking tunnel...            ✓

Tunnel ready

  SSH:    ssh -J mp.example.com:2222 dev-box
  Local:  ssh://127.0.0.1:22
```

Whoever connects needs a public key on their account, under **Account → SSH keys**, or
`POST /api/v1/ssh-keys`. Then:

```console
$ ssh -J mp.example.com:2222 doug@dev-box
```

* **There are two locks.** The gateway checks that your key is on an account that shares a tag with
  the tunnel; owners get in through their personal tag. Then the machine's own sshd logs you in as usual,
  with its `authorized_keys`. Neither replaces the other. The same key can do both, but needn't.
* **The server can't read the session.** Your `ssh` talks to the real sshd inside the tunnel, so scp,
  rsync, git and port forwarding all work, the server holds no credentials for your machines, and it
  sees only encrypted traffic. Your `ssh` checks the machine's host key as it would anywhere, so the
  first connection asks about it. The gateway's own key is on the Account page.
* **It's always private.** `--public` is refused. For a port anyone can reach, use `--tcp`.
* **The gateway does nothing else.** It runs no commands and forwards nothing back in. Plain
  `ssh -p 2222 mp.example.com` lists the machines you can reach, and
  `ssh -p 2222 mp.example.com config >> ~/.ssh/config` makes plain `ssh dev-box` work. A machine you
  can't reach gets the same answer as one that doesn't exist.
* **Access follows your account.** Losing the tag, deleting the key, or being disabled ends sessions
  at once. Keys don't expire, and signing out everywhere leaves them alone.
* **Keys are Ed25519 or ECDSA**, up to 20 per account, and each can be on only one account. RSA and
  hardware (`sk-`) keys aren't taken yet: make one with `ssh-keygen -t ed25519`.

`--host` reaches an sshd elsewhere on the machine's network. Connections appear in the audit log as
`ssh.connect`, once a minute per key and machine at most.

#### Terminals in the browser

Everyone who can reach an SSH tunnel also gets **Open terminal**, in the Tunnels list and on the
tunnel's page: their own shell in the browser, logged in as the account they type, with no key on the
device they're using. The server is a certificate authority. For each session it makes a key and a
certificate that names the person by their MagicPipes email and lasts five minutes, and logs in with it
through the same tunnel as `ssh -J`. The machine decides who may be which account, so one SSH tunnel
can serve many accounts, each person their own.

Once per machine, as root (the tunnel's page shows these lines with your server's key), then reload sshd:

```console
# echo 'ssh-ed25519 AAAA… magicpipes user CA' > /etc/ssh/magicpipes_ca.pub
# cat >> /etc/ssh/sshd_config <<'EOF'
TrustedUserCAKeys /etc/ssh/magicpipes_ca.pub
AuthorizedPrincipalsFile %h/.ssh/authorized_principals
EOF
```

Then each account lists, one per line, the MagicPipes addresses that may log in as it:

```console
$ echo 'ann@example.com' >> ~/.ssh/authorized_principals
```

* **The server can read browser sessions,** and anyone controlling it could log in to every machine
  that trusts its key, as any account that lists someone. `ssh -J` stays end to end. The key is
  `<data_dir>/ssh-user-ca`, kept like the server's other secrets, and `GET /api/v1/ssh-ca` gives its public half.
* **The machine's host key is kept** the first time a browser terminal connects, and a different one is
  refused, since that would mean something is in between. After reinstalling the machine, its owner
  forgets the old key on the tunnel's page.
* **Access follows your account,** as for `ssh -J`: losing the tag, being disabled or signing out
  everywhere ends the session. Each person may have 8 open.
* **Addresses are principals.** With `trust_email` on for a sign-in provider, someone who can choose
  their address there can take on an address an account lists, unless an account already has it.
* Opened terminals appear in the audit log as `ssh.terminal`.

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

  URL:    tcp://example.com:65507
  Local:  tcp://127.0.0.1:5432
```

```bash
psql -h example.com -p 65507 -U me mydb
```

* **The port stays the same** for the tunnel: re-running `add`, restarting the agent or the
  server keeps it. `--remote-port N` asks for a specific port inside the server's range.
* **A new port says who may connect:** `--allow-cidr` (repeatable: networks or single addresses),
  or `--allow-any` for the whole internet, with only your service's own authentication in front of
  it. With neither, `add` refuses (`invalid_request`). Other clients are disconnected at once.
  Re-adding without either keeps the list; a new `--allow-cidr` replaces it, and `--allow-any`
  removes it.
* **UDP allow-lists aren't authentication.** A datagram's source address can be forged, so a
  forged packet can reach your service past `--allow-cidr` (the reply goes to the forged address).
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
  `::1`; `--host` picks another local address, and `--unix` a socket.
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
| 1 | `internal`, `invalid_request`, `bad_request`, `protocol`, `busy`, `rate_limited`, `invalid_server`, ... | Unexpected error, or a request that can't be served as it is |
| 2 | | Invalid command-line usage |
| 3 | `not_logged_in`, `unauthorized`, `invalid_enrollment_token`, `config_error`, `forbidden`, `unauthenticated` | Enrollment, credentials or local configuration |
| 4 | `local_unreachable`, `invalid_port`, `invalid_host`, `invalid_directory`, `invalid_command`, `invalid_socket`, `spawn_failed` | Nothing listening locally, `--serve` directory missing, `--unix` path not a socket or refused, or `--shell` program not found |
| 5 | `server_unreachable`, `agent_unavailable`, `agent_start_failed`, `agent_not_running`, `agent_protocol`, `agent_outdated`, `mail_failed` | Cannot reach server or agent, or the running agent (or, for the server, the machine's magicpipes) is too old for the request |
| 6 | `name_conflict`, `name_taken`, `email_taken`, `tag_unknown`, `public_not_allowed`, `invalid_name`, `limit_reached`, `not_found`, `port_unavailable`, `kind_mismatch`, `ports_disabled`, `ssh_disabled`, `ssh_key_taken`, `server_outdated`, `unsupported`, `invalid_cidr`, `mail_not_configured` | Naming/registry, the server cannot give out that port, or the server needs a newer version |
| 7 | `tls_failed`, `tls_timeout` | Certificate not ready |
| 8 | `probe_failed` | Public URL did not reach the application |

`name_conflict`: one of your own tunnels already uses the name for another target. `name_taken`:
another machine's agent owns it. `busy`: the local agent is in the middle of a conflicting operation.
`rate_limited`: too many failed attempts from this client. Codes are listed in
`crates/magicpipes-core/src/error.rs`; new ones may appear in later versions, so treat an unknown
code like `internal`.

Pages the server generates for public traffic say which of these it was in an `x-magicpipes-error`
header, so a script can tell them from the application's own answers:

| HTTP | Code | Meaning |
|---|---|---|
| 400 | `bad_host`, `bad_uri` | The request's host or address is malformed |
| 404 | `tunnel_not_found` | No tunnel has this address |
| 405 | `method_not_allowed` | `CONNECT` isn't supported |
| 421 | `misdirected_request` | The request names a different host than its TLS connection |
| 502 | `agent_offline` | The machine serving the tunnel isn't connected |
| 502 | `tunnel_inactive` | The agent no longer serves this tunnel |
| 502 | `local_unreachable`, `upstream_error`, `bad_upstream` | The application couldn't be reached, broke off, or sent an invalid answer |
| 503 | `agent_busy` | The tunnel is handling too many connections; try again shortly |
| 504 | `upstream_timeout` | The application didn't answer in time |

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
| `MAGICPIPES_HOME` | State directory (default `~/.magicpipes`, mode 0700): `config.json`, `tunnels.json`, `agent.sock`, `agent.lock`, `agent-start.lock`, `agent.pid`, `agent.log` |
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
| POST | `/api/v1/enrollments` | 201 `{"enrollment_token", "expires_in_secs"}`; optional body `{"owner_user_id"?, "tags"?, "allow_public"?, "default_private"?}`; `tags` only for a service agent (no owner). Members may enroll only their own machines |
| POST | `/api/v1/enroll` | Exchange an enrollment token for agent credentials (used by `login`) |
| GET | `/api/v1/me` | `{"kind": "admin_token"}` or `{"kind": "user", "user": {...}}` |
| GET | `/api/v1/shared` | Tunnels you can reach but don't manage (`name`, `public_url`, `kind`, `visibility`, `owner_email`) |
| PATCH | `/api/v1/agents/{id}` | `{"tags"?}`; a service agent's tags (administrators) |
| GET | `/api/v1/tags` | `{"tags": [{"name", "description", "access", "created_at"}]}` (administrators; personal tags not listed) |
| POST | `/api/v1/tags` | 201; body `{"name", "description"?, "access"?}` (`access` defaults to true; `user:` names are reserved) |
| PATCH | `/api/v1/tags/{name}` | `{"access": bool}`: whether it grants access |
| DELETE | `/api/v1/tags/{name}` | 204; removes it from every user, agent and tunnel |
| GET | `/api/v1/hostnames` | `{"hostnames": [{"hostname", "owner_user_id"?, "owner_email"?, "agent_id"?, "agent_name"?, "tunnel"?, "tls", "created_at"}]}` (administrators: all; others: those assigned to them) |
| POST | `/api/v1/hostnames` | 201; body `{"hostname", "owner_user_id"? \| "agent_id"?}` (exactly one; administrators) |
| DELETE | `/api/v1/hostnames/{hostname}` | 204; deletes the tunnel on it |
| POST | `/api/v1/device` | Starts a browser-approved `magicpipes login` (used by the CLI) |
| POST | `/api/v1/device/poll` | Its result: `pending`, `approved` (with `enrollment_token`), `denied` or `expired` |
| GET | `/api/v1/users` | `{"users": [...]}`: every account for administrators, your own for members |
| POST | `/api/v1/users` | 201 `{"user", "password"?}`; body `{"email", "display_name"?, "role"?, "password"?}`. Without `password` one is generated and returned once. `409 email_taken` if the email has an account |
| GET | `/api/v1/users/{id}` | One user |
| PATCH | `/api/v1/users/{id}` | `{"role"?: "admin" \| "member", "disabled"?: bool, "tags"?: [...]}`; role and status not for your own account |
| POST | `/api/v1/users/{id}/password` | `{"password"}`: a new generated password the user must change; ends their sessions and revokes their API tokens |
| DELETE | `/api/v1/users/{id}/tokens` | `{"revoked": n}`: revokes all of a user's API tokens (your own, or anyone's for an administrator) |
| GET | `/api/v1/invitations` | `{"invitations": [...]}`, newest first (administrators) |
| POST | `/api/v1/invitations` | 201 `{"invitation"}`, once the mail server has taken the message; body `{"email", "display_name"?, "role"?, "tags"?}`. Replaces any invitation for that address. `409 email_taken`, `409 mail_not_configured`, `502 mail_failed` |
| POST | `/api/v1/invitations/{id}/resend` | `{"invitation"}`: sends it again with a new link, for another 7 days. The old link stops working once this one has gone out |
| DELETE | `/api/v1/invitations/{id}` | 204; its link stops working |
| GET | `/api/v1/tokens` | Your API tokens (never their secrets) |
| POST | `/api/v1/tokens` | 201 `{"api_token", "token"}`; body `{"name", "expires_in_days"?}`; the secret is returned once; at most 20 per user |
| DELETE | `/api/v1/tokens/{id}` | 204 |
| GET | `/api/v1/ssh-ca` | `{"public_key"}`: the certificate authority browser terminals log in with, for sshd's `TrustedUserCAKeys`; `ssh_disabled` (409) without a gateway |
| GET | `/api/v1/ssh-keys` | Your public keys for the SSH gateway |
| POST | `/api/v1/ssh-keys` | 201 `{"ssh_key"}`; body `{"public_key", "name"?}`; `invalid_ssh_key` (400), `ssh_key_taken` (409), or `limit_reached` (409) past 20 |
| DELETE | `/api/v1/ssh-keys/{id}` | 204; connections using it end |
| GET | `/api/v1/audit?limit=N` | `{"entries": [{"at", "actor", "action", "resource", "detail"}]}`, newest first |
| GET | `/api/v1/agent/connect` | Agent transport (HTTP upgrade); not for humans |

User object: `id`, `email`, `display_name`, `role`, `disabled`, `must_change_password`,
`has_password` (false for someone who only signs in with single sign-on), `email_verified` (they
proved the address is theirs), `tags` (assigned), `personal_tag`, `created_at`, `last_login_at`.

Invitation object: `id`, `email`, `display_name`, `role`, `tags`, `invited_by` (a user's id or
`admin-token`), `created_at`, `expires_at`, `expired`. Never its code.

Agent object: `id`, `name`, `connected`, `remote_addr`, `connected_at`, `protocol` (the connected
agent's protocol version), `owner_user_id`, `owner_email`, `tags` (what it publishes with: its owner's, or a service agent's own),
`allow_public`, `default_private`, `last_seen_at`, `tunnels`, `created_at`.

Tunnel object: `id`, `name`, `hostname`, `public_url`, `target`, `agent_id`, `visibility`,
`tags` (the owner's personal tag included), `access` (private: the tags that let people in), `status`
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

To measure a change against a baseline, on macOS or Linux (see
[`scripts/bench`](scripts/bench/README.md)):

```bash
scripts/bench/build.sh base origin/main
scripts/bench/build.sh new
scripts/bench/compare.sh base new
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
`LICENSE-xterm-addon-unicode11` and `LICENSE-nerd-fonts` in release archives. The management UI
uses icons from Lucide (ISC, © Lucide Contributors, with portions © Cole Bemis as part of Feather);
its license ships as `LICENSE-lucide`.

Third-party Rust dependencies are checked by `cargo deny check` against [deny.toml](deny.toml)
(permissive licenses only, no known advisories, crates.io only); CI runs it on every push.
