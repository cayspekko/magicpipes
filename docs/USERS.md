# Users, SSO and tag-based access (design)

Status: proposal, not implemented. This is roadmap phase 4. It replaces the per-user "grants"
in ROADMAP.md, and the SSH gateway, browser desktops and a future VPN use the same model.

## Goals

- People log in with a password an admin set for them, through an authenticating proxy that is
  already in front of the server, with SSO (OIDC), with a social account, or with an emailed
  link. These ship in that order, and every method ends in the same kind of session. Agents
  and tunnels belong to someone.
- One access mechanism, **tags**, for users, agents, tunnels and later VPN connections. One
  function, `authorize(principal, action, resource)`, makes every decision, whether for HTTP,
  TCP/UDP, the management UI or the API.
- KISS: exact tag matching, any-match rules, two fixed roles (admin and member). There is no
  policy language, no role hierarchy and no wildcards.
- Default deny. Public tunnels are an explicit, visible exception.
- Nothing changes for a server that has no users or doesn't use these features. Migrated
  agents and tunnels keep working as they do today, and the admin token always works.
- Use free, permissively licensed libraries where they save real work (password hashing, JWT
  checks, SMTP), never a hosted identity service.

Non-goals for this phase:
- several organizations per server in the UI (the schema allows it);
- SCIM provisioning;
- per-path or per-method rules;
- the VPN itself.

## The model in one page

```text
Org (workspace)                     every tag, user, agent and tunnel belongs to one org
 ├─ access tags: team:dev, team:ops  registered by an admin; the only tags authorize() reads
 ├─ users ── tags ← admin assignment | rules (proxy or IdP group, IdP claim, verified email domain)
 ├─ agents ── owner (a user, or none for service agents)
 │            tags ← enrollment token (at most the owner's tags)
 └─ tunnels ── owner = its agent's owner
               public, or private with access tags (default: the agent's tags)
               labels: free-form metadata, never used for access
```

**The rule:** a principal may connect to a private tunnel, and see it in lists, when the
principal shares at least one access tag with the tunnel's effective access set, or owns the
tunnel. That is the whole access rule. Everything else is about where the tags come from.

### Access tags and labels

There are two kinds of tags, stored separately so metadata can never grant access:

| | Access tags | Labels |
|---|---|---|
| Example | `team:dev`, `contractor:acme` | `environment:production`, `owner:doug` |
| Created by | org admins, in the `tags` registry | anyone who can manage the object, free-form |
| Attached to | users, agents, enrollment tokens, tunnel access sets | agents and tunnels |
| Read by `authorize()` | yes | **never** |
| Purpose | who may reach what | search, filters and display in the UI and CLI |

Both kinds use the same syntax: lowercase, `[a-z0-9][a-z0-9._-]*` with an optional `:value`
made of `[a-z0-9._@-]`, at most 64 bytes. Names are normalized and validated on write, and
matching is exact string equality. Access tags live in their own tables, and labels in a
`labels` column. A label string that later gets registered as an access tag therefore grants
nothing retroactively: no stored row changes kind.

### Roles

Each membership has one of two roles. Neither is a tag, and neither can be assigned by the
holder.

- **admin**: manages the org (users, access tags, rules, enrollment tokens, any agent or
  tunnel). An admin doesn't automatically *connect* to private tunnels. Like anyone else, they
  need a shared tag or ownership. Admins can give themselves tags, so this is not a hard
  barrier. What it buys is that reaching someone's shell tunnel takes an explicit, audited
  step instead of being implicit.
- **member**: logs in, sees and connects to what the tags allow, owns agents and tunnels
  enrolled for them, and manages those.

The existing admin tokens (`admin_tokens`) stay permanently, whatever login methods are
configured. They are a break-glass principal with admin rights for the default org, and they
are how the first user gets created. Disabling and regenerating them from the UI comes later;
today `magicpipesd admin-token --rotate` replaces them. For scripts, named API tokens owned by
users (below) are the better choice.

## Principals, actions and resources

```rust
pub enum Principal {
    Anonymous,                                  // a public client with no session
    User { org: OrgId, user: UserId, role: Role, tags: TagSet },
    Agent { org: OrgId, agent: AgentId, owner: Option<UserId>, tags: TagSet },
    AdminToken { org: OrgId },                  // break-glass, today's admin token
}

pub enum Action { Discover, Connect, Manage }

pub enum Resource<'a> {
    Tunnel(&'a TunnelAuthz),   // org, owner user, agent, public flag, effective access set
    Agent(&'a AgentAuthz),     // org, owner user
    Org(OrgId),                // users, tags, rules, enrollment tokens, audit log
}

pub fn authorize(p: &Principal, a: Action, r: &Resource) -> Decision;
```

The decision table, evaluated in this order; the first matching row wins:

| # | Condition | Result |
|---|---|---|
| 1 | `Connect` to a public tunnel, by anyone, including anonymous clients and other orgs | allow (after the network allow-list, see below) |
| 2 | Anonymous, disabled or expired principals, or a principal whose org differs from the resource's | deny |
| 3 | `Org`: admin or admin token, any action | allow |
| 4 | `Org`: anyone else | deny |
| 5 | `Manage` a tunnel or agent: its owner user, the agent itself (for its own tunnels), an admin, the admin token | allow |
| 6 | `Manage`: anyone else | deny |
| 7 | `Discover` a public tunnel | allow |
| 8 | `Connect` or `Discover` a private tunnel: its owner user, or its own agent | allow |
| 9 | `Connect` or `Discover` a private tunnel: shares any access tag with the tunnel's effective access set | allow |
| 10 | Anything else | deny |

- **Enrollment tokens are a validation, not a decision row.** A member may create one only for
  themselves, with tags they hold (see "Agents"); the handler checks that. It isn't a
  permission on `Org`.
- **Discovery equals connection.** Rows 8–9 give `Discover` and `Connect` the same answer for
  private tunnels. If a separate "listed but not reachable" or "reachable but unlisted" mode
  is ever needed, it becomes an extra tunnel flag, not a second permission model.
- **`authorize()` is a pure function** over precomputed views (`TagSet` is a sorted
  `Box<[Arc<str>]>`). It is unit-tested as a table and called in three places:
  - the control plane, for API, UI and RPC handlers, replacing the five copies of the ownership
    check (audit design item 1);
  - the data plane, per HTTP request or per TCP/UDP connection;
  - later, the SSH gateway and the VPN.
- **The data plane still never touches SQLite.** At publish time the control plane computes
  each route's `TunnelAuthz` and a `principals` map, user id → `{ org, role, tags,
  sessions_valid_after, disabled }`. It puts both into the immutable `RouteTable` snapshot.
  A tag or membership change republishes, so every new request sees it immediately.
- **The network allow-list stays in front of everything.** `--allow-cidr` is checked first, and
  `authorize()` runs only for clients inside the allowed networks. Both must pass. `Route.allow`
  becomes `Route.access: AccessPolicy { allow: Vec<Cidr>, authz: TunnelAuthz }`, checked in one
  helper for HTTP and ports (audit design item 5).

## Where tags come from

### Users

| Source | When it applies | Revoked when |
|---|---|---|
| Admin assignment | immediately | an admin removes it: immediate |
| Rule: group from the IdP (`groups` claim or a configured claim), the proxy's groups header, or GitHub org/team | at each login | the user's next login without the group, or the session's maximum age; deleting the rule: immediate |
| Rule: other IdP claim (`hd`, `department`, …) equals a value | at each login | same |
| Rule: verified email domain | at each login, only for a verified email | same |

An email counts as verified in these cases:
- the IdP says `email_verified: true`;
- GitHub lists it as verified;
- the proxy is trusted for email (`trust_email = true`);
- the user proved it by accepting an invitation or using an emailed link.

An email typed in by an admin is not verified.

- **How rules work.** A rule is `(provider, claim, value) → access tag`, created by an admin.
  On every login the server re-evaluates every rule against the fresh claims (ID token, proxy
  assertion or GitHub API) and replaces that user's rows in `user_rule_matches`. A user's tags
  are their admin-assigned `user_tags` plus the tags of the rules they match. Deleting a rule
  therefore revokes its tag from everyone at once, through the cascade.
- **Matching is exact**: `claim == value`, or `value ∈ claim` when the claim is a list. The
  email-domain rule compares the part after `@`, lowercased, with no subdomain wildcard.
- **Revocation lag for rule-based tags.** It is bounded by the session's maximum age
  (`session_max_age_secs`, default 12 h): after that the user must log in again, which
  re-reads the IdP. Re-checking through the refresh token every hour is a later improvement.
- **No self-assignment.** Only admins create access tags, assign them to users, and write
  rules. A member can't add a tag to themselves, and an IdP claim can only map to tags that an
  admin has wired up.

### Agents

- **Agents get tags only through their enrollment token.** The token records who created it,
  which org it belongs to, the owner the new agent will have, its access tags and labels, and
  whether its tunnels may be public.
  - Admins may create tokens for any owner, including none (a service agent), with any
    registered access tags.
  - Members may create tokens only for themselves, and only with access tags they currently
    hold. This is how `magicpipes login` works for a person: see "CLI".
- **A personal agent can never have more access than its owner.** For an agent owned by a user,
  the effective tags are its assigned tags intersected with the owner's current tags. If the
  owner leaves `team:dev`, their agent loses it in the same publish. A service agent
  (`owner_user_id IS NULL`) keeps exactly the tags an admin gave it.
- **After enrollment**, only an admin changes a service agent's tags. The owner may *remove*
  tags from their own agent but never add one; adding means enrolling again or asking an
  admin.

### Tunnels

- **Visibility is `public` or `private`.**
  - The default comes from the agent's enrollment.
  - Migrated agents default to `public`, as today.
  - New enrollments default to `private` once the server has users. `--public` is allowed only
    if the enrollment allows it. Members' enrollments allow it when `[users]
    members_can_publish` is true (the default).
- **Access set.** A private tunnel's access set defaults to the agent's effective access tags.
  The owner may narrow it (`--access team:dev`), but never widen it beyond the agent's tags:
  `effective access = requested ∩ agent's effective tags`. An agent can't publish to an
  audience it isn't part of.
- **Empty access set.** A private tunnel whose effective access set is empty is reachable only
  by its owner and its own agent. It is never treated as public. This is the fail-closed case,
  for example after a tag is deleted.
- **Labels** are inherited: tunnel labels = agent labels + the tunnel's own. They are shown and
  filterable, never used for access.

### Revocation summary

Every change below takes effect on the next request through the published snapshot.

| Change | Effect |
|---|---|
| Remove an access tag from a user | That user loses it; their personal agents lose it; tunnels whose effective access drops it shrink |
| Delete a rule | Every user who got a tag only through that rule loses it |
| Delete an access tag | Cascades to every user, agent, enrollment token, rule and tunnel access row; tunnels left with an empty set become owner-only |
| Disable a user or remove their membership | Sessions, API tokens and tunnel cookies are rejected. Their personal agents can't connect, and their tunnels are unpublished |
| "Log out everywhere" | Bumps `sessions_valid_after`; every session and tunnel cookie issued before it is rejected |
| Revoke an agent | As today, plus its tunnels' access rows |

**Long-lived connections are re-checked too.** Each one carries its principal: WebSockets,
TCP, and later SSH and VPN flows. On every publish, the data plane re-runs `authorize()` for
each open connection and closes the denied ones. An HTTP request in flight finishes.

## Logging in

Every method ends the same way:
1. The server resolves an **identity** to a user.
2. It checks that the user isn't disabled and is a member of the org.
3. It re-evaluates the tag rules.
4. It creates a `sessions` row and sets `__Host-mp_session` (with its CSRF token).

Everything after login is the same whichever method was used. Identities are keyed by
`(issuer, subject)`. A user is never matched by email alone, except through methods that prove
the user controls the address.

| Method | `issuer` | `subject` |
|---|---|---|
| Password, invite, emailed link | `local` | the account's email, lowercased |
| Authenticating proxy | `proxy` (plain headers) or the JWT's `iss` | the asserted user, or the JWT's `sub` |
| SSO (OIDC), and Google, Microsoft and GitLab social login | the provider's issuer URL | `sub` |
| GitHub | `https://github.com` | the numeric GitHub user id |

**Sessions and API tokens**
- **Sessions move from memory to the `sessions` table.** They survive restarts, and admins can
  revoke them. The cookie keeps its name, `__Host-mp_session`, and its CSRF token, and it
  expires after `session_max_age_secs` (12 h, as today).
- **API tokens** become `api_tokens` rows: owned by a user, named, with an optional expiry, and
  shown once at creation. A request with one acts as that user, with that user's current role
  and tags.

The methods ship in this order, each usable on its own.

### 1. Users with passwords

- **Admins create users** in the UI or API: email, display name, role, access tags, and either
  a password they choose or a generated one shown once. Either way the user must change it at
  first login.
  - Admins can also reset a password (same forced change) and disable a user.
  - Users change their own password after entering the current one. A change ends their other
    sessions.
- **Hashing uses Argon2id** from the `argon2` crate (RustCrypto, MIT/Apache-2.0), with OWASP's
  parameters: 19 MiB of memory, 2 iterations, 1 lane. Hashing runs on the blocking pool behind
  a semaphore of 4, so a burst of logins can't use up memory or CPU.
- **Password rules.** At least 12 characters and at most 256 bytes, with no composition rules.
  The password may not equal the email.
- **No account enumeration.** An unknown email still runs a dummy hash and gets the same error
  ("email or password is incorrect").
- **Throttling** comes in two layers:
  - the existing per-client failure limiter;
  - a per-account limit: after 10 failures in 15 minutes, one attempt per account every 10 s.

  Unlike tokens, a password is guessable. So the account limit applies *before* the password
  is checked: a correct password from a throttled account waits too. The cost is that an
  attacker can slow one account down. They can't lock it out, and the admin token is never
  affected.
- **TOTP is not in this phase.** It can come later with `totp-rs` (MIT).

### 2. Authenticating proxy (forward auth)

This is for servers that already sit behind oauth2-proxy, Authelia, Authentik, Pomerium,
Cloudflare Access, or Caddy/nginx forward auth. The proxy logs the user in, passes who they are
to magicpipesd, and magicpipesd turns that into a normal session. It is off unless
`[proxy_auth]` is configured. There are two modes.

- **Signed assertion (recommended).**
  - The proxy forwards a JWT, for example `Cf-Access-Jwt-Assertion`,
    `X-Pomerium-Jwt-Assertion`, or the IdP's ID token from oauth2-proxy
    (`--pass-authorization-header`).
  - magicpipesd verifies its signature against the configured JWKS URL, plus the issuer,
    audience and expiry.
  - A forged request can't produce one, even from inside the Docker network.
- **Plain headers.**
  - `X-Forwarded-Email`, `Remote-User`, `X-Auth-Request-Email` or similar, plus an optional
    groups header.
  - They are believed only when *both* conditions hold:
    - the peer is in `trusted_proxies`, checked with the same `TrustedProxies` code as
      X-Forwarded-For;
    - the request carries a shared secret header that the proxy is configured to add,
      compared in constant time.
  - Requests that fail either check are treated as having no identity headers. Rejections are
    logged at debug level.

How it behaves:
- **Logging in.** A request with a valid assertion and no session creates one. While proxy mode
  is on, every request's assertion must still name the session's user. If it disappears or
  changes, the session ends, so logging out at the proxy logs out here too.
- **Unknown users** are refused unless an admin created them first. With `auto_create = true`,
  they are created as members.
- **Email.** An asserted email counts as verified only with `trust_email = true`, since the
  proxy is what checked it.
- **Groups** feed tag rules with `issuer = "proxy"` and `claim = "groups"`, the same way as
  OIDC groups.
- **Tunnels too, optionally.** With `apply_to_tunnels = true`, the proxy also fronts
  `*.base_domain`, and its assertion is the principal for private tunnels. The tunnel cookie
  flow below is then skipped.
- **Header hygiene.** The configured identity and secret headers are always removed before
  anything is forwarded to a tunnel app.

Deployment notes:
- **The proxy must terminate TLS for the management host** to see HTTP. A pure SNI passthrough
  like the current HAProxy setup can't do this. That host would be routed through, for
  example, Caddy with forward auth. Then `management.proxy_protocol` is off, and the client
  address comes from X-Forwarded-For through `trusted_proxies`.
- **Some paths must skip the proxy's authentication**: `/api/v1/agent/connect`,
  `/api/v1/enroll` and `/api/v1/*` with bearer tokens. Agents and scripts have their own
  credentials.

### 3. SSO (OIDC)

Any OpenID Connect provider: Google Workspace, Microsoft Entra, Okta, Authentik, Keycloak, Dex
and others.

- **Flow:** authorization code with PKCE (S256). State and nonce live in a 10-minute
  `__Host-mp_oidc` cookie.
- **Our own code over the existing hyper/rustls client** fetches the discovery document and
  JWKS. They are cached and refetched when a key id is unknown, at most once a minute.
- **ID token checks:** signature, `iss`, `aud`, `exp`, `nonce`. Signatures are verified with
  `jsonwebtoken` (approved; see "Libraries"). The identity is `(iss, sub)`.
- **Linking to an existing local user.** A first SSO login whose verified email matches an
  existing local user links to that user only when the provider has `link_by_email = true`.
  It is off by default, because some providers let users change the email claim (Entra's
  `email`, for example). Otherwise the user must be invited, or match `allowed_email_domains`.
- **The first admin.** `[users] bootstrap_admins` lists verified emails that become admin on
  their first SSO login. Without it, the first user is created with the admin token.
- **Groups and claims** feed tag rules (see "Users" under "Where tags come from").

### 4. Social login

- **Google, Microsoft personal accounts and GitLab are OIDC.** They are presets of method 3
  with the issuer filled in.
- **GitHub isn't OIDC.**
  - It uses the OAuth 2 code flow, then `GET /user` and `GET /user/emails`, keeping only
    verified emails.
  - Optionally it also calls `GET /user/orgs` and `GET /user/teams`, exposed as the claims
    `github:org` and `github:team` for tag rules.
  - It is the same small code-flow code, written once.
- **Anyone can have a Google or GitHub account**, so social logins never create users by
  default. They work only for invited users, existing users that link by verified email, or
  `allowed_email_domains`.

### 5. Email invitations

- **SMTP** is configured in `[smtp]` and sent with `lettre` (MIT/Apache-2.0), using its rustls
  transport.
- **An admin invites an email** with a role and access tags. The recipient gets a link with a
  single-use token: stored hashed, valid for 7 days, revocable, and possible to re-send.
- **The invitation page** lets the recipient set a password or continue with any enabled SSO or
  social method. Accepting marks the email verified, which matters for email-domain rules.
- **Invitations replace admin-set passwords** as the usual way to add people. Method 1 stays
  for servers without SMTP.
- **Sending is rate-limited** per admin and per server per hour.

### 6. Emailed sign-in links

- **"Email me a sign-in link"** sends a single-use token valid for 15 minutes, stored hashed.
  It works only for existing users with a verified email.
- **No account enumeration.** The page says "if that address has an account, a link is on its
  way" in every case. Sends are limited per address and per client.
- **Mail scanners can't use it up.** The link opens a confirmation page with a "Sign in"
  button (a POST), so scanners that prefetch links don't consume the token.
- **The same mechanism gives "forgot password"**: a sign-in link, then a forced password
  change.

## The login screen

Anyone who opens a private resource without being signed in sees this screen. It is served by
the management host, so it is the same page whether they started at the UI or at a tunnel.

```text
┌───────────────────────────────────────────┐
│  Sign in to continue to                   │
│  dev-api.mp.example.com                   │   ← only when arriving from a tunnel
│                                           │
│  Email     [                         ]    │   ← method 1, when any local users exist
│  Password  [                         ]    │
│  [ Sign in ]             Forgot password? │   ← "forgot" needs SMTP (method 6)
│  ─────────────── or ───────────────────   │
│  [ Continue with Company SSO ]            │   ← one button per [[oidc]] provider
│  [ Continue with Google ] [ GitHub ]      │   ← social presets
│  [ Email me a sign-in link ]              │   ← method 6
│                                           │
│  Admin token                              │   ← small link, always present
└───────────────────────────────────────────┘
```

- **It shows only the methods that are configured.** With a single SSO provider and no local
  users, the page can send the browser straight to the provider (`[users] auto_redirect`).
  With proxy auth, the user is normally already signed in and never sees this page.
- **It is server-rendered, under the same strict CSP as the UI**, with no third-party scripts.
  It works on phones. Error messages are generic ("email or password is incorrect").
- **After signing in, the browser returns to exactly where it started.** For a tunnel, that is
  the original URL through the tunnel-cookie flow below. Otherwise it is the requested UI page.
  Return targets are checked: a relative path, or the host of a published tunnel. It is never
  an open redirect.
- **Signed in but not allowed: an "access denied" page**, returned with status 403:
  "You're signed in as alice@example.com, but you don't have access to
  dev-api.mp.example.com. Ask its owner or an administrator." It offers "Switch account" and
  "Sign out". It doesn't reveal the owner or the tags.
- **A first password change, an invitation or a linking choice** is shown as one extra step
  on this page, and the redirect back happens afterwards.
- **Non-browser clients never get HTML.** API calls, `curl`, and requests that don't accept
  HTML get `401` `unauthenticated` (or `403` `forbidden`) as JSON with `x-magicpipes-error`.
  The tunnel app never sees the request.
- **The CLI uses the same screen.** `magicpipes login` and, later, `magicpipes connect` open
  this page in the browser (see "CLI").
- **Raw TCP/UDP ports can't show a page.** That is why private port tunnels wait for
  `magicpipes connect`.

### Private HTTP tunnels in the browser

The management cookie is deliberately confined to the management host, so a tunnel host needs
a cookie of its own:

1. A browser without a valid tunnel cookie gets a short-lived `__Host-mp_state` cookie on the
   tunnel host, holding a random nonce. It is then redirected to
   `https://<management>/auth/tunnel?host=<tunnel host>&state=<nonce>&return=<path>`. The
   `return` path must be relative.
2. **Not signed in there?** The login screen above is shown, with "Sign in to continue to
   <tunnel host>".
3. **Signed in?** The server runs `authorize(user, Connect, tunnel)`.
   - If denied, it shows the access-denied page.
   - If allowed, it redirects to `https://<tunnel host>/.magicpipes/callback?code=…`. The code
     is HMAC-signed, valid for 60 s, and bound to the host and the nonce.
   - The code is single-use, enforced by a nonce cache in the data plane. The cache is bounded
     and entries expire after 60 s.
   - The callback accepts the code only if the nonce matches the browser's `__Host-mp_state`.
     Without that check, someone could send a victim a link that logs them into the tunnel
     under the sender's account.
4. The data plane exchanges the code for a cookie `__Host-mp_tunnel`: HttpOnly, Secure,
   `SameSite=Lax`. It contains `{user, host, issued_at, expiry}` and is HMAC-signed with a
   server key in `data_dir/session-key` (0600). Every request checks the signature and then
   runs `authorize()` against the current snapshot, so revocation still works.
5. The proxy removes `__Host-mp_tunnel` and `__Host-mp_state` from the `Cookie` header before
   forwarding, so the tunnel app never sees them. The proxy reserves `/.magicpipes/` on tunnel
   hosts.
6. The app receives `X-MagicPipes-User` (email) and `X-MagicPipes-User-Id`. Clients can't
   forge them: the proxy already strips client-sent `x-magicpipes-*` headers.

Signing out of the management UI also ends that user's tunnel cookies. Like "log out
everywhere", it bumps `sessions_valid_after`. A per-tunnel "sign out" link lives at
`/.magicpipes/logout`.

## CLI

```text
magicpipes login --server https://mp.example.com   # opens the login screen in the browser
magicpipes add 3000                                 # private, reachable by the agent's tags
magicpipes add 3000 --access team:dev               # narrower audience
magicpipes add 3000 --public                        # explicit; refused unless the enrollment allows it
magicpipes add 3000 --label environment:staging
magicpipes ls --all                                 # tunnels you can discover in the org
magicpipes whoami                                   # user, org, role, tags; agent tags
```

- **`magicpipes login` without an enrollment token** uses a device-style flow:
  1. The CLI shows a short code and opens `https://<management>/cli?code=…`.
  2. The user logs in and approves the request. They pick the new agent's access tags from the
     tags they hold; all of them are pre-selected.
  3. The server creates a personal enrollment token for this machine and returns it to the
     waiting CLI.
- **Today's `magicpipes login --server <url> --token <token>`** keeps working for admin-issued
  tokens, which is how service agents get enrolled.

## Later uses of the same rule

- **TCP/UDP to private port tunnels.** A raw port can't carry a cookie, so a private port
  tunnel isn't published on a public port. Instead, `magicpipes connect <tunnel> [--local
  5432]` runs on the user's machine:
  - It authenticates as the user (API token from `login`) and opens a local listener.
  - It sends each connection through an upgraded stream to the server.
  - The server runs `authorize(user, Connect, tunnel)` and pipes the stream into the owning
    agent's data stream, under the same budget as public traffic.
  - Until that exists, `--private` on a port tunnel is refused with `unsupported`.
- **SSH gateway, SSH and agent web terminals, RDP/VNC.**
  - A session is allowed if `authorize(user, Connect, tunnel)` is.
  - The roadmap's "grants" table is no longer needed.
  - Writable shells additionally require ownership or an explicit `terminal:write`-style tag on
    the tunnel's access set. Exactly which is decided in that phase.
- **VPN.** Users' devices and agents are principals with tags, and reachable subnets or
  services are resources with access sets. The rule doesn't change: share a tag, or own it.

## Schema

New entries are appended to `MIGRATIONS` in `store.rs`, one per implementation step:
- **users** (step 2): orgs, users, identities, memberships, passwords, sessions, API tokens,
  the audit log, and the agent and enrollment ownership columns;
- **tags** (step 3): the tag registry, rules and access tables, plus the visibility and label
  columns;
- **email** (step 7): email tokens.

Existing tables only gain columns. The first migration creates the default org and assigns
every existing agent to it. The whole target schema:

```sql
CREATE TABLE orgs (
    id          TEXT PRIMARY KEY,           -- 'org_default' for migrated data
    name        TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);
INSERT INTO orgs (id, name, created_at) VALUES ('org_default', 'default', CAST(strftime('%s', 'now') AS INTEGER));
CREATE TABLE users (
    id           TEXT PRIMARY KEY,           -- us_…
    email        TEXT NOT NULL,              -- lowercase; contact and display address
    email_verified_at INTEGER,               -- set by a verifying IdP, invitation or emailed link
    display_name TEXT NOT NULL DEFAULT '',
    disabled_at  INTEGER,
    sessions_valid_after INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL
);
CREATE TABLE identities (                   -- how a user logs in; see "Logging in"
    issuer      TEXT NOT NULL,              -- 'local', 'proxy', an OIDC issuer, 'https://github.com'
    subject     TEXT NOT NULL,              -- 'local': the email, lowercase
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    last_login_at INTEGER,
    PRIMARY KEY (issuer, subject)
);
CREATE TABLE passwords (
    user_id     TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    hash        TEXT NOT NULL,              -- Argon2id PHC string (includes salt and parameters)
    must_change INTEGER NOT NULL DEFAULT 1,
    updated_at  INTEGER NOT NULL
);
CREATE TABLE memberships (
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (org_id, user_id)
);
CREATE TABLE tags (                         -- access tags only; labels are not registered
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_by  TEXT,                       -- user id; NULL for the admin token
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (org_id, name)
);
CREATE TABLE tag_rules (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    issuer      TEXT NOT NULL,
    claim       TEXT NOT NULL,              -- 'groups', 'hd', … or 'email_domain'
    value       TEXT NOT NULL,
    tag         TEXT NOT NULL,
    created_by  TEXT,
    created_at  INTEGER NOT NULL,
    FOREIGN KEY (org_id, tag) REFERENCES tags(org_id, name) ON DELETE CASCADE
);
CREATE TABLE user_tags (                    -- assigned by an admin
    org_id      TEXT NOT NULL,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tag         TEXT NOT NULL,
    assigned_by TEXT,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (org_id, user_id, tag),
    FOREIGN KEY (org_id, tag) REFERENCES tags(org_id, name) ON DELETE CASCADE
);
CREATE TABLE user_rule_matches (            -- rules the user matched at their last login
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rule_id     TEXT NOT NULL REFERENCES tag_rules(id) ON DELETE CASCADE,
    matched_at  INTEGER NOT NULL,
    PRIMARY KEY (user_id, rule_id)
);

ALTER TABLE agents ADD COLUMN org_id TEXT NOT NULL DEFAULT 'org_default';
ALTER TABLE agents ADD COLUMN owner_user_id TEXT REFERENCES users(id);   -- NULL = service agent
ALTER TABLE agents ADD COLUMN allow_public INTEGER NOT NULL DEFAULT 1;   -- migrated agents: as today
ALTER TABLE agents ADD COLUMN default_private INTEGER NOT NULL DEFAULT 0;
ALTER TABLE agents ADD COLUMN labels TEXT NOT NULL DEFAULT '';
CREATE TABLE agent_tags (
    agent_id    TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    org_id      TEXT NOT NULL,
    tag         TEXT NOT NULL,
    PRIMARY KEY (agent_id, tag),
    FOREIGN KEY (org_id, tag) REFERENCES tags(org_id, name) ON DELETE CASCADE
);

ALTER TABLE enrollments ADD COLUMN org_id TEXT NOT NULL DEFAULT 'org_default';
ALTER TABLE enrollments ADD COLUMN created_by TEXT;                      -- NULL = admin token
ALTER TABLE enrollments ADD COLUMN owner_user_id TEXT;
ALTER TABLE enrollments ADD COLUMN allow_public INTEGER NOT NULL DEFAULT 1;
ALTER TABLE enrollments ADD COLUMN default_private INTEGER NOT NULL DEFAULT 0;
ALTER TABLE enrollments ADD COLUMN labels TEXT NOT NULL DEFAULT '';
CREATE TABLE enrollment_tags (
    token_hash  TEXT NOT NULL REFERENCES enrollments(token_hash) ON DELETE CASCADE,
    org_id      TEXT NOT NULL,
    tag         TEXT NOT NULL,
    PRIMARY KEY (token_hash, tag),
    FOREIGN KEY (org_id, tag) REFERENCES tags(org_id, name) ON DELETE CASCADE
);

ALTER TABLE tunnels ADD COLUMN visibility TEXT NOT NULL DEFAULT 'public'
    CHECK (visibility IN ('public', 'private'));
ALTER TABLE tunnels ADD COLUMN labels TEXT NOT NULL DEFAULT '';
CREATE TABLE tunnel_access (                -- the requested set; effective = this ∩ agent tags
    tunnel_id   TEXT NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
    org_id      TEXT NOT NULL,
    tag         TEXT NOT NULL,
    PRIMARY KEY (tunnel_id, tag),
    FOREIGN KEY (org_id, tag) REFERENCES tags(org_id, name) ON DELETE CASCADE
);

CREATE TABLE sessions (
    id_hash     TEXT PRIMARY KEY,           -- sha256 of the cookie
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id      TEXT NOT NULL,
    csrf        TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);
CREATE TABLE api_tokens (
    id          TEXT PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id      TEXT NOT NULL,
    name        TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER,
    last_used_at INTEGER
);
CREATE TABLE email_tokens (                 -- invitations and sign-in links
    token_hash  TEXT PRIMARY KEY,
    purpose     TEXT NOT NULL CHECK (purpose IN ('invite', 'login')),
    org_id      TEXT NOT NULL,
    email       TEXT NOT NULL,
    user_id     TEXT REFERENCES users(id) ON DELETE CASCADE,   -- 'login': the account
    role        TEXT CHECK (role IN ('admin', 'member')),      -- 'invite': role to grant
    created_by  TEXT,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER
);
CREATE TABLE invite_tags (
    token_hash  TEXT NOT NULL REFERENCES email_tokens(token_hash) ON DELETE CASCADE,
    org_id      TEXT NOT NULL,
    tag         TEXT NOT NULL,
    PRIMARY KEY (token_hash, tag),
    FOREIGN KEY (org_id, tag) REFERENCES tags(org_id, name) ON DELETE CASCADE
);
CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY,
    at          INTEGER NOT NULL,
    org_id      TEXT NOT NULL,
    actor       TEXT NOT NULL,              -- us_…, ag_…, 'admin-token'
    action      TEXT NOT NULL,              -- 'tag.assign', 'tunnel.connect', 'session.create', …
    resource    TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT ''
);
```

Schema notes:

- **Assignment tables only reference registered access tags** through their foreign key on
  `tags`, so an unregistered string can't be assigned as an access tag. Deleting a tag cascades,
  and the cascade is the revocation.
- **A tunnel has no `org_id`.** It belongs to its agent, which belongs to an org.
- **`users.email` is not unique.** Identity is `(issuer, subject)`, and an email can move
  between accounts at an IdP. The `local` identity's subject is unique, so two password
  accounts can't share an email.
- **Login throttling lives in memory, not in a table.** The per-account counters are bounded
  like the existing limiter, and sent-email counters are kept the same way.
- **`audit_log` bounds.** It records management changes, logins, and the first connection per
  tunnel cookie, not every HTTP request. It is pruned to `audit_retention_days` (default 90),
  and its writes are queued off the request path.
- **Rows that can't be read deny access.** If a stored tag, visibility or access row can't be
  read or parsed, the tunnel is unpublished and the error logged. This is the same rule
  `--allow-cidr` follows today.

## Wire protocol and compatibility

- **`RegisterTunnel` and `TunnelInfo` gain optional fields.** `visibility`, `access`
  (`Vec<String>`) and `labels`, each `#[serde(default)]` and skipped when empty.
  - An old agent sends none of them. Its tunnel takes the agent's defaults, which for a migrated
    agent means public, exactly as today.
  - A new agent that asked for `private` checks that `TunnelInfo` echoes it back. If an old
    server doesn't, the new agent removes the tunnel again and reports `server_outdated`. This
    is the same pattern as `kind`. It must never fall back to a public tunnel.
- **Error codes gain a few entries.** `unauthenticated`, `forbidden`, `unsupported`,
  `tag_unknown` and `public_not_allowed` go into the one `ErrorCode` enum (audit design item 3),
  each mapped to an HTTP status and an exit code.
- **The protocol version handshake comes first** (audit design item 4). With it, a new agent
  learns before registering whether the server understands private tunnels, instead of
  relying only on the echo.

## Configuration

```toml
[users]
bootstrap_admins = ["doug@example.com"]   # verified emails that become admin on first SSO/proxy login
allowed_email_domains = ["example.com"]   # SSO/social/proxy users created on first login; empty = none
members_can_publish = true                # may members' agents create public tunnels?
session_max_age_secs = 43200
auto_redirect = false                     # single SSO provider, no local users: skip the login page
audit_retention_days = 90

[proxy_auth]                              # method 2; off unless present
mode = "jwt"                              # or "headers"
jwt_header = "Cf-Access-Jwt-Assertion"
jwks_url = "https://team.cloudflareaccess.com/cdn-cgi/access/certs"
issuer = "https://team.cloudflareaccess.com"
audience = "…"
# mode = "headers":
# user_header = "X-Forwarded-Email"
# groups_header = "X-Forwarded-Groups"
# secret_header = "X-MagicPipes-Proxy-Secret"
# secret_file = "/etc/magicpipes/proxy-secret"
trust_email = false
auto_create = false
apply_to_tunnels = false

[[oidc]]                                  # methods 3 and 4; repeatable
id = "company"                            # used in URLs and rules
label = "Company SSO"                     # button text
issuer = "https://login.example.com"
client_id = "…"
client_secret_file = "/etc/magicpipes/company-oidc-secret"
# groups_claim = "groups"
# scopes = ["openid", "email", "profile"]
# link_by_email = false

[[oidc]]
id = "google"
preset = "google"                         # google, microsoft, gitlab, github
client_id = "…"
client_secret_file = "/etc/magicpipes/google-secret"

[smtp]                                    # methods 5 and 6; off unless present
host = "smtp.example.com"
port = 587                                # STARTTLS; 465 = implicit TLS
username = "magicpipes@example.com"
password_file = "/etc/magicpipes/smtp-password"
from = "MagicPipes <magicpipes@example.com>"
```

All secrets are read from files, never written inline. With none of these sections, the
server behaves as it does today: admin token login only, and every tunnel public. Creating the
first user with the admin token turns on password login (method 1).

## Libraries

All are free, permissively licensed crates that run inside magicpipesd. There are no hosted
identity services, and every one goes through `cargo deny check`.

| Need | Crate | License | Notes |
|---|---|---|---|
| Password hashing | `argon2` (RustCrypto) | MIT/Apache-2.0 | Argon2id, PHC strings |
| JWT verification (proxy assertions, ID tokens) | `jsonwebtoken` | MIT | Approved. At implementation, pick a version whose crypto backend is `ring`. If only `aws-lc-rs` or the RustCrypto `rsa` crate (which has an open timing advisory) are offered, verify RS256/ES256 with `ring::signature` directly instead: `ring` is already in the tree, and it is about 50 lines. |
| HMAC for tunnel cookies and codes | `hmac` (RustCrypto) | MIT/Apache-2.0 | Approved; uses the existing `sha2` |
| SMTP | `lettre` | MIT/Apache-2.0 | rustls transport; confirm it can use the `ring` provider, per the TLS rule in CLAUDE.md |
| TOTP (later) | `totp-rs` | MIT | not in this phase |

**Not used:**
- **`openidconnect` / `oauth2`.** They bring a second HTTP client and the `rsa` crate. The
  code flow we need is small and goes through the existing hyper/rustls client.
- **Hosted identity services** (Auth0, Clerk and the like).

## Implementation order

Each step ships on its own with tests, following CLAUDE.md. The login methods come in the order
settled below. Tags come right after the first one, because private tunnels are what make users
useful.

1. **Groundwork, no behavior change.** *Done:* `ErrorCode`, the protocol handshake,
   `authz::authorize` with today's principals, the `control/` split and `AccessPolicy`.
   - `ErrorCode` enum and protocol handshake.
   - `Principal` plus `authorize()` over today's model (admin token and agents).
   - Split `control/mod.rs`, and add `AccessPolicy` on routes for HTTP and ports.
   - Audit design items 1, 3, 4, 5 and 6.
2. **Users with passwords.** *Done:* the users migration (the agent and enrollment ownership
   columns move to step 3, where they are first used), database sessions, the sign-in and
   password pages, user administration, API tokens and the audit log.
   - The users migration, sessions in the database, and the login screen.
   - Admin-created users with forced password changes, and memberships with roles.
   - API tokens and the audit log.
   - The admin token stays.
3. **Tags and private HTTP tunnels.** *Done*, with these differences from the plan above:
   - Signing out of one UI session doesn't end tunnel cookies; "Sign out everywhere", a
     password change, disabling the user or losing the tag does.
   - The signed-in user without access sees the access-denied answer on the tunnel host
     (`403 forbidden`) when they already hold that host's cookie, and on the management host
     otherwise.
   - `magicpipes ls --all` is not built yet: the CLI holds only its agent credential. The UI's
     "Shared with you" and `GET /api/v1/shared` cover discovery.
   - Tag rules (IdP groups, claims, email domains) arrive with the SSO steps.
   - The tag registry and admin assignment.
   - Agent tags from enrollment tokens, and the device-style `magicpipes login`.
   - Tunnel visibility, access and labels.
   - The tunnel cookie flow and the access-denied page.
   - Discovery filtering in the API, UI and `ls --all`.
4. **Authenticating proxy** (method 2), with groups-header rules.
5. **SSO (OIDC)** (method 3), with claim, group and email-domain rules.
6. **Social login** (method 4): presets, plus GitHub's OAuth flow.
7. **Email:** SMTP, invitations (method 5), then sign-in links and "forgot password"
   (method 6).
8. **`magicpipes connect`** for private TCP and UDP tunnels.
9. **SSH gateway and web terminals** on the same rule; then RDP/VNC, then the VPN.

End-to-end tests, at minimum:

- Step 2: a wrong password and an unknown email give the same answer; a throttled account
  waits even with the right password; the admin token works while users exist.
- Step 3: a browser without a session lands on the login screen and, after signing in, back on
  the original tunnel URL.
- A member without the tag gets 403 on a private tunnel and doesn't see it in `ls --all`.
- After an admin assigns the tag, both work, without a restart.
- Removing the tag closes an open WebSocket.
- A cookie from one tunnel host is rejected on another.
- `__Host-mp_tunnel` never reaches the app, and a forged `X-MagicPipes-User` is stripped.
- A member's enrollment token can't carry a tag they don't hold.
- An old agent's tunnel stays public.
- A new agent asking for private against an old server ends with `server_outdated`, not a
  public tunnel.
- Step 4: plain identity headers from a peer outside `trusted_proxies`, or without the secret
  header, are ignored; a JWT with the wrong audience is rejected; neither header reaches a
  tunnel app.
- Steps 5–7: covered by a local test IdP (Dex in Docker, like the Pebble ACME test) and a
  local SMTP catcher.

## Known limitations

- **Certificate transparency.** In ACME mode every tunnel hostname, private ones included,
  appears in public certificate logs. Use `tls.mode = "files"` with a wildcard certificate, or
  unguessable names, when the names themselves are sensitive.
- **A private tunnel's existence is visible.** An anonymous request gets a login redirect where
  an unknown name gets 404. Hiding that would break the login flow.
- **IdP-driven revocation lags** by up to `session_max_age_secs` until refresh-token
  re-checks exist. With proxy auth there is no lag: every request carries the proxy's
  current assertion.
- **Password accounts have no second factor** until TOTP lands. For stronger login, put the
  server behind SSO or an authenticating proxy.
- **One org per server in the UI.** The schema already allows more.

## Decisions (settled 2026-11-01)

1. **The admin token stays permanently,** even with SSO or a proxy configured. UI controls to
   disable or regenerate it come later.
2. **Login methods ship in this order:**
   1. admin-created users with passwords;
   2. authenticating proxy;
   3. OIDC SSO;
   4. social login;
   5. email invitations;
   6. emailed sign-in links.
3. **Use free, permissively licensed libraries** where they help ("Libraries"):
   `jsonwebtoken` and `hmac` are approved; `argon2` and `lettre` are proposed under the same
   rule.
4. **Admins don't auto-connect to private tunnels.**
5. **New enrollments default to private tunnels once users exist.** Migrated agents stay
   public.
