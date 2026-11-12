# Users, SSO and tag-based access (design)

Status: partly built; see "Implementation order" for what is done. The rest is a proposal. This is roadmap phase 4. It replaces the per-user "grants"
in ROADMAP.md, and the SSH gateway, browser desktops and a future VPN use the same model.

## Goals

- People log in with a password an admin set for them, with SSO (OIDC), through an
  authenticating proxy that is already in front of the server, with a social account, or with an
  emailed link. These ship in that order, and every method ends in the same kind of session.
  Agents and tunnels belong to someone.
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
Org (workspace)            every tag, user, agent and tunnel belongs to one org
 ├─ tags: dev, prod, …      registered by an admin, each with `access` on or off
 │        user:k8p4x2m9qa, … one personal tag per user, made with the account
 ├─ users ── tags ← admin assignment | rules (proxy or IdP group, IdP claim, verified email domain)
 │                  + their personal tag
 ├─ agents ── owner (a user, or none for service agents)
 │            personal agent: publishes with its owner's tags; service agent: tags of its own
 └─ tunnels ── owner = its agent's owner (management only)
               public, or private; tags = the owner's personal tag + those given with --tag
```

**The rule:** a user may connect to a private tunnel, and see it in lists, when the user and
the tunnel share a tag whose `access` is on. That is the whole access rule; there is no owner
exception. An owner gets into their own tunnels the same way, through their personal tag, which
the server puts on every tunnel of their machines. Ownership only decides who manages.

### Tags

A tag such as `dev`, `team:ops` or `contractor:acme` is a label on users, service agents and
tunnels. Admins create tags in the registry and turn `access` on or off per tag: a tag without
access is only a label. The syntax is lowercase, `[a-z0-9][a-z0-9._-]*` with an optional
`:value` made of `[a-z0-9._@-]`, at most 64 bytes. Names are normalized and validated on write,
and matching is exact string equality.

**Personal tags.** Creating an account also creates its personal tag, `user:` and 10 random
characters (`user:k8p4x2m9qa`), tied to the account by `tags.user_id`. The name says nothing
about the person, so it never collides or goes stale; the UI shows their email instead (to
administrators; a member sees "you" for their own). A personal tag:
- is created automatically, and no one can create a `user:` tag by hand;
- is held by its user only: it can't be assigned to another user or to an agent;
- always grants access: its access can't be turned off;
- goes only with its account;
- can go on any tunnel (`--tag user:k8p4x2m9qa`), to share that tunnel with that one person;
- is put on every tunnel of its user's machines when they are registered.

The last point is the registration's policy, not a rule of the model: the owner's personal tag
is an ordinary `tunnel_tags` row, and `authorize` knows nothing about owners. Today every
registration adds it, so nobody locks themselves out of their own tunnel; handing a tunnel over
to someone else, and taking the original owner's access away, would be a change to that
policy, not to the model.

**Who attaches tags.**
- Users: only admins, directly or through rules they write. Nobody gives themselves a tag.
- Service agents: only admins, through the enrollment token or by editing the agent.
- Tunnels: the agent that registers them, with ordinary tags its publisher holds (the owner's
  tags for a personal agent, the agent's own for a service agent) and anyone's personal tag,
  plus the owner's personal tag added by the server. A member therefore can't put a group tag
  they don't hold on a tunnel, so turning a tag's access on never opens a tunnel to a group its
  owner isn't in. This is checked on every registration that names tags, against what the
  publisher holds at that moment, not only when the tags were first given: an older or
  compromised agent can't bring back a tag its owner has lost.

**A tunnel's tags belong to the tunnel.** They are stored (`tunnel_tags`) and apply as stored:
nothing is inherited or recomputed from the agent or the owner later. So if Alice publishes five
tunnels tagged `dev` and is then removed from `dev`, she loses her own access to other `dev`
tunnels, but her five stay shared with `dev` until someone changes them (and she can no longer
re-register them with `dev`). Disabling Alice withdraws every tunnel of her machines at once, and
revoking a machine deletes its tunnels. The tag model was replaced on 2026-11-03 (before,
tunnels inherited their agent's tags and owners had an exception of their own).

### Roles

Each membership has one of two roles. Neither is a tag, and neither can be assigned by the
holder.

- **admin**: manages the org (users, tags, rules, enrollment tokens, any agent or
  tunnel). An admin doesn't automatically *connect* to private tunnels. Like anyone else, they
  need a shared tag or ownership. Admins can give themselves tags, so this is not a hard
  barrier. What it buys is that reaching someone's shell tunnel takes an explicit, audited
  step instead of being implicit.
- **member**: logs in, sees and connects to what the tags allow, owns agents and tunnels
  enrolled for them, and manages those.

The existing admin tokens (`admin_tokens`) stay permanently, whatever login methods are
configured. They are a break-glass principal with admin rights for the default org, and they
are how the first user gets created. Disabling and regenerating them from the UI comes later;
today `magicpipesd admin-token --rotate` replaces them and ends every UI session signed in with
one. For scripts, named API tokens owned by
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
    Tunnel(&'a TunnelAuthz),   // org, owner user, agent, public flag, tags that grant access
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
| 8 | `Connect` or `Discover` a private tunnel: the user shares a tag with it whose `access` is on | allow |
| 9 | Anything else | deny |

- **Enrollment tokens are a validation, not a decision row.** A member may create one only for
  their own machine, without tags (see "Agents"); the handler checks that. It isn't a
  permission on `Org`.
- **Discovery equals connection.** Row 8 gives `Discover` and `Connect` the same answer for
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
- the proxy is trusted for email (`trust_email = true`), for rules that need one; email isn't
  offered behind a proxy, so nothing else asks;
- the user proved it by accepting an invitation or following a link sent there, in their own session.

An email typed in by an admin is not verified.

- **How rules work** (*built 2026-11-12*, `control/rules.rs`). A rule is `(issuer, claim, value) →
  tag`, created by an admin. At every single sign-on through a source (an OIDC or GitHub
  provider, or the proxy), the server checks that source's rules against the fresh claims (ID
  token, plus UserInfo for a claim a rule wants and the token lacks; proxy assertion or groups
  header; GitHub API) and replaces that user's rows in `user_rule_matches` for that source;
  other sources' matches stay. A user's tags are their admin-assigned `user_tags` plus the tags of
  the rules they match. Deleting a rule therefore revokes its tag from everyone at once, through
  the cascade. Claims kept from a sign-in are strings or lists of strings, at most 64 names, 256
  values each, 256 bytes a value.
- **Matching is exact**: `claim == value`, or `value ∈ claim` when the claim is a list. GitHub's
  `github:org` and `github:team` are lowercased on both sides, as GitHub compares them. The
  email-domain rule (issuer `*`) compares the part after `@` of the account's own address, when
  it's confirmed, with no subdomain wildcard; it applies to every such account at once, not at a
  login.
- **Revocation lag for rule-based tags.** A match counts for the session's maximum age
  (`session_max_age_secs`, default 12 h) after the sign-on that made it, and is then pruned (hourly)
  unless the person signed in through that source again. So it's bounded whichever way they sign in
  meanwhile: a password or an API token doesn't keep a group's tag. While a session has a refresh
  token, each re-check with the provider (`sso_recheck_secs`) renews or drops its matches, so a group
  taken away there goes within a round.
- **No self-assignment.** Only admins create tags, assign them to users, and write
  rules. A member can't add a tag to themselves, and an IdP claim can only map to tags that an
  admin has wired up.

### Agents

- **The enrollment token says who the agent belongs to.** It records who created it
  (`created_by`), which org it belongs to, the owner the new agent will have (`owner_user_id`,
  which may differ from the creator), and whether its tunnels may be public.
  - Admins may create tokens for any owner, or none (a service agent). Only a service agent's
    token carries tags.
  - Members may create tokens only for themselves, without tags. This is how `magicpipes login`
    works for a person: see "CLI".
- **A personal agent has no tags of its own.** It publishes with its owner's current tags. A
  service agent (`owner_user_id IS NULL`) has exactly the tags an admin gave it, changed only by
  an admin.

### Tunnels

- **Visibility is `public` or `private`.**
  - The default comes from the agent's enrollment.
  - Migrated agents default to `public`, as today.
  - New enrollments default to `private` once the server has users. `--public` is allowed only
    if the enrollment allows it. Members' enrollments allow it when `[users]
    members_can_publish` is true (the default). The setting is also checked whenever a
    member's machine registers a tunnel, so turning it off applies to machines enrolled before;
    their existing public tunnels stay until removed.
- **Tags.** A tunnel of a personal agent gets its owner's personal tag (the owner, not whoever
  created the enrollment token), plus the tags given with `--tag`, each of which the publisher
  must hold. Nothing else is added: `magicpipes add 3000` is for its owner alone.
- **No tag that grants access.** A private tunnel without one (a service agent's tunnel with no
  `--tag`, or after its only tag was deleted or had access turned off) is reachable by nobody.
  It is never treated as public.

### Revocation summary

Every change below takes effect on the next request through the published snapshot.

| Change | Effect |
|---|---|
| Remove a tag from a user | That user loses access through it, and their machines can't put it on a tunnel again. Tunnels they already published with it stay shared with it: a tunnel's tags are its own |
| Turn a tag's access off | Everyone it let in loses that; it stays as a label |
| Delete a rule | Every user who got a tag only through that rule loses it |
| Delete a tag | Cascades to every user, agent, enrollment token, rule and tunnel; a tunnel left without a tag that grants access is reachable by nobody |
| Disable a user or remove their membership | Sessions, API tokens and tunnel cookies are rejected. Their personal agents can't connect, and their tunnels are unpublished |
| "Sign out everywhere" | Bumps `sessions_valid_after`; every session and tunnel cookie issued before it is rejected |
| Revoke an agent | As today, plus its tunnels' access rows |

**Long-lived connections are re-checked too.** Each one carries its principal: WebSockets,
TCP, and later SSH and VPN flows. On every publish, the data plane re-runs `authorize()` for
each open connection and closes the denied ones. An HTTP request in flight finishes.

## Logging in

Every method ends the same way:
1. The server resolves an **identity** to a user.
2. It checks that the user isn't disabled and is a member of the org.
3. For a single sign-on, it re-evaluates that source's tag rules.
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

- **Admins create users** in the UI or API: email, display name, role, tags, and either
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

*Built 2026-11-06, with these differences from the plan below:*

- **Groups** (*built 2026-11-12*): `groups_header` in plain-header mode; a signed token's own claims.
- **Not built:** `apply_to_tunnels`.
- **Added:** `allow_unverified_admin`, the same rule as for a provider, and `sign_out_url`, because
  a "Sign out" that only ends the session here signs you straight back in.
- **Who gets in** is the same code as for OIDC. "Unknown users" means no account, no list and no
  `auto_create`; an administrator's account for an address is linked when that address is verified.
- **Other ways in close while it's on.** A session has to keep being named by the proxy, so passwords
  and providers aren't offered. Admin-token sessions don't depend on it.
- **A header sent twice counts as nobody**, in case a client's copy is beside the proxy's.
- **Keys that can't be fetched** answer 502 without ending the session, since that says nothing about
  the person.
- **`Authorization`** can carry the token, but isn't removed before a tunnel, where it may be the
  application's own.
- **Refusals are logged, not audited,** since every page request would otherwise add a row.

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

*Built 2026-11-04, ahead of the proxy.* Any OpenID Connect provider: Google Workspace, Microsoft
Entra, Okta, Authentik, Keycloak, Dex and others. The README says how to configure it and who
gets in; `docs/ARCHITECTURE.md` lists its limits.

- **Flow:** authorization code with PKCE (S256). State, nonce, verifier and destination live in
  a signed 10-minute `__Host-mp_oidc` cookie.
- **Our own code over hyper and rustls** fetches the discovery document and JWKS. They are
  cached and refetched when a key id is unknown, at most once a minute.
- **ID token checks:** signature, `iss`, `aud`, `azp`, `exp`, `iat`, `nonce`. Signatures are
  verified with `ring` directly (RS256 and ES256): `jsonwebtoken` now offers only `aws-lc-rs` or
  the RustCrypto `rsa` crate as backends, and `ring` is already in the tree. The identity is
  `(iss, sub)`. An email missing from the ID token is read from the UserInfo endpoint.
- **Linking to an existing local user.** A first SSO login whose verified email matches an
  existing local user links to that user only when the provider has `link_by_email = true`.
  It is off by default, because some providers let users change the email claim. An account has
  at most one identity per issuer, so an address reused at the provider doesn't reach it.
  Otherwise the address must match `bootstrap_admins` or `allowed_email_domains`.
- **Machines per member.** `[users] max_agents_per_user` (25) bounds the machines a member enrolls
  themself, counting tokens not used yet, since limits per agent would otherwise multiply with
  every machine. Administrators aren't limited, for themselves or on someone's behalf.
- **The first admin.** `[users] bootstrap_admins` lists verified emails that become admin when
  their account is created at their first SSO login. It doesn't change an existing account's
  role. Without it, the first user is created with the admin token.
- **Temporary passwords.** A password an administrator set stops working when its owner signs
  in with SSO, instead of forcing a change they have no use for.
- **Providers that don't verify addresses.** `trust_email` accepts a provider's addresses without
  `email_verified`, for Microsoft Entra (never sends it) and authentik (`false` by default since
  2025.10). Off by default. Anyone who can choose their address at that provider could use an
  address in `allowed_email_domains`, or an existing member's with `link_by_email`, so the page says
  so beside the option. It only moves a decision that a custom claim mapping at the provider would
  otherwise make out of sight. Such an address doesn't become or take over an administrator unless
  the provider also has `allow_unverified_admin`; it's refused rather than made a member, or the
  real administrator could never sign in.
- **The Settings page.** Administrators add providers and edit the two lists without a restart.
  Presets (Google, Microsoft, authentik, Keycloak, GitLab, any other) only build the issuer URL and
  say what to do at the provider; discovery does the rest. See "Settings" in
  `docs/ARCHITECTURE.md` for where these settings live.

**Past the sign-in** (*built 2026-11-12*, `control/sso.rs`), per provider on the Settings page or in
the file:
- **`scopes`**: what a sign-in asks for, `openid email profile` by default; `openid` is required.
- **Re-checks** (`[users] sso_recheck_secs`, an hour; 0: never). A session keeps the provider's
  refresh token and ID token, encrypted (AES-256-GCM under a key derived from `session-key`). Each
  round trades the refresh token at the provider (a batch of 500, 8 at once). `invalid_grant`, or
  an ID token naming someone else, ends the session and clears that person's rule matches from the
  provider; anything else leaves it for the next round. A refreshed ID token (checked as at sign-in,
  without a nonce) or UserInfo updates their tags from rules. Providers that give no refresh token
  (most only with `offline_access`; Google only with `access_type=offline`, which isn't asked for)
  leave sessions to their maximum age.
- **`auto_redirect`**, on one provider at most: `/login` goes straight to it. Other ways in stay
  at `/login?method=password` and `?method=token`. Signing out lands on `/signed-out`, the sign-in
  page without going anywhere, so it doesn't sign straight back in.
- **`sign_out`**: signing out here continues to the provider's `end_session_endpoint`
  (RP-Initiated Logout) with `client_id`, `id_token_hint` and `post_logout_redirect_uri` =
  `<management>/signed-out`. Off by default, since it signs people out of everything else using
  that provider. Not after "Switch account", which means to sign in again.
- **`[users] disable_idle_after_days`** (*built 2026-11-12*; 0, off, by default). An account with no
  password and an identity from a provider is disabled once nothing has vouched for it in that many
  days: `users.vouched_at`, set by a single sign-on, a re-check its provider answered, and an
  administrator enabling it (migration 15 starts it from the last single sign-on). The hourly
  prune does it, as disabling does: sessions, emailed links and invitations they sent end, and the
  directory refresh stops their API tokens, tunnel cookies, SSH keys and machines. It's recorded as
  `disabled_reason = 'idle'`, and the person's next single sign-on through an identity they already
  have clears it, so someone still there is back at once; a first sign-in that would link by email
  doesn't. **Keep disabled** (an administrator disabling it) clears the reason, so it sticks. Owners
  of machines with a confirmed address are emailed, at most 100 an hour, out of the server's 500.
  It must be longer than `session_max_age_secs`: a session without re-checks vouches for nobody
  while it lasts.

**Not built:**
- **`groups_claim`.** Not needed: a tag rule names its claim, `groups` or any other. Tag rules
  themselves were built on 2026-11-12 (see "Where tags come from").
- **Revoking the refresh token** (RFC 7009) when someone signs out here; it lapses at the provider.

### 4. Social login

*Built 2026-11-06; organizations and teams for tag rules on 2026-11-12, asked for (`read:org`) only
once a rule wants them, teams 50 to a page for at most 4 pages. A provider's `kind = "github"` takes
the place of the `preset` below, and also covers GitHub Enterprise Server, whose `issuer` is its
address.*

- **Google, Microsoft personal accounts and GitLab are OIDC.** They are presets of method 3
  with the issuer filled in. Microsoft personal accounts are that preset with the tenant ID
  `9188040d-6c67-4c5b-b112-36a304b66dad`, and need `trust_email`, since they never state
  `email_verified`.
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

*Built 2026-11-06, with these differences from the plan below:*

- **The mail server can also be set on the Settings page,** like providers and certificates. A
  mail server in the file is locked there.
- **A code is in the link's `#fragment`,** as CLAUDE.md requires of secrets in addresses, not in its
  path or query. So the server first sees it when a form is posted, which also means a link can't
  show who it's for until then: opening one is a page with one button, and that page shows the rest.
  Without scripts, it's pasted from the message.
- **Accepting with a provider takes any identity at it,** not one with the same address. The code is
  the proof, and the account gets the invited address. An identity that's someone else's is refused,
  and the invitation survives for another way in.
- **An invitation ends with its sender's powers:** when they're disabled or stop being an
  administrator.
- **A used code is deleted,** so `email_tokens` has no `used_at`, and an invitation is a table of its
  own (see "Schema"). The audit log says what happened.

- **SMTP** is configured in `[smtp]` and sent with `lettre` (MIT/Apache-2.0), using its rustls
  transport.
- **An admin invites an email** with a role and tags. The recipient gets a link with a
  single-use token: stored hashed, valid for 7 days, revocable, and possible to re-send.
- **The invitation page** lets the recipient set a password or continue with any enabled SSO or
  social method. Accepting marks the email verified, which matters for email-domain rules.
- **Invitations replace admin-set passwords** as the usual way to add people. Method 1 stays
  for servers without SMTP.
- **Sending is rate-limited** per admin and per server per hour.

### 6. Emailed sign-in links

*Built 2026-11-06, with these differences from the plan below:*

- **It needs a password as well as a verified address.** An account that only signs in with a
  provider gets no link, since that would be a way around the provider's own checks, such as a second
  factor.
- **Forgetting a password and asking for a link are one thing.** The sign-in page has "Forgot your
  password?", and the page a link opens offers a new password as well as signing in. That also needs
  no current password, which a forced change would. Someone whose password an administrator set has
  to choose one there.
- **Someone can confirm their own address,** from the Account page, with a link that only works in
  their own session. Getting the message doesn't prove the account is yours: whoever owns a mistyped
  address could otherwise confirm it, and then get links to it. Accounts from before this have no
  verified address, unless a provider vouches for it at their next sign-in.
- **A link doesn't return to where you were.** It may be opened anywhere, and a destination chosen by
  whoever asked for a link is one more thing to attack someone with.
- **Not offered behind an authenticating proxy,** where a `trust_email` address therefore doesn't need
  to count as verified.

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

- **It shows only the methods that are configured.** It can send the browser straight to one
  provider (that provider's `auto_redirect`).
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

1. A browser without a valid tunnel cookie gets a short-lived state cookie on the tunnel host,
   `__Host-mp_state_<nonce>`, one per sign-in attempt so tabs signing in at once don't overwrite
   each other's. It is then redirected to
   `https://<management>/auth/tunnel?host=<tunnel host>&state=<nonce>&return=<path>`. The
   `return` path must be relative.
2. **Not signed in there?** The login screen above is shown. After signing in (and a forced
   password change, if any) the browser is not redirected onward: browsers apply the
   management CSP's `form-action 'self'` to every redirect after a form submission, and the
   next hop leaves the management host. A small "Continuing…" page moves on with a `Refresh`
   instead, a navigation of its own.
3. **Signed in?** The server runs `authorize(user, Connect, tunnel)`.
   - If denied, it shows the access-denied page, whose "Switch account" comes back here.
   - If allowed, it redirects to `https://<tunnel host>/.magicpipes/callback#code=…&return=…`.
     The code is HMAC-signed, valid for 60 s, and bound to the host and the nonce. It travels
     in the URL fragment, so no server, log or Referer header sees it.
4. The callback page (served by MagicPipes on the tunnel host, under a CSP that allows only its
   own script and requests to its own host) removes the fragment from the history and posts the
   code to `/.magicpipes/callback`. Signing in to a private tunnel therefore needs JavaScript.
   - The code is accepted once (a bounded nonce cache in the data plane, entries kept 60 s),
     and only with the attempt's state cookie. Without that check, someone could send a victim
     a link that logs them into the tunnel under the sender's account.
   - The answer sets `__Host-mp_tunnel`: HttpOnly, Secure, `SameSite=Lax`, with
     `{user, host, issued_at, expiry}`, HMAC-signed with a server key in
     `data_dir/session-key` (0600). Every request checks the signature and then runs
     `authorize()` against the current snapshot, so revocation still works.
5. The proxy removes `__Host-mp_tunnel` and the state cookies from the `Cookie` header before
   forwarding, so the tunnel app never sees them. The proxy reserves `/.magicpipes/` on tunnel
   hosts.
6. The app receives `X-MagicPipes-User` (email) and `X-MagicPipes-User-Id`. Clients can't
   forge them: the proxy already strips client-sent `x-magicpipes-*` headers.

The management session cookie is `SameSite=Lax` (every form also needs its CSRF token), so it
comes along when a tunnel on another registrable domain sends the browser to the management
host. `scripts/browser-sign-in.mjs` and the ignored e2e test
`browser_signs_in_to_private_tunnels` check this flow in headless Chrome.

Signing out of the management UI also ends that user's tunnel cookies. Like "log out
everywhere", it bumps `sessions_valid_after`. A per-tunnel "sign out" link lives at
`/.magicpipes/logout`.

## CLI

```text
magicpipes login --server https://mp.example.com   # opens the login screen in the browser
magicpipes add 3000                                 # private, for you alone (your personal tag)
magicpipes add 3000 --tag dev                       # you, and everyone holding dev
magicpipes add 3000 --public                        # explicit; refused unless the enrollment allows it
magicpipes ls --all                                 # tunnels you can discover in the org
magicpipes whoami                                   # user, org, role, tags; agent tags
magicpipes connect db --local 5432                  # reach a private TCP or UDP tunnel, as you
```

- **`magicpipes login` without an enrollment token** uses a device-style flow:
  1. The CLI shows a short code and opens `https://<management>/cli?code=…`.
  2. The user logs in and approves the request. The machine publishes with their tags; it
     has none of its own.
  3. The server creates a personal enrollment token for this machine and returns it to the
     waiting CLI.
- **Today's `magicpipes login --server <url> --token <token>`** keeps working for admin-issued
  tokens, which is how service agents get enrolled.

## Later uses of the same rule

- **TCP/UDP to private port tunnels** (built). A raw port can't carry a cookie, so a private port
  tunnel isn't published on a public port. Instead, `magicpipes connect <tunnel> [--local
  5432]` runs on the user's machine:
  - It authenticates as the user with a connect pass, approved in a browser on any device as
    `login` is, or traded for an API token, and opens a local listener.
  - It sends each connection through an upgraded HTTPS connection to the server.
  - The server runs `authorize(user, Connect, tunnel)` and pipes the connection into the owning
    agent's data stream, under the same budget as public traffic. See "`magicpipes connect`" in
    ARCHITECTURE.md.
- **SSH gateway, SSH and agent web terminals, RDP/VNC.**
  - A session is allowed if `authorize(user, Connect, tunnel)` is.
  - The roadmap's "grants" table is no longer needed.
  - Writable shells additionally require ownership or an explicit `terminal:write`-style tag on
    the tunnel. Exactly which is decided in that phase.
- **VPN.** Users' devices and agents are principals with tags, and reachable subnets or
  services are resources with tags. The rule doesn't change: share a tag that grants access.

## Schema

`MIGRATIONS` in `store.rs` was restarted on 2026-11-03, when the tag model was replaced:
migration 1 is the whole schema, and databases from before then are refused (delete them).
New entries are appended from there, one per implementation step:
- **users and tags** (steps 2 and 3, migration 1): orgs, users, identities, memberships,
  passwords, sessions, API tokens, the audit log, ownership columns, the tag registry and the
  tag assignments;
- **email** (step 7, migration 7): invitations, email tokens and the mail server's settings;
- **rules** (step 10, migration 13): tag rules and their matches, with `UNIQUE (org_id, issuer,
  claim, value, tag)` and an index on `user_rule_matches(rule_id)`.

Migration 1 creates the default org. The whole target schema:

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
CREATE TABLE tags (                         -- the tag registry
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    access      INTEGER NOT NULL DEFAULT 1, -- users and tunnels sharing it may connect
    user_id     TEXT UNIQUE REFERENCES users(id) ON DELETE CASCADE,  -- set: that user's personal tag
    created_by  TEXT,                       -- user id; NULL for the admin token
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (org_id, name)
);
CREATE TABLE tag_rules (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    issuer      TEXT NOT NULL,
    claim       TEXT NOT NULL,              -- 'groups', 'hd', …, 'github:team', or 'email_domain' (issuer '*')
    value       TEXT NOT NULL,
    tag         TEXT NOT NULL,
    created_by  TEXT,
    created_at  INTEGER NOT NULL,
    FOREIGN KEY (org_id, tag) REFERENCES tags(org_id, name) ON DELETE CASCADE
);
CREATE TABLE user_tags (                    -- assigned by an admin, plus the personal tag
    org_id      TEXT NOT NULL,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tag         TEXT NOT NULL,
    assigned_by TEXT,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (org_id, user_id, tag),
    FOREIGN KEY (org_id, tag) REFERENCES tags(org_id, name) ON DELETE CASCADE
);
CREATE TABLE user_rule_matches (            -- rules the user matched at their last sign-on through each source
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rule_id     TEXT NOT NULL REFERENCES tag_rules(id) ON DELETE CASCADE,
    matched_at  INTEGER NOT NULL,
    PRIMARY KEY (user_id, rule_id)
);

CREATE TABLE agents (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    token_hash      TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    last_seen_at    INTEGER,
    org_id          TEXT NOT NULL DEFAULT 'org_default',
    owner_user_id   TEXT REFERENCES users(id),      -- NULL = service agent
    allow_public    INTEGER NOT NULL DEFAULT 1,
    default_private INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE agent_tags (                   -- service agents only
    agent_id    TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    org_id      TEXT NOT NULL,
    tag         TEXT NOT NULL,
    PRIMARY KEY (agent_id, tag),
    FOREIGN KEY (org_id, tag) REFERENCES tags(org_id, name) ON DELETE CASCADE
);

CREATE TABLE enrollments (
    token_hash      TEXT PRIMARY KEY,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    used_at         INTEGER,
    agent_id        TEXT,
    org_id          TEXT NOT NULL DEFAULT 'org_default',
    created_by      TEXT,                           -- NULL = admin token
    owner_user_id   TEXT,                           -- the new agent's owner; may differ from created_by
    allow_public    INTEGER NOT NULL DEFAULT 1,
    default_private INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE enrollment_tags (              -- service agents' tokens only
    token_hash  TEXT NOT NULL REFERENCES enrollments(token_hash) ON DELETE CASCADE,
    org_id      TEXT NOT NULL,
    tag         TEXT NOT NULL,
    PRIMARY KEY (token_hash, tag),
    FOREIGN KEY (org_id, tag) REFERENCES tags(org_id, name) ON DELETE CASCADE
);

-- tunnels: as before, plus `kind`, `public_port`, `allow` and
--   visibility TEXT NOT NULL DEFAULT 'private' CHECK (visibility IN ('public', 'private'))
CREATE TABLE tunnel_tags (                  -- the owner's personal tag + those given with --tag
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
CREATE TABLE invitations (                  -- one per address; gone once used
    id           TEXT PRIMARY KEY,             -- inv_…
    token_hash   TEXT NOT NULL UNIQUE,
    org_id       TEXT NOT NULL DEFAULT 'org_default',
    email        TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    role         TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    created_by   TEXT NOT NULL,                -- us_… or 'admin-token'
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
);
CREATE TABLE invitation_tags (
    invitation_id TEXT NOT NULL REFERENCES invitations(id) ON DELETE CASCADE,
    org_id        TEXT NOT NULL DEFAULT 'org_default',
    tag           TEXT NOT NULL,
    PRIMARY KEY (invitation_id, tag),
    FOREIGN KEY (org_id, tag) REFERENCES tags(org_id, name) ON DELETE CASCADE
);
CREATE TABLE email_tokens (                 -- links to an account; gone once used
    token_hash TEXT PRIMARY KEY,
    purpose    TEXT NOT NULL CHECK (purpose IN ('sign_in', 'confirm')),
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);
CREATE TABLE smtp_settings (                -- the mail server, if set on the Settings page
    org_id       TEXT PRIMARY KEY DEFAULT 'org_default',
    host         TEXT NOT NULL,
    port         INTEGER NOT NULL,
    tls          TEXT NOT NULL,
    username     TEXT,                      -- the password is <data_dir>/smtp-password
    from_address TEXT NOT NULL
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

- **Assignment tables only reference registered tags** through their foreign key on `tags`, so
  an unregistered string can't be assigned. Deleting a tag cascades, and the cascade is the
  revocation. The store never writes a personal tag into an assignment other than its own
  user's `user_tags` row and the tunnels of that user's machines.
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

- **`RegisterTunnel` and `TunnelInfo` gain optional fields.** `visibility` and `tags`
  (`Vec<String>`), each `#[serde(default)]` and skipped when empty. Builds before 2026-11-03
  called the field `access` (and briefly sent `labels`); the tag model changed then without
  keeping compatibility, and such agents' tags are ignored (their private tunnels are for
  their owner alone).
  - An old agent sends none of them. Its tunnel takes the agent's defaults, which for a migrated
    agent means public, exactly as today. An agent before protocol 3 enrolled with a private
    default gets `agent_outdated` instead: it couldn't check a private tunnel, and public isn't
    what its enrollment asked for.
  - A current agent restoring its tunnels after a reconnect, or re-adding one without
    `--private`/`--public`, sends no visibility either, so the server keeps what it stored
    (the agent's copy may name tags deleted since). It still checks that a private tunnel came
    back private.
  - The CLI asks a running agent for its `ipc_version` before an `add` with options an older
    agent would silently drop (private, tags, TCP/UDP, allow-lists, `--serve`,
    `--shell`), and stops with `agent_outdated` rather than get a public HTTPS tunnel.
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
sso_recheck_secs = 3600                   # check single sign-ons with their provider; 0: never
disable_idle_after_days = 0               # disable SSO-only accounts nothing vouched for in this long; 0: never
audit_retention_days = 90

[proxy_auth]                              # method 2; off unless present
mode = "jwt"                              # or "headers"
jwt_header = "Cf-Access-Jwt-Assertion"
jwks_url = "https://team.cloudflareaccess.com/cdn-cgi/access/certs"
issuer = "https://team.cloudflareaccess.com"
audience = "…"
# mode = "headers":
# user_header = "X-Forwarded-Email"
# groups_header = "X-Forwarded-Groups"     # comma-separated, the claim `groups` for tag rules
# secret_header = "X-MagicPipes-Proxy-Secret"
# secret_file = "/etc/magicpipes/proxy-secret"
trust_email = false
allow_unverified_admin = false
auto_create = false
# sign_out_url = "https://auth.example.com/logout"
# apply_to_tunnels = false                 # not built yet

[[oidc]]                                  # methods 3 and 4; repeatable
id = "company"                            # used in URLs and rules
label = "Company SSO"                     # button text
issuer = "https://login.example.com"
client_id = "…"
client_secret_file = "/etc/magicpipes/company-oidc-secret"
# scopes = ["openid", "email", "profile"] # add "groups" or "offline_access" if the provider needs asking
# auto_redirect = false                   # the sign-in page goes straight here; one provider at most
# sign_out = false                        # signing out here signs out there too
# link_by_email = false

[[oidc]]
id = "github"
kind = "github"                           # not OpenID Connect
label = "GitHub"
issuer = "https://github.com"             # or a GitHub Enterprise Server's address
client_id = "…"
client_secret_file = "/etc/magicpipes/github-secret"

[smtp]                                    # methods 5 and 6; off unless here or on the Settings page
host = "smtp.example.com"
username = "magicpipes@example.com"
password_file = "/etc/magicpipes/smtp-password"
from = "MagicPipes <magicpipes@example.com>"
# port = 587                              # the usual one: 587 with STARTTLS, 465 with TLS, 25 with none
# tls = "starttls"                        # or "implicit" (the default on port 465), or "none" with no password
# ca_file = "/etc/magicpipes/smtp-ca.pem" # a private CA, as well as the public ones
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
| JWT verification (proxy assertions, ID tokens) | `ring`, directly | ISC-style, already in the tree | RS256 and ES256 with `ring::signature`. `jsonwebtoken` was approved, but its current versions offer only `aws-lc-rs` or the RustCrypto `rsa` crate (which has an open timing advisory) as backends. |
| HMAC for tunnel cookies and codes | `hmac` (RustCrypto) | MIT/Apache-2.0 | Approved; uses the existing `sha2` |
| SMTP | `lettre` | MIT | rustls with the `ring` provider, per the TLS rule in CLAUDE.md; no connection pool |
| TOTP (later) | `totp-rs` | MIT | not in this phase |

**Not used:**
- **`jsonwebtoken`, `openidconnect` / `oauth2`.** They bring a second HTTP client or the `rsa` crate. The
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
   - Tag rules (IdP groups, claims, email domains) came after the SSO steps (step 10).
   - The tag registry and admin assignment.
   - Agent tags from enrollment tokens, and the device-style `magicpipes login`.
   - Tunnel visibility and tags. On 2026-11-03 the tag model was replaced (personal tags, an
     `access` setting per tag, no owner exception and no inheritance) and labels removed.
   - The tunnel cookie flow and the access-denied page.
   - Discovery filtering in the API, UI and `ls --all`.
4. **SSO (OIDC)** (method 3). *Done;* its rules came with step 10.
5. **Authenticating proxy** (method 2). *Done;* `apply_to_tunnels` isn't built (see method 2). It moved behind OIDC on 2026-11-04: it needs TLS terminated in front of the
   management host, which a TLS-passthrough deployment can't do, and its signed-assertion mode
   reuses OIDC's token checks.
6. **Social login** (method 4): presets, plus GitHub's OAuth flow. *Done;* GitHub organizations and
   teams came with step 10.
7. **Email:** SMTP, invitations (method 5), then sign-in links and "forgot password"
   (method 6). *Done,* with the differences listed under those methods.
8. **`magicpipes connect`** for private TCP and UDP tunnels. *Done.* It signs in with a connect pass
   rather than a session: approved in a browser on any device, or from an API token for scripts.
9. **SSH gateway and web terminals** on the same rule; then RDP/VNC, then the VPN. *The gateway and
   the SSH terminal in the browser are done* (see "SSH gateway" in ARCHITECTURE.md), ahead of step 8.
   Writing into a terminal needs no extra tag: the machine's sshd decides which account each person
   may log in as, from their email (`AuthorizedPrincipalsFile`).
10. **Tag rules:** OIDC and proxy claims, GitHub organizations and teams, and confirmed address
    domains, on the Tags page and at `/api/v1/tag-rules`. *Done* (2026-11-12). With it the phase is
    done; what's left for later is listed under "Known limitations".
11. **Past the sign-in:** provider scopes, re-checks through refresh tokens, `auto_redirect`, and
    signing out at the provider. *Done* (2026-11-12).

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
- Steps 5–7: covered by a small test provider and a small mail server in the test harness, with
  real STARTTLS, rather than Dex in Docker.

## Known limitations

- **Certificate transparency.** In ACME mode every tunnel hostname, private ones included,
  appears in public certificate logs. Use `tls.mode = "files"` with a wildcard certificate, or
  unguessable names, when the names themselves are sensitive.
- **A private tunnel's existence is visible.** An anonymous request gets a login redirect where
  an unknown name gets 404. Hiding that would break the login flow.
- **IdP-driven revocation lags** by up to `sso_recheck_secs` (plus a quarter of it) for a session
  whose provider gave a refresh token, and by up to `session_max_age_secs` for one that didn't
  (GitHub, Google without offline access). With proxy auth there is no lag for who someone is:
  every request carries the proxy's current assertion. Their groups, for tag rules, are read when a
  session starts, so tags from them lag up to `session_max_age_secs`.
- **Left for later:** TOTP (below), `apply_to_tunnels`, `magicpipes ls --all`, tag rules in the
  configuration file, and controls for the admin token in the UI.
- **Password accounts have no second factor** until TOTP lands. For stronger login, put the
  server behind SSO or an authenticating proxy.
- **Offboarding from the provider waits.** Removing someone at a provider stops their next sign-in
  there, and with re-checks their sessions, but their account here stays: API tokens they made and
  their machines keep working, and so do tags an administrator assigned them. With
  `disable_idle_after_days`, that lasts until the account has gone that long without a single
  sign-on; without it, until an administrator disables the account. There's no SCIM and no
  back-channel logout. Accounts with a password are never disabled for going without.
- **Rules see only top-level claims.** A nested one, such as Keycloak's `realm_access.roles`,
  can't be matched; configure the provider to send it as a top-level claim (Keycloak's group or
  role mappers can).
- **Microsoft Entra users in more than 200 groups** get no `groups` claim: Entra puts a pointer
  to Microsoft Graph in its place (`_claim_names`), which isn't followed. Rules on their groups
  don't match. Entra's "groups assigned to the application" option keeps the list short.
- **Google Workspace groups** aren't in Google's ID tokens, so rules can't use them; the domain
  (`hd`) is there.
- **One org per server in the UI.** The schema already allows more.

## Decisions (settled 2026-11-01)

1. **The admin token stays permanently,** even with SSO or a proxy configured. UI controls to
   disable or regenerate it come later.
2. **Login methods ship in this order:**
   1. admin-created users with passwords;
   2. OIDC SSO;
   3. authenticating proxy;
   4. social login;
   5. email invitations;
   6. emailed sign-in links.
3. **Use free, permissively licensed libraries** where they help ("Libraries"):
   `jsonwebtoken` and `hmac` are approved; `argon2` and `lettre` are proposed under the same
   rule.
4. **Admins don't auto-connect to private tunnels.**
5. **New enrollments default to private tunnels once users exist.** Migrated agents stay
   public.
