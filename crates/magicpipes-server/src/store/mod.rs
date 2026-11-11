//! SQLite persistence (control plane only — the data plane never touches the database).
//!
//! Secrets are stored as SHA-256 digests (passwords as Argon2id hashes, computed by the caller).
//! All queries are short; callers hold the connection mutex only for the duration of one
//! statement or transaction. Users, sessions, API tokens and the audit log are in [`users`].

mod email;
mod history;
mod hostnames;
mod settings;
mod ssh_keys;
mod tags;
mod users;

pub use email::{AcceptWith, Accepted, InvitationRow, Invited, LinkPurpose, NewInvitation, SmtpRow};
pub use history::AlertRow;
pub use hostnames::{HostnameRow, MAX_HOSTNAMES};
pub use ssh_keys::{AddedSshKey, NewSshKey, SshKeyRow};
pub use settings::{MAX_OIDC_PROVIDERS, MAX_SIGN_IN_RULES, OidcProviderRow, SignInRules};
pub use tags::{EnrollmentSpec, MAX_TAGS, TagRow};
pub use users::{ApiTokenRow, LOCAL_ISSUER, MAX_API_TOKENS_PER_USER, UserRow};

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use magicpipes_core::proto::{Kind, Visibility};
use magicpipes_core::{secret, unix_now};
use rusqlite::{Connection, OptionalExtension, params};

#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

#[derive(Debug, Clone)]
pub struct TunnelRow {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub agent_id: String,
    pub target: String,
    pub created_at: i64,
    pub kind: Kind,
    /// Port tunnels only.
    pub public_port: Option<u16>,
    /// Port tunnels: allowed client networks (canonical CIDRs); empty = anyone.
    pub allow: Vec<String>,
    pub visibility: Visibility,
    /// Its tags (sorted), including its owner's personal tag.
    pub tags: Vec<String>,
    /// Does the server check its app on its own (`add --no-check` turns it off)?
    pub checks: bool,
    /// HTTP tunnels: the path a check requests.
    pub check_path: String,
}

#[derive(Debug, Clone)]
pub struct AgentRow {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
    /// `None`: a service agent, managed by administrators.
    pub owner_user_id: Option<String>,
    /// May its tunnels be public?
    pub allow_public: bool,
    /// Are its tunnels private unless asked otherwise?
    pub default_private: bool,
}

/// The schema, applied in order and tracked in `user_version`. Append only: a released
/// migration never changes. The list was restarted on 2026-11-03 (the tag model was replaced);
/// databases written before then are refused and must be deleted.
const MIGRATIONS: &[&str] = &[
    // 1: the whole schema. One organization for now; account and tag rows name it so more can
    // come without another rewrite. Every tag reference points at the registry, so deleting a tag
    // removes it everywhere through the cascade.
    r#"
    CREATE TABLE admin_tokens (
        id          TEXT PRIMARY KEY,
        token_hash  TEXT NOT NULL UNIQUE,
        created_at  INTEGER NOT NULL
    );
    CREATE TABLE orgs (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        created_at  INTEGER NOT NULL
    );
    INSERT INTO orgs (id, name, created_at) VALUES ('org_default', 'default', CAST(strftime('%s', 'now') AS INTEGER));
    CREATE TABLE users (
        id                   TEXT PRIMARY KEY,
        email                TEXT NOT NULL,
        email_verified_at    INTEGER,
        display_name         TEXT NOT NULL DEFAULT '',
        disabled_at          INTEGER,
        sessions_valid_after INTEGER NOT NULL DEFAULT 0,
        created_at           INTEGER NOT NULL
    );
    CREATE TABLE identities (
        issuer        TEXT NOT NULL,
        subject       TEXT NOT NULL,
        user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        last_login_at INTEGER,
        PRIMARY KEY (issuer, subject)
    );
    CREATE INDEX identities_user ON identities(user_id);
    CREATE TABLE memberships (
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role        TEXT NOT NULL CHECK (role IN ('admin', 'member')),
        created_at  INTEGER NOT NULL,
        PRIMARY KEY (org_id, user_id)
    );
    CREATE TABLE passwords (
        user_id     TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        hash        TEXT NOT NULL,
        must_change INTEGER NOT NULL DEFAULT 1,
        updated_at  INTEGER NOT NULL
    );
    CREATE TABLE sessions (
        id_hash     TEXT PRIMARY KEY,
        user_id     TEXT REFERENCES users(id) ON DELETE CASCADE,
        org_id      TEXT NOT NULL,
        csrf        TEXT NOT NULL,
        created_at  INTEGER NOT NULL,
        expires_at  INTEGER NOT NULL
    );
    CREATE INDEX sessions_user ON sessions(user_id);
    CREATE TABLE api_tokens (
        id           TEXT PRIMARY KEY,
        token_hash   TEXT NOT NULL UNIQUE,
        user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        org_id       TEXT NOT NULL,
        name         TEXT NOT NULL,
        created_at   INTEGER NOT NULL,
        expires_at   INTEGER,
        last_used_at INTEGER
    );
    CREATE INDEX api_tokens_user ON api_tokens(user_id);
    CREATE TABLE audit_log (
        id          INTEGER PRIMARY KEY,
        at          INTEGER NOT NULL,
        org_id      TEXT NOT NULL,
        actor       TEXT NOT NULL,
        action      TEXT NOT NULL,
        resource    TEXT NOT NULL,
        detail      TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX audit_log_at ON audit_log(at);

    -- Tags label users, agents and tunnels. A user and a tunnel sharing a tag with `access`
    -- set is the only way into a private tunnel. A tag with `user_id` is that user's personal
    -- tag: the server creates it with the account and puts it on the tunnels of their machines.
    CREATE TABLE tags (
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        name        TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        access      INTEGER NOT NULL DEFAULT 1,
        user_id     TEXT UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        created_by  TEXT,
        created_at  INTEGER NOT NULL,
        PRIMARY KEY (org_id, name)
    );
    CREATE TABLE user_tags (
        org_id      TEXT NOT NULL,
        user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        tag         TEXT NOT NULL,
        assigned_by TEXT,
        created_at  INTEGER NOT NULL,
        PRIMARY KEY (org_id, user_id, tag),
        FOREIGN KEY (org_id, tag) REFERENCES tags(org_id, name) ON DELETE CASCADE
    );

    -- A personal agent (`owner_user_id` set) acts with its owner's tags; only service agents
    -- have tags of their own.
    CREATE TABLE agents (
        id              TEXT PRIMARY KEY,
        name            TEXT NOT NULL,
        token_hash      TEXT NOT NULL,
        created_at      INTEGER NOT NULL,
        last_seen_at    INTEGER,
        org_id          TEXT NOT NULL DEFAULT 'org_default',
        owner_user_id   TEXT REFERENCES users(id),
        allow_public    INTEGER NOT NULL DEFAULT 1,
        default_private INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE agent_tags (
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
        created_by      TEXT,
        owner_user_id   TEXT,
        allow_public    INTEGER NOT NULL DEFAULT 1,
        default_private INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE enrollment_tags (
        token_hash  TEXT NOT NULL REFERENCES enrollments(token_hash) ON DELETE CASCADE,
        org_id      TEXT NOT NULL,
        tag         TEXT NOT NULL,
        PRIMARY KEY (token_hash, tag),
        FOREIGN KEY (org_id, tag) REFERENCES tags(org_id, name) ON DELETE CASCADE
    );

    -- Port tunnels keep a hostname `<name>.<base_domain>` (names are unique across kinds) that
    -- is never routed or given a certificate.
    CREATE TABLE tunnels (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL UNIQUE,
        hostname    TEXT NOT NULL UNIQUE,
        agent_id    TEXT NOT NULL REFERENCES agents(id),
        target      TEXT NOT NULL,
        created_at  INTEGER NOT NULL,
        kind        TEXT NOT NULL DEFAULT 'http',
        public_port INTEGER,
        allow       TEXT NOT NULL DEFAULT '',
        visibility  TEXT NOT NULL DEFAULT 'private' CHECK (visibility IN ('public', 'private'))
    );
    CREATE UNIQUE INDEX tunnels_public_port ON tunnels(kind, public_port) WHERE public_port IS NOT NULL;
    CREATE TABLE tunnel_tags (
        tunnel_id   TEXT NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
        org_id      TEXT NOT NULL,
        tag         TEXT NOT NULL,
        PRIMARY KEY (tunnel_id, tag),
        FOREIGN KEY (org_id, tag) REFERENCES tags(org_id, name) ON DELETE CASCADE
    );
    "#,
    // 2: custom hostnames. An administrator registers a hostname outside `<name>.<base_domain>`
    // and assigns it to a user (for their machines) or to a service agent; only that machine
    // may serve it. Assignments go with their user or agent.
    r#"
    CREATE TABLE hostnames (
        hostname      TEXT PRIMARY KEY,
        org_id        TEXT NOT NULL DEFAULT 'org_default',
        owner_user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
        agent_id      TEXT REFERENCES agents(id) ON DELETE CASCADE,
        created_by    TEXT,
        created_at    INTEGER NOT NULL,
        CHECK ((owner_user_id IS NULL) != (agent_id IS NULL))
    );
    "#,
    // 3: one account per email. Single sign-on creates accounts as well as administrators do, and
    // a person must not end up with two.
    r#"
    CREATE UNIQUE INDEX users_email ON users(email);
    "#,
    // 4: sign-in settings made on the Settings page. Client secrets stay out of the database, in
    // `<data_dir>/oidc-secrets/`. The issuer is unique because identities are `(issuer, subject)`.
    r#"
    CREATE TABLE oidc_providers (
        id            TEXT PRIMARY KEY,
        org_id        TEXT NOT NULL DEFAULT 'org_default',
        label         TEXT NOT NULL,
        issuer        TEXT NOT NULL UNIQUE,
        client_id     TEXT NOT NULL,
        link_by_email INTEGER NOT NULL DEFAULT 0,
        trust_email   INTEGER NOT NULL DEFAULT 0,
        created_at    INTEGER NOT NULL
    );
    CREATE TABLE sign_in_rules (
        org_id TEXT NOT NULL DEFAULT 'org_default',
        kind   TEXT NOT NULL CHECK (kind IN ('bootstrap_admin', 'email_domain')),
        value  TEXT NOT NULL,
        PRIMARY KEY (org_id, kind, value)
    );
    "#,
    // 5: an address a trusted provider didn't verify reaches administrators' accounts only if
    // this says so.
    r#"
    ALTER TABLE oidc_providers ADD COLUMN allow_unverified_admin INTEGER NOT NULL DEFAULT 0;
    "#,
    // 6: GitHub isn't OpenID Connect, so a provider says what it speaks.
    r#"
    ALTER TABLE oidc_providers ADD COLUMN kind TEXT NOT NULL DEFAULT 'oidc';
    "#,
    // 7: email. Only digests of codes are stored, and a used one is deleted. One invitation per
    // address; a tag it names goes with the tag, like any other assignment. The mail server's
    // password stays out of the database, in `<data_dir>/smtp-password`.
    r#"
    CREATE TABLE invitations (
        id           TEXT PRIMARY KEY,
        token_hash   TEXT NOT NULL UNIQUE,
        org_id       TEXT NOT NULL DEFAULT 'org_default',
        email        TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL DEFAULT '',
        role         TEXT NOT NULL CHECK (role IN ('admin', 'member')),
        created_by   TEXT NOT NULL,
        created_at   INTEGER NOT NULL,
        expires_at   INTEGER NOT NULL
    );
    CREATE INDEX invitations_created_by ON invitations(created_by);
    CREATE TABLE invitation_tags (
        invitation_id TEXT NOT NULL REFERENCES invitations(id) ON DELETE CASCADE,
        org_id        TEXT NOT NULL DEFAULT 'org_default',
        tag           TEXT NOT NULL,
        PRIMARY KEY (invitation_id, tag),
        FOREIGN KEY (org_id, tag) REFERENCES tags(org_id, name) ON DELETE CASCADE
    );
    CREATE TABLE email_tokens (
        token_hash TEXT PRIMARY KEY,
        purpose    TEXT NOT NULL CHECK (purpose IN ('sign_in', 'confirm')),
        user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at INTEGER NOT NULL
    );
    CREATE INDEX email_tokens_user ON email_tokens(user_id);
    CREATE TABLE smtp_settings (
        org_id       TEXT PRIMARY KEY DEFAULT 'org_default',
        host         TEXT NOT NULL,
        port         INTEGER NOT NULL,
        tls          TEXT NOT NULL,
        username     TEXT,
        from_address TEXT NOT NULL
    );
    "#,
    // 8: public keys for the SSH gateway. The fingerprint is unique: a key stands for one person.
    r#"
    CREATE TABLE ssh_keys (
        id           TEXT PRIMARY KEY,
        user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        org_id       TEXT NOT NULL DEFAULT 'org_default',
        name         TEXT NOT NULL,
        algorithm    TEXT NOT NULL,
        fingerprint  TEXT NOT NULL UNIQUE,
        public_key   TEXT NOT NULL,
        created_at   INTEGER NOT NULL,
        last_used_at INTEGER
    );
    CREATE INDEX ssh_keys_user ON ssh_keys(user_id);
    "#,
    // 9: the host key each SSH tunnel's sshd showed the server's browser terminal first, kept so a
    // different one is refused.
    r#"
    CREATE TABLE ssh_host_keys (
        tunnel_id   TEXT PRIMARY KEY REFERENCES tunnels(id) ON DELETE CASCADE,
        fingerprint TEXT NOT NULL,
        seen_at     INTEGER NOT NULL
    );
    "#,
    // 10: history in 5-minute slots (`slot`: when one started, in Unix time), kept for
    // `monitoring.history_days`; and alerts, open and closed. `l0`-`l14` count answers by how
    // long they took (`LATENCY_BUCKETS_MS`, the last for longer ones). An alert's subject is
    // `tunnel:<id>`, `machine:<id>`, `certificate:<tunnel id>` or `server`, with its name when the
    // alert opened, for after it's gone.
    r#"
    CREATE TABLE tunnel_history (
        tunnel_id   TEXT NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
        slot        INTEGER NOT NULL,
        requests    INTEGER NOT NULL,
        offline     INTEGER NOT NULL,
        unreachable INTEGER NOT NULL,
        timed_out   INTEGER NOT NULL,
        refused     INTEGER NOT NULL,
        bytes_in    INTEGER NOT NULL,
        bytes_out   INTEGER NOT NULL,
        l0 INTEGER NOT NULL, l1 INTEGER NOT NULL, l2 INTEGER NOT NULL, l3 INTEGER NOT NULL, l4 INTEGER NOT NULL,
        l5 INTEGER NOT NULL, l6 INTEGER NOT NULL, l7 INTEGER NOT NULL, l8 INTEGER NOT NULL, l9 INTEGER NOT NULL,
        l10 INTEGER NOT NULL, l11 INTEGER NOT NULL, l12 INTEGER NOT NULL, l13 INTEGER NOT NULL, l14 INTEGER NOT NULL,
        PRIMARY KEY (tunnel_id, slot)
    ) WITHOUT ROWID;
    CREATE INDEX tunnel_history_slot ON tunnel_history(slot);
    CREATE TABLE agent_history (
        agent_id    TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
        slot        INTEGER NOT NULL,
        online      INTEGER NOT NULL,
        samples     INTEGER NOT NULL,
        connections INTEGER NOT NULL,
        round_trip  INTEGER NOT NULL,
        round_trips INTEGER NOT NULL,
        reconnects  INTEGER NOT NULL,
        PRIMARY KEY (agent_id, slot)
    ) WITHOUT ROWID;
    CREATE INDEX agent_history_slot ON agent_history(slot);
    CREATE TABLE alerts (
        id           TEXT PRIMARY KEY,
        rule         TEXT NOT NULL,
        subject      TEXT NOT NULL,
        subject_name TEXT NOT NULL,
        severity     TEXT NOT NULL,
        detail       TEXT NOT NULL,
        opened_at    INTEGER NOT NULL,
        closed_at    INTEGER
    );
    CREATE INDEX alerts_closed ON alerts(closed_at);
    "#,
    // 11: the server's own checks of each tunnel, on unless an agent turned them off, and the
    // path they request on an HTTP tunnel.
    r#"
    ALTER TABLE tunnels ADD COLUMN checks INTEGER NOT NULL DEFAULT 1;
    ALTER TABLE tunnels ADD COLUMN check_path TEXT NOT NULL DEFAULT '/';
    "#,
];

fn migrate(conn: &mut Connection) -> anyhow::Result<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let tables: i64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'", [], |r| r.get(0))?;
    // The schema restarted on 2026-11-03, reusing version numbers: its first migration is what
    // tells an older database at the same version apart.
    let restarted: i64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'tunnel_tags'", [], |r| r.get(0))?;
    if usize::try_from(version).map_or(true, |v| v > MIGRATIONS.len()) || (version == 0 && tables > 0) || (version > 0 && restarted == 0) {
        anyhow::bail!(
            "the database has schema version {version}, which this magicpipesd doesn't know; databases from before 2026-11-03 \
             can't be upgraded: delete it (and the -wal and -shm files next to it) to start over"
        );
    }
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(usize::try_from(version).unwrap_or(0)) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql).with_context(|| format!("database migration {}", i + 1))?;
        tx.pragma_update(None, "user_version", i as i64 + 1)?;
        tx.commit()?;
        tracing::info!(version = i + 1, "database migrated");
    }
    Ok(())
}

const TUNNEL_COLUMNS: &str =
    "id, name, hostname, agent_id, target, created_at, kind, public_port, allow, visibility, checks, check_path";

fn tunnel_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<TunnelRow> {
    let kind: String = r.get(6)?;
    let allow: String = r.get(8)?;
    let visibility: String = r.get(9)?;
    Ok(TunnelRow {
        id: r.get(0)?,
        name: r.get(1)?,
        hostname: r.get(2)?,
        agent_id: r.get(3)?,
        target: r.get(4)?,
        created_at: r.get(5)?,
        kind: Kind::parse(&kind).unwrap_or_default(),
        public_port: r.get(7)?,
        allow: allow.split_whitespace().map(str::to_string).collect(),
        // A visibility that can't be read keeps the tunnel private.
        visibility: Visibility::parse(&visibility).unwrap_or(Visibility::Private),
        tags: Vec::new(),
        checks: r.get(10)?,
        check_path: r.get(11)?,
    })
}

impl Store {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let mut conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        migrate(&mut conn)?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> anyhow::Result<T> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        Ok(f(&conn)?)
    }

    // ---- administrators -------------------------------------------------------------------

    pub fn admin_token_count(&self) -> anyhow::Result<i64> {
        self.with(|c| c.query_row("SELECT COUNT(*) FROM admin_tokens", [], |r| r.get(0)))
    }

    /// Creates a new admin token. With `replace_all`, every existing admin token is revoked,
    /// and so is every UI session signed in with one (sessions without a user).
    pub fn create_admin_token(&self, replace_all: bool) -> anyhow::Result<String> {
        let token = secret::new_token("mpadm");
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        if replace_all {
            tx.execute("DELETE FROM admin_tokens", [])?;
            tx.execute("DELETE FROM sessions WHERE user_id IS NULL", [])?;
        }
        tx.execute(
            "INSERT INTO admin_tokens (id, token_hash, created_at) VALUES (?1, ?2, ?3)",
            params![secret::new_id("adm"), secret::sha256_hex(&token), unix_now()],
        )?;
        tx.commit()?;
        Ok(token)
    }

    pub fn verify_admin_token(&self, token: &str) -> anyhow::Result<bool> {
        if !token.starts_with("mpadm_") {
            return Ok(false);
        }
        let hash = secret::sha256_hex(token);
        let found: Option<String> = self.with(|c| {
            c.query_row("SELECT token_hash FROM admin_tokens WHERE token_hash = ?1", [&hash], |r| r.get(0))
                .optional()
        })?;
        Ok(found.is_some_and(|h| secret::constant_time_eq(h.as_bytes(), hash.as_bytes())))
    }

    // ---- enrollment & agents --------------------------------------------------------------

    /// A user's machines, counting enrollment tokens that could still become one.
    pub fn machines_of(&self, user_id: &str) -> anyhow::Result<usize> {
        let n: i64 = self.with(|c| {
            c.query_row(
                "SELECT (SELECT COUNT(*) FROM agents WHERE owner_user_id = ?1)
                      + (SELECT COUNT(*) FROM enrollments WHERE owner_user_id = ?1 AND used_at IS NULL AND expires_at >= ?2)",
                params![user_id, unix_now()],
                |r| r.get(0),
            )
        })?;
        Ok(n as usize)
    }

    /// Creates a single-use enrollment token; the agent enrolled with it gets `spec`'s owner,
    /// tags and visibility settings.
    pub fn create_enrollment(&self, ttl_secs: u64, spec: &EnrollmentSpec) -> anyhow::Result<String> {
        let token = secret::new_token("mpenr");
        let hash = secret::sha256_hex(&token);
        let now = unix_now();
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM enrollments WHERE expires_at < ?1 AND used_at IS NULL", [now])?;
        tx.execute(
            "INSERT INTO enrollments (token_hash, created_at, expires_at, created_by, owner_user_id, allow_public, default_private)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                hash,
                now,
                now + ttl_secs as i64,
                spec.created_by,
                spec.owner_user_id,
                spec.allow_public as i64,
                spec.default_private as i64
            ],
        )?;
        for t in &spec.tags {
            tx.execute("INSERT INTO enrollment_tags (token_hash, org_id, tag) VALUES (?1, ?2, ?3)", params![hash, users::DEFAULT_ORG, t])?;
        }
        tx.commit()?;
        Ok(token)
    }

    /// Atomically consumes an enrollment token and creates an agent identity.
    /// Returns `(agent_id, agent_token)`, or `None` if the token is unknown, used or expired.
    pub fn enroll(&self, enrollment_token: &str, agent_name: &str) -> anyhow::Result<Option<(String, String)>> {
        let hash = secret::sha256_hex(enrollment_token);
        let now = unix_now();
        let agent_id = secret::new_id("ag");
        let agent_secret = secret::new_token("mpa");
        let agent_token = format!("{agent_id}.{agent_secret}");
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let updated = tx.execute(
            "UPDATE enrollments SET used_at = ?1, agent_id = ?2
             WHERE token_hash = ?3 AND used_at IS NULL AND expires_at >= ?1",
            params![now, agent_id, hash],
        )?;
        if updated != 1 {
            return Ok(None);
        }
        // The agent takes the token's owner, tags and visibility settings.
        tx.execute(
            "INSERT INTO agents (id, name, token_hash, created_at, owner_user_id, allow_public, default_private)
             SELECT ?1, ?2, ?3, ?4, owner_user_id, allow_public, default_private FROM enrollments WHERE token_hash = ?5",
            params![agent_id, agent_name, secret::sha256_hex(&agent_token), now, hash],
        )?;
        tx.execute(
            "INSERT INTO agent_tags (agent_id, org_id, tag) SELECT ?1, org_id, tag FROM enrollment_tags WHERE token_hash = ?2",
            params![agent_id, hash],
        )?;
        tx.commit()?;
        Ok(Some((agent_id, agent_token)))
    }

    /// Verifies an agent token (`<agent id>.<secret>`) and returns the agent id.
    pub fn verify_agent_token(&self, token: &str) -> anyhow::Result<Option<String>> {
        let Some((agent_id, _)) = token.split_once('.') else { return Ok(None) };
        if !agent_id.starts_with("ag_") {
            return Ok(None);
        }
        let stored: Option<String> = self.with(|c| {
            c.query_row("SELECT token_hash FROM agents WHERE id = ?1", [agent_id], |r| r.get(0)).optional()
        })?;
        Ok(stored.filter(|h| secret::verify(token, h)).map(|_| agent_id.to_string()))
    }

    pub fn touch_agent(&self, agent_id: &str) -> anyhow::Result<()> {
        self.with(|c| c.execute("UPDATE agents SET last_seen_at = ?1 WHERE id = ?2", params![unix_now(), agent_id]))?;
        Ok(())
    }

    pub fn agent_exists(&self, agent_id: &str) -> anyhow::Result<bool> {
        self.with(|c| c.query_row("SELECT EXISTS(SELECT 1 FROM agents WHERE id = ?1)", [agent_id], |r| r.get(0)))
    }

    /// Deletes an agent identity and every tunnel it owns. Returns false if the agent is unknown.
    pub fn delete_agent(&self, agent_id: &str) -> anyhow::Result<bool> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM tunnels WHERE agent_id = ?1", [agent_id])?;
        let deleted = tx.execute("DELETE FROM agents WHERE id = ?1", [agent_id])?;
        tx.commit()?;
        Ok(deleted == 1)
    }

    pub fn agents(&self) -> anyhow::Result<Vec<AgentRow>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT id, name, created_at, last_seen_at, owner_user_id, allow_public, default_private FROM agents ORDER BY created_at",
            )?;
            st.query_map([], |r| {
                Ok(AgentRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    created_at: r.get(2)?,
                    last_seen_at: r.get(3)?,
                    owner_user_id: r.get(4)?,
                    allow_public: r.get::<_, i64>(5)? != 0,
                    default_private: r.get::<_, i64>(6)? != 0,
                })
            })?
            .collect()
        })
    }

    // ---- tunnels --------------------------------------------------------------------------

    pub fn tunnels(&self) -> anyhow::Result<Vec<TunnelRow>> {
        let mut rows: Vec<TunnelRow> = self.with(|c| {
            let mut st = c.prepare(&format!("SELECT {TUNNEL_COLUMNS} FROM tunnels ORDER BY created_at"))?;
            st.query_map([], tunnel_row)?.collect()
        })?;
        let tags: Vec<(String, String)> = self.with(|c| {
            let mut st = c.prepare("SELECT tunnel_id, tag FROM tunnel_tags ORDER BY tag")?;
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
        })?;
        for (id, tag) in tags {
            if let Some(t) = rows.iter_mut().find(|t| t.id == id) {
                t.tags.push(tag);
            }
        }
        Ok(rows)
    }

    /// Replaces a tunnel's tags (inside the caller's transaction).
    fn write_tags(tx: &rusqlite::Transaction<'_>, t: &TunnelRow) -> rusqlite::Result<()> {
        tx.execute("DELETE FROM tunnel_tags WHERE tunnel_id = ?1", [&t.id])?;
        for tag in &t.tags {
            tx.execute("INSERT INTO tunnel_tags (tunnel_id, org_id, tag) VALUES (?1, ?2, ?3)", params![t.id, users::DEFAULT_ORG, tag])?;
        }
        Ok(())
    }

    pub fn insert_tunnel(&self, t: &TunnelRow) -> anyhow::Result<()> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        tx.execute(
            &format!("INSERT INTO tunnels ({TUNNEL_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"),
            params![
                t.id,
                t.name,
                t.hostname,
                t.agent_id,
                t.target,
                t.created_at,
                t.kind.as_str(),
                t.public_port,
                t.allow.join(" "),
                t.visibility.as_str(),
                t.checks,
                t.check_path
            ],
        )?;
        Self::write_tags(&tx, t)?;
        tx.commit()?;
        Ok(())
    }

    /// Saves the settings an agent may change on an existing tunnel.
    pub fn update_tunnel(&self, t: &TunnelRow) -> anyhow::Result<()> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE tunnels SET target = ?1, public_port = ?2, allow = ?3, visibility = ?4, checks = ?5, check_path = ?6 WHERE id = ?7",
            params![t.target, t.public_port, t.allow.join(" "), t.visibility.as_str(), t.checks, t.check_path, t.id],
        )?;
        Self::write_tags(&tx, t)?;
        tx.commit()?;
        Ok(())
    }

    pub fn delete_tunnel(&self, id: &str) -> anyhow::Result<()> {
        self.with(|c| c.execute("DELETE FROM tunnels WHERE id = ?1", [id]))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_is_single_use() {
        let dir = std::env::temp_dir().join(format!("mp-store-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("db.sqlite")).unwrap();
        let enr = store.create_enrollment(60, &EnrollmentSpec::default()).unwrap();
        let (id, token) = store.enroll(&enr, "laptop").unwrap().unwrap();
        assert!(store.enroll(&enr, "again").unwrap().is_none());
        assert_eq!(store.verify_agent_token(&token).unwrap().as_deref(), Some(id.as_str()));
        assert!(store.verify_agent_token(&format!("{id}.wrong")).unwrap().is_none());
        let adm = store.create_admin_token(false).unwrap();
        assert!(store.verify_admin_token(&adm).unwrap());
        assert!(!store.verify_admin_token("mpadm_nope").unwrap());
        // Rotating revokes the old tokens and the UI sessions signed in with them.
        let (cookie, _) = store.create_session(None, 3600).unwrap();
        assert!(store.session(&cookie).unwrap().is_some());
        let fresh = store.create_admin_token(true).unwrap();
        assert!(!store.verify_admin_token(&adm).unwrap() && store.verify_admin_token(&fresh).unwrap());
        assert!(store.session(&cookie).unwrap().is_none());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn deleting_an_agent_revokes_its_token_and_tunnels() {
        let dir = std::env::temp_dir().join(format!("mp-store-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("db.sqlite")).unwrap();
        let (id, token) = store.enroll(&store.create_enrollment(60, &EnrollmentSpec::default()).unwrap(), "laptop").unwrap().unwrap();
        let (other, other_token) = store.enroll(&store.create_enrollment(60, &EnrollmentSpec::default()).unwrap(), "desktop").unwrap().unwrap();
        for (tid, agent) in [("tn_a", &id), ("tn_b", &other)] {
            store
                .insert_tunnel(&TunnelRow {
                    id: tid.into(),
                    name: tid.into(),
                    hostname: format!("{tid}.example.com"),
                    agent_id: agent.clone(),
                    target: "http://127.0.0.1:1".into(),
                    created_at: 0,
                    kind: Kind::Http,
                    public_port: None,
                    allow: vec![],
                    visibility: Visibility::Public,
                    tags: vec![],
                    checks: true,
                    check_path: "/".into(),
                })
                .unwrap();
        }
        assert!(store.delete_agent(&id).unwrap());
        assert!(!store.delete_agent(&id).unwrap());
        assert!(store.verify_agent_token(&token).unwrap().is_none());
        assert_eq!(store.verify_agent_token(&other_token).unwrap().as_deref(), Some(other.as_str()));
        let left: Vec<_> = store.tunnels().unwrap().into_iter().map(|t| t.id).collect();
        assert_eq!(left, ["tn_b"]);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn keeps_ports_unique_and_refuses_old_databases() {
        let dir = std::env::temp_dir().join(format!("mp-store-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db.sqlite");
        let store = Store::open(&path).unwrap();
        let (agent, _) = store.enroll(&store.create_enrollment(60, &EnrollmentSpec::default()).unwrap(), "db").unwrap().unwrap();
        let row = |id: &str, kind, port| TunnelRow {
            id: id.into(),
            name: id.into(),
            hostname: format!("{id}.t.test"),
            agent_id: agent.clone(),
            target: "tcp://127.0.0.1:5432".into(),
            created_at: 1,
            kind,
            public_port: Some(port),
            allow: vec!["10.0.0.0/8".into(), "192.0.2.1/32".into()],
            visibility: Visibility::Public,
            tags: vec![],
            checks: false,
            check_path: "/".into(),
        };
        store.insert_tunnel(&row("tn_tcp", Kind::Tcp, 65500)).unwrap();
        store.insert_tunnel(&row("tn_udp", Kind::Udp, 65500)).unwrap();
        assert!(store.insert_tunnel(&row("tn_dup", Kind::Tcp, 65500)).is_err(), "a TCP port belongs to one tunnel");
        let tcp = store.tunnels().unwrap().into_iter().find(|t| t.id == "tn_tcp").unwrap();
        assert_eq!(tcp.allow, ["10.0.0.0/8", "192.0.2.1/32"]);
        drop(store);
        // Opening again does not re-run the schema.
        assert_eq!(Store::open(&path).unwrap().tunnels().unwrap().len(), 2);

        // A database from before the schema was restarted (which used versions 1 to 4 too), from
        // before migrations (version 0 with tables) or from a newer server is refused rather
        // than misread.
        for (version, name) in [(1, "v1.sqlite"), (4, "v4.sqlite"), (0, "v0.sqlite"), (999, "v999.sqlite")] {
            let old = dir.join(name);
            let c = Connection::open(&old).unwrap();
            c.execute_batch("CREATE TABLE agents (id TEXT PRIMARY KEY)").unwrap();
            c.pragma_update(None, "user_version", version).unwrap();
            drop(c);
            let e = Store::open(&old).err().expect("refused");
            assert!(format!("{e:#}").contains("delete it"), "{e:#}");
        }
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_database_from_before_ssh_keys_gets_them_and_keeps_its_rows() {
        let dir = std::env::temp_dir().join(format!("mp-store-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db.sqlite");
        let mut c = Connection::open(&path).unwrap();
        c.execute_batch("PRAGMA foreign_keys = ON").unwrap();
        for (i, sql) in MIGRATIONS.iter().enumerate().take(7) {
            let tx = c.transaction().unwrap();
            tx.execute_batch(sql).unwrap();
            tx.pragma_update(None, "user_version", i as i64 + 1).unwrap();
            tx.commit().unwrap();
        }
        c.execute("INSERT INTO agents (id, name, token_hash, created_at) VALUES ('ag_a', 'old', 'x', 0)", []).unwrap();
        drop(c);

        let store = Store::open(&path).unwrap();
        assert!(store.agents().unwrap().iter().any(|a| a.id == "ag_a"), "kept");
        assert!(store.ssh_keys().unwrap().is_empty());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_database_from_before_history_gets_it_and_keeps_its_rows() {
        let dir = std::env::temp_dir().join(format!("mp-store-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db.sqlite");
        let mut c = Connection::open(&path).unwrap();
        c.execute_batch("PRAGMA foreign_keys = ON").unwrap();
        for (i, sql) in MIGRATIONS.iter().enumerate().take(9) {
            let tx = c.transaction().unwrap();
            tx.execute_batch(sql).unwrap();
            tx.pragma_update(None, "user_version", i as i64 + 1).unwrap();
            tx.commit().unwrap();
        }
        c.execute("INSERT INTO agents (id, name, token_hash, created_at) VALUES ('ag_a', 'old', 'x', 0)", []).unwrap();
        drop(c);

        let store = Store::open(&path).unwrap();
        assert!(store.agents().unwrap().iter().any(|a| a.id == "ag_a"), "kept");
        assert!(store.open_alerts().unwrap().is_empty() && store.agent_history_since(0).unwrap().is_empty());
        let p = crate::control::history::Presence { online: 1, samples: 1, ..Default::default() };
        store.save_history(&[], &[("ag_a".into(), 300, p)]).unwrap();
        assert_eq!(store.agent_history_since(0).unwrap(), vec![("ag_a".to_string(), 300, p)]);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn tunnels_from_before_checks_are_checked_at_their_root() {
        let dir = std::env::temp_dir().join(format!("mp-store-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db.sqlite");
        let mut c = Connection::open(&path).unwrap();
        c.execute_batch("PRAGMA foreign_keys = ON").unwrap();
        for (i, sql) in MIGRATIONS.iter().enumerate().take(10) {
            let tx = c.transaction().unwrap();
            tx.execute_batch(sql).unwrap();
            tx.pragma_update(None, "user_version", i as i64 + 1).unwrap();
            tx.commit().unwrap();
        }
        c.execute("INSERT INTO agents (id, name, token_hash, created_at) VALUES ('ag_a', 'old', 'x', 0)", []).unwrap();
        c.execute("INSERT INTO tunnels (id, name, hostname, agent_id, target, created_at) VALUES ('tn_a', 'a', 'a.t.test', 'ag_a', 'x', 0)", []).unwrap();
        drop(c);
        let t = Store::open(&path).unwrap().tunnels().unwrap().remove(0);
        assert_eq!((t.id.as_str(), t.checks, t.check_path.as_str()), ("tn_a", true, "/"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn ssh_keys_stand_for_one_person_and_are_limited() {
        let dir = std::env::temp_dir().join(format!("mp-store-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("db.sqlite")).unwrap();
        let mut users = Vec::new();
        for email in ["a@example.com", "b@example.com"] {
            let id = store.create_user(email, "", crate::authz::Role::Member, "not a real hash").unwrap().unwrap();
            users.push(id);
        }
        fn key<'a>(user_id: &'a str, fingerprint: &'a str) -> NewSshKey<'a> {
            NewSshKey { user_id, name: "k", algorithm: "ssh-ed25519", fingerprint, public_key: "ssh-ed25519 AAAA" }
        }
        let AddedSshKey::Added(first) = store.add_ssh_key(&key(&users[0], "SHA256:one")).unwrap() else { panic!("added") };
        assert!(matches!(store.add_ssh_key(&key(&users[1], "SHA256:one")).unwrap(), AddedSshKey::Taken));
        assert!(matches!(store.add_ssh_key(&key(&users[0], "SHA256:one")).unwrap(), AddedSshKey::Taken));
        for i in 1..ssh_keys::MAX_SSH_KEYS_PER_USER {
            assert!(matches!(store.add_ssh_key(&key(&users[0], &format!("SHA256:{i}"))).unwrap(), AddedSshKey::Added(_)));
        }
        assert!(matches!(store.add_ssh_key(&key(&users[0], "SHA256:more")).unwrap(), AddedSshKey::Full));
        assert!(matches!(store.add_ssh_key(&key(&users[1], "SHA256:more")).unwrap(), AddedSshKey::Added(_)), "the limit is per person");

        // Only its owner deletes a key.
        assert!(!store.delete_ssh_key(&users[1], &first.id).unwrap());
        assert!(store.delete_ssh_key(&users[0], &first.id).unwrap());
        assert!(!store.delete_ssh_key(&users[0], &first.id).unwrap());
        // And it goes with its owner.
        store.with(|c| c.execute("DELETE FROM users WHERE id = ?1", [&users[1]])).unwrap();
        assert!(store.ssh_keys().unwrap().iter().all(|k| k.user_id == users[0]));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn deleting_a_tag_removes_it_from_tunnels() {
        let dir = std::env::temp_dir().join(format!("mp-store-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db.sqlite");
        let store = Store::open(&path).unwrap();
        let (agent, _) = store.enroll(&store.create_enrollment(60, &EnrollmentSpec::default()).unwrap(), "laptop").unwrap().unwrap();
        assert!(store.create_tag("secret", "", true, None).unwrap());
        assert!(store.create_tag("dev", "", true, None).unwrap());
        store
            .insert_tunnel(&TunnelRow {
                id: "tn_a".into(),
                name: "a".into(),
                hostname: "a.t.test".into(),
                agent_id: agent,
                target: "http://127.0.0.1:1".into(),
                created_at: 0,
                kind: Kind::Http,
                public_port: None,
                allow: vec![],
                visibility: Visibility::Private,
                tags: vec!["dev".into(), "secret".into()],
                checks: true,
                check_path: "/".into(),
            })
            .unwrap();
        assert!(store.delete_tag("secret").unwrap());
        drop(store);
        assert_eq!(Store::open(&path).unwrap().tunnels().unwrap()[0].tags, ["dev"]);
        std::fs::remove_dir_all(dir).ok();
    }
}
