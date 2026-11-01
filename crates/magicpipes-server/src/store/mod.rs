//! SQLite persistence (control plane only — the data plane never touches the database).
//!
//! Secrets are stored as SHA-256 digests (passwords as Argon2id hashes, computed by the caller).
//! All queries are short; callers hold the connection mutex only for the duration of one
//! statement or transaction. Users, sessions, API tokens and the audit log are in [`users`].

mod tags;
mod users;

pub use tags::{EnrollmentSpec, MAX_TAGS};
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
    /// Private tunnels: the requested access tags (the effective set is limited to the agent's
    /// tags when routes are published); empty = all of the agent's tags.
    pub access: Vec<String>,
    pub labels: Vec<String>,
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
    pub labels: Vec<String>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS admin_tokens (
    id          TEXT PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER
);
CREATE TABLE IF NOT EXISTS enrollments (
    token_hash  TEXT PRIMARY KEY,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER,
    agent_id    TEXT
);
CREATE TABLE IF NOT EXISTS tunnels (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    hostname    TEXT NOT NULL UNIQUE,
    agent_id    TEXT NOT NULL REFERENCES agents(id),
    target      TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);
"#;

/// Schema changes after the initial schema, applied in order and tracked in `user_version`.
/// Append only: a released migration never changes.
const MIGRATIONS: &[&str] = &[
    // 1: port tunnels. Their hostname stays `<name>.<base_domain>` (names are unique across
    // kinds) but is never routed or given a certificate.
    r#"
    ALTER TABLE tunnels ADD COLUMN kind TEXT NOT NULL DEFAULT 'http';
    ALTER TABLE tunnels ADD COLUMN public_port INTEGER;
    ALTER TABLE tunnels ADD COLUMN allow TEXT NOT NULL DEFAULT '';
    CREATE UNIQUE INDEX tunnels_public_port ON tunnels(kind, public_port) WHERE public_port IS NOT NULL;
    "#,
    // 2: users with passwords, UI sessions, API tokens and the audit log (docs/USERS.md). One
    // organization for now; every row names it so more can come without another rewrite.
    r#"
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
    "#,
    // 3: access tags, agent ownership and private tunnels (docs/USERS.md). Labels are a
    // separate column everywhere and never grant access. Every tag reference points at the
    // registry, so deleting a tag revokes it everywhere through the cascade.
    r#"
    CREATE TABLE tags (
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        name        TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
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
    ALTER TABLE agents ADD COLUMN org_id TEXT NOT NULL DEFAULT 'org_default';
    ALTER TABLE agents ADD COLUMN owner_user_id TEXT REFERENCES users(id);
    ALTER TABLE agents ADD COLUMN allow_public INTEGER NOT NULL DEFAULT 1;
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
    ALTER TABLE enrollments ADD COLUMN created_by TEXT;
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
    ALTER TABLE tunnels ADD COLUMN visibility TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'private'));
    ALTER TABLE tunnels ADD COLUMN labels TEXT NOT NULL DEFAULT '';
    CREATE TABLE tunnel_access (
        tunnel_id   TEXT NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
        org_id      TEXT NOT NULL,
        tag         TEXT NOT NULL,
        PRIMARY KEY (tunnel_id, tag),
        FOREIGN KEY (org_id, tag) REFERENCES tags(org_id, name) ON DELETE CASCADE
    );
    "#,
];

fn migrate(conn: &mut Connection) -> anyhow::Result<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(usize::try_from(version).unwrap_or(0)) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql).with_context(|| format!("database migration {}", i + 1))?;
        tx.pragma_update(None, "user_version", i as i64 + 1)?;
        tx.commit()?;
        tracing::info!(version = i + 1, "database migrated");
    }
    Ok(())
}

const TUNNEL_COLUMNS: &str = "id, name, hostname, agent_id, target, created_at, kind, public_port, allow, visibility, labels";

fn tunnel_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<TunnelRow> {
    let kind: String = r.get(6)?;
    let allow: String = r.get(8)?;
    let visibility: String = r.get(9)?;
    let labels: String = r.get(10)?;
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
        access: Vec::new(),
        labels: labels.split_whitespace().map(str::to_string).collect(),
    })
}

impl Store {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let mut conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;
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

    /// Creates a new admin token. With `replace_all`, every existing admin token is revoked.
    pub fn create_admin_token(&self, replace_all: bool) -> anyhow::Result<String> {
        let token = secret::new_token("mpadm");
        self.with(|c| {
            if replace_all {
                c.execute("DELETE FROM admin_tokens", [])?;
            }
            c.execute(
                "INSERT INTO admin_tokens (id, token_hash, created_at) VALUES (?1, ?2, ?3)",
                params![secret::new_id("adm"), secret::sha256_hex(&token), unix_now()],
            )
        })?;
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

    /// Creates a single-use enrollment token; the agent enrolled with it gets `spec`'s owner,
    /// tags, labels and visibility settings.
    pub fn create_enrollment(&self, ttl_secs: u64, spec: &EnrollmentSpec) -> anyhow::Result<String> {
        let token = secret::new_token("mpenr");
        let hash = secret::sha256_hex(&token);
        let now = unix_now();
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM enrollments WHERE expires_at < ?1 AND used_at IS NULL", [now])?;
        tx.execute(
            "INSERT INTO enrollments (token_hash, created_at, expires_at, created_by, owner_user_id, allow_public, default_private, labels)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                hash,
                now,
                now + ttl_secs as i64,
                spec.created_by,
                spec.owner_user_id,
                spec.allow_public as i64,
                spec.default_private as i64,
                spec.labels.join(" ")
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
        // The agent takes the token's owner, tags, labels and visibility settings.
        tx.execute(
            "INSERT INTO agents (id, name, token_hash, created_at, owner_user_id, allow_public, default_private, labels)
             SELECT ?1, ?2, ?3, ?4, owner_user_id, allow_public, default_private, labels FROM enrollments WHERE token_hash = ?5",
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
                "SELECT id, name, created_at, last_seen_at, owner_user_id, allow_public, default_private, labels FROM agents ORDER BY created_at",
            )?;
            st.query_map([], |r| {
                let labels: String = r.get(7)?;
                Ok(AgentRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    created_at: r.get(2)?,
                    last_seen_at: r.get(3)?,
                    owner_user_id: r.get(4)?,
                    allow_public: r.get::<_, i64>(5)? != 0,
                    default_private: r.get::<_, i64>(6)? != 0,
                    labels: labels.split_whitespace().map(str::to_string).collect(),
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
        let access: Vec<(String, String)> = self.with(|c| {
            let mut st = c.prepare("SELECT tunnel_id, tag FROM tunnel_access ORDER BY tag")?;
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
        })?;
        for (id, tag) in access {
            if let Some(t) = rows.iter_mut().find(|t| t.id == id) {
                t.access.push(tag);
            }
        }
        Ok(rows)
    }

    /// Replaces a tunnel's access rows (inside the caller's transaction).
    fn write_access(tx: &rusqlite::Transaction<'_>, t: &TunnelRow) -> rusqlite::Result<()> {
        tx.execute("DELETE FROM tunnel_access WHERE tunnel_id = ?1", [&t.id])?;
        for tag in &t.access {
            tx.execute("INSERT INTO tunnel_access (tunnel_id, org_id, tag) VALUES (?1, ?2, ?3)", params![t.id, users::DEFAULT_ORG, tag])?;
        }
        Ok(())
    }

    pub fn insert_tunnel(&self, t: &TunnelRow) -> anyhow::Result<()> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        tx.execute(
            &format!("INSERT INTO tunnels ({TUNNEL_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"),
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
                t.labels.join(" ")
            ],
        )?;
        Self::write_access(&tx, t)?;
        tx.commit()?;
        Ok(())
    }

    /// Saves the settings an agent may change on an existing tunnel.
    pub fn update_tunnel(&self, t: &TunnelRow) -> anyhow::Result<()> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE tunnels SET target = ?1, public_port = ?2, allow = ?3, visibility = ?4, labels = ?5 WHERE id = ?6",
            params![t.target, t.public_port, t.allow.join(" "), t.visibility.as_str(), t.labels.join(" "), t.id],
        )?;
        Self::write_access(&tx, t)?;
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
                    access: vec![],
                    labels: vec![],
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
    fn migrates_an_old_database_and_keeps_ports_unique() {
        let dir = std::env::temp_dir().join(format!("mp-store-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db.sqlite");
        {
            // A database written before migrations existed, with one HTTP tunnel.
            let c = Connection::open(&path).unwrap();
            c.execute_batch(SCHEMA).unwrap();
            c.execute_batch(
                "INSERT INTO agents (id, name, token_hash, created_at) VALUES ('ag_1', 'a', 'h', 0);
                 INSERT INTO tunnels (id, name, hostname, agent_id, target, created_at)
                 VALUES ('tn_old', 'old', 'old.t.test', 'ag_1', 'http://127.0.0.1:1', 0);",
            )
            .unwrap();
        }
        let store = Store::open(&path).unwrap();
        let old = &store.tunnels().unwrap()[0];
        assert_eq!((old.kind, old.public_port, old.allow.len()), (Kind::Http, None, 0));
        assert_eq!(old.visibility, Visibility::Public, "tunnels from before private tunnels stay public");
        let row = |id: &str, kind, port| TunnelRow {
            id: id.into(),
            name: id.into(),
            hostname: format!("{id}.t.test"),
            agent_id: "ag_1".into(),
            target: "tcp://127.0.0.1:5432".into(),
            created_at: 1,
            kind,
            public_port: Some(port),
            allow: vec!["10.0.0.0/8".into(), "192.0.2.1/32".into()],
            visibility: Visibility::Public,
            access: vec![],
            labels: vec![],
        };
        store.insert_tunnel(&row("tn_tcp", Kind::Tcp, 65500)).unwrap();
        store.insert_tunnel(&row("tn_udp", Kind::Udp, 65500)).unwrap();
        assert!(store.insert_tunnel(&row("tn_dup", Kind::Tcp, 65500)).is_err(), "a TCP port belongs to one tunnel");
        let tcp = store.tunnels().unwrap().into_iter().find(|t| t.id == "tn_tcp").unwrap();
        assert_eq!(tcp.allow, ["10.0.0.0/8", "192.0.2.1/32"]);
        // Migration 2 added accounts, starting empty.
        assert!(store.users().unwrap().is_empty());
        drop(store);
        // Opening again does not re-run migrations.
        assert_eq!(Store::open(&path).unwrap().tunnels().unwrap().len(), 3);
        std::fs::remove_dir_all(dir).ok();
    }
}
