//! Sign-in settings made on the Settings page (migration 4). Callers pass validated values
//! (`control::settings`).

use magicpipes_core::unix_now;
use rusqlite::params;

use super::Store;
use super::users::{DEFAULT_ORG, LOCAL_ISSUER};
use crate::config::ProviderKind;

/// Each is a button on the sign-in page.
pub const MAX_OIDC_PROVIDERS: usize = 32;
/// Per kind of rule.
pub const MAX_SIGN_IN_RULES: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcProviderRow {
    pub id: String,
    pub kind: ProviderKind,
    pub label: String,
    pub issuer: String,
    pub client_id: String,
    pub link_by_email: bool,
    pub trust_email: bool,
    pub allow_unverified_admin: bool,
    /// Empty: the default.
    pub scopes: Vec<String>,
    pub auto_redirect: bool,
    pub sign_out: bool,
}

/// Who a first sign-in may create an account for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignInRules {
    pub bootstrap_admins: Vec<String>,
    pub email_domains: Vec<String>,
}

impl Store {
    /// A provider of a kind this version doesn't know is left out, with a line in the log: signing
    /// someone in with the wrong protocol is worse than a button that's missing.
    pub fn oidc_provider_rows(&self) -> anyhow::Result<Vec<OidcProviderRow>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT id, label, issuer, client_id, link_by_email, trust_email, allow_unverified_admin, kind, scopes, auto_redirect, sign_out
                 FROM oidc_providers WHERE org_id = ?1 ORDER BY created_at, id",
            )?;
            let rows = st.query_map([DEFAULT_ORG], |r| {
                let kind: String = r.get(7)?;
                let scopes: String = r.get(8)?;
                Ok((
                    kind,
                    OidcProviderRow {
                        id: r.get(0)?,
                        kind: ProviderKind::Oidc,
                        label: r.get(1)?,
                        issuer: r.get(2)?,
                        client_id: r.get(3)?,
                        link_by_email: r.get(4)?,
                        trust_email: r.get(5)?,
                        allow_unverified_admin: r.get(6)?,
                        scopes: scopes.split_whitespace().map(str::to_string).collect(),
                        auto_redirect: r.get(9)?,
                        sign_out: r.get(10)?,
                    },
                ))
            })?;
            let mut known = Vec::new();
            for row in rows {
                let (kind, row) = row?;
                match ProviderKind::parse(&kind) {
                    Some(kind) => known.push(OidcProviderRow { kind, ..row }),
                    None => tracing::error!(provider = %row.id, kind, "this sign-in provider is of an unknown kind, so it's off"),
                }
            }
            Ok(known)
        })
    }

    /// `false` if the id or issuer is taken, or there are [`MAX_OIDC_PROVIDERS`]. A provider the
    /// sign-in page goes straight to takes that from any other.
    pub fn create_oidc_provider(&self, p: &OidcProviderRow) -> anyhow::Result<bool> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM oidc_providers WHERE org_id = ?1", [DEFAULT_ORG], |r| r.get(0))?;
        if count as usize >= MAX_OIDC_PROVIDERS {
            return Ok(false);
        }
        if p.auto_redirect {
            tx.execute("UPDATE oidc_providers SET auto_redirect = 0 WHERE org_id = ?1", [DEFAULT_ORG])?;
        }
        let n = tx.execute(
            "INSERT INTO oidc_providers (id, org_id, label, issuer, client_id, link_by_email, trust_email, allow_unverified_admin, created_at, kind, scopes, auto_redirect, sign_out)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT DO NOTHING",
            params![
                p.id,
                DEFAULT_ORG,
                p.label,
                p.issuer,
                p.client_id,
                p.link_by_email,
                p.trust_email,
                p.allow_unverified_admin,
                unix_now(),
                p.kind.as_str(),
                p.scopes.join(" "),
                p.auto_redirect,
                p.sign_out
            ],
        )?;
        tx.commit()?;
        Ok(n == 1)
    }

    /// Changes what can change about a provider: its id and issuer stay. One the sign-in page goes
    /// straight to now takes that from any other.
    pub fn update_oidc_provider(&self, p: &OidcProviderRow) -> anyhow::Result<bool> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        if p.auto_redirect {
            tx.execute("UPDATE oidc_providers SET auto_redirect = 0 WHERE org_id = ?1 AND id != ?2", params![DEFAULT_ORG, p.id])?;
        }
        let n = tx.execute(
            "UPDATE oidc_providers SET label = ?2, client_id = ?3, link_by_email = ?4, trust_email = ?5, allow_unverified_admin = ?6, scopes = ?8, auto_redirect = ?9, sign_out = ?10
             WHERE org_id = ?7 AND id = ?1",
            params![p.id, p.label, p.client_id, p.link_by_email, p.trust_email, p.allow_unverified_admin, DEFAULT_ORG, p.scopes.join(" "), p.auto_redirect, p.sign_out],
        )?;
        tx.commit()?;
        Ok(n == 1)
    }

    pub fn delete_oidc_provider(&self, id: &str) -> anyhow::Result<bool> {
        Ok(self.with(|c| c.execute("DELETE FROM oidc_providers WHERE org_id = ?1 AND id = ?2", params![DEFAULT_ORG, id]))? == 1)
    }

    /// People who could sign in only through this issuer: no password, no other provider.
    pub fn users_only_through(&self, issuer: &str) -> anyhow::Result<i64> {
        self.with(|c| {
            c.query_row(
                "SELECT COUNT(DISTINCT i.user_id) FROM identities i JOIN users u ON u.id = i.user_id
                 WHERE i.issuer = ?1 AND u.disabled_at IS NULL
                   AND NOT EXISTS (SELECT 1 FROM passwords p WHERE p.user_id = i.user_id)
                   AND NOT EXISTS (SELECT 1 FROM identities o WHERE o.user_id = i.user_id AND o.issuer NOT IN (?1, ?2))",
                params![issuer, LOCAL_ISSUER],
                |r| r.get(0),
            )
        })
    }

    pub fn sign_in_rules(&self) -> anyhow::Result<SignInRules> {
        self.with(|c| {
            let mut st = c.prepare("SELECT kind, value FROM sign_in_rules WHERE org_id = ?1 ORDER BY kind, value")?;
            let mut rules = SignInRules::default();
            for row in st.query_map([DEFAULT_ORG], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
                let (kind, value) = row?;
                match kind.as_str() {
                    "bootstrap_admin" => rules.bootstrap_admins.push(value),
                    _ => rules.email_domains.push(value),
                }
            }
            Ok(rules)
        })
    }

    /// Replaces the rules, in one transaction.
    pub fn set_sign_in_rules(&self, rules: &SignInRules) -> anyhow::Result<()> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM sign_in_rules WHERE org_id = ?1", [DEFAULT_ORG])?;
        for (kind, values) in [("bootstrap_admin", &rules.bootstrap_admins), ("email_domain", &rules.email_domains)] {
            for value in values {
                tx.execute("INSERT OR IGNORE INTO sign_in_rules (org_id, kind, value) VALUES (?1, ?2, ?3)", params![DEFAULT_ORG, kind, value])?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use magicpipes_core::secret;
    use rusqlite::Connection;

    use super::super::MIGRATIONS;
    use super::*;
    use crate::authz::Role;

    fn provider(id: &str, issuer: &str) -> OidcProviderRow {
        OidcProviderRow {
            id: id.into(),
            kind: ProviderKind::Oidc,
            label: "L".into(),
            issuer: issuer.into(),
            client_id: "c".into(),
            link_by_email: false,
            trust_email: true,
            allow_unverified_admin: false,
            scopes: Vec::new(),
            auto_redirect: false,
            sign_out: false,
        }
    }

    #[test]
    fn providers_and_rules() {
        let dir = std::env::temp_dir().join(format!("mp-store-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db.sqlite");
        // A database from before the Settings page gains the tables, and keeps what it has.
        {
            let c = Connection::open(&path).unwrap();
            for m in &MIGRATIONS[..3] {
                c.execute_batch(m).unwrap();
            }
            c.pragma_update(None, "user_version", 3).unwrap();
        }
        let s = Store::open(&path).unwrap();
        assert!(s.oidc_provider_rows().unwrap().is_empty());

        let a = provider("a", "https://a.example.com");
        assert!(s.create_oidc_provider(&a).unwrap());
        assert!(!s.create_oidc_provider(&provider("a", "https://other.example.com")).unwrap(), "the id is taken");
        assert!(!s.create_oidc_provider(&provider("b", "https://a.example.com")).unwrap(), "the issuer is taken");
        assert_eq!(s.oidc_provider_rows().unwrap(), [a]);

        let changed = OidcProviderRow { label: "New".into(), client_id: "c2".into(), link_by_email: true, trust_email: false, ..provider("a", "https://ignored.example.com") };
        assert!(s.update_oidc_provider(&changed).unwrap());
        assert!(!s.update_oidc_provider(&OidcProviderRow { id: "gone".into(), ..changed }).unwrap());
        let row = s.oidc_provider_rows().unwrap().remove(0);
        assert_eq!((row.label.as_str(), row.client_id.as_str(), row.link_by_email, row.trust_email), ("New", "c2", true, false));
        assert_eq!(row.issuer, "https://a.example.com", "the issuer stays");

        // Scopes and sign-out are kept; going straight to a provider moves from one to the next.
        let first = OidcProviderRow { scopes: vec!["openid".into(), "groups".into()], auto_redirect: true, sign_out: true, ..row.clone() };
        assert!(s.update_oidc_provider(&first).unwrap());
        assert!(s.create_oidc_provider(&OidcProviderRow { auto_redirect: true, ..provider("straight", "https://straight.example.com") }).unwrap());
        let rows = s.oidc_provider_rows().unwrap();
        assert_eq!((rows[0].scopes.clone(), rows[0].auto_redirect, rows[0].sign_out), (vec!["openid".to_string(), "groups".to_string()], false, true));
        assert!(rows[1].auto_redirect, "the newest one");
        assert!(s.update_oidc_provider(&first).unwrap());
        assert_eq!(s.oidc_provider_rows().unwrap().iter().filter(|r| r.auto_redirect).map(|r| r.id.as_str()).collect::<Vec<_>>(), ["a"]);
        assert!(s.delete_oidc_provider("straight").unwrap());

        for i in s.oidc_provider_rows().unwrap().len()..MAX_OIDC_PROVIDERS {
            assert!(s.create_oidc_provider(&provider(&format!("p{i}"), &format!("https://{i}.example.com"))).unwrap());
        }
        assert!(!s.create_oidc_provider(&provider("more", "https://more.example.com")).unwrap(), "bounded");
        assert!(s.delete_oidc_provider("a").unwrap() && !s.delete_oidc_provider("a").unwrap());

        let rules = SignInRules { bootstrap_admins: vec!["ann@example.com".into()], email_domains: vec!["example.com".into()] };
        s.set_sign_in_rules(&rules).unwrap();
        assert_eq!(s.sign_in_rules().unwrap(), rules);
        s.set_sign_in_rules(&SignInRules::default()).unwrap();
        assert_eq!(s.sign_in_rules().unwrap(), SignInRules::default());
        std::fs::remove_dir_all(dir).ok();
    }

    /// A database from before `allow_unverified_admin` keeps its providers, none of them allowed.
    #[test]
    fn existing_providers_do_not_gain_new_powers() {
        let dir = std::env::temp_dir().join(format!("mp-store-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db.sqlite");
        {
            let c = Connection::open(&path).unwrap();
            for m in &MIGRATIONS[..4] {
                c.execute_batch(m).unwrap();
            }
            c.pragma_update(None, "user_version", 4).unwrap();
            c.execute("INSERT INTO oidc_providers (id, label, issuer, client_id, trust_email, created_at) VALUES ('a', 'A', 'https://a.example.com', 'c', 1, 1)", []).unwrap();
        }
        let row = Store::open(&path).unwrap().oidc_provider_rows().unwrap().remove(0);
        assert!(row.trust_email && !row.allow_unverified_admin);
        std::fs::remove_dir_all(dir).ok();
    }

    /// A database from before providers had a kind keeps them as what they were, and a kind this
    /// version doesn't know turns that provider off, not the others.
    #[test]
    fn a_providers_kind_is_kept_and_an_unknown_one_is_off() {
        let dir = std::env::temp_dir().join(format!("mp-store-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db.sqlite");
        {
            let c = Connection::open(&path).unwrap();
            for m in &MIGRATIONS[..5] {
                c.execute_batch(m).unwrap();
            }
            c.pragma_update(None, "user_version", 5).unwrap();
            c.execute("INSERT INTO oidc_providers (id, label, issuer, client_id, created_at) VALUES ('a', 'A', 'https://a.example.com', 'c', 1)", []).unwrap();
        }
        let s = Store::open(&path).unwrap();
        assert_eq!(s.oidc_provider_rows().unwrap()[0].kind, ProviderKind::Oidc);

        let github = OidcProviderRow { kind: ProviderKind::Github, ..provider("gh", "https://github.com") };
        assert!(s.create_oidc_provider(&github).unwrap());
        assert_eq!(s.oidc_provider_rows().unwrap().iter().map(|r| r.kind).collect::<Vec<_>>(), [ProviderKind::Oidc, ProviderKind::Github]);
        assert!(s.update_oidc_provider(&OidcProviderRow { label: "New".into(), ..github }).unwrap());
        assert_eq!(s.oidc_provider_rows().unwrap()[1].kind, ProviderKind::Github, "changing a provider keeps its kind");

        s.with(|c| c.execute("UPDATE oidc_providers SET kind = 'from-the-future' WHERE id = 'gh'", [])).unwrap();
        assert_eq!(s.oidc_provider_rows().unwrap().iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["a"]);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn who_depends_on_a_provider() {
        let dir = std::env::temp_dir().join(format!("mp-store-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let s = Store::open(&dir.join("db.sqlite")).unwrap();
        let iss = "https://a.example.com";
        let only = s.create_sso_user("only@example.com", "", Role::Member, iss, "1").unwrap().unwrap();
        assert_eq!(s.users_only_through(iss).unwrap(), 1);
        // A password is another way in.
        s.set_password(&only, "hash", false).unwrap();
        assert_eq!(s.users_only_through(iss).unwrap(), 0);
        // So is another provider.
        let two = s.create_sso_user("two@example.com", "", Role::Member, iss, "2").unwrap().unwrap();
        assert_eq!(s.users_only_through(iss).unwrap(), 1);
        assert!(s.link_identity(&two, "https://b.example.com", "9").unwrap());
        assert_eq!(s.users_only_through(iss).unwrap(), 0);
        std::fs::remove_dir_all(dir).ok();
    }
}
