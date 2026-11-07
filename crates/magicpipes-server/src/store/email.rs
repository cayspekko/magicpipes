//! Invitations and emailed links (migration 7). Only digests of their codes are stored, and a code
//! that has been used is gone: the audit log says what happened. Callers pass validated values
//! (`control::email`).

use magicpipes_core::unix_now;
use rusqlite::{OptionalExtension, Transaction, params};

use super::Store;
use super::users::{DEFAULT_ORG, LOCAL_ISSUER, MAX_USERS, insert_user};
use crate::authz::Role;
use crate::config::SmtpTls;

/// Invitations waiting at once; each one is a row and a line on the Users page.
pub const MAX_INVITATIONS: i64 = 1_000;
/// Links one account can have open: requests are limited, so this only ever trims old ones.
const MAX_TOKENS_PER_USER: i64 = 8;
/// How long an expired invitation stays listed, so an administrator can see it and send it again.
const EXPIRED_INVITATIONS_KEPT_SECS: i64 = 30 * 86_400;

/// What an emailed link does, which only that kind of link can be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkPurpose {
    SignIn,
    Confirm,
}

impl LinkPurpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::SignIn => "sign_in",
            Self::Confirm => "confirm",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationRow {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub role: Role,
    pub tags: Vec<String>,
    /// `us_…` or `admin-token`.
    pub created_by: String,
    pub created_at: i64,
    pub expires_at: i64,
}

pub struct NewInvitation<'a> {
    pub token_hash: &'a str,
    pub email: &'a str,
    pub display_name: &'a str,
    pub role: Role,
    pub tags: &'a [String],
    pub created_by: &'a str,
    pub ttl_secs: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Invited {
    Created(String),
    EmailTaken,
    TooMany,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Accepted {
    /// The new account's id. The invitation is gone.
    Account(String),
    /// Unknown, expired or already used.
    Gone,
    /// The address has an account by now. The invitation is gone.
    EmailTaken,
    /// That outside identity is someone else's. The invitation stays, for another way in.
    IdentityTaken,
    Full,
}

/// How someone accepting an invitation will sign in.
pub enum AcceptWith<'a> {
    /// A password hash.
    Password(&'a str),
    /// An outside identity: issuer and subject.
    Identity(&'a str, &'a str),
}

const INVITATION_COLUMNS: &str = "id, email, display_name, role, created_by, created_at, expires_at";

fn invitation_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<InvitationRow> {
    let role: String = r.get(3)?;
    Ok(InvitationRow {
        id: r.get(0)?,
        email: r.get(1)?,
        display_name: r.get(2)?,
        // A role that can't be read grants the least.
        role: Role::parse(&role).unwrap_or(Role::Member),
        tags: Vec::new(),
        created_by: r.get(4)?,
        created_at: r.get(5)?,
        expires_at: r.get(6)?,
    })
}

fn tags_of(c: &rusqlite::Connection, invitation: &str) -> rusqlite::Result<Vec<String>> {
    let mut st = c.prepare_cached("SELECT tag FROM invitation_tags WHERE invitation_id = ?1 ORDER BY tag")?;
    st.query_map([invitation], |r| r.get(0))?.collect()
}

fn email_taken(tx: &Transaction<'_>, email: &str) -> rusqlite::Result<bool> {
    tx.query_row("SELECT EXISTS(SELECT 1 FROM users WHERE email = ?1)", [email], |r| r.get(0))
}

impl Store {
    /// Replaces any invitation already out for that address, whose link stops working.
    pub fn create_invitation(&self, new: &NewInvitation<'_>) -> anyhow::Result<Invited> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        if email_taken(&tx, new.email)? {
            return Ok(Invited::EmailTaken);
        }
        tx.execute("DELETE FROM invitations WHERE email = ?1", [new.email])?;
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM invitations", [], |r| r.get(0))?;
        if count >= MAX_INVITATIONS {
            return Ok(Invited::TooMany);
        }
        let id = magicpipes_core::secret::new_id("inv");
        let now = unix_now();
        tx.execute(
            "INSERT INTO invitations (id, token_hash, org_id, email, display_name, role, created_by, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![id, new.token_hash, DEFAULT_ORG, new.email, new.display_name, new.role.as_str(), new.created_by, now, now + new.ttl_secs],
        )?;
        for tag in new.tags {
            tx.execute("INSERT OR IGNORE INTO invitation_tags (invitation_id, org_id, tag) VALUES (?1, ?2, ?3)", params![id, DEFAULT_ORG, tag])?;
        }
        tx.commit()?;
        Ok(Invited::Created(id))
    }

    /// Whether one more could be added for this address.
    pub fn invitation_fits(&self, email: &str) -> anyhow::Result<bool> {
        self.with(|c| c.query_row("SELECT (SELECT COUNT(*) FROM invitations) < ?1 OR EXISTS(SELECT 1 FROM invitations WHERE email = ?2)", params![MAX_INVITATIONS, email], |r| r.get(0)))
    }

    /// Everything out there, the newest first, whether or not it has expired.
    pub fn invitations(&self) -> anyhow::Result<Vec<InvitationRow>> {
        self.with(|c| {
            let mut st = c.prepare(&format!("SELECT {INVITATION_COLUMNS} FROM invitations ORDER BY created_at DESC, rowid DESC"))?;
            let rows: Vec<InvitationRow> = st.query_map([], invitation_row)?.collect::<rusqlite::Result<_>>()?;
            rows.into_iter().map(|row| Ok(InvitationRow { tags: tags_of(c, &row.id)?, ..row })).collect()
        })
    }

    pub fn invitation(&self, id: &str) -> anyhow::Result<Option<InvitationRow>> {
        self.with(|c| {
            let row = c.query_row(&format!("SELECT {INVITATION_COLUMNS} FROM invitations WHERE id = ?1"), [id], invitation_row).optional()?;
            row.map(|row| Ok(InvitationRow { tags: tags_of(c, &row.id)?, ..row })).transpose()
        })
    }

    /// The invitation a code opens, unless it has expired.
    pub fn invitation_by_token(&self, token_hash: &str) -> anyhow::Result<Option<InvitationRow>> {
        self.with(|c| {
            let row = c
                .query_row(&format!("SELECT {INVITATION_COLUMNS} FROM invitations WHERE token_hash = ?1 AND expires_at >= ?2"), params![token_hash, unix_now()], invitation_row)
                .optional()?;
            row.map(|row| Ok(InvitationRow { tags: tags_of(c, &row.id)?, ..row })).transpose()
        })
    }

    /// Gives an invitation a new code and a new expiry. The old code stops working.
    pub fn renew_invitation(&self, id: &str, token_hash: &str, ttl_secs: i64) -> anyhow::Result<bool> {
        let n = self.with(|c| c.execute("UPDATE invitations SET token_hash = ?2, expires_at = ?3 WHERE id = ?1", params![id, token_hash, unix_now() + ttl_secs]))?;
        Ok(n == 1)
    }

    pub fn delete_invitation(&self, id: &str) -> anyhow::Result<bool> {
        Ok(self.with(|c| c.execute("DELETE FROM invitations WHERE id = ?1", [id]))? == 1)
    }

    /// Turns an invitation into an account, once. The address counts as verified, because whoever
    /// has the code got it there.
    pub fn accept_invitation(&self, token_hash: &str, display_name: &str, with: AcceptWith<'_>) -> anyhow::Result<Accepted> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let now = unix_now();
        let found = tx
            .query_row(&format!("SELECT {INVITATION_COLUMNS} FROM invitations WHERE token_hash = ?1 AND expires_at >= ?2"), params![token_hash, now], invitation_row)
            .optional()?;
        let Some(invitation) = found else { return Ok(Accepted::Gone) };
        if email_taken(&tx, &invitation.email)? {
            tx.execute("DELETE FROM invitations WHERE id = ?1", [&invitation.id])?;
            tx.commit()?;
            return Ok(Accepted::EmailTaken);
        }
        let users: i64 = tx.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
        if users >= MAX_USERS {
            return Ok(Accepted::Full);
        }
        if let AcceptWith::Identity(issuer, subject) = with {
            let taken: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM identities WHERE issuer = ?1 AND subject = ?2)", params![issuer, subject], |r| r.get(0))?;
            if taken {
                return Ok(Accepted::IdentityTaken);
            }
        }
        let tags = tags_of(&tx, &invitation.id)?;
        let name = if display_name.is_empty() { invitation.display_name.as_str() } else { display_name };
        // This also ends the invitation, as any new account for an address does.
        let id = insert_user(&tx, &invitation.email, name, invitation.role)?;
        match with {
            AcceptWith::Password(hash) => {
                tx.execute("INSERT INTO identities (issuer, subject, user_id) VALUES (?1, ?2, ?3)", params![LOCAL_ISSUER, invitation.email, id])?;
                tx.execute("INSERT INTO passwords (user_id, hash, must_change, updated_at) VALUES (?1, ?2, 0, ?3)", params![id, hash, now])?;
            }
            AcceptWith::Identity(issuer, subject) => {
                tx.execute("INSERT INTO identities (issuer, subject, user_id) VALUES (?1, ?2, ?3)", params![issuer, subject, id])?;
            }
        }
        for tag in &tags {
            tx.execute("INSERT OR IGNORE INTO user_tags (org_id, user_id, tag, created_at) VALUES (?1, ?2, ?3, ?4)", params![DEFAULT_ORG, id, tag, now])?;
        }
        tx.execute("UPDATE users SET email_verified_at = ?1 WHERE id = ?2", params![now, id])?;
        tx.commit()?;
        Ok(Accepted::Account(id))
    }

    // ---- emailed links ----------------------------------------------------------------------

    pub fn create_email_token(&self, purpose: LinkPurpose, user_id: &str, token_hash: &str, ttl_secs: i64) -> anyhow::Result<()> {
        let now = unix_now();
        self.with(|c| {
            c.execute("INSERT INTO email_tokens (token_hash, purpose, user_id, expires_at) VALUES (?1, ?2, ?3, ?4)", params![token_hash, purpose.as_str(), user_id, now + ttl_secs])?;
            c.execute(
                "DELETE FROM email_tokens WHERE user_id = ?1 AND token_hash NOT IN (SELECT token_hash FROM email_tokens WHERE user_id = ?1 ORDER BY expires_at DESC, rowid DESC LIMIT ?2)",
                params![user_id, MAX_TOKENS_PER_USER],
            )
        })?;
        Ok(())
    }

    /// Whose link this is, without using it up.
    pub fn email_token_user(&self, token_hash: &str, purpose: LinkPurpose) -> anyhow::Result<Option<String>> {
        self.with(|c| {
            c.query_row("SELECT user_id FROM email_tokens WHERE token_hash = ?1 AND purpose = ?2 AND expires_at >= ?3", params![token_hash, purpose.as_str(), unix_now()], |r| r.get(0)).optional()
        })
    }

    /// Uses a link up, and says whose it was. Only one caller gets an answer for a link.
    pub fn take_email_token(&self, token_hash: &str, purpose: LinkPurpose) -> anyhow::Result<Option<String>> {
        self.with(|c| {
            c.query_row("DELETE FROM email_tokens WHERE token_hash = ?1 AND purpose = ?2 AND expires_at >= ?3 RETURNING user_id", params![token_hash, purpose.as_str(), unix_now()], |r| r.get(0))
                .optional()
        })
    }

    pub fn delete_email_token(&self, token_hash: &str) -> anyhow::Result<()> {
        self.with(|c| c.execute("DELETE FROM email_tokens WHERE token_hash = ?1", [token_hash]))?;
        Ok(())
    }

    pub fn mark_email_verified(&self, user_id: &str) -> anyhow::Result<()> {
        self.with(|c| c.execute("UPDATE users SET email_verified_at = COALESCE(email_verified_at, ?1) WHERE id = ?2", params![unix_now(), user_id]))?;
        Ok(())
    }

    /// Drops links that have expired, and invitations long past theirs.
    pub(super) fn prune_email(&self) -> anyhow::Result<()> {
        let now = unix_now();
        self.with(|c| {
            c.execute("DELETE FROM email_tokens WHERE expires_at < ?1", [now])?;
            c.execute("DELETE FROM invitations WHERE expires_at < ?1", [now - EXPIRED_INVITATIONS_KEPT_SECS])
        })?;
        Ok(())
    }

    // ---- the mail server on the Settings page -----------------------------------------------

    /// A row this version can't read leaves email off, with a line in the log.
    pub fn smtp_row(&self) -> anyhow::Result<Option<SmtpRow>> {
        let row = self.with(|c| {
            c.query_row("SELECT host, port, tls, username, from_address FROM smtp_settings WHERE org_id = ?1", [DEFAULT_ORG], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?, r.get::<_, Option<String>>(3)?, r.get::<_, String>(4)?))
            })
            .optional()
        })?;
        let Some((host, port, tls, username, from)) = row else { return Ok(None) };
        match (SmtpTls::parse(&tls), u16::try_from(port)) {
            (Some(tls), Ok(port)) => Ok(Some(SmtpRow { host, port, tls, username, from })),
            _ => {
                tracing::error!(tls, port, "the saved mail server settings can't be read, so email is off");
                Ok(None)
            }
        }
    }

    pub fn set_smtp_row(&self, row: &SmtpRow) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO smtp_settings (org_id, host, port, tls, username, from_address) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (org_id) DO UPDATE SET host = excluded.host, port = excluded.port, tls = excluded.tls, username = excluded.username, from_address = excluded.from_address",
                params![DEFAULT_ORG, row.host, row.port, row.tls.as_str(), row.username, row.from],
            )
        })?;
        Ok(())
    }

    pub fn delete_smtp_row(&self) -> anyhow::Result<bool> {
        Ok(self.with(|c| c.execute("DELETE FROM smtp_settings WHERE org_id = ?1", [DEFAULT_ORG]))? == 1)
    }
}

/// The mail server, as saved on the Settings page. Its password is a file in `data_dir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpRow {
    pub host: String,
    pub port: u16,
    pub tls: SmtpTls,
    pub username: Option<String>,
    pub from: String,
}

#[cfg(test)]
mod tests {
    use magicpipes_core::secret;
    use rusqlite::Connection;

    use super::super::MIGRATIONS;
    use super::*;

    fn store() -> (Store, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("mp-email-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        (Store::open(&dir.join("db.sqlite")).unwrap(), dir)
    }

    fn invite<'a>(hash: &'a str, email: &'a str, tags: &'a [String], by: &'a str) -> NewInvitation<'a> {
        NewInvitation { token_hash: hash, email, display_name: "Named", role: Role::Member, tags, created_by: by, ttl_secs: 60 }
    }

    fn created(i: Invited) -> String {
        match i {
            Invited::Created(id) => id,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_database_from_before_email_gains_the_tables_and_keeps_its_accounts() {
        let dir = std::env::temp_dir().join(format!("mp-email-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db.sqlite");
        {
            let c = Connection::open(&path).unwrap();
            for m in &MIGRATIONS[..6] {
                c.execute_batch(m).unwrap();
            }
            c.pragma_update(None, "user_version", 6).unwrap();
            c.execute("INSERT INTO users (id, email, created_at) VALUES ('us_old', 'old@example.com', 1)", []).unwrap();
            c.execute("INSERT INTO memberships (org_id, user_id, role, created_at) VALUES ('org_default', 'us_old', 'member', 1)", []).unwrap();
        }
        let s = Store::open(&path).unwrap();
        let old = s.user("us_old").unwrap().unwrap();
        assert!(!old.email_verified, "an address nobody proved isn't verified by a migration");
        assert!(s.invitations().unwrap().is_empty() && s.smtp_row().unwrap().is_none());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn an_invitation_makes_one_account_with_what_it_promised() {
        let (s, dir) = store();
        assert!(s.create_tag("team:dev", "", true, None).unwrap());
        let tags = vec!["team:dev".to_string()];
        let id = created(s.create_invitation(&invite("h1", "ann@example.com", &tags, "admin-token")).unwrap());
        let row = s.invitation_by_token("h1").unwrap().unwrap();
        assert_eq!((row.id.as_str(), row.email.as_str(), row.role, row.tags.as_slice()), (id.as_str(), "ann@example.com", Role::Member, tags.as_slice()));
        assert!(s.invitation_by_token("nope").unwrap().is_none());

        // Another invitation for that address replaces it.
        let id = created(s.create_invitation(&invite("h2", "ann@example.com", &tags, "admin-token")).unwrap());
        assert!(s.invitation_by_token("h1").unwrap().is_none());
        assert_eq!(s.invitations().unwrap().len(), 1);
        // A new code ends the old one.
        assert!(s.renew_invitation(&id, "h3", 60).unwrap());
        assert!(s.invitation_by_token("h2").unwrap().is_none());

        let Accepted::Account(user) = s.accept_invitation("h3", "Ann", AcceptWith::Password("hash")).unwrap() else { panic!() };
        let u = s.user(&user).unwrap().unwrap();
        assert_eq!((u.email.as_str(), u.display_name.as_str(), u.role, u.email_verified, u.must_change_password, u.has_password), ("ann@example.com", "Ann", Role::Member, true, false, true));
        assert_eq!(s.password_login("ann@example.com").unwrap().unwrap().1, "hash");
        assert!(s.user_tags().unwrap()[&user].contains(&"team:dev".to_string()));

        // Once.
        assert_eq!(s.accept_invitation("h3", "Ann", AcceptWith::Password("other")).unwrap(), Accepted::Gone);
        assert!(s.invitations().unwrap().is_empty());
        assert_eq!(s.create_invitation(&invite("h4", "ann@example.com", &[], "admin-token")).unwrap(), Invited::EmailTaken);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn an_expired_invitation_opens_nothing_but_stays_listed_for_a_while() {
        let (s, dir) = store();
        let id = created(s.create_invitation(&NewInvitation { ttl_secs: -1, ..invite("h", "ann@example.com", &[], "admin-token") }).unwrap());
        assert!(s.invitation_by_token("h").unwrap().is_none());
        assert_eq!(s.accept_invitation("h", "", AcceptWith::Password("x")).unwrap(), Accepted::Gone);
        s.prune_email().unwrap();
        assert_eq!(s.invitation(&id).unwrap().unwrap().email, "ann@example.com");
        let long_ago = created(s.create_invitation(&NewInvitation { ttl_secs: -EXPIRED_INVITATIONS_KEPT_SECS - 1, ..invite("g", "bob@example.com", &[], "admin-token") }).unwrap());
        s.prune_email().unwrap();
        assert!(s.invitation(&long_ago).unwrap().is_none());
        assert!(s.invitation(&id).unwrap().is_some());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn an_outside_identity_can_accept_but_only_one_nobody_uses() {
        let (s, dir) = store();
        let iss = "https://idp.example.com";
        s.create_sso_user("other@example.com", "", Role::Member, iss, "taken").unwrap().unwrap();
        created(s.create_invitation(&invite("h", "ann@example.com", &[], "admin-token")).unwrap());
        assert_eq!(s.accept_invitation("h", "", AcceptWith::Identity(iss, "taken")).unwrap(), Accepted::IdentityTaken);
        assert!(s.invitation_by_token("h").unwrap().is_some(), "another way in still works");
        let Accepted::Account(id) = s.accept_invitation("h", "", AcceptWith::Identity(iss, "new")).unwrap() else { panic!() };
        let u = s.identity_user(iss, "new").unwrap().unwrap();
        assert_eq!((u.id.as_str(), u.email.as_str(), u.display_name.as_str(), u.has_password, u.email_verified), (id.as_str(), "ann@example.com", "Named", false, true));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn any_new_account_for_an_address_ends_its_invitation() {
        let (s, dir) = store();
        created(s.create_invitation(&invite("h", "ann@example.com", &[], "admin-token")).unwrap());
        s.create_user("ann@example.com", "", Role::Member, "hash").unwrap().unwrap();
        assert!(s.invitations().unwrap().is_empty());
        assert_eq!(s.accept_invitation("h", "", AcceptWith::Password("x")).unwrap(), Accepted::Gone);
        created(s.create_invitation(&invite("g", "bob@example.com", &[], "admin-token")).unwrap());
        s.create_sso_user("bob@example.com", "", Role::Member, "https://i.example.com", "1").unwrap().unwrap();
        assert!(s.invitations().unwrap().is_empty());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn invitations_end_with_the_powers_of_whoever_sent_them() {
        let (s, dir) = store();
        let admin = s.create_user("boss@example.com", "", Role::Admin, "hash").unwrap().unwrap();
        created(s.create_invitation(&invite("a", "a@example.com", &[], &admin)).unwrap());
        created(s.create_invitation(&invite("b", "b@example.com", &[], "admin-token")).unwrap());
        assert!(s.set_role(&admin, Role::Admin).unwrap());
        assert_eq!(s.invitations().unwrap().len(), 2, "still an administrator");
        assert!(s.set_role(&admin, Role::Member).unwrap());
        assert!(s.invitation_by_token("a").unwrap().is_none() && s.invitation_by_token("b").unwrap().is_some());

        assert!(s.set_role(&admin, Role::Admin).unwrap());
        created(s.create_invitation(&invite("c", "c@example.com", &[], &admin)).unwrap());
        assert!(s.set_disabled(&admin, true).unwrap());
        assert!(s.invitation_by_token("c").unwrap().is_none() && s.invitation_by_token("b").unwrap().is_some());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_deleted_tag_leaves_the_invitations_that_named_it() {
        let (s, dir) = store();
        assert!(s.create_tag("team:dev", "", true, None).unwrap());
        let id = created(s.create_invitation(&invite("h", "ann@example.com", &["team:dev".to_string()], "admin-token")).unwrap());
        assert!(s.delete_tag("team:dev").unwrap());
        assert!(s.invitation(&id).unwrap().unwrap().tags.is_empty());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn invitations_are_bounded() {
        let (s, dir) = store();
        s.with(|c| {
            for i in 0..MAX_INVITATIONS {
                c.execute(
                    "INSERT INTO invitations (id, token_hash, email, role, created_by, created_at, expires_at) VALUES (?1, ?1, ?2, 'member', 'admin-token', 1, 2)",
                    params![format!("i{i}"), format!("{i}@example.com")],
                )?;
            }
            Ok(())
        })
        .unwrap();
        assert!(!s.invitation_fits("new@example.com").unwrap());
        assert_eq!(s.create_invitation(&invite("h", "new@example.com", &[], "admin-token")).unwrap(), Invited::TooMany);
        assert!(s.invitation_fits("7@example.com").unwrap(), "replacing one adds none");
        created(s.create_invitation(&invite("h", "7@example.com", &[], "admin-token")).unwrap());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_link_works_once_for_its_purpose_while_it_lasts() {
        let (s, dir) = store();
        let ann = s.create_user("ann@example.com", "", Role::Member, "hash").unwrap().unwrap();
        s.create_email_token(LinkPurpose::SignIn, &ann, "h", 60).unwrap();
        assert_eq!(s.email_token_user("h", LinkPurpose::SignIn).unwrap().as_deref(), Some(ann.as_str()));
        assert_eq!(s.email_token_user("h", LinkPurpose::Confirm).unwrap(), None, "it's for signing in");
        assert_eq!(s.take_email_token("h", LinkPurpose::Confirm).unwrap(), None);
        assert_eq!(s.email_token_user("h", LinkPurpose::SignIn).unwrap().as_deref(), Some(ann.as_str()), "looking doesn't use it up");
        assert_eq!(s.take_email_token("h", LinkPurpose::SignIn).unwrap().as_deref(), Some(ann.as_str()));
        assert_eq!(s.take_email_token("h", LinkPurpose::SignIn).unwrap(), None);

        s.create_email_token(LinkPurpose::SignIn, &ann, "old", -1).unwrap();
        assert_eq!(s.take_email_token("old", LinkPurpose::SignIn).unwrap(), None, "expired");

        // Ending someone's sessions ends their links, which are sessions waiting to happen.
        s.create_email_token(LinkPurpose::SignIn, &ann, "open", 60).unwrap();
        s.end_sessions(&ann).unwrap();
        assert_eq!(s.email_token_user("open", LinkPurpose::SignIn).unwrap(), None);

        // Bounded per account, keeping the newest.
        for i in 0..MAX_TOKENS_PER_USER + 3 {
            s.create_email_token(LinkPurpose::SignIn, &ann, &format!("t{i}"), 60 + i).unwrap();
        }
        let held: i64 = s.with(|c| c.query_row("SELECT COUNT(*) FROM email_tokens WHERE user_id = ?1", [&ann], |r| r.get(0))).unwrap();
        assert_eq!(held, MAX_TOKENS_PER_USER);
        assert!(s.email_token_user(&format!("t{}", MAX_TOKENS_PER_USER + 2), LinkPurpose::SignIn).unwrap().is_some());
        assert!(s.email_token_user("t0", LinkPurpose::SignIn).unwrap().is_none());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn saved_mail_settings_read_back_and_an_unknown_kind_of_tls_means_off() {
        let (s, dir) = store();
        let row = SmtpRow { host: "m.example.com".into(), port: 587, tls: SmtpTls::Starttls, username: Some("u".into()), from: "a@example.com".into() };
        s.set_smtp_row(&row).unwrap();
        assert_eq!(s.smtp_row().unwrap().as_ref(), Some(&row));
        let changed = SmtpRow { tls: SmtpTls::Implicit, username: None, port: 465, ..row };
        s.set_smtp_row(&changed).unwrap();
        assert_eq!(s.smtp_row().unwrap().as_ref(), Some(&changed));
        s.with(|c| c.execute("UPDATE smtp_settings SET tls = 'from-the-future'", [])).unwrap();
        assert_eq!(s.smtp_row().unwrap(), None);
        assert!(s.delete_smtp_row().unwrap() && !s.delete_smtp_row().unwrap());
        std::fs::remove_dir_all(dir).ok();
    }
}
