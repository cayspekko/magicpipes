//! Tags and their assignments to users, agents and tunnels.
//!
//! Callers pass normalized tag names (`magicpipes_core::tags`). Assignments reference the
//! registry by foreign key, so an unregistered name can't be assigned and deleting a tag removes
//! every assignment. Personal tags (`user_id` set) are written only here: with their account
//! ([`Store::create_user`]), and never by [`Store::set_user_tags`].

use std::collections::HashMap;

use magicpipes_core::unix_now;
use rusqlite::params;

use super::Store;
use super::users::DEFAULT_ORG;

/// At most this many tags per organization (personal tags not counted), and per user, agent or
/// tunnel.
pub const MAX_TAGS: usize = 200;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TagRow {
    pub name: String,
    pub description: String,
    /// Users and tunnels sharing it may connect.
    pub access: bool,
    /// Set for a personal tag: the user it belongs to.
    pub user_id: Option<String>,
    pub created_at: i64,
}

/// What an enrollment token gives the agent enrolled with it.
#[derive(Debug, Clone)]
pub struct EnrollmentSpec {
    /// The user who created the token; `None` for the admin token or `magicpipesd enroll`.
    pub created_by: Option<String>,
    /// The agent's owner; `None` for a service agent.
    pub owner_user_id: Option<String>,
    /// Service agents only: a personal agent uses its owner's tags.
    pub tags: Vec<String>,
    pub allow_public: bool,
    pub default_private: bool,
}

impl Default for EnrollmentSpec {
    /// A service agent whose tunnels are public.
    fn default() -> Self {
        Self { created_by: None, owner_user_id: None, tags: Vec::new(), allow_public: true, default_private: false }
    }
}

impl Store {
    /// Every tag, personal ones included.
    pub fn tags(&self) -> anyhow::Result<Vec<TagRow>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT name, description, access, user_id, created_at FROM tags WHERE org_id = ?1 ORDER BY name")?;
            st.query_map([DEFAULT_ORG], |r| {
                Ok(TagRow { name: r.get(0)?, description: r.get(1)?, access: r.get::<_, i64>(2)? != 0, user_id: r.get(3)?, created_at: r.get(4)? })
            })?
            .collect()
        })
    }

    /// Registers a tag; `false` if it exists already or the registry is full.
    pub fn create_tag(&self, name: &str, description: &str, access: bool, created_by: Option<&str>) -> anyhow::Result<bool> {
        let n = self.with(|c| {
            let count: i64 = c.query_row("SELECT COUNT(*) FROM tags WHERE org_id = ?1 AND user_id IS NULL", [DEFAULT_ORG], |r| r.get(0))?;
            if count as usize >= MAX_TAGS {
                return Ok(0);
            }
            c.execute(
                "INSERT OR IGNORE INTO tags (org_id, name, description, access, created_by, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![DEFAULT_ORG, name, description, access as i64, created_by, unix_now()],
            )
        })?;
        Ok(n == 1)
    }

    /// Turns a tag's access on or off; `false` if there is no such tag, or it is personal.
    pub fn set_tag_access(&self, name: &str, access: bool) -> anyhow::Result<bool> {
        let n = self.with(|c| {
            c.execute(
                "UPDATE tags SET access = ?1 WHERE org_id = ?2 AND name = ?3 AND user_id IS NULL",
                params![access as i64, DEFAULT_ORG, name],
            )
        })?;
        Ok(n == 1)
    }

    /// Deletes a tag and, through the cascade, every assignment of it; `false` if there is no
    /// such tag, or it is personal (it goes with its account).
    pub fn delete_tag(&self, name: &str) -> anyhow::Result<bool> {
        let n = self.with(|c| c.execute("DELETE FROM tags WHERE org_id = ?1 AND name = ?2 AND user_id IS NULL", params![DEFAULT_ORG, name]))?;
        Ok(n == 1)
    }

    /// Every user's tags, their personal tag included.
    pub fn user_tags(&self) -> anyhow::Result<HashMap<String, Vec<String>>> {
        self.assignments("SELECT user_id, tag FROM user_tags WHERE org_id = ?1 ORDER BY tag")
    }

    /// Every service agent's tags.
    pub fn agent_tags(&self) -> anyhow::Result<HashMap<String, Vec<String>>> {
        self.assignments("SELECT agent_id, tag FROM agent_tags WHERE org_id = ?1 ORDER BY tag")
    }

    fn assignments(&self, sql: &str) -> anyhow::Result<HashMap<String, Vec<String>>> {
        let rows: Vec<(String, String)> = self.with(|c| {
            let mut st = c.prepare(sql)?;
            st.query_map([DEFAULT_ORG], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
        })?;
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for (id, tag) in rows {
            map.entry(id).or_default().push(tag);
        }
        Ok(map)
    }

    /// Replaces a user's assigned tags. Every tag must be registered; personal tags are neither
    /// removed nor added, whatever the list says.
    pub fn set_user_tags(&self, user_id: &str, tags: &[String], assigned_by: Option<&str>) -> anyhow::Result<()> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM user_tags WHERE org_id = ?1 AND user_id = ?2
             AND tag NOT IN (SELECT name FROM tags WHERE org_id = ?1 AND user_id IS NOT NULL)",
            params![DEFAULT_ORG, user_id],
        )?;
        for t in tags {
            tx.execute(
                "INSERT INTO user_tags (org_id, user_id, tag, assigned_by, created_at)
                 SELECT ?1, ?2, name, ?4, ?5 FROM tags WHERE org_id = ?1 AND name = ?3 AND user_id IS NULL",
                params![DEFAULT_ORG, user_id, t, assigned_by, unix_now()],
            )?;
            anyhow::ensure!(tx.changes() == 1, "'{t}' is not a tag that can be assigned");
        }
        tx.commit()?;
        Ok(())
    }

    /// Replaces a service agent's tags. Every tag must be registered and not personal.
    pub fn set_agent_tags(&self, agent_id: &str, tags: &[String]) -> anyhow::Result<()> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM agent_tags WHERE agent_id = ?1", [agent_id])?;
        for t in tags {
            tx.execute(
                "INSERT INTO agent_tags (agent_id, org_id, tag) SELECT ?1, ?2, name FROM tags WHERE org_id = ?2 AND name = ?3 AND user_id IS NULL",
                params![agent_id, DEFAULT_ORG, t],
            )?;
            anyhow::ensure!(tx.changes() == 1, "'{t}' is not a tag that can be assigned");
        }
        tx.commit()?;
        Ok(())
    }

    /// Whether any user account exists (new enrollments then default to private tunnels).
    pub fn has_users(&self) -> anyhow::Result<bool> {
        self.with(|c| c.query_row("SELECT EXISTS(SELECT 1 FROM users)", [], |r| r.get(0)))
    }
}

#[cfg(test)]
mod tests {
    use magicpipes_core::secret;

    use super::*;
    use crate::authz::Role;

    #[test]
    fn tags_follow_the_registry() {
        let dir = std::env::temp_dir().join(format!("mp-store-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let s = Store::open(&dir.join("db.sqlite")).unwrap();
        assert!(s.create_tag("team:dev", "Developers", true, None).unwrap());
        assert!(!s.create_tag("team:dev", "again", true, None).unwrap());
        s.create_tag("team:ops", "", false, None).unwrap();

        // Every account gets a personal tag, assigned to it, with access, kept by every replace.
        let user = s.create_user("ann@example.com", "", Role::Member, "h").unwrap().unwrap();
        let twin = s.create_user("ann@example.org", "", Role::Member, "h").unwrap().unwrap();
        let personal = |u: &str| s.tags().unwrap().into_iter().find(|t| t.user_id.as_deref() == Some(u)).unwrap();
        let (mine, theirs) = (personal(&user).name, personal(&twin).name);
        assert!(mine.starts_with("user:") && mine.len() == 15 && !mine.contains("ann"), "opaque: {mine}");
        assert!(personal(&user).access && mine != theirs);
        assert_eq!(magicpipes_core::tags::normalize(&mine).unwrap(), mine);
        assert_eq!(s.user_tags().unwrap()[&user], std::slice::from_ref(&mine));
        s.set_user_tags(&user, &["team:dev".into(), "team:ops".into()], None).unwrap();
        assert!(s.set_user_tags(&user, &["team:qa".into()], None).is_err(), "unregistered tags can't be assigned");
        assert!(s.set_user_tags(&user, std::slice::from_ref(&theirs), None).is_err(), "nor someone's personal tag");
        assert!(s.set_agent_tags("ag_x", std::slice::from_ref(&mine)).is_err());
        assert_eq!(s.user_tags().unwrap()[&user], ["team:dev".to_string(), "team:ops".into(), mine.clone()], "a failed replace changes nothing");
        s.set_user_tags(&user, &[], None).unwrap();
        assert_eq!(s.user_tags().unwrap()[&user], std::slice::from_ref(&mine), "the personal tag stays");
        assert!(!s.delete_tag(&mine).unwrap() && !s.set_tag_access(&mine, false).unwrap());
        assert!(s.set_tag_access("team:ops", true).unwrap());
        assert!(s.tags().unwrap().iter().find(|t| t.name == "team:ops").unwrap().access);

        // An enrollment's owner, tags and settings carry over to the agent.
        let spec = EnrollmentSpec { tags: vec!["team:dev".into()], ..Default::default() };
        let (service, _) = s.enroll(&s.create_enrollment(60, &spec).unwrap(), "ci").unwrap().unwrap();
        let row = s.agents().unwrap().into_iter().find(|a| a.id == service).unwrap();
        assert_eq!((row.owner_user_id, row.allow_public, row.default_private), (None, true, false));
        assert_eq!(s.agent_tags().unwrap()[&service], ["team:dev"]);
        let spec = EnrollmentSpec { created_by: Some(user.clone()), owner_user_id: Some(user.clone()), allow_public: false, default_private: true, ..Default::default() };
        let (laptop, _) = s.enroll(&s.create_enrollment(60, &spec).unwrap(), "laptop").unwrap().unwrap();
        let row = s.agents().unwrap().into_iter().find(|a| a.id == laptop).unwrap();
        assert_eq!((row.owner_user_id.as_deref(), row.allow_public, row.default_private), (Some(user.as_str()), false, true));

        // Deleting a tag removes it everywhere.
        assert!(s.delete_tag("team:dev").unwrap());
        assert!(!s.agent_tags().unwrap().contains_key(&service));
        std::fs::remove_dir_all(dir).ok();
    }
}
