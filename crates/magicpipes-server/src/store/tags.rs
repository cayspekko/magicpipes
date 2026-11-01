//! Access tags and their assignments to users and agents (migration 3).
//!
//! Callers pass normalized tag names (`magicpipes_core::tags`). Assignments reference the
//! registry by foreign key, so an unregistered name can't be assigned and deleting a tag removes
//! every assignment.

use std::collections::HashMap;

use magicpipes_core::unix_now;
use rusqlite::params;

use super::Store;
use super::users::DEFAULT_ORG;

/// At most this many access tags per organization, and per user or agent.
pub const MAX_TAGS: usize = 200;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TagRow {
    pub name: String,
    pub description: String,
    pub created_at: i64,
}

/// What an enrollment token gives the agent enrolled with it.
#[derive(Debug, Clone)]
pub struct EnrollmentSpec {
    /// The user who created the token; `None` for the admin token or `magicpipesd enroll`.
    pub created_by: Option<String>,
    /// The agent's owner; `None` for a service agent.
    pub owner_user_id: Option<String>,
    pub tags: Vec<String>,
    pub labels: Vec<String>,
    pub allow_public: bool,
    pub default_private: bool,
}

impl Default for EnrollmentSpec {
    /// Today's behavior: a service agent whose tunnels are public.
    fn default() -> Self {
        Self { created_by: None, owner_user_id: None, tags: Vec::new(), labels: Vec::new(), allow_public: true, default_private: false }
    }
}

impl Store {
    pub fn tags(&self) -> anyhow::Result<Vec<TagRow>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT name, description, created_at FROM tags WHERE org_id = ?1 ORDER BY name")?;
            st.query_map([DEFAULT_ORG], |r| Ok(TagRow { name: r.get(0)?, description: r.get(1)?, created_at: r.get(2)? }))?.collect()
        })
    }

    /// Registers an access tag; `false` if it exists already or the registry is full.
    pub fn create_tag(&self, name: &str, description: &str, created_by: Option<&str>) -> anyhow::Result<bool> {
        let n = self.with(|c| {
            let count: i64 = c.query_row("SELECT COUNT(*) FROM tags WHERE org_id = ?1", [DEFAULT_ORG], |r| r.get(0))?;
            if count as usize >= MAX_TAGS {
                return Ok(0);
            }
            c.execute(
                "INSERT OR IGNORE INTO tags (org_id, name, description, created_by, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![DEFAULT_ORG, name, description, created_by, unix_now()],
            )
        })?;
        Ok(n == 1)
    }

    /// Deletes a tag and, through the cascade, every assignment of it.
    pub fn delete_tag(&self, name: &str) -> anyhow::Result<bool> {
        let n = self.with(|c| c.execute("DELETE FROM tags WHERE org_id = ?1 AND name = ?2", params![DEFAULT_ORG, name]))?;
        Ok(n == 1)
    }

    /// The names in `tags` that are not registered.
    pub fn unknown_tags(&self, tags: &[String]) -> anyhow::Result<Vec<String>> {
        let known: Vec<String> = self.tags()?.into_iter().map(|t| t.name).collect();
        Ok(tags.iter().filter(|t| !known.contains(t)).cloned().collect())
    }

    /// Every user's admin-assigned tags.
    pub fn user_tags(&self) -> anyhow::Result<HashMap<String, Vec<String>>> {
        self.assignments("SELECT user_id, tag FROM user_tags WHERE org_id = ?1 ORDER BY tag")
    }

    /// Every agent's assigned tags (before limiting them to the owner's).
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

    /// Replaces a user's admin-assigned tags. Every tag must be registered.
    pub fn set_user_tags(&self, user_id: &str, tags: &[String], assigned_by: Option<&str>) -> anyhow::Result<()> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM user_tags WHERE org_id = ?1 AND user_id = ?2", params![DEFAULT_ORG, user_id])?;
        for t in tags {
            tx.execute(
                "INSERT INTO user_tags (org_id, user_id, tag, assigned_by, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![DEFAULT_ORG, user_id, t, assigned_by, unix_now()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Replaces an agent's tags. Every tag must be registered.
    pub fn set_agent_tags(&self, agent_id: &str, tags: &[String]) -> anyhow::Result<()> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM agent_tags WHERE agent_id = ?1", [agent_id])?;
        for t in tags {
            tx.execute("INSERT INTO agent_tags (agent_id, org_id, tag) VALUES (?1, ?2, ?3)", params![agent_id, DEFAULT_ORG, t])?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn set_agent_labels(&self, agent_id: &str, labels: &[String]) -> anyhow::Result<()> {
        self.with(|c| c.execute("UPDATE agents SET labels = ?1 WHERE id = ?2", params![labels.join(" "), agent_id]))?;
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
        assert!(s.create_tag("team:dev", "Developers", None).unwrap());
        assert!(!s.create_tag("team:dev", "again", None).unwrap());
        s.create_tag("team:ops", "", None).unwrap();
        assert_eq!(s.unknown_tags(&["team:dev".into(), "team:qa".into()]).unwrap(), ["team:qa"]);

        let user = s.create_user("ann@example.com", "", Role::Member, "h").unwrap().unwrap();
        s.set_user_tags(&user, &["team:dev".into(), "team:ops".into()], None).unwrap();
        assert!(s.set_user_tags(&user, &["team:qa".into()], None).is_err(), "unregistered tags can't be assigned");
        assert_eq!(s.user_tags().unwrap()[&user], ["team:dev", "team:ops"], "a failed replace changes nothing");

        // An enrollment's owner, tags and settings carry over to the agent.
        let spec = EnrollmentSpec {
            created_by: Some(user.clone()),
            owner_user_id: Some(user.clone()),
            tags: vec!["team:dev".into()],
            labels: vec!["env:laptop".into()],
            allow_public: false,
            default_private: true,
        };
        let (agent, _) = s.enroll(&s.create_enrollment(60, &spec).unwrap(), "laptop").unwrap().unwrap();
        let row = s.agents().unwrap().into_iter().find(|a| a.id == agent).unwrap();
        assert_eq!((row.owner_user_id.as_deref(), row.allow_public, row.default_private), (Some(user.as_str()), false, true));
        assert_eq!(row.labels, ["env:laptop"]);
        assert_eq!(s.agent_tags().unwrap()[&agent], ["team:dev"]);
        let (service, _) = s.enroll(&s.create_enrollment(60, &EnrollmentSpec::default()).unwrap(), "ci").unwrap().unwrap();
        let row = s.agents().unwrap().into_iter().find(|a| a.id == service).unwrap();
        assert_eq!((row.owner_user_id, row.allow_public, row.default_private), (None, true, false));

        // Deleting a tag revokes it everywhere.
        assert!(s.delete_tag("team:dev").unwrap());
        assert_eq!(s.user_tags().unwrap()[&user], ["team:ops"]);
        assert!(!s.agent_tags().unwrap().contains_key(&agent));
        std::fs::remove_dir_all(dir).ok();
    }
}
