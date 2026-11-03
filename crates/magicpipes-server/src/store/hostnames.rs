//! Custom hostnames and who may serve them (migration 2).
//!
//! Callers pass validated, lowercase hostnames (`control::hostnames::validate`).

use magicpipes_core::unix_now;
use rusqlite::params;

use super::Store;
use super::users::DEFAULT_ORG;

/// At most this many custom hostnames per organization.
pub const MAX_HOSTNAMES: usize = 500;

#[derive(Debug, Clone)]
pub struct HostnameRow {
    pub hostname: String,
    /// Assigned to this user's machines, or else (exactly one is set) to this service agent.
    pub owner_user_id: Option<String>,
    pub agent_id: Option<String>,
    pub created_at: i64,
}

impl Store {
    pub fn hostnames(&self) -> anyhow::Result<Vec<HostnameRow>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT hostname, owner_user_id, agent_id, created_at FROM hostnames WHERE org_id = ?1 ORDER BY hostname",
            )?;
            st.query_map([DEFAULT_ORG], |r| {
                Ok(HostnameRow { hostname: r.get(0)?, owner_user_id: r.get(1)?, agent_id: r.get(2)?, created_at: r.get(3)? })
            })?
            .collect()
        })
    }

    /// Registers a hostname for a user or a service agent; `false` if it exists already or the
    /// organization has [`MAX_HOSTNAMES`].
    pub fn create_hostname(&self, hostname: &str, owner_user_id: Option<&str>, agent_id: Option<&str>, created_by: Option<&str>) -> anyhow::Result<bool> {
        let n = self.with(|c| {
            let count: i64 = c.query_row("SELECT COUNT(*) FROM hostnames WHERE org_id = ?1", [DEFAULT_ORG], |r| r.get(0))?;
            if count as usize >= MAX_HOSTNAMES {
                return Ok(0);
            }
            c.execute(
                "INSERT INTO hostnames (hostname, org_id, owner_user_id, agent_id, created_by, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (hostname) DO NOTHING",
                params![hostname, DEFAULT_ORG, owner_user_id, agent_id, created_by, unix_now()],
            )
        })?;
        Ok(n == 1)
    }

    /// Removes a hostname's registration and every tunnel on it, in one transaction. `false`
    /// if it wasn't registered.
    pub fn delete_hostname(&self, hostname: &str) -> anyhow::Result<bool> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM tunnels WHERE hostname = ?1", [hostname])?;
        let deleted = tx.execute("DELETE FROM hostnames WHERE org_id = ?1 AND hostname = ?2", params![DEFAULT_ORG, hostname])?;
        tx.commit()?;
        Ok(deleted == 1)
    }
}

#[cfg(test)]
mod tests {
    use magicpipes_core::secret;
    use rusqlite::Connection;

    use super::super::{EnrollmentSpec, MIGRATIONS};
    use super::*;
    use crate::authz::Role;

    #[test]
    fn hostnames_belong_to_one_user_or_agent() {
        let dir = std::env::temp_dir().join(format!("mp-store-{}", secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db.sqlite");
        // A database at migration 1, from before custom hostnames, gains the table.
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(MIGRATIONS[0]).unwrap();
            c.pragma_update(None, "user_version", 1).unwrap();
        }
        let s = Store::open(&path).unwrap();
        let user = s.create_user("ann@example.com", "", Role::Member, "h").unwrap().unwrap();
        let (agent, _) = s.enroll(&s.create_enrollment(60, &EnrollmentSpec::default()).unwrap(), "ci").unwrap().unwrap();
        assert!(s.create_hostname("shop.example.com", Some(&user), None, None).unwrap());
        assert!(s.create_hostname("api.example.com", None, Some(&agent), None).unwrap());
        assert!(!s.create_hostname("shop.example.com", None, Some(&agent), None).unwrap(), "registered already");
        assert!(s.create_hostname("both.example.com", Some(&user), Some(&agent), None).is_err(), "one owner only");
        assert!(s.create_hostname("none.example.com", None, None, None).is_err());
        let rows = s.hostnames().unwrap();
        assert_eq!(rows.iter().map(|h| h.hostname.as_str()).collect::<Vec<_>>(), ["api.example.com", "shop.example.com"]);
        // Revoking the agent takes its hostname with it.
        assert!(s.delete_agent(&agent).unwrap());
        assert_eq!(s.hostnames().unwrap().len(), 1);
        assert!(s.delete_hostname("shop.example.com").unwrap() && !s.delete_hostname("shop.example.com").unwrap());
        std::fs::remove_dir_all(dir).ok();
    }
}
