//! Who owns which agent and which tags everyone holds: an in-memory copy of the account tables,
//! reloaded after every change to users, tags or agents ([`ControlPlane::refresh`]). Access
//! decisions and the published routes are computed from it, so a change applies on the next
//! request without a database read on the request path.

use std::collections::HashMap;

use super::ControlPlane;
use crate::store::{AgentRow, Store, UserRow};

#[derive(Default)]
pub(super) struct Directory {
    agents: HashMap<String, AgentRow>,
    agent_tags: HashMap<String, Vec<String>>,
    user_tags: HashMap<String, Vec<String>>,
    users: HashMap<String, UserRow>,
}

impl Directory {
    pub(super) fn load(store: &Store) -> anyhow::Result<Self> {
        Ok(Self {
            agents: store.agents()?.into_iter().map(|a| (a.id.clone(), a)).collect(),
            agent_tags: store.agent_tags()?,
            user_tags: store.user_tags()?,
            users: store.users()?.into_iter().map(|u| (u.id.clone(), u)).collect(),
        })
    }

    /// A user's access tags (sorted).
    pub(super) fn user_tags(&self, user_id: &str) -> Vec<String> {
        self.user_tags.get(user_id).cloned().unwrap_or_default()
    }

    pub(super) fn agent(&self, agent_id: &str) -> Option<&AgentRow> {
        self.agents.get(agent_id)
    }

    pub(super) fn owner(&self, agent_id: &str) -> Option<&str> {
        self.agents.get(agent_id)?.owner_user_id.as_deref()
    }

    pub(super) fn email(&self, user_id: &str) -> Option<&str> {
        self.users.get(user_id).map(|u| u.email.as_str())
    }

    /// Users who are not disabled.
    pub(super) fn active_users(&self) -> impl Iterator<Item = &UserRow> {
        self.users.values().filter(|u| !u.disabled)
    }

    /// The tags assigned to an agent, before limiting them to its owner's.
    pub(super) fn assigned_agent_tags(&self, agent_id: &str) -> Vec<String> {
        self.agent_tags.get(agent_id).cloned().unwrap_or_default()
    }

    /// An agent's access tags (sorted): its assigned tags, limited to its owner's current tags
    /// for a personal agent, so it never has more access than its owner.
    pub(super) fn agent_tags(&self, agent_id: &str) -> Vec<String> {
        let assigned = self.assigned_agent_tags(agent_id);
        match self.owner(agent_id) {
            Some(owner) => {
                let held = self.user_tags.get(owner);
                assigned.into_iter().filter(|t| held.is_some_and(|h| h.contains(t))).collect()
            }
            None => assigned,
        }
    }

    /// False for an agent whose owner is disabled or gone: it may not connect, and its tunnels
    /// are not published.
    pub(super) fn agent_active(&self, agent_id: &str) -> bool {
        match self.owner(agent_id) {
            Some(owner) => self.users.get(owner).is_some_and(|u| !u.disabled),
            None => true,
        }
    }
}

impl ControlPlane {
    /// Reloads the directory and republishes the routes. Call after any change to users, tags
    /// or agents. If the database can't be read, the previous copy stays and the error is logged.
    pub(super) fn refresh(&self) {
        let mut st = self.state.lock().unwrap();
        match Directory::load(&self.store) {
            Ok(dir) => st.dir = dir,
            Err(e) => tracing::error!(error = %format!("{e:#}"), "could not reload users and tags"),
        }
        // Sessions of agents whose owner was disabled end now.
        let inactive: Vec<String> = st.sessions.keys().filter(|a| !st.dir.agent_active(a)).cloned().collect();
        for a in inactive {
            if let Some(s) = st.sessions.remove(&a) {
                tracing::info!(agent = %a, "closing session: the agent's owner is disabled");
                s.handle.close();
            }
        }
        self.publish(&st);
    }
}
