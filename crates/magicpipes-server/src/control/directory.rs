//! Who owns which agent and which tags everyone holds: an in-memory copy of the account tables,
//! reloaded after every change to users, tags or agents ([`ControlPlane::refresh`]). Access
//! decisions and the published routes are computed from it, so a change applies on the next
//! request without a database read on the request path.

use std::collections::HashMap;

use super::ControlPlane;
use crate::store::{AgentRow, HostnameRow, SshKeyRow, Store, TagRow, UserRow};

#[derive(Default)]
pub(super) struct Directory {
    agents: HashMap<String, AgentRow>,
    agent_tags: HashMap<String, Vec<String>>,
    user_tags: HashMap<String, Vec<String>>,
    users: HashMap<String, UserRow>,
    tags: HashMap<String, TagRow>,
    hostnames: HashMap<String, HostnameRow>,
    ssh_keys: Vec<SshKeyRow>,
}

impl Directory {
    pub(super) fn load(store: &Store) -> anyhow::Result<Self> {
        Ok(Self {
            agents: store.agents()?.into_iter().map(|a| (a.id.clone(), a)).collect(),
            agent_tags: store.agent_tags()?,
            user_tags: store.user_tags()?,
            users: store.users()?.into_iter().map(|u| (u.id.clone(), u)).collect(),
            tags: store.tags()?.into_iter().map(|t| (t.name.clone(), t)).collect(),
            hostnames: store.hostnames()?.into_iter().map(|h| (h.hostname.clone(), h)).collect(),
            ssh_keys: store.ssh_keys()?,
        })
    }

    /// Every public key for the SSH gateway.
    pub(super) fn ssh_keys(&self) -> &[SshKeyRow] {
        &self.ssh_keys
    }

    /// A registered custom hostname.
    pub(super) fn hostname(&self, hostname: &str) -> Option<&HostnameRow> {
        self.hostnames.get(hostname)
    }

    /// Every registered custom hostname, in order.
    pub(super) fn hostnames(&self) -> impl Iterator<Item = &HostnameRow> {
        let mut list: Vec<&HostnameRow> = self.hostnames.values().collect();
        list.sort_by(|a, b| a.hostname.cmp(&b.hostname));
        list.into_iter()
    }

    /// Does the tag grant access? False for a tag that isn't known (fail closed).
    pub(super) fn grants_access(&self, tag: &str) -> bool {
        self.tags.get(tag).is_some_and(|t| t.access)
    }

    /// The personal tag of a user.
    pub(super) fn personal_tag(&self, user_id: &str) -> Option<&str> {
        self.tags.values().find(|t| t.user_id.as_deref() == Some(user_id)).map(|t| t.name.as_str())
    }

    /// Every personal tag with the email of its user.
    pub(super) fn personal_tags(&self) -> impl Iterator<Item = (&str, &str)> {
        self.tags.values().filter_map(|t| {
            let user = t.user_id.as_deref()?;
            Some((t.name.as_str(), self.email(user)?))
        })
    }

    /// Is it someone's personal tag?
    pub(super) fn is_personal(&self, tag: &str) -> bool {
        self.tags.get(tag).is_some_and(|t| t.user_id.is_some())
    }

    /// A user's tags (sorted), their personal tag included.
    pub(super) fn user_tags(&self, user_id: &str) -> Vec<String> {
        self.user_tags.get(user_id).cloned().unwrap_or_default()
    }

    pub(super) fn agent(&self, agent_id: &str) -> Option<&AgentRow> {
        self.agents.get(agent_id)
    }

    pub(super) fn agents(&self) -> impl Iterator<Item = &AgentRow> {
        self.agents.values()
    }

    pub(super) fn owner(&self, agent_id: &str) -> Option<&str> {
        self.agents.get(agent_id)?.owner_user_id.as_deref()
    }

    /// Is the agent owned by a member (not an administrator)?
    pub(super) fn member_owned(&self, agent_id: &str) -> bool {
        self.owner(agent_id).and_then(|u| self.users.get(u)).is_some_and(|u| u.role == crate::authz::Role::Member)
    }

    pub(super) fn email(&self, user_id: &str) -> Option<&str> {
        self.users.get(user_id).map(|u| u.email.as_str())
    }

    /// Users who are not disabled.
    pub(super) fn active_users(&self) -> impl Iterator<Item = &UserRow> {
        self.users.values().filter(|u| !u.disabled)
    }

    /// The tags an agent publishes with (sorted): its owner's for a personal agent, its own for
    /// a service agent. Its tunnels may carry only these.
    pub(super) fn agent_tags(&self, agent_id: &str) -> Vec<String> {
        let list = match self.owner(agent_id) {
            Some(owner) => self.user_tags.get(owner),
            None => self.agent_tags.get(agent_id),
        };
        list.cloned().unwrap_or_default()
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
            if let Some(link) = st.sessions.remove(&a) {
                tracing::info!(agent = %a, "closing session: the agent's owner is disabled");
                link.close();
            }
        }
        self.publish(&st);
    }
}
