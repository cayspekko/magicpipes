//! The tag registry, tag assignments to users and service agents, and enrollment tokens.
//!
//! Only administrators create tags, decide whether a tag grants access, and assign tags to
//! users and service agents. Every user also holds a personal tag, made with the account, which
//! no other user or agent can hold, whose access can't be turned off, and which goes only with
//! the account; a tunnel may carry it, to share the tunnel with that one person. A personal agent
//! has no tags of its own: it publishes with its owner's.

use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::ErrorBody;
use magicpipes_core::{rfc3339, tags};
use serde::Serialize;

use super::{ControlPlane, OrLog, err, internal};
use crate::authz::{self, Action, Principal, Resource};
use crate::store::{EnrollmentSpec, MAX_TAGS};

#[derive(Debug, Clone, Serialize)]
pub struct TagView {
    pub name: String,
    pub description: String,
    /// Users and private tunnels sharing it may connect.
    pub access: bool,
    pub created_at: String,
}

/// What a new enrollment token gives its agent.
#[derive(Debug, Clone, Default)]
pub struct EnrollmentOptions {
    /// The user the agent will belong to; `None` for a service agent (administrators only).
    /// Members always enroll their own machines.
    pub owner_user_id: Option<String>,
    /// Service agents only: a personal agent publishes with its owner's tags.
    pub tags: Vec<String>,
    /// Default: allowed (members: `[users] members_can_publish`).
    pub allow_public: Option<bool>,
    /// Default: private once the server has user accounts; always for members.
    pub default_private: Option<bool>,
}

fn invalid(msg: String) -> ErrorBody {
    err(ErrorCode::InvalidRequest, msg)
}

/// Tags to take away: normalized, but not necessarily registered any more.
fn removable(list: &[String]) -> Result<Vec<String>, ErrorBody> {
    let list = tags::normalize_list(list).map_err(invalid)?;
    if list.len() > MAX_TAGS {
        return Err(invalid(format!("at most {MAX_TAGS} tags")));
    }
    Ok(list)
}

/// `current` without `remove`, plus `add`; sorted and bounded.
fn changed(current: Vec<String>, add: &[String], remove: &[String]) -> Result<Vec<String>, ErrorBody> {
    let mut list: Vec<String> = current.into_iter().filter(|t| !remove.contains(t)).collect();
    list.extend(add.iter().filter(|t| !remove.contains(t)).cloned());
    list.sort();
    list.dedup();
    if list.len() > MAX_TAGS {
        return Err(invalid(format!("at most {MAX_TAGS} tags")));
    }
    Ok(list)
}

impl ControlPlane {
    /// Normalized, registered tags that can be assigned to a user or agent (not personal);
    /// `tag_unknown` names the first unregistered one.
    pub(super) fn registered(&self, list: &[String]) -> Result<Vec<String>, ErrorBody> {
        self.known_tags(list, false)
    }

    /// Like [`Self::registered`], and with `personal`, someone's personal tag is fine too (a
    /// tunnel shared with one person).
    pub(super) fn known_tags(&self, list: &[String], personal: bool) -> Result<Vec<String>, ErrorBody> {
        let list = tags::normalize_list(list).map_err(invalid)?;
        if list.len() > MAX_TAGS {
            return Err(invalid(format!("at most {MAX_TAGS} tags")));
        }
        let known = self.store.tags().map_err(internal)?;
        for t in &list {
            match known.iter().find(|k| k.name == *t) {
                None => return Err(err(ErrorCode::TagUnknown, format!("'{t}' is not a tag; an administrator must create it first"))),
                Some(k) if k.user_id.is_some() && !personal => {
                    return Err(err(ErrorCode::Forbidden, format!("'{t}' is a personal tag; only its user holds it")));
                }
                Some(_) => {}
            }
        }
        Ok(list)
    }

    /// The tag registry, without personal tags.
    pub fn tags(&self, who: &Principal) -> Vec<TagView> {
        if !authz::authorize(who, Action::Discover, Resource::Org) {
            return Vec::new();
        }
        let rows = self.store.tags().or_log().unwrap_or_default();
        rows.into_iter()
            .filter(|t| t.user_id.is_none())
            .map(|t| TagView { name: t.name, description: t.description, access: t.access, created_at: rfc3339(t.created_at) })
            .collect()
    }

    pub fn create_tag(&self, who: &Principal, name: &str, description: &str, access: bool) -> Result<TagView, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(err(ErrorCode::Forbidden, "only administrators create tags"));
        }
        let name = tags::normalize(name).map_err(invalid)?;
        if name == "user" || name.starts_with("user:") {
            return Err(invalid("'user:' tags are personal tags, made with each account".into()));
        }
        let description: String = description.chars().filter(|c| !c.is_control()).take(200).collect();
        let created_by = matches!(who, Principal::User { .. }).then(|| who.actor());
        if !self.store.create_tag(&name, description.trim(), access, created_by).map_err(internal)? {
            return Err(err(ErrorCode::InvalidRequest, format!("'{name}' exists already, or there are {MAX_TAGS} tags")));
        }
        self.audit(who, "tag.create", &name, if access { "access" } else { "" });
        self.refresh();
        Ok(TagView { name, description: description.trim().to_string(), access, created_at: rfc3339(magicpipes_core::unix_now()) })
    }

    /// Turns a tag's access on or off; everyone it let in loses that at once.
    pub fn set_tag_access(&self, who: &Principal, name: &str, access: bool) -> Result<bool, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(err(ErrorCode::Forbidden, "only administrators change tags"));
        }
        let name = name.trim().to_ascii_lowercase();
        let changed = self.store.set_tag_access(&name, access).map_err(internal)?;
        if changed {
            self.audit(who, "tag.access", &name, if access { "on" } else { "off" });
            self.refresh();
        }
        Ok(changed)
    }

    /// Deletes a tag and every assignment of it; access that depended on it ends at once.
    pub fn delete_tag(&self, who: &Principal, name: &str) -> Result<bool, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(err(ErrorCode::Forbidden, "only administrators delete tags"));
        }
        let name = name.trim().to_ascii_lowercase();
        let deleted = self.store.delete_tag(&name).map_err(internal)?;
        if deleted {
            // The store cascaded it out of tunnel_tags; do the same in memory, so a new tag of
            // the same name doesn't bring the old grant back.
            for t in self.state.lock().unwrap().tunnels.values_mut() {
                t.row.tags.retain(|a| *a != name);
            }
            self.audit(who, "tag.delete", &name, "");
            self.refresh();
        }
        Ok(deleted)
    }

    /// Replaces a user's assigned tags (administrators only); the personal tag stays.
    pub fn set_user_tags(&self, who: &Principal, user_id: &str, list: &[String]) -> Result<Vec<String>, ErrorBody> {
        self.edit_user_tags(who, user_id, |_| self.registered(list))
    }

    /// Adds and removes some of a user's tags (administrators only), keeping the others as they
    /// are now, so two administrators changing different tags don't undo each other.
    pub fn change_user_tags(&self, who: &Principal, user_id: &str, add: &[String], remove: &[String]) -> Result<Vec<String>, ErrorBody> {
        let (add, remove) = (self.registered(add)?, removable(remove)?);
        self.edit_user_tags(who, user_id, |current| changed(current, &add, &remove))
    }

    /// Reads the user's assigned tags, computes the new list and writes it under the state lock,
    /// so concurrent edits apply one after the other.
    fn edit_user_tags(
        &self,
        who: &Principal,
        user_id: &str,
        edit: impl FnOnce(Vec<String>) -> Result<Vec<String>, ErrorBody>,
    ) -> Result<Vec<String>, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(err(ErrorCode::Forbidden, "only administrators assign tags"));
        }
        if self.store.user(user_id).map_err(internal)?.is_none() {
            return Err(err(ErrorCode::NotFound, "no such user"));
        }
        let list = {
            let st = self.state.lock().unwrap();
            let current = self.store.user_tags().map_err(internal)?.remove(user_id).unwrap_or_default();
            let list = edit(current.into_iter().filter(|t| !st.dir.is_personal(t)).collect())?;
            let by = matches!(who, Principal::User { .. }).then(|| who.actor());
            self.store.set_user_tags(user_id, &list, by).map_err(internal)?;
            list
        };
        self.audit(who, "user.tags", user_id, &list.join(" "));
        self.refresh();
        Ok(list)
    }

    /// Adds and removes some of a service agent's tags (administrators only), keeping the others.
    pub fn change_agent_tags(&self, who: &Principal, agent_id: &str, add: &[String], remove: &[String]) -> Result<Vec<String>, ErrorBody> {
        let (add, remove) = (self.registered(add)?, removable(remove)?);
        self.edit_agent_tags(who, agent_id, |current| changed(current, &add, &remove))
    }

    /// Replaces a service agent's tags (administrators only).
    pub fn set_agent_tags(&self, who: &Principal, agent_id: &str, list: &[String]) -> Result<Vec<String>, ErrorBody> {
        self.edit_agent_tags(who, agent_id, |_| self.registered(list))
    }

    fn edit_agent_tags(
        &self,
        who: &Principal,
        agent_id: &str,
        edit: impl FnOnce(Vec<String>) -> Result<Vec<String>, ErrorBody>,
    ) -> Result<Vec<String>, ErrorBody> {
        let list = {
            let st = self.state.lock().unwrap();
            if st.dir.agent(agent_id).is_none() || !authz::authorize(who, Action::Manage, st.agent_resource(agent_id)) {
                return Err(err(ErrorCode::NotFound, "no such agent"));
            }
            if !who.is_admin() {
                return Err(err(ErrorCode::Forbidden, "only administrators assign tags"));
            }
            if st.dir.owner(agent_id).is_some() {
                return Err(err(ErrorCode::InvalidRequest, "a personal machine uses its owner's tags; change the owner's tags instead"));
            }
            let current = self.store.agent_tags().map_err(internal)?.remove(agent_id).unwrap_or_default();
            let list = edit(current)?;
            self.store.set_agent_tags(agent_id, &list).map_err(internal)?;
            list
        };
        self.audit(who, "agent.tags", agent_id, &list.join(" "));
        self.refresh();
        Ok(list)
    }

    /// Creates a single-use enrollment token. Administrators may enroll service agents (with any
    /// tags) and anyone's machines; members only their own machines.
    pub fn create_enrollment(&self, who: &Principal, opts: EnrollmentOptions) -> Result<String, ErrorBody> {
        let tag_list = self.registered(&opts.tags)?;
        let spec = match who {
            _ if who.is_admin() => {
                if let Some(owner) = &opts.owner_user_id {
                    if self.store.user(owner).map_err(internal)?.is_none() {
                        return Err(err(ErrorCode::NotFound, "no such user"));
                    }
                    if !tag_list.is_empty() {
                        return Err(invalid("a personal machine uses its owner's tags; tags are for service agents".into()));
                    }
                }
                let has_users = self.store.has_users().map_err(internal)?;
                EnrollmentSpec {
                    created_by: matches!(who, Principal::User { .. }).then(|| who.actor().to_string()),
                    owner_user_id: opts.owner_user_id,
                    tags: tag_list,
                    allow_public: opts.allow_public.unwrap_or(true),
                    default_private: opts.default_private.unwrap_or(has_users),
                }
            }
            Principal::User { id, .. } => {
                if opts.owner_user_id.as_deref().is_some_and(|o| o != id) {
                    return Err(err(ErrorCode::Forbidden, "members enroll only their own machines"));
                }
                if !tag_list.is_empty() {
                    return Err(invalid("your machine uses your tags; tags are for service agents".into()));
                }
                let max = self.cfg.users.max_agents_per_user;
                if max > 0 && self.store.machines_of(id).map_err(internal)? >= max {
                    return Err(err(ErrorCode::LimitReached, format!("you may have at most {max} machines on this server, counting enrollment tokens not used yet; revoke one you no longer use")));
                }
                EnrollmentSpec {
                    created_by: Some(id.clone()),
                    owner_user_id: Some(id.clone()),
                    tags: Vec::new(),
                    allow_public: self.cfg.users.members_can_publish && opts.allow_public.unwrap_or(true),
                    default_private: opts.default_private.unwrap_or(true),
                }
            }
            _ => return Err(err(ErrorCode::Forbidden, "log in to create enrollment tokens")),
        };
        let token = self.store.create_enrollment(self.cfg.agents.enrollment_ttl_secs, &spec).map_err(internal)?;
        let detail = format!("owner={} tags={}", spec.owner_user_id.as_deref().unwrap_or("-"), spec.tags.join(","));
        self.audit(who, "enrollment.create", "enrollment", &detail);
        Ok(token)
    }
}
