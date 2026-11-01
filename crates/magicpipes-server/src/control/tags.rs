//! The tag registry, tag assignments to users and agents, and enrollment tokens.
//!
//! Only administrators create tags and assign them to users. Agents get tags only through their
//! enrollment token: administrators may give any registered tags; members only tags they hold,
//! and only to their own machines. Afterwards an agent's owner may remove tags but never add one.

use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::ErrorBody;
use magicpipes_core::{rfc3339, tags};
use serde::Serialize;

use super::{ControlPlane, err, internal};
use crate::authz::{self, Action, Principal, Resource};
use crate::store::{EnrollmentSpec, MAX_TAGS};

#[derive(Debug, Clone, Serialize)]
pub struct TagView {
    pub name: String,
    pub description: String,
    pub created_at: String,
}

/// What a new enrollment token gives its agent.
#[derive(Debug, Clone, Default)]
pub struct EnrollmentOptions {
    /// The user the agent will belong to; `None` for a service agent (administrators only).
    /// Members always enroll their own machines.
    pub owner_user_id: Option<String>,
    pub tags: Vec<String>,
    pub labels: Vec<String>,
    /// Default: allowed (members: `[users] members_can_publish`).
    pub allow_public: Option<bool>,
    /// Default: private once the server has user accounts; always for members.
    pub default_private: Option<bool>,
}

fn invalid(msg: String) -> ErrorBody {
    err(ErrorCode::InvalidRequest, msg)
}

impl ControlPlane {
    /// Normalized, registered tags; `tag_unknown` names the first unregistered one.
    pub(super) fn registered(&self, list: &[String]) -> Result<Vec<String>, ErrorBody> {
        let list = tags::normalize_list(list).map_err(invalid)?;
        if list.len() > MAX_TAGS {
            return Err(invalid(format!("at most {MAX_TAGS} tags")));
        }
        if let Some(t) = self.store.unknown_tags(&list).map_err(internal)?.first() {
            return Err(err(ErrorCode::TagUnknown, format!("'{t}' is not an access tag; an administrator must create it first")));
        }
        Ok(list)
    }

    pub fn tags(&self, who: &Principal) -> Vec<TagView> {
        if !authz::authorize(who, Action::Discover, Resource::Org) {
            return Vec::new();
        }
        let rows = self.store.tags().unwrap_or_default();
        rows.into_iter().map(|t| TagView { name: t.name, description: t.description, created_at: rfc3339(t.created_at) }).collect()
    }

    pub fn create_tag(&self, who: &Principal, name: &str, description: &str) -> Result<TagView, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(err(ErrorCode::Forbidden, "only administrators create tags"));
        }
        let name = tags::normalize(name).map_err(invalid)?;
        let description: String = description.chars().filter(|c| !c.is_control()).take(200).collect();
        let created_by = matches!(who, Principal::User { .. }).then(|| who.actor());
        if !self.store.create_tag(&name, description.trim(), created_by).map_err(internal)? {
            return Err(err(ErrorCode::InvalidRequest, format!("'{name}' exists already, or there are {MAX_TAGS} tags")));
        }
        self.audit(who, "tag.create", &name, "");
        Ok(TagView { name, description: description.trim().to_string(), created_at: rfc3339(magicpipes_core::unix_now()) })
    }

    /// Deletes a tag and every assignment of it; access that depended on it ends at once.
    pub fn delete_tag(&self, who: &Principal, name: &str) -> Result<bool, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(err(ErrorCode::Forbidden, "only administrators delete tags"));
        }
        let deleted = self.store.delete_tag(&name.trim().to_ascii_lowercase()).map_err(internal)?;
        if deleted {
            self.audit(who, "tag.delete", name, "");
            self.refresh();
        }
        Ok(deleted)
    }

    /// Replaces a user's tags (administrators only).
    pub fn set_user_tags(&self, who: &Principal, user_id: &str, list: &[String]) -> Result<Vec<String>, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(err(ErrorCode::Forbidden, "only administrators assign tags"));
        }
        if self.store.user(user_id).map_err(internal)?.is_none() {
            return Err(err(ErrorCode::NotFound, "no such user"));
        }
        let list = self.registered(list)?;
        let by = matches!(who, Principal::User { .. }).then(|| who.actor());
        self.store.set_user_tags(user_id, &list, by).map_err(internal)?;
        self.audit(who, "user.tags", user_id, &list.join(" "));
        self.refresh();
        Ok(list)
    }

    /// Changes an agent's tags and labels. Administrators set any registered tags; an agent's
    /// owner may only remove tags.
    pub fn update_agent(&self, who: &Principal, agent_id: &str, tag_list: Option<&[String]>, labels: Option<&[String]>) -> Result<(), ErrorBody> {
        let assigned = {
            let st = self.state.lock().unwrap();
            if st.dir.agent(agent_id).is_none() || !authz::authorize(who, Action::Manage, st.agent_resource(agent_id)) {
                return Err(err(ErrorCode::NotFound, "no such agent"));
            }
            st.dir.assigned_agent_tags(agent_id)
        };
        if let Some(list) = tag_list {
            let list = self.registered(list)?;
            if !who.is_admin() && list.iter().any(|t| !assigned.contains(t)) {
                return Err(err(ErrorCode::Forbidden, "you can remove an agent's tags; adding one takes an administrator"));
            }
            self.store.set_agent_tags(agent_id, &list).map_err(internal)?;
            self.audit(who, "agent.tags", agent_id, &list.join(" "));
        }
        if let Some(labels) = labels {
            let labels = tags::normalize_list(labels).map_err(invalid)?;
            self.store.set_agent_labels(agent_id, &labels).map_err(internal)?;
            self.audit(who, "agent.labels", agent_id, &labels.join(" "));
        }
        self.refresh();
        Ok(())
    }

    /// Creates a single-use enrollment token. Administrators may enroll service agents and
    /// anyone's machines with any registered tags; members only their own machines, with tags
    /// they hold.
    pub fn create_enrollment(&self, who: &Principal, opts: EnrollmentOptions) -> Result<String, ErrorBody> {
        let tag_list = self.registered(&opts.tags)?;
        let labels = tags::normalize_list(&opts.labels).map_err(invalid)?;
        let spec = match who {
            _ if who.is_admin() => {
                if let Some(owner) = &opts.owner_user_id
                    && self.store.user(owner).map_err(internal)?.is_none()
                {
                    return Err(err(ErrorCode::NotFound, "no such user"));
                }
                let has_users = self.store.has_users().map_err(internal)?;
                EnrollmentSpec {
                    created_by: matches!(who, Principal::User { .. }).then(|| who.actor().to_string()),
                    owner_user_id: opts.owner_user_id,
                    tags: tag_list,
                    labels,
                    allow_public: opts.allow_public.unwrap_or(true),
                    default_private: opts.default_private.unwrap_or(has_users),
                }
            }
            Principal::User { id, tags: held, .. } => {
                if opts.owner_user_id.as_deref().is_some_and(|o| o != id) {
                    return Err(err(ErrorCode::Forbidden, "members enroll only their own machines"));
                }
                if let Some(t) = tag_list.iter().find(|t| !held.contains(t)) {
                    return Err(err(ErrorCode::Forbidden, format!("you don't hold '{t}', so your machine can't have it")));
                }
                EnrollmentSpec {
                    created_by: Some(id.clone()),
                    owner_user_id: Some(id.clone()),
                    tags: tag_list,
                    labels,
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
