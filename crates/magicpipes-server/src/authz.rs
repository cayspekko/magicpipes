//! Authorization: the one decision function behind every access check, for the management API
//! and UI, agent RPCs and public traffic alike (docs/USERS.md, "Principals, actions and
//! resources").
//!
//! [`authorize`] is pure: callers pass precomputed views, so the data plane can call it per
//! connection without touching the registry or the database. Principals are the admin token,
//! users (admins and members), agents and anonymous public clients.
//!
//! The access rule for private tunnels: the user shares a tag that grants access with the
//! tunnel. Owners get in the same way, through the personal tag on each of their tunnels;
//! ownership itself only decides who manages.

/// Who is acting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// A public client without credentials.
    Anonymous,
    /// An admin token: an API bearer token or a UI session created with one.
    AdminToken,
    /// A logged-in user (UI session or API token), by id, with their current role and access
    /// tags (sorted).
    User { id: String, role: Role, tags: Vec<String> },
    /// An authenticated agent, by id.
    Agent(String),
}

impl Principal {
    /// The admin token and users with the admin role.
    pub fn is_admin(&self) -> bool {
        matches!(self, Principal::AdminToken | Principal::User { role: Role::Admin, .. })
    }

    /// For the audit log: `admin-token`, a user id or an agent id.
    pub fn actor(&self) -> &str {
        match self {
            Principal::Anonymous => "anonymous",
            Principal::AdminToken => "admin-token",
            Principal::User { id, .. } | Principal::Agent(id) => id,
        }
    }
}

/// A user's role in the organization. Not a tag, and never assigned by the user themself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Manages users, agents, tunnels and enrollment tokens.
    Admin,
    /// Logs in and manages their own account.
    Member,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Member => "member",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Role::Admin),
            "member" => Some(Role::Member),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// See it in a list or look it up.
    Discover,
    /// Reach it: send traffic through a tunnel.
    Connect,
    /// Change or delete it, or look at its management details.
    Manage,
}

/// What [`authorize`] needs to know about a tunnel. Built by the control plane and carried in
/// the data plane's routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelAuthz {
    /// The agent that serves the tunnel.
    pub agent_id: String,
    /// The agent's owner; `None` for a service agent.
    pub owner_user_id: Option<String>,
    /// Anyone may connect (network allow-lists still apply first).
    pub public: bool,
    /// The tunnel's tags that grant access (sorted), its owner's personal tag among them.
    /// Empty: nobody gets into a private tunnel.
    pub access: Vec<String>,
}

/// What [`authorize`] needs to know about an agent.
#[derive(Debug, Clone, Copy)]
pub struct AgentAuthz<'a> {
    pub id: &'a str,
    pub owner_user_id: Option<&'a str>,
}

/// Whether two sorted tag lists share an entry.
fn share_any(a: &[String], b: &[String]) -> bool {
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Equal => return true,
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
        }
    }
    false
}

#[derive(Debug, Clone, Copy)]
pub enum Resource<'a> {
    /// Server-wide management: status, users, enrollments, the audit log, every agent and tunnel.
    Org,
    /// A user account, by id.
    User(&'a str),
    Agent(AgentAuthz<'a>),
    Tunnel(&'a TunnelAuthz),
}

/// The decision table; the first matching rule wins and anything unmatched is denied.
pub fn authorize(who: &Principal, action: Action, what: Resource<'_>) -> bool {
    let user_is = |owner: Option<&str>| matches!((who, owner), (Principal::User { id, .. }, Some(o)) if id == o);
    // A tunnel's owners: the agent that serves it and that agent's user.
    let tunnel_owner = |t: &TunnelAuthz| matches!(who, Principal::Agent(id) if *id == t.agent_id) || user_is(t.owner_user_id.as_deref());
    match (what, action) {
        // Anyone may reach a public tunnel.
        (Resource::Tunnel(t), Action::Connect) if t.public => true,
        _ if *who == Principal::Anonymous => false,
        (Resource::Org, _) => who.is_admin(),
        // Users manage their own account (password, API tokens, sessions); administrators manage
        // every account, including roles, which a user can therefore never change for themself.
        (Resource::User(id), Action::Manage | Action::Discover) => {
            who.is_admin() || matches!(who, Principal::User { id: me, .. } if me == id)
        }
        (Resource::User(_), Action::Connect) => false,
        // An agent is managed by itself, its owner and administrators.
        (Resource::Agent(a), Action::Manage | Action::Discover) => {
            who.is_admin() || matches!(who, Principal::Agent(me) if me == a.id) || user_is(a.owner_user_id)
        }
        (Resource::Agent(_), Action::Connect) => false,
        // A tunnel is managed by its owners and by administrators.
        (Resource::Tunnel(t), Action::Manage) => tunnel_owner(t) || who.is_admin(),
        // Discovering and connecting give the same answer: public, or a shared tag. Owners
        // and administrators manage private tunnels but don't reach them through that.
        (Resource::Tunnel(t), Action::Discover | Action::Connect) => {
            t.public || matches!(who, Principal::User { tags, .. } if share_any(tags, &t.access))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Action::*;
    use super::*;

    fn tunnel(agent: &str, owner: Option<&str>, public: bool, access: &[&str]) -> TunnelAuthz {
        TunnelAuthz { agent_id: agent.into(), owner_user_id: owner.map(Into::into), public, access: access.iter().map(|s| s.to_string()).collect() }
    }

    fn user(id: &str, role: Role, tags: &[&str]) -> Principal {
        Principal::User { id: id.into(), role, tags: tags.iter().map(|s| s.to_string()).collect() }
    }

    fn agent<'a>(id: &'a str, owner: Option<&'a str>) -> Resource<'a> {
        Resource::Agent(AgentAuthz { id, owner_user_id: owner })
    }

    #[test]
    fn decision_table() {
        let anon = Principal::Anonymous;
        let admin = Principal::AdminToken;
        let alice = user("us_alice", Role::Admin, &[]);
        let bob = user("us_bob", Role::Member, &["team:dev", "user:bob"]);
        let carol = user("us_carol", Role::Member, &["team:ops", "zzz"]);
        let a = Principal::Agent("ag_a".into());
        let b = Principal::Agent("ag_b".into());
        let public = tunnel("ag_a", None, true, &[]);
        let private = tunnel("ag_a", None, false, &[]);
        // Served by bob's laptop, shared with team:ops.
        let bobs = tunnel("ag_bob", Some("us_bob"), false, &["team:ops", "user:bob"]);

        // Public tunnels: anyone connects; only the owner and administrators manage.
        for p in [&anon, &admin, &a, &b, &bob] {
            assert!(authorize(p, Connect, Resource::Tunnel(&public)), "{p:?}");
        }
        assert!(authorize(&a, Manage, Resource::Tunnel(&public)));
        assert!(authorize(&admin, Manage, Resource::Tunnel(&public)));
        assert!(authorize(&alice, Manage, Resource::Tunnel(&public)));
        for p in [&anon, &b, &bob] {
            assert!(!authorize(p, Manage, Resource::Tunnel(&public)), "{p:?}");
        }
        assert!(!authorize(&anon, Discover, Resource::Tunnel(&public)));
        assert!(authorize(&bob, Discover, Resource::Tunnel(&public)));

        // Private tunnels: shared tags only, the owner's personal tag among them; owners and
        // administrators manage, which doesn't let them in.
        for p in [&anon, &admin, &alice, &a, &b, &bob] {
            assert!(!authorize(p, Connect, Resource::Tunnel(&private)), "{p:?}");
            assert!(!authorize(p, Discover, Resource::Tunnel(&private)), "{p:?}");
        }
        assert!(authorize(&a, Manage, Resource::Tunnel(&private)));
        assert!(authorize(&admin, Manage, Resource::Tunnel(&private)));
        assert!(authorize(&bob, Connect, Resource::Tunnel(&bobs)), "the owner, through their personal tag");
        assert!(authorize(&bob, Manage, Resource::Tunnel(&bobs)));
        assert!(authorize(&carol, Connect, Resource::Tunnel(&bobs)), "a shared tag");
        assert!(authorize(&carol, Discover, Resource::Tunnel(&bobs)));
        assert!(!authorize(&carol, Manage, Resource::Tunnel(&bobs)), "sharing a tag doesn't make you an owner");
        assert!(!authorize(&user("us_dan", Role::Member, &["team:dev"]), Connect, Resource::Tunnel(&bobs)));
        let untagged = tunnel("ag_bob", Some("us_bob"), false, &[]);
        assert!(!authorize(&bob, Connect, Resource::Tunnel(&untagged)), "ownership alone doesn't let anyone in");
        assert!(authorize(&bob, Manage, Resource::Tunnel(&untagged)));

        // Accounts: your own, or any for administrators.
        assert!(authorize(&bob, Manage, Resource::User("us_bob")));
        assert!(!authorize(&bob, Manage, Resource::User("us_alice")));
        assert!(authorize(&alice, Manage, Resource::User("us_bob")));
        assert!(authorize(&admin, Manage, Resource::User("us_bob")));
        assert!(!authorize(&a, Manage, Resource::User("us_bob")));
        assert!(!authorize(&anon, Discover, Resource::User("us_bob")));

        // Server-wide management is for administrators only.
        for (p, ok) in [(&anon, false), (&admin, true), (&alice, true), (&bob, false), (&a, false)] {
            for action in [Discover, Connect, Manage] {
                assert_eq!(authorize(p, action, Resource::Org), ok, "{p:?} {action:?}");
            }
        }

        // Agents: themselves, their owner and administrators. Nobody "connects" to an agent.
        assert!(authorize(&a, Manage, agent("ag_a", None)));
        assert!(!authorize(&a, Manage, agent("ag_b", None)));
        assert!(authorize(&admin, Manage, agent("ag_b", None)));
        assert!(authorize(&bob, Manage, agent("ag_bob", Some("us_bob"))));
        assert!(!authorize(&carol, Manage, agent("ag_bob", Some("us_bob"))));
        assert!(!authorize(&anon, Discover, agent("ag_a", None)));
        assert!(!authorize(&admin, Connect, agent("ag_a", None)));
    }

    #[test]
    fn tag_matching_is_exact() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(share_any(&s(&["a", "c", "e"]), &s(&["b", "e"])));
        assert!(!share_any(&s(&["team:dev"]), &s(&["team:devops", "team"])));
        assert!(!share_any(&s(&[]), &s(&["a"])));
    }
}
