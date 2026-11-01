//! Authorization: the one decision function behind every access check, for the management API
//! and UI, agent RPCs and public traffic alike (docs/USERS.md, "Principals, actions and
//! resources").
//!
//! [`authorize`] is pure: callers pass precomputed views, so the data plane can call it per
//! connection without touching the registry or the database. Principals are the admin token,
//! users (admins and members), agents and anonymous public clients. Every tunnel is public until
//! tags and private tunnels arrive, which extend the same table.

/// Who is acting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// A public client without credentials.
    Anonymous,
    /// An admin token: an API bearer token or a UI session created with one.
    AdminToken,
    /// A logged-in user (UI session or API token), by id, with their current role.
    User { id: String, role: Role },
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
    /// The agent that owns the tunnel.
    pub agent_id: String,
    /// Anyone may connect (network allow-lists still apply first). Every tunnel is public until
    /// private tunnels exist.
    pub public: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum Resource<'a> {
    /// Server-wide management: status, users, enrollments, the audit log, every agent and tunnel.
    Org,
    /// A user account, by id.
    User(&'a str),
    /// An agent, by id.
    Agent(&'a str),
    Tunnel(&'a TunnelAuthz),
}

/// The decision table; the first matching rule wins and anything unmatched is denied.
pub fn authorize(who: &Principal, action: Action, what: Resource<'_>) -> bool {
    let tunnel_owner = |t: &TunnelAuthz| matches!(who, Principal::Agent(id) if *id == t.agent_id);
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
        // An agent manages and sees itself; an administrator manages and sees every agent.
        (Resource::Agent(id), Action::Manage | Action::Discover) => {
            who.is_admin() || matches!(who, Principal::Agent(me) if me == id)
        }
        (Resource::Agent(_), Action::Connect) => false,
        // A tunnel is managed by its own agent and by administrators.
        (Resource::Tunnel(t), Action::Manage) => tunnel_owner(t) || who.is_admin(),
        // Administrators manage private tunnels but don't reach them without being the owner.
        (Resource::Tunnel(t), Action::Discover) => t.public || tunnel_owner(t),
        (Resource::Tunnel(t), Action::Connect) => tunnel_owner(t),
    }
}

#[cfg(test)]
mod tests {
    use super::Action::*;
    use super::*;

    fn tunnel(agent: &str, public: bool) -> TunnelAuthz {
        TunnelAuthz { agent_id: agent.into(), public }
    }

    #[test]
    fn decision_table() {
        let anon = Principal::Anonymous;
        let admin = Principal::AdminToken;
        let alice = Principal::User { id: "us_alice".into(), role: Role::Admin };
        let bob = Principal::User { id: "us_bob".into(), role: Role::Member };
        let a = Principal::Agent("ag_a".into());
        let b = Principal::Agent("ag_b".into());
        let public = tunnel("ag_a", true);
        let private = tunnel("ag_a", false);

        // Public tunnels: anyone connects; only the owner and administrators manage.
        for p in [&anon, &admin, &a, &b] {
            assert!(authorize(p, Connect, Resource::Tunnel(&public)), "{p:?}");
        }
        assert!(authorize(&a, Manage, Resource::Tunnel(&public)));
        assert!(authorize(&admin, Manage, Resource::Tunnel(&public)));
        assert!(!authorize(&b, Manage, Resource::Tunnel(&public)));
        assert!(!authorize(&anon, Manage, Resource::Tunnel(&public)));
        assert!(!authorize(&anon, Discover, Resource::Tunnel(&public)));
        assert!(authorize(&b, Discover, Resource::Tunnel(&public)));

        // Private tunnels: the owner only; administrators manage but don't connect.
        assert!(authorize(&a, Connect, Resource::Tunnel(&private)));
        assert!(authorize(&a, Discover, Resource::Tunnel(&private)));
        for p in [&anon, &admin, &b] {
            assert!(!authorize(p, Connect, Resource::Tunnel(&private)), "{p:?}");
        }
        assert!(!authorize(&admin, Discover, Resource::Tunnel(&private)));
        assert!(!authorize(&b, Discover, Resource::Tunnel(&private)));
        assert!(authorize(&admin, Manage, Resource::Tunnel(&private)));

        // Admin users act like the admin token; members manage nothing they don't own.
        assert!(authorize(&alice, Manage, Resource::Tunnel(&public)));
        assert!(authorize(&alice, Manage, Resource::Agent("ag_b")));
        assert!(!authorize(&alice, Connect, Resource::Tunnel(&private)));
        assert!(!authorize(&bob, Manage, Resource::Tunnel(&public)));
        assert!(!authorize(&bob, Manage, Resource::Agent("ag_a")));
        assert!(authorize(&bob, Discover, Resource::Tunnel(&public)));
        assert!(!authorize(&bob, Discover, Resource::Tunnel(&private)));

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

        // Agents: themselves; administrators: all of them. Nobody "connects" to an agent.
        assert!(authorize(&a, Manage, Resource::Agent("ag_a")));
        assert!(!authorize(&a, Manage, Resource::Agent("ag_b")));
        assert!(authorize(&admin, Manage, Resource::Agent("ag_b")));
        assert!(!authorize(&anon, Discover, Resource::Agent("ag_a")));
        assert!(!authorize(&admin, Connect, Resource::Agent("ag_a")));
    }
}
