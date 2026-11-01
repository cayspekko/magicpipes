//! Authorization: the one decision function behind every access check, for the management API
//! and UI, agent RPCs and public traffic alike (docs/USERS.md, "Principals, actions and
//! resources").
//!
//! [`authorize`] is pure: callers pass precomputed views, so the data plane can call it per
//! connection without touching the registry or the database. Today's principals are the admin
//! token, agents and anonymous public clients, and every tunnel is public; users, roles and tags
//! extend the same table later.

/// Who is acting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// A public client without credentials.
    Anonymous,
    /// An admin token: an API bearer token or a UI session created with one.
    AdminToken,
    /// An authenticated agent, by id.
    Agent(String),
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
    /// Server-wide management: status, enrollments, every agent and tunnel.
    Org,
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
        (Resource::Org, _) => *who == Principal::AdminToken,
        // An agent manages and sees itself; an administrator manages and sees every agent.
        (Resource::Agent(id), Action::Manage | Action::Discover) => match who {
            Principal::AdminToken => true,
            Principal::Agent(me) => me == id,
            Principal::Anonymous => false,
        },
        (Resource::Agent(_), Action::Connect) => false,
        // A tunnel is managed by its own agent and by administrators.
        (Resource::Tunnel(t), Action::Manage) => tunnel_owner(t) || *who == Principal::AdminToken,
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

        // Server-wide management is for administrators only.
        for (p, ok) in [(&anon, false), (&admin, true), (&a, false)] {
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
