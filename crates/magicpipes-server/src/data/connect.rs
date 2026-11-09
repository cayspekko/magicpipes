//! `magicpipes connect`: how a signed-in person reaches a private TCP or UDP tunnel.
//!
//! The CLI listens on the person's machine and makes one HTTPS connection to the management host for
//! each local connection (TCP) or local client (UDP), with a connect pass as the bearer token. The
//! handshake checks the pass and the person's access against the published table, without the
//! database, opens a data stream to the tunnel's agent as for any public connection
//! ([`ports::open`], under the same budget), and only then answers `101`, so a failure is an HTTP
//! error the CLI can show. After that the connection is the tunnel's: raw bytes for TCP, and for UDP
//! the agent's own framing (a `u16` length before each datagram), which the CLI writes and reads. So
//! the agent changes nothing, and still dials only what its own user configured.
//!
//! A connection ends when either side closes it, when it has been quiet for `udp_idle_timeout` (UDP)
//! or `tcp_idle_timeout` (TCP, if set), or once the person may no longer reach the tunnel: checked on
//! every publish, which follows tag changes, signing out everywhere, disabled users and the tunnel
//! going away.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use magicpipes_core::mux::MuxStream;
use magicpipes_core::proto::{Kind, ServerOpen};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;

use super::ssh::Report;
use super::{DataPlane, Outcome, Route, RouteTable, ports};

/// Open connections and UDP flows per person: a database client's pool, or a few, fits.
pub const MAX_PER_PERSON: usize = 64;

/// Who a connect pass stands for.
#[derive(Debug, Clone)]
pub struct Person {
    pub user_id: String,
    /// When the pass was issued: signing out everywhere after that ends it.
    pub issued_at: i64,
}

/// A tunnel the person may connect to, as the published table has it.
pub struct Found {
    pub kind: Kind,
    /// Its name, without the base domain.
    pub name: String,
    route: Arc<Route>,
}

impl Found {
    pub fn online(&self) -> bool {
        self.route.session.as_ref().is_some_and(|s| !s.is_closed())
    }
}

/// Why a connection couldn't be opened.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// The person has [`MAX_PER_PERSON`] open, or the server its `[ports] max_connections`.
    Busy,
    Offline,
    /// The agent couldn't reach its local service.
    LocalUnreachable,
}

/// An agent stream opened for a person, ready to be joined to their connection.
pub struct Opened {
    person: Person,
    found: Found,
    client: IpAddr,
    stream: MuxStream,
    _slot: Slot,
}

/// Connections per person; the total shares the port tunnels' `max_connections`.
#[derive(Default)]
pub(super) struct Limits {
    per_person: Arc<Mutex<HashMap<String, usize>>>,
}

struct Slot {
    _permit: OwnedSemaphorePermit,
    people: Arc<Mutex<HashMap<String, usize>>>,
    user_id: String,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut people = self.people.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = people.get_mut(&self.user_id) {
            *n -= 1;
            if *n == 0 {
                people.remove(&self.user_id);
            }
        }
    }
}

/// The tunnel's name in what the person typed: the bare name, or the name under the base domain.
fn tunnel_name<'a>(asked: &'a str, base_domain: &str) -> &'a str {
    let asked = asked.trim_end_matches('.');
    match asked.len().checked_sub(base_domain.len() + 1) {
        Some(n) if asked.is_char_boundary(n) && asked[n..].starts_with('.') && asked[n + 1..].eq_ignore_ascii_case(base_domain) => &asked[..n],
        _ => asked,
    }
}

/// The tunnel's route, if the person may still use it.
fn admitted<'t>(table: &'t RouteTable, p: &Person, name: &str, client: IpAddr) -> Option<&'t (Kind, Arc<Route>)> {
    let user = table.users.get(&p.user_id).filter(|u| u.valid_after <= p.issued_at)?;
    table.by_connect.get(name).filter(|(_, r)| r.access.admits(&user.principal, client))
}

impl DataPlane {
    /// Who a connect pass stands for, if it's good and they may still sign in.
    pub fn connect_person(&self, pass: &str) -> Option<Person> {
        let claims = self.settings.signer.verify_pass(pass, &self.settings.management_host)?;
        let person = Person { user_id: claims.user_id, issued_at: claims.issued_at };
        self.table().users.get(&person.user_id).filter(|u| u.valid_after <= person.issued_at)?;
        Some(person)
    }

    /// The tunnel named `asked`, if `person`, connecting from `client`, may reach it. Every other
    /// answer is `None`, so nobody learns of tunnels they can't use.
    pub fn connect_find(&self, person: &Person, asked: &str, client: IpAddr) -> Option<Found> {
        let name = tunnel_name(asked, &self.settings.base_domain);
        let (kind, route) = admitted(&self.table(), person, name, client)?.clone();
        Some(Found { kind, name: name.to_string(), route })
    }

    /// Opens the agent's stream for one connection or UDP flow.
    pub async fn connect_open(&self, person: Person, found: Found, client: IpAddr) -> Result<Opened, Refused> {
        let slot = self.connect_slot(&person.user_id).ok_or(Refused::Busy)?;
        let session = match &found.route.session {
            Some(s) if !s.is_closed() => s.clone(),
            _ => return Err(Refused::Offline),
        };
        let (tunnel_id, peer) = (found.route.tunnel_id.clone(), Some(client.to_string()));
        let header = match found.kind {
            Kind::Udp => ServerOpen::Datagram { tunnel_id, peer },
            _ => ServerOpen::Data { tunnel_id, peer },
        };
        let stream = ports::opened(self, &found.route, &session, client, header).await.map_err(|outcome| match outcome {
            Outcome::LocalUnreachable => Refused::LocalUnreachable,
            Outcome::None => Refused::Busy,
            _ => Refused::Offline,
        })?;
        Ok(Opened { person, found, client, stream, _slot: slot })
    }

    fn connect_slot(&self, user_id: &str) -> Option<Slot> {
        let permit = self.tcp_permits.clone().try_acquire_owned().ok()?;
        let people = self.connections.per_person.clone();
        let mut map = people.lock().unwrap_or_else(|e| e.into_inner());
        let n = map.entry(user_id.to_string()).or_insert(0);
        if *n >= MAX_PER_PERSON {
            return None;
        }
        *n += 1;
        drop(map);
        Some(Slot { _permit: permit, people, user_id: user_id.to_string() })
    }

    /// Joins the person's connection to the agent's stream until either ends, it goes quiet for too
    /// long, or the person may no longer reach the tunnel. Runs on the traffic threads.
    pub async fn connect_run<S>(self: Arc<Self>, io: S, o: Opened)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let Opened { person, found, client, stream, _slot } = o;
        let tunnel_id = found.route.tunnel_id.clone();
        tracing::debug!(user = %person.user_id, tunnel = %tunnel_id, %client, "connect: opened");
        let _ = self.ssh_reports.try_send(Report::Connect { user_id: person.user_id.clone(), tunnel_id: tunnel_id.clone(), client });
        let idle = match found.kind {
            Kind::Udp => Some(self.settings.ports.udp_idle_timeout),
            _ => self.settings.ports.tcp_idle_timeout,
        };
        let revoked = async {
            let mut changes = self.generation.subscribe();
            loop {
                let ok = admitted(&self.table(), &person, &found.name, client).is_some_and(|(_, r)| r.tunnel_id == tunnel_id);
                if !ok || changes.changed().await.is_err() {
                    return;
                }
            }
        };
        tokio::select! {
            _ = super::io::bridge(io, stream, idle, CancellationToken::new()) => {}
            _ = revoked => tracing::debug!(user = %person.user_id, tunnel = %tunnel_id, "connect: closing, no longer admitted"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_with_or_without_the_base_domain() {
        assert_eq!(tunnel_name("db", "t.test"), "db");
        assert_eq!(tunnel_name("db.t.test", "t.test"), "db");
        assert_eq!(tunnel_name("db.T.Test.", "t.test"), "db");
        assert_eq!(tunnel_name("db.other.test", "t.test"), "db.other.test");
        assert_eq!(tunnel_name("dbt.test", "t.test"), "dbt.test");
        assert_eq!(tunnel_name("t.test", "t.test"), "t.test");
        assert_eq!(tunnel_name("", "t.test"), "");
        assert_eq!(tunnel_name("é.t.test", "t.test"), "é");
    }
}
