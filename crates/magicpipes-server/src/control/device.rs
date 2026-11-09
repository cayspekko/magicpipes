//! `magicpipes login` without a token: the CLI asks for a login code, the user approves it in the
//! browser while signed in, and the CLI receives a personal enrollment token for that user
//! (OAuth's device authorization flow, minus OAuth). `magicpipes connect` signs in the same way,
//! and receives a connect pass instead: the browser can be on another device, which is how a
//! machine without one signs in.
//!
//! Pending logins live only in memory: bounded in number, per client, and to ten minutes. The
//! CLI polls with a secret device code; the short user code only identifies the request on the
//! approval page, which also shows where the request came from, because approving someone
//! else's code would enroll their machine as yours.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::ErrorBody;
use magicpipes_core::{secret, unix_now};

use super::{ControlPlane, EnrollmentOptions, err};
use crate::authz::Principal;
use crate::forwarded::client_key;

pub const DEVICE_LOGIN_TTL: Duration = Duration::from_secs(600);
const MAX_PENDING: usize = 1000;
const MAX_PENDING_PER_CLIENT: usize = 5;
/// Unambiguous characters for codes people read and compare.
const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Default)]
pub(super) struct DeviceLogins {
    /// By SHA-256 of the device code.
    map: std::sync::Mutex<HashMap<String, Pending>>,
}

/// How long a connect pass made from an API token lasts. `magicpipes connect` gets a new one
/// before then, so revoking the token ends its use this soon.
pub const API_PASS_SECS: i64 = 900;

/// What a sign-in from the CLI is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// `magicpipes login`: the machine becomes the person's.
    Enroll,
    /// `magicpipes connect`: a connect pass for the person.
    Connect,
}

struct Pending {
    user_code: String,
    agent_name: String,
    client: IpAddr,
    created: Instant,
    purpose: Purpose,
    state: State,
}

enum State {
    Waiting,
    Approved(Granted),
    Denied,
}

/// What an approved sign-in hands out, once.
pub struct Granted {
    pub purpose: Purpose,
    /// The enrollment token or the connect pass.
    pub secret: String,
    /// When a connect pass stops working.
    pub expires_at: Option<i64>,
}

/// What the approval page shows.
pub struct DeviceRequest {
    pub user_code: String,
    pub agent_name: String,
    pub client: IpAddr,
    pub age_secs: u64,
    pub purpose: Purpose,
}

pub enum DevicePoll {
    Pending,
    Approved(Granted),
    Denied,
    /// Unknown or expired: start over.
    Gone,
}

fn user_code() -> String {
    // 32 symbols divide 2^64 evenly, so every symbol is equally likely.
    let chars: String = (0..8).map(|_| CODE_ALPHABET[(secret::random_u64() % CODE_ALPHABET.len() as u64) as usize] as char).collect();
    format!("{}-{}", &chars[..4], &chars[4..])
}

/// `abcd efgh` or `ABCDEFGH` → `ABCD-EFGH`.
pub fn normalize_user_code(code: &str) -> String {
    let c: String = code.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).take(8).collect();
    if c.len() == 8 { format!("{}-{}", &c[..4], &c[4..]) } else { c }
}

impl DeviceLogins {
    fn prune(map: &mut HashMap<String, Pending>) {
        map.retain(|_, p| p.created.elapsed() < DEVICE_LOGIN_TTL);
    }

    /// The table is full: makes room for a client with `holding` waiting logins by dropping the
    /// oldest waiting login of the client holding the most, if that is more than `holding`. So
    /// clients with many addresses can't keep everyone else out; approved logins are kept.
    fn evict_for(map: &mut HashMap<String, Pending>, holding: usize) -> bool {
        let mut per_client: HashMap<IpAddr, usize> = HashMap::new();
        for p in map.values().filter(|p| matches!(p.state, State::Waiting)) {
            *per_client.entry(client_key(p.client)).or_default() += 1;
        }
        let Some((&top, &n)) = per_client.iter().max_by_key(|(_, n)| **n) else { return false };
        if n <= holding {
            return false;
        }
        let victim = map
            .iter()
            .filter(|(_, p)| matches!(p.state, State::Waiting) && client_key(p.client) == top)
            .min_by_key(|(_, p)| p.created)
            .map(|(k, _)| k.clone());
        victim.is_some_and(|k| map.remove(&k).is_some())
    }
}

impl ControlPlane {
    /// A connect pass for `who`, who must be a person, lasting `ttl_secs`. Returns it and when it
    /// expires.
    pub fn connect_pass(&self, who: &Principal, ttl_secs: i64) -> Result<(String, i64), ErrorBody> {
        let Principal::User { id, .. } = who else {
            return Err(err(ErrorCode::Forbidden, "a connect pass is for a person: use one of your own API tokens, or sign in with your user account"));
        };
        let pass = self.data.signer().pass(id, &self.cfg.management.hostname, ttl_secs);
        Ok((pass, unix_now() + ttl_secs))
    }

    /// Starts a sign-in from the CLI on the machine `agent_name`. Returns `(device code, user code)`.
    pub fn start_device_login(&self, agent_name: &str, client: IpAddr, purpose: Purpose) -> Result<(String, String), ErrorBody> {
        let agent_name: String = agent_name.chars().filter(|c| !c.is_control()).take(64).collect();
        let mut map = self.devices.map.lock().unwrap();
        DeviceLogins::prune(&mut map);
        let from_client = map.values().filter(|p| client_key(p.client) == client_key(client)).count();
        if from_client >= MAX_PENDING_PER_CLIENT {
            return Err(err(ErrorCode::RateLimited, "too many pending logins; finish or wait for the others"));
        }
        if map.len() >= MAX_PENDING && !DeviceLogins::evict_for(&mut map, from_client) {
            return Err(err(ErrorCode::RateLimited, "too many pending logins; try again in a few minutes"));
        }
        let device_code = secret::new_token("mpdev");
        let code = user_code();
        map.insert(
            secret::sha256_hex(&device_code),
            Pending { user_code: code.clone(), agent_name: agent_name.trim().to_string(), client, created: Instant::now(), purpose, state: State::Waiting },
        );
        Ok((device_code, code))
    }

    /// The waiting request with this user code, for the approval page.
    pub fn device_request(&self, user_code: &str) -> Option<DeviceRequest> {
        let code = normalize_user_code(user_code);
        let mut map = self.devices.map.lock().unwrap();
        DeviceLogins::prune(&mut map);
        map.values().find(|p| p.user_code == code && matches!(p.state, State::Waiting)).map(|p| DeviceRequest {
            user_code: p.user_code.clone(),
            agent_name: p.agent_name.clone(),
            client: p.client,
            age_secs: p.created.elapsed().as_secs(),
            purpose: p.purpose,
        })
    }

    /// Approves or denies a waiting request. Approving `login` creates an enrollment token for
    /// `who`'s own machine, which publishes with their tags; approving `connect` makes a connect
    /// pass for them, for as long as a browser session lasts.
    pub fn answer_device_login(&self, who: &Principal, user_code: &str, approve: bool) -> Result<(), ErrorBody> {
        let Principal::User { id, .. } = who else {
            return Err(err(ErrorCode::Forbidden, "sign in with your user account to approve this"));
        };
        let code = normalize_user_code(user_code);
        let (agent_name, purpose) = {
            let mut map = self.devices.map.lock().unwrap();
            DeviceLogins::prune(&mut map);
            let pending = map.values().find(|p| p.user_code == code && matches!(p.state, State::Waiting));
            pending.map(|p| (p.agent_name.clone(), p.purpose)).ok_or_else(|| err(ErrorCode::NotFound, "this login code is unknown or has expired"))?
        };
        let state = match (approve, purpose) {
            (false, _) => State::Denied,
            (true, Purpose::Enroll) => {
                let opts = EnrollmentOptions { owner_user_id: Some(id.clone()), ..Default::default() };
                State::Approved(Granted { purpose, secret: self.create_enrollment(who, opts)?, expires_at: None })
            }
            (true, Purpose::Connect) => {
                let (secret, expires_at) = self.connect_pass(who, self.cfg.users.session_max_age_secs as i64)?;
                State::Approved(Granted { purpose, secret, expires_at: Some(expires_at) })
            }
        };
        let mut map = self.devices.map.lock().unwrap();
        if let Some(p) = map.values_mut().find(|p| p.user_code == code && matches!(p.state, State::Waiting)) {
            p.state = state;
        }
        drop(map);
        let action = match (approve, purpose) {
            (true, Purpose::Enroll) => "device.approve",
            (false, Purpose::Enroll) => "device.deny",
            (true, Purpose::Connect) => "connect.approve",
            (false, Purpose::Connect) => "connect.deny",
        };
        self.audit(who, action, &code, &agent_name);
        Ok(())
    }

    pub fn poll_device_login(&self, device_code: &str) -> DevicePoll {
        let key = secret::sha256_hex(device_code);
        let mut map = self.devices.map.lock().unwrap();
        DeviceLogins::prune(&mut map);
        match map.get(&key).map(|p| &p.state) {
            None => DevicePoll::Gone,
            Some(State::Waiting) => DevicePoll::Pending,
            Some(State::Denied) => {
                map.remove(&key);
                DevicePoll::Denied
            }
            Some(State::Approved(_)) => match map.remove(&key).map(|p| p.state) {
                Some(State::Approved(granted)) => DevicePoll::Approved(granted),
                _ => DevicePoll::Gone,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes() {
        let c = user_code();
        assert_eq!(c.len(), 9);
        assert!(c.bytes().all(|b| b == b'-' || CODE_ALPHABET.contains(&b)), "{c}");
        assert_eq!(normalize_user_code("abcd efgh"), "ABCD-EFGH");
        assert_eq!(normalize_user_code(&c.to_lowercase()), c);
    }

    #[tokio::test]
    async fn many_addresses_cannot_fill_the_table() {
        let f = crate::control::tests::fixture();
        // 200 /64s, five logins each: the table is full.
        for i in 0..MAX_PENDING / MAX_PENDING_PER_CLIENT {
            for _ in 0..MAX_PENDING_PER_CLIENT {
                f.cp.start_device_login("x", format!("2001:db8:0:{i:x}::1").parse().unwrap(), Purpose::Enroll).unwrap();
            }
        }
        // Someone else still gets in, at the expense of a client holding several.
        for i in 0..20u8 {
            f.cp.start_device_login("laptop", IpAddr::from([198, 51, 100, i]), Purpose::Enroll).unwrap();
        }
        let map = f.cp.devices.map.lock().unwrap();
        assert_eq!(map.len(), MAX_PENDING);
        assert_eq!(map.values().filter(|p| p.agent_name == "laptop").count(), 20);
    }
}
