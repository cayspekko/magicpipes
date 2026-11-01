//! `magicpipes login` without a token: the CLI asks for a login code, the user approves it in the
//! browser while signed in, and the CLI receives a personal enrollment token for that user
//! (OAuth's device authorization flow, minus OAuth).
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
use magicpipes_core::secret;

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

struct Pending {
    user_code: String,
    agent_name: String,
    client: IpAddr,
    created: Instant,
    state: State,
}

enum State {
    Waiting,
    Approved(String),
    Denied,
}

/// What the approval page shows.
pub struct DeviceRequest {
    pub user_code: String,
    pub agent_name: String,
    pub client: IpAddr,
    pub age_secs: u64,
}

pub enum DevicePoll {
    Pending,
    /// The enrollment token, handed out once.
    Approved(String),
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
}

impl ControlPlane {
    /// Starts a login for a machine. Returns `(device code, user code)`.
    pub fn start_device_login(&self, agent_name: &str, client: IpAddr) -> Result<(String, String), ErrorBody> {
        let agent_name: String = agent_name.chars().filter(|c| !c.is_control()).take(64).collect();
        let mut map = self.devices.map.lock().unwrap();
        DeviceLogins::prune(&mut map);
        let from_client = map.values().filter(|p| client_key(p.client) == client_key(client)).count();
        if map.len() >= MAX_PENDING || from_client >= MAX_PENDING_PER_CLIENT {
            return Err(err(ErrorCode::RateLimited, "too many pending logins; finish or wait for the others"));
        }
        let device_code = secret::new_token("mpdev");
        let code = user_code();
        map.insert(
            secret::sha256_hex(&device_code),
            Pending { user_code: code.clone(), agent_name: agent_name.trim().to_string(), client, created: Instant::now(), state: State::Waiting },
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
        })
    }

    /// Approves (with `Some(tags)`) or denies a waiting request. Approving creates an
    /// enrollment token for `who`'s own machine with those tags.
    pub fn answer_device_login(&self, who: &Principal, user_code: &str, approve: Option<Vec<String>>) -> Result<(), ErrorBody> {
        let Principal::User { id, .. } = who else {
            return Err(err(ErrorCode::Forbidden, "sign in with your user account to enroll your own machine"));
        };
        let code = normalize_user_code(user_code);
        let agent_name = {
            let mut map = self.devices.map.lock().unwrap();
            DeviceLogins::prune(&mut map);
            let pending = map.values().find(|p| p.user_code == code && matches!(p.state, State::Waiting));
            pending.map(|p| p.agent_name.clone()).ok_or_else(|| err(ErrorCode::NotFound, "this login code is unknown or has expired"))?
        };
        let state = match approve {
            Some(tags) => {
                let opts = EnrollmentOptions { owner_user_id: Some(id.clone()), tags, ..Default::default() };
                State::Approved(self.create_enrollment(who, opts)?)
            }
            None => State::Denied,
        };
        let approved = matches!(state, State::Approved(_));
        let mut map = self.devices.map.lock().unwrap();
        if let Some(p) = map.values_mut().find(|p| p.user_code == code && matches!(p.state, State::Waiting)) {
            p.state = state;
        }
        drop(map);
        self.audit(who, if approved { "device.approve" } else { "device.deny" }, &code, &agent_name);
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
                Some(State::Approved(token)) => DevicePoll::Approved(token),
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
}
