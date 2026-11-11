//! Public keys for the SSH gateway, and writing down what the gateway reports.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::ErrorBody;
use magicpipes_core::{rfc3339, unix_now};
use russh::keys::{Algorithm, HashAlg, PublicKey};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use magicpipes_core::proto::Kind;

use super::users::clean_name;
use super::{ControlPlane, OrLog, err, internal};
use crate::authz::{Action, Principal};
use crate::data::ssh::Report;
use crate::store::{AddedSshKey, NewSshKey, SshKeyRow};

/// A public key is one short line; this is for a pasted something else.
const MAX_KEY_CHARS: usize = 4096;

/// One person connecting again and again, as scripts and `rsync` loops do, is one line in the audit
/// log and one write for this long.
const REPORT_EVERY: Duration = Duration::from_secs(60);

/// Pairs of person and machine remembered for that; a sweep drops what has expired.
const MAX_REMEMBERED: usize = 10_000;

#[derive(Debug, Clone, Serialize)]
pub struct SshKeyView {
    pub id: String,
    pub name: String,
    pub algorithm: String,
    pub fingerprint: String,
    pub public_key: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
}

impl From<SshKeyRow> for SshKeyView {
    fn from(k: SshKeyRow) -> Self {
        Self {
            id: k.id,
            name: k.name,
            algorithm: k.algorithm,
            fingerprint: k.fingerprint,
            public_key: k.public_key,
            created_at: rfc3339(k.created_at),
            last_used_at: k.last_used_at.map(rfc3339),
        }
    }
}

/// A browser terminal or remote desktop someone may open (see `data::terminal`, `data::desktop`).
#[derive(Debug, Clone)]
pub struct TerminalTarget {
    pub user_id: String,
    pub email: String,
    pub tunnel_id: String,
    pub name: String,
}

/// How people reach the SSH gateway, when it's on.
#[derive(Debug, Clone)]
pub struct SshGateway {
    /// `host:port`, as `ssh -J` wants it.
    pub address: String,
    pub fingerprint: String,
}

/// Does this look like a private key? It must then not be shown back, stored or logged.
pub fn looks_private(text: &str) -> bool {
    text.contains("PRIVATE KEY")
}

/// Reads one key in `authorized_keys` form: its canonical text without the comment, and the comment.
fn parse_key(text: &str) -> Result<(PublicKey, String), ErrorBody> {
    let invalid = |m: &str| err(ErrorCode::InvalidSshKey, m);
    if looks_private(text) {
        return Err(invalid("That's a private key, which never leaves your machine. Paste the public one instead: the file ending in .pub."));
    }
    let text = text.trim();
    if text.is_empty() || text.chars().count() > MAX_KEY_CHARS || text.lines().count() != 1 {
        return Err(invalid("Paste one public key, on one line: the contents of a file such as ~/.ssh/id_ed25519.pub."));
    }
    let key = PublicKey::from_openssh(text).map_err(|_| invalid("That isn't a public key. It should start with ssh-ed25519 or ecdsa-sha2-."))?;
    if !matches!(key.algorithm(), Algorithm::Ed25519 | Algorithm::Ecdsa { .. }) {
        return Err(invalid("This server takes Ed25519 and ECDSA keys. Make one with: ssh-keygen -t ed25519"));
    }
    let comment = String::from_utf8_lossy(key.comment().as_bytes()).into_owned();
    Ok((key, comment))
}

impl ControlPlane {
    /// The keys of the logged-in user.
    pub fn ssh_keys(&self, who: &Principal) -> Vec<SshKeyView> {
        match who {
            Principal::User { id, .. } => self.store.user_ssh_keys(id).or_log().unwrap_or_default().into_iter().map(Into::into).collect(),
            _ => Vec::new(),
        }
    }

    pub fn add_ssh_key(&self, who: &Principal, name: &str, text: &str) -> Result<SshKeyView, ErrorBody> {
        let Principal::User { id, .. } = who else {
            return Err(err(ErrorCode::InvalidRequest, "SSH keys belong to a user; sign in with your account"));
        };
        let (mut key, comment) = parse_key(text)?;
        let name = clean_name(if name.trim().is_empty() { &comment } else { name }, 64);
        let name = if name.is_empty() { "SSH key".to_string() } else { name };
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        key.set_comment("");
        let public_key = key.to_openssh().map_err(|_| err(ErrorCode::InvalidSshKey, "That public key can't be read back."))?;
        let algorithm = key.algorithm();
        let new = NewSshKey { user_id: id, name: &name, algorithm: algorithm.as_str(), fingerprint: &fingerprint, public_key: public_key.trim() };
        let row = match self.store.add_ssh_key(&new).map_err(internal)? {
            AddedSshKey::Added(row) => row,
            AddedSshKey::Full => return Err(err(ErrorCode::LimitReached, "An account can hold 20 SSH keys. Delete one you no longer use first.")),
            AddedSshKey::Taken => return Err(err(ErrorCode::SshKeyTaken, "That key is already on an account. A key stands for one person, so each needs their own.")),
        };
        self.audit(who, "ssh_key.add", &row.id, &fingerprint);
        self.refresh();
        Ok(row.into())
    }

    /// Deletes one of the logged-in user's keys, which also closes connections that used it.
    /// Returns false if they have no such key.
    pub fn delete_ssh_key(&self, who: &Principal, id: &str) -> Result<bool, ErrorBody> {
        let Principal::User { id: user, .. } = who else { return Ok(false) };
        if !self.store.delete_ssh_key(user, id).map_err(internal)? {
            return Ok(false);
        }
        self.audit(who, "ssh_key.delete", id, "");
        self.refresh();
        Ok(true)
    }

    /// How to reach the SSH gateway; `None` unless it's on.
    pub fn ssh_gateway(&self) -> Option<SshGateway> {
        Some(SshGateway { address: self.cfg.ssh_address()?, fingerprint: self.data.ssh_fingerprint()?.to_string() })
    }

    /// Writes down what the gateway reports, on the control threads, so that connecting doesn't
    /// wait for the database.
    pub(super) fn start_gateway_reports(self: &Arc<Self>, shutdown: CancellationToken) {
        let Some(mut reports) = self.data.take_ssh_reports() else { return };
        let me = self.clone();
        tokio::spawn(async move {
            let mut seen: HashMap<(String, String), Instant> = HashMap::new();
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    report = reports.recv() => match report {
                        Some(Report::Connected { user_id, key_id, tunnel_id, client }) => {
                            if me.first_in_a_while(&mut seen, &key_id, &tunnel_id) {
                                me.store.touch_ssh_key(&key_id, unix_now()).or_log();
                                me.audit_as(&user_id, "ssh.connect", &tunnel_id, &format!("key {key_id} from {client}"));
                            }
                        }
                        Some(Report::Terminal { user_id, tunnel_id, login, client }) => {
                            if me.first_in_a_while(&mut seen, &format!("{user_id} {login}"), &tunnel_id) {
                                me.audit_as(&user_id, "ssh.terminal", &tunnel_id, &format!("as {login} from {client}"));
                            }
                        }
                        Some(Report::HostKey { tunnel_id, fingerprint }) => me.keep_host_key(&tunnel_id, &fingerprint),
                        Some(Report::KeyRefused { tunnel_id }) => me.alerts.lock().unwrap().key_refused(&tunnel_id, unix_now()),
                        Some(Report::Connect { user_id, tunnel_id, client }) => {
                            if me.first_in_a_while(&mut seen, &user_id, &tunnel_id) {
                                me.audit_as(&user_id, "tunnel.connect", &tunnel_id, &format!("from {client}"));
                            }
                        }
                        Some(Report::Desktop { user_id, tunnel_id, client, kind }) => {
                            if me.first_in_a_while(&mut seen, &format!("{user_id} desktop"), &tunnel_id) {
                                me.audit_as(&user_id, &format!("{kind}.desktop"), &tunnel_id, &format!("from {client}"));
                            }
                        }
                        None => return,
                    },
                }
            }
        });
    }

    /// Whether `who` reaching `tunnel` is worth writing down: not if they did within [`REPORT_EVERY`].
    fn first_in_a_while(&self, seen: &mut HashMap<(String, String), Instant>, who: &str, tunnel: &str) -> bool {
        if seen.len() >= MAX_REMEMBERED {
            seen.retain(|_, at| at.elapsed() < REPORT_EVERY);
            if seen.len() >= MAX_REMEMBERED {
                seen.clear();
            }
        }
        let pair = (who.to_string(), tunnel.to_string());
        if seen.get(&pair).is_some_and(|at| at.elapsed() < REPORT_EVERY) {
            return false;
        }
        seen.insert(pair, Instant::now());
        true
    }

    fn audit_as(&self, user_id: &str, action: &str, resource: &str, detail: &str) {
        if let Err(e) = self.store.audit(user_id, action, resource, detail) {
            tracing::error!(error = %format!("{e:#}"), "could not write the audit log");
        }
    }

    /// Keeps the first host key a tunnel's machine showed, unless one is kept already.
    fn keep_host_key(&self, tunnel_id: &str, fingerprint: &str) {
        let mut st = self.state.lock().unwrap();
        if st.host_keys.contains_key(tunnel_id) || !st.tunnels.contains_key(tunnel_id) {
            return;
        }
        if self.store.keep_ssh_host_key(tunnel_id, fingerprint).or_log() == Some(true) {
            tracing::info!(tunnel = %tunnel_id, %fingerprint, "kept the host key of a tunnel's machine");
            st.host_keys.insert(tunnel_id.to_string(), fingerprint.to_string());
            self.publish(&st);
        }
    }

    /// Who may open a browser terminal on the SSH tunnel `name`: a signed-in person who may reach
    /// it, with the gateway on. `None` otherwise, whatever the reason.
    pub fn terminal(&self, who: &Principal, name: &str) -> Option<TerminalTarget> {
        let Principal::User { id, .. } = who else { return None };
        self.data.ssh_ca_public()?;
        let st = self.state.lock().unwrap();
        let t = st.tunnels.values().find(|t| t.row.name == name && t.row.kind == Kind::Ssh)?;
        if !st.dir.agent_active(&t.row.agent_id) || !st.may(who, Action::Connect, t) {
            return None;
        }
        Some(TerminalTarget { user_id: id.clone(), email: st.dir.email(id)?.to_string(), tunnel_id: t.row.id.clone(), name: t.row.name.clone() })
    }

    /// Who may open the remote desktop (RDP or VNC) of the tunnel `name`: a signed-in person who
    /// may reach it, and which kind it is. `None` otherwise, whatever the reason.
    pub fn desktop(&self, who: &Principal, name: &str) -> Option<(TerminalTarget, Kind)> {
        let Principal::User { id, .. } = who else { return None };
        let st = self.state.lock().unwrap();
        let t = st.tunnels.values().find(|t| t.row.name == name && t.row.kind.is_desktop())?;
        if !st.dir.agent_active(&t.row.agent_id) || !st.may(who, Action::Connect, t) {
            return None;
        }
        let target = TerminalTarget { user_id: id.clone(), email: st.dir.email(id)?.to_string(), tunnel_id: t.row.id.clone(), name: t.row.name.clone() };
        Some((target, t.row.kind))
    }

    /// The certificate authority's public key, as a line for sshd; `None` unless the gateway is on.
    pub fn ssh_ca(&self) -> Option<String> {
        self.data.ssh_ca_public()
    }

    /// Forgets the host key kept for a tunnel's machine, for its owner or an administrator.
    /// Returns false if there's no such tunnel for them, or no key kept.
    /// Forgets the SSH host key or RDP certificate kept for a tunnel; says which kind it was.
    pub fn forget_host_key(&self, who: &Principal, id: &str) -> Result<Option<Kind>, ErrorBody> {
        let mut st = self.state.lock().unwrap();
        let Some(kind) = st.tunnels.get(id).filter(|t| st.may(who, Action::Manage, t)).map(|t| t.row.kind) else {
            return Ok(None);
        };
        if !self.store.forget_ssh_host_key(id).map_err(internal)? {
            return Ok(None);
        }
        st.host_keys.remove(id);
        self.publish(&st);
        drop(st);
        self.alerts.lock().unwrap().key_forgotten(id);
        self.audit(who, if kind == Kind::Rdp { "rdp.certificate.forget" } else { "ssh.host_key.forget" }, id, "");
        Ok(Some(kind))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl laptop";

    #[test]
    fn keys_are_read_from_one_line() {
        let (key, comment) = parse_key(&format!("  {ED25519}\n")).unwrap();
        assert_eq!(key.algorithm(), Algorithm::Ed25519);
        assert_eq!(comment, "laptop");
        for bad in ["", "   ", "hello", "ssh-ed25519", "ssh-ed25519 not-base64", &format!("{ED25519}\n{ED25519}"), &"a".repeat(MAX_KEY_CHARS + 1)] {
            assert!(parse_key(bad).unwrap_err().is(ErrorCode::InvalidSshKey), "{bad}");
        }
    }

    #[test]
    fn a_private_key_is_refused_without_repeating_it() {
        let e = parse_key("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----").unwrap_err();
        assert!(e.is(ErrorCode::InvalidSshKey));
        assert!(e.message.contains("private key") && !e.message.contains("b3Blbn"), "{}", e.message);
    }

    #[test]
    fn rsa_keys_are_refused_with_what_to_do() {
        // A real key's shape, 2048 bits: exponent 65537, and a modulus that needn't be anyone's.
        let mut blob = Vec::new();
        for part in [b"ssh-rsa".as_slice(), &[1, 0, 1], &[&[0u8][..], &[0xc5u8; 256][..]].concat()] {
            blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
            blob.extend_from_slice(part);
        }
        use base64::Engine;
        let line = format!("ssh-rsa {}", base64::engine::general_purpose::STANDARD.encode(blob));
        let e = parse_key(&line).unwrap_err();
        assert!(e.is(ErrorCode::InvalidSshKey));
        assert!(e.message.contains("ssh-keygen") || e.message.contains("isn't a public key"), "{}", e.message);
    }
}
