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

use super::users::clean_name;
use super::{ControlPlane, OrLog, err, internal};
use crate::authz::Principal;
use crate::data::ssh::Connected;
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
                        Some(report) => me.gateway_report(report, &mut seen),
                        None => return,
                    },
                }
            }
        });
    }

    fn gateway_report(&self, r: Connected, seen: &mut HashMap<(String, String), Instant>) {
        if seen.len() >= MAX_REMEMBERED {
            seen.retain(|_, at| at.elapsed() < REPORT_EVERY);
            if seen.len() >= MAX_REMEMBERED {
                seen.clear();
            }
        }
        let pair = (r.key_id.clone(), r.tunnel_id.clone());
        if seen.get(&pair).is_some_and(|at| at.elapsed() < REPORT_EVERY) {
            return;
        }
        seen.insert(pair, Instant::now());
        self.store.touch_ssh_key(&r.key_id, unix_now()).or_log();
        if let Err(e) = self.store.audit(&r.user_id, "ssh.connect", &r.tunnel_id, &format!("key {} from {}", r.key_id, r.client)) {
            tracing::error!(error = %format!("{e:#}"), "could not write the audit log");
        }
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
