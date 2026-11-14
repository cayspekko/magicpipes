//! Releases: what's published, and whether to trust it.
//!
//! Each release carries a manifest, `release.json`, listing a binary per platform with its address
//! and SHA-256, and `release.json.sig`, an Ed25519 signature of the manifest's exact bytes made by
//! the release workflow. A binary trusts only the keys built into it ([`RELEASE_KEYS`]), installs
//! only a binary for its own platform ([`TARGET`]) from a manifest one of them signed, and only a
//! version newer than its own. Fetching and installing are in [`crate::upgrade`].

use std::cmp::Ordering;
use std::fmt;

use base64::Engine;
use serde::{Deserialize, Serialize};

/// Where releases are read from unless configured otherwise: the latest GitHub release's files.
pub const DEFAULT_SOURCE: &str = "https://github.com/cayspekko/magicpipes/releases/latest/download/";
pub const MANIFEST: &str = "release.json";
pub const SIGNATURE: &str = "release.json.sig";
/// A manifest bigger than this isn't one.
pub const MAX_MANIFEST: u64 = 256 * 1024;
/// Nor is a binary bigger than this.
pub const MAX_BINARY: u64 = 256 * 1024 * 1024;

/// The public halves of the keys releases are signed with: Ed25519, 32 bytes, base64.
/// `scripts/release-key.sh` makes the key and prints the line to add here. Empty, this build
/// trusts no release, and can't upgrade itself.
pub const RELEASE_KEYS: &[&str] = &[];

/// In a debug build only (tests), one more key to trust, base64: never in a release build.
pub const TEST_KEY_ENV: &str = "MAGICPIPES_TEST_RELEASE_KEY";

/// The platform this binary was built for, as releases name it; `None` where there's no release.
pub const TARGET: Option<&str> = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
    // Static binaries, which run on any Linux.
    Some("x86_64-unknown-linux-musl")
} else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
    Some("aarch64-unknown-linux-musl")
} else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
    Some("aarch64-apple-darwin")
} else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
    Some("x86_64-pc-windows-msvc")
} else {
    None
};

/// What a release publishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    /// Where to read what changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// The release fixes a security problem: servers raise an alert until they have it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub security: bool,
    pub files: Vec<ReleaseFile>,
}

/// One binary for one platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseFile {
    pub target: String,
    /// `magicpipes` or `magicpipesd`.
    pub binary: String,
    pub url: String,
    /// Lowercase hex.
    pub sha256: String,
    pub size: u64,
}

impl Manifest {
    /// The `binary` for this platform, if the release has one.
    pub fn file(&self, binary: &str) -> Option<&ReleaseFile> {
        let target = TARGET?;
        self.files.iter().find(|f| f.target == target && f.binary == binary)
    }

    pub fn parsed_version(&self) -> Option<Version> {
        Version::parse(&self.version)
    }
}

/// The keys this binary trusts.
pub fn trusted_keys() -> Vec<[u8; 32]> {
    let mut keys: Vec<[u8; 32]> = RELEASE_KEYS.iter().filter_map(|k| decode_key(k)).collect();
    if cfg!(debug_assertions)
        && let Some(k) = std::env::var(TEST_KEY_ENV).ok().and_then(|k| decode_key(&k))
    {
        keys.push(k);
    }
    keys
}

fn decode_key(b64: &str) -> Option<[u8; 32]> {
    base64::engine::general_purpose::STANDARD.decode(b64.trim()).ok()?.try_into().ok()
}

/// Why a manifest isn't trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Untrusted {
    /// This build trusts no key.
    NoKeys,
    /// No trusted key made this signature.
    BadSignature,
    /// Signed, but not a manifest this build can read.
    Unreadable(String),
}

impl fmt::Display for Untrusted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Untrusted::NoKeys => f.write_str("this build trusts no release key, so it can't check a release"),
            Untrusted::BadSignature => f.write_str("the release's signature doesn't match a key this build trusts"),
            Untrusted::Unreadable(e) => write!(f, "the release's manifest can't be read: {e}"),
        }
    }
}

/// The manifest in `manifest`, if one of `keys` signed exactly these bytes. `signature` is the
/// 64-byte signature, raw or in base64 (as `release.json.sig` holds it).
pub fn verify(manifest: &[u8], signature: &[u8], keys: &[[u8; 32]]) -> Result<Manifest, Untrusted> {
    if keys.is_empty() {
        return Err(Untrusted::NoKeys);
    }
    let raw = if signature.len() == 64 {
        signature.to_vec()
    } else {
        let text = std::str::from_utf8(signature).map_err(|_| Untrusted::BadSignature)?;
        base64::engine::general_purpose::STANDARD.decode(text.trim()).map_err(|_| Untrusted::BadSignature)?
    };
    let signed = keys.iter().any(|k| ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, k).verify(manifest, &raw).is_ok());
    if !signed {
        return Err(Untrusted::BadSignature);
    }
    let m: Manifest = serde_json::from_slice(manifest).map_err(|e| Untrusted::Unreadable(e.to_string()))?;
    if m.parsed_version().is_none() {
        return Err(Untrusted::Unreadable(format!("'{}' isn't a version", m.version)));
    }
    Ok(m)
}

/// `MAJOR.MINOR.PATCH`, with an optional `-pre` part that sorts before the release it precedes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: Option<String>,
}

impl Version {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let s = s.strip_prefix('v').unwrap_or(s);
        let (core, pre) = match s.split_once('-') {
            Some((c, p)) if !p.is_empty() => (c, Some(p.to_string())),
            Some(_) => return None,
            None => (s, None),
        };
        let mut parts = core.split('.');
        let mut next = || parts.next().filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())).and_then(|p| p.parse().ok());
        let v = Version { major: next()?, minor: next()?, patch: next()?, pre };
        if parts.next().is_some() {
            return None;
        }
        Some(v)
    }

    /// This build's version.
    pub fn current() -> Self {
        Self::parse(crate::VERSION).unwrap_or(Version { major: 0, minor: 0, patch: 0, pre: None })
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch)).then_with(|| match (&self.pre, &other.pre) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => a.cmp(b),
        })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(p) = &self.pre {
            write!(f, "-{p}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::*;

    /// A key pair for signing test manifests.
    pub(crate) fn key() -> Ed25519KeyPair {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    pub(crate) fn public(k: &Ed25519KeyPair) -> [u8; 32] {
        k.public_key().as_ref().try_into().unwrap()
    }

    fn manifest(version: &str) -> Vec<u8> {
        serde_json::to_vec(&Manifest {
            version: version.into(),
            notes: None,
            security: false,
            files: vec![ReleaseFile { target: TARGET.unwrap_or("none").into(), binary: "magicpipes".into(), url: "https://x/magicpipes".into(), sha256: "00".into(), size: 1 }],
        })
        .unwrap()
    }

    #[test]
    fn only_a_trusted_key_signing_these_exact_bytes_is_believed() {
        let (signer, other) = (key(), key());
        let body = manifest("1.2.3");
        let sig = signer.sign(&body);
        let b64 = base64::engine::general_purpose::STANDARD.encode(sig.as_ref());

        let m = verify(&body, sig.as_ref(), &[public(&signer)]).unwrap();
        assert_eq!(m.version, "1.2.3");
        assert_eq!(verify(&body, format!("{b64}\n").as_bytes(), &[public(&other), public(&signer)]).unwrap(), m, "base64, any trusted key");
        assert_eq!(verify(&body, sig.as_ref(), &[public(&other)]), Err(Untrusted::BadSignature));
        assert_eq!(verify(&body, sig.as_ref(), &[]), Err(Untrusted::NoKeys));
        let mut changed = body.clone();
        changed[12] ^= 1;
        assert_eq!(verify(&changed, sig.as_ref(), &[public(&signer)]), Err(Untrusted::BadSignature));
        assert_eq!(verify(&body, b"not a signature", &[public(&signer)]), Err(Untrusted::BadSignature));

        // Signed, but nothing a binary could act on.
        let odd = manifest("one.two");
        assert!(matches!(verify(&odd, signer.sign(&odd).as_ref(), &[public(&signer)]), Err(Untrusted::Unreadable(_))));
    }

    #[test]
    fn versions_compare_by_number_and_a_pre_release_comes_first() {
        let v = |s: &str| Version::parse(s).unwrap();
        assert!(v("0.1.10") > v("0.1.9"));
        assert!(v("1.0.0") > v("0.99.99"));
        assert!(v("0.2.0") > v("0.2.0-rc.1"));
        assert!(v("0.2.0-rc.2") > v("0.2.0-rc.1"));
        assert_eq!(v("v0.1.1"), v("0.1.1"));
        assert_eq!(v("1.2.3-beta").to_string(), "1.2.3-beta");
        for bad in ["", "1", "1.2", "1.2.3.4", "1.x.3", "1.2.3-", "-1.2.3", "1..3"] {
            assert_eq!(Version::parse(bad), None, "{bad}");
        }
        assert!(Version::parse(crate::VERSION).is_some(), "this build's version parses");
    }

    #[test]
    fn the_release_key_list_holds_only_real_keys() {
        for k in RELEASE_KEYS {
            assert!(decode_key(k).is_some(), "{k} isn't a 32-byte key in base64");
        }
    }
}
