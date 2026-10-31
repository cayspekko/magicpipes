//! Secrets: random tokens, SHA-256 digests for storage, constant-time comparison.
//!
//! All tokens carry at least 192 bits of randomness, so an unsalted SHA-256 digest is an
//! adequate at-rest representation (there is nothing to brute-force).

use sha2::{Digest, Sha256};

const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// `len` random base62 characters (rejection sampling, no modulo bias).
pub fn random_string(len: usize) -> String {
    let mut out = String::with_capacity(len);
    while out.len() < len {
        let mut buf = [0u8; 64];
        getrandom::fill(&mut buf).expect("OS random number generator failed");
        for b in buf {
            // 248 = 62 * 4: values >= 248 would bias the distribution.
            if b < 248 && out.len() < len {
                out.push(ALPHABET[(b % 62) as usize] as char);
            }
        }
    }
    out
}

pub fn random_u64() -> u64 {
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).expect("OS random number generator failed");
    u64::from_le_bytes(buf)
}

/// Generates an identifier such as `tn_4f9Qx2LmT0aa`.
pub fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", random_string(14))
}

/// A secret token: `<prefix>_<43 base62 chars>` (~256 bits).
pub fn new_token(prefix: &str) -> String {
    format!("{prefix}_{}", random_string(43))
}

pub fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Compares `token` against a stored SHA-256 hex digest.
pub fn verify(token: &str, stored_hash: &str) -> bool {
    constant_time_eq(sha256_hex(token).as_bytes(), stored_hash.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens() {
        let t = new_token("mpa");
        assert!(t.starts_with("mpa_") && t.len() == 47);
        assert!(verify(&t, &sha256_hex(&t)));
        assert!(!verify("other", &sha256_hex(&t)));
        assert_ne!(new_token("x"), new_token("x"));
    }

    /// Stored token hashes must never change across dependency upgrades.
    #[test]
    fn sha256_known_answer() {
        assert_eq!(sha256_hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
