//! Sign-in codes from an authenticator app (`docs/USERS.md`, "Sign-in codes"): RFC 6238 TOTP with
//! HMAC-SHA1, 6 digits and 30-second steps, which is what every app does by default; recovery
//! codes for when the phone is gone; and the QR code an app scans to set itself up.

use magicpipes_core::secret;
use ring::rand::SecureRandom;

/// Seconds a code lasts.
const STEP_SECS: i64 = 30;
/// A key is 160 bits: HMAC-SHA1's own size, which RFC 4226 recommends and every app expects.
const KEY_BYTES: usize = 20;
/// Recovery codes made at once. Each works once.
pub const RECOVERY_CODES: usize = 10;
/// Characters of a recovery code: 16 from 32 is 80 bits, too many to try from a copy of the
/// database's digests.
const RECOVERY_CHARS: usize = 16;
/// Crockford's base 32: no i, l, o or u, so nothing is mistaken for something else.
const RECOVERY_ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// An authenticator app's key.
#[derive(Clone, PartialEq, Eq)]
pub struct Key(Vec<u8>);

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(…)")
    }
}

impl Key {
    pub fn generate() -> Self {
        let mut key = vec![0u8; KEY_BYTES];
        ring::rand::SystemRandom::new().fill(&mut key).expect("the system's randomness");
        Self(key)
    }

    /// As an app takes it typed in: base 32, without padding.
    pub fn text(&self) -> String {
        data_encoding::BASE32_NOPAD.encode(&self.0)
    }

    /// What [`Self::text`] wrote, from a form or the database.
    pub fn from_text(text: &str) -> Option<Self> {
        let key = data_encoding::BASE32_NOPAD.decode(text.as_bytes()).ok()?;
        (key.len() == KEY_BYTES).then_some(Self(key))
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        (bytes.len() == KEY_BYTES).then_some(Self(bytes))
    }

    /// The code for a 30-second step (RFC 4226's HOTP of the step number).
    fn code_at(&self, step: i64) -> u32 {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &self.0);
        let tag = ring::hmac::sign(&key, &step.to_be_bytes());
        let mac = tag.as_ref();
        // Dynamic truncation: the last byte's low bits say where four bytes are taken from.
        let at = usize::from(mac[mac.len() - 1] & 0x0f);
        let n = u32::from_be_bytes([mac[at] & 0x7f, mac[at + 1], mac[at + 2], mac[at + 3]]);
        n % 1_000_000
    }

    /// The step `code` is for, if it's now's or either one next to it (a clock a little off, a
    /// code typed as it changed) and later than `after`, the last one used: none works twice.
    pub fn matching_step(&self, code: &str, now: i64, after: i64) -> Option<i64> {
        let typed = six_digits(code)?;
        let current = now.div_euclid(STEP_SECS);
        let mut found = None;
        // Every step is computed, so the time taken says nothing about which matched.
        for step in [current - 1, current, current + 1] {
            let matches = secret::constant_time_eq(format!("{:06}", self.code_at(step)).as_bytes(), typed.as_bytes());
            if matches && step > after && found.is_none() {
                found = Some(step);
            }
        }
        found
    }

    /// The `otpauth://` address a QR code carries. `issuer` names the server in the app, and
    /// `account` the person.
    pub fn uri(&self, issuer: &str, account: &str) -> String {
        use magicpipes_core::url::encode;
        format!(
            "otpauth://totp/{label}?secret={key}&issuer={issuer}&algorithm=SHA1&digits=6&period={STEP_SECS}",
            label = encode(&format!("{issuer}:{account}")),
            key = self.text(),
            issuer = encode(issuer),
        )
    }
}

/// A code as typed, if it's six digits once spaces are gone.
fn six_digits(code: &str) -> Option<String> {
    let digits: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    (digits.len() == 6 && digits.bytes().all(|b| b.is_ascii_digit())).then_some(digits)
}

/// Does this look like an app's code rather than a recovery code?
pub fn is_app_code(code: &str) -> bool {
    six_digits(code).is_some()
}

/// New recovery codes, as shown: `xxxx-xxxx-xxxx-xxxx`.
pub fn new_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODES)
        .map(|_| {
            let mut bytes = [0u8; RECOVERY_CHARS];
            ring::rand::SystemRandom::new().fill(&mut bytes).expect("the system's randomness");
            let chars: Vec<char> = bytes.iter().map(|b| char::from(RECOVERY_ALPHABET[usize::from(b % 32)])).collect();
            chars.chunks(4).map(|c| c.iter().collect::<String>()).collect::<Vec<_>>().join("-")
        })
        .collect()
}

/// The digest a recovery code is kept as, however it was typed (case, dashes, spaces, and the
/// letters Crockford's alphabet leaves out for the digits they look like). `None` if it can't be one.
pub fn recovery_digest(typed: &str) -> Option<String> {
    let mut code = String::with_capacity(RECOVERY_CHARS);
    for c in typed.chars().filter(|c| !c.is_whitespace() && *c != '-') {
        let c = match c.to_ascii_lowercase() {
            'o' => '0',
            'i' | 'l' => '1',
            c => c,
        };
        if !c.is_ascii() || !RECOVERY_ALPHABET.contains(&(c as u8)) || code.len() == RECOVERY_CHARS {
            return None;
        }
        code.push(c);
    }
    (code.len() == RECOVERY_CHARS).then(|| secret::sha256_hex(&code))
}

/// `text` as a QR code in an SVG of its own, dark modules on a light ground whatever the page's
/// colors, as scanners expect. It's hidden from screen readers: the page says what it holds.
/// `None` if it's too long for one.
pub fn qr_svg(text: &str) -> Option<String> {
    let qr = qrcodegen::QrCode::encode_text(text, qrcodegen::QrCodeEcc::Medium).ok()?;
    let size = qr.size();
    // Four modules of quiet zone all round, as the standard asks.
    let edge = size + 8;
    let mut path = String::new();
    for y in 0..size {
        for x in 0..size {
            if qr.get_module(x, y) {
                path.push_str(&format!("M{} {}h1v1h-1z", x + 4, y + 4));
            }
        }
    }
    Some(format!(
        r#"<svg class="qr" viewBox="0 0 {edge} {edge}" aria-hidden="true" xmlns="http://www.w3.org/2000/svg"><rect width="{edge}" height="{edge}"/><path d="{path}"/></svg>"#
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_follow_rfc_6238() {
        // RFC 6238, appendix B, for SHA-1: its 8-digit codes end in these 6.
        let key = Key(b"12345678901234567890".to_vec());
        for (time, code) in [(59, "287082"), (1_111_111_109, "081804"), (1_111_111_111, "050471"), (1_234_567_890, "005924"), (2_000_000_000, "279037")] {
            assert_eq!(format!("{:06}", key.code_at(time / STEP_SECS)), code, "at {time}");
        }
        assert_eq!(key.text(), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(Key::from_text(&key.text()), Some(key.clone()));
        assert!(Key::from_text("GEZDGNBV").is_none(), "too short to be one of ours");
        assert!(Key::from_text("not base 32!").is_none());
    }

    #[test]
    fn a_code_works_near_its_time_and_once() {
        let key = Key::generate();
        let now = 1_700_000_015;
        let step = now / STEP_SECS;
        let code = |s: i64| format!("{:06}", key.code_at(s));
        assert_eq!(key.matching_step(&code(step), now, 0), Some(step));
        assert_eq!(key.matching_step(&code(step - 1), now, 0), Some(step - 1), "the one before, typed as it changed");
        assert_eq!(key.matching_step(&code(step + 1), now, 0), Some(step + 1), "a clock a little ahead");
        assert_eq!(key.matching_step(&code(step - 2), now, 0), None, "too old");
        assert_eq!(key.matching_step(&code(step), now, step), None, "used already");
        assert_eq!(key.matching_step(&code(step), now, step - 1), Some(step));
        let spaced = format!("{} {}", &code(step)[..3], &code(step)[3..]);
        assert_eq!(key.matching_step(&spaced, now, 0), Some(step), "as some apps show it");
        for bad in ["", "12345", "1234567", "abcdef"] {
            assert_eq!(key.matching_step(bad, now, 0), None, "{bad}");
        }
        assert!(is_app_code("123 456") && !is_app_code("abcd-efgh-jkmn-pqrs"));
    }

    #[test]
    fn recovery_codes_read_however_they_are_typed() {
        let codes = new_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODES);
        assert!(codes.iter().all(|c| c.len() == 19 && c.split('-').count() == 4), "{codes:?}");
        assert_ne!(codes[0], codes[1]);
        let digest = recovery_digest(&codes[0]).unwrap();
        assert_eq!(recovery_digest(&codes[0].to_uppercase()), Some(digest.clone()));
        assert_eq!(recovery_digest(&format!(" {} ", codes[0].replace('-', " "))), Some(digest));
        assert_eq!(recovery_digest("0000-1111-2222-3333"), recovery_digest("oOoO-iIlL-2222-3333"), "letters read as the digits they look like");
        for bad in ["", "abcd-efgh", "abcd-efgh-jkmn-pqrs-tvwx", "abcd-efgh-jkmn-pqru", "äbcd-efgh-jkmn-pqrs"] {
            assert!(recovery_digest(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn the_qr_code_carries_the_address() {
        let key = Key(b"12345678901234567890".to_vec());
        let uri = key.uri("MagicPipes (mp.example.com)", "ann@example.com");
        assert_eq!(
            uri,
            "otpauth://totp/MagicPipes%20%28mp.example.com%29%3Aann%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=MagicPipes%20%28mp.example.com%29&algorithm=SHA1&digits=6&period=30"
        );
        let svg = qr_svg(&uri).unwrap();
        assert!(svg.starts_with(r#"<svg class="qr" viewBox="0 0 "#) && svg.contains("<path d=\"M"), "{svg}");
        assert!(qr_svg(&"x".repeat(8000)).is_none(), "too long for a QR code");
    }
}
