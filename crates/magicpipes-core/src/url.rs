//! Percent-encoding, for both binaries.

use std::fmt::Write;

/// Percent-encodes everything but RFC 3986's unreserved characters, which makes it safe in a path
/// segment, a query value, a form field and a header's `filename*`.
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            // Writing to a String can't fail.
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// The value of the two hex digits at the start of `b`.
fn hex_pair(b: &[u8]) -> Option<u8> {
    let digit = |c: &u8| (*c as char).to_digit(16);
    Some((digit(b.first()?)? * 16 + digit(b.get(1)?)?) as u8)
}

/// Decodes strictly, for what must mean one exact thing (a file name): `None` for a malformed
/// escape, or a result that isn't UTF-8. A `+` stays a `+`.
pub fn decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            out.push(hex_pair(b.get(i + 1..)?)?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Decodes a form or query value as browsers send it: a `+` is a space, and a malformed escape or
/// invalid UTF-8 is kept as well as it can be rather than refused.
pub fn decode_form(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match (b[i], b.get(i + 1..).and_then(hex_pair)) {
            (b'%', Some(v)) => {
                out.push(v);
                i += 3;
            }
            (b'+', _) => {
                out.push(b' ');
                i += 1;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_keeps_only_unreserved_characters() {
        assert_eq!(encode("aZ09-._~"), "aZ09-._~");
        assert_eq!(encode("/p?q=1 2&r+é"), "%2Fp%3Fq%3D1%202%26r%2B%C3%A9");
        assert_eq!(encode(""), "");
    }

    #[test]
    fn what_is_encoded_comes_back() {
        for s in ["/p?q=1 2&r", "naïve café.txt", "a+b", "100%", "%41", "😀"] {
            assert_eq!(decode(&encode(s)).as_deref(), Some(s));
            assert_eq!(decode_form(&encode(s)), s);
        }
    }

    #[test]
    fn strict_decoding_refuses_what_is_malformed() {
        assert_eq!(decode("a%20b").as_deref(), Some("a b"));
        assert_eq!(decode("a+b").as_deref(), Some("a+b"), "a plus is only a space in a form");
        assert_eq!(decode("%2f").as_deref(), Some("/"), "either case of hex");
        for bad in ["%", "%2", "%zz", "a%2", "%+1", "%-1", "%c3", "%ff"] {
            assert_eq!(decode(bad), None, "{bad}");
        }
    }

    #[test]
    fn form_decoding_keeps_what_is_malformed() {
        assert_eq!(decode_form("a+b%20c"), "a b c");
        assert_eq!(decode_form("100%"), "100%");
        assert_eq!(decode_form("%zz%2"), "%zz%2");
        assert_eq!(decode_form("%+1"), "% 1");
        assert_eq!(decode_form("%ff"), "\u{fffd}");
    }
}
