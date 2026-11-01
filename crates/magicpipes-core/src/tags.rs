//! Tag syntax, shared by access tags and labels (docs/USERS.md, "Access tags and labels").
//!
//! A tag is `key` or `key:value`: lowercase ASCII letters, digits and `._-`, starting with a
//! letter or digit; the value may also contain `@`. At most 64 bytes. Matching is exact string
//! equality after [`normalize`], with no wildcards.

pub const MAX_LEN: usize = 64;

/// Lowercases and checks a tag; returns it or a message for the user.
pub fn normalize(tag: &str) -> Result<String, String> {
    let t = tag.trim().to_ascii_lowercase();
    let bad = || format!("'{}' is not a valid tag: use key or key:value with a-z, 0-9 and ._- (at most {MAX_LEN} characters)", tag.trim());
    if t.is_empty() || t.len() > MAX_LEN {
        return Err(bad());
    }
    let (key, value) = match t.split_once(':') {
        Some((k, v)) => (k, Some(v)),
        None => (t.as_str(), None),
    };
    let word = |s: &str, extra: &[u8]| {
        s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
            && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b) || extra.contains(&b))
    };
    if !word(key, b"") || value.is_some_and(|v| !word(v, b"@")) {
        return Err(bad());
    }
    Ok(t)
}

/// Normalizes a list (comma- or whitespace-separated entries allowed), sorted, without
/// duplicates.
pub fn normalize_list<S: AsRef<str>>(tags: &[S]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for t in tags.iter().flat_map(|t| t.as_ref().split([',', ' ']).filter(|s| !s.trim().is_empty()).map(str::to_string).collect::<Vec<_>>()) {
        out.push(normalize(&t)?);
    }
    out.sort();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syntax() {
        for (input, want) in [("team:dev", "team:dev"), (" Team:Dev ", "team:dev"), ("ops", "ops"), ("domain:a.b@c.d", "domain:a.b@c.d"), ("env:prod-1", "env:prod-1")] {
            assert_eq!(normalize(input).unwrap(), want, "{input}");
        }
        for bad in ["", ":dev", "team:", "-x", "team:dev:x", "team dev", "tëam", "a@b", "team:_x", &"x".repeat(65)] {
            assert!(normalize(bad).is_err(), "{bad}");
        }
        assert_eq!(normalize_list(&["b, a", "a", " c "]).unwrap(), ["a", "b", "c"]);
        assert!(normalize_list(&["ok, not ok!"]).is_err());
    }
}
