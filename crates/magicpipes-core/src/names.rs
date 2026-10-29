//! Tunnel names are the first DNS label of the public hostname (`<name>.<base_domain>`).

use crate::secret::random_u64;

pub const MAX_NAME_LEN: usize = 40;

/// Labels that are never assigned to tunnels.
const RESERVED: &[&str] = &[
    "www", "api", "admin", "mgmt", "manage", "management", "dashboard", "agent", "agents", "mail",
    "smtp", "ns", "ns1", "ns2", "localhost", "magicpipes", "status", "acme", "_acme-challenge",
];

/// Validates a user-supplied tunnel name. Returns the normalized (lowercase) name.
pub fn validate(name: &str) -> Result<String, String> {
    let name = name.trim().to_ascii_lowercase();
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(format!("name must be 1-{MAX_NAME_LEN} characters"));
    }
    if !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
        return Err("name may only contain letters, digits and '-'".into());
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err("name must not start or end with '-'".into());
    }
    if name.starts_with("xn--") || name.get(2..4) == Some("--") {
        return Err("name must not look like an IDN label".into());
    }
    if RESERVED.contains(&name.as_str()) {
        return Err(format!("'{name}' is reserved"));
    }
    Ok(name)
}

const ADJECTIVES: &[&str] = &[
    "amber", "bold", "brave", "bright", "calm", "clever", "cosmic", "crisp", "daring", "eager",
    "fancy", "fluffy", "gentle", "golden", "happy", "humble", "jolly", "keen", "lively", "lucky",
    "mellow", "merry", "mighty", "nimble", "noble", "plucky", "proud", "quick", "quiet", "rapid",
    "rosy", "shiny", "silent", "silver", "sleek", "smooth", "snappy", "sunny", "swift", "tidy",
    "upbeat", "vivid", "warm", "witty", "zesty",
];

const ANIMALS: &[&str] = &[
    "badger", "beaver", "bison", "crane", "dingo", "dolphin", "eagle", "falcon", "ferret", "finch",
    "fox", "gecko", "heron", "ibis", "jaguar", "koala", "lemur", "lynx", "marmot", "moose",
    "narwhal", "newt", "ocelot", "orca", "otter", "owl", "panda", "panther", "puffin", "quokka",
    "raven", "robin", "salmon", "seal", "sparrow", "stoat", "swan", "tapir", "tiger", "toucan",
    "turtle", "walrus", "wombat", "yak", "zebra",
];

/// A random `adjective-animal` name. After `attempt` collisions a random suffix is appended.
pub fn random(attempt: u32) -> String {
    let r = random_u64();
    let adj = ADJECTIVES[(r % ADJECTIVES.len() as u64) as usize];
    let animal = ANIMALS[((r >> 16) % ANIMALS.len() as u64) as usize];
    if attempt < 3 {
        format!("{adj}-{animal}")
    } else {
        format!("{adj}-{animal}-{:04x}", (r >> 40) & 0xffff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation() {
        assert_eq!(validate("MyApp").unwrap(), "myapp");
        assert!(validate("my-app-2").is_ok());
        assert!(validate("").is_err());
        assert!(validate("-a").is_err());
        assert!(validate("a.b").is_err());
        assert!(validate("www").is_err());
        assert!(validate("xn--abc").is_err());
        assert!(validate(&"a".repeat(41)).is_err());
    }

    #[test]
    fn random_names_are_valid() {
        for i in 0..50 {
            validate(&random(i % 5)).unwrap();
        }
    }
}
