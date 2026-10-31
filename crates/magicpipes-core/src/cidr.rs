//! Client network allow-lists for port tunnels (`--allow-cidr`): `10.0.0.0/8`, `2001:db8::/32`,
//! or a bare address. The agent validates them when a tunnel is added; the server enforces them
//! on every connection.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr.parse().map_err(|_| format!("'{s}' is not an IP address or CIDR range"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p.parse::<u8>().ok().filter(|p| *p <= max).ok_or_else(|| format!("'{s}': prefix must be 0-{max}"))?,
            None => max,
        };
        Ok(Self { addr: canonical(addr), prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => masked(u32::from(net).into(), self.prefix, 32) == masked(u32::from(ip).into(), self.prefix, 32),
            (IpAddr::V6(net), IpAddr::V6(ip)) => masked(u128::from(net), self.prefix, 128) == masked(u128::from(ip), self.prefix, 128),
            _ => false,
        }
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// IPv4 clients of a dual-stack listener arrive as `::ffff:a.b.c.d`.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

fn masked(bits: u128, prefix: u8, width: u32) -> u128 {
    if prefix == 0 { 0 } else { bits >> (width - u32::from(prefix)) }
}

/// Parses an allow-list (each entry displays in canonical `addr/prefix` form).
pub fn parse_list(items: &[String]) -> Result<Vec<Cidr>, String> {
    items.iter().map(|s| Cidr::parse(s)).collect()
}

/// Whether `ip` may connect: an empty list allows everyone.
pub fn allowed(list: &[Cidr], ip: IpAddr) -> bool {
    list.is_empty() || list.iter().any(|c| c.contains(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn matching() {
        let net = Cidr::parse("10.1.0.0/16").unwrap();
        assert!(net.contains(ip("10.1.200.3")) && !net.contains(ip("10.2.0.1")));
        assert!(net.contains(ip("::ffff:10.1.0.9")), "IPv4-mapped clients match IPv4 ranges");
        assert!(!net.contains(ip("2001:db8::1")));
        let host = Cidr::parse("203.0.113.7").unwrap();
        assert!(host.contains(ip("203.0.113.7")) && !host.contains(ip("203.0.113.8")));
        assert_eq!(host.to_string(), "203.0.113.7/32");
        let v6 = Cidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains(ip("2001:db8:ffff::1")) && !v6.contains(ip("2001:db9::1")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
        assert!(allowed(&[], ip("1.2.3.4")));
    }

    #[test]
    fn rejects_bad_input() {
        for bad in ["", "10.0.0.0/33", "::/129", "example.com", "10.0.0.0/x", "1.2.3"] {
            assert!(Cidr::parse(bad).is_err(), "{bad}");
        }
    }
}
