//! Client addresses behind reverse proxies. Only peers in `trusted_proxies` may say who the
//! client is (X-Forwarded-For on the HTTPS listeners, a PROXY header on port tunnels); for any
//! other peer, the peer is the client and forwarding headers it sends are discarded.

use std::net::{IpAddr, SocketAddr};

use http::HeaderMap;
use magicpipes_core::cidr::Cidr;

pub const FORWARDED_FOR: &str = "x-forwarded-for";

#[derive(Debug, Clone, Default)]
pub struct TrustedProxies(Vec<Cidr>);

impl TrustedProxies {
    pub fn new(list: Vec<Cidr>) -> Self {
        Self(list)
    }

    /// An empty list trusts nobody (unlike a tunnel allow-list, where empty means anyone).
    pub fn trusts(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|c| c.contains(ip))
    }

    /// The client's address: `peer` unless it is a trusted proxy, then the right-most
    /// X-Forwarded-For entry that is not one. Entries to the left of that were written by the
    /// client and prove nothing.
    pub fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let mut client = peer.to_canonical();
        if !self.trusts(client) {
            return client;
        }
        for entry in forwarded_for(headers).iter().rev() {
            let Some(ip) = parse_entry(entry) else { break };
            client = ip;
            if !self.trusts(client) {
                break;
            }
        }
        client
    }

    /// Rewrites forwarding headers for a request about to be passed to a tunnel. A trusted
    /// proxy's X-Forwarded-For chain is kept and the peer appended; from anyone else, all
    /// client-supplied forwarding headers are dropped and the chain starts at the peer.
    pub fn rewrite(&self, peer: IpAddr, headers: &mut HeaderMap) {
        let peer = peer.to_canonical();
        let mut chain = if self.trusts(peer) { forwarded_for(headers) } else { Vec::new() };
        if !self.trusts(peer) {
            headers.remove("forwarded");
            headers.remove("x-real-ip");
        }
        chain.push(peer.to_string());
        headers.remove(FORWARDED_FOR);
        if let Ok(v) = chain.join(", ").parse() {
            headers.insert(FORWARDED_FOR, v);
        }
    }
}

/// The unit for per-client limits: the address, or its /64 for IPv6 (one client usually
/// controls a whole /64).
pub fn client_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !u128::from(u64::MAX)).into()),
        v4 => v4,
    }
}

/// All X-Forwarded-For entries in order, across repeated header lines.
fn forwarded_for(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(FORWARDED_FOR)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// `1.2.3.4`, `2001:db8::1`, or either with a port (`1.2.3.4:80`, `[2001:db8::1]:80`).
fn parse_entry(s: &str) -> Option<IpAddr> {
    s.parse::<IpAddr>().ok().or_else(|| s.parse::<SocketAddr>().ok().map(|a| a.ip())).map(|ip| ip.to_canonical())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trusted() -> TrustedProxies {
        TrustedProxies::new(vec![Cidr::parse("172.16.0.0/12").unwrap()])
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn xff(lines: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for l in lines {
            h.append(FORWARDED_FOR, l.parse().unwrap());
        }
        h
    }

    #[test]
    fn client_ip_trusts_only_listed_proxies() {
        let t = trusted();
        // Direct client: its own header is ignored.
        assert_eq!(t.client_ip(ip("203.0.113.9"), &xff(&["10.0.0.1"])), ip("203.0.113.9"));
        // Through the proxy: the right-most untrusted entry, not the spoofed left-most one.
        assert_eq!(t.client_ip(ip("172.20.0.2"), &xff(&["1.1.1.1, 203.0.113.9"])), ip("203.0.113.9"));
        assert_eq!(t.client_ip(ip("172.20.0.2"), &xff(&["1.1.1.1", "203.0.113.9:4711, 172.20.0.3"])), ip("203.0.113.9"));
        assert_eq!(t.client_ip(ip("::ffff:172.20.0.2"), &xff(&["[2001:db8::1]:80"])), ip("2001:db8::1"));
        // Proxy without a header, or with garbage: the proxy itself.
        assert_eq!(t.client_ip(ip("172.20.0.2"), &HeaderMap::new()), ip("172.20.0.2"));
        assert_eq!(t.client_ip(ip("172.20.0.2"), &xff(&["unknown"])), ip("172.20.0.2"));
        // Nobody is trusted by default.
        assert_eq!(TrustedProxies::default().client_ip(ip("172.20.0.2"), &xff(&["1.1.1.1"])), ip("172.20.0.2"));
    }

    #[test]
    fn rewrite_drops_spoofed_headers() {
        let t = trusted();
        let mut h = xff(&["1.1.1.1", "2.2.2.2"]);
        h.insert("x-real-ip", "1.1.1.1".parse().unwrap());
        h.insert("forwarded", "for=1.1.1.1".parse().unwrap());
        t.rewrite(ip("203.0.113.9"), &mut h);
        let values: Vec<_> = h.get_all(FORWARDED_FOR).iter().map(|v| v.to_str().unwrap()).collect();
        assert_eq!(values, ["203.0.113.9"]);
        assert!(h.get("x-real-ip").is_none() && h.get("forwarded").is_none());

        let mut h = xff(&["1.1.1.1", "203.0.113.9"]);
        t.rewrite(ip("172.20.0.2"), &mut h);
        assert_eq!(h.get(FORWARDED_FOR).unwrap(), "1.1.1.1, 203.0.113.9, 172.20.0.2");
    }
}
