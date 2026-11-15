//! A small authoritative DNS responder for ACME DNS-01 (`[tls.dns01]`): it answers TXT queries with
//! the challenge values this server's own orders publish, and refuses everything else. No API key
//! for any DNS host is involved: each domain's `_acme-challenge` name leads here once, by an NS
//! record (`_acme-challenge.<domain>` delegated to this server) or by a CNAME to `<domain>.<zone>`
//! with the zone delegated here.
//!
//! It's on the internet, so it's deliberately narrow: one question per query, no recursion, no
//! compression to follow in what it reads, answers that stay small (amplification), a rate limit,
//! bounded TCP connections, and nothing it reads goes anywhere but into its answer.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

const TYPE_NS: u16 = 2;
const TYPE_SOA: u16 = 6;
const TYPE_TXT: u16 = 16;
const TYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;
const CLASS_ANY: u16 = 255;

const RCODE_FORMERR: u16 = 1;
const RCODE_NXDOMAIN: u16 = 3;
const RCODE_NOTIMP: u16 = 4;
const RCODE_REFUSED: u16 = 5;

/// The largest UDP query read and answer sent: classic DNS, so answers never need EDNS.
const MAX_UDP: usize = 512;
/// The largest query read over TCP.
const MAX_TCP_QUERY: usize = 1024;
/// TCP connections served at once, queries on each, and how long one waits for the next.
const MAX_TCP_CONNECTIONS: usize = 32;
const MAX_TCP_QUERIES: usize = 8;
const TCP_IDLE: Duration = Duration::from_secs(10);
/// Answers per second over both transports, with a burst: far more than ACME validation needs.
const RATE: f64 = 200.0;
const BURST: f64 = 400.0;
/// Values per domain (a certificate for `D` and `*.D` needs two), and how long one is served if
/// the order that published it never withdraws it.
const MAX_VALUES: usize = 4;
const VALUE_LIFETIME: Duration = Duration::from_secs(15 * 60);
/// TTLs: challenge values change with every order, so they're barely cached.
const TXT_TTL: u32 = 1;
const ZONE_TTL: u32 = 300;

/// The challenge values being served, and the names they're served at.
pub struct DnsChallenges {
    /// `[tls.dns01] domains`, lowercase.
    domains: Vec<String>,
    zone: Option<String>,
    nameserver: String,
    values: Mutex<HashMap<String, Vec<(String, Instant)>>>,
    bucket: Mutex<(f64, Instant)>,
}

/// What a query's name is to this responder.
#[derive(Debug, PartialEq, Eq)]
enum Name {
    /// A name a domain's challenge is read at; `apex` when it is the top of a zone delegated here
    /// (`_acme-challenge.<domain>`), not a name inside `zone` (`<domain>.<zone>`).
    Challenge { domain: usize, apex: bool },
    ZoneApex,
    /// Inside `zone`, but nothing's there.
    InZone,
    Outside,
}

impl DnsChallenges {
    pub fn new(domains: &[String], zone: Option<&str>, nameserver: &str) -> Self {
        Self {
            domains: domains.iter().map(|d| d.to_ascii_lowercase()).collect(),
            zone: zone.map(str::to_ascii_lowercase),
            nameserver: nameserver.to_ascii_lowercase(),
            values: Mutex::new(HashMap::new()),
            bucket: Mutex::new((BURST, Instant::now())),
        }
    }

    /// Serves `value` at `domain`'s challenge names until [`DnsChallenges::withdraw`], for at most
    /// [`VALUE_LIFETIME`]. False if `domain` isn't one of this server's, or has too many already.
    pub fn publish(&self, domain: &str, value: &str) -> bool {
        let domain = domain.to_ascii_lowercase();
        if !self.domains.contains(&domain) || value.len() > 255 {
            return false;
        }
        let mut values = self.values.lock().unwrap_or_else(|e| e.into_inner());
        let list = values.entry(domain).or_default();
        list.retain(|(_, at)| at.elapsed() < VALUE_LIFETIME);
        if list.len() >= MAX_VALUES {
            return false;
        }
        list.push((value.to_string(), Instant::now()));
        true
    }

    pub fn withdraw(&self, domain: &str, value: &str) {
        let mut values = self.values.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(list) = values.get_mut(&domain.to_ascii_lowercase()) {
            if let Some(i) = list.iter().position(|(v, _)| v == value) {
                list.remove(i);
            }
            if list.is_empty() {
                values.remove(&domain.to_ascii_lowercase());
            }
        }
    }

    fn current(&self, domain: usize) -> Vec<String> {
        let values = self.values.lock().unwrap_or_else(|e| e.into_inner());
        values.get(&self.domains[domain]).map(|l| l.iter().filter(|(_, at)| at.elapsed() < VALUE_LIFETIME).map(|(v, _)| v.clone()).collect()).unwrap_or_default()
    }

    /// The names that must lead here, for the page that says what to add at the DNS host: per
    /// domain, its challenge name, and the CNAME target when there's a zone.
    pub fn records(&self) -> Vec<(String, Option<String>)> {
        self.domains.iter().map(|d| (format!("_acme-challenge.{d}"), self.zone.as_ref().map(|z| format!("{d}.{z}")))).collect()
    }

    fn classify(&self, name: &str) -> Name {
        if let Some(d) = name.strip_prefix("_acme-challenge.").and_then(|d| self.domains.iter().position(|x| x == d)) {
            return Name::Challenge { domain: d, apex: true };
        }
        let Some(zone) = &self.zone else { return Name::Outside };
        if name == zone {
            return Name::ZoneApex;
        }
        match name.strip_suffix(zone.as_str()).and_then(|rest| rest.strip_suffix('.')) {
            Some(d) => match self.domains.iter().position(|x| x == d) {
                Some(d) => Name::Challenge { domain: d, apex: false },
                None => Name::InZone,
            },
            None => Name::Outside,
        }
    }

    /// One more answer, if the rate allows it.
    fn allow(&self) -> bool {
        let mut b = self.bucket.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        b.0 = (b.0 + now.duration_since(b.1).as_secs_f64() * RATE).min(BURST);
        b.1 = now;
        if b.0 >= 1.0 {
            b.0 -= 1.0;
            true
        } else {
            false
        }
    }

    /// The answer to `packet`, at most `limit` bytes (truncated past that); `None` to send nothing.
    pub fn respond(&self, packet: &[u8], limit: usize) -> Option<Vec<u8>> {
        if packet.len() < 12 {
            return None;
        }
        let id = u16::from_be_bytes([packet[0], packet[1]]);
        let flags = u16::from_be_bytes([packet[2], packet[3]]);
        // An answer, not a question: never answer one (reflection loops).
        if flags & 0x8000 != 0 {
            return None;
        }
        let opcode = (flags >> 11) & 0xF;
        let rd = flags & 0x0100;
        let header = |rcode: u16, aa: bool, counts: [u16; 4]| {
            let mut h = Vec::with_capacity(12);
            h.extend_from_slice(&id.to_be_bytes());
            h.extend_from_slice(&(0x8000 | (opcode << 11) | if aa { 0x0400 } else { 0 } | rd | rcode).to_be_bytes());
            for c in counts {
                h.extend_from_slice(&c.to_be_bytes());
            }
            h
        };
        if opcode != 0 {
            return Some(header(RCODE_NOTIMP, false, [0; 4]));
        }
        if u16::from_be_bytes([packet[4], packet[5]]) != 1 {
            return Some(header(RCODE_FORMERR, false, [0; 4]));
        }
        let Some((name, end)) = read_name(packet, 12) else { return Some(header(RCODE_FORMERR, false, [0; 4])) };
        let Some(tail) = packet.get(end..end + 4) else { return Some(header(RCODE_FORMERR, false, [0; 4])) };
        let (qtype, qclass) = (u16::from_be_bytes([tail[0], tail[1]]), u16::from_be_bytes([tail[2], tail[3]]));
        let question = &packet[12..end + 4];
        if qclass != CLASS_IN && qclass != CLASS_ANY {
            return Some([header(RCODE_REFUSED, false, [1, 0, 0, 0]), question.to_vec()].concat());
        }

        // Records: owner (as a pointer to the question's name, or written out), type, data.
        let mut answers: Vec<(Option<String>, u16, u32, Vec<u8>)> = Vec::new();
        let mut authority: Vec<(Option<String>, u16, u32, Vec<u8>)> = Vec::new();
        let mut rcode = 0;
        let apex_of = |n: &Name| match n {
            Name::Challenge { domain, apex: true } => Some(format!("_acme-challenge.{}", self.domains[*domain])),
            _ => self.zone.clone(),
        };
        let class = self.classify(&name);
        match &class {
            Name::Outside => return Some([header(RCODE_REFUSED, false, [1, 0, 0, 0]), question.to_vec()].concat()),
            Name::Challenge { domain, apex } => {
                if qtype == TYPE_TXT || qtype == TYPE_ANY {
                    for v in self.current(*domain) {
                        answers.push((None, TYPE_TXT, TXT_TTL, txt(&v)));
                    }
                }
                if *apex && qtype == TYPE_SOA {
                    answers.push((None, TYPE_SOA, ZONE_TTL, self.soa()));
                } else if *apex && qtype == TYPE_NS {
                    answers.push((None, TYPE_NS, ZONE_TTL, encode_name(&self.nameserver)));
                }
            }
            Name::ZoneApex => match qtype {
                TYPE_SOA => answers.push((None, TYPE_SOA, ZONE_TTL, self.soa())),
                TYPE_NS => answers.push((None, TYPE_NS, ZONE_TTL, encode_name(&self.nameserver))),
                _ => {}
            },
            Name::InZone => rcode = RCODE_NXDOMAIN,
        }
        // Nothing to say: the zone's SOA, so resolvers know how long to remember that.
        if answers.is_empty() {
            let apex = apex_of(&class).unwrap_or_default();
            let owner = if apex == name { None } else { Some(apex) };
            authority.push((owner, TYPE_SOA, TXT_TTL, self.soa()));
        }

        let mut out = header(rcode, true, [1, answers.len() as u16, authority.len() as u16, 0]);
        out.extend_from_slice(question);
        for (owner, rtype, ttl, data) in answers.iter().chain(&authority) {
            match owner {
                None => out.extend_from_slice(&[0xC0, 0x0C]),
                Some(n) => out.extend_from_slice(&encode_name(n)),
            }
            out.extend_from_slice(&rtype.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&(data.len() as u16).to_be_bytes());
            out.extend_from_slice(data);
        }
        if out.len() > limit {
            // Truncated: the question alone, and TC so the resolver asks again over TCP.
            let mut short = header(rcode, true, [1, 0, 0, 0]);
            short[2] |= 0x02;
            short.extend_from_slice(question);
            return Some(short);
        }
        Some(out)
    }

    fn soa(&self) -> Vec<u8> {
        let mut d = encode_name(&self.nameserver);
        d.extend_from_slice(&encode_name(&format!("hostmaster.{}", self.nameserver)));
        // Minutes since 1970: increases, and fits in 32 bits for millennia.
        let serial = (magicpipes_core::unix_now().max(0) / 60) as u32;
        for v in [serial, 3600, 600, 86_400, TXT_TTL] {
            d.extend_from_slice(&v.to_be_bytes());
        }
        d
    }
}

/// The name at `at` in `packet`, lowercase, and where it ends. Plain labels only: a query has no
/// reason to compress its one name, so a pointer is refused rather than followed.
fn read_name(packet: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    loop {
        let len = *packet.get(at)? as usize;
        at += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None;
        }
        let label = packet.get(at..at + len)?;
        at += len;
        if !name.is_empty() {
            name.push('.');
        }
        // Bytes outside printable ASCII can't be one of this server's names anyway.
        name.extend(label.iter().map(|b| if b.is_ascii_graphic() { b.to_ascii_lowercase() as char } else { '?' }));
        if name.len() > 253 {
            return None;
        }
    }
    Some((name, at))
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let label = &label.as_bytes()[..label.len().min(63)];
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
    out
}

fn txt(value: &str) -> Vec<u8> {
    let v = &value.as_bytes()[..value.len().min(255)];
    let mut out = Vec::with_capacity(v.len() + 1);
    out.push(v.len() as u8);
    out.extend_from_slice(v);
    out
}

/// Answers DNS over UDP until `stop`.
pub async fn serve_udp(socket: UdpSocket, ch: Arc<DnsChallenges>, stop: CancellationToken) {
    let mut buf = [0u8; MAX_UDP];
    loop {
        let (n, peer) = tokio::select! {
            _ = stop.cancelled() => return,
            r = socket.recv_from(&mut buf) => match r {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(error = %e, "dns: receive failed");
                    continue;
                }
            },
        };
        if !ch.allow() {
            continue;
        }
        if let Some(answer) = ch.respond(&buf[..n], MAX_UDP) {
            let _ = socket.send_to(&answer, peer).await;
        }
    }
}

/// Answers DNS over TCP until `stop`: a few queries per connection, a few connections at once.
pub async fn serve_tcp(listener: TcpListener, ch: Arc<DnsChallenges>, stop: CancellationToken) {
    let slots = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    loop {
        let (stream, peer) = tokio::select! {
            _ = stop.cancelled() => return,
            r = listener.accept() => match r {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(error = %e, "dns: accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else { continue };
        let (ch, stop) = (ch.clone(), stop.clone());
        tokio::spawn(async move {
            let _slot = slot;
            tokio::select! {
                _ = stop.cancelled() => {}
                _ = tcp_connection(stream, peer, &ch) => {}
            }
        });
    }
}

async fn tcp_connection(mut stream: TcpStream, peer: SocketAddr, ch: &DnsChallenges) {
    let _ = stream.set_nodelay(true);
    let mut buf = vec![0u8; MAX_TCP_QUERY];
    for _ in 0..MAX_TCP_QUERIES {
        let mut len = [0u8; 2];
        if !matches!(tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut len)).await, Ok(Ok(_))) {
            return;
        }
        let n = u16::from_be_bytes(len) as usize;
        if n > MAX_TCP_QUERY || !matches!(tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut buf[..n])).await, Ok(Ok(_))) {
            return;
        }
        if !ch.allow() {
            return;
        }
        let Some(answer) = ch.respond(&buf[..n], u16::MAX as usize) else { return };
        let mut out = Vec::with_capacity(answer.len() + 2);
        out.extend_from_slice(&(answer.len() as u16).to_be_bytes());
        out.extend_from_slice(&answer);
        if tokio::time::timeout(TCP_IDLE, stream.write_all(&out)).await.is_err() {
            tracing::debug!(%peer, "dns: a TCP client stopped reading");
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(&encode_name(name));
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        q
    }

    fn rcode(a: &[u8]) -> u16 {
        u16::from_be_bytes([a[2], a[3]]) & 0xF
    }

    fn counts(a: &[u8]) -> [u16; 3] {
        [u16::from_be_bytes([a[6], a[7]]), u16::from_be_bytes([a[8], a[9]]), u16::from_be_bytes([a[10], a[11]])]
    }

    /// The TXT strings of an answer whose records all point at the question's name.
    fn txts(a: &[u8], question_len: usize) -> Vec<String> {
        let mut at = 12 + question_len;
        let mut out = Vec::new();
        for _ in 0..counts(a)[0] {
            assert_eq!(&a[at..at + 2], &[0xC0, 0x0C]);
            let rtype = u16::from_be_bytes([a[at + 2], a[at + 3]]);
            let len = u16::from_be_bytes([a[at + 10], a[at + 11]]) as usize;
            if rtype == TYPE_TXT {
                let data = &a[at + 12..at + 12 + len];
                out.push(String::from_utf8(data[1..1 + data[0] as usize].to_vec()).unwrap());
            }
            at += 12 + len;
        }
        out
    }

    fn responder() -> DnsChallenges {
        DnsChallenges::new(&["example.com".into(), "sonasora.com".into()], Some("acme.example.com"), "mp.example.com")
    }

    #[test]
    fn challenge_values_are_served_at_both_names_while_published() {
        let ch = responder();
        let q = query("_ACME-Challenge.Example.com", TYPE_TXT);
        let qlen = q.len() - 12;
        let a = ch.respond(&q, MAX_UDP).unwrap();
        assert_eq!((rcode(&a), counts(&a)), (0, [0, 1, 0]), "nothing yet: no data, and the SOA");
        assert!(ch.publish("example.com", "value-for-the-domain") && ch.publish("example.com", "value-for-the-wildcard"));
        let a = ch.respond(&q, MAX_UDP).unwrap();
        assert_eq!(&a[..2], &[0x12, 0x34]);
        assert!(a[2] & 0x80 != 0 && a[2] & 0x04 != 0, "an authoritative answer");
        assert_eq!(&a[12..12 + qlen], &q[12..], "the question as asked, case and all");
        assert_eq!(txts(&a, qlen), ["value-for-the-domain", "value-for-the-wildcard"]);
        // Through the zone (CNAME to example.com.acme.example.com): the same values.
        let q2 = query("example.com.acme.example.com", TYPE_TXT);
        assert_eq!(txts(&ch.respond(&q2, MAX_UDP).unwrap(), q2.len() - 12).len(), 2);
        ch.withdraw("example.com", "value-for-the-domain");
        assert_eq!(txts(&ch.respond(&q, MAX_UDP).unwrap(), qlen), ["value-for-the-wildcard"]);
        // Only this server's domains, and only a few values each.
        assert!(!ch.publish("other.com", "v"));
        for i in 0..3 {
            assert!(ch.publish("sonasora.com", &format!("v{i}")));
        }
        assert!(ch.publish("sonasora.com", "v3") && !ch.publish("sonasora.com", "v4"));
    }

    #[test]
    fn everything_else_is_refused_or_empty() {
        let ch = responder();
        let refused = ch.respond(&query("example.org", TYPE_TXT), MAX_UDP).unwrap();
        assert_eq!((rcode(&refused), counts(&refused)), (RCODE_REFUSED, [0, 0, 0]), "not a recursive resolver");
        assert_eq!(rcode(&ch.respond(&query("_acme-challenge.other.com", TYPE_TXT), MAX_UDP).unwrap()), RCODE_REFUSED);
        let nx = ch.respond(&query("nothing.acme.example.com", TYPE_A_FOR_TESTS), MAX_UDP).unwrap();
        assert_eq!((rcode(&nx), counts(&nx)), (RCODE_NXDOMAIN, [0, 1, 0]));
        let ns = ch.respond(&query("acme.example.com", TYPE_NS), MAX_UDP).unwrap();
        assert_eq!((rcode(&ns), counts(&ns)), (0, [1, 0, 0]));
        let soa = ch.respond(&query("_acme-challenge.example.com", TYPE_SOA), MAX_UDP).unwrap();
        assert_eq!(counts(&soa), [1, 0, 0]);
        // An answer is never answered, and broken queries get FORMERR or nothing.
        let mut answer = query("_acme-challenge.example.com", TYPE_TXT);
        answer[2] |= 0x80;
        assert!(ch.respond(&answer, MAX_UDP).is_none());
        assert!(ch.respond(&[0; 11], MAX_UDP).is_none());
        let mut pointer = query("x", TYPE_TXT);
        pointer.truncate(12);
        pointer.extend_from_slice(&[0xC0, 0x0C, 0, 16, 0, 1]);
        assert_eq!(rcode(&ch.respond(&pointer, MAX_UDP).unwrap()), RCODE_FORMERR, "no pointers in a question");
        let mut cut = query("_acme-challenge.example.com", TYPE_TXT);
        cut.truncate(cut.len() - 3);
        assert_eq!(rcode(&ch.respond(&cut, MAX_UDP).unwrap()), RCODE_FORMERR);
        let mut two = query("x.com", TYPE_TXT);
        two[5] = 2;
        assert_eq!(rcode(&ch.respond(&two, MAX_UDP).unwrap()), RCODE_FORMERR);
        let mut update = query("x.com", TYPE_TXT);
        update[2] = 5 << 3;
        assert_eq!(rcode(&ch.respond(&update, MAX_UDP).unwrap()), RCODE_NOTIMP);
    }

    const TYPE_A_FOR_TESTS: u16 = 1;

    #[test]
    fn an_answer_too_long_for_udp_is_truncated() {
        let ch = DnsChallenges::new(&["example.com".into()], None, "mp.example.com");
        for i in 0..4 {
            assert!(ch.publish("example.com", &format!("{i}{}", "x".repeat(200))));
        }
        let q = query("_acme-challenge.example.com", TYPE_TXT);
        let short = ch.respond(&q, MAX_UDP).unwrap();
        assert!(short.len() <= MAX_UDP && short[2] & 0x02 != 0 && counts(&short) == [0, 0, 0], "TC, so the resolver asks over TCP");
        assert_eq!(txts(&ch.respond(&q, 65_535).unwrap(), q.len() - 12).len(), 4);
    }

    #[test]
    fn random_bytes_never_panic() {
        let ch = responder();
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        for len in 0..600 {
            let packet: Vec<u8> = (0..len)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    seed as u8
                })
                .collect();
            if let Some(a) = ch.respond(&packet, MAX_UDP) {
                assert!(a.len() <= MAX_UDP);
            }
        }
    }

    #[tokio::test]
    async fn it_answers_over_udp_and_tcp() {
        let ch = Arc::new(responder());
        ch.publish("example.com", "over-the-wire");
        let stop = CancellationToken::new();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (udp_addr, tcp_addr) = (udp.local_addr().unwrap(), tcp.local_addr().unwrap());
        tokio::spawn(serve_udp(udp, ch.clone(), stop.clone()));
        tokio::spawn(serve_tcp(tcp, ch.clone(), stop.clone()));
        let q = query("_acme-challenge.example.com", TYPE_TXT);

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&q, udp_addr).await.unwrap();
        let mut buf = [0u8; 600];
        let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf)).await.unwrap().unwrap();
        assert_eq!(txts(&buf[..n], q.len() - 12), ["over-the-wire"]);

        let mut s = TcpStream::connect(tcp_addr).await.unwrap();
        for _ in 0..2 {
            s.write_all(&[&(q.len() as u16).to_be_bytes()[..], &q].concat()).await.unwrap();
            let mut len = [0u8; 2];
            s.read_exact(&mut len).await.unwrap();
            let mut a = vec![0u8; u16::from_be_bytes(len) as usize];
            s.read_exact(&mut a).await.unwrap();
            assert_eq!(txts(&a, q.len() - 12), ["over-the-wire"]);
        }
        stop.cancel();
    }
}
