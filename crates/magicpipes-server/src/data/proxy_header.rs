//! PROXY protocol (v1 text and v2 binary) as sent by HAProxy and other TCP load balancers, so
//! port tunnels see — and allow-lists check — the real client address rather than the proxy's.
//! Reads exactly the header and nothing after it.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

const V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
/// Longest v1 line, including CRLF (from the specification).
const V1_MAX: usize = 107;

/// The client address from a PROXY header; `None` for a header that carries no address (the
/// proxy's own health checks: v1 `UNKNOWN`, v2 `LOCAL` or a non-IP family).
pub async fn read<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<SocketAddr>> {
    // Both versions are at least 12 bytes long ("PROXY UNKNOWN\r\n" is 15).
    let mut head = [0u8; 12];
    r.read_exact(&mut head).await?;
    if head == V2_SIGNATURE {
        return read_v2(r).await;
    }
    if !head.starts_with(b"PROXY ") {
        return Err(invalid("not a PROXY protocol header"));
    }
    let mut line = head.to_vec();
    while !line.ends_with(b"\r\n") {
        if line.len() >= V1_MAX {
            return Err(invalid("PROXY v1 header too long"));
        }
        line.push(r.read_u8().await?);
    }
    parse_v1(&line[..line.len() - 2])
}

fn parse_v1(line: &[u8]) -> io::Result<Option<SocketAddr>> {
    let line = std::str::from_utf8(line).map_err(|_| invalid("PROXY v1 header is not text"))?;
    let parts: Vec<&str> = line.split(' ').collect();
    match parts.as_slice() {
        ["PROXY", "UNKNOWN", ..] => Ok(None),
        ["PROXY", "TCP4" | "TCP6", src, _dst, sport, _dport] => {
            let ip: IpAddr = src.parse().map_err(|_| invalid("bad PROXY v1 source address"))?;
            let port: u16 = sport.parse().map_err(|_| invalid("bad PROXY v1 source port"))?;
            Ok(Some(SocketAddr::new(ip, port)))
        }
        _ => Err(invalid("malformed PROXY v1 header")),
    }
}

async fn read_v2<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<SocketAddr>> {
    let mut fixed = [0u8; 4];
    r.read_exact(&mut fixed).await?;
    let [ver_cmd, family, len_hi, len_lo] = fixed;
    if ver_cmd >> 4 != 2 {
        return Err(invalid("unsupported PROXY protocol version"));
    }
    let mut body = vec![0u8; usize::from(u16::from_be_bytes([len_hi, len_lo]))];
    r.read_exact(&mut body).await?;
    if ver_cmd & 0x0f == 0 {
        return Ok(None); // LOCAL
    }
    let addr = match family >> 4 {
        1 if body.len() >= 12 => {
            let ip = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            Some(SocketAddr::new(ip.into(), u16::from_be_bytes([body[8], body[9]])))
        }
        2 if body.len() >= 36 => {
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&body[..16]).expect("16 bytes"));
            Some(SocketAddr::new(ip.into(), u16::from_be_bytes([body[32], body[33]])))
        }
        0 | 3 => None, // UNSPEC or a Unix socket
        _ => return Err(invalid("short PROXY v2 address block")),
    };
    Ok(addr)
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn parse(bytes: &[u8]) -> (io::Result<Option<SocketAddr>>, Vec<u8>) {
        let mut r = bytes;
        let res = read(&mut r).await;
        (res, r.to_vec())
    }

    #[tokio::test]
    async fn v1() {
        let (res, rest) = parse(b"PROXY TCP4 203.0.113.9 10.0.0.1 51234 65500\r\nSSH-2.0").await;
        assert_eq!(res.unwrap(), Some("203.0.113.9:51234".parse().unwrap()));
        assert_eq!(rest, b"SSH-2.0", "bytes after the header are left alone");
        let (res, _) = parse(b"PROXY TCP6 2001:db8::5 2001:db8::1 4000 65500\r\n").await;
        assert_eq!(res.unwrap(), Some("[2001:db8::5]:4000".parse().unwrap()));
        assert_eq!(parse(b"PROXY UNKNOWN\r\n").await.0.unwrap(), None);
        assert!(parse(b"GET / HTTP/1.1\r\n").await.0.is_err());
        assert!(parse(&[b"PROXY TCP4 ".as_slice(), &[b'1'; 120]].concat()).await.0.is_err());
    }

    #[tokio::test]
    async fn v2() {
        let mut h = V2_SIGNATURE.to_vec();
        h.extend([0x21, 0x11, 0, 12, 198, 51, 100, 7, 10, 0, 0, 1, 0x1f, 0x90, 0xff, 0xdc]);
        h.extend(b"data");
        let (res, rest) = parse(&h).await;
        assert_eq!(res.unwrap(), Some("198.51.100.7:8080".parse().unwrap()));
        assert_eq!(rest, b"data");

        let mut local = V2_SIGNATURE.to_vec();
        local.extend([0x20, 0x00, 0, 0]);
        assert_eq!(parse(&local).await.0.unwrap(), None);
    }
}
