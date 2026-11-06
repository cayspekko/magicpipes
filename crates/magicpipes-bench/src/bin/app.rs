//! Test application for `scripts/bench`: answers HTTP/1.1 as cheaply as it can, so that what gets
//! measured is the tunnel. `GET /big/<MiB>`, `/64k`, `/1k`, and 13 bytes for anything else; a POST's
//! body (`Content-Length` only) is read and discarded first.

use std::io;

use anyhow::Context;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const THREADS: usize = 4;
const KIB: u64 = 1024;
const CHUNK: usize = 64 * 1024;
static FILL: [u8; CHUNK] = [b'x'; CHUNK];

/// Bytes to answer with.
fn response_length(path: &str) -> u64 {
    match path {
        "/1k" => KIB,
        "/64k" => 64 * KIB,
        _ => match path.strip_prefix("/big/").and_then(|mib| mib.parse::<u64>().ok()) {
            Some(mib) => mib * KIB * KIB,
            None => 13,
        },
    }
}

async fn serve(mut tcp: TcpStream) -> io::Result<()> {
    tcp.set_nodelay(true)?;
    let mut buf = vec![0u8; CHUNK];
    let mut have = 0;
    loop {
        let end = loop {
            if let Some(at) = buf[..have].windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            if have == buf.len() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            match tcp.read(&mut buf[have..]).await? {
                0 => return Ok(()),
                n => have += n,
            }
        };
        let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
        let path = head.split(' ').nth(1).unwrap_or("/").to_string();
        let close = head.contains("connection: close");
        let body: u64 = head.lines().find_map(|l| l.strip_prefix("content-length:")?.trim().parse().ok()).unwrap_or(0);
        let mut read = (have - end) as u64;
        while read < body {
            match tcp.read(&mut buf).await? {
                0 => return Ok(()),
                n => read += n as u64,
            }
        }
        have = 0;

        let length = response_length(&path);
        let connection = if close { "connection: close\r\n" } else { "" };
        let head = format!("HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {length}\r\n{connection}\r\n");
        if length <= CHUNK as u64 {
            let mut response = head.into_bytes();
            response.extend_from_slice(&FILL[..length as usize]);
            tcp.write_all(&response).await?;
        } else {
            tcp.write_all(head.as_bytes()).await?;
            let mut left = length;
            while left > 0 {
                let n = left.min(CHUNK as u64) as usize;
                tcp.write_all(&FILL[..n]).await?;
                left -= n as u64;
            }
        }
        if close {
            return Ok(());
        }
    }
}

fn main() -> anyhow::Result<()> {
    let port: u16 = std::env::args().nth(1).context("usage: mp-bench-app <port>")?.parse().context("the port")?;
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(THREADS).enable_all().build()?;
    runtime.block_on(async {
        let listener = TcpListener::bind(("127.0.0.1", port)).await?;
        loop {
            let (tcp, _) = listener.accept().await?;
            tokio::spawn(serve(tcp));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_choose_the_size() {
        assert_eq!(response_length("/small"), 13);
        assert_eq!(response_length("/1k"), 1024);
        assert_eq!(response_length("/64k"), 65536);
        assert_eq!(response_length("/big/2"), 2 << 20);
        assert_eq!(response_length("/big/nope"), 13);
    }
}
