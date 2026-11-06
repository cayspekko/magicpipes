//! Load generator for `scripts/bench`: one task per simulated client, each sending HTTP/1.1 requests
//! over its own keep-alive connection, through TLS or plain TCP. Prints one line of `key=value`
//! pairs, latencies in milliseconds.
//!
//! It reads only as much of a response as it takes to find where it ends, which keeps its own cost
//! out of what it measures.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
use clap::Parser;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const BUFFER: usize = 256 * 1024;

#[derive(Parser)]
struct Args {
    /// Port on 127.0.0.1.
    #[arg(long)]
    port: u16,
    /// Connect through TLS, to this name, which is also the request's Host. Without it, plain TCP.
    #[arg(long, requires = "ca")]
    sni: Option<String>,
    /// The CA certificate to trust.
    #[arg(long)]
    ca: Option<PathBuf>,
    /// Simulated clients.
    #[arg(long, default_value_t = 1)]
    conc: usize,
    /// Start no more requests after this many seconds.
    #[arg(long, default_value_t = 3.0)]
    secs: f64,
    /// Start no more requests after this many, in all.
    #[arg(long, default_value_t = u64::MAX)]
    reqs: u64,
    #[arg(long, default_value = "/small")]
    path: String,
    /// POST a body of this many bytes.
    #[arg(long, default_value_t = 0)]
    post: u64,
    /// A new connection for every request.
    #[arg(long)]
    close: bool,
    /// Give each client its own X-Forwarded-For, so that a server trusting 127.0.0.1 counts them as
    /// different clients.
    #[arg(long)]
    xff: bool,
    /// Threads of the generator itself.
    #[arg(long, default_value_t = 4)]
    threads: usize,
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// What a client saw.
#[derive(Default)]
struct Results {
    latencies_us: Vec<u32>,
    failed: u64,
    connect_failed: u64,
    bytes: u64,
    statuses: BTreeMap<u16, u64>,
    errors: BTreeMap<String, u64>,
}

impl Results {
    fn merge(&mut self, other: Results) {
        self.latencies_us.extend(other.latencies_us);
        self.failed += other.failed;
        self.connect_failed += other.connect_failed;
        self.bytes += other.bytes;
        for (status, n) in other.statuses {
            *self.statuses.entry(status).or_default() += n;
        }
        for (error, n) in other.errors {
            *self.errors.entry(error).or_default() += n;
        }
    }

    fn line(&mut self, elapsed: f64) -> String {
        self.latencies_us.sort_unstable();
        let at = |p| percentile_ms(&self.latencies_us, p);
        format!(
            "rps={:.0} mb_s={:.1} p50={:.2} p90={:.2} p99={:.2} max={:.1} ok={} failed={} connect_failed={} status={} errors={}",
            self.latencies_us.len() as f64 / elapsed,
            self.bytes as f64 / elapsed / (1024.0 * 1024.0),
            at(0.5),
            at(0.9),
            at(0.99),
            at(1.0),
            self.latencies_us.len(),
            self.failed,
            self.connect_failed,
            pairs(&self.statuses),
            pairs(&self.errors),
        )
    }
}

fn pairs<K: std::fmt::Display>(counts: &BTreeMap<K, u64>) -> String {
    let list: Vec<String> = counts.iter().map(|(k, n)| format!("{k}:{n}")).collect();
    if list.is_empty() { "-".into() } else { list.join(",") }
}

fn percentile_ms(sorted_us: &[u32], p: f64) -> f64 {
    let Some(last) = sorted_us.len().checked_sub(1) else { return 0.0 };
    sorted_us[(last as f64 * p).round() as usize] as f64 / 1000.0
}

/// What matters in a response's head.
#[derive(Debug, Default, PartialEq)]
struct Head {
    /// Where the body starts.
    end: usize,
    status: u16,
    length: Option<u64>,
    chunked: bool,
    close: bool,
    error: Option<String>,
}

/// `None` until `buf` holds a whole head.
fn parse_head(buf: &[u8]) -> Option<Head> {
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let text = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
    let mut lines = text.lines();
    let status = lines.next()?.split(' ').nth(1)?.parse().ok()?;
    let mut head = Head { end, status, ..Head::default() };
    for (name, value) in lines.filter_map(|l| l.split_once(':')) {
        let value = value.trim();
        match name {
            "content-length" => head.length = value.parse().ok(),
            "transfer-encoding" => head.chunked = value.contains("chunked"),
            "connection" => head.close = value.contains("close"),
            "x-magicpipes-error" => head.error = Some(value.to_string()),
            _ => {}
        }
    }
    Some(head)
}

async fn read_some(io: &mut Box<dyn Io>, buf: &mut [u8]) -> io::Result<usize> {
    match io.read(buf).await? {
        0 => Err(io::ErrorKind::UnexpectedEof.into()),
        n => Ok(n),
    }
}

/// Sends one request and reads its response; true if the server closes the connection after it.
async fn request(io: &mut Box<dyn Io>, head: &[u8], post: u64, buf: &mut [u8], results: &mut Results) -> io::Result<bool> {
    static ZEROS: [u8; 64 * 1024] = [0; 64 * 1024];
    io.write_all(head).await?;
    let mut left = post;
    while left > 0 {
        let n = left.min(ZEROS.len() as u64) as usize;
        io.write_all(&ZEROS[..n]).await?;
        left -= n as u64;
    }
    io.flush().await?;

    let mut have = 0;
    let response = loop {
        if let Some(response) = parse_head(&buf[..have]) {
            break response;
        }
        if have == buf.len() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        have += read_some(io, &mut buf[have..]).await?;
    };
    *results.statuses.entry(response.status).or_default() += 1;
    if let Some(error) = response.error {
        *results.errors.entry(error).or_default() += 1;
    }
    let mut got = (have - response.end) as u64;
    if response.chunked {
        // The last chunk is empty. Body bytes that look the same would only end this a little early.
        let mut tail = buf[response.end..have].to_vec();
        while !tail.ends_with(b"0\r\n\r\n") {
            let n = read_some(io, buf).await?;
            got += n as u64;
            tail.extend_from_slice(&buf[..n]);
            tail.drain(..tail.len().saturating_sub(5));
        }
    } else if let Some(length) = response.length {
        while got < length {
            got += read_some(io, buf).await? as u64;
        }
    }
    results.bytes += got;
    Ok(response.close)
}

type Tls = Option<(TlsConnector, ServerName<'static>)>;

async fn connect(port: u16, tls: &Tls) -> io::Result<Box<dyn Io>> {
    let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
    tcp.set_nodelay(true)?;
    Ok(match tls {
        Some((connector, name)) => Box::new(connector.connect(name.clone(), tcp).await?),
        None => Box::new(tcp),
    })
}

/// New connections do a full handshake, the costliest case.
fn tls_config(sni: &str, ca: &std::path::Path) -> anyhow::Result<Tls> {
    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?;
    for cert in CertificateDer::pem_slice_iter(&pem) {
        roots.add(cert?)?;
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Some((TlsConnector::from(Arc::new(config)), ServerName::try_from(sni.to_string())?)))
}

fn request_head(args: &Args, client: usize) -> Vec<u8> {
    let method = if args.post > 0 { "POST" } else { "GET" };
    let host = args.sni.as_deref().unwrap_or("localhost");
    let mut head = format!("{method} {} HTTP/1.1\r\nhost: {host}\r\nuser-agent: mp-bench-load\r\naccept: */*\r\n", args.path);
    if args.xff {
        head += &format!("x-forwarded-for: 198.18.{}.{}\r\n", (client >> 8) & 255, client & 255);
    }
    if args.close {
        head += "connection: close\r\n";
    }
    if args.post > 0 {
        head += &format!("content-length: {}\r\n", args.post);
    }
    head += "\r\n";
    head.into_bytes()
}

/// One simulated client, until the time or the requests run out.
async fn client(args: Arc<Args>, tls: Arc<Tls>, head: Vec<u8>, started: Instant, issued: Arc<AtomicU64>) -> Results {
    let duration = Duration::from_secs_f64(args.secs);
    let mut results = Results::default();
    let mut buf = vec![0u8; BUFFER];
    let mut kept: Option<Box<dyn Io>> = None;
    while started.elapsed() < duration && issued.fetch_add(1, Ordering::Relaxed) < args.reqs {
        let began = Instant::now();
        let mut conn = match kept.take() {
            Some(conn) => conn,
            None => match tokio::time::timeout(CONNECT_TIMEOUT, connect(args.port, &tls)).await {
                Ok(Ok(conn)) => conn,
                _ => {
                    results.connect_failed += 1;
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    continue;
                }
            },
        };
        match tokio::time::timeout(REQUEST_TIMEOUT, request(&mut conn, &head, args.post, &mut buf, &mut results)).await {
            Ok(Ok(close)) => {
                results.latencies_us.push(began.elapsed().as_micros() as u32);
                if !close && !args.close {
                    kept = Some(conn);
                }
            }
            _ => results.failed += 1,
        }
    }
    results
}

fn main() -> anyhow::Result<()> {
    let args = Arc::new(Args::parse());
    let tls = Arc::new(match (&args.sni, &args.ca) {
        (Some(sni), Some(ca)) => tls_config(sni, ca)?,
        _ => None,
    });
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(args.threads).enable_all().build()?;
    let started = Instant::now();
    let issued = Arc::new(AtomicU64::new(0));
    let mut total = runtime.block_on(async {
        let mut clients = tokio::task::JoinSet::new();
        for n in 0..args.conc {
            clients.spawn(client(args.clone(), tls.clone(), request_head(&args, n), started, issued.clone()));
        }
        let mut total = Results::default();
        while let Some(results) = clients.join_next().await {
            total.merge(results?);
        }
        Ok::<_, anyhow::Error>(total)
    })?;
    println!("{}", total.line(started.elapsed().as_secs_f64()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heads_say_where_a_response_ends() {
        assert_eq!(parse_head(b"HTTP/1.1 200 OK\r\ncontent-le"), None, "not all here yet");
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nbody";
        assert_eq!(parse_head(head), Some(Head { end: head.len() - 4, status: 200, length: Some(13), ..Head::default() }));
        let head = parse_head(b"HTTP/1.1 503 Busy\r\nConnection: close\r\nX-MagicPipes-Error: agent_busy\r\n\r\n").unwrap();
        assert_eq!((head.status, head.close, head.error.as_deref()), (503, true, Some("agent_busy")));
        assert!(parse_head(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap().chunked);
    }

    #[test]
    fn percentiles_come_from_the_sorted_list() {
        assert_eq!(percentile_ms(&[], 0.5), 0.0);
        let latencies = [1000, 2000, 3000, 4000, 5000];
        assert_eq!(percentile_ms(&latencies, 0.0), 1.0);
        assert_eq!(percentile_ms(&latencies, 0.5), 3.0);
        assert_eq!(percentile_ms(&latencies, 1.0), 5.0);
    }
}
