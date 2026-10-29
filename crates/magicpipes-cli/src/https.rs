//! Minimal HTTPS client built on hyper + rustls (Mozilla roots plus an optional extra CA).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use bytes::Bytes;
use http::{Request, Response, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub fn tls_config(extra_ca_pem: Option<&str>) -> anyhow::Result<Arc<ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = extra_ca_pem {
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            roots.add(cert.map_err(|e| anyhow!("invalid CA certificate: {e}"))?)?;
        }
    }
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// `https://host[:port]` -> `(host, port)`.
pub fn parse_server(url: &str) -> anyhow::Result<(String, u16)> {
    let uri: Uri = url.parse().with_context(|| format!("invalid URL {url}"))?;
    if uri.scheme_str() != Some("https") {
        bail!("server URL must start with https:// (got {url})");
    }
    let host = uri.host().ok_or_else(|| anyhow!("server URL has no host"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
    Ok((host, uri.port_u16().unwrap_or(443)))
}

/// Opens a TLS connection to `host:port`, verifying the certificate for `host`.
/// `addr` overrides DNS resolution (connects to that IP, still verifying `host`).
pub async fn connect(host: &str, port: u16, tls: &Arc<ClientConfig>, addr: Option<IpAddr>) -> anyhow::Result<TlsStream<TcpStream>> {
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, async {
        match addr {
            Some(ip) => TcpStream::connect(SocketAddr::new(ip, port)).await,
            None => TcpStream::connect((host, port)).await,
        }
    })
    .await
    .map_err(|_| anyhow!("timed out connecting to {host}:{port}"))?
    .with_context(|| format!("connecting to {host}:{port}"))?;
    let _ = tcp.set_nodelay(true);
    let name = ServerName::try_from(host.to_string()).map_err(|_| anyhow!("invalid server name {host}"))?;
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TlsConnector::from(tls.clone()).connect(name, tcp))
        .await
        .map_err(|_| anyhow!("TLS handshake with {host}:{port} timed out"))?
        .with_context(|| format!("TLS handshake with {host}:{port}"))?;
    Ok(stream)
}

/// Sends one request over a fresh connection. The connection task supports upgrades.
pub async fn send(stream: TlsStream<TcpStream>, req: Request<Full<Bytes>>) -> anyhow::Result<Response<Incoming>> {
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    Ok(sender.send_request(req).await?)
}

pub fn host_header(host: &str, port: u16) -> String {
    let h = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
    if port == 443 { h } else { format!("{h}:{port}") }
}

/// POSTs JSON to `<server><path>` and returns the status and parsed JSON body.
pub async fn post_json(
    server: &str,
    path: &str,
    tls: &Arc<ClientConfig>,
    body: &serde_json::Value,
) -> anyhow::Result<(http::StatusCode, serde_json::Value)> {
    let (host, port) = parse_server(server)?;
    let stream = connect(&host, port, tls, None).await?;
    let req = Request::post(path)
        .header(http::header::HOST, host_header(&host, port))
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::USER_AGENT, concat!("magicpipes/", env!("CARGO_PKG_VERSION")))
        .body(Full::new(Bytes::from(serde_json::to_vec(body)?)))?;
    let resp = tokio::time::timeout(Duration::from_secs(30), send(stream, req)).await.map_err(|_| anyhow!("request timed out"))??;
    let status = resp.status();
    let bytes = resp.into_body().collect().await?.to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    Ok((status, json))
}
