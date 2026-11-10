//! HTTPS to the local app (`add --local-https`): for apps that only speak HTTPS, such as Proxmox's
//! web UI on 8006, a NAS or a router. The server still speaks plain HTTP inside the tunnel; the
//! agent adds TLS on the way to the app.
//!
//! Such apps have certificates nobody issued, so there is nothing to check one against. Instead,
//! `add` keeps the certificate it finds ([`fetch`]), and every later connection must show the
//! same one ([`connect`]): someone between the agent and the app (for `--host`, on the network)
//! would have to show another. When the app gets a new certificate, running `add` again keeps the
//! new one; the person running it is at the machine, which is the consent the first time needed.
//! The fingerprint is the SHA-256 of the whole certificate, as browsers show it, so it can be
//! compared with what a browser on that network says.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

/// A certificate's fingerprint as browsers show it: SHA-256, in hex pairs with colons.
pub fn fingerprint(cert: &[u8]) -> String {
    let digest = Sha256::digest(cert);
    let mut out = String::with_capacity(95);
    for (i, b) in digest.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{b:02X}"));
    }
    out
}

/// Accepts the certificate that has `pin` as its fingerprint, or, with no pin, any (to learn
/// it). Handshake signatures are checked either way, so the app must hold the certificate's key.
#[derive(Debug)]
struct Pinned {
    pin: Option<String>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(&self, cert: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        match &self.pin {
            Some(pin) if *pin != fingerprint(cert) => Err(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)),
            _ => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Configurations kept per pin, so connections to the same app resume TLS sessions instead of
/// starting each from scratch. At most a few dozen: one per tunnel to an HTTPS app.
const MAX_CONFIGS: usize = 64;
static CONFIGS: LazyLock<Mutex<HashMap<Option<String>, Arc<ClientConfig>>>> = LazyLock::new(Mutex::default);

fn config(pin: Option<&str>) -> Arc<ClientConfig> {
    let mut configs = CONFIGS.lock().unwrap_or_else(|e| e.into_inner());
    let key = pin.map(str::to_string);
    if let Some(c) = configs.get(&key) {
        return c.clone();
    }
    if configs.len() >= MAX_CONFIGS {
        configs.clear();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(Pinned { pin: key.clone(), provider: provider.clone() });
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    // The tunnel carries HTTP/1.1, so the app must speak it too.
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let cfg = Arc::new(cfg);
    configs.insert(key, cfg.clone());
    cfg
}

/// The name to ask for: none for an address (rustls sends no SNI then), else the host given.
fn server_name(host: &str) -> io::Result<ServerName<'static>> {
    match host.parse::<IpAddr>() {
        Ok(ip) => Ok(ServerName::IpAddress(ip.into())),
        Err(_) => ServerName::try_from(host.to_string()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e)),
    }
}

/// TLS to the app at `host:port`, which must show the certificate `pin` names.
pub async fn connect(host: &str, port: u16, pin: &str) -> io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect((host, port)).await?;
    tcp.set_nodelay(true)?;
    tokio_rustls::TlsConnector::from(config(Some(pin))).connect(server_name(host)?, tcp).await
}

/// The fingerprint of the certificate the app at `host:port` shows now.
pub async fn fetch(host: &str, port: u16) -> io::Result<String> {
    let tcp = TcpStream::connect((host, port)).await?;
    let tls = tokio_rustls::TlsConnector::from(config(None)).connect(server_name(host)?, tcp).await?;
    let cert = tls.get_ref().1.peer_certificates().and_then(|c| c.first()).ok_or_else(|| io::Error::other("the app showed no certificate"))?;
    Ok(fingerprint(cert))
}

/// Whether a failed [`connect`] was the app showing a certificate other than the one kept.
pub fn is_other_certificate(e: &io::Error) -> bool {
    e.get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .is_some_and(|e| matches!(e, rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// An app that speaks HTTPS with a new self-signed certificate: its port, and that
    /// certificate's fingerprint. It echoes one line.
    async fn app() -> (u16, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["app.local".into()]).unwrap().self_signed(&key).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], rustls_pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()))
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                    let mut buf = [0u8; 64];
                    if let Ok(n @ 1..) = tls.read(&mut buf).await {
                        let _ = tls.write_all(&buf[..n]).await;
                        let _ = tls.shutdown().await;
                    }
                });
            }
        });
        (port, fingerprint(cert.der()))
    }

    #[test]
    fn fingerprints_look_like_a_browsers() {
        let f = fingerprint(b"anything");
        assert_eq!(f.len(), 32 * 3 - 1);
        assert!(f.split(':').all(|pair| pair.len() == 2 && pair.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_lowercase())), "{f}");
    }

    #[tokio::test]
    async fn the_kept_certificate_and_no_other() {
        let (port, pin) = app().await;
        assert_eq!(fetch("127.0.0.1", port).await.unwrap(), pin);
        let mut tls = connect("127.0.0.1", port, &pin).await.unwrap();
        tls.write_all(b"hello\n").await.unwrap();
        let mut echoed = Vec::new();
        tls.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"hello\n");

        // Another app on that port, as after a new certificate or someone in between.
        let (other, _) = app().await;
        let Err(e) = connect("127.0.0.1", other, &pin).await else { panic!("another certificate was accepted") };
        assert!(is_other_certificate(&e), "{e}");
    }

    #[tokio::test]
    async fn an_app_without_tls_is_no_https_app() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                let _ = tcp.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            }
        });
        let Err(e) = fetch("127.0.0.1", port).await else { panic!("plain HTTP was taken for TLS") };
        assert!(!is_other_certificate(&e));
    }
}
