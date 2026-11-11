//! Remote desktops in the browser: IronRDP's web client, reaching an RDP tunnel's machine, and
//! noVNC, reaching a VNC tunnel's (`relay`, at the end).
//!
//! The browser's WebSocket arrives here once the management side has checked the session cookie,
//! the page's origin and that the person may reach the tunnel. The client runs in the page and
//! starts with RDCleanPath, as with Devolutions Gateway: it sends the first message of the RDP
//! handshake (the X.224 connection request); this side opens a data stream to the tunnel's agent,
//! as for any connection, passes the message on, takes the machine's answer, and does the TLS
//! handshake with the machine itself, which a page can't. It answers with the machine's reply and
//! certificate chain, and from then on carries the page's RDP, unencrypted inside the WebSocket,
//! over that TLS session. So this side reads the session, as it does a browser terminal's; native
//! clients through `magicpipes connect` stay end to end.
//!
//! The machine's certificate key is kept the first time (`Report::HostKey`), and a different one
//! is refused later, as browser terminals do with SSH host keys: the stream crosses the agent's
//! network. Where the page asks to go (`destination`) is ignored, since the tunnel decides, and the
//! agent dials only what its own user configured. The session ends when the person loses access to
//! the tunnel, signs out everywhere, or the tunnel goes, checked on every publish.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use ironrdp_rdcleanpath::{DetectionResult, RDCleanPath, RDCleanPathPdu};
use magicpipes_core::mux::COPY_BUFFER;
use magicpipes_core::proto::{Kind, ServerOpen};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use super::ssh::Report;
use super::terminal::{MAX_PER_PERSON, Opening};
use super::{DataPlane, Route, RouteTable, ports};

/// The page's first message: the RDCleanPath request, a few hundred bytes.
const MAX_REQUEST: usize = 16 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Reaching the machine: its X.224 answer, then the TLS handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// The machine's X.224 answer is a TPKT packet of a few dozen bytes.
const MAX_X224: usize = 1024;
const PING_EVERY: Duration = Duration::from_secs(30);

/// Why a desktop couldn't open, as the page's client reports it: an HTTP status it can explain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// The page didn't speak RDCleanPath, or asked for something not offered.
    BadRequest = 400,
    /// The machine showed a different certificate than the one kept.
    CertificateChanged = 403,
    /// No such desktop that this person may reach, or not any more.
    NotFound = 404,
    TooMany = 429,
    /// The machine didn't answer, or not as an RDP server with TLS.
    Unreachable = 502,
    Offline = 503,
}

/// The tunnel's route, if the person may still use it as a desktop of this kind.
fn admitted<'t>(table: &'t RouteTable, o: &Opening, kind: Kind) -> Option<&'t Arc<Route>> {
    let user = table.users.get(&o.user_id).filter(|u| u.valid_after <= o.signed_in_at)?;
    table
        .by_connect
        .get(&o.name)
        .filter(|(k, r)| *k == kind && r.tunnel_id == o.tunnel_id && r.access.admits(&user.principal, o.client))
        .map(|(_, r)| r)
}

/// A fingerprint of a certificate's public key: `SHA256:` and the digest in base64, as OpenSSH
/// writes them. The key, not the whole certificate, so one reissued for the same key still counts.
pub fn key_fingerprint(cert: &[u8]) -> Option<String> {
    let (_, x509) = x509_parser::parse_x509_certificate(cert).ok()?;
    let digest = Sha256::digest(x509.public_key().raw);
    Some(format!("SHA256:{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)))
}

/// How the machine answered the X.224 connection request.
#[derive(Debug, PartialEq, Eq)]
enum Negotiated {
    /// It chose TLS (plain, or with NLA).
    Tls,
    /// It refused what was offered: the page's client explains the code.
    Failure,
    /// Something else: standard RDP security without TLS, or not an answer at all.
    Other,
}

/// TPKT (4 bytes), the X.224 Connection Confirm (7), then the RDP negotiation response or
/// failure (8): its type, flags, length, and the protocol chosen or the failure code.
fn negotiated(x224: &[u8]) -> Negotiated {
    const CONNECTION_CONFIRM: u8 = 0xd0;
    const NEG_RSP: u8 = 0x02;
    const NEG_FAILURE: u8 = 0x03;
    /// PROTOCOL_SSL, PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX: all start with TLS.
    const WITH_TLS: u32 = 0x1 | 0x2 | 0x8;
    if x224.get(5).is_none_or(|code| code & 0xf0 != CONNECTION_CONFIRM) {
        return Negotiated::Other;
    }
    match x224.get(11) {
        Some(&NEG_FAILURE) => Negotiated::Failure,
        Some(&NEG_RSP) => match x224.get(15..19).and_then(|b| <[u8; 4]>::try_from(b).ok()) {
            Some(p) if u32::from_le_bytes(p) & WITH_TLS != 0 => Negotiated::Tls,
            _ => Negotiated::Other,
        },
        _ => Negotiated::Other,
    }
}

/// Reads one TPKT packet: version 3, a reserved byte, and the whole length, big-endian.
async fn read_tpkt<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut packet = vec![0u8; 4];
    r.read_exact(&mut packet).await?;
    let len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if packet[0] != 3 || !(11..=MAX_X224).contains(&len) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "not an X.224 answer"));
    }
    packet.resize(len, 0);
    r.read_exact(&mut packet[4..]).await?;
    Ok(packet)
}

/// Accepts the machine's certificate, whatever it is: RDP certificates are usually self-signed,
/// so the machine is known by its key instead, kept the first time and compared afterwards. The
/// handshake's signatures are still checked, so the machine holds that key.
#[derive(Debug)]
struct AnyCertificate(Arc<CryptoProvider>);

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// TLS toward the machine. No SNI (machines are known by their key), and no session resumption,
/// which CredSSP forbids.
fn tls_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut config = ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .expect("ring supports TLS 1.2 and 1.3")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
                .with_no_client_auth();
            config.enable_sni = false;
            config.resumption = rustls::client::Resumption::disabled();
            Arc::new(config)
        })
        .clone()
}

/// Reads the page's RDCleanPath request: one DER message, possibly over several WebSocket messages.
async fn read_request<S>(ws: &mut WebSocketStream<S>) -> Option<RDCleanPath>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = Vec::new();
    let read = async {
        loop {
            match ws.next().await? {
                Ok(Message::Binary(data)) => buf.extend_from_slice(&data),
                Ok(Message::Close(_)) | Err(_) => return None,
                Ok(_) => continue,
            }
            if buf.len() > MAX_REQUEST {
                return None;
            }
            match RDCleanPathPdu::detect(&buf) {
                // Nothing may follow it: the page waits for the answer.
                DetectionResult::Detected { total_length, .. } if total_length == buf.len() => return RDCleanPathPdu::from_der(&buf).ok()?.into_enum().ok(),
                DetectionResult::NotEnoughBytes => continue,
                _ => return None,
            }
        }
    };
    tokio::time::timeout(REQUEST_TIMEOUT, read).await.ok().flatten()
}

async fn send_pdu<S>(ws: &mut WebSocketStream<S>, pdu: RDCleanPathPdu) -> Result<(), ()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let der = pdu.to_der().map_err(|_| ())?;
    ws.send(Message::Binary(der.into())).await.map_err(|_| ())
}

/// Tells the page why, and closes.
async fn refuse<S>(mut ws: WebSocketStream<S>, why: Refusal)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = send_pdu(&mut ws, RDCleanPathPdu::new_http_error(why as u16)).await;
        let _ = ws.close(None).await;
    })
    .await;
}

/// Serves one remote desktop until it ends.
pub async fn run<S>(dp: Arc<DataPlane>, mut ws: WebSocketStream<S>, o: Opening)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(request) = read_request(&mut ws).await else {
        return refuse(ws, Refusal::BadRequest).await;
    };
    // A preconnection blob is for Hyper-V's console, which tunnels don't reach.
    let RDCleanPath::Request { x224_connection_request, preconnection_blob: None, .. } = request else {
        return refuse(ws, Refusal::BadRequest).await;
    };
    let Some(_slot) = dp.desktops.take(&o.user_id) else {
        tracing::debug!(user = %o.user_id, "refusing a desktop: {MAX_PER_PERSON} open, or the server is at its limit");
        return refuse(ws, Refusal::TooMany).await;
    };
    let (tls, x224) = match reach(&dp, &o, x224_connection_request.as_bytes()).await {
        Ok(Reached::Tls(tls, x224)) => (tls, x224),
        Ok(Reached::NegotiationFailed(x224)) => {
            if let Ok(pdu) = RDCleanPathPdu::new_negotiation_error(x224) {
                let _ = send_pdu(&mut ws, pdu).await;
            }
            let _ = ws.close(None).await;
            return;
        }
        Err(why) => return refuse(ws, why).await,
    };
    let chain: Vec<Vec<u8>> = tls.get_ref().1.peer_certificates().unwrap_or_default().iter().map(|c| c.to_vec()).collect();
    let Ok(response) = RDCleanPathPdu::new_response(o.name.clone(), x224, chain) else {
        return refuse(ws, Refusal::Unreachable).await;
    };
    if send_pdu(&mut ws, response).await.is_err() {
        return;
    }
    tracing::info!(user = %o.user_id, tunnel = %o.tunnel_id, client = %o.client, "remote desktop opened");
    let _ = dp.ssh_reports.try_send(Report::Desktop { user_id: o.user_id.clone(), tunnel_id: o.tunnel_id.clone(), client: o.client, kind: Kind::Rdp });
    pump(&dp, ws, tls, &o, Kind::Rdp).await;
}

enum Reached<T> {
    Tls(T, Vec<u8>),
    NegotiationFailed(Vec<u8>),
}

/// Reaches the machine through the agent, and as far as the end of the TLS handshake.
async fn reach(dp: &DataPlane, o: &Opening, x224_request: &[u8]) -> Result<Reached<tokio_rustls::client::TlsStream<magicpipes_core::mux::MuxStream>>, Refusal> {
    let (route, mut stream) = open_stream(dp, o, Kind::Rdp).await?;
    let handshake = async {
        stream.write_all(x224_request).await.map_err(|_| Refusal::Unreachable)?;
        let x224 = read_tpkt(&mut stream).await.map_err(|_| Refusal::Unreachable)?;
        match negotiated(&x224) {
            Negotiated::Tls => {}
            Negotiated::Failure => return Ok(Reached::NegotiationFailed(x224)),
            Negotiated::Other => {
                tracing::debug!(tunnel = %o.tunnel_id, "the machine didn't choose TLS");
                return Err(Refusal::Unreachable);
            }
        }
        let name = ServerName::try_from("rdp.invalid").map_err(|_| Refusal::Unreachable)?;
        let tls = tokio_rustls::TlsConnector::from(tls_config()).connect(name, stream).await.map_err(|e| {
            tracing::debug!(tunnel = %o.tunnel_id, error = %e, "no TLS with the machine");
            Refusal::Unreachable
        })?;
        Ok(Reached::Tls(tls, x224))
    };
    let reached = tokio::time::timeout(CONNECT_TIMEOUT, handshake).await.map_err(|_| Refusal::Unreachable)??;
    let Reached::Tls(tls, x224) = reached else { return Ok(reached) };
    let shown = tls.get_ref().1.peer_certificates().and_then(|c| c.first()).and_then(|c| key_fingerprint(c)).ok_or(Refusal::Unreachable)?;
    match &route.host_key {
        Some(kept) if *kept != shown => {
            tracing::warn!(tunnel = %o.tunnel_id, %kept, %shown, "remote desktop refused a changed certificate");
            let _ = dp.ssh_reports.try_send(Report::KeyRefused { tunnel_id: o.tunnel_id.clone() });
            Err(Refusal::CertificateChanged)
        }
        Some(_) => Ok(Reached::Tls(tls, x224)),
        None => {
            let _ = dp.ssh_reports.try_send(Report::HostKey { tunnel_id: route.tunnel_id.clone(), fingerprint: shown });
            Ok(Reached::Tls(tls, x224))
        }
    }
}

/// Writes one of the page's messages to the machine. The flush matters: when the agent's stream
/// is full, the TLS stream keeps what it couldn't send, which would otherwise wait for the page's
/// next message.
async fn send_to_machine<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> std::io::Result<()> {
    w.write_all(data).await?;
    w.flush().await
}

/// A data stream to the tunnel's machine through its agent, as for any connection.
async fn open_stream(dp: &DataPlane, o: &Opening, kind: Kind) -> Result<(Arc<Route>, magicpipes_core::mux::MuxStream), Refusal> {
    let route = admitted(&dp.table(), o, kind).ok_or(Refusal::NotFound)?.clone();
    let agent = match route.agent.as_ref().filter(|a| a.is_online()) {
        Some(a) => a.clone(),
        None => return Err(Refusal::Offline),
    };
    let header = ServerOpen::Data { tunnel_id: route.tunnel_id.clone(), peer: Some(o.client.to_string()) };
    let stream = ports::open(dp, &route, &agent, o.client, header).await.ok_or(Refusal::Unreachable)?;
    Ok((route, stream))
}

/// Carries the page's messages to the machine and back, until either ends or the person may no
/// longer reach the tunnel.
async fn pump<S, T>(dp: &DataPlane, mut ws: WebSocketStream<S>, machine: T, o: &Opening, kind: Kind)
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (mut from_machine, mut to_machine) = tokio::io::split(machine);
    let mut changes = dp.generation.subscribe();
    let mut ping = tokio::time::interval(PING_EVERY);
    ping.tick().await;
    let mut buf = vec![0u8; COPY_BUFFER];
    loop {
        tokio::select! {
            _ = dp.shutdown.cancelled() => break,
            r = changes.changed() => {
                if r.is_err() || admitted(&dp.table(), o, kind).is_none() {
                    tracing::debug!(user = %o.user_id, tunnel = %o.tunnel_id, "closing a remote desktop its user may no longer use");
                    break;
                }
            }
            msg = ws.next() => match msg {
                Some(Ok(Message::Binary(data))) => {
                    if send_to_machine(&mut to_machine, &data).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
            n = from_machine.read(&mut buf) => match n {
                Ok(n) if n > 0 => {
                    if ws.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                        break;
                    }
                }
                _ => break,
            },
            _ = ping.tick() => {
                if ws.send(Message::Ping(Default::default())).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), ws.close(None)).await;
}

/// The greeting a VNC server opens with: `RFB 003.008\n`.
const RFB_GREETING: usize = 12;

/// Serves one VNC desktop until it ends. noVNC speaks RFB itself inside the WebSocket, so this
/// side only carries bytes, as websockify would; it checks only that the machine greets as a VNC
/// server, so that the page can say so when it doesn't. A refusal closes the WebSocket with
/// 4000 + the HTTP status of [`Refusal`], which the page, holding the socket, can read.
pub async fn relay<S>(dp: Arc<DataPlane>, mut ws: WebSocketStream<S>, o: Opening)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(_slot) = dp.desktops.take(&o.user_id) else {
        tracing::debug!(user = %o.user_id, "refusing a desktop: {MAX_PER_PERSON} open, or the server is at its limit");
        return close_with(ws, Refusal::TooMany).await;
    };
    let reached = async {
        let (_, mut stream) = open_stream(&dp, &o, Kind::Vnc).await?;
        let mut greeting = [0u8; RFB_GREETING];
        stream.read_exact(&mut greeting).await.map_err(|_| Refusal::Unreachable)?;
        if !greeting.starts_with(b"RFB ") {
            tracing::debug!(tunnel = %o.tunnel_id, "the machine didn't greet as a VNC server");
            return Err(Refusal::Unreachable);
        }
        Ok((stream, greeting))
    };
    let (stream, greeting) = match tokio::time::timeout(CONNECT_TIMEOUT, reached).await {
        Ok(Ok(r)) => r,
        Ok(Err(why)) => return close_with(ws, why).await,
        Err(_) => return close_with(ws, Refusal::Unreachable).await,
    };
    if ws.send(Message::Binary(greeting.to_vec().into())).await.is_err() {
        return;
    }
    tracing::info!(user = %o.user_id, tunnel = %o.tunnel_id, client = %o.client, "remote desktop opened");
    let _ = dp.ssh_reports.try_send(Report::Desktop { user_id: o.user_id.clone(), tunnel_id: o.tunnel_id.clone(), client: o.client, kind: Kind::Vnc });
    pump(&dp, ws, stream, &o, Kind::Vnc).await;
}

/// Closes a VNC desktop's WebSocket with the reason as its code.
async fn close_with<S>(mut ws: WebSocketStream<S>, why: Refusal)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use tokio_tungstenite::tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};
    let frame = CloseFrame { code: CloseCode::Library(4000 + why as u16), reason: "".into() };
    let _ = tokio::time::timeout(Duration::from_secs(5), ws.close(Some(frame))).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Connection Confirm with the RDP negotiation response or failure, as Windows sends them.
    fn confirm(neg: [u8; 8]) -> Vec<u8> {
        let mut x224 = vec![3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0];
        x224.extend_from_slice(&neg);
        x224
    }

    #[test]
    fn only_a_tls_answer_goes_on() {
        assert_eq!(negotiated(&confirm([2, 0x1f, 8, 0, 2, 0, 0, 0])), Negotiated::Tls, "NLA");
        assert_eq!(negotiated(&confirm([2, 0, 8, 0, 1, 0, 0, 0])), Negotiated::Tls, "TLS");
        assert_eq!(negotiated(&confirm([2, 0, 8, 0, 0, 0, 0, 0])), Negotiated::Other, "standard RDP security");
        assert_eq!(negotiated(&confirm([3, 0, 8, 0, 5, 0, 0, 0])), Negotiated::Failure);
        assert_eq!(negotiated(&[3, 0, 0, 11, 6, 0xd0, 0, 0, 0, 0, 0]), Negotiated::Other, "no negotiation at all");
        let mut not_a_confirm = confirm([2, 0, 8, 0, 2, 0, 0, 0]);
        not_a_confirm[5] = 0xe0;
        assert_eq!(negotiated(&not_a_confirm), Negotiated::Other);
        assert_eq!(negotiated(&[3, 0]), Negotiated::Other);
    }

    #[tokio::test]
    async fn an_answer_is_one_bounded_tpkt_packet() {
        let packet = confirm([2, 0, 8, 0, 2, 0, 0, 0]);
        let mut with_more = packet.clone();
        with_more.extend_from_slice(b"next");
        let mut r = &with_more[..];
        assert_eq!(read_tpkt(&mut r).await.unwrap(), packet);
        assert_eq!(r, b"next", "nothing after it is read");
        for bad in [vec![4, 0, 0, 19], vec![3, 0, 0, 4], vec![3, 0, 0xff, 0xff]] {
            assert!(read_tpkt(&mut &bad[..]).await.is_err(), "{bad:?}");
        }
    }

    /// The agent's stream takes a little at a time when its window is full, as this pipe does.
    #[tokio::test]
    async fn what_the_page_sends_reaches_the_machine_whole() {
        let (near, far) = tokio::io::duplex(512);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["pc".into()]).unwrap().self_signed(&key).unwrap();
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], rustls_pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()))
            .unwrap();
        let machine = tokio::spawn(async move {
            let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(server)).accept(far).await.unwrap();
            let mut got = vec![0u8; 200_000];
            tls.read_exact(&mut got).await.map(|_| got)
        });
        let name = ServerName::try_from("rdp.invalid").unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(tls_config()).connect(name, near).await.unwrap();
        let sent: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        for message in sent.chunks(50_000) {
            send_to_machine(&mut tls, message).await.unwrap();
        }
        // Nothing more is written: what's left in the TLS stream must already be on its way.
        let got = tokio::time::timeout(Duration::from_secs(10), machine).await.expect("all of it arrived").unwrap().unwrap();
        assert!(got == sent);
        drop(tls);
    }

    #[test]
    fn a_machine_is_known_by_its_key() {
        let key = rcgen::KeyPair::generate().unwrap();
        let a = rcgen::CertificateParams::new(vec!["pc".into()]).unwrap().self_signed(&key).unwrap();
        let b = rcgen::CertificateParams::new(vec!["pc-renewed".into()]).unwrap().self_signed(&key).unwrap();
        let other = rcgen::CertificateParams::new(vec!["pc".into()]).unwrap().self_signed(&rcgen::KeyPair::generate().unwrap()).unwrap();
        let fp = key_fingerprint(a.der()).unwrap();
        assert!(fp.starts_with("SHA256:") && fp.len() == 7 + 43, "{fp}");
        assert_eq!(key_fingerprint(b.der()).unwrap(), fp, "a certificate reissued for the same key");
        assert_ne!(key_fingerprint(other.der()).unwrap(), fp);
        assert!(key_fingerprint(b"not a certificate").is_none());
    }
}
