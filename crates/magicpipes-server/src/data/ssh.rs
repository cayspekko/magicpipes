//! The SSH gateway: a jump host for `ssh -J`, and nothing else.
//!
//! A client authenticates with a public key registered on someone's account, then asks for a
//! `direct-tcpip` channel to a tunnel's name. [`authz::authorize`] decides, the same way as for a
//! private tunnel's web page, and the channel is piped into a data stream to the tunnel's agent,
//! which connects to its local sshd. The client's real SSH session runs inside, end to end: this
//! side only sees ciphertext, and holds no credentials for any machine. The host and port the client
//! asks for are never dialed; the name only picks a tunnel, and the agent knows its own target.
//!
//! There is no shell. A session channel gets the list of machines its user can reach, or with the
//! command `config` entries for `~/.ssh/config`, and ends.
//!
//! Everything comes from the [`RouteTable`] snapshot, as for all traffic, and open connections are
//! checked again on every publish. What is worth writing down goes to the control plane through a
//! queue ([`Connected`]), so nothing here waits for the database.

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use magicpipes_core::proto::ServerOpen;
use russh::keys::ssh_key::LineEnding;
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::{HashAlg, PrivateKey};
use russh::server::{Auth, ChannelOpenHandle, Config, Handler, Msg, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId, ChannelOpenFailure, MethodKind, MethodSet, Pty, SshId};
use socket2::{SockRef, TcpKeepalive};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

use super::{AgentLink, DataPlane, GatewayKey, Outcome, Route, RouteTable, ports};
use crate::authz::Principal;
use crate::config::SshConfig;
use crate::listen::PerClient;
use crate::proxy_header;

/// Reports waiting for the control plane; more are dropped.
pub(super) const REPORT_QUEUE: usize = 256;

/// Time to get authenticated. Long enough for a person to touch a hardware key or type a passphrase.
const SIGN_IN_TIME: Duration = Duration::from_secs(60);
/// Connections still authenticating, in all and per client. Each costs some processor time.
const MAX_HANDSHAKES: usize = 128;
const MAX_HANDSHAKES_PER_CLIENT: usize = 8;
/// Key attempts per connection: as many as a person's SSH agent is likely to offer.
const MAX_AUTH_ATTEMPTS: usize = 10;
/// Channels at once per connection. `ssh -J` needs one; a shared connection (`ControlMaster`) a few.
const MAX_CHANNELS: usize = 16;
/// Machines in the list of a session channel.
const MAX_LISTED: usize = 200;
/// Every attempt with a key that isn't known takes this long.
const REJECTION_TIME: Duration = Duration::from_millis(200);
/// Dead clients are noticed after three of these without an answer.
const KEEPALIVE: Duration = Duration::from_secs(30);
/// What a channel asked for doesn't exist, or isn't this person's to reach: the same answer.
const NO_SUCH_MACHINE: &str = "no such machine";
const CONNECT_FAILED: u32 = 2;

/// What the gateway and browser terminals report to the control plane, which writes it down.
#[derive(Debug)]
pub enum Report {
    /// Someone reached a machine through the gateway (`ssh -J`).
    Connected { user_id: String, key_id: String, tunnel_id: String, client: std::net::IpAddr },
    /// Someone logged in to a machine in a browser terminal.
    Terminal { user_id: String, tunnel_id: String, login: String, client: std::net::IpAddr },
    /// The first host key a tunnel's sshd showed a browser terminal, to be kept.
    HostKey { tunnel_id: String, fingerprint: String },
    /// Someone reached a private TCP or UDP tunnel with `magicpipes connect`.
    Connect { user_id: String, tunnel_id: String, client: std::net::IpAddr },
    /// Someone opened a remote desktop in the browser: `rdp.desktop` or `vnc.desktop`.
    Desktop { user_id: String, tunnel_id: String, client: std::net::IpAddr, kind: magicpipes_core::proto::Kind },
}

/// Random bytes from the system.
pub(super) fn random<const N: usize>() -> anyhow::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes).map_err(|_| anyhow::anyhow!("no system randomness"))?;
    Ok(bytes)
}

/// A new Ed25519 key.
pub(super) fn new_key(comment: &str) -> anyhow::Result<PrivateKey> {
    Ok(PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::from_seed(&random()?)), comment)?)
}

/// A key kept in `<data_dir>/<file>` in OpenSSH's format, so `ssh-keygen -lf` reads it: the
/// gateway's host key (`ssh-host-key`) and the certificate authority for browser terminals
/// (`ssh-user-ca`). Made on first use. Anything wrong with an existing one stops the server: a new
/// host key would have every client warn about an attack, and a new authority would lock everyone
/// out of the machines that trust the old one.
pub fn load_key(data_dir: &Path, file: &str, comment: &str) -> anyhow::Result<PrivateKey> {
    let path = data_dir.join(file);
    match std::fs::read_to_string(&path) {
        Ok(text) => PrivateKey::from_openssh(text).map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let key = new_key(comment)?;
            crate::certs::write_private(&path, key.to_openssh(LineEnding::LF)?.as_bytes())?;
            Ok(key)
        }
        Err(e) => Err(anyhow::anyhow!("reading {}: {e}", path.display())),
    }
}

/// Serves the gateway until `shutdown`.
pub async fn serve(listener: TcpListener, key: PrivateKey, dp: Arc<DataPlane>, settings: SshConfig, shutdown: CancellationToken) {
    let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
    tracing::info!(listen = %settings.listen, %fingerprint, "SSH gateway started");
    let _ = dp.ssh_fingerprint.set(fingerprint);
    let config = Arc::new(Config {
        server_id: SshId::Standard("SSH-2.0-magicpipes".into()),
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        auth_rejection_time: REJECTION_TIME,
        // OpenSSH always starts by asking what's on offer.
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![key],
        max_auth_attempts: MAX_AUTH_ATTEMPTS,
        // A quiet session is normal. Keepalives find the dead ones.
        inactivity_timeout: None,
        keepalive_interval: Some(KEEPALIVE),
        keepalive_max: 3,
        nodelay: true,
        ..Config::default()
    });
    let connections = Arc::new(Semaphore::new(settings.max_connections.max(1)));
    let handshakes = Arc::new(Semaphore::new(MAX_HANDSHAKES));
    let per_client = Arc::new(PerClient::default());
    let handshakes_per_client = Arc::new(PerClient::default());
    let max_per_client = settings.max_connections_per_client.max(1);
    loop {
        let (tcp, peer) = tokio::select! {
            _ = shutdown.cancelled() => return,
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "SSH gateway: accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            tracing::warn!(%peer, "SSH gateway: too many connections; refusing");
            continue;
        };
        let (dp, config, handshakes, per_client, handshakes_per_client, stop) =
            (dp.clone(), config.clone(), handshakes.clone(), per_client.clone(), handshakes_per_client.clone(), shutdown.child_token());
        let proxy_protocol = settings.proxy_protocol;
        tokio::spawn(async move {
            let _permit = permit;
            let mut tcp = tcp;
            let Some(peer) = client_address(&dp, &mut tcp, peer, proxy_protocol).await else { return };
            let Some(_slot) = per_client.acquire(peer.ip(), max_per_client) else {
                return tracing::debug!(%peer, "SSH gateway: too many connections from this client");
            };
            let Some(handshake_slot) = handshakes_per_client.acquire(peer.ip(), MAX_HANDSHAKES_PER_CLIENT) else {
                return tracing::debug!(%peer, "SSH gateway: too many unauthenticated connections from this client");
            };
            let Ok(handshake) = handshakes.try_acquire_owned() else {
                return tracing::debug!(%peer, "SSH gateway: too many unauthenticated connections");
            };
            connection(dp, config, tcp, peer, (handshake, Box::new(handshake_slot)), stop).await;
        });
    }
}

/// The real client's address, when a trusted proxy in front says so.
async fn client_address(dp: &DataPlane, tcp: &mut TcpStream, peer: SocketAddr, proxy_protocol: bool) -> Option<SocketAddr> {
    let _ = tcp.set_nodelay(true);
    let _ = SockRef::from(&*tcp).set_tcp_keepalive(&TcpKeepalive::new().with_time(Duration::from_secs(60)));
    if !proxy_protocol {
        return Some(peer);
    }
    match proxy_header::client_addr(tcp, peer, &dp.settings.trusted_proxies).await {
        Ok(client) => Some(client),
        Err(e) => {
            tracing::debug!(%peer, error = %e, "SSH gateway: bad PROXY header");
            None
        }
    }
}

/// What stops a connection from being authenticated: released when it is.
type Handshake = (OwnedSemaphorePermit, Box<dyn Send + Sync>);

/// One client, from the handshake until it leaves, its time runs out or its key stops counting.
async fn connection(dp: Arc<DataPlane>, config: Arc<Config>, tcp: TcpStream, peer: SocketAddr, handshake: Handshake, stop: CancellationToken) {
    // russh runs the session in a task of its own. Shutting the socket down is what ends that from
    // here, whatever it's waiting for, and costs reads and writes nothing until then.
    let socket = match SockRef::from(&tcp).try_clone() {
        Ok(s) => s,
        Err(e) => return tracing::warn!(error = %e, "SSH gateway: can't manage a socket"),
    };
    let signed_in = CancellationToken::new();
    let key_gone = CancellationToken::new();
    let handler = Client {
        dp: dp.clone(),
        peer,
        who: None,
        handshake: Some(handshake),
        signed_in: signed_in.clone(),
        key_gone: key_gone.clone(),
        stop: stop.clone(),
        channels: Arc::new(Semaphore::new(MAX_CHANNELS)),
        sessions: Vec::new(),
        pty: false,
    };
    let session = async {
        match russh::server::run_stream(config, tcp, handler).await {
            Ok(running) => {
                if let Err(e) = running.await {
                    tracing::debug!(%peer, error = %e, "SSH gateway: connection ended");
                }
            }
            Err(e) => tracing::debug!(%peer, error = %e, "SSH gateway: handshake failed"),
        }
    };
    let out_of_time = async {
        if tokio::time::timeout(SIGN_IN_TIME, signed_in.cancelled()).await.is_err() {
            tracing::debug!(%peer, "SSH gateway: not authenticated in time");
        } else {
            std::future::pending::<()>().await
        }
    };
    tokio::select! {
        _ = session => {}
        _ = out_of_time => {}
        _ = stop.cancelled() => {}
        _ = key_gone.cancelled() => tracing::debug!(%peer, "SSH gateway: closing a connection whose key no longer counts"),
    }
    stop.cancel();
    let _ = socket.shutdown(std::net::Shutdown::Both);
}

/// Who a connection authenticated as.
#[derive(Debug, Clone)]
struct SignedIn {
    fingerprint: String,
    key: GatewayKey,
}

impl SignedIn {
    /// Their principal as of `table`, if the key and its owner still count.
    fn principal<'t>(&self, table: &'t RouteTable) -> Option<&'t Principal> {
        if table.ssh_keys.get(&self.fingerprint) != Some(&self.key) {
            return None;
        }
        table.users.get(&self.key.user_id).map(|u| &u.principal)
    }
}

/// A tunnel's name from what a client asked to connect to: the name, or its full hostname.
fn machine_name(asked: &str, base_domain: &str) -> String {
    let asked = asked.trim_end_matches('.').to_ascii_lowercase();
    match asked.strip_suffix(base_domain).and_then(|n| n.strip_suffix('.')) {
        Some(name) => name.to_string(),
        None => asked,
    }
}

struct Client {
    dp: Arc<DataPlane>,
    peer: SocketAddr,
    who: Option<SignedIn>,
    handshake: Option<Handshake>,
    signed_in: CancellationToken,
    key_gone: CancellationToken,
    stop: CancellationToken,
    channels: Arc<Semaphore>,
    /// Session channels, which live until they've been answered.
    sessions: Vec<(Channel<Msg>, OwnedSemaphorePermit)>,
    pty: bool,
}

impl Client {
    /// The route for a channel to `asked`, and the agent's connections; or what to tell the client.
    fn route(&self, who: &SignedIn, asked: &str) -> Result<(Arc<Route>, AgentLink), String> {
        let table = self.dp.table();
        let name = machine_name(asked, &self.dp.settings.base_domain);
        let found = who.principal(&table).and_then(|p| table.by_ssh.get(&name).filter(|r| r.access.admits(p, self.peer.ip())));
        let Some(route) = found else { return Err(NO_SUCH_MACHINE.into()) };
        match route.agent.as_ref().filter(|a| a.is_online()) {
            Some(a) => Ok((route.clone(), a.clone())),
            None => {
                route.stats.record(Outcome::AgentOffline);
                Err(format!("{name} is offline"))
            }
        }
    }

    /// The machines this person can reach, in order.
    fn machines(&self) -> Vec<String> {
        let Some(who) = &self.who else { return Vec::new() };
        let table = self.dp.table();
        let Some(principal) = who.principal(&table) else { return Vec::new() };
        let mut names: Vec<String> = table.by_ssh.iter().filter(|(_, r)| r.access.admits(principal, self.peer.ip())).map(|(n, _)| n.clone()).collect();
        names.sort();
        names
    }

    fn listing(&self) -> String {
        let address = self.dp.settings.ssh_address.as_deref().unwrap_or_default();
        let names = self.machines();
        let mut out = String::new();
        if names.is_empty() {
            out.push_str("No machines are shared with you yet. Publish one with: magicpipes add 22 --ssh\n");
        } else {
            out.push_str("Machines you can reach:\n\n");
            for name in names.iter().take(MAX_LISTED) {
                out.push_str(&format!("  ssh -J {address} {name}\n"));
            }
            if names.len() > MAX_LISTED {
                out.push_str(&format!("  and {} more\n", names.len() - MAX_LISTED));
            }
            let (host, port) = address.rsplit_once(':').filter(|(h, _)| !h.ends_with(':')).unwrap_or((address, "22"));
            out.push_str(&format!("\nFor plain `ssh <machine>`, add them to your configuration:\n\n  ssh -p {port} {host} config >> ~/.ssh/config\n"));
        }
        out
    }

    fn config_entries(&self) -> String {
        let address = self.dp.settings.ssh_address.as_deref().unwrap_or_default();
        self.machines().iter().take(MAX_LISTED).map(|name| format!("Host {name}\n    ProxyJump {address}\n\n")).collect()
    }

    /// Answers a session channel and ends it.
    fn answer(&self, channel: ChannelId, text: &str, status: u32, session: &mut Session) -> Result<(), russh::Error> {
        let text = if self.pty { text.replace('\n', "\r\n") } else { text.to_string() };
        session.data(channel, text.into_bytes())?;
        session.exit_status_request(channel, status)?;
        session.eof(channel)?;
        session.close(channel)
    }
}

impl Handler for Client {
    type Error = russh::Error;

    /// Every key is asked to sign, and only then looked up: whether a server knows a public key,
    /// which anyone can get from GitHub, isn't for someone without its private half to find out.
    async fn auth_publickey(&mut self, _user: &str, key: VerifiedPublicKey<'_>) -> Result<Auth, Self::Error> {
        let fingerprint = key.public_key.fingerprint(HashAlg::Sha256).to_string();
        let table = self.dp.table();
        let found = table.ssh_keys.get(&fingerprint).filter(|k| table.users.contains_key(&k.user_id)).cloned();
        let Some(found) = found else { return Ok(Auth::reject()) };
        let who = SignedIn { fingerprint, key: found };
        tokio::spawn(key_watch(self.dp.clone(), who.clone(), self.key_gone.clone(), self.stop.clone()));
        self.who = Some(who);
        self.handshake = None;
        self.signed_in.cancel();
        Ok(Auth::Accept)
    }

    /// `ssh -J`: the request to reach a machine. Answered once the agent has connected to it, from
    /// a task of its own, so that a slow agent holds up nothing else on this connection.
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(who) = self.who.clone() else { return Ok(()) };
        let Ok(permit) = self.channels.clone().try_acquire_owned() else {
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
            return Ok(());
        };
        let (route, agent) = match self.route(&who, host_to_connect) {
            Ok(v) => v,
            Err(reason) => {
                tracing::debug!(peer = %self.peer, user = %who.key.user_id, asked = %host_to_connect.escape_debug(), "SSH gateway: refused");
                reply.reject(ChannelOpenFailure::Other { code: CONNECT_FAILED, reason }).await;
                return Ok(());
            }
        };
        let handle = session.handle();
        let name = machine_name(host_to_connect, &self.dp.settings.base_domain);
        let (dp, peer, stop) = (self.dp.clone(), self.peer, self.stop.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let header = ServerOpen::Data { tunnel_id: route.tunnel_id.clone(), peer: Some(peer.to_string()) };
            let Some(stream) = ports::open(&dp, &route, &agent, peer.ip(), header).await else {
                reply.reject(ChannelOpenFailure::Other { code: CONNECT_FAILED, reason: format!("{name} did not answer") }).await;
                return;
            };
            reply.accept().await;
            let report = Report::Connected { user_id: who.key.user_id.clone(), key_id: who.key.id.clone(), tunnel_id: route.tunnel_id.clone(), client: peer.ip() };
            let _ = dp.ssh_reports.try_send(report);
            let id = channel.id();
            tokio::select! {
                _ = super::io::bridge(channel.into_stream(), stream, None, stop.child_token()) => {}
                _ = revoked(&dp, &who, &name, &route.tunnel_id, peer.ip()) => {
                    tracing::debug!(%peer, %name, "SSH gateway: closing a channel its user may no longer use");
                }
            }
            let _ = handle.close(id).await;
        });
        Ok(())
    }

    async fn channel_open_session(&mut self, channel: Channel<Msg>, reply: ChannelOpenHandle, _session: &mut Session) -> Result<(), Self::Error> {
        if self.who.is_none() {
            return Ok(());
        }
        let Ok(permit) = self.channels.clone().try_acquire_owned() else {
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
            return Ok(());
        };
        self.sessions.push((channel, permit));
        reply.accept().await;
        Ok(())
    }

    async fn channel_close(&mut self, channel: ChannelId, _session: &mut Session) -> Result<(), Self::Error> {
        self.sessions.retain(|(c, _)| c.id() != channel);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.pty = true;
        session.channel_success(channel)
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let text = self.listing();
        self.answer(channel, &text, 0, session)
    }

    async fn exec_request(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        match data {
            b"config" => {
                let text = self.config_entries();
                self.answer(channel, &text, 0, session)
            }
            b"list" => {
                let text = self.listing();
                self.answer(channel, &text, 0, session)
            }
            _ => self.answer(channel, "This server only forwards to machines, with ssh -J. It runs no commands except `list` and `config`.\n", 1, session),
        }
    }
}

/// Returns once the person may no longer reach the tunnel. Checked on every publish.
async fn revoked(dp: &DataPlane, who: &SignedIn, name: &str, tunnel_id: &str, client: std::net::IpAddr) {
    let mut changes = dp.generation.subscribe();
    loop {
        let table = dp.table();
        let ok = who.principal(&table).is_some_and(|p| table.by_ssh.get(name).is_some_and(|r| r.tunnel_id == tunnel_id && r.access.admits(p, client)));
        if !ok || changes.changed().await.is_err() {
            return;
        }
    }
}

/// Ends the connection once its key or its owner no longer counts.
async fn key_watch(dp: Arc<DataPlane>, who: SignedIn, gone: CancellationToken, stop: CancellationToken) {
    let mut changes = dp.generation.subscribe();
    loop {
        if who.principal(&dp.table()).is_none() {
            return gone.cancel();
        }
        tokio::select! {
            _ = stop.cancelled() => return,
            r = changes.changed() => if r.is_err() { return },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::Role;
    use crate::data::TunnelUser;

    #[test]
    fn machines_are_named_with_or_without_the_domain() {
        for asked in ["dev-box", "DEV-BOX", "dev-box.mp.example.com", "dev-box.mp.example.com."] {
            assert_eq!(machine_name(asked, "mp.example.com"), "dev-box", "{asked}");
        }
        assert_eq!(machine_name("dev-box.elsewhere.example", "mp.example.com"), "dev-box.elsewhere.example");
        assert_eq!(machine_name("mp.example.com", "mp.example.com"), "mp.example.com");
    }

    #[test]
    fn a_connection_counts_only_while_its_key_and_owner_do() {
        let key = GatewayKey { id: "key_a".into(), user_id: "us_a".into() };
        let who = SignedIn { fingerprint: "SHA256:a".into(), key: key.clone() };
        let principal = Principal::User { id: "us_a".into(), role: Role::Member, tags: vec![] };
        let user = TunnelUser { email: "a@example.com".into(), principal, valid_after: 0 };

        let mut table = RouteTable::default();
        assert!(who.principal(&table).is_none(), "nothing known");
        table.ssh_keys.insert("SHA256:a".into(), key.clone());
        assert!(who.principal(&table).is_none(), "the owner is disabled or gone");
        table.users.insert("us_a".into(), user);
        assert!(who.principal(&table).is_some());
        table.ssh_keys.insert("SHA256:a".into(), GatewayKey { id: "key_b".into(), user_id: "us_b".into() });
        assert!(who.principal(&table).is_none(), "the key was deleted, and someone else added it");
        table.ssh_keys.remove("SHA256:a");
        assert!(who.principal(&table).is_none(), "the key was deleted");
    }

    #[test]
    fn a_host_key_is_made_once_and_kept() {
        let dir = std::env::temp_dir().join(format!("mp-ssh-key-{}", magicpipes_core::secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let first = load_key(&dir, "ssh-host-key", "test").unwrap();
        let again = load_key(&dir, "ssh-host-key", "test").unwrap();
        assert_eq!(first.fingerprint(HashAlg::Sha256), again.fingerprint(HashAlg::Sha256));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.join("ssh-host-key")).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // A damaged key stops the server, rather than quietly becoming a new one.
        std::fs::write(dir.join("ssh-host-key"), "not a key").unwrap();
        assert!(load_key(&dir, "ssh-host-key", "test").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
