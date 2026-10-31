//! Agent operations behind the IPC API. `add` implements the readiness state machine:
//!
//! ```text
//! LOCAL_OK -> AGENT_CONNECTED -> ROUTE_REGISTERED -> TLS_READY -> PROBING -> READY
//!     \______________\________________\_______________\____________\-> FAILED(step, code)
//! ```
//!
//! Port tunnels (`tcp`, `udp`) replace the last two steps: the server checks the path to the
//! local service (CHECKED), then, for TCP, this machine connects to the public port. That last
//! probe only warns when it fails, since some networks cannot reach their own public address.
//!
//! Every step is bounded by the request's overall deadline. On failure a tunnel created by this
//! request is unregistered again; pre-existing tunnels are left untouched.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use magicpipes_core::cidr;
use magicpipes_core::proto::{CertState, Kind, RegisterTunnel, Request as Rpc, Response as RpcResponse, TunnelInfo};
use rustls::ClientConfig;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use super::probe;
use super::serve;
use super::session::{ConnState, RpcError, Session};
use super::shell;
use super::tunnels::{Registration, Tunnels};
use crate::ipc::{AddRequest, ErrorInfo, IpcEvent, Step, StepState};
use crate::state::{LocalTunnel, Target, address, target_url};

pub struct Agent {
    pub session: Arc<Session>,
    pub tunnels: Arc<Tunnels>,
    pub shutdown: CancellationToken,
    tls: Arc<ClientConfig>,
    /// Serializes the find-or-register step so concurrent `add`s of one port don't duplicate.
    register_lock: Mutex<()>,
    inflight: AtomicUsize,
    started_at: i64,
}

struct Events<'a>(&'a mpsc::Sender<IpcEvent>);

impl Events<'_> {
    async fn step(&self, step: Step, state: StepState) {
        let _ = self.0.send(IpcEvent::Step { step, state }).await;
    }
}

struct InflightGuard<'a>(&'a AtomicUsize);
impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Agent {
    pub fn new(session: Arc<Session>, tunnels: Arc<Tunnels>, tls: Arc<ClientConfig>, shutdown: CancellationToken) -> Arc<Self> {
        Arc::new(Self {
            session,
            tunnels,
            shutdown,
            tls,
            register_lock: Mutex::new(()),
            inflight: AtomicUsize::new(0),
            started_at: magicpipes_core::unix_now(),
        })
    }

    pub async fn add(&self, req: AddRequest, tx: &mpsc::Sender<IpcEvent>) -> Result<Value, ErrorInfo> {
        self.inflight.fetch_add(1, Ordering::SeqCst);
        let _guard = InflightGuard(&self.inflight);
        let ev = Events(tx);
        let deadline = Instant::now() + Duration::from_secs(req.timeout_secs.clamp(5, 900));
        let remaining = || deadline.saturating_duration_since(Instant::now());

        // 1. Local service.
        ev.step(Step::Local, StepState::Running).await;
        let target = match local_target(&req).await {
            Ok(t) => t,
            Err(e) => {
                ev.step(Step::Local, StepState::Failed).await;
                return Err(e.at(Step::Local));
            }
        };
        ev.step(Step::Local, StepState::Done).await;

        // 2. Server session.
        ev.step(Step::Connect, StepState::Running).await;
        if let Err(msg) = self.session.wait_connected(remaining().min(Duration::from_secs(20))).await {
            ev.step(Step::Connect, StepState::Failed).await;
            let code = if matches!(self.session.state(), ConnState::Unauthorized(_)) { "unauthorized" } else { "server_unreachable" };
            return Err(ErrorInfo::new(code, msg).at(Step::Connect));
        }
        ev.step(Step::Connect, StepState::Done).await;

        // 3. Registration (find-or-create, serialized).
        ev.step(Step::Register, StepState::Running).await;
        let (tunnel, created) = match self.register(&req, target).await {
            Ok(v) => v,
            Err(e) => {
                ev.step(Step::Register, StepState::Failed).await;
                return Err(e.at(Step::Register));
            }
        };
        ev.step(Step::Register, StepState::Done).await;

        let result = match tunnel.kind {
            Kind::Http => self.verify(&tunnel, &req, &ev, deadline).await.map(|()| None),
            _ => self.verify_port(&tunnel, &ev, deadline).await,
        };
        let reachable = match result {
            Ok(r) => r,
            Err(e) => {
                if created {
                    self.forget(&tunnel).await;
                    tracing::info!(tunnel = %tunnel.name, "removed tunnel after failed readiness check");
                }
                return Err(e);
            }
        };
        tracing::info!(tunnel = %tunnel.name, url = %tunnel.public_url, "tunnel ready");
        let mut out = json!({
            "id": tunnel.id,
            "name": tunnel.name,
            "kind": tunnel.kind,
            "public_url": tunnel.public_url,
            "target": tunnel.describe(),
            "share_url": tunnel.share_url(),
            "status": "ready",
            "background": true,
            "created": created,
        });
        if let Some(port) = tunnel.public_port {
            out["public_port"] = json!(port);
            out["allow"] = json!(tunnel.allow);
        }
        match tunnel.kind {
            Kind::Tcp => out["reachable"] = json!(reachable),
            // A datagram service cannot be checked end to end (it need not answer anything).
            Kind::Udp => out["verified"] = json!(false),
            Kind::Http => {}
        }
        Ok(out)
    }

    /// Unregisters a tunnel this request created and forgets it locally.
    async fn forget(&self, tunnel: &LocalTunnel) {
        let _ = self.session.rpc(&Rpc::Unregister { id: tunnel.id.clone() }, Duration::from_secs(10)).await;
        self.tunnels.remove(&tunnel.id);
    }

    async fn register(&self, req: &AddRequest, mut target: Target) -> Result<(LocalTunnel, bool), ErrorInfo> {
        let _lock = self.register_lock.lock().await;
        let name = match &req.name {
            Some(n) => Some(magicpipes_core::names::validate(n).map_err(|m| ErrorInfo::new("invalid_name", m))?),
            None => None,
        };
        let existing = match &name {
            Some(n) => self.tunnels.find(|t| &t.name == n),
            None => self.tunnels.find(|t| t.kind == req.kind && t.target.same_destination(&target)),
        };
        if let Some(t) = &existing
            && (t.kind != req.kind || !t.target.same_destination(&target))
        {
            return Err(ErrorInfo::new(
                "name_conflict",
                format!("tunnel '{}' already forwards to {}; remove it first or pick another --name", t.name, t.describe()),
            ));
        }
        // A writable shell keeps its key across re-adds, so links already shared keep working.
        if let Target::Shell { writable: true, key, .. } = &mut target {
            let old = existing.as_ref().and_then(|t| match &t.target {
                Target::Shell { writable: true, key, .. } => key.clone(),
                _ => None,
            });
            *key = old.or_else(|| Some(magicpipes_core::secret::random_string(32)));
        }
        // Settings follow the latest `add`: re-adding without --allow-cidr opens the port to anyone.
        let allow: Vec<String> = cidr::parse_list(&req.allow)
            .map_err(|m| ErrorInfo::new("invalid_cidr", m))?
            .iter()
            .map(ToString::to_string)
            .collect();
        let mut rpc_req = RegisterTunnel {
            id: existing.as_ref().map(|t| t.id.clone()),
            name: existing.as_ref().map(|t| t.name.clone()).or(name.clone()),
            target: target.describe(req.kind),
            kind: req.kind,
            remote_port: req.remote_port,
            allow: allow.clone(),
        };
        let info: TunnelInfo = loop {
            match self.session.rpc(&Rpc::Register(rpc_req.clone()), Duration::from_secs(15)).await {
                Ok(RpcResponse::Tunnel(info)) => break info,
                Err(RpcError::Server(e)) if e.code == "not_found" && rpc_req.id.is_some() => {
                    // Deleted on the server while we still had it: forget it and register anew.
                    if let Some(id) = rpc_req.id.take() {
                        self.tunnels.remove(&id);
                    }
                    rpc_req.name = name.clone();
                }
                Err(RpcError::Server(e)) => return Err(ErrorInfo::new(&e.code, e.message)),
                Err(e) => return Err(ErrorInfo::new("server_unreachable", e.to_string())),
                Ok(other) => return Err(ErrorInfo::new("protocol", format!("unexpected response {other:?}"))),
            }
        };
        if info.kind != req.kind {
            // A server that predates port tunnels ignores `kind` and registers an HTTP tunnel.
            if info.created {
                let _ = self.session.rpc(&Rpc::Unregister { id: info.id.clone() }, Duration::from_secs(10)).await;
            }
            return Err(ErrorInfo::new(
                "server_outdated",
                format!("the server does not support {} tunnels; it needs a newer magicpipesd", req.kind),
            ));
        }
        let tunnel = LocalTunnel {
            created_at: existing.as_ref().map(|t| t.created_at).unwrap_or_else(magicpipes_core::unix_now),
            id: info.id,
            name: info.name,
            hostname: info.hostname,
            public_url: info.public_url,
            target,
            kind: info.kind,
            public_port: info.public_port,
            allow,
        };
        self.tunnels.upsert(tunnel.clone(), Registration::Registered);
        Ok((tunnel, info.created))
    }

    async fn verify(&self, t: &LocalTunnel, req: &AddRequest, ev: &Events<'_>, deadline: Instant) -> Result<(), ErrorInfo> {
        let remaining = || deadline.saturating_duration_since(Instant::now());

        // 4. Certificate.
        ev.step(Step::Tls, StepState::Running).await;
        loop {
            let wait = remaining().min(Duration::from_secs(25));
            let rpc = Rpc::CertStatus { hostname: t.hostname.clone(), wait_ms: wait.as_millis() as u64 };
            match self.session.rpc(&rpc, wait + Duration::from_secs(10)).await {
                Ok(RpcResponse::Cert(CertState::Ready)) => break,
                Ok(RpcResponse::Cert(CertState::Failed { message })) => {
                    ev.step(Step::Tls, StepState::Failed).await;
                    return Err(ErrorInfo::new("tls_failed", format!("certificate provisioning failed.\n{message}")).at(Step::Tls));
                }
                Ok(RpcResponse::Cert(CertState::Pending)) if !remaining().is_zero() => continue,
                Ok(RpcResponse::Cert(CertState::Pending)) => {
                    ev.step(Step::Tls, StepState::Failed).await;
                    return Err(ErrorInfo::new(
                        "tls_timeout",
                        format!(
                            "the certificate for {} is still being issued after {}s. The server keeps trying; run the command again shortly",
                            t.hostname, req.timeout_secs
                        ),
                    )
                    .at(Step::Tls));
                }
                Ok(other) => return Err(ErrorInfo::new("protocol", format!("unexpected response {other:?}")).at(Step::Tls)),
                Err(e) => {
                    ev.step(Step::Tls, StepState::Failed).await;
                    let code = match &e {
                        RpcError::Server(b) => b.code.clone(),
                        RpcError::Unavailable(_) => "server_unreachable".into(),
                    };
                    return Err(ErrorInfo::new(&code, e.to_string()).at(Step::Tls));
                }
            }
        }
        ev.step(Step::Tls, StepState::Done).await;

        // 5. End-to-end probe through the public HTTPS endpoint.
        ev.step(Step::Probe, StepState::Running).await;
        loop {
            let last = match probe::probe(t, &req.probe_path, &self.tls, &self.tunnels).await {
                Ok(status) => {
                    tracing::debug!(tunnel = %t.name, status, "probe succeeded");
                    break;
                }
                Err(e) => e,
            };
            if remaining() < Duration::from_millis(500) {
                ev.step(Step::Probe, StepState::Failed).await;
                return Err(ErrorInfo::new("probe_failed", format!("public endpoint verification failed: {last}")).at(Step::Probe));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        ev.step(Step::Probe, StepState::Done).await;
        Ok(())
    }

    /// Port tunnels: the server's check of the path to the local service, then (TCP) a connection
    /// from this machine to the public port. Returns whether that connection came through.
    async fn verify_port(&self, t: &LocalTunnel, ev: &Events<'_>, deadline: Instant) -> Result<Option<bool>, ErrorInfo> {
        let remaining = || deadline.saturating_duration_since(Instant::now());
        ev.step(Step::Check, StepState::Running).await;
        match self.session.rpc(&Rpc::Check { id: t.id.clone() }, remaining().min(Duration::from_secs(30))).await {
            Ok(_) => ev.step(Step::Check, StepState::Done).await,
            Err(e) => {
                ev.step(Step::Check, StepState::Failed).await;
                let err = match e {
                    RpcError::Server(b) if b.code == "local_unreachable" => {
                        ErrorInfo::new("local_unreachable", format!("the server reached this agent, but {} refused the connection", t.describe()))
                    }
                    RpcError::Server(b) => ErrorInfo::new(&b.code, b.message),
                    RpcError::Unavailable(m) => ErrorInfo::new("server_unreachable", m),
                };
                return Err(err.at(Step::Check));
            }
        }
        if t.kind != Kind::Tcp {
            return Ok(None);
        }
        ev.step(Step::Probe, StepState::Running).await;
        let reachable = match probe::tcp(t, &self.tunnels, remaining().min(Duration::from_secs(10))).await {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(tunnel = %t.name, error = %e, "public port not reachable from this machine");
                false
            }
        };
        ev.step(Step::Probe, if reachable { StepState::Done } else { StepState::Warned }).await;
        Ok(Some(reachable))
    }

    pub async fn remove(&self, selector: &str, force: bool) -> Result<Value, ErrorInfo> {
        let port = selector.parse::<u16>().ok();
        let matches: Vec<LocalTunnel> = self
            .tunnels
            .list()
            .into_iter()
            .filter(|t| t.name == selector || t.id == selector || matches!(&t.target, Target::Port { port: p, .. } if port == Some(*p)))
            .collect();
        let t = match matches.as_slice() {
            [] => return Err(ErrorInfo::new("not_found", format!("no tunnel named '{selector}'"))),
            [t] => t.clone(),
            many => match many.iter().find(|t| t.name == selector || t.id == selector) {
                Some(t) => t.clone(),
                None => {
                    let names: Vec<&str> = many.iter().map(|t| t.name.as_str()).collect();
                    return Err(ErrorInfo::new(
                        "name_conflict",
                        format!("several tunnels use port {selector} ({}); give the tunnel's name", names.join(", ")),
                    ));
                }
            },
        };
        if !force {
            let _ = self.session.wait_connected(Duration::from_secs(10)).await;
        }
        match self.session.rpc(&Rpc::Unregister { id: t.id.clone() }, Duration::from_secs(15)).await {
            Ok(_) => {}
            Err(e) if !force => {
                return Err(ErrorInfo::new(
                    "server_unreachable",
                    format!("could not unregister '{}' on the server: {e}. Use --force to remove it locally only", t.name),
                ));
            }
            Err(e) => tracing::warn!(tunnel = %t.name, error = %e, "removing locally only"),
        }
        self.tunnels.remove(&t.id);
        tracing::info!(tunnel = %t.name, "tunnel removed");
        Ok(json!({ "id": t.id, "name": t.name, "removed": true }))
    }

    fn connection(&self) -> (&'static str, Option<String>) {
        match self.session.state() {
            ConnState::Connected { handle, .. } if !handle.is_closed() => ("connected", None),
            ConnState::Connected { .. } => ("connecting", None),
            ConnState::Connecting { last_error, .. } => ("connecting", last_error),
            ConnState::Unauthorized(m) => ("unauthorized", Some(m)),
        }
    }

    pub fn list(&self) -> Value {
        let (conn, _) = self.connection();
        let tunnels: Vec<Value> = self
            .tunnels
            .snapshots()
            .into_iter()
            .map(|s| {
                let status = match (conn, s.registration) {
                    ("connected", Registration::Registered) => "connected",
                    ("connected", Registration::Failed) => "error",
                    ("connected", Registration::Pending) | ("connecting", _) => "connecting",
                    _ => "disconnected",
                };
                json!({
                    "id": s.tunnel.id,
                    "name": s.tunnel.name,
                    "kind": s.tunnel.kind,
                    "public_url": s.tunnel.public_url,
                    "target": s.tunnel.describe(),
                    "share_url": s.tunnel.share_url(),
                    "status": status,
                    "error": s.last_error,
                    "created_at": magicpipes_core::rfc3339(s.tunnel.created_at),
                })
            })
            .collect();
        json!({ "agent_running": true, "connection": conn, "tunnels": tunnels })
    }

    pub fn status(&self) -> Value {
        let (conn, err) = self.connection();
        let (connected_since, reconnect_attempt) = match self.session.state() {
            ConnState::Connected { since, .. } => (Some(magicpipes_core::rfc3339(since)), None),
            ConnState::Connecting { attempt, .. } => (None, Some(attempt)),
            ConnState::Unauthorized(_) => (None, None),
        };
        json!({
            "agent": {
                "running": true,
                "pid": std::process::id(),
                "version": magicpipes_core::VERSION,
                "started_at": magicpipes_core::rfc3339(self.started_at),
            },
            "server": self.session.server(),
            "connection": conn,
            "connected_since": connected_since,
            "reconnect_attempt": reconnect_attempt,
            "last_error": err,
            "tunnels": self.tunnels.len(),
        })
    }

    pub fn shutdown(&self, if_idle: bool) -> Result<Value, ErrorInfo> {
        // The request asking for shutdown is not itself counted as in-flight work.
        if if_idle && (self.tunnels.len() > 0 || self.inflight.load(Ordering::SeqCst) > 0) {
            return Err(ErrorInfo::new("busy", "agent has active tunnels or operations"));
        }
        self.shutdown.cancel();
        Ok(json!({ "stopping": true }))
    }
}

/// Checks the local side of an `add`: a listening port, a directory to serve, or a program to
/// run in a web terminal.
async fn local_target(req: &AddRequest) -> Result<Target, ErrorInfo> {
    if let Some(command) = &req.shell {
        let cwd = req.cwd.clone().ok_or_else(|| ErrorInfo::new("invalid_request", "--shell needs a working directory"))?;
        shell::check(command, &cwd)?;
        let max_clients = req.max_clients.unwrap_or(shell::DEFAULT_MAX_CLIENTS);
        if max_clients == 0 {
            return Err(ErrorInfo::new("invalid_request", "--max-clients must be at least 1"));
        }
        // The key is assigned at registration (kept from an existing tunnel when re-added).
        return Ok(Target::Shell { shell: command.clone(), cwd, writable: req.writable, key: None, max_clients });
    }
    if !req.kind.is_http() && (req.serve.is_some() || req.port.is_none()) {
        return Err(ErrorInfo::new("invalid_request", format!("--{} needs a local port", req.kind)));
    }
    cidr::parse_list(&req.allow).map_err(|m| ErrorInfo::new("invalid_cidr", m))?;
    match (&req.serve, req.port) {
        (Some(dir), _) => Ok(Target::Static { serve: serve::check_root(dir).await?, list: req.list }),
        // A UDP service cannot be probed: anything may or may not answer a datagram.
        (None, Some(port)) if req.kind == Kind::Udp => {
            let host = req.host.clone().unwrap_or_else(|| "127.0.0.1".into());
            check_host(&host)?;
            if port == 0 {
                return Err(ErrorInfo::new("invalid_port", "port must be between 1 and 65535"));
            }
            Ok(Target::Port { host, port })
        }
        (None, Some(port)) => Ok(Target::Port { host: resolve_local(req.host.as_deref(), port, req.kind).await?, port }),
        (None, None) => Err(ErrorInfo::new("invalid_request", "give a local port, --serve <dir> or --shell")),
    }
}

fn check_host(h: &str) -> Result<(), ErrorInfo> {
    if h.is_empty() || !h.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b)) {
        return Err(ErrorInfo::new("invalid_host", format!("invalid host '{h}'")));
    }
    Ok(())
}

/// Finds where the local application listens: the given host, or 127.0.0.1 then ::1.
async fn resolve_local(host: Option<&str>, port: u16, kind: Kind) -> Result<String, ErrorInfo> {
    if port == 0 {
        return Err(ErrorInfo::new("invalid_port", "port must be between 1 and 65535"));
    }
    let candidates: Vec<&str> = match host {
        Some(h) => {
            check_host(h)?;
            vec![h]
        }
        None => vec!["127.0.0.1", "::1"],
    };
    for h in &candidates {
        if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect((*h, port))).await {
            return Ok(h.to_string());
        }
    }
    Err(ErrorInfo::new(
        "local_unreachable",
        format!(
            "nothing is accepting connections on {}. Start your application first",
            if kind.is_http() { target_url(candidates[0], port) } else { address(kind.as_str(), candidates[0], port) }
        ),
    ))
}
