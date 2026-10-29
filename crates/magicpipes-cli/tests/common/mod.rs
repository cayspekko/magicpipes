//! End-to-end test harness: runs real `magicpipesd` and `magicpipes` processes in an isolated
//! temporary directory, with a development CA and loopback ports.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::sync::{Arc, Once};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

pub const BASE: &str = "t.test";

static BUILD: Once = Once::new();

/// Path of a workspace binary; builds `magicpipesd` once (cargo only builds this package's bins).
pub fn bin(name: &str) -> PathBuf {
    let cli = PathBuf::from(env!("CARGO_BIN_EXE_magicpipes"));
    if name == "magicpipes" {
        return cli;
    }
    BUILD.call_once(|| {
        let status = std::process::Command::new(env!("CARGO"))
            .args(["build", "-p", "magicpipes-server", "--bin", "magicpipesd"])
            .status()
            .expect("running cargo build");
        assert!(status.success(), "building magicpipesd failed");
    });
    cli.with_file_name(name)
}

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tls {
    DevCa,
    /// ACME pointed at an unreachable directory; management uses a test-generated certificate.
    BrokenAcme,
    /// ACME against a Pebble test CA (see `acme_with_pebble` in e2e.rs for the environment).
    Pebble,
}

pub struct Env {
    pub root: PathBuf,
    pub https_port: u16,
    pub http_port: u16,
    pub mgmt_port: u16,
    pub ca_path: PathBuf,
    server: Option<std::process::Child>,
    tls: Tls,
}

impl Env {
    pub async fn new(tls: Tls) -> Env {
        let root = std::env::temp_dir().join(format!("mpe2e-{}", magicpipes_core_rand()));
        std::fs::create_dir_all(root.join("home")).unwrap();
        let (https_port, mut http_port, mgmt_port) = (free_port(), free_port(), free_port());
        // With real HTTP-01 validation, Pebble connects to a fixed port (its `httpPort`).
        if tls == Tls::Pebble
            && let Some(p) = std::env::var("MAGICPIPES_PEBBLE_HTTP_PORT").ok().and_then(|p| p.parse().ok()) {
                http_port = p;
            }
        let mut tls_section = String::new();
        let mut mgmt_extra = String::new();
        let ca_path;
        match tls {
            Tls::DevCa => {
                tls_section.push_str("mode = \"dev-ca\"\n");
                ca_path = root.join("server/dev-ca/ca.crt");
            }
            Tls::Pebble => {
                let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} must be set for the Pebble test"));
                tls_section.push_str(&format!(
                    "mode = \"acme\"\nacme_directory = \"{}\"\nacme_ca_root = \"{}\"\nissuance_timeout_secs = 60\n",
                    var("MAGICPIPES_PEBBLE_DIRECTORY"),
                    var("MAGICPIPES_PEBBLE_API_CA"),
                ));
                let (ca, crt, key) = test_certs(&root);
                mgmt_extra = format!("cert_file = \"{}\"\nkey_file = \"{}\"\n", crt.display(), key.display());
                // Clients must trust both the management test CA and Pebble's issuing root.
                let bundle = root.join("trust.pem");
                let mut pem = std::fs::read_to_string(&ca).unwrap();
                pem.push_str(&std::fs::read_to_string(var("MAGICPIPES_PEBBLE_ISSUER_ROOT")).unwrap());
                std::fs::write(&bundle, pem).unwrap();
                ca_path = bundle;
            }
            Tls::BrokenAcme => {
                let dead = free_port();
                tls_section.push_str(&format!(
                    "mode = \"acme\"\nacme_directory = \"https://127.0.0.1:{dead}/directory\"\nissuance_timeout_secs = 10\n"
                ));
                let (ca, crt, key) = test_certs(&root);
                mgmt_extra = format!("cert_file = \"{}\"\nkey_file = \"{}\"\n", crt.display(), key.display());
                ca_path = ca;
            }
        }
        let cfg = format!(
            r#"base_domain = "{BASE}"
data_dir = "{data}"
[public]
https_listen = "127.0.0.1:{https_port}"
http_listen = "127.0.0.1:{http_port}"
websocket_idle_timeout_secs = 30
[management]
listen = "127.0.0.1:{mgmt_port}"
hostname = "localhost"
{mgmt_extra}
[tls]
{tls_section}
[agents]
session_timeout_secs = 20
"#,
            data = root.join("server").display(),
        );
        std::fs::write(root.join("server.toml"), cfg).unwrap();
        let mut env = Env { root, https_port, http_port, mgmt_port, ca_path, server: None, tls };
        env.start_server().await;
        env
    }

    pub fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    pub async fn start_server(&mut self) {
        assert!(self.server.is_none());
        let log = std::fs::OpenOptions::new().create(true).append(true).open(self.root.join("server.log")).unwrap();
        let child = std::process::Command::new(bin("magicpipesd"))
            .arg("--config")
            .arg(self.root.join("server.toml"))
            .env("MAGICPIPESD_LOG", "info,magicpipesd=debug")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("start magicpipesd");
        self.server = Some(child);
        wait_port(self.mgmt_port).await;
        wait_port(self.https_port).await;
        if self.tls == Tls::DevCa {
            let start = Instant::now();
            while !self.ca_path.exists() {
                assert!(start.elapsed() < Duration::from_secs(5));
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }

    pub async fn stop_server(&mut self) {
        if let Some(mut c) = self.server.take() {
            unsafe { libc::kill(c.id() as i32, libc::SIGTERM) };
            let start = Instant::now();
            while c.try_wait().unwrap().is_none() {
                if start.elapsed() > Duration::from_secs(20) {
                    let _ = c.kill();
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }

    pub fn server_log(&self) -> String {
        std::fs::read_to_string(self.root.join("server.log")).unwrap_or_default()
    }

    pub fn agent_log(&self) -> String {
        std::fs::read_to_string(self.home().join("agent.log")).unwrap_or_default()
    }

    pub fn admin_token(&self) -> String {
        std::fs::read_to_string(self.root.join("server/admin-token")).unwrap().trim().to_string()
    }

    fn cli_command(&self, args: &[&str]) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(bin("magicpipes"));
        cmd.args(args)
            .env("MAGICPIPES_HOME", self.home())
            .env("MAGICPIPES_SOCKET", self.root.join("a.sock"))
            .env("MAGICPIPES_PROBE_ADDR", "127.0.0.1")
            .env("MAGICPIPES_LOG", "info,magicpipes=debug")
            .env_remove("MAGICPIPES_TOKEN")
            .stdin(Stdio::null());
        cmd
    }

    pub async fn cli(&self, args: &[&str]) -> Output {
        self.cli_command(args).output().await.expect("run magicpipes")
    }

    pub async fn cli_ok(&self, args: &[&str]) -> Output {
        let out = self.cli(args).await;
        assert!(
            out.status.success(),
            "magicpipes {args:?} failed: {:?}\nstdout: {}\nstderr: {}\nagent log:\n{}\nserver log:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
            self.agent_log(),
            self.server_log()
        );
        out
    }

    pub async fn cli_json(&self, args: &[&str]) -> Value {
        let out = self.cli_ok(args).await;
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("invalid JSON from {args:?}: {e}: {}", String::from_utf8_lossy(&out.stdout)))
    }

    pub fn enrollment_token(&self) -> String {
        let out = std::process::Command::new(bin("magicpipesd"))
            .arg("--config")
            .arg(self.root.join("server.toml"))
            .arg("enroll")
            .output()
            .unwrap();
        assert!(out.status.success(), "enroll failed: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap().split_whitespace().last().unwrap().to_string()
    }

    pub fn server_url(&self) -> String {
        format!("https://localhost:{}", self.mgmt_port)
    }

    pub async fn login(&self) {
        let token = self.enrollment_token();
        let url = self.server_url();
        let ca = self.ca_path.to_string_lossy().to_string();
        self.cli_ok(&["login", "--server", &url, "--token", &token, "--ca-cert", &ca, "--name", "test-agent"]).await;
    }

    pub fn tls(&self) -> Arc<ClientConfig> {
        let pem = std::fs::read(&self.ca_path).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for c in CertificateDer::pem_slice_iter(&pem) {
            roots.add(c.unwrap()).unwrap();
        }
        Arc::new(
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    /// TLS connection to `host` (SNI + verification) on 127.0.0.1:`port`.
    pub async fn connect(&self, host: &str, port: u16) -> TlsStream<TcpStream> {
        self.try_connect(host, port).await.unwrap()
    }

    pub async fn try_connect(&self, host: &str, port: u16) -> std::io::Result<TlsStream<TcpStream>> {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
        TlsConnector::from(self.tls()).connect(ServerName::try_from(host.to_string()).unwrap(), tcp).await
    }

    pub async fn send(&self, host: &str, port: u16, req: Request<Full<Bytes>>) -> Response<Incoming> {
        let stream = self.connect(host, port).await;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        sender.send_request(req).await.unwrap()
    }

    /// GET on a public tunnel hostname; returns status, `x-magicpipes-error` and body.
    pub async fn get_public(&self, hostname: &str, path: &str) -> (StatusCode, Option<String>, String) {
        let req = Request::get(path)
            .header(header::HOST, format!("{hostname}:{}", self.https_port))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = self.send(hostname, self.https_port, req).await;
        let status = resp.status();
        let err = resp.headers().get("x-magicpipes-error").map(|v| v.to_str().unwrap().to_string());
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, err, String::from_utf8_lossy(&body).into_owned())
    }

    /// Management API call; returns status and JSON body (Null if empty).
    pub async fn api(&self, method: &str, path: &str, token: Option<&str>) -> (StatusCode, Value) {
        let mut b = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, format!("localhost:{}", self.mgmt_port));
        if let Some(t) = token {
            b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let resp = self.send("localhost", self.mgmt_port, b.body(Full::new(Bytes::new())).unwrap()).await;
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    /// Polls `f` until it returns true or `timeout` passes.
    pub async fn eventually<F, Fut>(&self, what: &str, timeout: Duration, mut f: F)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let start = Instant::now();
        loop {
            if f().await {
                return;
            }
            if start.elapsed() > timeout {
                panic!("timed out waiting for: {what}\nagent log:\n{}\nserver log:\n{}", self.agent_log(), self.server_log());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    pub fn agent_pid(&self) -> Option<i32> {
        std::fs::read_to_string(self.home().join("agent.pid")).ok()?.trim().parse().ok()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        if let Some(pid) = self.agent_pid() {
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
        if let Some(mut c) = self.server.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        if std::env::var_os("MAGICPIPES_KEEP_TEST_DIR").is_none() && !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

async fn wait_port(port: u16) {
    let start = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).await.is_err() {
        assert!(start.elapsed() < Duration::from_secs(15), "port {port} never opened");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn magicpipes_core_rand() -> String {
    let mut b = [0u8; 6];
    getrandom_fill(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn getrandom_fill(buf: &mut [u8]) {
    use std::io::Read;
    std::fs::File::open("/dev/urandom").unwrap().read_exact(buf).unwrap();
}

/// A CA and a `localhost` certificate signed by it.
fn test_certs(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["localhost".to_string()]).unwrap().signed_by(&key, &issuer).unwrap();
    let (ca, crt, k) = (root.join("test-ca.crt"), root.join("mgmt.crt"), root.join("mgmt.key"));
    std::fs::write(&ca, ca_cert.pem()).unwrap();
    std::fs::write(&crt, cert.pem()).unwrap();
    std::fs::write(&k, key.serialize_pem()).unwrap();
    (ca, crt, k)
}

// ---- local test applications --------------------------------------------------------------

pub struct App {
    pub port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl App {
    pub fn stop(&self) {
        self.task.abort();
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// HTTP app: `GET /` -> "hello from app", `POST /echo` streams the body back,
/// `GET /stream` sends "first" then waits for `release` before "second",
/// `GET /status/401` -> 401, anything else -> 404.
pub async fn http_app(release: Arc<tokio::sync::Notify>) -> App {
    use http_body_util::combinators::BoxBody;
    use hyper::service::service_fn;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let release = release.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let release = release.clone();
                    async move {
                        let resp: Response<BoxBody<Bytes, hyper::Error>> = match (req.method().as_str(), req.uri().path()) {
                            ("GET", "/") => {
                                let xff = req.headers().get("x-forwarded-proto").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
                                Response::builder()
                                    .header("x-app", "yes")
                                    .header("x-seen-proto", xff)
                                    .body(full("hello from app"))
                                    .unwrap()
                            }
                            ("POST", "/echo") => Response::new(req.into_body().boxed()),
                            ("GET", "/stream") => {
                                let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(2);
                                tokio::spawn(async move {
                                    tx.send(Bytes::from_static(b"first")).await.ok();
                                    release.notified().await;
                                    tx.send(Bytes::from_static(b"second")).await.ok();
                                });
                                let stream = futures_util::stream::unfold(rx, |mut rx| async move {
                                    rx.recv().await.map(|b| (Ok::<_, hyper::Error>(hyper::body::Frame::data(b)), rx))
                                });
                                Response::new(http_body_util::StreamBody::new(stream).boxed())
                            }
                            ("GET", "/status/401") => Response::builder().status(401).body(full("nope")).unwrap(),
                            _ => Response::builder().status(404).body(full("app 404")).unwrap(),
                        };
                        Ok::<_, std::convert::Infallible>(resp)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tcp), svc).await;
            });
        }
    });
    App { port, task }
}

fn full(s: &'static str) -> http_body_util::combinators::BoxBody<Bytes, hyper::Error> {
    Full::new(Bytes::from_static(s.as_bytes())).map_err(|never| match never {}).boxed()
}

/// WebSocket echo server; a text message "close" makes the server close the connection.
pub async fn ws_echo_app() -> App {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else { return };
                while let Some(Ok(msg)) = ws.next().await {
                    match msg {
                        Message::Text(t) if t.as_str() == "close" => {
                            let _ = ws.close(None).await;
                            return;
                        }
                        Message::Text(_) | Message::Binary(_) => {
                            if ws.send(msg).await.is_err() {
                                return;
                            }
                        }
                        Message::Close(_) => return,
                        _ => {}
                    }
                }
            });
        }
    });
    App { port, task }
}

pub fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}
