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
/// Longest a test waits for one command, answer or response body before failing with what it
/// waited for. Generous: it's there to name a hang, not to time anything.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(120);

/// A whole response body, failing the test if it doesn't end in [`STEP_TIMEOUT`].
pub async fn body(resp: Response<Incoming>, what: &str) -> Bytes {
    match tokio::time::timeout(STEP_TIMEOUT, resp.into_body().collect()).await {
        Ok(b) => b.unwrap().to_bytes(),
        Err(_) => panic!("the response to {what} didn't end within {STEP_TIMEOUT:?}"),
    }
}

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

/// The code an authenticator app shows for a base 32 `key` at `unix` seconds (RFC 6238: HMAC-SHA1,
/// 6 digits, 30 seconds).
pub fn totp_code(key: &str, unix: i64) -> String {
    let (mut bits, mut have, mut bytes) = (0u32, 0, Vec::new());
    for c in key.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => panic!("not base 32: {key}"),
        };
        bits = ((bits << 5) | u32::from(v)) & 0xffff;
        have += 5;
        if have >= 8 {
            have -= 8;
            bytes.push((bits >> have) as u8);
        }
    }
    let tag = ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &bytes), &(unix / 30).to_be_bytes());
    let m = tag.as_ref();
    let at = usize::from(m[19] & 0x0f);
    format!("{:06}", u32::from_be_bytes([m[at] & 0x7f, m[at + 1], m[at + 2], m[at + 3]]) % 1_000_000)
}

pub fn free_port() -> u16 {
    free_port_range(1).0
}

/// `n` consecutive ports free for TCP and UDP, below the ephemeral ranges (Linux's starts at 32768),
/// or another test's outgoing connection could take one between here and the server opening it. No
/// port is handed out twice, since nothing holds it until then.
pub fn free_port_range(n: u16) -> (u16, u16) {
    static HANDED_OUT: std::sync::Mutex<Option<std::collections::HashSet<u16>>> = std::sync::Mutex::new(None);
    loop {
        let first = 20_000 + (magicpipes_core_rand_u16() % 12_000);
        let mut handed_out = HANDED_OUT.lock().unwrap();
        let handed_out = handed_out.get_or_insert_default();
        let free = (first..first + n).all(|p| {
            !handed_out.contains(&p) && std::net::TcpListener::bind(("127.0.0.1", p)).is_ok() && std::net::UdpSocket::bind(("127.0.0.1", p)).is_ok()
        });
        if free {
            handed_out.extend(first..first + n);
            return (first, first + n - 1);
        }
    }
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
    /// The server's `[ports]` range (bound on 127.0.0.1).
    pub ports: (u16, u16),
    pub ca_path: PathBuf,
    server: Option<std::process::Child>,
    tls: Tls,
}

impl Env {
    pub async fn new(tls: Tls) -> Env {
        Self::with_config(tls, "").await
    }

    /// `extra` is appended to the server's configuration.
    pub async fn with_config(tls: Tls, extra: &str) -> Env {
        Self::with_settings(tls, "", extra).await
    }

    /// `top` goes before the first section of the server's configuration, `extra` after the last.
    pub async fn with_settings(tls: Tls, top: &str, extra: &str) -> Env {
        let root = std::env::temp_dir().join(format!("mpe2e-{}", magicpipes_core_rand()));
        std::fs::create_dir_all(root.join("home")).unwrap();
        let (https_port, mut http_port, mgmt_port) = (free_port(), free_port(), free_port());
        let ports = free_port_range(8);
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
{top}
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
[ports]
range = "{first}-{last}"
bind = "127.0.0.1"
public_host = "localhost"
udp_idle_timeout_secs = 5
{extra}
"#,
            data = root.join("server").display(),
            first = ports.0,
            last = ports.1,
        );
        std::fs::write(root.join("server.toml"), cfg).unwrap();
        let mut env = Env { root, https_port, http_port, mgmt_port, ports, ca_path, server: None, tls };
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
            // The listener is up a moment before its certificate is.
            while self.try_connect("localhost", self.mgmt_port).await.is_err() {
                assert!(start.elapsed() < Duration::from_secs(10), "management never answered TLS");
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

    /// As [`Env::cli`], run from `dir`.
    pub async fn cli_in(&self, dir: &Path, args: &[&str]) -> Output {
        let mut cmd = self.cli_command(args);
        cmd.current_dir(dir);
        self.run(cmd, args).await
    }

    /// Runs a CLI command to its end. One that doesn't end fails the test, saying which command:
    /// otherwise a hang says nothing until CI gives up on the whole job.
    async fn run(&self, mut cmd: tokio::process::Command, args: &[&str]) -> Output {
        match tokio::time::timeout(STEP_TIMEOUT, cmd.kill_on_drop(true).output()).await {
            Ok(out) => out.expect("run magicpipes"),
            Err(_) => panic!("magicpipes {args:?} didn't finish within {STEP_TIMEOUT:?}\nagent log:\n{}\nserver log:\n{}", self.agent_log(), self.server_log()),
        }
    }

    /// Starts the CLI with stdout and stderr piped (and no browser), for commands that wait.
    pub fn cli_spawn(&self, args: &[&str]) -> tokio::process::Child {
        self.cli_command(args)
            .env("MAGICPIPES_NO_BROWSER", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("run magicpipes")
    }

    pub async fn cli(&self, args: &[&str]) -> Output {
        self.run(self.cli_command(args), args).await
    }

    /// [`Env::cli`] with more environment variables, which an agent it starts inherits.
    pub async fn cli_with(&self, vars: &[(&str, &str)], args: &[&str]) -> Output {
        let mut cmd = self.cli_command(args);
        cmd.envs(vars.iter().copied());
        self.run(cmd, args).await
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

    /// As [`Env::try_connect`], trusting only `ca_pem`: this succeeds only if the server presents a
    /// certificate from that CA.
    pub async fn connect_trusting(&self, ca_pem: &str, host: &str, port: u16) -> std::io::Result<TlsStream<TcpStream>> {
        let mut roots = rustls::RootCertStore::empty();
        for c in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        let tls = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
        TlsConnector::from(Arc::new(tls)).connect(ServerName::try_from(host.to_string()).unwrap(), tcp).await
    }

    /// What the server says when its configuration keeps it from starting.
    pub async fn why_server_wont_start(&self) -> String {
        let mut cmd = tokio::process::Command::new(bin("magicpipesd"));
        cmd.arg("--config").arg(self.root.join("server.toml")).kill_on_drop(true);
        let out = tokio::time::timeout(Duration::from_secs(20), cmd.output()).await.expect("the server started after all").unwrap();
        assert!(!out.status.success());
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    pub async fn send(&self, host: &str, port: u16, req: Request<Full<Bytes>>) -> Response<Incoming> {
        let what = format!("{} {} on {host}:{port}", req.method(), req.uri());
        let send = async {
            let stream = self.connect(host, port).await;
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
            tokio::spawn(async move {
                let _ = conn.with_upgrades().await;
            });
            sender.send_request(req).await.unwrap()
        };
        match tokio::time::timeout(STEP_TIMEOUT, send).await {
            Ok(resp) => resp,
            Err(_) => panic!("no answer to {what} within {STEP_TIMEOUT:?}\nagent log:\n{}\nserver log:\n{}", self.agent_log(), self.server_log()),
        }
    }

    /// GET on a tunnel hostname with cookies, as a browser (`html`) or not.
    pub async fn tunnel_get(&self, hostname: &str, path: &str, cookies: &str, html: bool) -> TunnelResponse {
        self.tunnel_request("GET", hostname, path, cookies, html, String::new()).await
    }

    /// POST of a form body to a tunnel hostname, as a page's script would.
    pub async fn tunnel_post(&self, hostname: &str, path: &str, cookies: &str, form: &str) -> TunnelResponse {
        self.tunnel_request("POST", hostname, path, cookies, false, form.to_string()).await
    }

    async fn tunnel_request(&self, method: &str, hostname: &str, path: &str, cookies: &str, html: bool, body: String) -> TunnelResponse {
        let mut b = Request::builder().method(method).uri(path).header(header::HOST, format!("{hostname}:{}", self.https_port));
        if !cookies.is_empty() {
            b = b.header(header::COOKIE, cookies);
        }
        if html {
            b = b.header(header::ACCEPT, "text/html,application/xhtml+xml");
        }
        if !body.is_empty() {
            b = b.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        }
        let resp = self.send(hostname, self.https_port, b.body(Full::new(Bytes::from(body))).unwrap()).await;
        let get = |n| resp.headers().get(n).and_then(|v| v.to_str().ok()).map(str::to_string);
        let (location, error) = (get(header::LOCATION), get(http::HeaderName::from_static("x-magicpipes-error")));
        let set_cookies = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok()?.split(';').next().map(str::to_string))
            .collect();
        let status = resp.status();
        let body = String::from_utf8_lossy(&self::body(resp, path).await).into_owned();
        TunnelResponse { status, location, error, set_cookies, body }
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
        let body = body(resp, path).await;
        (status, err, String::from_utf8_lossy(&body).into_owned())
    }

    /// Management API call; returns status and JSON body (Null if empty).
    /// A management API call with a JSON body.
    pub async fn api_json(&self, method: &str, path: &str, token: Option<&str>, body: Value) -> (StatusCode, Value) {
        let mut b = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, format!("localhost:{}", self.mgmt_port))
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(t) = token {
            b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let resp = self.send("localhost", self.mgmt_port, b.body(Full::new(Bytes::from(body.to_string()))).unwrap()).await;
        let status = resp.status();
        let body = self::body(resp, path).await;
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    /// A management UI request: GET without `form`, otherwise a POSTed form. Returns the status,
    /// the `Location` and `Set-Cookie` session values (if any) and the body.
    pub async fn ui(&self, path: &str, cookie: Option<&str>, form: Option<&[(&str, &str)]>) -> UiResponse {
        self.ui_with(path, cookie, form, &[]).await
    }

    /// As [`Env::ui`], with what an authenticating proxy would add.
    pub async fn ui_with(&self, path: &str, cookie: Option<&str>, form: Option<&[(&str, &str)]>, headers: &[(&str, &str)]) -> UiResponse {
        let mut b = Request::builder().uri(path).header(header::HOST, format!("localhost:{}", self.mgmt_port));
        for (name, value) in headers {
            b = b.header(*name, *value);
        }
        if let Some(c) = cookie {
            b = b.header(header::COOKIE, c);
        }
        let body = match form {
            Some(fields) => {
                b = b.method("POST").header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
                let enc = |s: &str| s.bytes().map(|c| if c.is_ascii_alphanumeric() { (c as char).to_string() } else { format!("%{c:02X}") }).collect::<String>();
                fields.iter().map(|(k, v)| format!("{}={}", enc(k), enc(v))).collect::<Vec<_>>().join("&")
            }
            None => String::new(),
        };
        let resp = self.send("localhost", self.mgmt_port, b.body(Full::new(Bytes::from(body))).unwrap()).await;
        let header = |name| resp.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
        let location = header(header::LOCATION);
        let refresh = header(http::HeaderName::from_static("refresh"));
        let cookie = header(header::SET_COOKIE).and_then(|c| c.split(';').next().map(str::to_string)).filter(|c| !c.ends_with('='));
        let status = resp.status();
        let html = String::from_utf8_lossy(&self::body(resp, path).await).into_owned();
        UiResponse { status, location, refresh, cookie, html }
    }

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
        let body = body(resp, path).await;
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    /// A GET on the management host with a bearer token or a cookie: the status, the content type
    /// and the body as text.
    pub async fn mgmt_text(&self, path: &str, token: Option<&str>, cookie: Option<&str>) -> (StatusCode, String, String) {
        let mut b = Request::get(path).header(header::HOST, format!("localhost:{}", self.mgmt_port));
        if let Some(t) = token {
            b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        if let Some(c) = cookie {
            b = b.header(header::COOKIE, c);
        }
        let resp = self.send("localhost", self.mgmt_port, b.body(Full::new(Bytes::new())).unwrap()).await;
        let status = resp.status();
        let kind = resp.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
        (status, kind, String::from_utf8_lossy(&body(resp, path).await).into_owned())
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

fn magicpipes_core_rand_u16() -> u16 {
    let mut b = [0u8; 2];
    getrandom_fill(&mut b);
    u16::from_le_bytes(b)
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

/// A certificate from a CA of its own: `(ca, chain, key)`, as PEM text. `days_left`: its end, after
/// a long life already. Otherwise it lasts for a year.
pub fn own_certificate(names: &[&str], days_left: Option<u64>) -> (String, String, String) {
    use std::time::{Duration, SystemTime};

    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    let day = Duration::from_secs(24 * 3600);
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
    let now = SystemTime::now();
    params.not_before = match days_left {
        Some(_) => (now - day * 300).into(),
        None => (now - day).into(),
    };
    params.not_after = (now + day * days_left.unwrap_or(365) as u32).into();
    let cert = params.signed_by(&key, &issuer).unwrap();
    (ca_cert.pem(), cert.pem(), key.serialize_pem())
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
/// `GET /status/401` -> 401, `GET /conn` -> the number of the TCP connection it came on,
/// `GET /headers` -> the names of the request's headers, anything else -> 404.
pub async fn http_app(release: Arc<tokio::sync::Notify>) -> App {
    use http_body_util::combinators::BoxBody;
    use hyper::service::service_fn;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut accepted = 0u64;
        // Stopping the app closes its connections too, as stopping a real one does.
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            accepted += 1;
            let conn = accepted;
            let release = release.clone();
            connections.spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let release = release.clone();
                    async move {
                        let resp: Response<BoxBody<Bytes, hyper::Error>> = match (req.method().as_str(), req.uri().path()) {
                            ("GET", "/conn") => Response::new(Full::new(Bytes::from(conn.to_string())).map_err(|never| match never {}).boxed()),
                            ("GET", "/") => {
                                let xff = req.headers().get("x-forwarded-proto").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
                                Response::builder()
                                    .header("x-app", "yes")
                                    .header("x-seen-proto", xff)
                                    .body(full("hello from app"))
                                    .unwrap()
                            }
                            ("POST", "/echo") => Response::new(req.into_body().boxed()),
                            ("GET", "/whoami") => {
                                let h = |n: &str| req.headers().get(n).map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
                                let body = format!("user={} id={} cookie={}", h("x-magicpipes-user"), h("x-magicpipes-user-id"), h("cookie"));
                                Response::new(Full::new(Bytes::from(body)).map_err(|never| match never {}).boxed())
                            }
                            ("GET", "/headers") => {
                                let names: Vec<&str> = req.headers().keys().map(|k| k.as_str()).collect();
                                Response::new(Full::new(Bytes::from(names.join(","))).map_err(|never| match never {}).boxed())
                            }
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
                            ("GET", "/cookies") => Response::builder()
                                .header(header::SET_COOKIE, format!("shared=1; Path=/; Domain={BASE}"))
                                .header(header::SET_COOKIE, format!("own=2; Domain=open.{BASE}"))
                                .body(full("cookies"))
                                .unwrap(),
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

/// A Unix socket at `path`, replacing what's left of an earlier one, as applications do.
fn bind_unix(path: &Path) -> tokio::net::UnixListener {
    let _ = std::fs::remove_file(path);
    tokio::net::UnixListener::bind(path).unwrap()
}

/// An HTTP application on a Unix socket: `GET /` -> `hello over <name>`, `POST /echo` streams the
/// body back, anything else -> 404.
pub fn unix_http_app(path: &Path, name: &'static str) -> App {
    use http_body_util::combinators::BoxBody;
    use hyper::service::service_fn;
    let listener = bind_unix(path);
    let task = tokio::spawn(async move {
        // Stopping the app closes its connections too, as stopping a real one does.
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            connections.spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| async move {
                    let resp: Response<BoxBody<Bytes, hyper::Error>> = match (req.method().as_str(), req.uri().path()) {
                        ("GET", "/") => Response::new(Full::new(Bytes::from(format!("hello over {name}"))).map_err(|never| match never {}).boxed()),
                        ("POST", "/echo") => Response::new(req.into_body().boxed()),
                        _ => Response::builder().status(404).body(full("app 404")).unwrap(),
                    };
                    Ok::<_, std::convert::Infallible>(resp)
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
            });
        }
    });
    App { port: 0, task }
}

/// An echo service on a Unix socket.
pub fn unix_echo_app(path: &Path) -> App {
    let listener = bind_unix(path);
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let (mut read, mut write) = stream.into_split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    App { port: 0, task }
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

/// A TCP service that echoes every byte back.
pub async fn tcp_echo_app() -> App {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    App { port, task }
}

/// A UDP service that answers each datagram with `echo:` + the datagram.
pub async fn udp_echo_app() -> App {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf).await else { return };
            let mut reply = b"echo:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            let _ = socket.send_to(&reply, from).await;
        }
    });
    App { port, task }
}

/// Who the fake OpenID Connect provider says is signing in, and how it misbehaves.
#[derive(Clone)]
pub struct OidcPerson {
    pub sub: String,
    pub email: String,
    pub verified: bool,
    /// Give the email only through the UserInfo endpoint.
    pub email_in_userinfo: bool,
    /// Sign the ID token with a key the provider doesn't publish.
    pub wrong_key: bool,
    /// Put this in the ID token instead of the nonce it was given.
    pub wrong_nonce: bool,
    /// Publish no signing keys, like authentik without a Signing Key.
    pub no_signing_keys: bool,
    /// More claims in the ID token, such as `{"groups": ["eng"]}`.
    pub claims: Value,
    /// More claims only from the UserInfo endpoint.
    pub userinfo_claims: Value,
    /// As GitHub: their organizations, and teams as `org/team`, read only with `read:org`.
    pub orgs: Vec<String>,
    pub teams: Vec<String>,
    /// Refuse refresh tokens (`invalid_grant`), as for someone removed at the provider.
    pub refresh_refused: bool,
}

impl OidcPerson {
    pub fn new(sub: &str, email: &str) -> Self {
        Self {
            sub: sub.into(),
            email: email.into(),
            verified: true,
            email_in_userinfo: false,
            wrong_key: false,
            wrong_nonce: false,
            no_signing_keys: false,
            claims: serde_json::json!({}),
            userinfo_claims: serde_json::json!({}),
            orgs: Vec::new(),
            teams: Vec::new(),
            refresh_refused: false,
        }
    }
}

/// Copies an object's fields into another.
fn merge(into: &mut Value, more: &Value) {
    if let (Some(into), Some(more)) = (into.as_object_mut(), more.as_object()) {
        into.extend(more.iter().map(|(k, v)| (k.clone(), v.clone())));
    }
}

/// A small OpenID Connect provider on plain HTTP on this machine: discovery, keys, an
/// authorization endpoint that signs in `person` at once, a token endpoint and UserInfo. It checks
/// what a real provider checks: the client's credentials, one use of a code, the redirect URI and
/// PKCE. It's also a GitHub Enterprise Server, at its OAuth and `/api/v3` addresses, answering as
/// GitHub does: a refused code gets a 200, and a request without a User-Agent a 403. `person.sub`
/// is then the numeric user id.
pub struct FakeOidc {
    pub issuer: String,
    pub person: Arc<std::sync::Mutex<OidcPerson>>,
    pub token_requests: Arc<std::sync::atomic::AtomicUsize>,
    /// The scope the last sign-in asked for.
    pub last_scope: Arc<std::sync::Mutex<String>>,
    /// Refresh tokens traded.
    pub refreshes: Arc<std::sync::atomic::AtomicUsize>,
    pub task: tokio::task::JoinHandle<()>,
    key: Arc<ring::signature::EcdsaKeyPair>,
    other_key: Arc<ring::signature::EcdsaKeyPair>,
}

pub const OIDC_CLIENT: &str = "client-1";
pub const OIDC_SECRET: &str = "secret/with+odd chars";

impl FakeOidc {
    pub async fn start() -> FakeOidc {
        use base64::Engine;
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64};
        use ring::rand::SystemRandom;
        use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING as ALG, EcdsaKeyPair, KeyPair};
        use sha2::Digest;

        type Code = (String, OidcPerson, String, String, String);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let rng = SystemRandom::new();
        let new_key = || EcdsaKeyPair::from_pkcs8(&ALG, EcdsaKeyPair::generate_pkcs8(&ALG, &rng).unwrap().as_ref(), &rng).unwrap();
        let (key, other) = (Arc::new(new_key()), Arc::new(new_key()));
        let (signing_key, other_key) = (key.clone(), other.clone());
        let person = Arc::new(std::sync::Mutex::new(OidcPerson::new("sub-1", "ann@example.com")));
        let codes: Arc<std::sync::Mutex<std::collections::HashMap<String, Code>>> = Arc::default();
        let token_requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let last_scope: Arc<std::sync::Mutex<String>> = Arc::default();
        let refreshes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (iss, who, requests, scope_seen, refreshed) = (issuer.clone(), person.clone(), token_requests.clone(), last_scope.clone(), refreshes.clone());
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let (iss, who, codes, key, other, requests, scope_seen, refreshed) =
                    (iss.clone(), who.clone(), codes.clone(), key.clone(), other.clone(), requests.clone(), scope_seen.clone(), refreshed.clone());
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let (iss, who, codes, key, other, requests, scope_seen, refreshed) =
                            (iss.clone(), who.clone(), codes.clone(), key.clone(), other.clone(), requests.clone(), scope_seen.clone(), refreshed.clone());
                        async move {
                            let path = req.uri().path().to_string();
                            let query: std::collections::HashMap<String, String> = parse_form(req.uri().query().unwrap_or(""));
                            let auth = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).map(str::to_string);
                            let has_agent = req.headers().contains_key(header::USER_AGENT);
                            let body = String::from_utf8_lossy(&req.into_body().collect().await.unwrap().to_bytes()).into_owned();
                            let json = |status: StatusCode, v: Value| Response::builder().status(status).header(header::CONTENT_TYPE, "application/json").body(Full::new(Bytes::from(v.to_string()))).unwrap();
                            let refuse = || json(StatusCode::BAD_REQUEST, serde_json::json!({ "error": "invalid_grant" }));
                            let resp = match path.as_str() {
                                "/.well-known/openid-configuration" => json(StatusCode::OK, serde_json::json!({
                                    "issuer": iss,
                                    "authorization_endpoint": format!("{iss}/authorize"),
                                    "token_endpoint": format!("{iss}/token"),
                                    "jwks_uri": format!("{iss}/keys"),
                                    "userinfo_endpoint": format!("{iss}/userinfo"),
                                    "end_session_endpoint": format!("{iss}/logout"),
                                })),
                                "/keys" if who.lock().unwrap().no_signing_keys => json(StatusCode::OK, serde_json::json!({ "keys": [] })),
                                "/keys" => {
                                    let p = key.public_key().as_ref();
                                    json(StatusCode::OK, serde_json::json!({ "keys": [{ "kty": "EC", "kid": "k1", "use": "sig", "crv": "P-256", "x": B64.encode(&p[1..33]), "y": B64.encode(&p[33..65]) }] }))
                                }
                                "/authorize" | "/login/oauth/authorize" => {
                                    let code = format!("code-{}", magicpipes_core_rand());
                                    let scope = query.get("scope").cloned().unwrap_or_default();
                                    *scope_seen.lock().unwrap() = scope.clone();
                                    let entry = (query.get("nonce").cloned().unwrap_or_default(), who.lock().unwrap().clone(), query["code_challenge"].clone(), query["redirect_uri"].clone(), scope);
                                    assert_eq!(query["code_challenge_method"], "S256");
                                    assert_eq!(query["client_id"], OIDC_CLIENT);
                                    codes.lock().unwrap().insert(code.clone(), entry);
                                    let to = format!("{}?code={code}&state={}&iss={}", query["redirect_uri"], query["state"], iss);
                                    Response::builder().status(StatusCode::FOUND).header(header::LOCATION, to).body(Full::new(Bytes::new())).unwrap()
                                }
                                "/token" => {
                                    requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                    let form = parse_form(&body);
                                    let enc = |s: &str| s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect::<String>();
                                    let basic = format!("Basic {}", STANDARD.encode(format!("{}:{}", enc(OIDC_CLIENT), enc(OIDC_SECRET))));
                                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                                    let sign = |claims: &Value| {
                                        let msg = format!("{}.{}", B64.encode(r#"{"alg":"ES256","kid":"k1"}"#), B64.encode(claims.to_string()));
                                        let sig = key.sign(&SystemRandom::new(), msg.as_bytes()).unwrap();
                                        format!("{msg}.{}", B64.encode(sig.as_ref()))
                                    };
                                    // A refresh: a new ID token about whoever is signed in now, and the next refresh token.
                                    if form.get("grant_type").map(String::as_str) == Some("refresh_token") {
                                        refreshed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                        let p = who.lock().unwrap().clone();
                                        let given = form.get("refresh_token").cloned().unwrap_or_default();
                                        let resp = if auth.as_deref() != Some(&basic) {
                                            json(StatusCode::UNAUTHORIZED, serde_json::json!({ "error": "invalid_client" }))
                                        } else if p.refresh_refused || !given.starts_with(&format!("rt-{}-", p.sub)) {
                                            json(StatusCode::BAD_REQUEST, serde_json::json!({ "error": "invalid_grant" }))
                                        } else {
                                            let mut claims = serde_json::json!({ "iss": iss, "aud": OIDC_CLIENT, "sub": p.sub, "exp": now + 300, "iat": now, "email": p.email, "email_verified": p.verified });
                                            merge(&mut claims, &p.claims);
                                            let next = format!("rt-{}-{}", p.sub, magicpipes_core_rand());
                                            json(StatusCode::OK, serde_json::json!({ "id_token": sign(&claims), "access_token": p.sub, "refresh_token": next, "token_type": "Bearer" }))
                                        };
                                        return Ok::<_, std::convert::Infallible>(resp);
                                    }
                                    let entry = codes.lock().unwrap().remove(form.get("code").map_or("", |c| c.as_str()));
                                    match entry {
                                        Some((nonce, p, challenge, redirect, scope))
                                            if auth.as_deref() == Some(&basic)
                                                && form.get("redirect_uri") == Some(&redirect)
                                                && B64.encode(sha2::Sha256::digest(form["code_verifier"].as_bytes())) == challenge =>
                                        {
                                            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                                            let mut claims = serde_json::json!({
                                                "iss": iss, "aud": OIDC_CLIENT, "sub": p.sub, "exp": now + 300, "iat": now,
                                                "nonce": if p.wrong_nonce { "another".to_string() } else { nonce }, "name": "Test Person",
                                            });
                                            if !p.email_in_userinfo {
                                                claims["email"] = p.email.clone().into();
                                                claims["email_verified"] = p.verified.into();
                                            }
                                            merge(&mut claims, &p.claims);
                                            let msg = format!("{}.{}", B64.encode(r#"{"alg":"ES256","kid":"k1"}"#), B64.encode(claims.to_string()));
                                            let signer = if p.wrong_key { &other } else { &key };
                                            let sig = signer.sign(&SystemRandom::new(), msg.as_bytes()).unwrap();
                                            let mut answer = serde_json::json!({ "id_token": format!("{msg}.{}", B64.encode(sig.as_ref())), "access_token": p.sub, "token_type": "Bearer" });
                                            // A refresh token only when asked for, as many providers do.
                                            if scope.split(' ').any(|s| s == "offline_access") {
                                                answer["refresh_token"] = format!("rt-{}-0", p.sub).into();
                                            }
                                            json(StatusCode::OK, answer)
                                        }
                                        _ => refuse(),
                                    }
                                }
                                "/login/oauth/access_token" => {
                                    requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                    let form = parse_form(&body);
                                    let entry = codes.lock().unwrap().remove(form.get("code").map_or("", |c| c.as_str()));
                                    match entry {
                                        Some((_, p, challenge, redirect, scope))
                                            if form.get("client_id").map(String::as_str) == Some(OIDC_CLIENT)
                                                && form.get("client_secret").map(String::as_str) == Some(OIDC_SECRET)
                                                && form.get("redirect_uri") == Some(&redirect)
                                                && B64.encode(sha2::Sha256::digest(form["code_verifier"].as_bytes())) == challenge =>
                                        {
                                            // A token that may read organizations says so, for the fake's own checks.
                                            let token = if scope.split(' ').any(|s| s == "read:org") { format!("gho_{}_org", p.sub) } else { format!("gho_{}", p.sub) };
                                            json(StatusCode::OK, serde_json::json!({ "access_token": token, "token_type": "bearer", "scope": scope.replace(' ', ",") }))
                                        }
                                        _ => json(StatusCode::OK, serde_json::json!({ "error": "bad_verification_code", "error_description": "The code passed is incorrect or expired." })),
                                    }
                                }
                                "/api/v3/" => json(StatusCode::OK, serde_json::json!({ "current_user_url": format!("{iss}/api/v3/user") })),
                                "/api/v3/user" | "/api/v3/user/emails" | "/api/v3/user/orgs" | "/api/v3/user/teams" => {
                                    let p = who.lock().unwrap().clone();
                                    let with_orgs = format!("Bearer gho_{}_org", p.sub);
                                    if !has_agent {
                                        json(StatusCode::FORBIDDEN, Value::Null)
                                    } else if auth.as_deref() != Some(&format!("Bearer gho_{}", p.sub)) && auth.as_deref() != Some(&with_orgs) {
                                        json(StatusCode::UNAUTHORIZED, Value::Null)
                                    } else if (path.ends_with("/orgs") || path.ends_with("/teams")) && auth.as_deref() != Some(&with_orgs) {
                                        json(StatusCode::FORBIDDEN, serde_json::json!({ "message": "Resource not accessible by integration" }))
                                    } else if path.ends_with("/orgs") {
                                        json(StatusCode::OK, Value::Array(p.orgs.iter().map(|o| serde_json::json!({ "login": o, "id": 1 })).collect()))
                                    } else if path.ends_with("/teams") {
                                        let page: usize = query.get("page").and_then(|n| n.parse().ok()).unwrap_or(1);
                                        let teams: Vec<Value> = if page == 1 {
                                            p.teams.iter().filter_map(|t| t.split_once('/')).map(|(o, t)| serde_json::json!({ "slug": t, "name": t, "organization": { "login": o } })).collect()
                                        } else {
                                            Vec::new()
                                        };
                                        json(StatusCode::OK, Value::Array(teams))
                                    } else if path.ends_with("/emails") {
                                        // An address it didn't verify comes first, so taking the first would be wrong.
                                        json(StatusCode::OK, serde_json::json!([
                                            { "email": "never-verified@example.com", "primary": false, "verified": false, "visibility": null },
                                            { "email": p.email, "primary": true, "verified": p.verified, "visibility": "public" },
                                        ]))
                                    } else {
                                        json(StatusCode::OK, serde_json::json!({ "login": "someone", "id": p.sub.parse::<u64>().unwrap_or(0), "name": null, "email": null }))
                                    }
                                }
                                "/userinfo" => {
                                    let p = who.lock().unwrap().clone();
                                    if auth.as_deref() == Some(&format!("Bearer {}", p.sub)) {
                                        let mut info = serde_json::json!({ "sub": p.sub, "email": p.email, "email_verified": p.verified });
                                        merge(&mut info, &p.userinfo_claims);
                                        json(StatusCode::OK, info)
                                    } else {
                                        json(StatusCode::UNAUTHORIZED, Value::Null)
                                    }
                                }
                                _ => json(StatusCode::NOT_FOUND, Value::Null),
                            };
                            Ok::<_, std::convert::Infallible>(resp)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
                });
            }
        });
        FakeOidc { issuer, person, token_requests, last_scope, refreshes, task, key: signing_key, other_key }
    }

    /// A token with these claims, signed with the key this provider publishes.
    pub fn sign(&self, claims: &Value) -> String {
        sign_es256(&self.key, claims)
    }

    /// A token signed with a key nobody published, under the same key id.
    pub fn sign_with_another_key(&self, claims: &Value) -> String {
        sign_es256(&self.other_key, claims)
    }

    /// The configuration that uses this provider.
    pub fn config(&self, root: &Path, users: &str, link_by_email: bool) -> String {
        std::fs::create_dir_all(root).unwrap();
        let secret = root.join("oidc-secret");
        std::fs::write(&secret, format!("{OIDC_SECRET}\n")).unwrap();
        format!(
            "[users]\n{users}\n[[oidc]]\nid = \"fake\"\nlabel = \"Fake ID\"\nissuer = \"{}\"\nclient_id = \"{OIDC_CLIENT}\"\nclient_secret_file = \"{}\"\nlink_by_email = {link_by_email}\n",
            self.issuer,
            secret.display(),
        )
    }
}

/// A message a [`FakeSmtp`] accepted.
#[derive(Debug, Clone)]
pub struct SmtpMessage {
    pub to: String,
    pub from: String,
    pub text: String,
    /// Was the connection encrypted when the message came?
    pub encrypted: bool,
    /// What `AUTH PLAIN` said, decoded: `\0user\0password`.
    pub auth: Option<String>,
}

impl SmtpMessage {
    /// The code in the message's link.
    pub fn code(&self) -> String {
        let at = self.text.find("#code=").unwrap_or_else(|| panic!("no code in {}", self.text)) + "#code=".len();
        self.text[at..].split_whitespace().next().unwrap().to_string()
    }
}

/// What a [`FakeSmtp`] does about TLS.
#[derive(Clone)]
pub enum SmtpTlsOffer {
    /// Doesn't offer STARTTLS.
    Plain,
    /// Offers STARTTLS with this certificate for `localhost`.
    Starttls { cert_pem: String, key_pem: String },
}

/// A small mail server on this machine: it takes messages the way a real one does, and keeps them.
/// It asks for a password only when it can be sent encrypted, and takes any it's given.
pub struct FakeSmtp {
    pub port: u16,
    pub messages: Arc<std::sync::Mutex<Vec<SmtpMessage>>>,
    /// Refuse recipients with a permanent error.
    pub refuse: Arc<std::sync::atomic::AtomicBool>,
    /// Every `AUTH` and `MAIL` line seen, for asserting what was never sent.
    pub commands: Arc<std::sync::Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeSmtp {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeSmtp {
    pub async fn start() -> FakeSmtp {
        Self::offering(SmtpTlsOffer::Plain).await
    }

    pub async fn offering(offer: SmtpTlsOffer) -> FakeSmtp {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let messages: Arc<std::sync::Mutex<Vec<SmtpMessage>>> = Arc::default();
        let refuse = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let commands: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let (kept, refusing, seen) = (messages.clone(), refuse.clone(), commands.clone());
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let (kept, refusing, seen, offer) = (kept.clone(), refusing.clone(), seen.clone(), offer.clone());
                tokio::spawn(async move {
                    let _ = serve_smtp(stream, offer, kept, refusing, seen).await;
                });
            }
        });
        FakeSmtp { port, messages, refuse, commands, task }
    }

    /// `[smtp]`, without encryption or a password.
    pub fn config(&self) -> String {
        format!("[smtp]\nhost = \"127.0.0.1\"\nport = {}\ntls = \"none\"\nfrom = \"MagicPipes <mp@example.com>\"\n", self.port)
    }

    pub fn sent_to(&self, address: &str) -> Vec<SmtpMessage> {
        self.messages.lock().unwrap().iter().filter(|m| m.to == address).cloned().collect()
    }

    /// Waits for `count` messages to `address`, and returns the last.
    pub async fn wait_for(&self, address: &str, count: usize) -> SmtpMessage {
        let start = Instant::now();
        loop {
            let sent = self.sent_to(address);
            if sent.len() >= count {
                return sent.last().unwrap().clone();
            }
            assert!(start.elapsed() < Duration::from_secs(10), "{count} messages to {address} never came: {:?}", self.messages.lock().unwrap());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// A message as a mail client shows it: long lines arrive quoted-printable.
fn decode_message(text: &str) -> String {
    let Some((head, body)) = text.split_once("\r\n\r\n") else { return text.to_string() };
    if !head.to_ascii_lowercase().contains("content-transfer-encoding: quoted-printable") {
        return text.to_string();
    }
    let joined = body.replace("=\r\n", "");
    let bytes = joined.as_bytes();
    let (mut out, mut i) = (Vec::new(), 0);
    while i < bytes.len() {
        if bytes[i] == b'=' && i + 2 < bytes.len() {
            out.push(u8::from_str_radix(&joined[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    format!("{head}\r\n\r\n{}", String::from_utf8(out).unwrap())
}

async fn serve_smtp(
    stream: TcpStream,
    offer: SmtpTlsOffer,
    messages: Arc<std::sync::Mutex<Vec<SmtpMessage>>>,
    refuse: Arc<std::sync::atomic::AtomicBool>,
    commands: Arc<std::sync::Mutex<Vec<String>>>,
) -> std::io::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut plain = Some(BufReader::new(stream));
    let mut tls: Option<BufReader<tokio_rustls::server::TlsStream<TcpStream>>> = None;
    let mut mail = SmtpMessage { to: String::new(), from: String::new(), text: String::new(), encrypted: false, auth: None };
    macro_rules! say {
        ($text:expr) => {{
            let text: String = $text;
            match (&mut plain, &mut tls) {
                (_, Some(t)) => t.get_mut().write_all(text.as_bytes()).await?,
                (Some(p), _) => p.get_mut().write_all(text.as_bytes()).await?,
                _ => unreachable!(),
            }
        }};
    }
    macro_rules! read_line {
        () => {{
            let mut line = String::new();
            let n = match (&mut plain, &mut tls) {
                (_, Some(t)) => t.read_line(&mut line).await?,
                (Some(p), _) => p.read_line(&mut line).await?,
                _ => unreachable!(),
            };
            if n == 0 {
                return Ok(());
            }
            line
        }};
    }
    say!("220 fake ESMTP\r\n".to_string());
    loop {
        let line = read_line!();
        let upper = line.to_ascii_uppercase();
        if upper.starts_with("AUTH") || upper.starts_with("MAIL") {
            commands.lock().unwrap().push(line.trim().to_string());
        }
        if upper.starts_with("EHLO") {
            let encrypted = tls.is_some();
            let mut lines = vec!["250-fake".to_string()];
            if !encrypted && matches!(offer, SmtpTlsOffer::Starttls { .. }) {
                lines.push("250-STARTTLS".to_string());
            }
            if encrypted {
                lines.push("250-AUTH PLAIN".to_string());
            }
            lines.push("250 8BITMIME".to_string());
            say!(format!("{}\r\n", lines.join("\r\n")));
        } else if upper.starts_with("STARTTLS") {
            let SmtpTlsOffer::Starttls { cert_pem, key_pem } = &offer else {
                say!("502 not offered\r\n".to_string());
                continue;
            };
            say!("220 go ahead\r\n".to_string());
            let certs: Vec<CertificateDer> = CertificateDer::pem_slice_iter(cert_pem.as_bytes()).map(Result::unwrap).collect();
            let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let stream = plain.take().unwrap().into_inner();
            tls = Some(BufReader::new(acceptor.accept(stream).await?));
        } else if upper.starts_with("AUTH PLAIN") {
            use base64::Engine;
            let given = line.split_whitespace().nth(2).unwrap_or("");
            let decoded = base64::engine::general_purpose::STANDARD.decode(given).unwrap_or_default();
            mail.auth = Some(String::from_utf8_lossy(&decoded).into_owned());
            say!("235 ok\r\n".to_string());
        } else if upper.starts_with("MAIL FROM") {
            mail.from = line.split(['<', '>']).nth(1).unwrap_or("").to_string();
            say!("250 ok\r\n".to_string());
        } else if upper.starts_with("RCPT TO") {
            if refuse.load(std::sync::atomic::Ordering::Relaxed) {
                say!("550 5.1.1 no such mailbox\r\n".to_string());
                continue;
            }
            mail.to = line.split(['<', '>']).nth(1).unwrap_or("").to_string();
            say!("250 ok\r\n".to_string());
        } else if upper.starts_with("DATA") {
            say!("354 go on\r\n".to_string());
            let mut text = String::new();
            loop {
                let l = read_line!();
                if l == ".\r\n" {
                    break;
                }
                text.push_str(l.strip_prefix('.').unwrap_or(&l));
            }
            mail.text = decode_message(&text);
            mail.encrypted = tls.is_some();
            messages.lock().unwrap().push(mail.clone());
            say!("250 kept\r\n".to_string());
        } else if upper.starts_with("QUIT") {
            say!("221 bye\r\n".to_string());
            return Ok(());
        } else {
            say!("250 ok\r\n".to_string());
        }
    }
}

fn sign_es256(key: &ring::signature::EcdsaKeyPair, claims: &Value) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    let msg = format!("{}.{}", B64.encode(r#"{"alg":"ES256","kid":"k1"}"#), B64.encode(claims.to_string()));
    let sig = key.sign(&ring::rand::SystemRandom::new(), msg.as_bytes()).unwrap();
    format!("{msg}.{}", B64.encode(sig.as_ref()))
}

fn parse_form(s: &str) -> std::collections::HashMap<String, String> {
    let decode = |v: &str| {
        let b = v.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'%' if i + 2 < b.len() => {
                    out.push(u8::from_str_radix(&v[i + 1..i + 3], 16).unwrap());
                    i += 3;
                }
                b'+' => {
                    out.push(b' ');
                    i += 1;
                }
                c => {
                    out.push(c);
                    i += 1;
                }
            }
        }
        String::from_utf8(out).unwrap()
    };
    s.split('&').filter_map(|kv| kv.split_once('=')).map(|(k, v)| (decode(k), decode(v))).collect()
}

#[derive(Debug)]
pub struct UiResponse {
    pub status: StatusCode,
    pub location: Option<String>,
    /// Where a page moves on to by itself.
    pub refresh: Option<String>,
    /// `name=value` of a session cookie the response set.
    pub cookie: Option<String>,
    pub html: String,
}

impl UiResponse {
    /// The CSRF token embedded in the page's forms.
    pub fn csrf(&self) -> String {
        let at = self.html.find(r#"name="csrf" value=""#).expect("page has a CSRF field") + r#"name="csrf" value=""#.len();
        self.html[at..].split('"').next().unwrap().to_string()
    }
}

pub struct TunnelResponse {
    pub status: StatusCode,
    pub location: Option<String>,
    pub error: Option<String>,
    /// `name=value` of each `Set-Cookie`.
    pub set_cookies: Vec<String>,
    pub body: String,
}

impl TunnelResponse {
    pub fn cookie(&self, name: &str) -> Option<String> {
        self.set_cookies.iter().find(|c| c.starts_with(&format!("{name}="))).cloned()
    }

    /// The first cookie set whose name starts with `prefix`.
    pub fn cookie_prefixed(&self, prefix: &str) -> Option<String> {
        self.set_cookies.iter().find(|c| c.starts_with(prefix)).cloned()
    }
}

/// A real sshd on a free port, run as this user, and keys and client settings for `ssh`.
pub struct Sshd {
    pub port: u16,
    pub dir: PathBuf,
    program: &'static str,
    child: tokio::process::Child,
}

impl Sshd {
    /// `None` where this machine has no OpenSSH server or client to test with. `extra` goes at
    /// the end of its configuration.
    pub async fn start(root: &Path, extra: &str) -> Option<Sshd> {
        let sshd = ["/usr/sbin/sshd", "/usr/bin/sshd"].into_iter().find(|p| Path::new(p).exists())?;
        which("ssh")?;
        which("ssh-keygen")?;
        let dir = root.join("sshd");
        std::fs::create_dir_all(&dir).unwrap();
        Self::keygen(&dir.join("host_key")).await;
        std::fs::write(dir.join("authorized_keys"), "").unwrap();
        let port = free_port();
        let config = dir.join("sshd_config");
        std::fs::write(
            &config,
            format!(
                "Port {port}\nListenAddress 127.0.0.1\nHostKey {host}\nAuthorizedKeysFile {authorized}\nStrictModes no\nUsePAM no\nPidFile none\n\
                 PasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nSubsystem sftp internal-sftp\nLogLevel ERROR\n{extra}",
                host = dir.join("host_key").display(),
                authorized = dir.join("authorized_keys").display(),
            ),
        )
        .unwrap();
        let child = Self::spawn(sshd, &dir)?;
        let this = Sshd { port, dir, program: sshd, child };
        this.wait().await;
        Some(this)
    }

    fn spawn(program: &str, dir: &Path) -> Option<tokio::process::Child> {
        let config = dir.join("sshd_config");
        tokio::process::Command::new(program).arg("-D").arg("-e").arg("-f").arg(config).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn().ok()
    }

    async fn wait(&self) {
        for _ in 0..100 {
            if TcpStream::connect(("127.0.0.1", self.port)).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("sshd didn't start");
    }

    /// Starts it again on the same port with a new host key, as a reinstalled machine would.
    pub async fn reinstall(&mut self) {
        self.stop().await;
        let _ = std::fs::remove_file(self.dir.join("host_key"));
        let _ = std::fs::remove_file(self.dir.join("host_key.pub"));
        Self::keygen(&self.dir.join("host_key")).await;
        self.child = Self::spawn(self.program, &self.dir).expect("sshd starts again");
        self.wait().await;
    }

    /// The user this sshd can log in as: whoever runs the tests.
    pub fn login() -> String {
        let out = std::process::Command::new("id").arg("-un").output().unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    async fn keygen(path: &Path) {
        let ok = tokio::process::Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(path).output().await.unwrap();
        assert!(ok.status.success(), "{}", String::from_utf8_lossy(&ok.stderr));
    }

    pub async fn stop(&mut self) {
        let _ = self.child.kill().await;
    }

    /// A new key allowed to log in to this sshd (unless `log_in` is false). Returns someone's `ssh`
    /// settings for it, reaching machines through the gateway on `gateway`, and the public key.
    pub async fn person(&self, name: &str, gateway: u16, log_in: bool) -> SshClient {
        let key = self.dir.join(format!("{name}_key"));
        Self::keygen(&key).await;
        let public = std::fs::read_to_string(key.with_extension("pub").as_path()).unwrap_or_else(|_| std::fs::read_to_string(format!("{}.pub", key.display())).unwrap());
        if log_in {
            let file = self.dir.join("authorized_keys");
            let all = std::fs::read_to_string(&file).unwrap();
            std::fs::write(&file, format!("{all}{public}")).unwrap();
        }
        let config = self.dir.join(format!("{name}_config"));
        std::fs::write(
            &config,
            format!(
                "Host gw\n  HostName 127.0.0.1\n  Port {gateway}\nHost * !gw\n  ProxyJump gw\nHost *\n  IdentityFile {key}\n  IdentitiesOnly yes\n  \
                 UserKnownHostsFile {known}\n  StrictHostKeyChecking accept-new\n  BatchMode yes\n  ConnectTimeout 15\n  ControlMaster no\n",
                key = key.display(),
                known = self.dir.join(format!("{name}_known_hosts")).display(),
            ),
        )
        .unwrap();
        SshClient { config, public: public.trim().to_string() }
    }
}

fn which(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| std::env::split_paths(&paths).map(|p| p.join(program)).find(|p| p.exists()))
}

/// Someone's `ssh`: their key, and a configuration that goes through the gateway.
pub struct SshClient {
    pub config: PathBuf,
    pub public: String,
}

impl SshClient {
    pub fn command(&self, program: &str) -> tokio::process::Command {
        let mut c = tokio::process::Command::new(program);
        c.arg("-F").arg(&self.config).stdin(Stdio::null()).kill_on_drop(true);
        c
    }

    /// Runs `ssh <args>`: stdout, stderr and whether it succeeded.
    pub async fn ssh(&self, args: &[&str]) -> (String, String, bool) {
        let run = self.command("ssh").args(args).output();
        let out = tokio::time::timeout(Duration::from_secs(30), run).await.unwrap_or_else(|_| panic!("ssh {args:?} took too long")).unwrap();
        (String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned(), out.status.success())
    }
}
