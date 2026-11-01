//! End-to-end lifecycle tests with real `magicpipesd` and `magicpipes` processes (Unix only).
#![cfg(unix)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use common::{BASE, Env, Tls};
use futures_util::{SinkExt, StreamExt};
use http::{Request, StatusCode, header};
use http_body_util::{BodyExt, Full};
use serde_json::Value;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

fn hostname(public_url: &str) -> String {
    public_url.trim_start_matches("https://").split(':').next().unwrap().to_string()
}

async fn add_json(env: &Env, args: &[&str]) -> Value {
    let mut a = vec!["add"];
    a.extend_from_slice(args);
    // Before a `--` that starts a `--shell` command.
    let at = a.iter().position(|x| *x == "--").unwrap_or(a.len());
    a.insert(at, "--json");
    env.cli_json(&a).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_websocket_and_lifecycle() {
    let mut env = Env::new(Tls::DevCa).await;
    env.login().await;
    let release = Arc::new(tokio::sync::Notify::new());
    let app = common::http_app(release.clone()).await;
    let ws = common::ws_echo_app().await;

    // --- create a tunnel (human output) -----------------------------------------------------
    let out = env.cli_ok(&["add", &app.port.to_string()]).await;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("Tunnel ready"), "{stdout}");
    assert!(stderr.contains("Verifying public endpoint...  ✓"), "{stderr}");
    let agent_pid = env.agent_pid().expect("agent running after CLI exit");

    // Idempotent: same port again returns the same tunnel, as valid JSON on stdout.
    let t1 = add_json(&env, &[&app.port.to_string()]).await;
    assert_eq!(t1["status"], "ready");
    assert_eq!(t1["created"], false);
    assert_eq!(t1["background"], true);
    let host1 = hostname(t1["public_url"].as_str().unwrap());
    assert!(host1.ends_with(&format!(".{BASE}")));

    // --- HTTP forwarding ---------------------------------------------------------------------
    let req = Request::get("/?q=1").header(header::HOST, format!("{host1}:{}", env.https_port)).body(Full::new(Bytes::new())).unwrap();
    let resp = env.send(&host1, env.https_port, req).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["x-app"], "yes", "response must come from the local app");
    assert_eq!(resp.headers()["x-seen-proto"], "https");
    assert!(resp.headers().get("x-magicpipes-probe-ack").is_none());
    assert_eq!(resp.into_body().collect().await.unwrap().to_bytes(), "hello from app");

    let (status, err, body) = env.get_public(&host1, "/status/401").await;
    assert_eq!((status, err, body.as_str()), (StatusCode::UNAUTHORIZED, None, "nope"));

    // Large request body streamed through and echoed back.
    let big: Vec<u8> = (0..8 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let req = Request::post("/echo")
        .header(header::HOST, &host1)
        .body(Full::new(Bytes::from(big.clone())))
        .unwrap();
    let resp = env.send(&host1, env.https_port, req).await;
    assert_eq!(resp.status(), 200);
    let echoed = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(echoed == big, "echoed body differs ({} vs {} bytes)", echoed.len(), big.len());

    // Streaming: the first chunk arrives before the app produces the second one.
    let req = Request::get("/stream").header(header::HOST, &host1).body(Full::new(Bytes::new())).unwrap();
    let mut body = env.send(&host1, env.https_port, req).await.into_body();
    let first = tokio::time::timeout(Duration::from_secs(5), body.frame()).await.expect("first chunk streamed").unwrap().unwrap();
    assert_eq!(first.into_data().unwrap(), "first");
    release.notify_one();
    let rest = body.collect().await.unwrap().to_bytes();
    assert_eq!(rest, "second");

    // Unknown hostnames get no certificate (none is issued on demand) and are never routed.
    assert!(env.try_connect(&format!("nope.{BASE}"), env.https_port).await.is_err());
    // A known SNI with a different Host header is refused (no open proxy, no cross-tunnel routing).
    let req = Request::get("/").header(header::HOST, "example.org").body(Full::new(Bytes::new())).unwrap();
    let resp = env.send(&host1, env.https_port, req).await;
    assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);
    assert_eq!(resp.headers()["x-magicpipes-error"], "misdirected_request");
    let req = Request::get("http://example.org/").header(header::HOST, &host1).body(Full::new(Bytes::new())).unwrap();
    assert_eq!(env.send(&host1, env.https_port, req).await.status(), StatusCode::BAD_REQUEST);

    // --- second tunnel (WebSocket app) reuses the agent ---------------------------------------
    let t2 = add_json(&env, &[&ws.port.to_string(), "--name", "sockets", "--probe-path", "/"]).await;
    assert_eq!(t2["name"], "sockets");
    assert_eq!(env.agent_pid(), Some(agent_pid), "second tunnel must reuse the agent");
    let host2 = format!("sockets.{BASE}");

    let tls = env.connect(&host2, env.https_port).await;
    let url = format!("wss://{host2}:{}/socket", env.https_port);
    let (mut sock, resp) = tokio_tungstenite::client_async(url, tls).await.expect("websocket handshake");
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
    sock.send(Message::text("hello")).await.unwrap();
    assert_eq!(sock.next().await.unwrap().unwrap(), Message::text("hello"));
    let blob: Vec<u8> = (0..300_000u32).map(|i| (i % 7) as u8).collect();
    sock.send(Message::binary(blob.clone())).await.unwrap();
    assert_eq!(sock.next().await.unwrap().unwrap(), Message::binary(blob));
    // Server-initiated close propagates to the public client.
    sock.send(Message::text("close")).await.unwrap();
    let next = tokio::time::timeout(Duration::from_secs(5), sock.next()).await.expect("close propagated");
    assert!(matches!(next, Some(Ok(Message::Close(_))) | None | Some(Err(_))), "{next:?}");

    // --- listing: CLI and management API ------------------------------------------------------
    let list = env.cli_json(&["list", "--json"]).await;
    assert_eq!(list["tunnels"].as_array().unwrap().len(), 2);
    assert!(list["tunnels"].as_array().unwrap().iter().all(|t| t["status"] == "connected"));

    let admin = env.admin_token();
    let (s, v) = env.api("GET", "/api/v1/tunnels", Some(&admin)).await;
    assert_eq!(s, 200);
    let tunnels = v["tunnels"].as_array().unwrap();
    assert_eq!(tunnels.len(), 2);
    assert!(tunnels.iter().all(|t| t["status"] == "connected" && t["tls"] == "ready"));
    let (s, v) = env.api("GET", "/api/v1/agents", Some(&admin)).await;
    assert_eq!(s, 200);
    assert_eq!(v["agents"][0]["connected"], true);
    // Both sides announced their protocol version on connect.
    assert_eq!(v["agents"][0]["protocol"], magicpipes_core::proto::PROTOCOL_VERSION);
    assert_eq!(env.cli_json(&["status", "--json"]).await["server_protocol"], magicpipes_core::proto::PROTOCOL_VERSION);
    assert_eq!(env.api("GET", "/api/v1/tunnels", None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(env.api("GET", "/api/v1/tunnels", Some("mpadm_wrong")).await.0, StatusCode::UNAUTHORIZED);

    // --- management UI ------------------------------------------------------------------------
    let ui_login = |token: String| {
        let host = format!("localhost:{}", env.mgmt_port);
        Request::post("/login")
            .header(header::HOST, host)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Full::new(Bytes::from(format!("token={token}"))))
            .unwrap()
    };
    let resp = env.send("localhost", env.mgmt_port, ui_login("mpadm_wrong".into())).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = env.send("localhost", env.mgmt_port, ui_login(admin.clone())).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cookie = resp.headers()[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_string();
    assert!(cookie.starts_with("__Host-mp_session="), "{cookie}");
    assert!(resp.headers()[header::SET_COOKIE].to_str().unwrap().contains("HttpOnly"));
    let page = |cookie: String| {
        Request::get("/").header(header::HOST, format!("localhost:{}", env.mgmt_port)).header(header::COOKIE, cookie).body(Full::new(Bytes::new())).unwrap()
    };
    let resp = env.send("localhost", env.mgmt_port, page(cookie.clone())).await;
    assert_eq!(resp.status(), 200);
    let html = String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(html.contains(&host1) && html.contains("sockets") && html.contains("connected"), "{html}");
    // Without a session the UI redirects to the login page.
    let resp = env.send("localhost", env.mgmt_port, page("__Host-mp_session=bogus".into())).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    // State-changing forms need the session's CSRF token, not just the cookie.
    let forged = Request::post("/logout")
        .header(header::HOST, format!("localhost:{}", env.mgmt_port))
        .header(header::COOKIE, cookie.clone())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Full::new(Bytes::from("csrf=wrong")))
        .unwrap();
    assert_eq!(env.send("localhost", env.mgmt_port, forged).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(env.send("localhost", env.mgmt_port, page(cookie.clone())).await.status(), 200, "session survived");
    // The management interface answers only for its own hostname, never a tunnel's.
    let misdirected = Request::get("/login").header(header::HOST, &host1).body(Full::new(Bytes::new())).unwrap();
    assert_eq!(env.send("localhost", env.mgmt_port, misdirected).await.status(), StatusCode::MISDIRECTED_REQUEST);

    // --- local app down: infrastructure error, status "error" -----------------------------------
    app.stop();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (status, err, _) = env.get_public(&host1, "/").await;
    assert_eq!((status, err.as_deref()), (StatusCode::BAD_GATEWAY, Some("local_unreachable")));
    let (_, v) = env.api("GET", &format!("/api/v1/tunnels/{}", t1["id"].as_str().unwrap()), Some(&admin)).await;
    assert_eq!(v["status"], "error");

    // --- agent stop: UI/API report disconnection; start restores registrations ----------------
    env.cli_ok(&["agent", "stop"]).await;
    env.eventually("server sees agent offline", Duration::from_secs(10), || async {
        let (_, v) = env.api("GET", "/api/v1/tunnels/sockets", Some(&admin)).await;
        v["status"] == "disconnected"
    })
    .await;
    let (status, err, _) = env.get_public(&host2, "/").await;
    assert_eq!((status, err.as_deref()), (StatusCode::BAD_GATEWAY, Some("agent_offline")));
    let list = env.cli_json(&["list", "--json"]).await;
    assert_eq!(list["agent_running"], false);

    env.cli_ok(&["agent", "start"]).await;
    let new_pid = env.agent_pid().unwrap();
    assert_ne!(new_pid, agent_pid);
    env.eventually("tunnel restored after agent restart", Duration::from_secs(15), || async {
        env.api("GET", "/api/v1/tunnels/sockets", Some(&admin)).await.1["status"] == "connected"
    })
    .await;
    ws_roundtrip(&env, &host2).await;

    // --- server restart: registrations persist and the agent reconnects -----------------------
    env.stop_server().await;
    env.start_server().await;
    env.eventually("agent reconnects after server restart", Duration::from_secs(30), || async {
        env.api("GET", "/api/v1/tunnels/sockets", Some(&admin)).await.1["status"] == "connected"
    })
    .await;
    let (s, v) = env.api("GET", "/api/v1/tunnels", Some(&admin)).await;
    assert_eq!(s, 200);
    assert_eq!(v["tunnels"].as_array().unwrap().len(), 2, "registrations persisted");
    ws_roundtrip(&env, &host2).await;
    assert_eq!(env.agent_pid(), Some(new_pid), "agent survived the server restart");

    // --- remove: public routing disabled -------------------------------------------------------
    let r = env.cli_json(&["remove", "sockets", "--json"]).await;
    assert_eq!(r["removed"], true);
    let (status, err, _) = env.get_public(&host2, "/").await;
    assert_eq!((status, err.as_deref()), (StatusCode::NOT_FOUND, Some("tunnel_not_found")));

    // --- admin deletion via API is pushed to the agent ----------------------------------------
    let id1 = t1["id"].as_str().unwrap().to_string();
    let (s, _) = env.api("DELETE", &format!("/api/v1/tunnels/{id1}"), Some(&admin)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    env.eventually("agent dropped admin-deleted tunnel", Duration::from_secs(10), || async {
        env.cli_json(&["list", "--json"]).await["tunnels"].as_array().unwrap().is_empty()
    })
    .await;
    assert_eq!(env.api("DELETE", &format!("/api/v1/tunnels/{id1}"), Some(&admin)).await.0, StatusCode::NOT_FOUND);

    env.cli_ok(&["agent", "stop"]).await;
    drop(ws);
}

async fn ws_roundtrip(env: &Env, host: &str) {
    let tls = env.connect(host, env.https_port).await;
    let (mut sock, _) = tokio_tungstenite::client_async(format!("wss://{host}/"), tls).await.expect("websocket handshake");
    sock.send(Message::text("ping")).await.unwrap();
    assert_eq!(sock.next().await.unwrap().unwrap(), Message::text("ping"));
    let _ = sock.close(None).await;
}

/// Entry paths of a `.tar.gz` response body, without trailing slashes.
async fn tar_entries(resp: http::Response<hyper::body::Incoming>) -> Vec<String> {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(&bytes[..]));
    archive
        .entries()
        .unwrap()
        .map(|e| e.unwrap().path().unwrap().to_string_lossy().trim_end_matches('/').to_string())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn static_files() {
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    let site = env.root.join("site");
    std::fs::create_dir_all(site.join("sub dir")).unwrap();
    std::fs::write(site.join("hello.txt"), "hello world").unwrap();
    std::fs::write(site.join("sub dir/a.html"), "<p>a</p>").unwrap();
    std::fs::write(site.join("notes.md"), "# notes").unwrap();
    std::fs::write(site.join("song.mp3"), b"ID3fake").unwrap();
    std::fs::write(site.join("pack.zip"), b"PK").unwrap();
    std::fs::write(site.join(".env"), "SECRET=1").unwrap();
    std::fs::create_dir_all(site.join(".git")).unwrap();
    std::fs::write(site.join(".git/config"), "secret").unwrap();
    std::fs::write(env.root.join("outside.txt"), "outside").unwrap();
    std::os::unix::fs::symlink(env.root.join("outside.txt"), site.join("escape.txt")).unwrap();
    std::os::unix::fs::symlink(&env.root, site.join("escape-dir")).unwrap();
    std::os::unix::fs::symlink(site.join("hello.txt"), site.join("inside.txt")).unwrap();
    let dir = site.to_str().unwrap();

    let out = env.cli_ok(&["add", "--serve", dir, "--name", "files"]).await;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("Serving:"), "{stdout}");
    assert!(stderr.contains("Checking directory...") && stderr.contains("Directory listing is on"), "{stderr}");
    let host = format!("files.{BASE}");
    let request = |method: &str, path: &str| {
        Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, &host)
            .body(Full::new(Bytes::new()))
            .unwrap()
    };

    // Files, with content types; symlinks are followed only inside the root.
    let resp = env.send(&host, env.https_port, request("GET", "/hello.txt")).await;
    assert_eq!(resp.status(), 200);
    assert!(resp.headers()[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/plain"));
    assert_eq!(resp.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(resp.into_body().collect().await.unwrap().to_bytes(), "hello world");
    assert_eq!(env.get_public(&host, "/inside.txt").await.2, "hello world");
    let resp = env.send(&host, env.https_port, request("GET", "/sub%20dir/a.html")).await;
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "text/html; charset=utf-8");
    let content_type = |path: &'static str| {
        let req = request("HEAD", path);
        async { env.send(&host, env.https_port, req).await.headers()[header::CONTENT_TYPE].to_str().unwrap().to_string() }
    };
    assert_eq!(content_type("/notes.md").await, "text/plain; charset=utf-8", "markdown opens as text");
    assert_eq!(content_type("/song.mp3").await, "audio/mpeg");
    assert_eq!(content_type("/pack.zip").await, "application/zip");
    let resp = env.send(&host, env.https_port, request("GET", "/hello.txt?download")).await;
    assert_eq!(resp.headers()[header::CONTENT_DISPOSITION], r#"attachment; filename="hello.txt"; filename*=UTF-8''hello.txt"#);

    // Listing: hidden entries and symlinks leaving the root are not shown.
    let (status, _, body) = env.get_public(&host, "/").await;
    assert_eq!(status, 200);
    assert!(body.contains(r#"href="hello.txt""#) && body.contains(r#"href="sub%20dir/""#) && body.contains("inside.txt"), "{body}");
    // Media opens in a new tab with its icon; archives download.
    assert!(body.contains(r##"href="song.mp3" target="_blank" rel="noopener" title="Audio"><svg class="ic"><use href="#i-audio"/>"##), "{body}");
    assert!(body.contains(r#"href="pack.zip?download" download"#), "{body}");
    assert!(body.contains(r#"<form id="files" class="list" method="post" action="./">"#));
    let csp = env.send(&host, env.https_port, request("GET", "/")).await.headers()[header::CONTENT_SECURITY_POLICY].to_str().unwrap().to_string();
    assert!(csp.contains("script-src 'nonce-") && !csp.contains("unsafe-eval"), "{csp}");
    for hidden in [".env", ".git", "escape.txt", "escape-dir"] {
        assert!(!body.contains(hidden), "{hidden} must not be listed: {body}");
    }

    // Refused: hidden files, traversal, symlinks out of the root.
    for path in ["/.env", "/.git/config", "/escape.txt", "/escape-dir/outside.txt", "/%2e%2e/outside.txt", "/sub%20dir/../../outside.txt", "/nope"] {
        let (status, _, body) = env.get_public(&host, path).await;
        assert_eq!(status, 404, "{path}");
        assert!(!body.contains("outside") && !body.contains("SECRET"), "{path}: {body}");
    }

    // Directories redirect to the trailing-slash form, built from the decoded path.
    let resp = env.send(&host, env.https_port, request("GET", "/sub%20dir?x=1")).await;
    assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(resp.headers()[header::LOCATION], "/sub%20dir/?x=1");
    // A `//host` path naming a real directory must not become a protocol-relative redirect.
    std::fs::create_dir_all(site.join("evil.example")).unwrap();
    let resp = env.send(&host, env.https_port, request("GET", "//evil.example")).await;
    assert_eq!(resp.headers()[header::LOCATION], "/evil.example/", "no open redirect");

    // Ranges, HEAD, and read-only methods.
    let mut req = request("GET", "/hello.txt");
    req.headers_mut().insert(header::RANGE, "bytes=0-4".parse().unwrap());
    let resp = env.send(&host, env.https_port, req).await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(resp.into_body().collect().await.unwrap().to_bytes(), "hello");
    let resp = env.send(&host, env.https_port, request("HEAD", "/hello.txt")).await;
    assert_eq!((resp.status().as_u16(), resp.headers()[header::CONTENT_LENGTH].to_str().unwrap()), (200, "11"));
    let resp = env.send(&host, env.https_port, request("PUT", "/new.txt")).await;
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(!site.join("new.txt").exists());

    // Bulk download: a whole folder, or a posted selection, as a streamed .tar.gz. Hidden entries
    // and symlinks leaving the root are never included; symlinked files inside it are.
    let resp = env.send(&host, env.https_port, request("GET", "/?archive")).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "application/gzip");
    assert!(resp.headers()[header::CONTENT_DISPOSITION].to_str().unwrap().contains(r#"filename="site.tar.gz""#));
    let all = tar_entries(resp).await;
    for want in ["hello.txt", "inside.txt", "notes.md", "song.mp3", "pack.zip", "sub dir", "sub dir/a.html", "evil.example"] {
        assert!(all.iter().any(|e| e == want), "{want} missing from {all:?}");
    }
    for never in [".env", ".git", "escape.txt", "escape-dir", "outside.txt"] {
        assert!(!all.iter().any(|e| e.contains(never)), "{never} must not be archived: {all:?}");
    }
    let mut req = request("POST", "/");
    *req.body_mut() = Full::new(Bytes::from("f=hello.txt&f=sub+dir&f=escape.txt"));
    req.headers_mut().insert(header::CONTENT_TYPE, "application/x-www-form-urlencoded".parse().unwrap());
    let picked = tar_entries(env.send(&host, env.https_port, req).await).await;
    assert_eq!(picked, ["hello.txt", "sub dir", "sub dir/a.html"]);
    let resp = env.send(&host, env.https_port, request("GET", "/sub%20dir/?archive")).await;
    assert!(resp.headers()[header::CONTENT_DISPOSITION].to_str().unwrap().contains(r#"filename="sub dir.tar.gz""#));
    assert_eq!(tar_entries(resp).await, ["a.html"]);
    for (body, status) in [("f=.env", 400), ("f=..%2Fsecret", 400), ("f=", 400), ("", 400)] {
        let mut req = request("POST", "/");
        *req.body_mut() = Full::new(Bytes::from(body));
        assert_eq!(env.send(&host, env.https_port, req).await.status(), status, "{body:?}");
    }
    assert_eq!(env.send(&host, env.https_port, request("POST", "/hello.txt")).await.status(), StatusCode::METHOD_NOT_ALLOWED);

    // Same directory again: same tunnel, now without a listing; index.html is still served.
    let t = add_json(&env, &["--serve", dir, "--no-list"]).await;
    assert_eq!((t["name"].as_str(), t["created"].as_bool()), (Some("files"), Some(false)));
    assert!(t["target"].as_str().unwrap().starts_with("static:/"), "{t}");
    assert_eq!(env.get_public(&host, "/").await.0, 404);
    std::fs::write(site.join("index.html"), "<h1>home</h1>").unwrap();
    assert_eq!(env.get_public(&host, "/").await.2, "<h1>home</h1>");
    // Without listings there are no folder archives either.
    assert_eq!(env.get_public(&host, "/sub%20dir/").await.0, 404);
    assert_eq!(env.get_public(&host, "/sub%20dir/?archive").await.0, 404);
    assert_eq!(env.send(&host, env.https_port, request("POST", "/sub%20dir/")).await.status(), StatusCode::METHOD_NOT_ALLOWED);

    // Input errors.
    let out = env.cli(&["add", "--serve", "/nonexistent/dir", "--json"]).await;
    assert_eq!(out.status.code(), Some(4));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "invalid_directory");
    let out = env.cli(&["add", "--serve", site.join("hello.txt").to_str().unwrap(), "--json"]).await;
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "invalid_directory", "{v}");
    assert_eq!(env.cli(&["add", "8080", "--serve", dir]).await.status.code(), Some(2));

    env.cli_ok(&["remove", "files"]).await;
    env.cli_ok(&["agent", "stop"]).await;
}

/// Opens a web terminal session and says hello; returns the socket and the first control message.
async fn terminal(env: &Env, host: &str, key: Option<&str>) -> (Terminal, Value) {
    let tls = env.connect(host, env.https_port).await;
    let mut req = format!("wss://{host}/ws").into_client_request().unwrap();
    req.headers_mut().insert("origin", format!("https://{host}").parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::client_async(req, tls).await.expect("terminal handshake");
    let hello = serde_json::json!({ "type": "hello", "key": key, "cols": 100, "rows": 30 });
    ws.send(Message::text(hello.to_string())).await.unwrap();
    let (_, first) = read_terminal(&mut ws, "", Duration::from_secs(10)).await;
    (ws, first.expect("a control message after hello"))
}

type Terminal = tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

/// Collects terminal output until it contains `want` (if not empty), a control message arrives
/// (returned), the socket closes or `wait` passes.
async fn read_terminal(ws: &mut Terminal, want: &str, wait: Duration) -> (String, Option<Value>) {
    let mut out = String::new();
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Ok(Some(Ok(Message::Binary(b)))) => {
                out.push_str(&String::from_utf8_lossy(&b));
                if !want.is_empty() && out.contains(want) {
                    return (out, None);
                }
            }
            Ok(Some(Ok(Message::Text(t)))) => return (out, Some(serde_json::from_str(&t).unwrap())),
            Ok(Some(Ok(_))) => {}
            _ => return (out, None),
        }
    }
}

fn process_alive(pid: &str) -> bool {
    std::process::Command::new("kill").args(["-0", pid]).stderr(std::process::Stdio::null()).status().unwrap().success()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn web_terminal() {
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    let script = "echo READY; read line; echo GOT:$line";

    // --- read-only (the default) ----------------------------------------------------------------
    let out = env.cli_ok(&["add", "--shell", "--name", "ro", "--", "/bin/sh", "-c", script]).await;
    let (stdout, stderr) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("Shell:  /bin/sh -c 'echo READY; read line; echo GOT:$line' (read-only)"), "{stdout}");
    assert!(stderr.contains("Checking program...") && stderr.contains("Visitors only watch"), "{stderr}");
    let listed = env.cli_json(&["list", "--json"]).await;
    let ro = &listed["tunnels"][0];
    assert_eq!(ro["share_url"], ro["public_url"], "no key for a read-only terminal");
    let host = format!("ro.{BASE}");

    let get = |path: &str, gzip: bool| {
        let mut b = Request::get(path).header(header::HOST, &host);
        if gzip {
            b = b.header(header::ACCEPT_ENCODING, "gzip");
        }
        b.body(Full::new(Bytes::new())).unwrap()
    };
    let page = env.send(&host, env.https_port, get("/", false)).await;
    assert_eq!(page.status(), StatusCode::OK);
    let csp = page.headers()[header::CONTENT_SECURITY_POLICY].to_str().unwrap().to_string();
    let html = String::from_utf8(page.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(html.contains(r#"data-access="open""#) && html.contains("<title>sh · MagicPipes</title>"), "{html}");
    let nonce = csp.split("'nonce-").nth(1).unwrap().split('\'').next().unwrap();
    assert!(html.contains(&format!(r#"<script type="module" nonce="{nonce}">"#)));
    let js = env.send(&host, env.https_port, get("/assets/xterm.mjs", true)).await;
    assert_eq!((js.status(), js.headers().get(header::CONTENT_ENCODING).map(|v| v.to_str().unwrap())), (StatusCode::OK, Some("gzip")));
    // The icon font is already compressed, and the CSP lets the page load it.
    let font = env.send(&host, env.https_port, get("/assets/symbols-nerd-font-mono.woff2", true)).await;
    assert_eq!((font.status(), font.headers().get(header::CONTENT_ENCODING)), (StatusCode::OK, None));
    assert_eq!(font.headers()[header::CONTENT_TYPE], "font/woff2");
    assert!(csp.contains("font-src 'self'"), "{csp}");
    assert_eq!(env.send(&host, env.https_port, get("/nope", false)).await.status(), StatusCode::NOT_FOUND);
    // A plain request for /ws is not a WebSocket.
    assert_eq!(env.send(&host, env.https_port, get("/ws", false)).await.status(), StatusCode::BAD_REQUEST);

    // Cross-origin pages cannot open sessions.
    let tls = env.connect(&host, env.https_port).await;
    let mut req = format!("wss://{host}/ws").into_client_request().unwrap();
    req.headers_mut().insert("origin", "https://evil.example".parse().unwrap());
    assert!(tokio_tungstenite::client_async(req, tls).await.is_err(), "cross-origin handshake must fail");

    // Output arrives; typing is ignored by the agent.
    let (mut ws, ready) = terminal(&env, &host, None).await;
    assert_eq!(ready, serde_json::json!({ "type": "ready", "writable": false }));
    let (screen, _) = read_terminal(&mut ws, "READY", Duration::from_secs(10)).await;
    assert!(screen.contains("READY"), "{screen:?}");
    ws.send(Message::binary(b"typed\r".to_vec())).await.unwrap();
    let (screen, ctl) = read_terminal(&mut ws, "GOT:", Duration::from_millis(1500)).await;
    assert!(!screen.contains("typed") && ctl.is_none(), "read-only input reached the program: {screen:?} {ctl:?}");
    drop(ws);

    // --- read-write with the secret link -------------------------------------------------------
    let rw = add_json(&env, &["--shell", "--write", "--name", "rw", "--", "/bin/sh", "-c", script]).await;
    assert_eq!(rw["target"], "shell:/bin/sh -c 'echo READY; read line; echo GOT:$line' (read-write)");
    let share = rw["share_url"].as_str().unwrap().to_string();
    let key = share.split_once("#k=").expect("share URL carries the key").1.to_string();
    assert!(key.len() >= 32 && !rw["public_url"].as_str().unwrap().contains(&key));
    let tunnels = std::fs::read_to_string(env.home().join("tunnels.json")).unwrap();
    assert!(tunnels.contains(&key), "the key is kept in tunnels.json");
    // Re-adding keeps the link.
    let again = add_json(&env, &["--shell", "--write", "--name", "rw", "--", "/bin/sh", "-c", script]).await;
    assert_eq!((again["share_url"].as_str(), again["created"].as_bool()), (Some(share.as_str()), Some(false)));

    let host = format!("rw.{BASE}");
    for bad in [None, Some("wrong")] {
        let (_, refused) = terminal(&env, &host, bad).await;
        assert_eq!((refused["type"].as_str(), refused["code"].as_str()), (Some("error"), Some("key")), "{bad:?}");
    }
    let (mut ws, ready) = terminal(&env, &host, Some(&key)).await;
    assert_eq!(ready["writable"], true);
    read_terminal(&mut ws, "READY", Duration::from_secs(10)).await;
    ws.send(Message::binary(b"typed\r".to_vec())).await.unwrap();
    let (screen, _) = read_terminal(&mut ws, "GOT:typed", Duration::from_secs(10)).await;
    assert!(screen.contains("GOT:typed"), "{screen:?}");
    let (_, exit) = read_terminal(&mut ws, "", Duration::from_secs(10)).await;
    assert_eq!(exit, Some(serde_json::json!({ "type": "exit", "code": 0, "signal": null })));

    // Re-adding read-only revokes the key and ends open sessions.
    let (mut ws, _) = terminal(&env, &host, Some(&key)).await;
    let ro_again = add_json(&env, &["--shell", "--name", "rw", "--", "/bin/sh", "-c", script]).await;
    assert_eq!(ro_again["share_url"], ro_again["public_url"]);
    let (_, ended) = read_terminal(&mut ws, "", Duration::from_secs(10)).await;
    assert_eq!(ended.unwrap()["type"], "ended");
    let (_, ready) = terminal(&env, &host, Some(&key)).await;
    assert_eq!(ready["writable"], false, "a stale key no longer grants writing");

    // --- session limit, and programs end with their session ------------------------------------
    let pidfile = env.root.join("pid");
    let cmd = format!("echo $$ > {}; echo STARTED; exec sleep 60", pidfile.display());
    add_json(&env, &["--shell", "--max-clients", "1", "--name", "one", "--", "/bin/sh", "-c", &cmd]).await;
    let host = format!("one.{BASE}");
    let (mut first, ready) = terminal(&env, &host, None).await;
    assert_eq!(ready["type"], "ready");
    read_terminal(&mut first, "STARTED", Duration::from_secs(10)).await;
    let (_, busy) = terminal(&env, &host, None).await;
    assert_eq!(busy["code"], "busy");
    let pid = std::fs::read_to_string(&pidfile).unwrap().trim().to_string();
    assert!(process_alive(&pid));
    let _ = first.close(None).await;
    drop(first);
    env.eventually("program killed when its session closed", Duration::from_secs(10), || async { !process_alive(&pid) }).await;
    let (mut second, ready) = terminal(&env, &host, None).await;
    assert_eq!(ready["type"], "ready", "the slot was released");
    read_terminal(&mut second, "STARTED", Duration::from_secs(10)).await;

    // Removing the tunnel ends its sessions and their programs.
    let pid = std::fs::read_to_string(&pidfile).unwrap().trim().to_string();
    env.cli_ok(&["remove", "one"]).await;
    let (_, ended) = read_terminal(&mut second, "", Duration::from_secs(10)).await;
    assert_eq!(ended.unwrap()["type"], "ended");
    env.eventually("program killed when its tunnel was removed", Duration::from_secs(10), || async { !process_alive(&pid) }).await;

    // --- input errors ---------------------------------------------------------------------------
    let out = env.cli(&["add", "--shell", "--json", "--", "no-such-program-mp"]).await;
    assert_eq!(out.status.code(), Some(4));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "invalid_command");
    assert_eq!(env.cli(&["add", "--shell", "8080"]).await.status.code(), Some(2));
    assert_eq!(env.cli(&["add", "8080", "--write"]).await.status.code(), Some(2));

    env.cli_ok(&["agent", "stop"]).await;
}

/// Sends `msg` through a TCP port and returns what came back (empty if the server closed it).
async fn tcp_roundtrip(port: u16, msg: &[u8]) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Ok(mut s) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await else { return Vec::new() };
    if s.write_all(msg).await.is_err() {
        return Vec::new();
    }
    let mut got = vec![0u8; msg.len()];
    match tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut got)).await {
        Ok(Ok(_)) => got,
        _ => Vec::new(),
    }
}

async fn udp_roundtrip(client: &tokio::net::UdpSocket, port: u16, msg: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 65536];
    for _ in 0..5 {
        client.send_to(msg, ("127.0.0.1", port)).await.unwrap();
        if let Ok(Ok((n, _))) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await {
            return buf[..n].to_vec();
        }
    }
    Vec::new()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn port_tunnels() {
    let mut env = Env::new(Tls::DevCa).await;
    env.login().await;
    let echo = common::tcp_echo_app().await;
    let (first, last) = env.ports;

    // --- TCP: an echo service through a public port -------------------------------------------
    let out = env.cli_ok(&["add", &echo.port.to_string(), "--tcp", "--name", "echo"]).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Checking tunnel...") && stderr.contains("Verifying public endpoint...  ✓"), "{stderr}");
    assert!(stderr.contains("--allow-cidr"), "warns that the port is open to anyone: {stderr}");
    let t = add_json(&env, &[&echo.port.to_string(), "--tcp"]).await;
    assert_eq!((t["kind"].as_str(), t["created"].as_bool(), t["reachable"].as_bool()), (Some("tcp"), Some(false), Some(true)));
    let port = t["public_port"].as_u64().unwrap() as u16;
    assert!((first..=last).contains(&port), "{t}");
    assert_eq!(t["public_url"], format!("tcp://localhost:{port}"));
    assert_eq!(t["target"], format!("tcp://127.0.0.1:{}", echo.port));
    assert_eq!(tcp_roundtrip(port, b"hello over tcp").await, b"hello over tcp");
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(tcp_roundtrip(port, &big).await, big, "large transfers arrive intact");

    // An HTTP tunnel to the same local port is a separate tunnel.
    let list = env.cli_json(&["list", "--json"]).await;
    assert_eq!(list["tunnels"].as_array().unwrap().len(), 1);
    assert_eq!(list["tunnels"][0]["kind"], "tcp");

    // The management API shows the port.
    let token = env.admin_token();
    let (_, tunnels) = env.api("GET", "/api/v1/tunnels", Some(&token)).await;
    let api_t = tunnels["tunnels"].as_array().unwrap().iter().find(|x| x["name"] == "echo").cloned().unwrap();
    assert_eq!((api_t["kind"].as_str(), api_t["public_port"].as_u64(), api_t["tls"].as_str()), (Some("tcp"), Some(port as u64), Some("none")));

    // --- --remote-port --------------------------------------------------------------------------
    let echo2 = common::tcp_echo_app().await;
    let wanted = if port == last { first } else { last };
    let t2 = add_json(&env, &[&echo2.port.to_string(), "--tcp", "--remote-port", &wanted.to_string()]).await;
    assert_eq!(t2["public_port"].as_u64(), Some(wanted as u64));
    assert_eq!(tcp_roundtrip(wanted, b"second").await, b"second");
    let echo3 = common::tcp_echo_app().await;
    let out = env.cli(&["add", &echo3.port.to_string(), "--tcp", "--json", "--remote-port", &wanted.to_string()]).await;
    assert_eq!(out.status.code(), Some(6), "{}", String::from_utf8_lossy(&out.stdout));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "port_unavailable");
    let out = env.cli(&["add", &echo3.port.to_string(), "--tcp", "--json", "--remote-port", "80"]).await;
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "port_unavailable", "outside the range: {v}");

    // --- --allow-cidr ---------------------------------------------------------------------------
    // Re-adding replaces the settings; 127.0.0.1 is not in 10.0.0.0/8, so even this machine's
    // own check of the public port is refused (a warning, not a failure).
    let t = add_json(&env, &[&echo.port.to_string(), "--tcp", "--allow-cidr", "10.0.0.0/8"]).await;
    assert_eq!((t["public_port"].as_u64(), t["reachable"].as_bool()), (Some(port as u64), Some(false)));
    assert_eq!(t["allow"], serde_json::json!(["10.0.0.0/8"]));
    assert!(tcp_roundtrip(port, b"blocked").await.is_empty(), "client outside the allow-list");
    let t = add_json(&env, &[&echo.port.to_string(), "--tcp", "--allow-cidr", "10.0.0.0/8", "--allow-cidr", "127.0.0.1"]).await;
    assert_eq!(t["reachable"], true);
    assert_eq!(tcp_roundtrip(port, b"allowed").await, b"allowed");
    add_json(&env, &[&echo.port.to_string(), "--tcp"]).await;

    // --- the local service stops, the agent goes away, the server restarts ---------------------
    echo2.stop();
    assert!(tcp_roundtrip(wanted, b"x").await.is_empty(), "local service down: connection closed");
    env.cli_ok(&["agent", "stop"]).await;
    assert!(tcp_roundtrip(port, b"x").await.is_empty(), "agent offline: connection closed");
    assert!(tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok(), "the port stays reserved while the agent is offline");
    env.stop_server().await;
    env.start_server().await;
    env.cli_ok(&["agent", "start"]).await;
    env.eventually("tunnel restored after a server restart", Duration::from_secs(20), || async {
        tcp_roundtrip(port, b"back").await == b"back"
    })
    .await;

    // --- UDP --------------------------------------------------------------------------------------
    let dns = common::udp_echo_app().await;
    let out = env.cli_ok(&["add", &dns.port.to_string(), "--udp", "--name", "dns"]).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("UDP cannot be verified"), "{stderr}");
    let u = add_json(&env, &[&dns.port.to_string(), "--udp"]).await;
    assert_eq!((u["kind"].as_str(), u["verified"].as_bool()), (Some("udp"), Some(false)));
    let uport = u["public_port"].as_u64().unwrap() as u16;
    assert_eq!(u["public_url"], format!("udp://localhost:{uport}"));
    let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_eq!(udp_roundtrip(&a, uport, b"one").await, b"echo:one");
    assert_eq!(udp_roundtrip(&b, uport, b"two").await, b"echo:two", "each client gets its own replies");
    assert_eq!(udp_roundtrip(&a, uport, b"three").await, b"echo:three");
    // macOS caps UDP datagrams at 9216 bytes by default.
    let big = vec![7u8; 9_000];
    assert_eq!(udp_roundtrip(&a, uport, &big).await.len(), 9_005, "large datagrams keep their size");
    // A flow ends after the idle timeout (5s in tests) and a new one starts on the next datagram.
    tokio::time::sleep(Duration::from_secs(7)).await;
    assert_eq!(udp_roundtrip(&a, uport, b"later").await, b"echo:later");

    // --- removing frees the port -------------------------------------------------------------------
    env.cli_ok(&["remove", "echo"]).await;
    env.eventually("port closed after remove", Duration::from_secs(5), || async {
        tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_err()
    })
    .await;
    env.cli_ok(&["remove", "dns"]).await;

    // --- input errors ------------------------------------------------------------------------------
    assert_eq!(env.cli(&["add", "8080", "--remote-port", "65500"]).await.status.code(), Some(2));
    assert_eq!(env.cli(&["add", "8080", "--tcp", "--allow-cidr", "10.0.0.0/33"]).await.status.code(), Some(2));
    assert_eq!(env.cli(&["add", "--serve", ".", "--tcp"]).await.status.code(), Some(2));
    let out = env.cli(&["add", &common::free_port().to_string(), "--tcp", "--json"]).await;
    assert_eq!(out.status.code(), Some(4), "nothing listening locally");

    env.cli_ok(&["agent", "stop"]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_adds_start_one_agent() {
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    let a = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let b = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let (pa, pb) = (a.port.to_string(), b.port.to_string());
    // Four concurrent invocations, two per port, with no agent running yet.
    let (args_a, args_b) = ([pa.as_str()], [pb.as_str()]);
    let (r1, r2, r3, r4) = tokio::join!(
        add_json(&env, &args_a),
        add_json(&env, &args_b),
        add_json(&env, &args_a),
        add_json(&env, &args_b),
    );
    assert_eq!(r1["id"], r3["id"], "same port must map to one tunnel");
    assert_eq!(r2["id"], r4["id"], "same port must map to one tunnel");
    assert_ne!(r1["id"], r2["id"]);
    let starts = env.agent_log().matches("agent started").count();
    assert_eq!(starts, 1, "exactly one agent must start:\n{}", env.agent_log());
    let (_, v) = env.api("GET", "/api/v1/tunnels", Some(&env.admin_token())).await;
    assert_eq!(v["tunnels"].as_array().unwrap().len(), 2, "no duplicate registrations");
    env.cli_ok(&["agent", "stop"]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoked_agent_is_cut_off() {
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let t = add_json(&env, &[&app.port.to_string()]).await;
    let host = hostname(t["public_url"].as_str().unwrap());
    assert_eq!(env.get_public(&host, "/").await.0, StatusCode::OK);

    let admin = env.admin_token();
    let (_, v) = env.api("GET", "/api/v1/agents", Some(&admin)).await;
    let agent_id = v["agents"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(env.api("DELETE", &format!("/api/v1/agents/{agent_id}"), None).await.0, StatusCode::UNAUTHORIZED);
    let (s, _) = env.api("DELETE", &format!("/api/v1/agents/{agent_id}"), Some(&admin)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // The agent's tunnels are gone at once, and its reconnect is rejected.
    let (status, err, _) = env.get_public(&host, "/").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(err.as_deref(), Some("tunnel_not_found"));
    let (_, v) = env.api("GET", "/api/v1/agents", Some(&admin)).await;
    assert!(v["agents"].as_array().unwrap().is_empty(), "{v}");
    let (_, v) = env.api("GET", "/api/v1/tunnels", Some(&admin)).await;
    assert!(v["tunnels"].as_array().unwrap().is_empty(), "{v}");
    env.eventually("agent sees its credential rejected", Duration::from_secs(15), || async {
        env.cli_json(&["status", "--json"]).await["connection"] == "unauthorized"
    })
    .await;
    assert!(env.server_log().contains("agent revoked"));
    assert_eq!(env.api("DELETE", &format!("/api/v1/agents/{agent_id}"), Some(&admin)).await.0, StatusCode::NOT_FOUND);
    env.cli_ok(&["agent", "stop"]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn certificate_failure_is_reported() {
    let env = Env::new(Tls::BrokenAcme).await;
    env.login().await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let out = env.cli(&["add", &app.port.to_string(), "--timeout", "60"]).await;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(7), "stdout: {stdout}\nstderr: {stderr}");
    assert!(stderr.contains("Checking HTTPS certificate... ✗"), "{stderr}");
    assert!(stderr.contains("certificate provisioning failed"), "{stderr}");
    assert!(!stdout.contains("https://"), "no URL may be printed on failure: {stdout}");

    // JSON mode: a structured error on stdout.
    let out = env.cli(&["add", &app.port.to_string(), "--json", "--timeout", "60"]).await;
    assert_eq!(out.status.code(), Some(7));
    let v: Value = serde_json::from_slice(&out.stdout).expect("JSON error on stdout");
    assert_eq!(v["error"]["code"], "tls_failed");
    assert_eq!(v["error"]["step"], "tls");

    // The half-created tunnel was cleaned up and the idle agent we started was stopped.
    let (_, v) = env.api("GET", "/api/v1/tunnels", Some(&env.admin_token())).await;
    assert!(v["tunnels"].as_array().unwrap().is_empty(), "{v}");
    env.eventually("idle agent stopped", Duration::from_secs(5), || async {
        env.cli_json(&["status", "--json"]).await["agent"]["running"] == false
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authentication_and_input_failures() {
    let env = Env::new(Tls::DevCa).await;
    let url = env.server_url();
    let ca = env.ca_path.to_string_lossy().to_string();

    // Not enrolled yet.
    let out = env.cli(&["add", "9", "--json"]).await;
    assert_eq!(out.status.code(), Some(3));

    // Invalid and reused enrollment tokens.
    let out = env.cli(&["login", "--server", &url, "--token", "mpenr_invalid", "--ca-cert", &ca]).await;
    assert_eq!(out.status.code(), Some(3), "{}", String::from_utf8_lossy(&out.stderr));
    let token = env.enrollment_token();
    env.cli_ok(&["login", "--server", &url, "--token", &token, "--ca-cert", &ca]).await;
    let out = env.cli(&["login", "--server", &url, "--token", &token, "--ca-cert", &ca]).await;
    assert_eq!(out.status.code(), Some(3), "enrollment tokens are single-use");

    // Nothing listening locally.
    let closed = common::free_port().to_string();
    let out = env.cli(&["add", &closed, "--json"]).await;
    assert_eq!(out.status.code(), Some(4));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "local_unreachable");

    // Tampered agent credentials are rejected by the server.
    let cfg_path = env.home().join("config.json");
    let mut cfg: Value = serde_json::from_str(&std::fs::read_to_string(&cfg_path).unwrap()).unwrap();
    let id = cfg["agent_id"].as_str().unwrap().to_string();
    cfg["agent_token"] = Value::String(format!("{id}.mpa_forged"));
    std::fs::write(&cfg_path, cfg.to_string()).unwrap();
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let out = env.cli(&["add", &app.port.to_string(), "--json", "--timeout", "15"]).await;
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(out.status.code(), Some(3), "{v}");
    assert_eq!(v["error"]["code"], "unauthorized");
    assert!(env.server_log().contains("invalid credentials"));
}

/// The secret a "shown once" page displays.
fn shown_secret(html: &str) -> String {
    let at = html.find(r#"<pre class="term">"#).expect("secret on the page") + r#"<pre class="term">"#.len();
    html[at..].split("</pre>").next().unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn user_accounts() {
    let env = Env::new(Tls::DevCa).await;
    let admin = env.admin_token();
    let new_user = |email: &str, role: &str| serde_json::json!({ "email": email, "display_name": "Ann", "role": role });

    // Only administrators create users; the server generates a password that must be changed.
    assert_eq!(env.api_json("POST", "/api/v1/users", None, new_user("ann@example.com", "member")).await.0, StatusCode::UNAUTHORIZED);
    let (s, v) = env.api_json("POST", "/api/v1/users", Some(&admin), new_user("Ann@Example.com", "member")).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!((v["user"]["email"].as_str(), v["user"]["must_change_password"].as_bool()), (Some("ann@example.com"), Some(true)));
    let ann_id = v["user"]["id"].as_str().unwrap().to_string();
    let generated = v["password"].as_str().unwrap().to_string();
    let (s, v) = env.api_json("POST", "/api/v1/users", Some(&admin), new_user("ann@example.com", "admin")).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("email_taken")));

    // A wrong password and an unknown email look the same.
    let env = &env;
    let login = |email: &'static str, password: String| async move {
        env.ui("/login", None, Some(&[("email", email), ("password", password.as_str())])).await
    };
    let wrong = login("ann@example.com", "not the password".into()).await;
    let unknown = login("nobody@example.com", "not the password".into()).await;
    assert_eq!((wrong.status, unknown.status), (StatusCode::UNAUTHORIZED, StatusCode::UNAUTHORIZED));
    assert!(wrong.html.contains("Email or password is incorrect.") && unknown.html.contains("Email or password is incorrect."));

    // First sign-in: the user must replace the generated password before anything else.
    let first = login("ann@example.com", generated.clone()).await;
    assert_eq!((first.status, first.location.as_deref()), (StatusCode::SEE_OTHER, Some("/password")));
    let cookie = first.cookie.clone().unwrap();
    assert!(cookie.starts_with("__Host-mp_session="));
    assert_eq!(env.ui("/account", Some(&cookie), None).await.location.as_deref(), Some("/password?next=%2Faccount"));
    let form = env.ui("/password", Some(&cookie), None).await;
    assert_eq!(form.status, 200);
    let new_password = "correct horse battery staple";
    let changed = env
        .ui("/password", Some(&cookie), Some(&[("csrf", &form.csrf()), ("current", &generated), ("new", new_password), ("repeat", new_password)]))
        .await;
    assert_eq!(changed.status, StatusCode::SEE_OTHER, "{}", changed.html);
    let cookie2 = changed.cookie.clone().unwrap();
    assert_eq!(env.ui("/account", Some(&cookie), None).await.location.as_deref(), Some("/login?next=%2Faccount"), "old session ended");

    // Members get their account and machines, not the administration pages.
    let account = env.ui("/account", Some(&cookie2), None).await;
    assert!(account.status == 200 && account.html.contains("ann@example.com"), "{}", account.html);
    let home = env.ui("/", Some(&cookie2), None).await;
    assert!(home.status == 200 && !home.html.contains("Create enrollment token"), "members see their machines, not the administration");
    assert_eq!(env.ui("/users", Some(&cookie2), None).await.location.as_deref(), Some("/account"));

    // An API token acts as its user, with the user's role.
    let created = env.ui("/account/tokens", Some(&cookie2), Some(&[("csrf", &account.csrf()), ("name", "ci")])).await;
    let token = shown_secret(&created.html);
    assert!(token.starts_with("tok_"), "{}", created.html);
    let (s, v) = env.api("GET", "/api/v1/me", Some(&token)).await;
    assert_eq!((s, v["user"]["id"].as_str()), (StatusCode::OK, Some(ann_id.as_str())));
    let (s, v) = env.api("GET", "/api/v1/status", Some(&token)).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::FORBIDDEN, Some("forbidden")));
    assert_eq!(env.api("GET", "/api/v1/users", Some(&token)).await.1["users"].as_array().unwrap().len(), 1);
    let (s, _) = env.api_json("PATCH", &format!("/api/v1/users/{ann_id}"), Some(&token), serde_json::json!({ "role": "admin" })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "users can't promote themselves");

    // Disabling ends the sessions and the API tokens; the admin token keeps working.
    let (s, v) = env.api_json("PATCH", &format!("/api/v1/users/{ann_id}"), Some(&admin), serde_json::json!({ "disabled": true })).await;
    assert_eq!((s, v["disabled"].as_bool()), (StatusCode::OK, Some(true)));
    assert_eq!(env.ui("/account", Some(&cookie2), None).await.location.as_deref(), Some("/login?next=%2Faccount"));
    assert_eq!(env.api("GET", "/api/v1/me", Some(&token)).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(login("ann@example.com", new_password.into()).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(env.api("GET", "/api/v1/status", Some(&admin)).await.0, StatusCode::OK);

    // After repeated failures an account accepts one attempt every few seconds, right or not.
    let (_, v) = env
        .api_json("POST", "/api/v1/users", Some(&admin), serde_json::json!({ "email": "bo@example.com", "password": new_password, "role": "admin" }))
        .await;
    assert!(v.get("password").is_none(), "no generated password when one was given");
    for _ in 0..10 {
        login("bo@example.com", "guess guess guess".into()).await;
    }
    let throttled = login("bo@example.com", new_password.into()).await;
    assert_eq!(throttled.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(throttled.html.contains("this account"), "{}", throttled.html);

    let (s, v) = env.api("GET", "/api/v1/audit", Some(&admin)).await;
    assert_eq!(s, StatusCode::OK);
    let actions: Vec<&str> = v["entries"].as_array().unwrap().iter().filter_map(|e| e["action"].as_str()).collect();
    for want in ["user.create", "login.failed", "session.login", "user.password_change", "token.create", "user.disable"] {
        assert!(actions.contains(&want), "{want} missing from {actions:?}");
    }
    // A disabled user's token is refused (429 by now: this client failed too often).
    assert!(matches!(env.api("GET", "/api/v1/audit", Some(&token)).await.0, StatusCode::UNAUTHORIZED | StatusCode::TOO_MANY_REQUESTS));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn browser_login_enrolls_your_machine() {
    use tokio::io::AsyncBufReadExt;
    let env = Env::new(Tls::DevCa).await;
    let admin = env.admin_token();
    let (s, _) = env.api_json("POST", "/api/v1/tags", Some(&admin), serde_json::json!({ "name": "team:dev" })).await;
    assert_eq!(s, StatusCode::CREATED);
    let password = "correct horse battery staple";
    let (_, v) = env
        .api_json("POST", "/api/v1/users", Some(&admin), serde_json::json!({ "email": "ann@example.com", "password": password }))
        .await;
    let ann = v["user"]["id"].as_str().unwrap().to_string();
    let (s, v) = env.api_json("PATCH", &format!("/api/v1/users/{ann}"), Some(&admin), serde_json::json!({ "tags": ["Team:Dev"] })).await;
    assert_eq!((s, v["tags"].clone()), (StatusCode::OK, serde_json::json!(["team:dev"])));
    let (s, v) = env.api_json("PATCH", &format!("/api/v1/users/{ann}"), Some(&admin), serde_json::json!({ "tags": ["team:qa"] })).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::BAD_REQUEST, Some("tag_unknown")));

    // `magicpipes login` without a token prints an approval link and waits.
    let url = env.server_url();
    let ca = env.ca_path.to_string_lossy().to_string();
    let mut child = env.cli_spawn(&["login", "--server", &url, "--ca-cert", &ca, "--browser", "--name", "laptop"]);
    let mut lines = tokio::io::BufReader::new(child.stderr.take().unwrap()).lines();
    let link = tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(line) = lines.next_line().await.unwrap() {
            if let Some(at) = line.find("/cli?code=") {
                return line[at..].trim().to_string();
            }
        }
        panic!("no approval link");
    })
    .await
    .unwrap();

    // Signing in on the way keeps the destination (and the forced password change).
    let page = env.ui(&link, None, None).await;
    assert_eq!(page.location.as_deref(), Some(format!("/login?next={}", link.replace('/', "%2F").replace('?', "%3F").replace('=', "%3D")).as_str()));
    let signed_in = env.ui("/login", None, Some(&[("email", "ann@example.com"), ("password", password), ("next", &link)])).await;
    assert!(signed_in.location.as_deref().is_some_and(|l| l.starts_with("/password?next=")), "{:?}", signed_in.location);
    let cookie = signed_in.cookie.unwrap();
    let form = env.ui("/password", Some(&cookie), None).await;
    let new_password = "another horse battery staple";
    let changed = env
        .ui("/password", Some(&cookie), Some(&[("csrf", &form.csrf()), ("current", password), ("new", new_password), ("repeat", new_password), ("next", &link)]))
        .await;
    assert_eq!(changed.location.as_deref(), Some(link.as_str()));
    let cookie = changed.cookie.unwrap();
    // An outside `next` is ignored.
    let elsewhere = env.ui("/login", None, Some(&[("email", "ann@example.com"), ("password", new_password), ("next", "//evil.example/")])).await;
    assert_eq!(elsewhere.location.as_deref(), Some("/"));

    let approval = env.ui(&link, Some(&cookie), None).await;
    assert!(approval.status == 200 && approval.html.contains("laptop") && approval.html.contains("team:dev"), "{}", approval.html);
    let code = link.split("code=").nth(1).unwrap().to_string();
    let done = env.ui("/cli", Some(&cookie), Some(&[("csrf", &approval.csrf()), ("code", &code), ("answer", "approve"), ("tag", "team:dev")])).await;
    assert!(done.html.contains("Approved"), "{}", done.html);
    let out = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output()).await.unwrap().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    assert!(env.ui(&link, Some(&cookie), None).await.status == StatusCode::NOT_FOUND, "a code works once");

    // The machine belongs to Ann, with her tag, and its tunnels default to private.
    let (_, v) = env.api("GET", "/api/v1/agents", Some(&admin)).await;
    let laptop = v["agents"].as_array().unwrap().iter().find(|a| a["name"] == "laptop").unwrap().clone();
    assert_eq!(laptop["owner_email"], "ann@example.com");
    assert_eq!(laptop["tags"], serde_json::json!(["team:dev"]));
    assert_eq!(laptop["default_private"], true);
    let mine = env.ui("/", Some(&cookie), None).await;
    assert!(mine.status == 200 && mine.html.contains("laptop"), "members see their own machines");

    // Denying works too, and the waiting CLI says so.
    let mut child = env.cli_spawn(&["login", "--server", &url, "--ca-cert", &ca, "--browser", "--name", "other"]);
    let mut lines = tokio::io::BufReader::new(child.stderr.take().unwrap()).lines();
    let code = loop {
        let line = lines.next_line().await.unwrap().unwrap();
        if let Some(at) = line.find("code=") {
            break line[at + 5..].trim().to_string();
        }
    };
    let approval = env.ui(&format!("/cli?code={code}"), Some(&cookie), None).await;
    env.ui("/cli", Some(&cookie), Some(&[("csrf", &approval.csrf()), ("code", &code), ("answer", "deny")])).await;
    let out = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output()).await.unwrap().unwrap();
    assert_eq!(out.status.code(), Some(3));
}

/// Signs a new user in and replaces the password an administrator set; returns the session cookie.
async fn sign_in(env: &Env, email: &str, password: &str) -> String {
    let first = env.ui("/login", None, Some(&[("email", email), ("password", password)])).await;
    let cookie = first.cookie.expect("signed in");
    let form = env.ui("/password", Some(&cookie), None).await;
    let new = format!("{password} again");
    let changed = env.ui("/password", Some(&cookie), Some(&[("csrf", &form.csrf()), ("current", password), ("new", &new), ("repeat", &new)])).await;
    changed.cookie.expect("new session")
}

/// A browser opening `path` on a private tunnel while signed in to the management UI with
/// `ui_cookie`. Returns the tunnel cookie, or the management page that refused.
async fn open_private(env: &Env, host: &str, path: &str, ui_cookie: &str) -> Result<String, common::UiResponse> {
    let first = env.tunnel_get(host, path, "", true).await;
    assert_eq!(first.status, StatusCode::SEE_OTHER, "{}", first.body);
    let state = first.cookie("__Host-mp_state").expect("state cookie");
    let mgmt = format!("https://localhost:{}", env.mgmt_port);
    let at = first.location.unwrap().strip_prefix(&mgmt).expect("sent to the management host").to_string();
    let auth = env.ui(&at, Some(ui_cookie), None).await;
    let Some(callback) = auth.location.clone().filter(|_| auth.status == StatusCode::SEE_OTHER) else { return Err(auth) };
    let callback = callback.strip_prefix(&format!("https://{host}:{}", env.https_port)).expect("back to the tunnel").to_string();
    let done = env.tunnel_get(host, &callback, &state, true).await;
    assert_eq!((done.status, done.location.as_deref()), (StatusCode::SEE_OTHER, Some(path)), "{}", done.body);
    // The code works once.
    assert_eq!(env.tunnel_get(host, &callback, &state, true).await.status, StatusCode::UNAUTHORIZED);
    Ok(done.cookie("__Host-mp_tunnel").expect("tunnel cookie"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_tunnels() {
    let env = Env::new(Tls::DevCa).await;
    let admin = env.admin_token();
    for t in ["team:dev", "team:ops"] {
        env.api_json("POST", "/api/v1/tags", Some(&admin), serde_json::json!({ "name": t })).await;
    }
    let mut ids = std::collections::HashMap::new();
    for (email, tags) in [("ann@example.com", vec!["team:dev"]), ("bob@example.com", vec![]), ("cy@example.com", vec!["team:ops"])] {
        let body = serde_json::json!({ "email": email, "password": "correct horse battery" });
        let (_, v) = env.api_json("POST", "/api/v1/users", Some(&admin), body).await;
        let id = v["user"]["id"].as_str().unwrap().to_string();
        env.api_json("PATCH", &format!("/api/v1/users/{id}"), Some(&admin), serde_json::json!({ "tags": tags })).await;
        ids.insert(email, id);
    }
    let (ann, bob, cy) = (
        sign_in(&env, "ann@example.com", "correct horse battery").await,
        sign_in(&env, "bob@example.com", "correct horse battery").await,
        sign_in(&env, "cy@example.com", "correct horse battery").await,
    );

    // Ann's machine, enrolled by an administrator with her tag; private only.
    let body = serde_json::json!({ "owner_user_id": ids["ann@example.com"], "tags": ["team:dev"], "allow_public": false });
    let (_, v) = env.api_json("POST", "/api/v1/enrollments", Some(&admin), body).await;
    let (url, ca) = (env.server_url(), env.ca_path.to_string_lossy().to_string());
    env.cli_ok(&["login", "--server", &url, "--token", v["enrollment_token"].as_str().unwrap(), "--ca-cert", &ca, "--name", "anns-laptop"]).await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let port = app.port.to_string();
    let out = env.cli(&["add", &port, "--public", "--json", "--timeout", "30"]).await;
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!((out.status.code(), v["error"]["code"].as_str()), (Some(6), Some("public_not_allowed")), "{v}");
    let out = env.cli(&["add", &port, "--access", "team:ops", "--json", "--timeout", "30"]).await;
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "forbidden", "the machine doesn't hold team:ops: {v}");
    let t = add_json(&env, &[&port, "--name", "wiki", "--label", "env:test"]).await;
    assert_eq!(t["status"], "ready", "private tunnels are verified through the server: {t}");
    assert_eq!((t["visibility"].as_str(), t["access"].clone()), (Some("private"), serde_json::json!([])), "{t}");
    let host = hostname(t["public_url"].as_str().unwrap());
    let list = env.cli_json(&["list", "--json"]).await;
    assert_eq!(list["tunnels"][0]["visibility"], "private", "{list}");

    // Not signed in: browsers are sent to sign in; everything else gets a 401.
    let api = env.tunnel_get(&host, "/whoami", "", false).await;
    assert_eq!((api.status, api.error.as_deref()), (StatusCode::UNAUTHORIZED, Some("unauthenticated")));
    assert!(!api.body.contains("user="), "the app never saw it");

    // Ann (owner) gets in; the app learns who she is but never sees the tunnel cookie.
    let ann_cookie = open_private(&env, &host, "/whoami", &ann).await.unwrap();
    let r = env.tunnel_get(&host, "/whoami", &format!("{ann_cookie}; theirs=1"), false).await;
    assert_eq!(r.status, 200);
    assert!(r.body.starts_with(&format!("user=ann@example.com id={}", ids["ann@example.com"])), "{}", r.body);
    assert!(r.body.ends_with("cookie=theirs=1"), "{}", r.body);
    let forged = env.tunnel_get(&host, "/whoami", "", false).await;
    assert_eq!(forged.status, StatusCode::UNAUTHORIZED);
    // A cookie for one tunnel host is useless on another.
    let other = add_json(&env, &[&port, "--name", "other"]).await;
    let other_host = hostname(other["public_url"].as_str().unwrap());
    assert_eq!(env.tunnel_get(&other_host, "/whoami", &ann_cookie, false).await.status, StatusCode::UNAUTHORIZED);

    // Bob has no shared tag: the management host says so. Cy has team:ops, not team:dev.
    let refused = open_private(&env, &host, "/", &bob).await.unwrap_err();
    assert!(refused.status == StatusCode::FORBIDDEN && refused.html.contains("bob@example.com"), "{}", refused.html);
    assert!(open_private(&env, &host, "/", &cy).await.is_err());
    let (_, v) = env.api("GET", "/api/v1/shared", Some(&admin)).await;
    assert!(v["tunnels"].as_array().unwrap().is_empty(), "administrators don't discover private tunnels through their role");

    // An administrator gives Cy team:dev: she gets in, without restarts, and sees it shared.
    env.api_json("PATCH", &format!("/api/v1/users/{}", ids["cy@example.com"]), Some(&admin), serde_json::json!({ "tags": ["team:dev"] })).await;
    let cy_cookie = open_private(&env, &host, "/", &cy).await.unwrap();
    assert_eq!(env.tunnel_get(&host, "/", &cy_cookie, false).await.status, 200);
    let shared = env.ui("/", Some(&cy), None).await;
    assert!(shared.html.contains("Shared with you") && shared.html.contains(&host), "{}", shared.html);

    // A WebSocket to a private tunnel, opened with the tunnel cookie.
    let ws = common::ws_echo_app().await;
    let live = add_json(&env, &[&ws.port.to_string(), "--name", "live"]).await;
    let live_host = hostname(live["public_url"].as_str().unwrap());
    let cy_live = open_private(&env, &live_host, "/", &cy).await.unwrap();
    let mut req = format!("wss://{live_host}/").into_client_request().unwrap();
    req.headers_mut().insert(header::COOKIE, cy_live.parse().unwrap());
    let (mut sock, _) = tokio_tungstenite::client_async(req, env.connect(&live_host, env.https_port).await).await.expect("websocket handshake");
    sock.send(Message::text("ping")).await.unwrap();
    assert_eq!(sock.next().await.unwrap().unwrap(), Message::text("ping"));

    // Taking the tag away ends her access on the very next request, and closes the WebSocket.
    env.api_json("PATCH", &format!("/api/v1/users/{}", ids["cy@example.com"]), Some(&admin), serde_json::json!({ "tags": [] })).await;
    let r = env.tunnel_get(&host, "/", &cy_cookie, false).await;
    assert_eq!((r.status, r.error.as_deref()), (StatusCode::FORBIDDEN, Some("forbidden")));
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match sock.next().await {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                Some(Ok(_)) => {}
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "the WebSocket stayed open after access was revoked");

    // "Sign out everywhere" ends Ann's tunnel cookies too (issued before it, at second precision).
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let account = env.ui("/account", Some(&ann), None).await;
    env.ui("/account/logout-everywhere", Some(&ann), Some(&[("csrf", &account.csrf())])).await;
    assert_eq!(env.tunnel_get(&host, "/whoami", &ann_cookie, false).await.status, StatusCode::UNAUTHORIZED);

    env.cli_ok(&["agent", "stop"]).await;
}

/// Real ACME issuance against Pebble (https://github.com/letsencrypt/pebble), including real
/// HTTP-01 validation of magicpipesd's challenge responder. Not run by default.
///
/// ```text
/// docker network create mp-acme
/// # Test DNS server answering every name with the Docker host's address:
/// docker run -d --name mp-cts --network mp-acme ghcr.io/letsencrypt/pebble-challtestsrv \
///   -defaultIPv4 "$(docker run --rm alpine getent hosts host.docker.internal | cut -d' ' -f1)" -defaultIPv6 ""
/// docker run -d --name mp-pebble --network mp-acme -e PEBBLE_VA_NOSLEEP=1 \
///   -p 14000:14000 -p 15000:15000 ghcr.io/letsencrypt/pebble -dnsserver mp-cts:8053
/// curl -sk https://localhost:15000/roots/0 > /tmp/pebble-issuer.pem
/// curl -s https://raw.githubusercontent.com/letsencrypt/pebble/main/test/certs/pebble.minica.pem > /tmp/pebble-api.pem
/// MAGICPIPES_PEBBLE_HTTP_PORT=5002 MAGICPIPES_PEBBLE_DIRECTORY=https://localhost:14000/dir \
/// MAGICPIPES_PEBBLE_API_CA=/tmp/pebble-api.pem MAGICPIPES_PEBBLE_ISSUER_ROOT=/tmp/pebble-issuer.pem \
///   cargo test -p magicpipes-cli --test e2e acme_with_pebble -- --ignored
/// ```
///
/// Pebble validates HTTP-01 on port 5002, so the test's HTTP listener is pinned there
/// (`MAGICPIPES_PEBBLE_HTTP_PORT`). To skip validation instead, start Pebble with
/// `-e PEBBLE_VA_ALWAYS_VALID=1` and omit the DNS server and the port variable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Pebble ACME server"]
async fn acme_with_pebble() {
    let mut env = Env::new(Tls::Pebble).await;
    env.login().await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let t = add_json(&env, &[&app.port.to_string(), "--name", "acme-test", "--timeout", "90"]).await;
    assert_eq!(t["status"], "ready");
    let (status, err, body) = env.get_public(&format!("acme-test.{BASE}"), "/").await;
    assert_eq!((status, err, body.as_str()), (StatusCode::OK, None, "hello from app"));
    assert!(env.root.join(format!("server/certs/acme-test.{BASE}.crt")).exists(), "certificate cached");
    // The cached certificate is reused after a restart (no new order).
    env.stop_server().await;
    env.start_server().await;
    env.eventually("tunnel back after restart", Duration::from_secs(30), || async {
        env.get_public(&format!("acme-test.{BASE}"), "/").await.0 == StatusCode::OK
    })
    .await;
    assert_eq!(env.server_log().matches("obtaining certificate host=acme-test").count(), 1, "no reissue on restart");
    env.cli_ok(&["agent", "stop"]).await;
}
