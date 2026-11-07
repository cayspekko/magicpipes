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

fn magicpipes_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
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
    assert!(stdout.contains("Tunnel ready") && stdout.contains("  URL:    https://") && !stdout.contains("Status:"), "{stdout}");
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

    // Requests share pooled connections to the app instead of opening one each, whichever
    // public connection they arrive on.
    let mut conns = std::collections::HashSet::new();
    for _ in 0..10 {
        let (status, _, body) = env.get_public(&host1, "/conn").await;
        assert_eq!(status, 200, "{body}");
        conns.insert(body);
    }
    assert!(conns.len() <= 2, "ten requests opened {} connections to the app", conns.len());
    // Concurrent requests each get a connection, and every one of them is answered.
    let answers = futures_util::future::join_all((0..20).map(|_| env.get_public(&host1, "/conn"))).await;
    assert!(answers.iter().all(|(s, _, _)| *s == 200), "{answers:?}");

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
    // The same fields as when the agent runs, from tunnels.json.
    let stopped = &list["tunnels"][0];
    assert_eq!((stopped["status"].as_str(), stopped["share_url"].as_str()), (Some("stopped"), stopped["public_url"].as_str()), "{stopped}");
    assert!(stopped.get("visibility").is_some() && stopped["tags"].is_array(), "{stopped}");

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
    // A new port says who may connect: it isn't opened to the internet by default.
    let out = env.cli(&["add", &echo.port.to_string(), "--tcp", "--name", "echo", "--json"]).await;
    assert_eq!(out.status.code(), Some(1), "{}", String::from_utf8_lossy(&out.stdout));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "invalid_request");
    assert!(v["error"]["message"].as_str().unwrap().contains("--allow-any"), "{v}");
    assert_eq!(env.cli(&["add", "8080", "--allow-any"]).await.status.code(), Some(2), "only for raw ports");

    let out = env.cli_ok(&["add", &echo.port.to_string(), "--tcp", "--allow-any", "--name", "echo"]).await;
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
    let t2 = add_json(&env, &[&echo2.port.to_string(), "--tcp", "--allow-any", "--remote-port", &wanted.to_string()]).await;
    assert_eq!(t2["public_port"].as_u64(), Some(wanted as u64));
    assert_eq!(tcp_roundtrip(wanted, b"second").await, b"second");
    let echo3 = common::tcp_echo_app().await;
    let out = env.cli(&["add", &echo3.port.to_string(), "--tcp", "--allow-any", "--json", "--remote-port", &wanted.to_string()]).await;
    assert_eq!(out.status.code(), Some(6), "{}", String::from_utf8_lossy(&out.stdout));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "port_unavailable");
    let out = env.cli(&["add", &echo3.port.to_string(), "--tcp", "--allow-any", "--json", "--remote-port", "80"]).await;
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "port_unavailable", "outside the range: {v}");

    // --- --allow-cidr ---------------------------------------------------------------------------
    // A new list replaces the old one; 127.0.0.1 is not in 10.0.0.0/8, so even this machine's
    // own check of the public port is refused (a warning, not a failure).
    let t = add_json(&env, &[&echo.port.to_string(), "--tcp", "--allow-cidr", "10.0.0.0/8"]).await;
    assert_eq!((t["public_port"].as_u64(), t["reachable"].as_bool()), (Some(port as u64), Some(false)));
    assert_eq!(t["allow"], serde_json::json!(["10.0.0.0/8"]));
    assert!(tcp_roundtrip(port, b"blocked").await.is_empty(), "client outside the allow-list");
    let t = add_json(&env, &[&echo.port.to_string(), "--tcp", "--allow-cidr", "10.0.0.0/8", "--allow-cidr", "127.0.0.1"]).await;
    assert_eq!(t["reachable"], true);
    assert_eq!(tcp_roundtrip(port, b"allowed").await, b"allowed");
    // Narrowing the allow-list closes a connection already open from a network it now excludes.
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut open = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        open.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        open.read_exact(&mut got).await.unwrap();
        add_json(&env, &[&echo.port.to_string(), "--tcp", "--allow-cidr", "10.0.0.0/8"]).await;
        let read = tokio::time::timeout(Duration::from_secs(5), open.read(&mut got)).await;
        assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))), "the open connection was closed: {read:?}");
    }
    // Running the command again without the flag doesn't open it up; saying so does.
    let t = add_json(&env, &[&echo.port.to_string(), "--tcp"]).await;
    assert_eq!(t["allow"], serde_json::json!(["10.0.0.0/8"]), "re-adding keeps the list");
    assert!(tcp_roundtrip(port, b"blocked").await.is_empty());
    let t = add_json(&env, &[&echo.port.to_string(), "--tcp", "--allow-any"]).await;
    assert_eq!(t["allow"], serde_json::json!([]));

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
    let out = env.cli_ok(&["add", &dns.port.to_string(), "--udp", "--allow-any", "--name", "dns"]).await;
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
    // One client address gets a share of the tunnel's flows (16 of the default 128).
    let mut more = Vec::new();
    for i in 0..14 {
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert_eq!(udp_roundtrip(&s, uport, format!("f{i}").as_bytes()).await, format!("echo:f{i}").into_bytes());
        more.push(s);
    }
    let extra = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    extra.send_to(b"seventeenth", ("127.0.0.1", uport)).await.unwrap();
    let mut buf = [0u8; 64];
    assert!(tokio::time::timeout(Duration::from_millis(1500), extra.recv_from(&mut buf)).await.is_err(), "over the per-client share");
    drop(more);
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
async fn custom_hostnames() {
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    let admin = env.admin_token();
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let port = app.port.to_string();
    // The development CA issues only under the base domain, so the custom names live there.
    let (shop, soon) = (format!("shop.app.{BASE}"), format!("soon.app.{BASE}"));

    // Not assigned to this machine yet: refused, and nothing is created.
    let out = env.cli(&["add", &port, "--hostname", &shop, "--json"]).await;
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "not_found", "{v}");

    // An administrator registers it for this (service) agent; only then can it serve it.
    let (_, v) = env.api("GET", "/api/v1/agents", Some(&admin)).await;
    let agent = v["agents"][0]["id"].as_str().unwrap().to_string();
    for h in [&shop, &soon] {
        let (s, v) = env.api_json("POST", "/api/v1/hostnames", Some(&admin), serde_json::json!({ "hostname": h, "agent_id": agent })).await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
    }
    let (s, v) = env.api_json("POST", "/api/v1/hostnames", Some(&admin), serde_json::json!({ "hostname": format!("app.{BASE}"), "agent_id": agent })).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid_request")), "a tunnel name: {v}");
    let t = add_json(&env, &[&port, "--hostname", &shop]).await;
    assert_eq!((t["status"].as_str(), t["public_url"].as_str(), t["name"].as_str()), (Some("ready"), Some(format!("https://{shop}:{}", env.https_port).as_str()), Some("shop")), "{t}");
    assert_eq!(env.get_public(&shop, "/").await.2, "hello from app");
    assert_eq!(add_json(&env, &[&port, "--hostname", &shop]).await["created"], false, "adding it again finds it");
    let (_, v) = env.api("GET", "/api/v1/hostnames", Some(&admin)).await;
    let listed = v["hostnames"].as_array().unwrap().iter().find(|h| h["hostname"] == shop.as_str()).unwrap().clone();
    assert_eq!((listed["tunnel"].as_str(), listed["tls"].as_str()), (Some("shop"), Some("ready")), "{listed}");

    // --no-verify registers without the certificate wait and the public check.
    let other = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let out = env.cli(&["add", &other.port.to_string(), "--hostname", &soon, "--no-verify"]).await;
    let (stdout, stderr) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success() && stderr.contains("skipped") && stdout.contains("Not verified (--no-verify)"), "{stdout}{stderr}");
    assert_eq!(env.get_public(&soon, "/").await.0, StatusCode::OK);

    // The UI lists them; removing a registration deletes its tunnel.
    let body = serde_json::json!({ "email": "ad@example.com", "password": "correct horse battery", "role": "admin" });
    env.api_json("POST", "/api/v1/users", Some(&admin), body).await;
    let cookie = sign_in(&env, "ad@example.com", "correct horse battery").await;
    let page = env.ui("/hostnames", Some(&cookie), None).await;
    assert!(page.status == 200 && page.html.contains(&shop) && page.html.contains(r#"value="agent:"#), "{}", page.html);
    let (s, _) = env.api("DELETE", &format!("/api/v1/hostnames/{soon}"), Some(&admin)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (status, err, _) = env.get_public(&soon, "/").await;
    assert_eq!((status, err.as_deref()), (StatusCode::NOT_FOUND, Some("tunnel_not_found")));
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

    // A tunnel kept anyway: the list, which only mentions certificates in trouble, says so.
    env.cli_ok(&["add", &app.port.to_string(), "--no-verify", "--name", "kept"]).await;
    let admin = admin_session(&env).await;
    env.eventually("the list shows the failed certificate", Duration::from_secs(30), || async {
        let home = env.ui("/", Some(&admin), None).await.html;
        home.contains(">certificate failed</span>") && home.contains(r##"<a href="#tunnels">1 certificate failed</a>"##)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authentication_and_input_failures() {
    let env = Env::new(Tls::DevCa).await;
    let url = env.server_url();
    let ca = env.ca_path.to_string_lossy().to_string();

    // Browser icons are there before signing in, and every page links them.
    let login = env.ui("/login", None, None).await;
    assert!(login.html.contains(r#"<link rel="icon" href="/favicon.svg" type="image/svg+xml">"#), "{}", login.html);
    for path in ["/favicon.svg", "/favicon.ico", "/apple-touch-icon.png"] {
        assert_eq!(env.ui(path, None, None).await.status, StatusCode::OK, "{path}");
    }
    assert!(env.ui("/favicon.svg", None, None).await.html.starts_with("<svg"));

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
    let machines = env.ui("/machines", Some(&cookie2), None).await;
    assert!(machines.status == 200 && !machines.html.contains("Create enrollment token"), "members see their machines, not the administration");
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

    // After repeated failures, password logins are refused, right password or not: from this
    // address before the password is even checked (the per-account limit has a unit test).
    let (_, v) = env
        .api_json("POST", "/api/v1/users", Some(&admin), serde_json::json!({ "email": "bo@example.com", "password": new_password, "role": "admin" }))
        .await;
    assert!(v.get("password").is_none(), "no generated password when one was given");
    for _ in 0..10 {
        login("bo@example.com", "guess guess guess".into()).await;
    }
    let throttled = login("bo@example.com", new_password.into()).await;
    assert_eq!(throttled.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(throttled.html.contains("Too many failed attempts"), "{}", throttled.html);
    let (s, _) = env.api("GET", "/api/v1/status", Some(&admin)).await;
    assert_eq!(s, StatusCode::OK, "a valid admin token still works from a blocked address");

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
    // The sign-in page keeps the destination in its form and in the link to the other form.
    let login_page = env.ui(page.location.as_deref().unwrap(), None, None).await;
    assert!(login_page.html.contains(r#"name="next""#) && login_page.html.contains("method=token&amp;next=%2Fcli"), "{}", login_page.html);
    let signed_in = env.ui("/login", None, Some(&[("email", "ann@example.com"), ("password", password), ("next", &link)])).await;
    assert!(signed_in.location.as_deref().is_some_and(|l| l.starts_with("/password?next=")), "{:?}", signed_in.location);
    let cookie = signed_in.cookie.unwrap();
    let form = env.ui("/password", Some(&cookie), None).await;
    let new_password = "another horse battery staple";
    let changed = env
        .ui("/password", Some(&cookie), Some(&[("csrf", &form.csrf()), ("current", password), ("new", new_password), ("repeat", new_password), ("next", &link)]))
        .await;
    // A form's redirects must stay on the management host (CSP form-action), so the destination
    // comes from a page that moves on by itself.
    assert!(changed.status == 200 && changed.location.is_none() && changed.html.contains("Continuing"), "{}", changed.html);
    assert!(changed.html.contains(&link.replace('&', "&amp;")), "{}", changed.html);
    let cookie = changed.cookie.unwrap();
    // An outside `next` is ignored.
    let elsewhere = env.ui("/login", None, Some(&[("email", "ann@example.com"), ("password", new_password), ("next", "//evil.example/")])).await;
    assert_eq!(elsewhere.location.as_deref(), Some("/"));

    let approval = env.ui(&link, Some(&cookie), None).await;
    assert!(approval.status == 200 && approval.html.contains("laptop") && approval.html.contains("--tag"), "{}", approval.html);
    let code = link.split("code=").nth(1).unwrap().to_string();
    let done = env.ui("/cli", Some(&cookie), Some(&[("csrf", &approval.csrf()), ("code", &code), ("answer", "approve")])).await;
    assert!(done.html.contains("Approved"), "{}", done.html);
    let out = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output()).await.unwrap().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    assert!(env.ui(&link, Some(&cookie), None).await.status == StatusCode::NOT_FOUND, "a code works once");

    // The machine belongs to Ann and publishes with her tags; its tunnels default to private.
    let (_, v) = env.api("GET", "/api/v1/agents", Some(&admin)).await;
    let laptop = v["agents"].as_array().unwrap().iter().find(|a| a["name"] == "laptop").unwrap().clone();
    assert_eq!(laptop["owner_email"], "ann@example.com");
    let personal = env.api("GET", &format!("/api/v1/users/{ann}"), Some(&admin)).await.1["personal_tag"].as_str().unwrap().to_string();
    assert_eq!(laptop["tags"], serde_json::json!(["team:dev", personal]));
    assert_eq!(laptop["default_private"], true);
    let mine = env.ui("/machines", Some(&cookie), None).await;
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
#[tokio::test]
async fn tag_forms_apply_only_what_changed() {
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    let admin = env.admin_token();
    for (name, description) in [("team:dev", "Engineering"), ("team:ops", "</script><b>ops</b>"), ("env:prod", "")] {
        env.api_json("POST", "/api/v1/tags", Some(&admin), serde_json::json!({ "name": name, "description": description })).await;
    }
    let mut ids = Vec::new();
    for (email, role) in [("ad@example.com", "admin"), ("ann@example.com", "member")] {
        let body = serde_json::json!({ "email": email, "password": "correct horse battery", "role": role });
        ids.push(env.api_json("POST", "/api/v1/users", Some(&admin), body).await.1["user"]["id"].as_str().unwrap().to_string());
    }
    let ann = &ids[1];
    let tags_of = |id: String| {
        let env = &env;
        let admin = admin.clone();
        async move { env.api("GET", &format!("/api/v1/users/{id}"), Some(&admin)).await.1["tags"].clone() }
    };
    env.api_json("PATCH", &format!("/api/v1/users/{ann}"), Some(&admin), serde_json::json!({ "tags": ["team:dev"] })).await;
    let personal_of = |id: String| {
        let env = &env;
        let admin = admin.clone();
        async move { env.api("GET", &format!("/api/v1/users/{id}"), Some(&admin)).await.1["personal_tag"].as_str().unwrap().to_string() }
    };
    let (ann_tag, ad_tag) = (personal_of(ann.clone()).await, personal_of(ids[0].clone()).await);
    let cookie = sign_in(&env, "ad@example.com", "correct horse battery").await;

    // The users page carries the registry for the picker, with descriptions unable to end it.
    let users = env.ui("/users", Some(&cookie), None).await;
    assert!(users.html.contains(r#"id="mp-tags""#) && users.html.contains(&format!(r#"href="/users/{ann}/tags" aria-label="Edit tags of ann@example.com" data-tag-edit"#)), "{}", users.html);
    assert!(users.html.contains(r#"\u003c/script>\u003cb>ops"#) && !users.html.contains("</script><b>"), "{}", users.html);
    assert!(users.html.contains(&format!("<code>{ann_tag}</code>")) && !users.html.contains(r#""n":"user:"#), "personal tags are shown, never offered: {}", users.html);
    // The row's other actions are in a menu; the irreversible ones ask first.
    assert!(users.html.contains(r#"aria-label="More actions for ann@example.com""#), "{}", users.html);
    assert!(users.html.contains(r#"data-confirm="Disable ann@example.com?"#), "{}", users.html);
    // Without scripts the Edit link opens a page of checkboxes.
    let page = env.ui(&format!("/users/{ann}/tags"), Some(&cookie), None).await;
    assert!(page.html.contains(r#"value="team:dev" checked"#) && page.html.contains(r#"name="base" value="team:dev""#), "{}", page.html);

    // Another administrator adds a tag after the page was shown: saving keeps it.
    env.api_json("PATCH", &format!("/api/v1/users/{ann}"), Some(&admin), serde_json::json!({ "tags": ["env:prod", "team:dev"] })).await;
    let csrf = users.csrf();
    let saved = env.ui(&format!("/users/{ann}/tags"), Some(&cookie), Some(&[("csrf", &csrf), ("base", "team:dev"), ("tags", "team:dev team:ops")])).await;
    assert_eq!(saved.location.as_deref(), Some("/users?done=tags-saved"));
    assert_eq!(tags_of(ann.clone()).await, serde_json::json!(["env:prod", "team:dev", "team:ops"]));
    // Checkboxes from the page: everything unchecked but one.
    env.ui(&format!("/users/{ann}/tags"), Some(&cookie), Some(&[("csrf", &csrf), ("base", "env:prod team:dev team:ops"), ("tag", "team:ops")])).await;
    assert_eq!(tags_of(ann.clone()).await, serde_json::json!(["team:ops"]));
    let refused = env.ui(&format!("/users/{ann}/tags"), Some(&cookie), Some(&[("csrf", &csrf), ("base", ""), ("tags", "team:qa")])).await;
    assert!(refused.status == StatusCode::BAD_REQUEST && refused.html.contains("is not a tag"), "{}", refused.html);
    let personal = env.ui(&format!("/users/{ann}/tags"), Some(&cookie), Some(&[("csrf", &csrf), ("base", ""), ("tags", &ad_tag)])).await;
    assert!(personal.status == StatusCode::BAD_REQUEST && personal.html.contains("personal tag"), "{}", personal.html);
    let forged = env.ui(&format!("/users/{ann}/tags"), Some(&cookie), Some(&[("csrf", "wrong"), ("base", ""), ("tags", "env:prod")])).await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    // The picker can make up a tag: it's created on save, then given.
    let made = env
        .ui(&format!("/users/{ann}/tags"), Some(&cookie), Some(&[("csrf", &csrf), ("base", "team:ops"), ("tags", "team:ops team:qa"), ("create", "team:qa")]))
        .await;
    assert_eq!(made.location.as_deref(), Some("/users?done=tags-saved"), "{}", made.html);
    assert_eq!(tags_of(ann.clone()).await, serde_json::json!(["team:ops", "team:qa"]));
    let (_, v) = env.api("GET", "/api/v1/tags", Some(&admin)).await;
    assert!(v["tags"].as_array().unwrap().iter().any(|t| t["name"] == "team:qa"));
    // Creating one that exists by now is fine.
    env.ui(&format!("/users/{ann}/tags"), Some(&cookie), Some(&[("csrf", &csrf), ("base", "team:ops team:qa"), ("tags", "team:qa"), ("create", "team:qa")])).await;
    assert_eq!(tags_of(ann.clone()).await, serde_json::json!(["team:qa"]));

    // Agents work the same way.
    let (_, v) = env.api("GET", "/api/v1/agents", Some(&admin)).await;
    let agent = v["agents"][0]["id"].as_str().unwrap().to_string();
    let machines = env.ui("/machines", Some(&cookie), None).await;
    assert!(machines.html.contains(&format!(r#"href="/agents/{agent}/tags" aria-label="Edit tags of"#)), "{}", machines.html);
    env.ui(&format!("/agents/{agent}/tags"), Some(&cookie), Some(&[("csrf", &csrf), ("base", ""), ("tags", "team:dev env:prod")])).await;
    env.ui(&format!("/agents/{agent}/tags"), Some(&cookie), Some(&[("csrf", &csrf), ("base", "env:prod team:dev"), ("tags", "team:dev")])).await;
    let (_, v) = env.api("GET", "/api/v1/agents", Some(&admin)).await;
    assert_eq!(v["agents"][0]["tags"], serde_json::json!(["team:dev"]));
    let page = env.ui(&format!("/agents/{agent}/tags"), Some(&cookie), None).await;
    assert!(page.html.contains(r#"value="team:dev" checked"#) && page.html.contains(r#"value="team:ops">"#), "{}", page.html);

    // Enrollment tokens take checkboxes too.
    assert!(machines.html.contains(r#"fieldset class="tags" data-picker"#), "{}", machines.html);
    let made = env.ui("/enrollments", Some(&cookie), Some(&[("csrf", &csrf), ("owner", ""), ("tag", "team:ops"), ("allow_public", "on")])).await;
    assert!(made.status == StatusCode::OK && made.html.contains("--token"), "{}", made.html);
    let bad = env.ui("/enrollments", Some(&cookie), Some(&[("csrf", &csrf), ("owner", ""), ("tag", "team:nope")])).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    let made = env.ui("/enrollments", Some(&cookie), Some(&[("csrf", &csrf), ("owner", ""), ("tag", "env:new"), ("create", "env:new")])).await;
    assert!(made.status == StatusCode::OK && made.html.contains("--token"), "{}", made.html);
    let personal = env.ui("/enrollments", Some(&cookie), Some(&[("csrf", &csrf), ("owner", ann.as_str()), ("tag", "team:dev")])).await;
    assert_eq!(personal.status, StatusCode::BAD_REQUEST, "a personal machine has no tags of its own");

    // Whether a tag grants access is its own setting, on the Tags page and in the API.
    let tags_page = env.ui("/tags", Some(&cookie), None).await;
    assert!(tags_page.html.contains("grants access") && !tags_page.html.contains(&ann_tag) && !tags_page.html.contains(&ad_tag), "{}", tags_page.html);
    env.ui("/tags/access", Some(&cookie), Some(&[("csrf", &csrf), ("name", "env:prod"), ("access", "off")])).await;
    let access_of = |v: &Value, name: &str| v["tags"].as_array().unwrap().iter().find(|t| t["name"] == name).map(|t| t["access"].clone());
    assert_eq!(access_of(&env.api("GET", "/api/v1/tags", Some(&admin)).await.1, "env:prod"), Some(Value::Bool(false)));
    let (s, v) = env.api_json("PATCH", "/api/v1/tags/env:prod", Some(&admin), serde_json::json!({ "access": true })).await;
    assert_eq!((s, v["access"].clone()), (StatusCode::OK, Value::Bool(true)));
    let (s, _) = env.api_json("PATCH", &format!("/api/v1/tags/{ann_tag}"), Some(&admin), serde_json::json!({ "access": false })).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "personal tags can't be changed");
    let (s, v) = env.api_json("POST", "/api/v1/tags", Some(&admin), serde_json::json!({ "name": "user:mallory" })).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid_request")));
}

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
    let state = first.cookie_prefixed("__Host-mp_state_").expect("state cookie");
    let mgmt = format!("https://localhost:{}", env.mgmt_port);
    let at = first.location.unwrap().strip_prefix(&mgmt).expect("sent to the management host").to_string();
    let auth = env.ui(&at, Some(ui_cookie), None).await;
    let Some(callback) = auth.location.clone().filter(|_| auth.status == StatusCode::SEE_OTHER) else { return Err(auth) };
    // The code travels in the fragment, which no server sees; the callback page posts it back.
    let (page, fragment) = callback.split_once('#').expect("code in the fragment");
    assert_eq!(page, format!("https://{host}:{}/.magicpipes/callback", env.https_port));
    let callback_page = env.tunnel_get(host, "/.magicpipes/callback", "", true).await;
    assert!(callback_page.status == 200 && callback_page.body.contains("/.magicpipes/callback.js"), "{}", callback_page.body);
    assert_eq!(env.tunnel_get(host, "/.magicpipes/callback.js", "", false).await.status, 200);
    // Without the state cookie of the attempt (another browser), the code is refused.
    assert_eq!(env.tunnel_post(host, "/.magicpipes/callback", "", fragment).await.status, StatusCode::UNAUTHORIZED);
    let done = env.tunnel_post(host, "/.magicpipes/callback", &state, fragment).await;
    assert_eq!(done.status, 200, "{}", done.body);
    let to: Value = serde_json::from_str(&done.body).unwrap();
    assert_eq!(to["to"], path);
    // The code works once.
    assert_eq!(env.tunnel_post(host, "/.magicpipes/callback", &state, fragment).await.status, StatusCode::UNAUTHORIZED);
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

    // Ann's machine, enrolled by an administrator; it publishes with her tags, private only.
    let body = serde_json::json!({ "owner_user_id": ids["ann@example.com"], "allow_public": false });
    let (_, v) = env.api_json("POST", "/api/v1/enrollments", Some(&admin), body).await;
    let (url, ca) = (env.server_url(), env.ca_path.to_string_lossy().to_string());
    env.cli_ok(&["login", "--server", &url, "--token", v["enrollment_token"].as_str().unwrap(), "--ca-cert", &ca, "--name", "anns-laptop"]).await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let port = app.port.to_string();
    let out = env.cli(&["add", &port, "--public", "--json", "--timeout", "30"]).await;
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!((out.status.code(), v["error"]["code"].as_str()), (Some(6), Some("public_not_allowed")), "{v}");
    let out = env.cli(&["add", &port, "--tag", "team:ops", "--json", "--timeout", "30"]).await;
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "forbidden", "Ann doesn't hold team:ops: {v}");
    let t = add_json(&env, &[&port, "--name", "wiki", "--tag", "team:dev"]).await;
    assert_eq!(t["status"], "ready", "private tunnels are verified through the server: {t}");
    let personal = |email: &str| {
        let (env, admin, id) = (&env, admin.clone(), ids[email].clone());
        async move { env.api("GET", &format!("/api/v1/users/{id}"), Some(&admin)).await.1["personal_tag"].as_str().unwrap().to_string() }
    };
    let (ann_tag, bob_tag) = (personal("ann@example.com").await, personal("bob@example.com").await);
    assert_eq!((t["visibility"].as_str(), t["tags"].clone(), t["owner_tag"].as_str()), (Some("private"), serde_json::json!(["team:dev", ann_tag]), Some(ann_tag.as_str())), "{t}");
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
    // Two tabs signing in at once each keep their own attempt: both finish.
    let mgmt = format!("https://localhost:{}", env.mgmt_port);
    let mut attempts = Vec::new();
    for _ in 0..2 {
        let r = env.tunnel_get(&host, "/whoami", "", true).await;
        let at = r.location.clone().unwrap().strip_prefix(&mgmt).unwrap().to_string();
        attempts.push((r.cookie_prefixed("__Host-mp_state_").unwrap(), at));
    }
    let jar = format!("{}; {}", attempts[0].0, attempts[1].0);
    for (_, at) in attempts.iter().rev() {
        let auth = env.ui(at, Some(&ann), None).await;
        let fragment = auth.location.unwrap().split_once('#').unwrap().1.to_string();
        assert_eq!(env.tunnel_post(&host, "/.magicpipes/callback", &jar, &fragment).await.status, 200);
    }
    // A cookie for one tunnel host is useless on another.
    let other = add_json(&env, &[&port, "--name", "other"]).await;
    assert_eq!(other["tags"], serde_json::json!([ann_tag]), "without --tag, only its owner: {other}");
    let other_host = hostname(other["public_url"].as_str().unwrap());
    assert_eq!(env.tunnel_get(&other_host, "/whoami", &ann_cookie, false).await.status, StatusCode::UNAUTHORIZED);
    assert!(open_private(&env, &other_host, "/", &ann).await.is_ok(), "the owner gets in through her personal tag");

    // Bob has no shared tag: the management host says so. Cy has team:ops, not team:dev.
    let refused = open_private(&env, &host, "/", &bob).await.unwrap_err();
    assert!(refused.status == StatusCode::FORBIDDEN && refused.html.contains("bob@example.com"), "{}", refused.html);
    assert!(open_private(&env, &host, "/", &cy).await.is_err());
    // Bob's personal tag on a tunnel shares it with him alone.
    let pair = add_json(&env, &[&port, "--name", "pair", "--tag", &bob_tag]).await;
    let pair_host = hostname(pair["public_url"].as_str().unwrap());
    assert!(open_private(&env, &pair_host, "/", &bob).await.is_ok() && open_private(&env, &pair_host, "/", &cy).await.is_err());
    let index = env.ui("/", Some(&ann), None).await;
    assert!(index.html.contains(&format!(r#"<code class="tag" title="{ann_tag}">you</code>"#)), "{}", index.html);
    // Icons go with the words, which are still there for anyone who can't see them.
    assert!(index.html.contains(r#"<span class="kind" title="Web app"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true">"#), "{}", index.html);
    assert!(index.html.contains(r#"<span class="status ok iconic"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true">"#) && index.html.contains("</svg>private</span>"), "{}", index.html);
    assert!(index.html.contains(r#"aria-label="More actions for"#) || !index.html.contains("details class=\"menu\""), "{}", index.html);
    let (_, v) = env.api("GET", "/api/v1/shared", Some(&admin)).await;
    assert!(v["tunnels"].as_array().unwrap().is_empty(), "administrators don't discover private tunnels through their role");

    // An administrator gives Cy team:dev: she gets in, without restarts, and sees it shared.
    env.api_json("PATCH", &format!("/api/v1/users/{}", ids["cy@example.com"]), Some(&admin), serde_json::json!({ "tags": ["team:dev"] })).await;
    let cy_cookie = open_private(&env, &host, "/", &cy).await.unwrap();
    assert_eq!(env.tunnel_get(&host, "/", &cy_cookie, false).await.status, 200);
    let shared = env.ui("/", Some(&cy), None).await;
    assert!(shared.html.contains("Shared with you") && shared.html.contains(&host), "{}", shared.html);
    assert!(open_private(&env, &other_host, "/", &cy).await.is_err(), "a tunnel with only Ann's personal tag stays hers");

    // A WebSocket to a private tunnel, opened with the tunnel cookie.
    let ws = common::ws_echo_app().await;
    let live = add_json(&env, &[&ws.port.to_string(), "--name", "live", "--tag", "team:dev"]).await;
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

/// Signing in to private tunnels in a real browser (headless Chrome via `scripts/browser-sign-in.mjs`):
/// plain HTTP clients don't apply CSP or cookie rules, and that is where sign-in flows break.
/// Not run by default; needs Chrome and Node 22 or newer:
///
/// ```text
/// cargo test -p magicpipes-cli --test e2e browser_signs_in_to_private_tunnels -- --ignored
/// ```
///
/// `MAGICPIPES_CHROME` overrides the Chrome binary.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Chrome and Node"]
async fn browser_signs_in_to_private_tunnels() {
    let chrome = std::env::var("MAGICPIPES_CHROME").unwrap_or_else(|_| {
        if cfg!(target_os = "macos") { "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into() } else { "google-chrome".into() }
    });
    let env = Env::new(Tls::DevCa).await;
    let admin = env.admin_token();
    let first_password = "correct horse battery";
    let body = serde_json::json!({ "email": "ann@example.com", "password": first_password });
    let (_, v) = env.api_json("POST", "/api/v1/users", Some(&admin), body).await;
    let ann = v["user"]["id"].as_str().unwrap().to_string();
    // She has already chosen her own password, like anyone signing in after their first time.
    sign_in(&env, "ann@example.com", first_password).await;
    let password = format!("{first_password} again");

    let body = serde_json::json!({ "owner_user_id": ann });
    let (_, v) = env.api_json("POST", "/api/v1/enrollments", Some(&admin), body).await;
    let (url, ca) = (env.server_url(), env.ca_path.to_string_lossy().to_string());
    env.cli_ok(&["login", "--server", &url, "--token", v["enrollment_token"].as_str().unwrap(), "--ca-cert", &ca, "--name", "laptop"]).await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let first = add_json(&env, &[&app.port.to_string(), "--private", "--name", "one"]).await;
    let second = add_json(&env, &[&app.port.to_string(), "--private", "--name", "two"]).await;

    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/browser-sign-in.mjs");
    let profile = std::env::temp_dir().join(format!("mp-chrome-{}", std::process::id()));
    let opts = serde_json::json!({
        "chrome": chrome,
        "first": format!("{}/", first["public_url"].as_str().unwrap()),
        "second": format!("{}/", second["public_url"].as_str().unwrap()),
        "management": url,
        "email": "ann@example.com",
        "password": password,
        "resolve": format!("MAP *.{BASE} 127.0.0.1"),
        "profile": profile,
    });
    let out = tokio::process::Command::new("node").arg(&script).arg(opts.to_string()).output().await.expect("run node");
    std::fs::remove_dir_all(&profile).ok();
    let result: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&out.stderr)));

    // Signing in on the way lands on the application, not back on the sign-in page.
    assert!(result["first"]["url"].as_str().unwrap_or("").starts_with(first["public_url"].as_str().unwrap()), "{result}");
    assert_eq!(result["first"]["text"], "hello from app", "{result}");
    // Already signed in: the second private tunnel needs no form.
    assert!(result["second"]["url"].as_str().unwrap_or("").starts_with(second["public_url"].as_str().unwrap()), "{result}");
    assert_eq!(result["second"]["text"], "hello from app", "{result}");
    assert!(result["errors"].as_array().unwrap().is_empty(), "the browser reported errors: {result}");
    env.cli_ok(&["agent", "stop"]).await;
}

/// A browser going to the fake provider and back: the sign-in link, the provider, the callback.
/// Returns the callback's answer.
async fn oidc_sign_in(env: &Env, next: Option<&str>) -> common::UiResponse {
    oidc_sign_in_at(env, "fake", next).await
}

async fn oidc_sign_in_at(env: &Env, provider: &str, next: Option<&str>) -> common::UiResponse {
    let at = next.map_or(format!("/auth/oidc/{provider}"), |n| format!("/auth/oidc/{provider}?next={n}"));
    let start = env.ui(&at, None, None).await;
    assert_eq!(start.status, StatusCode::SEE_OTHER, "{}", start.html);
    let attempt = start.cookie.clone().expect("attempt cookie");
    let callback = follow_to_callback(env, &start).await;
    env.ui(&callback, Some(&attempt), None).await
}

/// Follows the redirect to the provider, which answers at once; the path to come back to.
async fn follow_to_callback(env: &Env, start: &common::UiResponse) -> String {
    let at = start.location.clone().expect("sent to the provider");
    let (status, location) = plain_get(&at).await;
    assert_eq!(status, StatusCode::FOUND);
    location.strip_prefix(&format!("https://localhost:{}", env.mgmt_port)).expect("back to the management host").to_string()
}

/// A GET over plain HTTP to the fake provider; the status and the redirect's target.
async fn plain_get(url: &str) -> (StatusCode, String) {
    use http_body_util::BodyExt;
    let uri: http::Uri = url.parse().unwrap();
    let stream = tokio::net::TcpStream::connect((uri.host().unwrap(), uri.port_u16().unwrap())).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await.unwrap();
    tokio::spawn(conn);
    let req = http::Request::builder()
        .uri(uri.path_and_query().unwrap().as_str())
        .header(http::header::HOST, uri.authority().unwrap().as_str())
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let location = resp.headers().get(http::header::LOCATION).map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
    resp.into_body().collect().await.unwrap();
    (status, location)
}

fn session_of(resp: &common::UiResponse) -> String {
    let cookie = resp.cookie.clone().unwrap_or_else(|| panic!("signed in: {} {}", resp.status, resp.html));
    assert!(cookie.starts_with("__Host-mp_session="), "{cookie}");
    cookie
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oidc_sign_in_admits_only_who_it_should() {
    let idp = common::FakeOidc::start().await;
    let dir = std::env::temp_dir().join(format!("mp-oidc-{}", std::process::id()));
    let users = r#"bootstrap_admins = ["Boss@Example.com"]
allowed_email_domains = ["team.example.com"]"#;
    let env = Env::with_config(Tls::DevCa, &idp.config(&dir, users, true)).await;
    let admin = env.admin_token();
    let set = |p: common::OidcPerson| *idp.person.lock().unwrap() = p;

    // The sign-in page offers the provider, and keeps the destination.
    let login = env.ui("/login?next=/account", None, None).await;
    assert!(login.html.contains(r#"href="/auth/oidc/fake?next=%2Faccount""#) && login.html.contains("Continue with Fake ID"), "{}", login.html);
    assert!(!env.ui("/login?method=token", None, None).await.html.contains("Continue with"), "the admin token form is on its own");

    // Nobody is admitted just for having an account at the provider.
    set(common::OidcPerson::new("stranger", "stranger@example.org"));
    let r = oidc_sign_in(&env, None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.html);
    assert!(r.html.contains("stranger@example.org can&#39;t sign in here") || r.html.contains("stranger@example.org can't sign in here"), "{}", r.html);
    assert!(r.cookie.is_none());

    // An address the provider didn't verify proves nothing, even a listed one.
    let mut unverified = common::OidcPerson::new("boss-1", "boss@example.com");
    unverified.verified = false;
    set(unverified);
    let r = oidc_sign_in(&env, None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.html);
    assert!(r.html.contains("didn"), "{}", r.html);

    // A bootstrap administrator gets an account with the administrator's role and no password.
    set(common::OidcPerson::new("boss-1", "boss@example.com"));
    let r = oidc_sign_in(&env, None).await;
    assert_eq!((r.status, r.location.as_deref()), (StatusCode::SEE_OTHER, Some("/")));
    let boss = session_of(&r);
    assert_eq!(env.ui("/users", Some(&boss), None).await.status, StatusCode::OK, "an administrator's page");
    let account = env.ui("/account", Some(&boss), None).await;
    assert!(!account.html.contains("Change password"), "no password to change");
    let (_, list) = env.api("GET", "/api/v1/users", Some(&admin)).await;
    let row = list["users"].as_array().unwrap().iter().find(|u| u["email"] == "boss@example.com").unwrap().clone();
    assert_eq!((row["role"].as_str(), row["has_password"].as_bool(), row["display_name"].as_str()), (Some("admin"), Some(false), Some("Test Person")));
    assert!(row["personal_tag"].as_str().unwrap().starts_with("user:"));

    // An address in an allowed domain gets a member's account; its destination is kept.
    set(common::OidcPerson::new("dev-1", "dev@team.example.com"));
    let r = oidc_sign_in(&env, Some("/account")).await;
    let dev = session_of(&r);
    assert!(r.html.contains(r#"<a href="/account">"#), "continues to where it started: {}", r.html);
    assert_eq!(env.ui("/users", Some(&dev), None).await.status, StatusCode::SEE_OTHER, "a member is sent away");
    // Subdomains aren't the domain.
    set(common::OidcPerson::new("sub-1", "dev@x.team.example.com"));
    assert_eq!(oidc_sign_in(&env, None).await.status, StatusCode::FORBIDDEN);

    // The email can come from UserInfo instead of the ID token.
    let mut late = common::OidcPerson::new("dev-2", "second@team.example.com");
    late.email_in_userinfo = true;
    set(late);
    session_of(&oidc_sign_in(&env, None).await);

    // An identity is its subject: a changed address still signs in to the same account.
    set(common::OidcPerson::new("dev-1", "renamed@elsewhere.example.org"));
    session_of(&oidc_sign_in(&env, None).await);
    let (_, list) = env.api("GET", "/api/v1/users", Some(&admin)).await;
    assert_eq!(list["users"].as_array().unwrap().len(), 3, "no new account: {list}");

    // An administrator's temporary password stops working when its owner signs in here. Linking
    // needs the verified email to match, and only once per issuer.
    let body = serde_json::json!({ "email": "pat@example.org", "password": "correct horse battery" });
    let (status, v) = env.api_json("POST", "/api/v1/users", Some(&admin), body).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    let pat = v["user"]["id"].as_str().unwrap().to_string();
    set(common::OidcPerson::new("pat-1", "pat@example.org"));
    let r = oidc_sign_in(&env, None).await;
    let cookie = session_of(&r);
    assert_eq!(r.location.as_deref(), Some("/"), "no forced password change");
    assert_eq!(env.ui("/account", Some(&cookie), None).await.status, StatusCode::OK);
    let refused = env.ui("/login", None, Some(&[("email", "pat@example.org"), ("password", "correct horse battery")])).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "the temporary password is gone");
    // Someone else who now has that address at the provider doesn't reach the account.
    set(common::OidcPerson::new("pat-2", "pat@example.org"));
    assert_eq!(oidc_sign_in(&env, None).await.status, StatusCode::FORBIDDEN);
    // An administrator can still give them a password, for when the provider goes away.
    let (status, v) = env.api("POST", &format!("/api/v1/users/{pat}/password"), Some(&admin)).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let again = v["password"].as_str().unwrap().to_string();
    let signed_in = env.ui("/login", None, Some(&[("email", "pat@example.org"), ("password", &again)])).await;
    assert!(signed_in.cookie.is_some(), "{}", signed_in.html);

    // A disabled account stays out.
    let (status, _) = env.api_json("PATCH", &format!("/api/v1/users/{pat}"), Some(&admin), serde_json::json!({ "disabled": true })).await;
    assert_eq!(status, StatusCode::OK);
    set(common::OidcPerson::new("pat-1", "pat@example.org"));
    assert_eq!(oidc_sign_in(&env, None).await.status, StatusCode::FORBIDDEN);

    // Tokens that fail their checks.
    let mut forged = common::OidcPerson::new("boss-1", "boss@example.com");
    forged.wrong_key = true;
    set(forged);
    assert_eq!(oidc_sign_in(&env, None).await.status, StatusCode::UNAUTHORIZED);
    let mut replayed = common::OidcPerson::new("boss-1", "boss@example.com");
    replayed.wrong_nonce = true;
    set(replayed);
    assert_eq!(oidc_sign_in(&env, None).await.status, StatusCode::UNAUTHORIZED);

    // The way back only works in the browser that left. No request reaches the provider without
    // the attempt that matches.
    set(common::OidcPerson::new("boss-1", "boss@example.com"));
    let start = env.ui("/auth/oidc/fake", None, None).await;
    let attempt = start.cookie.clone().unwrap();
    let callback = follow_to_callback(&env, &start).await;
    let before = idp.token_requests.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(env.ui(&callback, None, None).await.status, StatusCode::BAD_REQUEST, "no cookie: another browser");
    let other = env.ui("/auth/oidc/fake", None, None).await.cookie.unwrap();
    assert_eq!(env.ui(&callback, Some(&other), None).await.status, StatusCode::BAD_REQUEST, "another attempt's cookie");
    let (name, value) = attempt.split_once('=').unwrap();
    let forged = format!("{name}={}", value.replacen('o', "p", 1));
    assert_eq!(env.ui(&callback, Some(&forged), None).await.status, StatusCode::BAD_REQUEST, "a changed cookie");
    assert_eq!(idp.token_requests.load(std::sync::atomic::Ordering::SeqCst), before);
    // The real one still works, with a provider that says who it is; another name is refused.
    let wrong_iss = format!("{}&iss=https://evil.example.com", callback.split("&iss=").next().unwrap());
    assert_eq!(env.ui(&wrong_iss, Some(&attempt), None).await.status, StatusCode::UNAUTHORIZED);
    session_of(&env.ui(&callback, Some(&attempt), None).await);
    // A used code doesn't work twice.
    assert_eq!(env.ui(&callback, Some(&attempt), None).await.status, StatusCode::UNAUTHORIZED);
    // A provider's error, and a provider we don't have.
    let state = callback.split("state=").nth(1).unwrap().split('&').next().unwrap();
    let cancelled = env.ui(&format!("/auth/oidc/fake/callback?error=access_denied&state={state}"), Some(&attempt), None).await;
    assert!(cancelled.status == StatusCode::BAD_REQUEST && cancelled.html.contains("cancelled"), "{}", cancelled.html);
    assert_eq!(env.ui("/auth/oidc/other", None, None).await.status, StatusCode::NOT_FOUND);

    idp.task.abort();
    std::fs::remove_dir_all(&dir).ok();
}

/// A provider that is down shows a page, and the password form still works.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oidc_provider_down_leaves_other_sign_ins_alone() {
    let idp = common::FakeOidc::start().await;
    let dir = std::env::temp_dir().join(format!("mp-oidc-down-{}", std::process::id()));
    let config = idp.config(&dir, "", false);
    idp.task.abort();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let env = Env::with_config(Tls::DevCa, &config).await;
    let r = env.ui("/auth/oidc/fake?next=/account", None, None).await;
    assert_eq!(r.status, StatusCode::BAD_GATEWAY, "{}", r.html);
    assert!(r.html.contains("Fake ID can&#39;t be reached") || r.html.contains("Fake ID can't be reached"), "{}", r.html);
    assert!(r.html.contains(r#"action="/login""#), "the password form is still offered: {}", r.html);
    std::fs::remove_dir_all(&dir).ok();
}

/// Opens a connection and asks for `req`; the connection if the listener answered at all.
async fn served<S>(mut conn: S, req: &str) -> Option<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    conn.write_all(req.as_bytes()).await.ok()?;
    let mut head = [0u8; 8];
    tokio::time::timeout(Duration::from_secs(5), conn.read_exact(&mut head)).await.ok()?.ok()?;
    (&head == b"HTTP/1.1").then_some(conn)
}

/// Every listener limits how many connections one address can hold. Public HTTPS has always done
/// so; the management and plain HTTP listeners used to let them go right after the handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_address_cannot_hold_every_connection() {
    const PER_CLIENT: usize = 64;
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    add_json(&env, &[&app.port.to_string(), "--name", "app"]).await;
    // Earlier connections have gone; the agent's session is still up, and must not count.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let healthz = format!("GET /healthz HTTP/1.1\r\nHost: localhost:{}\r\n\r\n", env.mgmt_port);
    let mut held = Vec::new();
    for i in 0..PER_CLIENT {
        let tls = env.connect("localhost", env.mgmt_port).await;
        held.push(served(tls, &healthz).await.unwrap_or_else(|| panic!("management connection {i} was refused")));
    }
    let refused = match env.try_connect("localhost", env.mgmt_port).await {
        Ok(tls) => served(tls, &healthz).await.is_none(),
        Err(_) => true,
    };
    assert!(refused, "management accepted more than {PER_CLIENT} connections from one address");
    // Those limits are per listener: tunnels go on working.
    assert_eq!(env.send(&format!("app.{BASE}"), env.https_port, Request::get("/").header(header::HOST, format!("app.{BASE}")).body(Full::new(Bytes::new())).unwrap()).await.status(), StatusCode::OK);
    drop(held);
    env.eventually("a management connection is served again", Duration::from_secs(5), || async {
        match env.try_connect("localhost", env.mgmt_port).await {
            Ok(tls) => served(tls, &healthz).await.is_some(),
            Err(_) => false,
        }
    })
    .await;

    let plain = "GET /x HTTP/1.1\r\nHost: app.example.test\r\n\r\n";
    let tcp = || tokio::net::TcpStream::connect(("127.0.0.1", env.http_port));
    let mut held = Vec::new();
    for i in 0..PER_CLIENT {
        held.push(served(tcp().await.unwrap(), plain).await.unwrap_or_else(|| panic!("plain connection {i} was refused")));
    }
    assert!(served(tcp().await.unwrap(), plain).await.is_none(), "plain HTTP accepted more than {PER_CLIENT} connections from one address");
    drop(held);
    env.eventually("a plain connection is served again", Duration::from_secs(5), || async { served(tcp().await.unwrap(), plain).await.is_some() }).await;
}

/// MagicPipes' cookies don't reach a public tunnel's application: a tunnel's name can pass to
/// someone else, while a browser keeps sending what it was given for that hostname.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_applications_never_get_our_cookies() {
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let t = add_json(&env, &[&app.port.to_string(), "--name", "open"]).await;
    let host = hostname(t["public_url"].as_str().unwrap());
    let r = env.tunnel_get(&host, "/whoami", "a=1; __Host-mp_tunnel=c~us_x~h~-~1~2~mac; __Host-mp_state_n=1; b=2", false).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("cookie=a=1; b=2") && !r.body.contains("mp_"), "{}", r.body);
    let r = env.tunnel_get(&host, "/whoami", "only=theirs", false).await;
    assert!(r.body.contains("cookie=only=theirs"), "{}", r.body);

    // And an application's cookies stay on its tunnel: `Domain` can't reach the others, or the
    // management host. Its own hostname is fine.
    let req = Request::get("/cookies").header(header::HOST, &host).body(Full::new(Bytes::new())).unwrap();
    let resp = env.send(&host, env.https_port, req).await;
    let cookies: Vec<&str> = resp.headers().get_all(header::SET_COOKIE).iter().map(|v| v.to_str().unwrap()).collect();
    assert_eq!(cookies, ["shared=1; Path=/".to_string(), format!("own=2; Domain=open.{BASE}")], "{cookies:?}");
}

/// Files in a shared folder can't run scripts on the tunnel's origin unless the tunnel is a site.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn served_pages_run_scripts_only_with_site() {
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    let site = env.root.join("site");
    std::fs::create_dir_all(site.join("sub")).unwrap();
    std::fs::write(site.join("index.html"), "<h1>home</h1>").unwrap();
    std::fs::write(site.join("logo.svg"), "<svg xmlns='http://www.w3.org/2000/svg'/>").unwrap();
    std::fs::write(site.join("notes.txt"), "0123456789").unwrap();
    std::fs::write(site.join("sub/file.txt"), "inside").unwrap();
    let dir = site.to_str().unwrap();
    let host = format!("files.{BASE}");
    let get = async |path: &str| {
        let req = Request::get(path).header(header::HOST, &host).body(Full::new(Bytes::new())).unwrap();
        env.send(&host, env.https_port, req).await
    };
    let csp = async |path: &str| get(path).await.headers().get(header::CONTENT_SECURITY_POLICY).map(|v| v.to_str().unwrap().to_string());

    let out = env.cli_ok(&["add", "--serve", dir, "--name", "files"]).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--site"), "says how to turn scripts on: {stderr}");
    for page in ["/", "/index.html", "/logo.svg"] {
        let policy = csp(page).await.unwrap_or_else(|| panic!("{page} has no policy"));
        assert!(policy.starts_with("sandbox") && !policy.contains("allow-scripts"), "{page}: {policy}");
    }
    assert_eq!(csp("/notes.txt").await, None, "a text file can't run anything");
    assert_eq!(get("/").await.into_body().collect().await.unwrap().to_bytes(), "<h1>home</h1>");

    // Files are served from what was opened: Range requests and conditional ones still work.
    let req = Request::get("/notes.txt").header(header::HOST, &host).header(header::RANGE, "bytes=2-4").body(Full::new(Bytes::new())).unwrap();
    let resp = env.send(&host, env.https_port, req).await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(resp.into_body().collect().await.unwrap().to_bytes(), "234");
    let modified = get("/notes.txt").await.headers()[header::LAST_MODIFIED].clone();
    let req = Request::get("/notes.txt").header(header::HOST, &host).header(header::IF_MODIFIED_SINCE, modified).body(Full::new(Bytes::new())).unwrap();
    assert_eq!(env.send(&host, env.https_port, req).await.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(get("/sub/").await.status(), StatusCode::OK, "a listing is read through what was opened too");

    // --site is for a web app you trust.
    let out = env.cli_ok(&["add", "--serve", dir, "--name", "files", "--site"]).await;
    assert!(!String::from_utf8_lossy(&out.stderr).contains("--site"));
    assert_eq!(csp("/").await, None);
    assert_eq!(csp("/logo.svg").await, None);

    // Re-running a command doesn't turn listings back on; asking for them does.
    add_json(&env, &["--serve", dir, "--name", "files", "--no-list"]).await;
    assert_eq!(get("/sub/").await.status(), StatusCode::NOT_FOUND);
    add_json(&env, &["--serve", dir, "--name", "files"]).await;
    assert_eq!(get("/sub/").await.status(), StatusCode::NOT_FOUND, "re-adding keeps --no-list");
    add_json(&env, &["--serve", dir, "--name", "files", "--list"]).await;
    assert_eq!(get("/sub/").await.status(), StatusCode::OK);
    assert_eq!(env.cli(&["add", "--serve", dir, "--list", "--no-list"]).await.status.code(), Some(2));
    assert_eq!(env.cli(&["add", "8080", "--site"]).await.status.code(), Some(2));

    // Archives are read through what was opened as well.
    assert_eq!(get("/sub/?archive").await.status(), StatusCode::OK);
    env.cli_ok(&["remove", "files"]).await;

    // A folder holding more than anyone means to share takes an explicit flag.
    let home = env.home();
    for dir in ["/", home.to_str().unwrap()] {
        let out = env.cli(&["add", "--serve", dir, "--json"]).await;
        assert_eq!(out.status.code(), Some(4), "{dir}");
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["error"]["code"], "invalid_directory");
        assert!(v["error"]["message"].as_str().unwrap().contains("--allow-sensitive-root"), "{v}");
    }
    add_json(&env, &["--serve", home.to_str().unwrap(), "--allow-sensitive-root", "--name", "mine"]).await;
}

/// A terminal's place is held until its program has really gone, so --max-clients bounds programs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_terminal_place_is_held_until_its_program_has_gone() {
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    let pidfile = env.root.join("pid");
    // Ignores the hangup that ends most programs right away.
    let cmd = format!("trap '' HUP; echo $$ > {}; echo STARTED; exec sleep 60", pidfile.display());
    add_json(&env, &["--shell", "--max-clients", "1", "--name", "stubborn", "--", "/bin/sh", "-c", &cmd]).await;
    let host = format!("stubborn.{BASE}");
    let (mut first, ready) = terminal(&env, &host, None).await;
    assert_eq!(ready["type"], "ready");
    read_terminal(&mut first, "STARTED", Duration::from_secs(10)).await;
    let pid = std::fs::read_to_string(&pidfile).unwrap().trim().to_string();
    let _ = first.close(None).await;
    drop(first);

    // Closing the page doesn't make room while the program is still running.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(process_alive(&pid));
    let (_, busy) = terminal(&env, &host, None).await;
    assert_eq!(busy["code"], "busy", "{busy}");

    // The kill comes after a grace period, and only then is there room.
    env.eventually("the program is killed", Duration::from_secs(10), || async { !process_alive(&pid) }).await;
    env.eventually("the place is given back", Duration::from_secs(5), || async { terminal(&env, &host, None).await.1["type"] == "ready" }).await;
}

/// `ports.tcp_idle_timeout_secs` closes quiet connections to raw ports.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quiet_port_connections_can_be_closed() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let env = Env::with_config(Tls::DevCa, "tcp_idle_timeout_secs = 1").await;
    env.login().await;
    let echo = common::tcp_echo_app().await;
    let t = add_json(&env, &[&echo.port.to_string(), "--tcp", "--allow-any"]).await;
    let port = t["public_port"].as_u64().unwrap() as u16;
    let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    conn.write_all(b"ping").await.unwrap();
    let mut got = [0u8; 4];
    conn.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping");
    let read = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut got)).await;
    assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))), "the quiet connection was closed: {read:?}");
}

/// Management requests wait for the database on threads of their own, so a slow disk or a burst of
/// writes doesn't hold up tunnels.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stuck_database_does_not_hold_up_tunnels() {
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let t = add_json(&env, &[&app.port.to_string(), "--public"]).await;
    let host = hostname(t["public_url"].as_str().unwrap());
    assert_eq!(env.get_public(&host, "/").await.0, StatusCode::OK);

    // Another process holds the write lock, and more writers wait for it than the server has threads.
    let db = rusqlite::Connection::open(env.root.join("server/magicpipes.db")).unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let admin = env.admin_token();
    let writers = std::thread::available_parallelism().map_or(8, |n| n.get()).min(48) + 8;
    let writes = futures_util::future::join_all(
        (0..writers).map(|_| env.api_json("POST", "/api/v1/enrollments", Some(&admin), serde_json::json!({}))),
    );
    let traffic = async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        for _ in 0..5 {
            let got = tokio::time::timeout(Duration::from_secs(2), env.get_public(&host, "/")).await;
            assert_eq!(got.expect("tunnels keep answering").0, StatusCode::OK);
        }
        db.execute_batch("ROLLBACK").unwrap();
    };
    let (written, ()) = tokio::join!(writes, traffic);
    for (status, body) in written {
        assert_eq!(status, StatusCode::CREATED, "the writes finish once the database is free: {body}");
    }
}

/// Connections to an application are kept for its tunnel's next requests, whatever happens to other
/// tunnels.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pooled_connections_outlast_changes_to_other_tunnels() {
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    let release = Arc::new(tokio::sync::Notify::new());
    let (app, other) = (common::http_app(release.clone()).await, common::http_app(release).await);
    let t = add_json(&env, &[&app.port.to_string(), "--public", "--name", "web"]).await;
    let host = hostname(t["public_url"].as_str().unwrap());
    let used = env.get_public(&host, "/conn").await.2;
    add_json(&env, &[&other.port.to_string(), "--public", "--name", "other"]).await;
    assert_eq!(env.get_public(&host, "/conn").await.2, used, "still the same connection");
}

/// After a change the page says what happened, and a form that fails comes back as it was typed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_ui_says_what_happened_and_keeps_what_you_typed() {
    let env = Env::new(Tls::DevCa).await;
    let admin = admin_session(&env).await;
    let page = async |path: &str| env.ui(path, Some(&admin), None).await;
    let csrf = page("/tags").await.csrf();

    // A change redirects with a key, and only known keys ever put words on the page.
    let made = env.ui("/tags", Some(&admin), Some(&[("csrf", &csrf), ("name", "team:dev"), ("access", "on")])).await;
    assert_eq!(made.location.as_deref(), Some("/tags?done=tag-created"));
    assert!(page("/tags?done=tag-created").await.html.contains(r#"role="status""#));
    assert!(page("/tags?done=tag-created").await.html.contains("Tag created."));
    let forged = page("/tags?done=%3Cscript%3E").await;
    assert!(!forged.html.contains("class=\"done") && !forged.html.contains("%3Cscript"), "{}", forged.html);

    // A failure keeps what was typed, names the field and says so in the title. A password never comes back.
    let bad = env.ui("/tags", Some(&admin), Some(&[("csrf", &csrf), ("name", "NOT OK!"), ("description", "for the &team")])).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert!(bad.html.contains("<title>Error: Tags") && bad.html.contains(r#"value="NOT OK!" aria-invalid="true""#) && bad.html.contains(r#"value="for the &amp;team""#), "{}", bad.html);
    assert!(bad.html.contains(r#"id="form-error""#) && !bad.html.contains("access\" value=\"on\" checked"), "the unchecked box stays unchecked: {}", bad.html);
    let secret = "not-the-address-short";
    let bad = env.ui("/users", Some(&admin), Some(&[("csrf", &csrf), ("email", "nope"), ("display_name", "Ann"), ("role", "admin"), ("password", secret)])).await;
    assert!(bad.status == StatusCode::BAD_REQUEST && bad.html.contains(r#"value="nope" aria-invalid="true""#) && bad.html.contains(r#"value="Ann""#), "{}", bad.html);
    assert!(bad.html.contains(r#"value="admin" selected"#) && !bad.html.contains(secret), "{}", bad.html);
    let bad = env.ui("/hostnames", Some(&admin), Some(&[("csrf", &csrf), ("hostname", "shop.example.com"), ("assign", "")])).await;
    assert!(bad.status == StatusCode::BAD_REQUEST && bad.html.contains(r#"value="shop.example.com""#) && bad.html.contains(r#"name="assign" aria-invalid="true""#), "{}", bad.html);

    // Removing what's already gone says so, instead of looking like it worked.
    let gone = async || env.ui("/tags/delete", Some(&admin), Some(&[("csrf", &csrf), ("name", "team:dev")])).await;
    assert_eq!(gone().await.location.as_deref(), Some("/tags?done=tag-deleted"));
    let again = gone().await;
    assert!(again.status == StatusCode::NOT_FOUND && again.html.contains("already gone") && again.html.contains(r#"role="alert""#), "{}", again.html);

    // Where you are, in the words the page uses.
    let tags = page("/tags").await;
    assert!(tags.html.contains(r#"href="/tags" aria-current="page""#) && !tags.html.contains(r#"href="/users" aria-current"#), "{}", tags.html);
    assert!(page("/settings/providers/new?type=oidc").await.html.contains(r#"href="/settings" aria-current="true""#));
    assert!(!tags.html.contains("Log out") && tags.html.contains("Sign out"));

    // Pages that used to be bare.
    let missing = page("/no/such/page").await;
    assert!(missing.status == StatusCode::NOT_FOUND && missing.html.contains("<h1>") && missing.html.contains("<title>Not found"), "{}", missing.html);
    let (status, body) = env.api("GET", "/api/v1/nope", None).await;
    assert_eq!((status, body["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("not_found")));
    let expired = env.ui("/tags", Some(&admin), Some(&[("csrf", "stale"), ("name", "team:x")])).await;
    assert!(expired.status == StatusCode::FORBIDDEN && expired.html.contains("expired"), "{}", expired.html);

    // The script can be kept, because its address changes with it.
    let script = tags.html.split(r#"<script src=""#).nth(1).and_then(|s| s.split('"').next()).expect("a script").to_string();
    assert!(script.starts_with("/ui.js?v="), "{script}");
    let get = Request::get(&script).header(header::HOST, format!("localhost:{}", env.mgmt_port)).body(Full::new(Bytes::new())).unwrap();
    let resp = env.send("localhost", env.mgmt_port, get).await;
    assert!(resp.headers()[header::CACHE_CONTROL].to_str().unwrap().contains("immutable"));
}

/// A tunnel's row shows a few tags, so that many can't push the rest of the list off the page, and
/// its own page shows them all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_tunnels_list_keeps_to_a_few_tags() {
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    let admin = env.admin_token();
    let names = ["team:a", "team:b", "team:c", "team:d", "team:e", "team:f"];
    for name in names {
        env.api_json("POST", "/api/v1/tags", Some(&admin), serde_json::json!({ "name": name, "access": true })).await;
    }
    let (_, agents) = env.api("GET", "/api/v1/agents", Some(&admin)).await;
    let agent = agents["agents"][0]["id"].as_str().unwrap().to_string();
    env.api_json("PATCH", &format!("/api/v1/agents/{agent}"), Some(&admin), serde_json::json!({ "tags": names })).await;

    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let port = app.port.to_string();
    let add = async |name: &str, tags: &[&str]| {
        let mut args = vec![port.as_str(), "--name", name];
        for tag in tags {
            args.extend(["--tag", tag]);
        }
        add_json(&env, &args).await["id"].as_str().unwrap().to_string()
    };
    add("four", &names[..4]).await;
    let many = add("many", &names).await;

    let cookie = admin_session(&env).await;
    let home = env.ui("/", Some(&cookie), None).await.html;
    let row = |name: &str| {
        let at = home.find(&format!(">{name}</a>")).unwrap_or_else(|| panic!("{name} is listed: {home}"));
        home[at..].split("</tr>").next().unwrap().to_string()
    };
    let chips = |html: &str| html.matches(r#"<code class="tag""#).count();
    assert!(!row("four").contains(">ready<"), "a certificate that's fine isn't worth a word in the list: {}", row("four"));
    assert!(chips(&row("four")) == 4 && !row("four").contains("more"), "{}", row("four"));
    assert_eq!(chips(&row("many")), 3, "{}", row("many"));
    assert!(row("many").contains(&format!(r#"href="/tunnels/{many}""#)) && row("many").contains("+3 more</a>"), "{}", row("many"));
    assert!(row("many").contains(r#"title="team:d, team:e, team:f""#) && row("many").contains(r#"aria-label="All 6 tags of many""#), "{}", row("many"));

    let page = env.ui(&format!("/tunnels/{many}"), Some(&cookie), None).await.html;
    assert!(chips(&page) == 6 && !page.contains("+3 more"), "{page}");

    let machines = env.ui("/machines", Some(&cookie), None).await.html;
    assert_eq!(chips(&machines), 6, "editing a machine's tags needs to see them all: {machines}");
}

/// The home page answers "is everything OK?", and from nothing shows the way to a working tunnel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_home_page_says_how_things_are() {
    let env = Env::new(Tls::DevCa).await;
    let admin = admin_session(&env).await;
    let home = async || env.ui("/", Some(&admin), None).await.html;
    let first = home().await;
    assert!(first.contains("Get started") && first.contains("/machines") && !first.contains(r#"class="stats""#), "{first}");

    env.login().await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    add_json(&env, &[&app.port.to_string(), "--public", "--name", "web"]).await;
    let healthy = home().await;
    assert!(healthy.contains("Your tunnel is healthy") && !healthy.contains("Get started"), "{healthy}");
    assert!(env.ui("/machines", Some(&admin), None).await.html.contains("test-agent"), "machines have a page of their own");

    // The CLI's list says who can open it, and lines up however long a target is.
    let list = String::from_utf8(env.cli_ok(&["list"]).await.stdout).unwrap();
    let mut lines = list.lines();
    let (head, row) = (lines.next().unwrap(), lines.next().unwrap());
    assert!(head.contains("ACCESS") && row.contains("public"), "{list}");
    assert_eq!(head.find("ACCESS"), row.find("public"), "{list}");

    env.cli_ok(&["agent", "stop"]).await;
    env.eventually("the home page notices", Duration::from_secs(10), || async {
        home().await.contains(r#"<a href="/machines">1 machine offline</a>"#)
    }).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_enrollment_token_can_come_from_a_file() {
    let env = Env::new(Tls::DevCa).await;
    let file = env.root.join("token");
    std::fs::write(&file, format!("{}\n", env.enrollment_token())).unwrap();
    let (url, ca) = (env.server_url(), env.ca_path.to_string_lossy().to_string());
    env.cli_ok(&["login", "--server", &url, "--token-file", &file.to_string_lossy(), "--ca-cert", &ca, "--name", "from-a-file"]).await;
    let admin = env.admin_token();
    let (_, agents) = env.api("GET", "/api/v1/agents", Some(&admin)).await;
    assert_eq!(agents["agents"][0]["name"], "from-a-file");
    let missing = env.cli(&["login", "--server", &url, "--token-file", "/no/such/file", "--json"]).await;
    assert!(!missing.status.success() && String::from_utf8_lossy(&missing.stdout).contains("config_error"), "{missing:?}");
}

/// Anyone who can choose their address at a trusted provider can use any address, so that alone
/// doesn't reach an administrator's account.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unverified_addresses_do_not_reach_administrators() {
    let idp = common::FakeOidc::start().await;
    let dir = std::env::temp_dir().join(format!("mp-oidc-trust-{}", std::process::id()));
    let users = r#"bootstrap_admins = ["boss@example.com"]
allowed_email_domains = ["team.example.com"]"#;
    let config = format!("{}trust_email = true\n", idp.config(&dir, users, true));
    let env = Env::with_config(Tls::DevCa, &config).await;
    let admin = env.admin_token();
    let unverified = |sub: &str, email: &str| {
        let mut p = common::OidcPerson::new(sub, email);
        p.verified = false;
        *idp.person.lock().unwrap() = p;
    };
    let accounts = async || env.api("GET", "/api/v1/users", Some(&admin)).await.1["users"].as_array().unwrap().clone();

    // That's what trusting a provider is for: members.
    unverified("dev-1", "dev@team.example.com");
    session_of(&oidc_sign_in(&env, None).await);

    // A bootstrap address isn't enough without the provider's word, and isn't made a member either.
    unverified("mallory", "boss@example.com");
    assert_eq!(oidc_sign_in(&env, None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(accounts().await.len(), 1, "no account for it");
    let audit = env.api("GET", "/api/v1/audit", Some(&admin)).await.1;
    assert!(audit.to_string().contains("unverified address"), "the audit log says how the first one got in: {audit}");

    // An existing administrator's address doesn't reach their account; a member's does, which is
    // what link_by_email and trust_email together ask for.
    let (s, _) = env.api_json("POST", "/api/v1/users", Some(&admin), serde_json::json!({ "email": "carol@example.org", "role": "admin" })).await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _) = env.api_json("POST", "/api/v1/users", Some(&admin), serde_json::json!({ "email": "pat@example.org" })).await;
    assert_eq!(s, StatusCode::CREATED);
    unverified("mallory", "carol@example.org");
    assert_eq!(oidc_sign_in(&env, None).await.status, StatusCode::FORBIDDEN);
    unverified("pat-1", "pat@example.org");
    session_of(&oidc_sign_in(&env, None).await);

    // The provider's own word still counts.
    *idp.person.lock().unwrap() = common::OidcPerson::new("boss-1", "boss@example.com");
    let boss = session_of(&oidc_sign_in(&env, None).await);
    assert_eq!(env.ui("/users", Some(&boss), None).await.status, StatusCode::OK, "an administrator");
    std::fs::remove_dir_all(&dir).ok();

    // And so does the operator's, explicitly.
    let idp = common::FakeOidc::start().await;
    let dir = std::env::temp_dir().join(format!("mp-oidc-trust2-{}", std::process::id()));
    let config = format!("{}trust_email = true\nallow_unverified_admin = true\n", idp.config(&dir, users, false));
    let env = Env::with_config(Tls::DevCa, &config).await;
    let mut p = common::OidcPerson::new("boss-1", "boss@example.com");
    p.verified = false;
    *idp.person.lock().unwrap() = p;
    let boss = session_of(&oidc_sign_in(&env, None).await);
    assert_eq!(env.ui("/users", Some(&boss), None).await.status, StatusCode::OK, "an administrator");
    std::fs::remove_dir_all(&dir).ok();
}

/// Waits for a WebSocket to be closed by the other side.
async fn closes_soon<S>(sock: &mut tokio_tungstenite::WebSocketStream<S>) -> bool
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match sock.next().await {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .is_ok()
}

/// A WebSocket opened while a tunnel was public doesn't outlast its being made private or removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_websockets_close_when_access_changes() {
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    let ws = common::ws_echo_app().await;
    let port = ws.port.to_string();
    let t = add_json(&env, &[&port, "--name", "open", "--public", "--probe-path", "/"]).await;
    let host = hostname(t["public_url"].as_str().unwrap());
    let connect = || async {
        let (mut sock, _) = tokio_tungstenite::client_async(format!("wss://{host}/"), env.connect(&host, env.https_port).await).await.expect("websocket handshake");
        sock.send(Message::text("ping")).await.unwrap();
        assert_eq!(sock.next().await.unwrap().unwrap(), Message::text("ping"));
        sock
    };

    // Going private: the anonymous connection ends, though nothing changed at the agent.
    let mut sock = connect().await;
    env.cli_ok(&["add", &port, "--name", "open", "--private", "--no-verify"]).await;
    assert!(closes_soon(&mut sock).await, "the WebSocket stayed open after the tunnel went private");

    // A change that keeps it public leaves connections alone.
    env.cli_ok(&["add", &port, "--name", "open", "--public", "--probe-path", "/"]).await;
    let mut sock = connect().await;
    env.cli_ok(&["add", &port, "--name", "open", "--public", "--probe-path", "/"]).await;
    sock.send(Message::text("still here")).await.unwrap();
    assert_eq!(sock.next().await.unwrap().unwrap(), Message::text("still here"));

    // Removing it ends them too.
    env.cli_ok(&["remove", "open"]).await;
    assert!(closes_soon(&mut sock).await, "the WebSocket stayed open after the tunnel was removed");
}

/// Anonymous visitors of a terminal learn the program's name, never its arguments.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_terminal_that_cannot_start_keeps_its_arguments_private() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    let program = env.root.join("console-tool");
    std::fs::write(&program, "#!/bin/sh\nread line\n").unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    env.cli_ok(&["add", "--shell", "--name", "gone", "--", program.to_str().unwrap(), "postgres://u:hunter2@db"]).await;
    std::fs::remove_file(&program).unwrap();

    let (_, answer) = terminal(&env, &format!("gone.{BASE}"), None).await;
    assert_eq!((answer["type"].as_str(), answer["code"].as_str()), (Some("error"), Some("spawn_failed")), "{answer}");
    let message = answer["message"].as_str().unwrap();
    assert!(message.contains("console-tool") && !message.contains("hunter2") && !message.contains(env.root.to_str().unwrap()), "{message}");
}

/// Taking an account back also takes back its API tokens, which outlive its sessions otherwise.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_tokens_can_be_revoked() {
    let env = Env::new(Tls::DevCa).await;
    let admin = env.admin_token();
    let body = serde_json::json!({ "email": "ann@example.com", "password": "correct horse battery" });
    let (_, v) = env.api_json("POST", "/api/v1/users", Some(&admin), body).await;
    let ann = v["user"]["id"].as_str().unwrap().to_string();
    let first = env.ui("/login", None, Some(&[("email", "ann@example.com"), ("password", "correct horse battery")])).await;
    let cookie = first.cookie.clone().unwrap();
    let form = env.ui("/password", Some(&cookie), None).await;
    let new = "another correct horse battery";
    let changed = env.ui("/password", Some(&cookie), Some(&[("csrf", &form.csrf()), ("current", "correct horse battery"), ("new", new), ("repeat", new)])).await;
    let cookie = changed.cookie.clone().unwrap();
    let new_token = async |csrf: &str| shown_secret(&env.ui("/account/tokens", Some(&cookie), Some(&[("csrf", csrf), ("name", "ci")])).await.html);
    let account = env.ui("/account", Some(&cookie), None).await;
    let csrf = account.csrf();
    let works = async |token: &str| env.api("GET", "/api/v1/me", Some(token)).await.0 == StatusCode::OK;

    // A typo in the expiry is refused, instead of making a token that never expires.
    let typo = env.ui("/account/tokens", Some(&cookie), Some(&[("csrf", &csrf), ("name", "typo"), ("expires_in_days", "abc")])).await;
    assert_eq!(typo.status, StatusCode::BAD_REQUEST, "{}", typo.html);
    assert!(typo.html.contains("whole number of days"), "{}", typo.html);
    let token = new_token(&csrf).await;
    assert_eq!(env.api("GET", "/api/v1/tokens", Some(&token)).await.1["tokens"].as_array().unwrap().len(), 1, "the typo made no token");

    // Through the API.
    let path = format!("/api/v1/users/{ann}/tokens");
    let (s, v) = env.api("DELETE", &path, Some(&admin)).await;
    assert_eq!((s, v["revoked"].as_u64()), (StatusCode::OK, Some(1)));
    assert!(!works(&token).await);

    // From the Users page.
    let token = new_token(&csrf).await;
    let session = admin_session(&env).await;
    let users = env.ui("/users", Some(&session), None).await;
    assert!(users.html.contains("Revoke API tokens"), "{}", users.html);
    let r = env.ui(&format!("/users/{ann}"), Some(&session), Some(&[("csrf", &users.csrf()), ("action", "revoke-tokens")])).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.html);
    assert!(!works(&token).await);

    // A password reset takes them too.
    let token = new_token(&csrf).await;
    assert!(works(&token).await);
    assert_eq!(env.api("POST", &format!("/api/v1/users/{ann}/password"), Some(&admin)).await.0, StatusCode::OK);
    assert!(!works(&token).await);
}

/// An administrator's session, signed in with the admin token.
async fn admin_session(env: &Env) -> String {
    let token = env.admin_token();
    env.ui("/login", None, Some(&[("token", token.as_str())])).await.cookie.expect("signed in")
}

/// Plain headers from an authenticating proxy: believed only with the secret, and only as long as
/// they keep naming the session's user.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_proxys_plain_headers_sign_people_in() {
    const SECRET: &str = "a-long-enough-shared-secret";
    let dir = std::env::temp_dir().join(format!("mp-proxy-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let secret_file = dir.join("proxy-secret");
    std::fs::write(&secret_file, format!("{SECRET}\n")).unwrap();
    let extra = format!(
        "[proxy_auth]\nmode = \"headers\"\nuser_header = \"X-Forwarded-Email\"\nsecret_header = \"X-Proxy-Secret\"\nsecret_file = \"{}\"\ntrust_email = true\nsign_out_url = \"https://auth.example.com/logout\"\n",
        secret_file.display()
    );
    let env = Env::with_settings(Tls::DevCa, "trusted_proxies = [\"127.0.0.1/32\"]", &extra).await;
    let token = env.admin_token();
    let as_person = async |path: &str, cookie: Option<&str>, email: &str| env.ui_with(path, cookie, None, &[("x-forwarded-email", email), ("x-proxy-secret", SECRET)]).await;
    let add_user = async |email: &str| {
        let body = serde_json::json!({ "email": email, "password": "correct horse battery" });
        env.api_json("POST", "/api/v1/users", Some(&token), body).await.1["user"]["id"].as_str().unwrap().to_string()
    };

    // Nobody named: the sign-in page says why, and takes only an admin token.
    let start = env.ui("/", None, None).await;
    assert_eq!(start.location.as_deref(), Some("/login"));
    let login = env.ui("/login", None, None).await;
    assert!(login.html.contains("signs people in through its proxy") && login.html.contains(r#"name="token""#) && !login.html.contains(r#"name="email""#), "{}", login.html);
    let password = env.ui("/login", None, Some(&[("email", "ann@example.com"), ("password", "correct horse battery")])).await;
    assert_eq!(password.status, StatusCode::FORBIDDEN, "{}", password.html);

    // Without the secret, or with a copy from the client beside the proxy's, nobody is named.
    add_user("ann@example.com").await;
    let forged: [&[(&str, &str)]; 3] = [
        &[("x-forwarded-email", "ann@example.com")],
        &[("x-forwarded-email", "ann@example.com"), ("x-proxy-secret", "wrong")],
        &[("x-forwarded-email", "ann@example.com"), ("x-forwarded-email", "bob@example.com"), ("x-proxy-secret", SECRET)],
    ];
    for headers in forged {
        let r = env.ui_with("/", None, None, headers).await;
        assert!(r.location.as_deref() == Some("/login") && r.cookie.is_none(), "{headers:?}");
    }

    // Someone the server doesn't know gets a reason, and no account.
    let stranger = as_person("/", None, "stranger@example.com").await;
    assert!(stranger.status == StatusCode::FORBIDDEN && stranger.html.contains("stranger@example.com can&#39;t sign in here") && stranger.html.contains(r#"role="alert""#), "{}", stranger.html);
    assert!(stranger.cookie.is_none());
    let (_, users) = env.api("GET", "/api/v1/users", Some(&token)).await;
    assert_eq!(users["users"].as_array().unwrap().len(), 1);

    // Someone an administrator created is in, without the forced change of a password they don't use.
    let first = as_person("/", None, "Ann@Example.com").await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.html);
    let cookie = first.cookie.clone().expect("a session");
    assert!(first.html.contains("ann@example.com") && first.html.contains(r#"href="https://auth.example.com/logout""#) && !first.html.contains(r#"action="/logout""#), "{}", first.html);
    let account = as_person("/account", Some(&cookie), "ann@example.com").await;
    assert!(account.status == StatusCode::OK && account.cookie.is_none(), "the same session: {}", account.html);
    assert!(!account.html.contains("Sign out everywhere") && !account.html.contains(r#"href="/password""#), "the proxy's to manage: {}", account.html);

    // On a sign-in page, someone signed in moves on, unless they asked for the admin token form.
    assert_eq!(as_person("/login", Some(&cookie), "ann@example.com").await.location.as_deref(), Some("/"));
    assert_eq!(as_person("/login?next=%2Faccount", Some(&cookie), "ann@example.com").await.location.as_deref(), Some("/account"));
    assert_eq!(as_person("/login?next=%2F%5Cevil.example", Some(&cookie), "ann@example.com").await.location.as_deref(), Some("/"));
    assert!(as_person("/login?method=token", Some(&cookie), "ann@example.com").await.html.contains(r#"name="token""#));

    // Naming someone else ends the session, and starts theirs.
    add_user("bob@example.com").await;
    let bob = as_person("/", Some(&cookie), "bob@example.com").await;
    let bobs = bob.cookie.clone().expect("a new session");
    assert!(bobs != cookie && bob.html.contains("bob@example.com"), "{}", bob.html);
    assert!(as_person("/", Some(&cookie), "ann@example.com").await.cookie.is_some(), "Ann's old session is gone");

    // Naming nobody ends it too, so signing out at the proxy signs out here.
    let gone = env.ui("/", Some(&bobs), None).await;
    assert_eq!(gone.location.as_deref(), Some("/login"));
    assert!(as_person("/", Some(&bobs), "bob@example.com").await.cookie.is_some(), "that session doesn't come back");

    // A disabled account stays out, whatever the proxy says.
    let dave = add_user("dave@example.com").await;
    assert_eq!(as_person("/", None, "dave@example.com").await.status, StatusCode::OK);
    env.api_json("PATCH", &format!("/api/v1/users/{dave}"), Some(&token), serde_json::json!({ "disabled": true })).await;
    assert_eq!(as_person("/", None, "dave@example.com").await.status, StatusCode::FORBIDDEN);

    // The admin token doesn't depend on the proxy, whoever it names or if it names nobody.
    let signed_in = env.ui_with("/login", None, Some(&[("token", token.as_str())]), &[("x-forwarded-email", "ann@example.com"), ("x-proxy-secret", SECRET)]).await;
    let admin = signed_in.cookie.clone().expect("an admin session");
    for headers in [&[][..], &[("x-forwarded-email", "ann@example.com"), ("x-proxy-secret", SECRET)][..]] {
        let users = env.ui_with("/users", Some(&admin), None, headers).await;
        assert!(users.status == StatusCode::OK && users.cookie.is_none() && users.html.contains("admin token") && users.html.contains(r#"action="/logout""#), "{}", users.html);
    }

    // Nothing offers what can't work here: passwords, or adding a provider.
    let users = env.ui("/users", Some(&admin), None).await;
    assert!(!users.html.contains(r#"name="password""#) && !users.html.contains("Reset password") && users.html.contains("through the proxy"), "{}", users.html);
    let csrf = users.csrf();
    let added = env.ui("/users", Some(&admin), Some(&[("csrf", &csrf), ("email", "erin@example.com"), ("role", "member")])).await;
    assert_eq!(added.location.as_deref(), Some("/users?done=user-added-proxy"), "no password to hand over: {}", added.html);
    assert_eq!(as_person("/", None, "erin@example.com").await.status, StatusCode::OK);

    // Settings say so, and the configuration in effect holds the path of the secret, not the secret.
    let settings = env.ui("/settings", Some(&admin), None).await;
    assert!(settings.html.contains("signs people in through its proxy") && settings.html.contains("proxy_auth") && !settings.html.contains(SECRET), "{}", settings.html);
    assert!(!settings.html.contains("Add a provider") && !settings.html.contains("sign in with a password"), "{}", settings.html);
    let generated = std::fs::read_to_string(env.root.join("server/magicpipesd.generated.toml")).unwrap();
    assert!(generated.contains("[proxy_auth]") && generated.contains("proxy-secret") && !generated.contains(SECRET), "{generated}");

    // Agents and scripts have their own credentials.
    let (status, _) = env.api("GET", "/api/v1/tunnels", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    env.login().await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let t = add_json(&env, &[&app.port.to_string(), "--public", "--name", "open"]).await;
    assert_eq!(t["status"], "ready", "{t}");

    // None of this reaches an application, even from a client that tries.
    let host = format!("open.{BASE}");
    let req = Request::get("/headers")
        .header(header::HOST, format!("{host}:{}", env.https_port))
        .header("x-forwarded-email", "ann@example.com")
        .header("x-proxy-secret", SECRET)
        .header("x-theirs", "1")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = env.send(&host, env.https_port, req).await;
    let seen = String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).into_owned();
    assert!(seen.contains("x-theirs") && !seen.contains("x-forwarded-email") && !seen.contains("x-proxy-secret"), "{seen}");
    std::fs::remove_dir_all(&dir).ok();
}

/// Signed tokens from an authenticating proxy: the same account rules as a sign-in provider.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_proxys_signed_tokens_sign_people_in() {
    let idp = common::FakeOidc::start().await;
    let iss = idp.issuer.clone();
    let extra = format!("[users]\nbootstrap_admins = [\"boss@example.com\"]\n[proxy_auth]\nmode = \"jwt\"\njwt_header = \"X-Proxy-Token\"\njwks_url = \"{iss}/keys\"\nissuer = \"{iss}\"\naudience = \"magicpipes\"\nauto_create = true\n");
    let env = Env::with_config(Tls::DevCa, &extra).await;
    let token = env.admin_token();
    let now = magicpipes_now();
    let claims = |sub: &str, email: &str, verified: bool| serde_json::json!({ "iss": iss, "aud": ["another-app", "magicpipes"], "sub": sub, "exp": now + 300, "iat": now, "email": email, "email_verified": verified, "name": "Someone" });
    let with_token = async |path: &str, cookie: Option<&str>, jwt: &str| env.ui_with(path, cookie, None, &[("x-proxy-token", jwt)]).await;
    let accounts = async || env.api("GET", "/api/v1/users", Some(&token)).await.1["users"].as_array().unwrap().clone();

    // Someone new with a verified address gets a member account, and keeps it under a new address.
    let first = with_token("/", None, &idp.sign(&claims("sub-1", "ann@example.com", true))).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.html);
    let cookie = first.cookie.clone().expect("a session");
    let users = accounts().await;
    assert_eq!((users.len(), users[0]["email"].as_str(), users[0]["role"].as_str()), (1, Some("ann@example.com"), Some("member")), "{users:?}");
    let renamed = with_token("/", Some(&cookie), &idp.sign(&claims("sub-1", "ann@elsewhere.example.com", true))).await;
    assert!(renamed.status == StatusCode::OK && renamed.cookie.is_none(), "the identity is the subject");
    assert_eq!(accounts().await.len(), 1);

    // The token can also arrive as a bearer token, as oauth2-proxy forwards it.
    let bearer = format!("Bearer {}", idp.sign(&claims("sub-1", "ann@example.com", true)));
    assert_eq!(with_token("/", Some(&cookie), &bearer).await.status, StatusCode::OK);

    // An address nobody verified doesn't make an account without `trust_email`, and says why.
    let unverified = with_token("/", None, &idp.sign(&claims("sub-2", "eve@example.com", false))).await;
    assert!(unverified.status == StatusCode::FORBIDDEN && unverified.html.contains("didn&#39;t confirm an email address"), "{}", unverified.html);
    assert_eq!(accounts().await.len(), 1);

    // A bootstrap address makes an administrator, if it's verified.
    assert_eq!(with_token("/", None, &idp.sign(&claims("sub-3", "boss@example.com", false))).await.status, StatusCode::FORBIDDEN);
    let boss = with_token("/users", None, &idp.sign(&claims("sub-3", "boss@example.com", true))).await;
    assert_eq!(boss.status, StatusCode::OK, "{}", boss.html);

    // A token that doesn't pass names nobody, and ends the session it came with.
    let mut bad: Vec<(&str, String)> = vec![("another key", idp.sign_with_another_key(&claims("sub-1", "ann@example.com", true))), ("rubbish", "a.b.c".to_string())];
    for (field, value) in [("aud", serde_json::json!("another-app")), ("iss", serde_json::json!("https://other.example.com")), ("exp", serde_json::json!(now - 3600)), ("nbf", serde_json::json!(now + 3600))] {
        let mut c = claims("sub-1", "ann@example.com", true);
        c[field] = value;
        bad.push((field, idp.sign(&c)));
    }
    let header = serde_json::json!({ "alg": "none" }).to_string();
    let payload = claims("sub-1", "ann@example.com", true).to_string();
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    bad.push(("no signature", format!("{}.{}.", b64.encode(header), b64.encode(payload))));
    for (what, jwt) in &bad {
        let r = with_token("/", None, jwt).await;
        assert!(r.location.as_deref() == Some("/login") && r.cookie.is_none(), "{what}: {:?}", r.location);
    }
    assert_eq!(with_token("/", Some(&cookie), &bad[0].1).await.location.as_deref(), Some("/login"));
    assert!(with_token("/", Some(&cookie), &idp.sign(&claims("sub-1", "ann@example.com", true))).await.cookie.is_some(), "that session is gone");

    // Without keys nothing can be said about a token. That's not the same as nobody, and an
    // administrator can still get in.
    let dead = common::free_port();
    let extra = format!("[proxy_auth]\nmode = \"jwt\"\njwt_header = \"X-Proxy-Token\"\njwks_url = \"http://127.0.0.1:{dead}/keys\"\nissuer = \"{iss}\"\naudience = \"magicpipes\"\n");
    let down = Env::with_config(Tls::DevCa, &extra).await;
    let refused = down.ui_with("/", None, None, &[("x-proxy-token", &idp.sign(&claims("sub-1", "ann@example.com", true)))]).await;
    assert!(refused.status == StatusCode::BAD_GATEWAY && refused.html.contains("can&#39;t be fetched"), "{}", refused.html);
    assert_eq!(down.ui("/", None, None).await.location.as_deref(), Some("/login"), "no token, no keys needed");
    let admin = admin_session(&down).await;
    assert_eq!(down.ui("/users", Some(&admin), None).await.status, StatusCode::OK);
}

/// What every form gets from `Posted` and `AdminPosted`, and where signing in may send a browser.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_needs_its_token_a_whole_form_and_the_right_person() {
    let env = Env::new(Tls::DevCa).await;
    let admin = admin_session(&env).await;
    let token = env.admin_token();
    let csrf = env.ui("/tags", Some(&admin), None).await.csrf();

    // No token, a wrong one, or two: nothing happens, and the page says so.
    let forms: [&[(&str, &str)]; 3] = [&[("name", "team:x")], &[("csrf", "wrong"), ("name", "team:x")], &[("csrf", &csrf), ("csrf", &csrf), ("name", "team:x")]];
    for form in forms {
        let refused = env.ui("/tags", Some(&admin), Some(form)).await;
        assert!(refused.status == StatusCode::FORBIDDEN && refused.html.contains("Nothing was changed"), "{form:?}: {}", refused.html);
    }
    assert!(!env.ui("/tags", Some(&admin), None).await.html.contains("team:x"));

    // A form without a field it needs gets a page, not a bare error.
    let incomplete = env.ui("/tags/delete", Some(&admin), Some(&[("csrf", &csrf)])).await;
    assert!(incomplete.status == StatusCode::BAD_REQUEST && incomplete.html.contains(r#"role="alert""#) && incomplete.html.contains("incomplete"), "{}", incomplete.html);

    // What's for administrators sends anyone else to their own page, with a good token too.
    let password = "correct horse battery";
    let body = serde_json::json!({ "email": "ann@example.com", "password": password });
    let (_, v) = env.api_json("POST", "/api/v1/users", Some(&token), body).await;
    let ann_id = v["user"]["id"].as_str().unwrap().to_string();
    let ann = sign_in(&env, "ann@example.com", password).await;
    for page in ["/users", "/tags", "/hostnames", "/audit", "/settings", "/settings/export", "/settings/providers/new?type=google", &format!("/users/{ann_id}/tags")] {
        assert_eq!(env.ui(page, Some(&ann), None).await.location.as_deref(), Some("/account"), "{page}");
    }
    let hers = env.ui("/account", Some(&ann), None).await.csrf();
    let refused = env.ui("/settings/sign-in", Some(&ann), Some(&[("csrf", &hers), ("bootstrap_admins", "ann@evil.example")])).await;
    assert_eq!(refused.location.as_deref(), Some("/account"));
    assert!(!env.ui("/settings", Some(&admin), None).await.html.contains("ann@evil.example"));

    // A sign-in stays on this host, however the path is written, and one check says so everywhere.
    for bad in ["%2F%5Cevil.example", "%2F%2Fevil.example", "https%3A%2F%2Fevil.example", "%2F%09%2Fevil.example"] {
        assert!(!env.ui(&format!("/login?next={bad}"), None, None).await.html.contains("evil.example"), "{bad}");
    }
    let long = format!("/{}", "a".repeat(1500));
    assert!(env.ui(&format!("/login?next={long}"), None, None).await.html.contains(&long), "a long address on this host is fine");

    let body = serde_json::json!({ "owner_user_id": ann_id });
    let (_, v) = env.api_json("POST", "/api/v1/enrollments", Some(&token), body).await;
    let (url, ca) = (env.server_url(), env.ca_path.to_string_lossy().to_string());
    env.cli_ok(&["login", "--server", &url, "--token", v["enrollment_token"].as_str().unwrap(), "--ca-cert", &ca, "--name", "laptop"]).await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    add_json(&env, &[&app.port.to_string(), "--private", "--name", "one"]).await;
    let host = format!("one.{BASE}");
    let sent = env.tunnel_get(&host, "/report", "", true).await.location.unwrap();
    let at = sent.strip_prefix(&format!("https://localhost:{}", env.mgmt_port)).unwrap();
    let (start, wanted) = at.rsplit_once("return=").unwrap();
    assert_eq!(wanted, "%2Freport");
    let back_to = async |path: &str| env.ui(&format!("{start}return={path}"), Some(&ann), None).await.location.unwrap();
    assert!(back_to("%2Freport").await.ends_with("&return=%2Freport"));
    for bad in ["%2F%5Cevil.example", "%2F%2Fevil.example", "https%3A%2F%2Fevil.example"] {
        assert!(back_to(bad).await.ends_with("&return=%2F"), "{bad}");
    }
}

/// Your own certificate from the Settings page: what it serves, what it never serves, and what a
/// failed form gives back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_certificate_added_on_the_settings_page_serves_its_names() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut env = Env::new(Tls::DevCa).await;
    env.login().await;
    let token = env.admin_token();
    let admin = admin_session(&env).await;
    let (_, v) = env.api("GET", "/api/v1/agents", Some(&token)).await;
    let agent = v["agents"][0]["id"].as_str().unwrap().to_string();
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let shop = format!("shop.app.{BASE}");
    let mut page = env.ui("/settings", Some(&admin), None).await;
    assert!(page.html.contains("None yet: every name gets its certificate from the development CA.") && page.html.contains(r#"href="/settings/certificates/new""#), "{}", page.html);
    let csrf = page.csrf();
    let new = "/settings/certificates/new";

    // It names the management hostname too, which must keep what it has.
    let (ca, chain, key) = common::own_certificate(&[&shop, "localhost"], None);
    let (_, _, wrong_key) = common::own_certificate(&[&shop], None);
    let key_body = |k: &str| k.lines().nth(1).unwrap().to_string();

    // A failed form keeps the certificate and names the problem, and never gives a key back.
    let bad = env.ui(new, Some(&admin), Some(&[("csrf", &csrf), ("chain", &chain), ("key", &wrong_key)])).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert!(bad.html.contains("belong to the first certificate") && bad.html.contains("<title>Error: Add a certificate") && bad.html.contains(chain.lines().nth(1).unwrap()), "{}", bad.html);
    assert!(bad.html.contains(r#"name="key" rows="6" spellcheck="false" autocomplete="off" placeholder="-----BEGIN PRIVATE KEY-----" required aria-invalid="true""#), "{}", bad.html);
    assert!(!bad.html.contains(&key_body(&wrong_key)), "{}", bad.html);
    let both = format!("{chain}{key}");
    let bad = env.ui(new, Some(&admin), Some(&[("csrf", &csrf), ("chain", &both), ("key", &key)])).await;
    assert!(bad.status == StatusCode::BAD_REQUEST && !bad.html.contains(&key_body(&key)), "a combined file isn't shown again: {}", bad.html);
    assert!(env.ui("/settings", Some(&admin), None).await.html.contains("None yet"));

    // The token is checked before anything else, like any other form.
    let forged = env.ui(new, Some(&admin), Some(&[("csrf", "wrong"), ("chain", &chain), ("key", &key)])).await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);

    // Only administrators get here at all.
    let password = "correct horse battery";
    let (_, _) = env.api_json("POST", "/api/v1/users", Some(&token), serde_json::json!({ "email": "ann@example.com", "password": password })).await;
    let ann = sign_in(&env, "ann@example.com", password).await;
    assert_eq!(env.ui(new, Some(&ann), None).await.location.as_deref(), Some("/account"));
    let hers = env.ui("/account", Some(&ann), None).await.csrf();
    let refused = env.ui(new, Some(&ann), Some(&[("csrf", &hers), ("chain", &chain), ("key", &key)])).await;
    assert_eq!(refused.location.as_deref(), Some("/account"));
    assert!(env.connect_trusting(&ca, &shop, env.https_port).await.is_err());

    let made = env.ui(new, Some(&admin), Some(&[("csrf", &csrf), ("chain", &chain), ("key", &key)])).await;
    assert_eq!(made.location.as_deref(), Some("/settings?done=certificate-added"));

    // Its names use it at once, and a hostname registered now says so instead of being ordered.
    let assign = format!("agent:{agent}");
    let form = [("csrf", csrf.as_str()), ("hostname", shop.as_str()), ("assign", assign.as_str())];
    assert_eq!(env.ui("/hostnames", Some(&admin), Some(&form)).await.location.as_deref(), Some("/hostnames?done=hostname-covered"));
    add_json(&env, &[&app.port.to_string(), "--hostname", &shop, "--public", "--no-verify"]).await;
    let (_, v) = env.api("GET", "/api/v1/hostnames", Some(&token)).await;
    assert_eq!(v["hostnames"][0]["tls"], "ready", "{v}");
    assert!(env.try_connect(&shop, env.https_port).await.is_err(), "not the development CA's any more");
    let get_home = async |ca: &str| {
        let mut tls = env.connect_trusting(ca, &shop, env.https_port).await.unwrap();
        tls.write_all(format!("GET / HTTP/1.1\r\nHost: {shop}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut answer = String::new();
        tls.read_to_string(&mut answer).await.unwrap();
        answer
    };
    assert!(get_home(&ca).await.contains("hello from app"));

    // The management listener keeps its own, though the certificate names it.
    assert!(env.try_connect("localhost", env.mgmt_port).await.is_ok());
    assert!(env.connect_trusting(&ca, "localhost", env.mgmt_port).await.is_err());

    page = env.ui("/settings", Some(&admin), None).await;
    assert!(page.html.contains(&format!(r#"<span class="name">{shop}</span>"#)) && page.html.contains(">ready<") && page.html.contains("data-confirm=\"Remove the certificate for"), "{}", page.html);
    let (_, audit) = env.api("GET", "/api/v1/audit", Some(&token)).await;
    assert!(audit.to_string().contains("settings.certificate.add"), "{audit}");
    let config = env.ui("/settings/export", Some(&admin), None).await.html;
    assert!(config.contains("[[tls.certificates]]") && !config.contains(&key_body(&key)), "{config}");

    // One about to run out shows on the home page, for administrators.
    assert!(!env.ui("/", Some(&admin), None).await.html.contains("expiring soon"));
    let (_, soon_chain, soon_key) = common::own_certificate(&[&format!("late.app.{BASE}"), &shop], Some(10));
    env.ui(new, Some(&admin), Some(&[("csrf", &csrf), ("chain", &soon_chain), ("key", &soon_key)])).await;
    let home = env.ui("/", Some(&admin), None).await.html;
    assert!(home.contains(r##"<a href="/settings#certificates">1 of your certificates expiring soon</a>"##), "{home}");
    assert!(env.ui("/settings", Some(&admin), None).await.html.contains(">expires soon<"));
    assert!(get_home(&ca).await.contains("hello from app"), "the longer-lived one still serves it");

    // A restart keeps them.
    env.stop_server().await;
    env.start_server().await;
    let admin = admin_session(&env).await;
    let csrf = env.ui("/settings", Some(&admin), None).await.csrf();
    assert!(env.connect_trusting(&ca, &shop, env.https_port).await.is_ok());

    // Removing them hands the name back to the usual source, without being asked again.
    let page = env.ui("/settings", Some(&admin), None).await;
    let ids: Vec<&str> = page.html.split("/settings/certificates/").skip(1).filter_map(|s| s.split_once("/delete")).map(|(id, _)| id).filter(|id| id.len() == 16).collect();
    assert_eq!(ids.len(), 2, "{}", page.html);
    let remove = async |id: &str| env.ui(&format!("/settings/certificates/{id}/delete"), Some(&admin), Some(&[("csrf", &csrf)])).await;
    for id in &ids {
        assert_eq!(remove(id).await.location.as_deref(), Some("/settings?done=certificate-removed"));
    }
    let again = remove(ids[0]).await;
    assert!(again.status == StatusCode::NOT_FOUND && again.html.contains("already gone"), "{}", again.html);
    let start = std::time::Instant::now();
    while env.try_connect(&shop, env.https_port).await.is_err() {
        assert!(start.elapsed() < Duration::from_secs(10), "it never went back to the development CA");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(env.connect_trusting(&ca, &shop, env.https_port).await.is_err());
    assert!(env.ui("/settings", Some(&admin), None).await.html.contains("None yet"));
}

/// Certificates in the configuration file: read at startup, shown on the page, not removable there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_certificate_in_the_configuration_file_is_listed_and_kept() {
    let dir = std::env::temp_dir().join(format!("mpe2e-certs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let shop = format!("shop.app.{BASE}");
    let (ca, chain, key) = common::own_certificate(&[&shop], None);
    let (cert_file, key_file) = (dir.join("shop.crt"), dir.join("shop.key"));
    std::fs::write(&cert_file, chain).unwrap();
    std::fs::write(&key_file, key).unwrap();
    let mut env = Env::with_config(Tls::DevCa, &format!("[[tls.certificates]]\ncert_file = {cert_file:?}\nkey_file = {key_file:?}\n")).await;

    assert!(env.connect_trusting(&ca, &shop, env.https_port).await.is_ok());
    let admin = admin_session(&env).await;
    let page = env.ui("/settings", Some(&admin), None).await.html;
    assert!(page.contains("in the configuration file") && page.contains(&shop), "{page}");
    assert!(!page.contains("data-confirm=\"Remove the certificate"), "{page}");

    // A mistake in the file stops the server, as other configuration mistakes do.
    env.stop_server().await;
    std::fs::remove_file(&key_file).unwrap();
    let why = env.why_server_wont_start().await;
    assert!(why.contains("shop.key"), "{why}");
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settings_page_adds_providers_without_a_restart() {
    use std::os::unix::fs::PermissionsExt;
    let idp = common::FakeOidc::start().await;
    let mut env = Env::new(Tls::DevCa).await;
    let admin = admin_session(&env).await;
    let set = |p: common::OidcPerson| *idp.person.lock().unwrap() = p;
    let page = env.ui("/settings", Some(&admin), None).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.html.contains("None yet") && page.html.contains(r#"href="/settings"#), "{}", page.html);
    let csrf = page.csrf();

    // The generated configuration is there from the start.
    let generated = env.root.join("server/magicpipesd.generated.toml");
    let on_disk = || std::fs::read_to_string(&generated).unwrap();
    assert!(on_disk().contains("base_domain = "), "{}", on_disk());

    // The page says what to register, for the id it's going to use.
    let form = env.ui("/settings/providers/new?type=oidc", Some(&admin), None).await;
    assert!(form.html.contains(&format!("https://localhost:{}/auth/oidc/oidc/callback", env.mgmt_port)), "{}", form.html);
    assert!(form.html.contains(r#"name="id" value="oidc""#), "{}", form.html);
    let add = |url: &str, label: &str, csrf: &str| -> Vec<(String, String)> {
        [("csrf", csrf), ("type", "oidc"), ("id", "oidc"), ("url", url), ("label", label), ("client_id", common::OIDC_CLIENT), ("client_secret", common::OIDC_SECRET)]
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .to_vec()
    };
    let post = |fields: &[(String, String)]| fields.iter().map(|(k, v)| (k.clone(), v.clone())).collect::<Vec<_>>();
    let send = async |at: &str, fields: Vec<(String, String)>| {
        let pairs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        env.ui(at, Some(&admin), Some(&pairs)).await
    };

    // Without the session's CSRF token nothing happens.
    let r = send("/settings/providers/new", post(&add(&idp.issuer, "Fake ID", "wrong"))).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // A provider that can't be used is refused, with the reason, and what was typed comes back,
    // except the secret.
    let mut no_keys = common::OidcPerson::new("sub-1", "ann@example.com");
    no_keys.no_signing_keys = true;
    set(no_keys);
    let r = send("/settings/providers/new", post(&add(&idp.issuer, "Fake ID", &csrf))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.html);
    assert!(r.html.contains("no RS256 or ES256 signing key") && r.html.contains("Signing Key"), "{}", r.html);
    assert!(r.html.contains(r#"value="Fake ID""#) && !r.html.contains("secret/with"), "{}", r.html);
    set(common::OidcPerson::new("sub-1", "ann@example.com"));
    let r = send("/settings/providers/new", post(&add("http://idp.example.com", "Fake ID", &csrf))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.html);
    assert!(r.html.contains("https://"), "{}", r.html);
    assert!(!env.ui("/login", None, None).await.html.contains("Continue with"), "nothing was added");

    // A discovery URL does as well as the issuer, and the button is there at once.
    let r = send("/settings/providers/new", post(&add(&format!("{}/.well-known/openid-configuration", idp.issuer), "Fake ID", &csrf))).await;
    assert_eq!((r.status, r.location.as_deref()), (StatusCode::SEE_OTHER, Some("/settings?done=provider-added")), "{}", r.html);
    assert!(env.ui("/login", None, None).await.html.contains(r#"href="/auth/oidc/oidc""#));
    let r = send("/settings/providers/new", post(&add(&idp.issuer, "Again", &csrf))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "the same id and issuer again: {}", r.html);
    let r = env.ui("/settings/providers/new?type=oidc", Some(&admin), None).await;
    assert!(r.html.contains(r#"name="id" value="oidc-2""#), "the next one gets another id: {}", r.html);

    // The secret is a private file, and in neither the generated file nor the page.
    let secret_file = env.root.join("server/oidc-secrets/oidc");
    assert_eq!(std::fs::read_to_string(&secret_file).unwrap().trim(), common::OIDC_SECRET);
    assert_eq!(std::fs::metadata(&secret_file).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(secret_file.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(std::fs::metadata(&generated).unwrap().permissions().mode() & 0o777, 0o600);
    let text = on_disk();
    assert!(text.contains(&format!("issuer = \"{}\"", idp.issuer)) && text.contains("client_secret_file = ") && !text.contains("secret/with"), "{text}");
    let page = env.ui("/settings", Some(&admin), None).await;
    assert!(page.html.contains("Fake ID") && !page.html.contains("secret/with"), "{}", page.html);
    let export = env.ui("/settings/export", Some(&admin), None).await;
    assert_eq!((export.status, export.html.as_str()), (StatusCode::OK, text.as_str()));

    // Having an account at the provider still isn't enough, until the rules say so; no restart.
    set(common::OidcPerson::new("boss-1", "boss@example.com"));
    assert_eq!(oidc_sign_in_at(&env, "oidc", None).await.status, StatusCode::FORBIDDEN);
    let rules = |admins: &str, domains: &str| [("csrf", csrf.as_str()), ("bootstrap_admins", admins), ("email_domains", domains)].map(|(k, v)| (k.to_string(), v.to_string())).to_vec();
    let r = send("/settings/sign-in", rules("nobody", "")).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.html);
    assert!(r.html.contains("not an email address") && r.html.contains(">nobody</textarea>"), "{}", r.html);
    let r = send("/settings/sign-in", rules("Boss@Example.com", "team.example.com\nexample.org")).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.html);
    let boss = session_of(&oidc_sign_in_at(&env, "oidc", None).await);
    assert_eq!(env.ui("/settings", Some(&boss), None).await.status, StatusCode::OK, "a new administrator");
    assert!(on_disk().contains("boss@example.com") && on_disk().contains("team.example.com"), "{}", on_disk());

    // A member gets none of this.
    set(common::OidcPerson::new("dev-1", "dev@team.example.com"));
    let dev = session_of(&oidc_sign_in_at(&env, "oidc", None).await);
    for at in ["/settings", "/settings/export", "/settings/providers/new?type=google", "/settings/providers/oidc"] {
        let r = env.ui(at, Some(&dev), None).await;
        assert_eq!((r.status, r.location.as_deref()), (StatusCode::SEE_OTHER, Some("/account")), "{at}");
    }
    let member_page = env.ui("/account", Some(&dev), None).await;
    let member_csrf = member_page.csrf();
    let r = env.ui("/settings/providers/oidc/delete", Some(&dev), Some(&[("csrf", member_csrf.as_str())])).await;
    assert_eq!(r.location.as_deref(), Some("/account"));
    let r = env.ui("/settings/sign-in", Some(&dev), Some(&[("csrf", member_csrf.as_str()), ("bootstrap_admins", "dev@team.example.com")])).await;
    assert_eq!(r.location.as_deref(), Some("/account"));
    assert!(env.ui("/login", None, None).await.html.contains(r#"href="/auth/oidc/oidc""#), "still there");
    assert!(on_disk().contains("boss@example.com") && !on_disk().contains("dev@team.example.com"), "{}", on_disk());
    let (_, list) = env.api("GET", "/api/v1/users", Some(&env.admin_token())).await;
    assert_eq!(list["users"].as_array().unwrap().iter().find(|u| u["email"] == "dev@team.example.com").unwrap()["role"], "member");

    // An address the provider won't vouch for gets in only once the provider is trusted. Saving
    // without a new secret keeps the old one, or this sign-in would fail at the token endpoint.
    let mut unverified = common::OidcPerson::new("auth-1", "new@team.example.com");
    unverified.verified = false;
    set(unverified.clone());
    assert_eq!(oidc_sign_in_at(&env, "oidc", None).await.status, StatusCode::FORBIDDEN);
    let edit = env.ui("/settings/providers/oidc", Some(&admin), None).await;
    assert!(edit.html.contains(&idp.issuer) && !edit.html.contains("secret/with"), "{}", edit.html);
    let change = |extra: &[(&str, &str)]| {
        let mut f = vec![("csrf", csrf.as_str()), ("label", "Renamed"), ("client_id", common::OIDC_CLIENT), ("client_secret", "")];
        f.extend_from_slice(extra);
        f.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<Vec<_>>()
    };
    // Unverified administrators only follow from trusting the provider's addresses.
    let r = send("/settings/providers/oidc", change(&[("allow_unverified_admin", "on")])).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.html);
    let r = send("/settings/providers/oidc", change(&[("trust_email", "on")])).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.html);
    assert!(env.ui("/login", None, None).await.html.contains("Continue with Renamed"));
    assert!(on_disk().contains("trust_email = true"), "{}", on_disk());
    session_of(&oidc_sign_in_at(&env, "oidc", None).await);
    assert!(std::fs::read_to_string(env.root.join("server/oidc-secrets/oidc")).unwrap().contains("secret/with"), "kept");

    // It all survives a restart.
    env.stop_server().await;
    env.start_server().await;
    assert!(env.ui("/login", None, None).await.html.contains("Continue with Renamed"));
    set(common::OidcPerson::new("boss-1", "boss@example.com"));
    let boss = session_of(&oidc_sign_in_at(&env, "oidc", None).await);
    assert_eq!(env.ui("/settings", Some(&boss), None).await.status, StatusCode::OK);

    // Losing the secret turns off that provider only, and the page says so.
    let secret_file = env.root.join("server/oidc-secrets/oidc");
    let kept = std::fs::read(&secret_file).unwrap();
    std::fs::remove_file(&secret_file).unwrap();
    env.stop_server().await;
    env.start_server().await;
    let login = env.ui("/login", None, None).await;
    assert!(login.status == StatusCode::OK && !login.html.contains("Continue with"), "{}", login.html);
    let admin = admin_session(&env).await;
    let page = env.ui("/settings", Some(&admin), None).await;
    assert!(page.html.contains("Client secret can't be read"), "{}", page.html);
    let csrf = page.csrf();
    std::fs::write(&secret_file, kept).unwrap();

    // Removing it takes the button and the secret, and leaves the accounts.
    assert!(page.html.contains(r#"data-confirm="Remove Renamed?"#), "{}", page.html);
    let r = env.ui("/settings/providers/oidc/delete", Some(&admin), Some(&[("csrf", csrf.as_str())])).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.html);
    assert!(!secret_file.exists());
    assert!(!on_disk().contains("[[oidc]]"), "{}", on_disk());
    assert_eq!(env.ui("/auth/oidc/oidc", None, None).await.status, StatusCode::NOT_FOUND);
    let (_, list) = env.api("GET", "/api/v1/users", Some(&env.admin_token())).await;
    assert_eq!(list["users"].as_array().unwrap().len(), 3, "{list}");
    let audit = env.ui("/audit", Some(&admin), None).await;
    assert!(audit.html.contains("settings.oidc.create") && audit.html.contains("settings.oidc.delete") && audit.html.contains("settings.sign_in"), "{}", audit.html);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn providers_in_the_configuration_file_are_locked_on_the_settings_page() {
    let idp = common::FakeOidc::start().await;
    let dir = std::env::temp_dir().join(format!("mp-oidc-locked-{}", std::process::id()));
    let env = Env::with_config(Tls::DevCa, &idp.config(&dir, r#"bootstrap_admins = ["boss@example.com"]"#, false)).await;
    let admin = admin_session(&env).await;
    let page = env.ui("/settings", Some(&admin), None).await;
    assert!(page.html.contains("in the configuration file") && !page.html.contains(r#"href="/settings/providers/fake""#), "{}", page.html);
    assert!(page.html.contains("from the configuration file: boss@example.com"), "{}", page.html);
    let csrf = page.csrf();

    // It can't be changed, removed or added again under another id.
    assert_eq!(env.ui("/settings/providers/fake", Some(&admin), None).await.location.as_deref(), Some("/settings"));
    let r = env.ui("/settings/providers/fake", Some(&admin), Some(&[("csrf", csrf.as_str()), ("label", "Changed"), ("client_id", "c")])).await;
    assert_eq!(r.location.as_deref(), Some("/settings"));
    env.ui("/settings/providers/fake/delete", Some(&admin), Some(&[("csrf", csrf.as_str())])).await;
    let again = [("csrf", csrf.as_str()), ("type", "oidc"), ("id", "other"), ("url", idp.issuer.as_str()), ("label", "Other"), ("client_id", "c"), ("client_secret", "s")];
    assert_eq!(env.ui("/settings/providers/new", Some(&admin), Some(&again)).await.status, StatusCode::BAD_REQUEST);
    assert!(env.ui("/login", None, None).await.html.contains("Continue with Fake ID"));
    assert!(dir.join("oidc-secret").exists());

    // Saved rules add to the file's; they don't replace them.
    env.ui("/settings/sign-in", Some(&admin), Some(&[("csrf", csrf.as_str()), ("email_domains", "team.example.com")])).await;
    let text = env.ui("/settings/export", Some(&admin), None).await.html;
    assert!(text.contains("boss@example.com") && text.contains("team.example.com") && text.contains("id = \"fake\""), "{text}");
    set_and_sign_in(&idp, &env, "boss-1", "boss@example.com").await;
    set_and_sign_in(&idp, &env, "dev-1", "dev@team.example.com").await;
    std::fs::remove_dir_all(&dir).ok();
}

async fn set_and_sign_in(idp: &common::FakeOidc, env: &Env, sub: &str, email: &str) {
    *idp.person.lock().unwrap() = common::OidcPerson::new(sub, email);
    session_of(&oidc_sign_in(env, None).await);
}

/// The same as `browser_signs_in_to_private_tunnels`, through an OpenID Connect provider: the
/// private tunnel sends the browser to the sign-in page, its link to the provider, the provider
/// back to the callback, and the callback on to the tunnel. Cookies have to survive coming back
/// from another site, and nothing on the way may trip the CSP. Run it like that test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Chrome and Node"]
async fn browser_signs_in_with_oidc() {
    let chrome = std::env::var("MAGICPIPES_CHROME").unwrap_or_else(|_| {
        if cfg!(target_os = "macos") { "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into() } else { "google-chrome".into() }
    });
    let idp = common::FakeOidc::start().await;
    let dir = std::env::temp_dir().join(format!("mp-oidc-browser-{}", std::process::id()));
    let env = Env::with_config(Tls::DevCa, &idp.config(&dir, r#"allowed_email_domains = ["example.com"]"#, false)).await;
    let admin = env.admin_token();

    // Ann signs in once, which makes her account, and enrolls a machine that serves the tunnels.
    let session = session_of(&oidc_sign_in(&env, None).await);
    assert_eq!(env.ui("/account", Some(&session), None).await.status, StatusCode::OK);
    let (_, list) = env.api("GET", "/api/v1/users", Some(&admin)).await;
    let ann = list["users"][0]["id"].as_str().unwrap().to_string();
    let body = serde_json::json!({ "owner_user_id": ann });
    let (_, v) = env.api_json("POST", "/api/v1/enrollments", Some(&admin), body).await;
    let (url, ca) = (env.server_url(), env.ca_path.to_string_lossy().to_string());
    env.cli_ok(&["login", "--server", &url, "--token", v["enrollment_token"].as_str().unwrap(), "--ca-cert", &ca, "--name", "laptop"]).await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let first = add_json(&env, &[&app.port.to_string(), "--private", "--name", "one"]).await;
    let second = add_json(&env, &[&app.port.to_string(), "--private", "--name", "two"]).await;

    // A fresh browser, not signed in to anything.
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/browser-sign-in.mjs");
    let profile = std::env::temp_dir().join(format!("mp-chrome-oidc-{}", std::process::id()));
    let opts = serde_json::json!({
        "chrome": chrome,
        "first": format!("{}/", first["public_url"].as_str().unwrap()),
        "second": format!("{}/", second["public_url"].as_str().unwrap()),
        "management": url,
        "sso": "Continue with Fake ID",
        "resolve": format!("MAP *.{BASE} 127.0.0.1"),
        "profile": profile,
    });
    let out = tokio::process::Command::new("node").arg(&script).arg(opts.to_string()).output().await.expect("run node");
    std::fs::remove_dir_all(&profile).ok();
    let result: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&out.stderr)));

    assert!(result["first"]["url"].as_str().unwrap_or("").starts_with(first["public_url"].as_str().unwrap()), "{result}");
    assert_eq!(result["first"]["text"], "hello from app", "{result}");
    assert!(result["second"]["url"].as_str().unwrap_or("").starts_with(second["public_url"].as_str().unwrap()), "{result}");
    assert_eq!(result["second"]["text"], "hello from app", "{result}");
    assert!(result["errors"].as_array().unwrap().is_empty(), "the browser reported errors: {result}");
    env.cli_ok(&["agent", "stop"]).await;
    idp.task.abort();
    std::fs::remove_dir_all(&dir).ok();
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
