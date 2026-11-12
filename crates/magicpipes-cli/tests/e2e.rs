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
    let bytes = common::body(resp, "an archive download").await;
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
        let (env, host) = (&env, &host);
        async move {
            let resp = env.send(host, env.https_port, req).await;
            assert_eq!(resp.status(), 200, "HEAD {path}: {:?}", resp.headers());
            resp.headers()[header::CONTENT_TYPE].to_str().unwrap().to_string()
        }
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
/// The value of one series in `/metrics`, such as `magicpipes_tunnel_requests_total{tunnel="web"}`.
fn metric(text: &str, series: &str) -> f64 {
    text.lines()
        .find_map(|l| l.strip_prefix(series)?.strip_prefix(' ')?.parse().ok())
        .unwrap_or_else(|| panic!("{series} missing from:\n{text}"))
}

/// The values of a metric's series whose labels include `with`.
fn metrics_with(text: &str, name: &str, with: &str) -> Vec<f64> {
    let prefix = format!("{name}{{");
    text.lines().filter(|l| l.starts_with(&prefix) && l.contains(with)).filter_map(|l| l.rsplit(' ').next()?.parse().ok()).collect()
}

/// `/metrics` is for administrators, and counts what tunnels carry: requests and why they failed,
/// how long the app took, bytes each way, and the machine's connections and round trips.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metrics_count_what_tunnels_carry() {
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let echo = common::tcp_echo_app().await;
    let web = add_json(&env, &[&app.port.to_string(), "--name", "web"]).await;
    let host = hostname(web["public_url"].as_str().unwrap());
    let tcp = add_json(&env, &[&echo.port.to_string(), "--tcp", "--allow-any", "--name", "echo"]).await;
    let port = tcp["public_port"].as_u64().unwrap() as u16;
    let dns = common::udp_echo_app().await;
    let udp = add_json(&env, &[&dns.port.to_string(), "--udp", "--allow-any", "--name", "dns"]).await;
    let udp_port = udp["public_port"].as_u64().unwrap() as u16;

    // Administrators only, with a bearer token or signed in.
    let admin = env.admin_token();
    assert_eq!(env.mgmt_text("/metrics", None, None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(env.mgmt_text("/metrics", Some("mpadm_wrong"), None).await.0, StatusCode::UNAUTHORIZED);
    let (status, kind, _) = env.mgmt_text("/metrics", Some(&admin), None).await;
    assert_eq!((status, kind.as_str()), (StatusCode::OK, "text/plain; version=0.0.4; charset=utf-8"));
    let signed_in = env.ui("/login", None, Some(&[("token", &admin)])).await.cookie.expect("signed in");
    assert_eq!(env.mgmt_text("/metrics", None, Some(&signed_in)).await.0, StatusCode::OK);
    let read = || async { env.mgmt_text("/metrics", Some(&admin), None).await.2 };

    // HTTP: requests, their times and bytes each way.
    let before = read().await;
    for _ in 0..3 {
        assert_eq!(env.get_public(&host, "/").await.2, "hello from app");
    }
    let req = Request::post("/echo").header(header::HOST, &host).body(Full::new(Bytes::from(vec![7u8; 1000]))).unwrap();
    let resp = env.send(&host, env.https_port, req).await;
    assert_eq!(resp.into_body().collect().await.unwrap().to_bytes().len(), 1000);
    let after = read().await;
    let grew = |series: &str| metric(&after, series) - metric(&before, series);
    assert_eq!(grew(r#"magicpipes_tunnel_requests_total{tunnel="web"}"#), 4.0, "{after}");
    assert_eq!(grew(r#"magicpipes_tunnel_response_seconds_count{tunnel="web"}"#), 4.0);
    assert_eq!(grew(r#"magicpipes_tunnel_response_seconds_bucket{tunnel="web",le="+Inf"}"#), 4.0);
    assert!(grew(r#"magicpipes_tunnel_response_seconds_sum{tunnel="web"}"#) > 0.0);
    assert_eq!(grew(r#"magicpipes_tunnel_bytes_total{tunnel="web",direction="to_app"}"#), 1000.0);
    assert_eq!(grew(r#"magicpipes_tunnel_bytes_total{tunnel="web",direction="from_app"}"#), 3.0 * 14.0 + 1000.0);
    assert_eq!(metric(&after, r#"magicpipes_tunnel_up{tunnel="web"}"#), 1.0);
    assert_eq!(metric(&after, &format!("magicpipes_certificate_ready{{hostname=\"{host}\"}}")), 1.0);
    let expires = metric(&after, &format!("magicpipes_certificate_expiry_time_seconds{{hostname=\"{host}\"}}"));
    assert!(expires > magicpipes_core::unix_now() as f64, "{expires}");

    // A TCP port: the connection, and every byte joined through.
    let before = read().await;
    let msg: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(tcp_roundtrip(port, &msg).await, msg);
    let after = read().await;
    let grew = |series: &str| metric(&after, series) - metric(&before, series);
    assert_eq!(grew(r#"magicpipes_tunnel_requests_total{tunnel="echo"}"#), 1.0);
    assert_eq!(grew(r#"magicpipes_tunnel_response_seconds_count{tunnel="echo"}"#), 1.0);
    assert_eq!(grew(r#"magicpipes_tunnel_bytes_total{tunnel="echo",direction="to_app"}"#), 50_000.0);
    assert_eq!(grew(r#"magicpipes_tunnel_bytes_total{tunnel="echo",direction="from_app"}"#), 50_000.0);

    // UDP: each datagram's payload, each way (a datagram that got no answer is sent again).
    let before = read().await;
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let reply = udp_roundtrip(&client, udp_port, &[9u8; 300]).await;
    assert!(reply.starts_with(b"echo:") && reply.len() == 305, "{reply:?}");
    let after = read().await;
    for (direction, size) in [("to_app", 300.0), ("from_app", 305.0)] {
        let series = format!("magicpipes_tunnel_bytes_total{{tunnel=\"dns\",direction=\"{direction}\"}}");
        let grew = metric(&after, &series) - metric(&before, &series);
        assert!(grew >= size && grew % size == 0.0, "{direction}: {grew}");
    }

    // The machine: connected, its connections, and a round trip timed on each.
    env.eventually("a round trip timed on the agent's connection", Duration::from_secs(10), || async {
        metrics_with(&read().await, "magicpipes_agent_ping_seconds", r#"connection="1""#).iter().any(|s| *s > 0.0 && *s < 5.0)
    })
    .await;
    let text = read().await;
    assert_eq!(metrics_with(&text, "magicpipes_agent_up", "agent_id="), [1.0], "{text}");
    assert!(metrics_with(&text, "magicpipes_agent_connections", "agent_id=").iter().all(|n| *n >= 1.0), "{text}");

    // Failures, by cause: the app gone, then the machine.
    app.stop();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let before = read().await;
    assert_eq!(env.get_public(&host, "/").await.1.as_deref(), Some("local_unreachable"));
    let after = read().await;
    let grew = |series: &str| metric(&after, series) - metric(&before, series);
    assert!(grew(r#"magicpipes_tunnel_failures_total{tunnel="web",cause="local_unreachable"}"#) >= 1.0, "{after}");
    assert_eq!(grew(r#"magicpipes_tunnel_failures_total{tunnel="web",cause="agent_offline"}"#), 0.0);

    env.cli_ok(&["agent", "stop"]).await;
    env.eventually("the tunnel shown down", Duration::from_secs(10), || async {
        metric(&read().await, r#"magicpipes_tunnel_up{tunnel="web"}"#) == 0.0
    })
    .await;
    let before = read().await;
    assert_eq!(env.get_public(&host, "/").await.1.as_deref(), Some("agent_offline"));
    let after = read().await;
    assert_eq!(metric(&after, r#"magicpipes_tunnel_failures_total{tunnel="web",cause="agent_offline"}"#)
        - metric(&before, r#"magicpipes_tunnel_failures_total{tunnel="web",cause="agent_offline"}"#), 1.0);
    assert_eq!(metrics_with(&after, "magicpipes_agent_up", "agent_id="), [0.0]);
    assert!(metrics_with(&after, "magicpipes_agent_ping_seconds", "agent_id=").is_empty(), "{after}");
}

/// The Health page lists tunnels and machines with what they did lately, and the tunnel's and the
/// machine's pages chart it; the history comes from samples taken every 10 seconds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_and_history_show_what_tunnels_carried() {
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let web = add_json(&env, &[&app.port.to_string(), "--name", "web"]).await;
    let host = hostname(web["public_url"].as_str().unwrap());
    let id = web["id"].as_str().unwrap().to_string();
    let admin = env.admin_token();
    let (_, agents) = env.api("GET", "/api/v1/agents", Some(&admin)).await;
    let agent = agents["agents"][0]["id"].as_str().unwrap().to_string();
    let cookie = admin_session(&env).await;

    for _ in 0..3 {
        assert_eq!(env.get_public(&host, "/").await.0, StatusCode::OK);
    }
    // Requests show once a sample has seen them: a number, and the tiny chart beside it. `add`'s
    // readiness probe was one too.
    let row = format!(r#"<a class="name" href="/tunnels/{id}">web</a>"#);
    env.eventually("a sample with the requests", Duration::from_secs(25), || async {
        let html = env.ui("/health", Some(&cookie), None).await.html;
        html.split(&row).nth(1).is_some_and(|rest| rest.contains(r#"<td class="num">4<svg class="spark""#))
    })
    .await;
    let health = env.ui("/health", Some(&cookie), None).await;
    assert_eq!(health.status, StatusCode::OK);
    assert!(health.html.contains(r#"href="/health" aria-current="page">Health</a>"#), "in the navigation");
    assert!(health.html.contains("Everything is working: no failures in the last 15 minutes"), "{}", health.html);
    assert!(health.html.contains(&format!(r#"href="/machines/{agent}""#)) && health.html.contains("Round trip"), "{}", health.html);
    assert!(health.html.contains(r#"<a class="btn small ghost" href="/health" aria-current="page">Last 15 minutes</a>"#));

    let page = env.ui(&format!("/tunnels/{id}"), Some(&cookie), None).await;
    assert!(page.html.contains("<h2>Traffic</h2>") && page.html.contains("4 requests in all"), "{}", page.html);
    assert!(page.html.contains(r#"<svg viewBox="0 0 900 100" preserveAspectRatio="none" role="img""#), "a chart of 90 slots: {}", page.html);
    assert!(page.html.contains("Couldn't reach app</h3><p class=\"sum\">None in the last 15 minutes."), "{}", page.html);
    let day = env.ui(&format!("/tunnels/{id}?period=24h"), Some(&cookie), None).await;
    assert!(day.html.contains(r#"aria-current="page">Last 24 hours</a>"#) && day.html.contains("4 requests in all"), "{}", day.html);
    assert!(day.html.contains(r#"<svg viewBox="0 0 2880 100""#), "288 slots of 5 minutes");

    // A machine's page: its connections, and the round trips timed on them.
    env.eventually("a round trip in a sample", Duration::from_secs(25), || async {
        env.ui(&format!("/machines/{agent}"), Some(&cookie), None).await.html.contains(r#"<h3>Round trip</h3><p class="sum">Average"#)
    })
    .await;
    let machine = env.ui(&format!("/machines/{agent}"), Some(&cookie), None).await;
    assert!(machine.html.contains("<h3>Connections</h3>") && machine.html.contains(&format!(r#"href="/tunnels/{id}">web</a>"#)), "{}", machine.html);
    assert!(machine.html.contains(&format!(r#"action="/agents/{agent}/revoke""#)));
    let nobody = env.ui("/machines/ag_nobody", Some(&cookie), None).await;
    assert_eq!(nobody.status, StatusCode::NOT_FOUND, "{}", nobody.html);
    assert!(env.ui("/machines", Some(&cookie), None).await.html.contains(&format!(r#"<a class="name" href="/machines/{agent}">"#)));

    // The app gone: the page says which tunnel, and why.
    app.stop();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(env.get_public(&host, "/").await.1.as_deref(), Some("local_unreachable"));
    env.eventually("the failure in a sample", Duration::from_secs(25), || async {
        let html = env.ui("/health", Some(&cookie), None).await.html;
        html.contains("1 tunnel couldn't reach its app in the last 15 minutes") && html.contains("app down 1")
    })
    .await;
    // Without a session, the sign-in page.
    assert_eq!(env.ui("/health", None, None).await.location.as_deref(), Some("/login?next=%2Fhealth"));
}

/// A tunnel whose app is down gets an alert once it has lasted two samples: on the Health page, as
/// a count in the navigation, on the tunnel's page and in `/metrics`. Open alerts outlast a
/// restart, and close after three fine samples.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_alert_opens_shows_everywhere_and_closes() {
    let mut env = Env::new(Tls::DevCa).await;
    env.login().await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let web = add_json(&env, &[&app.port.to_string(), "--name", "web"]).await;
    let host = hostname(web["public_url"].as_str().unwrap());
    let id = web["id"].as_str().unwrap().to_string();
    let cookie = admin_session(&env).await;
    assert!(!env.ui("/health", Some(&cookie), None).await.html.contains(r#"class="pill"#), "no alerts yet");

    // Over 5% of at least 20 requests in 5 minutes couldn't reach the app.
    app.stop();
    tokio::time::sleep(Duration::from_millis(200)).await;
    // A pooled connection may not have seen the app go yet: count the answers that say so.
    let mut unreachable = 0;
    for _ in 0..40 {
        if env.get_public(&host, "/").await.1.as_deref() == Some("local_unreachable") {
            unreachable += 1;
        }
        if unreachable == 20 {
            break;
        }
    }
    assert_eq!(unreachable, 20);
    env.eventually("the alert to open", Duration::from_secs(40), || async {
        env.ui("/health", Some(&cookie), None).await.html.contains(r#"<h2>Alerts<span class="count">1</span></h2>"#)
    })
    .await;
    let health = env.ui("/health", Some(&cookie), None).await.html;
    assert!(health.contains(r#"Health<span class="pill bad">1<span class="sr"> open alert</span></span></a>"#), "in the navigation: {health}");
    assert!(health.contains("1 open alert</a>: web: couldn&#39;t reach app"), "{health}");
    assert!(health.contains("20 of ") && health.contains(" requests in the last 5 minutes (") && health.contains(&format!(r#"href="/tunnels/{id}">web</a>"#)), "{health}");
    let page = env.ui(&format!("/tunnels/{id}"), Some(&cookie), None).await.html;
    assert!(page.contains(r#"<div class="notice bad"><span class="status bad">Couldn&#39;t reach app</span>20 of "#), "{page}");
    let (_, _, metrics) = env.mgmt_text("/metrics", Some(&env.admin_token()), None).await;
    assert!(metrics.contains(r#"magicpipes_alerts_open{severity="bad"} 1"#), "{metrics}");

    // It was kept: after a restart it's still open, until three fine samples close it.
    env.stop_server().await;
    env.start_server().await;
    let cookie = admin_session(&env).await;
    let health = env.ui("/health", Some(&cookie), None).await.html;
    assert!(health.contains(r#"<h2>Alerts<span class="count">1</span></h2>"#), "kept over a restart: {health}");
    env.eventually("the alert to close", Duration::from_secs(60), || async {
        let html = env.ui("/health", Some(&cookie), None).await.html;
        !html.contains("<h2>Alerts") && html.contains("1 alert closed in the last 24 hours")
    })
    .await;
    // Longer periods come from the database, with the minutes not yet in it.
    let week = env.ui(&format!("/tunnels/{id}?period=7d"), Some(&cookie), None).await.html;
    assert!(week.contains(r#"aria-current="page">Last 7 days</a>"#) && week.contains(r#"<svg viewBox="0 0 1680 100""#), "{week}");
    assert!(!week.contains("Last 30 days"), "only what's kept is offered");
}

/// The server checks each tunnel's app through its machine, says how it went on the tunnel's
/// page, and opens an alert once two checks in a row fail. `add --no-check` turns it off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_server_checks_tunnels_and_says_when_one_fails() {
    let env = Env::with_config(Tls::DevCa, "[monitoring]\ncheck_interval_secs = 10\n").await;
    env.login().await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let echo = common::tcp_echo_app().await;
    let web = add_json(&env, &[&app.port.to_string(), "--name", "web", "--probe-path", "/health"]).await;
    let port = add_json(&env, &[&echo.port.to_string(), "--tcp", "--allow-any", "--name", "echo"]).await;
    let quiet = add_json(&env, &[&app.port.to_string(), "--name", "quiet", "--no-check"]).await;
    let id = |t: &Value| t["id"].as_str().unwrap().to_string();
    let admin = env.admin_token();
    let (_, v) = env.api("GET", &format!("/api/v1/tunnels/{}", id(&web)), Some(&admin)).await;
    assert_eq!((v["checks"].as_bool(), v["check_path"].as_str()), (Some(true), Some("/health")), "{v}");
    let (_, v) = env.api("GET", &format!("/api/v1/tunnels/{}", id(&quiet)), Some(&admin)).await;
    assert_eq!(v["checks"].as_bool(), Some(false), "{v}");
    let cookie = admin_session(&env).await;

    // Any answer counts: the test app has no /health, and says 404.
    env.eventually("both checked", Duration::from_secs(30), || async {
        let web = env.ui(&format!("/tunnels/{}", id(&web)), Some(&cookie), None).await.html;
        let echo = env.ui(&format!("/tunnels/{}", id(&port)), Some(&cookie), None).await.html;
        web.contains(r#"<span class="status ok">passed</span>"#) && web.contains("HTTP 404 for /health") && echo.contains("Its machine reached the app")
    })
    .await;
    let page = env.ui(&format!("/tunnels/{}", id(&quiet)), Some(&cookie), None).await.html;
    assert!(page.contains("<dt>Check</dt><dd>Off.") && page.contains("without <code>--no-check</code>"), "{page}");

    // The app goes: two failed checks in a row open an alert.
    app.stop();
    env.eventually("the check alert", Duration::from_secs(60), || async {
        // However many it has been by the time it opens.
        // With what the machine saw.
        let refused = format!(" checks failed: Couldn&#39;t reach the app: connection refused by 127.0.0.1:{}.", app.port);
        env.ui("/health", Some(&cookie), None).await.html.contains(&refused)
    })
    .await;
    let page = env.ui(&format!("/tunnels/{}", id(&web)), Some(&cookie), None).await.html;
    assert!(page.contains(r#"<div class="notice bad"><span class="status bad">Check failing</span>"#) && page.contains("times in a row"), "{page}");
    // Its status says so, with no visitor needed to find out.
    let (_, v) = env.api("GET", &format!("/api/v1/tunnels/{}", id(&web)), Some(&admin)).await;
    assert_eq!(v["status"], "error", "{v}");
    // Only the tunnel that's checked: `quiet` reaches the same app, without checks.
    let health = env.ui("/health", Some(&cookie), None).await.html;
    assert_eq!(health.matches(r#"<span class="status bad">Check failing</span>"#).count(), 1, "{health}");
    assert!(health.contains("check failed") && health.contains("not checked"), "{health}");
}

/// Each delivery's `X-MagicPipes-Event` and `X-MagicPipes-Signature` headers, and its body.
type Deliveries = Arc<std::sync::Mutex<Vec<(String, String, Vec<u8>)>>>;

/// What an alert webhook received.
struct Catcher {
    port: u16,
    got: Deliveries,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Catcher {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Catcher {
    async fn start() -> Catcher {
        use hyper::service::service_fn;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let got = Arc::new(std::sync::Mutex::new(Vec::new()));
        let kept = got.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                let kept = kept.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                        let kept = kept.clone();
                        async move {
                            let h = |n: &str| req.headers().get(n).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
                            let (event, signature) = (h("x-magicpipes-event"), h("x-magicpipes-signature"));
                            let body = req.into_body().collect().await.map(|b| b.to_bytes().to_vec()).unwrap_or_default();
                            kept.lock().unwrap().push((event, signature, body));
                            Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(Bytes::from_static(b"ok"))))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tcp), svc).await;
                });
            }
        });
        Catcher { port, got, task }
    }

    /// The bodies of deliveries for `event`, as JSON, each checked against `secret`.
    fn deliveries(&self, event: &str, secret: &str) -> Vec<Value> {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
        self.got
            .lock()
            .unwrap()
            .iter()
            .filter(|(e, _, _)| e == event)
            .map(|(_, signature, body)| {
                let hex: String = ring::hmac::sign(&key, body).as_ref().iter().map(|b| format!("{b:02x}")).collect();
                assert_eq!(*signature, format!("sha256={hex}"), "signed with the secret shown");
                serde_json::from_slice(body).unwrap()
            })
            .collect()
    }
}

/// Alerts reach people: as a signed webhook post when one opens or closes, and by email to an
/// administrator who asked for it. `magicpipes probe` checks addresses from outside and reports,
/// and two failed reports in a row open an alert.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alerts_go_out_by_webhook_and_email_and_the_probe_reports_from_outside() {
    let smtp = common::FakeSmtp::start().await;
    let env = Env::with_config(Tls::DevCa, &smtp.config()).await;
    env.login().await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let echo = common::tcp_echo_app().await;
    let web = add_json(&env, &[&app.port.to_string(), "--name", "web"]).await;
    let port = add_json(&env, &[&echo.port.to_string(), "--tcp", "--allow-any", "--name", "echo"]).await;
    let id = |t: &Value| t["id"].as_str().unwrap().to_string();

    // Ann, an administrator, asks for alert email. The machine is a service agent, which is hers to
    // hear about.
    let body = serde_json::json!({ "email": "ann@example.com", "role": "admin" });
    let (status, v) = env.api_json("POST", "/api/v1/invitations", Some(&env.admin_token()), body).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    let code = smtp.wait_for("ann@example.com", 1).await.code();
    let password = "a long password for ann";
    let r = env.ui("/invite/accept", None, Some(&[("code", code.as_str()), ("display_name", ""), ("password", password), ("repeat", password)])).await;
    let ann = r.cookie.unwrap_or_else(|| panic!("no session: {}", r.html));
    let account = env.ui("/account", Some(&ann), None).await;
    assert!(account.html.contains("Send alerts to ann@example.com") && account.html.contains("service agents and the server"), "{}", account.html);
    let saved = env.ui("/account/alerts", Some(&ann), Some(&[("csrf", &account.csrf()), ("alert_email", "mine")])).await;
    assert_eq!(saved.location.as_deref(), Some("/account?done=alert-email-on"), "{}", saved.html);
    assert!(env.ui("/account", Some(&ann), None).await.html.contains(r#"value="mine" checked"#));

    // A webhook, added on the Settings page, with a secret shown once; a test reaches it, signed.
    let hook = Catcher::start().await;
    let admin = admin_session(&env).await;
    let settings = env.ui("/settings", Some(&admin), None).await;
    assert!(settings.html.contains(r#"href="/settings/webhooks/new">Add webhook</a>"#), "{}", settings.html);
    let form = env.ui("/settings/webhooks/new", Some(&admin), None).await;
    let refused = env.ui("/settings/webhooks", Some(&admin), Some(&[("csrf", &form.csrf()), ("name", "ops"), ("url", "http://hooks.example.com/x")])).await;
    assert!(refused.html.contains("Use an https:// address, or http:// to this machine.") && refused.html.contains(r#"value="ops""#), "{}", refused.html);
    let url = format!("http://127.0.0.1:{}/hook", hook.port);
    let added = env.ui("/settings/webhooks", Some(&admin), Some(&[("csrf", &form.csrf()), ("name", "ops"), ("url", &url)])).await;
    let secret = shown_secret(&added.html);
    let settings = env.ui("/settings", Some(&admin), None).await;
    assert!(settings.html.contains("nothing sent yet") && !settings.html.contains(&url), "the address can be a secret too: {}", settings.html);
    let test = settings.html.split(r#"action="/settings/webhooks/"#).nth(1).unwrap().split('"').next().unwrap().to_string();
    let tested = env.ui(&format!("/settings/webhooks/{test}"), Some(&admin), Some(&[("csrf", &settings.csrf())])).await;
    assert_eq!(tested.location.as_deref(), Some("/settings?done=webhook-tested"), "{}", tested.html);
    assert_eq!(hook.deliveries("test", &secret).len(), 1);
    assert!(env.ui("/settings", Some(&admin), None).await.html.contains("delivered "));

    // The probe, run "outside": the TCP port connects, and the tunnel's page says so.
    let token = api_token(&env, &ann).await;
    let ca = env.ca_path.to_string_lossy().to_string();
    let out = env.cli_with(&[("MAGICPIPES_API_TOKEN", &token)], &["probe", "echo", "--server", &env.server_url(), "--ca-cert", &ca, "--json"]).await;
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)));
    assert!(out.status.success(), "{v}");
    assert_eq!((v["results"][0]["name"].as_str(), v["results"][0]["ok"].as_bool(), v["reported"].as_bool()), (Some("echo"), Some(true), Some(true)), "{v}");
    let page = env.ui(&format!("/tunnels/{}", id(&port)), Some(&ann), None).await.html;
    assert!(page.contains(r#"<dt>From outside</dt><dd><span class="status ok">passed</span>"#) && page.contains("connected in"), "{page}");
    let out = env.cli_with(&[("MAGICPIPES_API_TOKEN", &token)], &["probe", "nothing-here", "--server", &env.server_url(), "--ca-cert", &ca]).await;
    assert_eq!(out.status.code(), Some(6), "not_found: {}", String::from_utf8_lossy(&out.stderr));

    // A member's report on tunnels that aren't theirs counts for nothing.
    let (_, v) = env.api_json("POST", "/api/v1/users", Some(&env.admin_token()), serde_json::json!({ "email": "pat@example.com", "password": "correct horse battery" })).await;
    assert!(v["user"]["id"].is_string(), "{v}");
    let first = env.ui("/login", None, Some(&[("email", "pat@example.com"), ("password", "correct horse battery")])).await;
    let pat = first.cookie.unwrap();
    let form = env.ui("/password", Some(&pat), None).await;
    let new = "another correct horse battery";
    let pat = env.ui("/password", Some(&pat), Some(&[("csrf", &form.csrf()), ("current", "correct horse battery"), ("new", new), ("repeat", new)])).await.cookie.unwrap();
    let pats = api_token(&env, &pat).await;
    let report = |ok: bool| serde_json::json!({ "results": [{ "tunnel": id(&web), "ok": ok, "said": "couldn't look up web.t.test" }] });
    for _ in 0..3 {
        let (status, v) = env.api_json("POST", "/api/v1/probes", Some(&pats), report(false)).await;
        assert_eq!((status, v["kept"].as_u64()), (StatusCode::OK, Some(0)), "{v}");
    }

    // Two failures in a row open an alert: the webhook hears at once, Ann by email shortly after.
    for _ in 0..2 {
        let (status, v) = env.api_json("POST", "/api/v1/probes", Some(&token), report(false)).await;
        assert_eq!((status, v["kept"].as_u64()), (StatusCode::OK, Some(1)), "{v}");
    }
    env.eventually("the webhook to hear of the alert", Duration::from_secs(40), || async { !hook.deliveries("opened", &secret).is_empty() }).await;
    let opened = hook.deliveries("opened", &secret).remove(0);
    assert_eq!((opened["alert"]["rule"].as_str(), opened["alert"]["severity"].as_str()), (Some("outside_failing"), Some("bad")), "{opened}");
    let text = opened["text"].as_str().unwrap();
    assert!(text.starts_with("Opened: Unreachable from outside, web. The last 2 checks from outside failed: couldn't look up web.t.test"), "{text}");
    assert!(text.ends_with(&format!("{}/tunnels/{}", env.server_url(), id(&web))), "{text}");
    // Fine again: three fine samples close it, and the webhook hears that too.
    env.api_json("POST", "/api/v1/probes", Some(&token), report(true)).await;
    env.eventually("Ann's alert email", Duration::from_secs(60), || async { smtp.sent_to("ann@example.com").len() >= 2 }).await;
    let mail = smtp.sent_to("ann@example.com").remove(1).text;
    assert!(mail.contains("Unreachable from outside, web") && mail.contains(&format!("{}/tunnels/{}", env.server_url(), id(&web))), "{mail}");
    env.eventually("the webhook to hear it closed", Duration::from_secs(60), || async { !hook.deliveries("closed", &secret).is_empty() }).await;
}

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

/// Waits for `magicpipes connect --json` to say where it listens, and returns that port.
async fn connect_port(child: &mut tokio::process::Child) -> u16 {
    use tokio::io::AsyncBufReadExt;
    let mut line = String::new();
    let mut stdout = tokio::io::BufReader::new(child.stdout.as_mut().unwrap());
    tokio::time::timeout(Duration::from_secs(60), stdout.read_line(&mut line)).await.expect("connect never said where it listens").unwrap();
    let v: Value = serde_json::from_str(&line).unwrap_or_else(|_| panic!("not where it listens: {line:?}"));
    v["local"].as_str().unwrap().parse::<std::net::SocketAddr>().unwrap().port()
}

/// What a `magicpipes` process that ended said last on stdout, as JSON.
fn last_json(out: &std::process::Output) -> Value {
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(stdout.lines().last().unwrap_or_default()).unwrap_or_else(|_| panic!("{stdout}{}", String::from_utf8_lossy(&out.stderr)))
}

/// A user's new API token, made on their account page.
async fn api_token(env: &Env, cookie: &str) -> String {
    let account = env.ui("/account", Some(cookie), None).await;
    shown_secret(&env.ui("/account/tokens", Some(cookie), Some(&[("csrf", &account.csrf()), ("name", "connect")])).await.html)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_reaches_private_port_tunnels() {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
    let env = Env::new(Tls::DevCa).await;
    let admin = env.admin_token();
    env.api_json("POST", "/api/v1/tags", Some(&admin), serde_json::json!({ "name": "team:dev" })).await;
    let mut ids = std::collections::HashMap::new();
    for (email, tags) in [("ann@example.com", vec!["team:dev"]), ("bob@example.com", vec![])] {
        let (_, v) = env.api_json("POST", "/api/v1/users", Some(&admin), serde_json::json!({ "email": email, "password": "correct horse battery" })).await;
        let id = v["user"]["id"].as_str().unwrap().to_string();
        env.api_json("PATCH", &format!("/api/v1/users/{id}"), Some(&admin), serde_json::json!({ "tags": tags })).await;
        ids.insert(email, id);
    }
    let (ann, bob) = (sign_in(&env, "ann@example.com", "correct horse battery").await, sign_in(&env, "bob@example.com", "correct horse battery").await);

    // Ann's machine, which may only publish private tunnels: a raw port is private too, and gets
    // no public port. Asking for a public one still asks for one.
    let body = serde_json::json!({ "owner_user_id": ids["ann@example.com"], "allow_public": false });
    let (_, v) = env.api_json("POST", "/api/v1/enrollments", Some(&admin), body).await;
    let (url, ca) = (env.server_url(), env.ca_path.to_string_lossy().to_string());
    env.cli_ok(&["login", "--server", &url, "--token", v["enrollment_token"].as_str().unwrap(), "--ca-cert", &ca, "--name", "anns-laptop"]).await;
    let (echo, dns) = (common::tcp_echo_app().await, common::udp_echo_app().await);
    let t = add_json(&env, &[&echo.port.to_string(), "--tcp", "--name", "db", "--tag", "team:dev"]).await;
    assert_eq!((t["status"].as_str(), t["visibility"].as_str(), t["public_url"].as_str()), (Some("ready"), Some("private"), Some("magicpipes connect db")), "{t}");
    assert!(t.get("public_port").is_none() && t.get("reachable").is_none(), "{t}");
    assert_eq!(add_json(&env, &[&dns.port.to_string(), "--udp", "--name", "dns"]).await["visibility"], "private");
    let out = env.cli(&["add", &echo.port.to_string(), "--tcp", "--name", "open", "--allow-any", "--json"]).await;
    assert_eq!(last_json(&out)["error"]["code"], "public_not_allowed");

    // With an API token, Ann reaches both from here.
    let ann_token = api_token(&env, &ann).await;
    let mut tcp = env.cli_spawn(&["connect", "db", "--api-token", &ann_token, "--json"]);
    let port = connect_port(&mut tcp).await;
    assert_eq!(tcp_roundtrip(port, b"hello over connect").await, b"hello over connect");
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(tcp_roundtrip(port, &big).await, big, "large transfers arrive intact");
    let mut udp = env.cli_spawn(&["connect", "dns", "--api-token", &ann_token, "--json"]);
    let uport = connect_port(&mut udp).await;
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_eq!(udp_roundtrip(&client, uport, b"ping").await, b"echo:ping");
    assert_eq!(udp_roundtrip(&client, uport, b"again").await, b"echo:again");

    // Bob holds no tag that lets him in: to him, there's no such tunnel.
    let bob_token = api_token(&env, &bob).await;
    let out = env.cli(&["connect", "db", "--api-token", &bob_token, "--json"]).await;
    assert_eq!((out.status.code(), last_json(&out)["error"]["code"].as_str()), (Some(6), Some("not_found")));
    // Given the tag, he gets in, and the tunnel is shared with him, with the way in.
    let bob_id = ids["bob@example.com"].clone();
    env.api_json("PATCH", &format!("/api/v1/users/{bob_id}"), Some(&admin), serde_json::json!({ "tags": ["team:dev"] })).await;
    assert!(env.ui("/", Some(&bob), None).await.html.contains("<code>magicpipes connect db</code>"));
    let mut bobs = env.cli_spawn(&["connect", "db", "--api-token", &bob_token, "--json"]);
    let bport = connect_port(&mut bobs).await;
    let mut open = tokio::net::TcpStream::connect(("127.0.0.1", bport)).await.unwrap();
    open.write_all(b"ping").await.unwrap();
    let mut got = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), open.read_exact(&mut got)).await.unwrap().unwrap();
    assert_eq!(&got, b"ping");
    // Losing it closes his open connection at once, and the next one ends `connect`, saying why.
    env.api_json("PATCH", &format!("/api/v1/users/{bob_id}"), Some(&admin), serde_json::json!({ "tags": [] })).await;
    let read = tokio::time::timeout(Duration::from_secs(10), open.read(&mut got)).await.expect("the connection stayed open");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    let _ = tokio::net::TcpStream::connect(("127.0.0.1", bport)).await;
    let out = tokio::time::timeout(Duration::from_secs(30), bobs.wait_with_output()).await.unwrap().unwrap();
    assert_eq!((out.status.code(), last_json(&out)["error"]["code"].as_str()), (Some(6), Some("not_found")));

    // Without a token, `connect` asks Ann to approve it in a browser, on any device, and keeps the pass.
    let mut child = env.cli_spawn(&["connect", "db", "--no-browser", "--json"]);
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
    let approval = env.ui(&link, Some(&ann), None).await;
    assert!(approval.html.contains("Connect from") && approval.html.contains("private TCP and UDP tunnels you can"), "{}", approval.html);
    let code = link.split("code=").nth(1).unwrap().to_string();
    let done = env.ui("/cli", Some(&ann), Some(&[("csrf", &approval.csrf()), ("code", &code), ("answer", "approve")])).await;
    assert!(done.html.contains("carries on by itself"), "{}", done.html);
    let port = connect_port(&mut child).await;
    assert_eq!(tcp_roundtrip(port, b"signed in").await, b"signed in");
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(env.home().join("connect.json")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    drop(child);
    // The next run uses it: nothing to approve.
    let mut again = env.cli_spawn(&["connect", "db", "--no-browser", "--json"]);
    let port = connect_port(&mut again).await;
    assert_eq!(tcp_roundtrip(port, b"once more").await, b"once more");
    // Signing out everywhere ends the pass (issued before it, at second precision).
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let account = env.ui("/account", Some(&ann), None).await;
    env.ui("/account/logout-everywhere", Some(&ann), Some(&[("csrf", &account.csrf())])).await;
    let _ = tokio::net::TcpStream::connect(("127.0.0.1", port)).await;
    let out = tokio::time::timeout(Duration::from_secs(30), again.wait_with_output()).await.unwrap().unwrap();
    assert_eq!((out.status.code(), last_json(&out)["error"]["code"].as_str()), (Some(3), Some("unauthenticated")));

    // Each way in is written down.
    env.eventually("connections in the audit log", Duration::from_secs(10), || async {
        let audit = env.api("GET", "/api/v1/audit", Some(&admin)).await.1.to_string();
        audit.contains("tunnel.connect") && audit.contains("connect.approve")
    })
    .await;
    drop((tcp, udp));
    env.cli_ok(&["agent", "stop"]).await;
}

/// The first message of an RDP client, the X.224 connection request, asking for TLS and NLA.
const RDP_REQUEST: [u8; 19] = [3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0];
/// What Windows answers it with: NLA chosen.
const RDP_CONFIRM: [u8; 19] = [3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, 2, 0x1f, 8, 0, 2, 0, 0, 0];

/// A stand-in Remote Desktop server on `port` (0: any): it answers the X.224 connection request
/// as Windows does, then TLS with a self-signed certificate for `key`, then echoes what comes
/// through that. Returns its port, its certificate, and the task serving it.
async fn rdp_stand_in(key: &rcgen::KeyPair, port: u16) -> (u16, Vec<u8>, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let cert = rcgen::CertificateParams::new(vec!["pc".into()]).unwrap().self_signed(key).unwrap();
    let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key_der)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                // The agent's checks connect and close without a word.
                let mut request = [0u8; RDP_REQUEST.len()];
                if tcp.read_exact(&mut request).await.is_err() || request != RDP_REQUEST || tcp.write_all(&RDP_CONFIRM).await.is_err() {
                    return;
                }
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                let mut buf = [0u8; 4096];
                while let Ok(n @ 1..) = tls.read(&mut buf).await {
                    if tls.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (port, cert.der().to_vec(), task)
}

async fn open_desktop(env: &Env, cookie: &str, name: &str, origin: Option<&str>) -> Result<Terminal, StatusCode> {
    let tls = env.connect("localhost", env.mgmt_port).await;
    let mut req = format!("wss://localhost:{}/desktop/{name}/ws", env.mgmt_port).into_client_request().unwrap();
    req.headers_mut().insert(header::COOKIE, cookie.parse().unwrap());
    let here = format!("https://localhost:{}", env.mgmt_port);
    req.headers_mut().insert(header::ORIGIN, origin.unwrap_or(&here).parse().unwrap());
    match tokio_tungstenite::client_async(req, tls).await {
        Ok((ws, _)) => Ok(ws),
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => Err(resp.status()),
        Err(e) => panic!("{e}"),
    }
}

/// Opens a desktop as IronRDP's browser client does: the RDCleanPath request, then the answer.
async fn rdcleanpath(ws: &mut Terminal) -> ironrdp_rdcleanpath::RDCleanPath {
    let request = ironrdp_rdcleanpath::RDCleanPathPdu::new_request(RDP_REQUEST.to_vec(), "anywhere.example:3389".into(), "token".into(), None).unwrap();
    ws.send(Message::binary(request.to_der().unwrap())).await.unwrap();
    loop {
        match tokio::time::timeout(Duration::from_secs(30), ws.next()).await.expect("an answer").expect("open").unwrap() {
            Message::Binary(b) => return ironrdp_rdcleanpath::RDCleanPathPdu::from_der(&b).unwrap().into_enum().unwrap(),
            _ => continue,
        }
    }
}

/// What came back through the desktop's WebSocket, until `want`, or `None` once it closes.
async fn desktop_echo(ws: &mut Terminal, want: &[u8]) -> Option<Vec<u8>> {
    let mut seen = Vec::new();
    while seen.len() < want.len() {
        match tokio::time::timeout(Duration::from_secs(20), ws.next()).await.expect("an answer") {
            Some(Ok(Message::Binary(b))) => seen.extend_from_slice(&b),
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return None,
            Some(Ok(_)) => {}
        }
    }
    Some(seen)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rdp_desktops() {
    use ironrdp_rdcleanpath::RDCleanPath;
    let env = Env::new(Tls::DevCa).await;
    let admin = env.admin_token();
    env.api_json("POST", "/api/v1/tags", Some(&admin), serde_json::json!({ "name": "team:dev" })).await;
    let mut ids = std::collections::HashMap::new();
    for (email, tags) in [("ann@example.com", vec!["team:dev"]), ("bob@example.com", vec![])] {
        let (_, v) = env.api_json("POST", "/api/v1/users", Some(&admin), serde_json::json!({ "email": email, "password": "correct horse battery" })).await;
        let id = v["user"]["id"].as_str().unwrap().to_string();
        env.api_json("PATCH", &format!("/api/v1/users/{id}"), Some(&admin), serde_json::json!({ "tags": tags })).await;
        ids.insert(email, id);
    }
    let (ann, bob) = (sign_in(&env, "ann@example.com", "correct horse battery").await, sign_in(&env, "bob@example.com", "correct horse battery").await);
    let body = serde_json::json!({ "owner_user_id": ids["ann@example.com"] });
    let (_, v) = env.api_json("POST", "/api/v1/enrollments", Some(&admin), body).await;
    let (url, ca) = (env.server_url(), env.ca_path.to_string_lossy().to_string());
    env.cli_ok(&["login", "--server", &url, "--token", v["enrollment_token"].as_str().unwrap(), "--ca-cert", &ca, "--name", "anns-pc"]).await;

    // Always private, and its address is the desktop's page.
    let key = rcgen::KeyPair::generate().unwrap();
    let (port, cert, machine) = rdp_stand_in(&key, 0).await;
    let t = add_json(&env, &[&port.to_string(), "--rdp", "--name", "pc", "--tag", "team:dev"]).await;
    assert_eq!((t["status"].as_str(), t["kind"].as_str(), t["visibility"].as_str()), (Some("ready"), Some("rdp"), Some("private")), "{t}");
    assert_eq!(t["public_url"], format!("{url}/desktop/pc"));
    let id = t["id"].as_str().unwrap().to_string();

    // The page and its files, linked from the tunnel; Bob can't reach it.
    let page = env.ui("/desktop/pc", Some(&ann), None).await;
    assert!(page.status == 200 && page.html.contains(r#"data-ws="/desktop/pc/ws""#) && page.html.contains("<iron-remote-desktop"), "{}", page.html);
    assert_eq!(env.ui("/desktop/pc", Some(&bob), None).await.status, StatusCode::NOT_FOUND);
    // Its files are under a version, which changes with them.
    let at = page.html.split(r#"<script type="module" src=""#).nth(1).and_then(|s| s.split("/page.mjs").next()).unwrap().to_string();
    assert!(at.starts_with("/assets/desktop/") && at.len() == "/assets/desktop/".len() + 16, "{at}");
    let script = env.ui(&format!("{at}/page.mjs"), None, None).await;
    assert!(script.status == 200 && script.html.contains(r#"from "./iron-remote-desktop-rdp.js""#));
    assert_eq!(env.ui(&format!("{at}/iron-remote-desktop-rdp.js"), None, None).await.status, 200);
    assert_eq!(env.ui("/assets/desktop/0123456789abcdef/page.mjs", None, None).await.status, StatusCode::NOT_FOUND);
    assert!(env.ui("/", Some(&ann), None).await.html.contains(r#"href="/desktop/pc""#));

    // Only from this host's pages, and only for people who may reach the machine.
    assert_eq!(open_desktop(&env, &ann, "pc", Some("https://evil.example")).await.err(), Some(StatusCode::FORBIDDEN));
    assert_eq!(open_desktop(&env, &bob, "pc", None).await.err(), Some(StatusCode::NOT_FOUND));
    assert_eq!(open_desktop(&env, &ann, "ghost", None).await.err(), Some(StatusCode::NOT_FOUND));

    // RDCleanPath: the machine's answer and certificate, then RDP over its TLS, both ways.
    let mut ws = open_desktop(&env, &ann, "pc", None).await.unwrap();
    match rdcleanpath(&mut ws).await {
        RDCleanPath::Response { x224_connection_response, server_cert_chain, .. } => {
            assert_eq!(x224_connection_response.as_bytes(), RDP_CONFIRM);
            assert_eq!(server_cert_chain.first().map(|c| c.as_bytes()), Some(&cert[..]));
        }
        other => panic!("{other:?}"),
    }
    ws.send(Message::binary(b"hello over rdp".to_vec())).await.unwrap();
    assert_eq!(desktop_echo(&mut ws, b"hello over rdp").await.as_deref(), Some(&b"hello over rdp"[..]));
    // Something that isn't RDCleanPath is turned away.
    let mut junk = open_desktop(&env, &ann, "pc", None).await.unwrap();
    junk.send(Message::binary(b"GET / HTTP/1.1\r\n\r\n".to_vec())).await.unwrap();
    assert!(desktop_echo(&mut junk, b"x").await.is_none_or(|b| ironrdp_rdcleanpath::RDCleanPathPdu::from_der(&b).is_ok()));

    // A Remote Desktop client gets there with `magicpipes connect`.
    let token = api_token(&env, &ann).await;
    let mut connect = env.cli_spawn(&["connect", "pc", "--api-token", &token, "--json"]);
    let local = connect_port(&mut connect).await;
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", local)).await.unwrap();
        c.write_all(&RDP_REQUEST).await.unwrap();
        let mut answer = [0u8; RDP_CONFIRM.len()];
        tokio::time::timeout(Duration::from_secs(20), c.read_exact(&mut answer)).await.unwrap().unwrap();
        assert_eq!(answer, RDP_CONFIRM);
    }
    drop(connect);

    // The machine's certificate was kept: shown another, the desktop is refused until its owner
    // forgets the old one.
    env.eventually("the certificate kept", Duration::from_secs(10), async || {
        env.ui(&format!("/tunnels/{id}"), Some(&ann), None).await.html.contains("Forget certificate")
    })
    .await;
    machine.abort();
    let _ = machine.await;
    let (_, other, _machine) = rdp_stand_in(&rcgen::KeyPair::generate().unwrap(), port).await;
    let mut ws = open_desktop(&env, &ann, "pc", None).await.unwrap();
    match rdcleanpath(&mut ws).await {
        RDCleanPath::GeneralErr(e) => assert_eq!(e.http_status_code, Some(403), "{e:?}"),
        other => panic!("{other:?}"),
    }
    let detail = env.ui(&format!("/tunnels/{id}"), Some(&ann), None).await;
    let forget = env.ui(&format!("/tunnels/{id}/host-key/forget"), Some(&ann), Some(&[("csrf", &detail.csrf())])).await;
    assert_eq!((forget.status, forget.location.as_deref()), (StatusCode::SEE_OTHER, Some(&*format!("/tunnels/{id}?done=certificate-forgotten"))));
    let mut ws = open_desktop(&env, &ann, "pc", None).await.unwrap();
    match rdcleanpath(&mut ws).await {
        RDCleanPath::Response { server_cert_chain, .. } => assert_eq!(server_cert_chain.first().map(|c| c.as_bytes()), Some(&other[..])),
        other => panic!("{other:?}"),
    }

    // Signing out everywhere ends it.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let account = env.ui("/account", Some(&ann), None).await;
    env.ui("/account/logout-everywhere", Some(&ann), Some(&[("csrf", &account.csrf())])).await;
    assert!(desktop_echo(&mut ws, b"anything").await.is_none(), "the desktop stayed open");

    env.eventually("the audit log says who opened a desktop", Duration::from_secs(5), async || {
        let audit = env.api("GET", "/api/v1/audit", Some(&admin)).await.1.to_string();
        audit.contains("rdp.desktop") && audit.contains("rdp.certificate.forget")
    })
    .await;
    env.cli_ok(&["agent", "stop"]).await;
}

/// A stand-in VNC server on any port: it greets as VNC servers do, or, while `as_vnc` is false, as
/// something else, then echoes. Returns its port and the task serving it.
async fn vnc_stand_in(as_vnc: Arc<std::sync::atomic::AtomicBool>) -> (u16, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let greeting: &[u8] = if as_vnc.load(std::sync::atomic::Ordering::SeqCst) { b"RFB 003.008\n" } else { b"SSH-2.0-OpenSSH\r\n" };
            tokio::spawn(async move {
                // The agent's checks connect and close without a word.
                if tcp.write_all(greeting).await.is_err() {
                    return;
                }
                let mut buf = [0u8; 4096];
                while let Ok(n @ 1..) = tcp.read(&mut buf).await {
                    if tcp.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (port, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vnc_desktops() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
    let env = Env::new(Tls::DevCa).await;
    let admin = env.admin_token();
    env.api_json("POST", "/api/v1/tags", Some(&admin), serde_json::json!({ "name": "team:dev" })).await;
    let mut ids = std::collections::HashMap::new();
    for (email, tags) in [("ann@example.com", vec!["team:dev"]), ("bob@example.com", vec![])] {
        let (_, v) = env.api_json("POST", "/api/v1/users", Some(&admin), serde_json::json!({ "email": email, "password": "correct horse battery" })).await;
        let id = v["user"]["id"].as_str().unwrap().to_string();
        env.api_json("PATCH", &format!("/api/v1/users/{id}"), Some(&admin), serde_json::json!({ "tags": tags })).await;
        ids.insert(email, id);
    }
    let (ann, bob) = (sign_in(&env, "ann@example.com", "correct horse battery").await, sign_in(&env, "bob@example.com", "correct horse battery").await);
    let body = serde_json::json!({ "owner_user_id": ids["ann@example.com"] });
    let (_, v) = env.api_json("POST", "/api/v1/enrollments", Some(&admin), body).await;
    let (url, ca) = (env.server_url(), env.ca_path.to_string_lossy().to_string());
    env.cli_ok(&["login", "--server", &url, "--token", v["enrollment_token"].as_str().unwrap(), "--ca-cert", &ca, "--name", "anns-pi"]).await;

    // Always private, and its address is the desktop's page.
    let as_vnc = Arc::new(AtomicBool::new(true));
    let (port, _machine) = vnc_stand_in(as_vnc.clone()).await;
    let t = add_json(&env, &[&port.to_string(), "--vnc", "--name", "pi", "--tag", "team:dev"]).await;
    assert_eq!((t["status"].as_str(), t["kind"].as_str(), t["visibility"].as_str()), (Some("ready"), Some("vnc"), Some("private")), "{t}");
    assert_eq!(t["public_url"], format!("{url}/desktop/pi"));

    // The page, with noVNC under a version that changes with it; Bob can't reach it.
    let page = env.ui("/desktop/pi", Some(&ann), None).await;
    assert!(page.status == 200 && page.html.contains(r#"<div class="vnc" id="vnc">"#) && page.html.contains(">VNC</span>"), "{}", page.html);
    assert_eq!(env.ui("/desktop/pi", Some(&bob), None).await.status, StatusCode::NOT_FOUND);
    let at = page.html.split(r#"<script type="module" src=""#).nth(1).and_then(|s| s.split("/page.mjs").next()).unwrap().to_string();
    assert!(at.starts_with("/assets/vnc/") && at.len() == "/assets/vnc/".len() + 16, "{at}");
    let script = env.ui(&format!("{at}/page.mjs"), None, None).await;
    assert!(script.status == 200 && script.html.contains(r#"from "./novnc/core/rfb.js""#));
    for file in ["novnc/core/rfb.js", "novnc/vendor/pako/lib/zlib/inflate.js"] {
        assert_eq!(env.ui(&format!("{at}/{file}"), None, None).await.status, 200, "{file}");
    }
    for missing in [format!("{at}/novnc/LICENSE.txt"), format!("{at}/rfb.js"), "/assets/vnc/0123456789abcdef/page.mjs".to_string()] {
        assert_eq!(env.ui(&missing, None, None).await.status, StatusCode::NOT_FOUND, "{missing}");
    }
    assert!(env.ui("/", Some(&ann), None).await.html.contains(r#"href="/desktop/pi""#));

    // Only from this host's pages, and only for people who may reach the machine.
    assert_eq!(open_desktop(&env, &ann, "pi", Some("https://evil.example")).await.err(), Some(StatusCode::FORBIDDEN));
    assert_eq!(open_desktop(&env, &bob, "pi", None).await.err(), Some(StatusCode::NOT_FOUND));

    // The machine's greeting, then bytes both ways: noVNC speaks VNC itself.
    let mut ws = open_desktop(&env, &ann, "pi", None).await.unwrap();
    assert_eq!(desktop_echo(&mut ws, b"RFB 003.008\n").await.as_deref(), Some(&b"RFB 003.008\n"[..]));
    ws.send(Message::binary(b"hello over vnc".to_vec())).await.unwrap();
    assert_eq!(desktop_echo(&mut ws, b"hello over vnc").await.as_deref(), Some(&b"hello over vnc"[..]));

    // Something that isn't a VNC server is refused with a code the page explains.
    as_vnc.store(false, Ordering::SeqCst);
    let mut other = open_desktop(&env, &ann, "pi", None).await.unwrap();
    let closed = match tokio::time::timeout(Duration::from_secs(30), other.next()).await.expect("an answer") {
        Some(Ok(Message::Close(frame))) => frame.map(|f| f.code),
        Some(Ok(m)) => panic!("{m:?}"),
        Some(Err(_)) | None => None,
    };
    assert_eq!(closed, Some(CloseCode::Library(4502)));
    as_vnc.store(true, Ordering::SeqCst);

    // A VNC viewer gets there with `magicpipes connect`.
    let token = api_token(&env, &ann).await;
    let mut connect = env.cli_spawn(&["connect", "pi", "--api-token", &token, "--json"]);
    let local = connect_port(&mut connect).await;
    {
        use tokio::io::AsyncReadExt;
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", local)).await.unwrap();
        let mut greeting = [0u8; 12];
        tokio::time::timeout(Duration::from_secs(20), c.read_exact(&mut greeting)).await.unwrap().unwrap();
        assert_eq!(&greeting, b"RFB 003.008\n");
    }
    drop(connect);

    // Signing out everywhere ends it.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let account = env.ui("/account", Some(&ann), None).await;
    env.ui("/account/logout-everywhere", Some(&ann), Some(&[("csrf", &account.csrf())])).await;
    assert!(desktop_echo(&mut ws, b"anything").await.is_none(), "the desktop stayed open");

    env.eventually("the audit log says who opened a desktop", Duration::from_secs(5), async || {
        env.api("GET", "/api/v1/audit", Some(&admin)).await.1.to_string().contains("vnc.desktop")
    })
    .await;
    env.cli_ok(&["agent", "stop"]).await;
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

/// A stopping agent holds its lock for a moment after its socket has gone. A start in that moment
/// mustn't wait for a socket nobody is going to open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_agent_starts_once_a_stopping_one_lets_go() {
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    // Stands in for an agent that is still exiting: the lock is held, and there's no socket.
    let lock = std::fs::File::options().create(true).truncate(false).write(true).open(env.home().join("agent.lock")).unwrap();
    lock.try_lock().unwrap();
    let start = env.cli_spawn(&["agent", "start"]);
    tokio::time::sleep(Duration::from_millis(600)).await;
    drop(lock);
    let out = start.wait_with_output().await.unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}{}\nagent log:\n{}", String::from_utf8_lossy(&out.stderr), env.agent_log());
    assert!(stdout.starts_with("Agent started"), "{stdout}");
    assert!(env.agent_pid().is_some());
    assert_eq!(env.agent_log().matches("agent started").count(), 1, "{}", env.agent_log());
    env.cli_ok(&["agent", "stop"]).await;
}

/// When several commands start an agent at once, all but one of the agents exit because the
/// first holds the lock. A slow one can get the lock only after that agent has been stopped, and
/// every command has stopped waiting; it mustn't run then.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_agent_nobody_waits_for_does_not_run() {
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    // Started the way commands start one, but with none waiting. If it runs, it never finishes.
    let out = env.cli(&["agent", "run", "--detached"]).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(!stderr.contains("agent started"), "{stderr}");
    assert_eq!(env.agent_pid(), None);
    // A command that waits still gets one.
    env.cli_ok(&["agent", "start"]).await;
    assert!(env.agent_pid().is_some());
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
    browser_sign_in(false).await;
}

/// The same with sign-in codes on: the note between the password and the code is a
/// `SameSite=Strict` cookie, which has to come along all the way from one to the other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Chrome and Node"]
async fn browser_signs_in_with_a_code() {
    browser_sign_in(true).await;
}

async fn browser_sign_in(with_code: bool) {
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
    let session = sign_in(&env, "ann@example.com", first_password).await;
    let password = format!("{first_password} again");
    let key = if with_code {
        let setup = env.ui("/account/codes", Some(&session), None).await;
        let key = between(&setup.html, r#"<code class="key">"#, "</code>").replace(' ', "");
        let sealed = between(&setup.html, r#"name="key" value=""#, "\"").to_string();
        let code = common::totp_code(&key, magicpipes_now());
        let on = env.ui("/account/codes", Some(&session), Some(&[("csrf", &setup.csrf()), ("key", &sealed), ("code", &code), ("password", &password)])).await;
        assert_eq!(on.status, StatusCode::OK, "{}", on.html);
        Some(key)
    } else {
        None
    };

    let body = serde_json::json!({ "owner_user_id": ann });
    let (_, v) = env.api_json("POST", "/api/v1/enrollments", Some(&admin), body).await;
    let (url, ca) = (env.server_url(), env.ca_path.to_string_lossy().to_string());
    env.cli_ok(&["login", "--server", &url, "--token", v["enrollment_token"].as_str().unwrap(), "--ca-cert", &ca, "--name", "laptop"]).await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let first = add_json(&env, &[&app.port.to_string(), "--private", "--name", "one"]).await;
    let second = add_json(&env, &[&app.port.to_string(), "--private", "--name", "two"]).await;

    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/browser-sign-in.mjs");
    // One profile per test: Chrome won't start a second time on one that's in use.
    let profile = std::env::temp_dir().join(format!("mp-chrome-{}-{}", std::process::id(), if with_code { "code" } else { "password" }));
    let opts = serde_json::json!({
        "chrome": chrome,
        "first": format!("{}/", first["public_url"].as_str().unwrap()),
        "second": format!("{}/", second["public_url"].as_str().unwrap()),
        "management": url,
        "email": "ann@example.com",
        "password": password,
        "totp": key,
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

/// Tag rules give tags from what a sign-in says: a provider's groups (in the ID token, or from
/// UserInfo when it lacks them), GitHub's organizations and teams, and a confirmed address's
/// domain. A sign-in without the group takes it away, and removing a rule takes its tag from
/// whoever had it only through the rule, at once; access to a private tunnel follows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tag_rules_give_tags_from_what_a_sign_in_says() {
    let idp = common::FakeOidc::start().await;
    let gh = common::FakeOidc::start().await;
    let dir = std::env::temp_dir().join(format!("mp-rules-{}", std::process::id()));
    let config = format!(
        "{}\n[[oidc]]\nid = \"gh\"\nlabel = \"Our GitHub\"\nkind = \"github\"\nissuer = \"{}\"\nclient_id = \"{}\"\nclient_secret_file = \"{}\"\nlink_by_email = true\n",
        idp.config(&dir, r#"allowed_email_domains = ["team.example.com"]"#, true),
        gh.issuer,
        common::OIDC_CLIENT,
        dir.join("oidc-secret").display(),
    );
    let env = Env::with_config(Tls::DevCa, &config).await;
    let admin = env.admin_token();
    for tag in ["team:eng", "team:ops", "gh:platform"] {
        let (s, v) = env.api_json("POST", "/api/v1/tags", Some(&admin), serde_json::json!({ "name": tag })).await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
    }
    let rule = async |source: &str, claim: &str, value: &str, tag: &str| {
        env.api_json("POST", "/api/v1/tag-rules", Some(&admin), serde_json::json!({ "source": source, "claim": claim, "value": value, "tag": tag })).await
    };

    // What a rule can name.
    let (_, v) = env.api("GET", "/api/v1/tag-rules", Some(&admin)).await;
    let sources: Vec<(&str, &str)> = v["sources"].as_array().unwrap().iter().map(|s| (s["name"].as_str().unwrap(), s["kind"].as_str().unwrap())).collect();
    assert_eq!(sources, vec![("Any sign-in", "any"), ("Fake ID", "oidc"), ("Our GitHub", "github")], "{v}");
    let (s, v) = rule(&idp.issuer, "groups", "eng", "team:eng").await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let eng_rule = v["rule"]["id"].as_str().unwrap().to_string();
    for (source, claim, value, tag, code) in [
        (idp.issuer.as_str(), "email", "dev@team.example.com", "team:eng", "invalid_request"),
        ("https://nowhere.example.com", "groups", "eng", "team:eng", "invalid_request"),
        (idp.issuer.as_str(), "groups", "eng", "no-such-tag", "tag_unknown"),
        (gh.issuer.as_str(), "groups", "eng", "team:eng", "invalid_request"),
        (idp.issuer.as_str(), "groups", "eng", "team:eng", "invalid_request"),
    ] {
        let (s, v) = rule(source, claim, value, tag).await;
        assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::BAD_REQUEST, Some(code)), "{source} {claim}={value} {tag}: {v}");
    }
    let member = async || user_named(&env, "dev@team.example.com").await;
    let set = |p: common::OidcPerson| *idp.person.lock().unwrap() = p;

    // A machine's private tunnel for team:eng, which follows who holds it.
    env.login().await;
    let (_, agents) = env.api("GET", "/api/v1/agents", Some(&admin)).await;
    let agent = agents["agents"][0]["id"].as_str().unwrap().to_string();
    let (s, v) = env.api_json("PATCH", &format!("/api/v1/agents/{agent}"), Some(&admin), serde_json::json!({ "tags": ["team:eng"] })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    add_json(&env, &[&app.port.to_string(), "--private", "--tag", "team:eng", "--name", "eng-app"]).await;

    // Signing in with the group gives the tag, and the tunnel.
    let mut dev = common::OidcPerson::new("dev-1", "dev@team.example.com");
    dev.claims = serde_json::json!({ "groups": ["eng", "other"] });
    set(dev.clone());
    let cookie = session_of(&oidc_sign_in(&env, None).await);
    let token = api_token(&env, &cookie).await;
    let shared = async || env.api("GET", "/api/v1/shared", Some(&token)).await.1["tunnels"].as_array().unwrap().iter().any(|t| t["name"] == "eng-app");
    let u = member().await;
    assert_eq!((u["rule_tags"].clone(), u["tags"].clone()), (serde_json::json!(["team:eng"]), serde_json::json!([])), "{u}");
    assert!(shared().await, "the tunnel for team:eng");

    // Signing in without it takes it away.
    dev.claims = serde_json::json!({ "groups": ["other"] });
    set(dev.clone());
    oidc_sign_in(&env, None).await;
    assert_eq!(member().await["rule_tags"], serde_json::json!([]));
    assert!(!shared().await);

    // Groups only UserInfo gives are read there, since a rule asks for them.
    dev.claims = serde_json::json!({});
    dev.userinfo_claims = serde_json::json!({ "groups": ["eng"] });
    set(dev.clone());
    oidc_sign_in(&env, None).await;
    assert_eq!(member().await["rule_tags"], serde_json::json!(["team:eng"]));

    // An address's domain: everyone confirmed there, at once.
    let (s, v) = rule("*", "", "Team.Example.com", "team:ops").await;
    assert_eq!((s, v["rule"]["claim"].as_str(), v["rule"]["value"].as_str(), v["rule"]["holders"].as_u64()), (StatusCode::CREATED, Some("email_domain"), Some("team.example.com"), Some(1)), "{v}");
    assert_eq!(member().await["rule_tags"], serde_json::json!(["team:eng", "team:ops"]));

    // GitHub: read:org is asked for only once a rule wants organizations or teams.
    let gh_start = env.ui("/auth/oidc/gh", None, None).await.location.unwrap();
    assert!(gh_start.contains("scope=user%3Aemail&"), "{gh_start}");
    let (s, v) = rule(&gh.issuer, "github:team", "Acme/Platform", "gh:platform").await;
    assert_eq!((s, v["rule"]["value"].as_str()), (StatusCode::CREATED, Some("acme/platform")), "{v}");
    let gh_start = env.ui("/auth/oidc/gh", None, None).await.location.unwrap();
    assert!(gh_start.contains("scope=user%3Aemail%20read%3Aorg"), "{gh_start}");
    let mut on_github = common::OidcPerson::new("201", "dev@team.example.com");
    on_github.teams = vec!["ACME/platform".into(), "acme/other".into()];
    on_github.orgs = vec!["acme".into()];
    *gh.person.lock().unwrap() = on_github;
    oidc_sign_in_at(&env, "gh", None).await;
    assert_eq!(member().await["rule_tags"], serde_json::json!(["gh:platform", "team:eng", "team:ops"]), "each source's matches stand side by side");

    // The Tags page lists the rules, and says what removing one does.
    let admin_cookie = admin_session(&env).await;
    let page = env.ui("/tags", Some(&admin_cookie), None).await.html;
    for want in [
        "A confirmed address at <code>team.example.com</code>",
        "<code>groups</code> has <code>eng</code><span class=\"sub wrap\">from Fake ID</span>",
        "Remove this rule? 1 person holds team:eng only through it, and lose it.",
    ] {
        assert!(page.contains(want), "{want} in {page}");
    }
    let users_page = env.ui("/users", Some(&admin_cookie), None).await.html;
    assert!(users_page.contains(r#"<div class="byrule"><span class="sub">by rule</span>"#), "{users_page}");
    let typo = env.ui("/tags/rules", Some(&admin_cookie), Some(&[("csrf", &env.ui("/tags", Some(&admin_cookie), None).await.csrf()), ("tag", "team:ops"), ("source", "*"), ("claim", ""), ("value", "not a domain@")])).await;
    assert!(typo.status == StatusCode::BAD_REQUEST && typo.html.contains("Enter a domain, like example.com.") && typo.html.contains(r#"value="not a domain@""#), "{}", typo.html);

    // Removing the groups rule takes team:eng, and the tunnel, at once.
    let (s, _) = env.api("DELETE", &format!("/api/v1/tag-rules/{eng_rule}"), Some(&admin)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(member().await["rule_tags"], serde_json::json!(["gh:platform", "team:ops"]));
    assert!(!shared().await);
    assert_eq!(env.api("DELETE", &format!("/api/v1/tag-rules/{eng_rule}"), Some(&admin)).await.0, StatusCode::NOT_FOUND);
    // Deleting a tag takes its rules with it.
    env.api("DELETE", "/api/v1/tags/team:ops", Some(&admin)).await;
    assert_eq!(env.api("GET", "/api/v1/tag-rules", Some(&admin)).await.1["rules"].as_array().unwrap().len(), 1);
    assert_eq!(member().await["rule_tags"], serde_json::json!(["gh:platform"]));
}

/// Single sign-on past the sign-in: a provider's own scopes, the sign-in page going straight to it,
/// sessions checked with it again (a group gone takes its tag; a refusal ends the session), and
/// signing out there too, coming back to a page that stays put.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sso_sessions_are_checked_again_and_sign_out_at_the_provider() {
    let idp = common::FakeOidc::start().await;
    let other = common::FakeOidc::start().await;
    let dir = std::env::temp_dir().join(format!("mp-sso-{}", std::process::id()));
    let users = "allowed_email_domains = [\"team.example.com\"]\nsso_recheck_secs = 10";
    let config = format!("{}scopes = [\"openid\", \"email\", \"groups\", \"offline_access\"]\nauto_redirect = true\nsign_out = true\n", idp.config(&dir, users, true));
    let env = Env::with_config(Tls::DevCa, &config).await;
    let admin = env.admin_token();
    env.api_json("POST", "/api/v1/tags", Some(&admin), serde_json::json!({ "name": "team:eng" })).await;
    let (s, v) = env.api_json("POST", "/api/v1/tag-rules", Some(&admin), serde_json::json!({ "source": idp.issuer, "claim": "groups", "value": "eng", "tag": "team:eng" })).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");

    // The sign-in page goes straight to the provider, keeping where to go next; other ways in stay.
    assert_eq!(env.ui("/login", None, None).await.location.as_deref(), Some("/auth/oidc/fake"));
    assert_eq!(env.ui("/login?next=/account", None, None).await.location.as_deref(), Some("/auth/oidc/fake?next=%2Faccount"));
    let password = env.ui("/login?method=password", None, None).await;
    assert!(password.status == StatusCode::OK && password.html.contains("Continue with Fake ID") && password.html.contains(r#"name="password""#), "{}", password.html);
    assert!(env.ui("/login?method=token", None, None).await.html.contains(r#"name="token""#));

    // Signing in asks for the provider's own scopes, and a group gives its tag.
    let mut dev = common::OidcPerson::new("dev-1", "dev@team.example.com");
    dev.claims = serde_json::json!({ "groups": ["eng"] });
    *idp.person.lock().unwrap() = dev.clone();
    let cookie = session_of(&oidc_sign_in(&env, None).await);
    assert_eq!(*idp.last_scope.lock().unwrap(), "openid email groups offline_access");
    let member = async || user_named(&env, "dev@team.example.com").await;
    assert_eq!(member().await["rule_tags"], serde_json::json!(["team:eng"]));

    // Out of the group at the provider: a re-check takes the tag, without signing in again.
    dev.claims = serde_json::json!({ "groups": [] });
    *idp.person.lock().unwrap() = dev.clone();
    env.eventually("a re-check to take the tag", Duration::from_secs(45), || async { member().await["rule_tags"] == serde_json::json!([]) }).await;
    assert!(idp.refreshes.load(std::sync::atomic::Ordering::SeqCst) >= 1);
    assert_eq!(env.ui("/account", Some(&cookie), None).await.status, StatusCode::OK, "the session goes on");

    // Removed at the provider: the next re-check ends the session.
    dev.refresh_refused = true;
    *idp.person.lock().unwrap() = dev.clone();
    env.eventually("a refused re-check to end the session", Duration::from_secs(45), || async {
        env.ui("/account", Some(&cookie), None).await.location.as_deref().is_some_and(|l| l.starts_with("/login"))
    })
    .await;
    let (_, audit) = env.api("GET", "/api/v1/audit?limit=20", Some(&admin)).await;
    assert!(audit["entries"].as_array().unwrap().iter().any(|e| e["action"] == "session.ended"), "{audit}");

    // Signing out continues to the provider's sign-out, which comes back to a page that stays put.
    dev.refresh_refused = false;
    *idp.person.lock().unwrap() = dev.clone();
    let cookie = session_of(&oidc_sign_in(&env, None).await);
    let account = env.ui("/account", Some(&cookie), None).await;
    let out = env.ui("/logout", Some(&cookie), Some(&[("csrf", &account.csrf())])).await;
    let to = out.refresh.clone().unwrap_or_else(|| panic!("a page moving on: {} {}", out.status, out.html));
    let back = format!("https%3A%2F%2Flocalhost%3A{}%2Fsigned-out", env.mgmt_port);
    assert!(to.contains(&format!("{}/logout?client_id={}&post_logout_redirect_uri={back}&id_token_hint=", idp.issuer, common::OIDC_CLIENT)), "{to}");
    assert!(out.html.contains("Continuing to <em>Fake ID</em>"), "{}", out.html);
    assert_eq!(env.ui("/account", Some(&cookie), None).await.status, StatusCode::SEE_OTHER, "signed out here");
    let signed_out = env.ui("/signed-out", None, None).await;
    assert!(signed_out.status == StatusCode::OK && signed_out.html.contains("You&#39;re signed out.") && signed_out.html.contains("Continue with Fake ID"), "{}", signed_out.html);

    // On the Settings page: a provider's scopes and options, and only one way straight in.
    let admin_cookie = admin_session(&env).await;
    let form = env.ui("/settings/providers/new?type=oidc", Some(&admin_cookie), None).await;
    assert!(form.html.contains(r#"name="scopes" value="openid email profile""#) && form.html.contains("/signed-out"), "{}", form.html);
    let fields = |extra: &[(&'static str, &'static str)]| {
        let mut f = vec![("csrf", form.csrf()), ("type", "oidc".into()), ("id", "other".into()), ("url", other.issuer.clone()), ("label", "Other".into()), ("client_id", common::OIDC_CLIENT.into()), ("client_secret", common::OIDC_SECRET.into())];
        f.extend(extra.iter().map(|(k, v)| (*k, v.to_string())));
        f
    };
    let send = async |f: Vec<(&str, String)>| {
        let pairs: Vec<(&str, &str)> = f.iter().map(|(k, v)| (*k, v.as_str())).collect();
        env.ui("/settings/providers/new", Some(&admin_cookie), Some(&pairs)).await
    };
    let straight = send(fields(&[("auto_redirect", "on")])).await;
    assert!(straight.status == StatusCode::BAD_REQUEST && straight.html.contains("already goes straight to Fake ID"), "{}", straight.html);
    let bad = send(fields(&[("scopes", "email profile")])).await;
    assert!(bad.status == StatusCode::BAD_REQUEST && bad.html.contains("must include openid"), "{}", bad.html);
    let added = send(fields(&[("scopes", "openid, email groups"), ("sign_out", "on")])).await;
    assert_eq!(added.location.as_deref(), Some("/settings?done=provider-added"), "{}", added.html);
    let edit = env.ui("/settings/providers/other", Some(&admin_cookie), None).await.html;
    assert!(edit.contains(r#"name="scopes" value="openid email groups""#) && edit.contains(r#"name="sign_out" checked"#), "{edit}");
}

/// `[users] disable_idle_after_days`: an account single sign-on went quiet about is disabled, and
/// its machines with it, and its owner is told. Signing in again enables it; an administrator can
/// keep it disabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accounts_single_sign_on_went_quiet_about_are_disabled() {
    let idp = common::FakeOidc::start().await;
    let smtp = common::FakeSmtp::start().await;
    let dir = std::env::temp_dir().join(format!("mp-idle-{}", std::process::id()));
    let users = "allowed_email_domains = [\"team.example.com\"]\ndisable_idle_after_days = 30";
    let mut env = Env::with_config(Tls::DevCa, &format!("{}{}", idp.config(&dir, users, true), smtp.config())).await;
    env.login().await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let t = add_json(&env, &[&app.port.to_string(), "--public"]).await;
    let host = hostname(t["public_url"].as_str().unwrap());
    let email = "dev@team.example.com";
    *idp.person.lock().unwrap() = common::OidcPerson::new("dev-1", email);
    let cookie = session_of(&oidc_sign_in(&env, None).await);
    let id = user_named(&env, email).await["id"].as_str().unwrap().to_string();
    assert_eq!(env.get_public(&host, "/").await.0, StatusCode::OK);

    // The machine is theirs, and 31 days pass with nothing vouching for them.
    env.stop_server().await;
    let db = rusqlite::Connection::open(env.root.join("server/magicpipes.db")).unwrap();
    db.execute("UPDATE users SET vouched_at = vouched_at - 31 * 86400 WHERE id = ?1", [&id]).unwrap();
    db.execute("UPDATE agents SET owner_user_id = ?1", [&id]).unwrap();
    env.start_server().await;

    // The hourly round, which starts with the server, disables the account and stops the machine.
    env.eventually("the account to be disabled", Duration::from_secs(10), || async { user_named(&env, email).await["disabled"] == true }).await;
    let disabled = user_named(&env, email).await;
    assert_eq!((disabled["disabled"].as_bool(), disabled["disabled_reason"].as_str()), (Some(true), Some("idle")), "{disabled}");
    let told = smtp.wait_for(email, 1).await;
    assert!(told.text.contains("hasn't been signed in to for 30 days") && told.text.contains(&format!("{}/login", env.server_url())), "{}", told.text);
    env.eventually("the machine to stop serving", Duration::from_secs(15), || async { env.get_public(&host, "/").await.0 != StatusCode::OK }).await;
    assert!(env.ui("/account", Some(&cookie), None).await.location.as_deref().is_some_and(|l| l.starts_with("/login")), "signed out");
    let admin = env.admin_token();
    let (_, audit) = env.api("GET", "/api/v1/audit?limit=20", Some(&admin)).await;
    assert!(audit["entries"].as_array().unwrap().iter().any(|e| e["action"] == "user.disable" && e["detail"] == "no single sign-on in 30 days"), "{audit}");
    let admin_cookie = admin_session(&env).await;
    let page = env.ui("/users", Some(&admin_cookie), None).await;
    assert!(page.html.contains("no sign-in in 30 days") && page.html.contains("Keep disabled"), "{}", page.html);

    // Signing in again enables it, and the machine serves again by itself.
    session_of(&oidc_sign_in(&env, None).await);
    let back = user_named(&env, email).await;
    assert!(back["disabled"] == false && back.get("disabled_reason").is_none(), "{back}");
    env.eventually("the machine to serve again", Duration::from_secs(30), || async { env.get_public(&host, "/").await.0 == StatusCode::OK }).await;
    let (_, audit) = env.api("GET", "/api/v1/audit?limit=20", Some(&admin)).await;
    assert!(audit["entries"].as_array().unwrap().iter().any(|e| e["action"] == "user.enable" && e["detail"] == "signed in again through oidc:fake"), "{audit}");

    // An administrator who knows they've left keeps it disabled, and signing in no longer helps.
    db.execute("UPDATE users SET disabled_at = unixepoch(), disabled_reason = 'idle' WHERE id = ?1", [&id]).unwrap();
    let page = env.ui("/users", Some(&admin_cookie), None).await;
    let kept = env.ui(&format!("/users/{id}"), Some(&admin_cookie), Some(&[("csrf", &page.csrf()), ("action", "keep-disabled")])).await;
    assert_eq!(kept.location.as_deref(), Some("/users?done=user-kept-disabled"), "{}", kept.html);
    let kept = user_named(&env, email).await;
    assert!(kept["disabled"] == true && kept.get("disabled_reason").is_none(), "{kept}");
    assert_eq!(oidc_sign_in(&env, None).await.status, StatusCode::FORBIDDEN);
}

/// GitHub isn't OpenID Connect, but who gets in is decided the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn github_sign_in_admits_only_who_it_should() {
    let idp = common::FakeOidc::start().await;
    let dir = std::env::temp_dir().join(format!("mp-github-{}", std::process::id()));
    let users = r#"bootstrap_admins = ["boss@example.com"]
allowed_email_domains = ["team.example.com"]"#;
    let config = format!("{}kind = \"github\"\n", idp.config(&dir, users, true));
    let env = Env::with_config(Tls::DevCa, &config).await;
    let admin = env.admin_token();
    let set = |p: common::OidcPerson| *idp.person.lock().unwrap() = p;
    let accounts = async || env.api("GET", "/api/v1/users", Some(&admin)).await.1["users"].as_array().unwrap().clone();

    // The browser goes to GitHub's own address, asking for no more than it needs.
    let start = env.ui("/auth/oidc/fake?next=/account", None, None).await;
    let to = start.location.clone().expect("sent to GitHub");
    assert!(to.starts_with(&format!("{}/login/oauth/authorize?", idp.issuer)) && to.contains("scope=user%3Aemail") && to.contains("code_challenge_method=S256"), "{to}");

    // Having a GitHub account gets nobody in.
    set(common::OidcPerson::new("101", "stranger@example.org"));
    let r = oidc_sign_in(&env, None).await;
    assert!(r.status == StatusCode::FORBIDDEN && r.html.contains("stranger@example.org can&#39;t sign in here") && r.cookie.is_none(), "{}", r.html);
    assert!(accounts().await.is_empty());

    // A verified address in an allowed domain makes a member, named by the numeric id.
    set(common::OidcPerson::new("102", "dev@team.example.com"));
    let r = oidc_sign_in(&env, None).await;
    assert_eq!(r.location.as_deref(), Some("/"), "{}", r.html);
    let cookie = session_of(&r);
    let users = accounts().await;
    assert_eq!((users.len(), users[0]["email"].as_str(), users[0]["role"].as_str()), (1, Some("dev@team.example.com"), Some("member")));
    assert_eq!(env.ui("/account", Some(&cookie), None).await.status, StatusCode::OK);
    assert!(env.ui("/account", Some(&cookie), None).await.html.contains("someone"), "the login, for someone without a public name");

    // Changing the address at GitHub changes nothing here: the account follows the id.
    set(common::OidcPerson::new("102", "new-address@elsewhere.example.org"));
    assert_eq!(oidc_sign_in(&env, None).await.location.as_deref(), Some("/"));
    assert_eq!(accounts().await.len(), 1);

    // Only an address GitHub verified counts, whatever else the account lists.
    let mut unverified = common::OidcPerson::new("103", "other@team.example.com");
    unverified.verified = false;
    set(unverified.clone());
    let r = oidc_sign_in(&env, None).await;
    assert!(r.status == StatusCode::FORBIDDEN && r.html.contains("confirm an email address"), "{}", r.html);
    assert_eq!(accounts().await.len(), 1);

    // A bootstrap address needs the same.
    unverified.sub = "104".into();
    unverified.email = "boss@example.com".into();
    set(unverified);
    assert_eq!(oidc_sign_in(&env, None).await.status, StatusCode::FORBIDDEN);
    set(common::OidcPerson::new("104", "boss@example.com"));
    assert_eq!(oidc_sign_in(&env, None).await.location.as_deref(), Some("/"));
    assert!(accounts().await.iter().any(|u| u["email"] == "boss@example.com" && u["role"] == "admin"));

    // A code that doesn't pass gets the 200 GitHub answers with, and no session.
    let start = env.ui("/auth/oidc/fake", None, None).await;
    let attempt = start.cookie.clone().expect("attempt cookie");
    let state = start.location.as_deref().unwrap().split("state=").nth(1).unwrap().split('&').next().unwrap().to_string();
    let refused = env.ui(&format!("/auth/oidc/fake/callback?code=made-up&state={state}"), Some(&attempt), None).await;
    assert!(refused.status == StatusCode::UNAUTHORIZED && refused.cookie.is_none(), "{}", refused.html);
    assert!(env.server_log().contains("bad_verification_code"), "the log says why");

    // Another browser's answer, or none at all, gets as far as for any provider.
    let forged = env.ui("/auth/oidc/fake/callback?code=x&state=wrong", Some(&attempt), None).await;
    assert!(forged.status == StatusCode::BAD_REQUEST && forged.cookie.is_none(), "{}", forged.html);
    std::fs::remove_dir_all(&dir).ok();
}

/// Adding GitHub on the Settings page, without a restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settings_page_adds_github() {
    let idp = common::FakeOidc::start().await;
    let env = Env::with_config(Tls::DevCa, "[users]\nallowed_email_domains = [\"team.example.com\"]\n").await;
    let admin = admin_session(&env).await;

    let form = env.ui("/settings/providers/new?type=github", Some(&admin), None).await;
    assert!(form.html.contains("OAuth Apps") && form.html.contains(r#"value="https://github.com""#), "{}", form.html);
    assert!(form.html.contains("/auth/oidc/github/callback"), "the callback to register: {}", form.html);
    assert!(!form.html.contains(r#"name="trust_email""#) && form.html.contains(r#"name="link_by_email""#), "it says which addresses it verified: {}", form.html);
    let csrf = form.csrf();
    let add = async |url: &str, extra: &[(&str, &str)]| {
        let mut fields = vec![("csrf", csrf.as_str()), ("type", "github"), ("id", "github"), ("url", url), ("label", "GitHub"), ("client_id", common::OIDC_CLIENT), ("client_secret", common::OIDC_SECRET)];
        fields.extend_from_slice(extra);
        env.ui("/settings/providers/new", Some(&admin), Some(&fields)).await
    };

    // An address that isn't GitHub shows up now, and the form comes back as typed.
    let wrong = add(&format!("{}/nothing-here", idp.issuer), &[]).await;
    assert!(wrong.status == StatusCode::BAD_REQUEST && wrong.html.contains("doesn&#39;t look like GitHub") && wrong.html.contains(common::OIDC_CLIENT) && !wrong.html.contains(common::OIDC_SECRET), "{}", wrong.html);
    let forced = add(&idp.issuer, &[("trust_email", "on")]).await;
    assert_eq!(forced.status, StatusCode::BAD_REQUEST, "{}", forced.html);

    let added = add(&format!("{}/", idp.issuer), &[]).await;
    assert_eq!(added.location.as_deref(), Some("/settings?done=provider-added"), "{}", added.html);
    let login = env.ui("/login", None, None).await;
    assert!(login.html.contains("Continue with GitHub"), "{}", login.html);

    idp.person.lock().unwrap().sub = "7".into();
    idp.person.lock().unwrap().email = "dev@team.example.com".into();
    let r = oidc_sign_in_at(&env, "github", None).await;
    assert_eq!(r.location.as_deref(), Some("/"), "{}", r.html);

    // What's there can be changed, and stays GitHub. The configuration in effect says so.
    let page = env.ui("/settings/providers/github", Some(&admin), None).await;
    assert!(page.status == StatusCode::OK && !page.html.contains(r#"name="trust_email""#), "{}", page.html);
    let saved = env.ui("/settings/providers/github", Some(&admin), Some(&[("csrf", &csrf), ("label", "GitHub at work"), ("client_id", common::OIDC_CLIENT), ("client_secret", "")])).await;
    assert_eq!(saved.location.as_deref(), Some("/settings?done=provider-saved"), "{}", saved.html);
    assert_eq!(oidc_sign_in_at(&env, "github", None).await.location.as_deref(), Some("/"));
    let generated = std::fs::read_to_string(env.root.join("server/magicpipesd.generated.toml")).unwrap();
    assert!(generated.contains("kind = \"github\"") && !generated.contains(common::OIDC_SECRET), "{generated}");

    // After a restart too: it's the database's word.
    let mut env = env;
    env.stop_server().await;
    env.start_server().await;
    assert_eq!(oidc_sign_in_at(&env, "github", None).await.location.as_deref(), Some("/"));
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
    // A scraper brings its own token, whatever the proxy adds.
    let bearer = format!("Bearer {}", down.admin_token());
    let proxied = idp.sign(&claims("sub-1", "ann@example.com", true));
    let scraped = down.ui_with("/metrics", None, None, &[("x-proxy-token", &proxied), ("authorization", &bearer)]).await;
    assert!(scraped.status == StatusCode::OK && scraped.html.contains("magicpipes_build_info"), "{}", scraped.html);
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

// ---- email ------------------------------------------------------------------------------------

/// A new account, through a real invitation. Returns its password and session.
async fn invited_account(env: &Env, smtp: &common::FakeSmtp, email: &str) -> (String, String) {
    let body = serde_json::json!({ "email": email });
    let (status, v) = env.api_json("POST", "/api/v1/invitations", Some(&env.admin_token()), body).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    let code = smtp.wait_for(email, 1).await.code();
    let password = format!("a long password for {email}");
    let r = env.ui("/invite/accept", None, Some(&[("code", code.as_str()), ("display_name", ""), ("password", password.as_str()), ("repeat", password.as_str())])).await;
    (password, r.cookie.unwrap_or_else(|| panic!("no session: {}", r.html)))
}

async fn user_named(env: &Env, email: &str) -> Value {
    let (_, list) = env.api("GET", "/api/v1/users", Some(&env.admin_token())).await;
    list["users"].as_array().unwrap().iter().find(|u| u["email"] == email).cloned().unwrap_or_else(|| panic!("no account for {email}: {list}"))
}

/// How many accounts there are.
async fn user_count(env: &Env) -> usize {
    env.api("GET", "/api/v1/users", Some(&env.admin_token())).await.1["users"].as_array().unwrap().len()
}

/// Inviting someone: the message, the page it opens, the account it makes, and that it does so once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invitations_bring_people_in_once() {
    let smtp = common::FakeSmtp::start().await;
    let env = Env::with_config(Tls::DevCa, &smtp.config()).await;
    let admin = admin_session(&env).await;
    let token = env.admin_token();
    env.api_json("POST", "/api/v1/tags", Some(&token), serde_json::json!({ "name": "team:dev", "access": true })).await;

    let users = env.ui("/users", Some(&admin), None).await;
    assert!(users.html.contains("Send invitation") && users.html.contains("Set a password yourself instead"), "{}", users.html);
    assert!(!users.html.contains("<h2>Invitations"), "nothing to list yet");
    let csrf = users.csrf();
    let sent = env.ui("/users", Some(&admin), Some(&[("csrf", &csrf), ("email", "Ann@Example.com"), ("display_name", "Ann"), ("role", "member"), ("tag", "team:dev"), ("how", "invite")])).await;
    assert_eq!(sent.location.as_deref(), Some("/users?done=invitation-sent"), "{}", sent.html);

    let mail = smtp.wait_for("ann@example.com", 1).await;
    let code = mail.code();
    assert_eq!(mail.from, "mp@example.com");
    assert!(mail.text.contains("You're invited to MagicPipes") && mail.text.contains("An administrator invited you"), "{}", mail.text);
    assert!(mail.text.contains(&format!("https://localhost:{}/invite#code={code}", env.mgmt_port)), "from the configuration, in the fragment: {}", mail.text);
    assert!(!env.server_log().contains(&code), "codes stay out of the log");

    // Administrators see who's invited, and never the code.
    let users = env.ui("/users", Some(&admin), None).await;
    assert!(users.html.contains("<h2>Invitations") && users.html.contains("ann@example.com") && users.html.contains("team:dev") && !users.html.contains(&code), "{}", users.html);
    let (_, list) = env.api("GET", "/api/v1/invitations", Some(&token)).await;
    assert_eq!((list["invitations"][0]["email"].as_str(), list["invitations"][0]["role"].as_str(), list["invitations"][0]["expired"].as_bool()), (Some("ann@example.com"), Some("member"), Some(false)), "{list}");
    assert!(!list.to_string().contains(&code));

    // The page a link opens needs nothing from the server, and without scripts asks for the code.
    let page = env.ui("/invite", None, None).await;
    assert!(page.status == StatusCode::OK && page.html.contains("<div data-code-field>"), "{}", page.html);

    let wrong = env.ui("/invite", None, Some(&[("code", "mpi_wrong")])).await;
    assert!(wrong.status == StatusCode::UNAUTHORIZED && wrong.html.contains("expired or was already used"), "{}", wrong.html);

    // Another site's form can't open it or use it.
    let elsewhere = [("sec-fetch-site", "cross-site")];
    assert_eq!(env.ui_with("/invite", None, Some(&[("code", code.as_str())]), &elsewhere).await.status, StatusCode::FORBIDDEN);
    let fields = [("code", code.as_str()), ("password", "a long enough password"), ("repeat", "a long enough password")];
    let refused = env.ui_with("/invite/accept", None, Some(&fields), &elsewhere).await;
    assert!(refused.status == StatusCode::FORBIDDEN && refused.cookie.is_none(), "{}", refused.html);

    // Opening it says who it's for and uses nothing up.
    for _ in 0..2 {
        let open = env.ui("/invite", None, Some(&[("code", code.as_str())])).await;
        assert!(open.status == StatusCode::OK && open.html.contains("ann@example.com") && open.html.contains("a member") && open.html.contains(r#"value="Ann""#), "{}", open.html);
    }

    // A password that can't be used brings the form back, as typed, and without the password.
    let short = env.ui("/invite/accept", None, Some(&[("code", code.as_str()), ("display_name", "Ann B"), ("password", "short"), ("repeat", "short")])).await;
    assert!(short.status == StatusCode::BAD_REQUEST && short.html.contains("at least 12") && short.html.contains(r#"value="Ann B""#) && short.cookie.is_none(), "{}", short.html);
    let differ = env.ui("/invite/accept", None, Some(&[("code", code.as_str()), ("display_name", "Ann B"), ("password", "a long enough password"), ("repeat", "another long password")])).await;
    assert!(differ.status == StatusCode::BAD_REQUEST && differ.html.contains("don&#39;t match") && !differ.html.contains("a long enough password"), "{}", differ.html);
    assert_eq!(user_count(&env).await, 0);

    let password = "a long enough password";
    let accepted = env.ui("/invite/accept", None, Some(&[("code", code.as_str()), ("display_name", "Ann B"), ("password", password), ("repeat", password)])).await;
    assert_eq!(accepted.location.as_deref(), Some("/?done=welcome"), "{}", accepted.html);
    let session = accepted.cookie.expect("signed in");
    assert!(env.ui("/?done=welcome", Some(&session), None).await.html.contains("Your account is ready"));

    // The account is what the invitation promised, and the address counts as proved.
    let ann = user_named(&env, "ann@example.com").await;
    assert_eq!((ann["role"].as_str(), ann["display_name"].as_str(), ann["email_verified"].as_bool(), ann["must_change_password"].as_bool()), (Some("member"), Some("Ann B"), Some(true), Some(false)), "{ann}");
    assert_eq!(ann["tags"], serde_json::json!(["team:dev"]), "{ann}");
    let signed_in = env.ui("/login", None, Some(&[("email", "ann@example.com"), ("password", password)])).await;
    assert_eq!(signed_in.location.as_deref(), Some("/"), "no forced change: they chose it");

    // Once.
    assert_eq!(env.ui("/invite", None, Some(&[("code", code.as_str())])).await.status, StatusCode::UNAUTHORIZED);
    let again = env.ui("/invite/accept", None, Some(&[("code", code.as_str()), ("password", password), ("repeat", password)])).await;
    assert!(again.status == StatusCode::UNAUTHORIZED && again.cookie.is_none(), "{}", again.html);
    let (_, list) = env.api("GET", "/api/v1/invitations", Some(&token)).await;
    assert_eq!(list["invitations"], serde_json::json!([]));
    assert_eq!(user_count(&env).await, 1);

    // Someone with an account isn't invited again, and the form says so as typed.
    let csrf = env.ui("/users", Some(&admin), None).await.csrf();
    let taken = env.ui("/users", Some(&admin), Some(&[("csrf", &csrf), ("email", "ann@example.com"), ("role", "admin"), ("how", "invite")])).await;
    assert!(taken.status == StatusCode::BAD_REQUEST && taken.html.contains("already exists") && taken.html.contains(r#"value="ann@example.com""#) && taken.html.contains(r#"value="admin" selected"#), "{}", taken.html);
    assert_eq!(smtp.sent_to("ann@example.com").len(), 1, "no second message");
    let (status, v) = env.api_json("POST", "/api/v1/invitations", Some(&token), serde_json::json!({ "email": "ann@example.com" })).await;
    assert_eq!((status, v["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("email_taken")));

    // A password set by hand is still there for someone without an inbox here, with their tags.
    let by_hand = env.ui("/users", Some(&admin), Some(&[("csrf", &csrf), ("email", "pat@example.com"), ("role", "member"), ("tag", "team:dev"), ("how", "password"), ("password", "")])).await;
    assert!(by_hand.status == StatusCode::OK && by_hand.html.contains("Password for pat@example.com"), "{}", by_hand.html);
    assert_eq!(user_named(&env, "pat@example.com").await["tags"], serde_json::json!(["team:dev"]));
    assert!(smtp.sent_to("pat@example.com").is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invitations_can_be_sent_again_revoked_or_refused() {
    let smtp = common::FakeSmtp::start().await;
    let env = Env::with_config(Tls::DevCa, &smtp.config()).await;
    let admin = admin_session(&env).await;
    let token = env.admin_token();
    let opens = async |code: &str| env.ui("/invite", None, Some(&[("code", code)])).await.status == StatusCode::OK;

    let (status, v) = env.api_json("POST", "/api/v1/invitations", Some(&token), serde_json::json!({ "email": "a@example.com", "role": "admin" })).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    let id = v["invitation"]["id"].as_str().unwrap().to_string();
    let first = smtp.wait_for("a@example.com", 1).await.code();
    assert!(!v.to_string().contains(&first), "the API never gives the code");
    assert!(opens(&first).await);

    // Sending again ends the old link, once the new one has gone out.
    let csrf = env.ui("/users", Some(&admin), None).await.csrf();
    let resent = env.ui(&format!("/invitations/{id}/resend"), Some(&admin), Some(&[("csrf", &csrf)])).await;
    assert_eq!(resent.location.as_deref(), Some("/users?done=invitation-resent"), "{}", resent.html);
    let second = smtp.wait_for("a@example.com", 2).await.code();
    assert!(second != first && !opens(&first).await && opens(&second).await);

    // When the mail server refuses, the page says why, and the link that's out keeps working.
    smtp.refuse.store(true, std::sync::atomic::Ordering::Relaxed);
    let failed = env.ui(&format!("/invitations/{id}/resend"), Some(&admin), Some(&[("csrf", &csrf)])).await;
    assert!(failed.status == StatusCode::BAD_GATEWAY && failed.html.contains("couldn&#39;t be sent") && failed.html.contains("no such mailbox"), "{}", failed.html);
    assert!(opens(&second).await);
    let refused = env.ui("/users", Some(&admin), Some(&[("csrf", &csrf), ("email", "b@example.com"), ("display_name", "Bea"), ("role", "member"), ("how", "invite")])).await;
    assert!(refused.status == StatusCode::BAD_REQUEST && refused.html.contains("no such mailbox") && refused.html.contains(r#"value="b@example.com""#) && refused.html.contains(r#"value="Bea""#), "{}", refused.html);
    let (status, v) = env.api_json("POST", "/api/v1/invitations", Some(&token), serde_json::json!({ "email": "b@example.com" })).await;
    assert_eq!((status, v["error"]["code"].as_str()), (StatusCode::BAD_GATEWAY, Some("mail_failed")), "{v}");
    assert_eq!(env.api("GET", "/api/v1/invitations", Some(&token)).await.1["invitations"].as_array().unwrap().len(), 1, "nothing to show for it");
    smtp.refuse.store(false, std::sync::atomic::Ordering::Relaxed);

    // Revoking ends the link, and the API can do both.
    let (status, v) = env.api_json("POST", &format!("/api/v1/invitations/{id}/resend"), Some(&token), serde_json::json!({})).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let third = smtp.wait_for("a@example.com", 3).await.code();
    let revoked = env.ui(&format!("/invitations/{id}/revoke"), Some(&admin), Some(&[("csrf", &csrf)])).await;
    assert_eq!(revoked.location.as_deref(), Some("/users?done=invitation-revoked"), "{}", revoked.html);
    assert!(!opens(&third).await);
    assert_eq!(env.api("DELETE", &format!("/api/v1/invitations/{id}"), Some(&token)).await.0, StatusCode::NOT_FOUND);

    // Someone who isn't an administrator can't invite, or see who's invited.
    let (_, member) = invited_account(&env, &smtp, "m@example.com").await;
    let member_csrf = env.ui("/account", Some(&member), None).await.csrf();
    let (_, v) = env.api_json("POST", "/api/v1/invitations", Some(&token), serde_json::json!({ "email": "n@example.com" })).await;
    let n = v["invitation"]["id"].as_str().unwrap().to_string();
    assert_eq!(env.ui(&format!("/invitations/{n}/revoke"), Some(&member), Some(&[("csrf", &member_csrf)])).await.location.as_deref(), Some("/account"));
    assert!(env.api("GET", "/api/v1/invitations", Some(&token)).await.1["invitations"].as_array().unwrap().iter().any(|i| i["id"] == n.as_str()));

    // An administrator's invitations end with their powers.
    let (_, boss_session) = invited_account(&env, &smtp, "boss@example.com").await;
    let boss = user_named(&env, "boss@example.com").await["id"].as_str().unwrap().to_string();
    env.api_json("PATCH", &format!("/api/v1/users/{boss}"), Some(&token), serde_json::json!({ "role": "admin" })).await;
    let boss_csrf = env.ui("/users", Some(&boss_session), None).await.csrf();
    env.ui("/users", Some(&boss_session), Some(&[("csrf", &boss_csrf), ("email", "friend@example.com"), ("role", "admin"), ("how", "invite")])).await;
    let friend = smtp.wait_for("friend@example.com", 1).await.code();
    assert!(smtp.wait_for("friend@example.com", 1).await.text.contains("boss@example.com invited you"));
    assert!(opens(&friend).await);
    env.api_json("PATCH", &format!("/api/v1/users/{boss}"), Some(&token), serde_json::json!({ "disabled": true })).await;
    assert!(!opens(&friend).await, "the administrator who sent it was disabled");
}

/// A server with no mail server shows none of this, and the API says why.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_a_mail_server_nothing_offers_email() {
    let env = Env::new(Tls::DevCa).await;
    let admin = admin_session(&env).await;
    let (status, v) = env.api_json("POST", "/api/v1/invitations", Some(&env.admin_token()), serde_json::json!({ "email": "a@example.com" })).await;
    assert_eq!((status, v["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("mail_not_configured")), "{v}");
    let login = env.ui("/login", None, None).await;
    assert!(!login.html.contains("Forgot your password"), "{}", login.html);
    assert_eq!(env.ui("/login/email", None, None).await.location.as_deref(), Some("/login"));
    let users = env.ui("/users", Some(&admin), None).await;
    assert!(users.html.contains("Add user") && !users.html.contains("Send invitation"), "{}", users.html);
    assert!(env.ui("/settings", Some(&admin), None).await.html.contains("Set up email"));

    // Adding someone by hand works as ever, without naming how.
    let added = env.ui("/users", Some(&admin), Some(&[("csrf", &users.csrf()), ("email", "pat@example.com"), ("role", "member"), ("password", "a long enough password")])).await;
    assert_eq!(added.location.as_deref(), Some("/users?done=user-added"), "{}", added.html);
}

/// An invitation is the proof, so the provider's own idea of the address doesn't matter. The form
/// can't redirect to another site (`form-action 'self'`), so a page moves on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_invitation_can_be_accepted_with_a_provider() {
    let idp = common::FakeOidc::start().await;
    let smtp = common::FakeSmtp::start().await;
    let dir = std::env::temp_dir().join(format!("mp-invite-oidc-{}", std::process::id()));
    let env = Env::with_config(Tls::DevCa, &format!("{}{}", idp.config(&dir, "", false), smtp.config())).await;
    let token = env.admin_token();
    let invite = async |email: &str, role: &str| {
        let (status, v) = env.api_json("POST", "/api/v1/invitations", Some(&token), serde_json::json!({ "email": email, "role": role })).await;
        assert_eq!(status, StatusCode::CREATED, "{v}");
        smtp.wait_for(email, 1).await.code()
    };
    // Leaves for the provider from the invitation; the attempt cookie and the way back.
    let leave = async |code: &str| {
        let start = env.ui("/invite/provider/fake", None, Some(&[("code", code)])).await;
        assert!(start.status == StatusCode::OK && start.location.is_none(), "{}", start.html);
        let attempt = start.cookie.clone().expect("attempt cookie");
        let to = start.refresh.clone().expect("a page that moves on");
        let to = to.strip_prefix("0;url=").expect("at once").to_string();
        assert!(to.starts_with(&idp.issuer) && start.html.contains(&format!(r#"href="{}""#, to.replace('&', "&amp;"))), "{to}");
        assert!(!to.contains(code), "the code never goes to the provider: {to}");
        let (status, back) = plain_get(&to).await;
        assert_eq!(status, StatusCode::FOUND);
        (attempt, back.strip_prefix(&format!("https://localhost:{}", env.mgmt_port)).expect("back to the management host").to_string())
    };

    // Ann's address at the provider isn't the invited one, and isn't anywhere in the sign-in rules.
    *idp.person.lock().unwrap() = common::OidcPerson::new("sub-ann", "ann.personal@elsewhere.example.org");
    let code = invite("ann@example.com", "admin").await;
    let open = env.ui("/invite", None, Some(&[("code", code.as_str())])).await;
    assert!(open.html.contains(r#"action="/invite/provider/fake""#) && open.html.contains("Continue with Fake ID") && open.html.contains("an administrator"), "{}", open.html);
    let (attempt, callback) = leave(&code).await;
    let r = env.ui(&callback, Some(&attempt), None).await;
    assert_eq!(r.location.as_deref(), Some("/"), "{}", r.html);
    assert_eq!(env.ui("/account", r.cookie.as_deref(), None).await.status, StatusCode::OK);

    let ann = user_named(&env, "ann@example.com").await;
    assert_eq!((ann["role"].as_str(), ann["email_verified"].as_bool(), ann["has_password"].as_bool()), (Some("admin"), Some(true), Some(false)), "{ann}");
    assert_eq!(env.ui("/invite", None, Some(&[("code", code.as_str())])).await.status, StatusCode::UNAUTHORIZED, "used up");

    // From now on that identity is her way in, and it makes no second account.
    assert_eq!(oidc_sign_in(&env, None).await.location.as_deref(), Some("/"));
    assert_eq!(user_count(&env).await, 1);

    // Her identity can't become someone else's account. Their invitation survives for another way.
    let code = invite("bob@example.com", "member").await;
    let (attempt, callback) = leave(&code).await;
    let r = env.ui(&callback, Some(&attempt), None).await;
    assert!(r.status == StatusCode::CONFLICT && r.html.contains("already signs in to another account") && r.cookie.is_none(), "{}", r.html);
    assert_eq!(user_count(&env).await, 1);
    assert_eq!(env.ui("/invite", None, Some(&[("code", code.as_str())])).await.status, StatusCode::OK);

    // An invitation used up while the browser is away at the provider gets nobody in.
    *idp.person.lock().unwrap() = common::OidcPerson::new("sub-bob", "bob@elsewhere.example.org");
    let (attempt, callback) = leave(&code).await;
    let password = "a long enough password";
    env.ui("/invite/accept", None, Some(&[("code", code.as_str()), ("password", password), ("repeat", password)])).await.cookie.expect("accepted with a password");
    let r = env.ui(&callback, Some(&attempt), None).await;
    assert!(r.status == StatusCode::BAD_REQUEST && r.html.contains("expired or was already used") && r.cookie.is_none(), "{}", r.html);
    assert_eq!(user_count(&env).await, 2);

    // An unknown code goes nowhere near the provider.
    let requests = idp.token_requests.load(std::sync::atomic::Ordering::Relaxed);
    let r = env.ui("/invite/provider/fake", None, Some(&[("code", "mpi_made_up")])).await;
    assert!(r.status == StatusCode::UNAUTHORIZED && r.refresh.is_none() && r.cookie.is_none(), "{}", r.html);
    assert_eq!(idp.token_requests.load(std::sync::atomic::Ordering::Relaxed), requests);
    std::fs::remove_dir_all(&dir).ok();
}

/// The answer never depends on who has an account, and the messages only go where they should.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sign_in_links_tell_nobody_who_has_an_account() {
    let idp = common::FakeOidc::start().await;
    let smtp = common::FakeSmtp::start().await;
    let dir = std::env::temp_dir().join(format!("mp-links-{}", std::process::id()));
    let env = Env::with_config(Tls::DevCa, &format!("{}{}", idp.config(&dir, r#"allowed_email_domains = ["example.com"]"#, false), smtp.config())).await;
    let token = env.admin_token();

    let (password, first_session) = invited_account(&env, &smtp, "ann@example.com").await;
    // Typed in by an administrator, so nothing shows the address is theirs.
    let body = serde_json::json!({ "email": "typed@example.com", "password": "a long enough password" });
    env.api_json("POST", "/api/v1/users", Some(&token), body).await;
    sign_in(&env, "typed@example.com", "a long enough password").await;
    // Only ever signs in with a provider, which vouches for the address.
    *idp.person.lock().unwrap() = common::OidcPerson::new("sub-sso", "sso@example.com");
    oidc_sign_in(&env, None).await.cookie.expect("signed in");
    assert_eq!(user_named(&env, "sso@example.com").await["email_verified"].as_bool(), Some(true), "the provider vouched for it");
    // Disabled.
    invited_account(&env, &smtp, "off@example.com").await;
    let off = user_named(&env, "off@example.com").await["id"].as_str().unwrap().to_string();
    env.api_json("PATCH", &format!("/api/v1/users/{off}"), Some(&token), serde_json::json!({ "disabled": true })).await;

    let login = env.ui("/login", None, None).await;
    assert!(login.html.contains(r#"href="/login/email""#) && login.html.contains("Forgot your password"), "{}", login.html);
    assert!(env.ui("/login/email", None, None).await.html.contains(r#"action="/login/email""#));

    let ask = async |address: &str| env.ui("/login/email", None, Some(&[("email", address)])).await;
    let before = smtp.messages.lock().unwrap().len();
    let answers = [ask("nobody@example.com").await, ask("typed@example.com").await, ask("sso@example.com").await, ask("off@example.com").await, ask("not an address").await];
    let shown = |r: &common::UiResponse, address: &str| r.html.replace(address, "ADDRESS");
    for (answer, address) in answers.iter().zip(["nobody@example.com", "typed@example.com", "sso@example.com", "off@example.com", "not an address"]) {
        assert_eq!((answer.status, answer.cookie.as_deref()), (StatusCode::OK, None), "{}", answer.html);
        assert_eq!(shown(answer, address), shown(&answers[0], "nobody@example.com"), "the same page for {address}");
    }
    assert!(answers[0].html.contains("If nobody@example.com has an account"), "{}", answers[0].html);

    // Requests are answered in order, so once this one's message is here, those were looked at.
    let answer = ask("ANN@example.com ").await;
    assert_eq!(shown(&answer, "ANN@example.com"), shown(&answers[0], "nobody@example.com"), "and for someone who has one");
    let mail = smtp.wait_for("ann@example.com", 2).await;
    assert_eq!(smtp.messages.lock().unwrap().len(), before + 1, "nothing went to the others: {:?}", smtp.messages.lock().unwrap());
    assert!(mail.text.contains("Your MagicPipes sign-in link") && mail.text.contains(&format!("https://localhost:{}/login/link#code=", env.mgmt_port)), "{}", mail.text);
    let code = mail.code();
    assert!(!env.server_log().contains(&code));

    // Opening the page uses nothing up, whoever opens it; a scanner sees a form.
    let page = env.ui("/login/link", None, None).await;
    assert!(page.status == StatusCode::OK && page.cookie.is_none() && page.html.contains("data-code-field"), "{}", page.html);
    assert_eq!(env.ui("/login/link", None, Some(&[("code", "mpl_wrong")])).await.status, StatusCode::UNAUTHORIZED);
    let elsewhere = env.ui_with("/login/link", None, Some(&[("code", code.as_str())]), &[("sec-fetch-site", "cross-site")]).await;
    assert!(elsewhere.status == StatusCode::FORBIDDEN && elsewhere.cookie.is_none(), "signing someone in to another account");
    assert_eq!(env.ui_with("/login/email", None, Some(&[("email", "ann@example.com")]), &[("sec-fetch-site", "cross-site")]).await.status, StatusCode::FORBIDDEN);

    let used = env.ui("/login/link", None, Some(&[("code", code.as_str())])).await;
    assert_eq!(used.location.as_deref(), Some("/"), "{}", used.html);
    let session = used.cookie.expect("signed in");
    assert_eq!(env.ui("/account", Some(&session), None).await.status, StatusCode::OK);
    assert_eq!(env.ui("/account", Some(&first_session), None).await.status, StatusCode::OK, "other sessions carry on");
    assert_eq!(env.ui("/login/link", None, Some(&[("code", code.as_str())])).await.status, StatusCode::UNAUTHORIZED, "once");
    assert_eq!(env.ui("/login", None, Some(&[("email", "ann@example.com"), ("password", &password)])).await.location.as_deref(), Some("/"), "the password still works");
    let (_, audit) = env.api("GET", "/api/v1/audit?limit=20", Some(&token)).await;
    assert!(audit["entries"].as_array().unwrap().iter().any(|e| e["action"] == "session.login" && e["detail"] == "email link"), "{audit}");
    std::fs::remove_dir_all(&dir).ok();
}

/// Forgetting a password: the link, a new one, and what that ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_in_link_can_replace_a_forgotten_password() {
    let smtp = common::FakeSmtp::start().await;
    let env = Env::with_config(Tls::DevCa, &smtp.config()).await;
    let token = env.admin_token();
    let (old, session) = invited_account(&env, &smtp, "ann@example.com").await;
    let ask_for_a_link = async |email: &str, nth: usize| {
        env.ui("/login/email", None, Some(&[("email", email)])).await;
        smtp.wait_for(email, nth).await.code()
    };

    let code = ask_for_a_link("ann@example.com", 2).await;
    let new = "my new and much longer password";
    let differ = env.ui("/login/link", None, Some(&[("code", code.as_str()), ("new", new), ("repeat", "something else")])).await;
    assert!(differ.status == StatusCode::BAD_REQUEST && differ.html.contains("don&#39;t match") && differ.html.contains(&format!(r#"value="{code}""#)) && !differ.html.contains(new) && differ.html.contains("<details class=\"more\" open"), "{}", differ.html);
    let short = env.ui("/login/link", None, Some(&[("code", code.as_str()), ("new", "short"), ("repeat", "short")])).await;
    assert!(short.status == StatusCode::BAD_REQUEST && short.html.contains("at least 12") && short.cookie.is_none(), "{}", short.html);
    assert_eq!(env.ui("/login", None, Some(&[("email", "ann@example.com"), ("password", &old)])).await.location.as_deref(), Some("/"), "nothing has changed yet");

    let done = env.ui("/login/link", None, Some(&[("code", code.as_str()), ("new", new), ("repeat", new)])).await;
    assert_eq!(done.location.as_deref(), Some("/?done=password-changed"), "{}", done.html);
    let current = done.cookie.expect("signed in");
    assert_eq!(env.ui("/account", Some(&current), None).await.status, StatusCode::OK);
    assert_eq!(env.ui("/account", Some(&session), None).await.status, StatusCode::SEE_OTHER, "other sessions ended");
    assert_eq!(env.ui("/login", None, Some(&[("email", "ann@example.com"), ("password", &old)])).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(env.ui("/login", None, Some(&[("email", "ann@example.com"), ("password", new)])).await.location.as_deref(), Some("/"));

    // Changing a password ends the links out there too.
    let code = ask_for_a_link("ann@example.com", 3).await;
    let form = env.ui("/password", Some(&current), None).await;
    let newer = "yet another much longer password";
    env.ui("/password", Some(&current), Some(&[("csrf", &form.csrf()), ("current", new), ("new", newer), ("repeat", newer)])).await.cookie.expect("changed");
    assert_eq!(env.ui("/login/link", None, Some(&[("code", code.as_str())])).await.status, StatusCode::UNAUTHORIZED);

    // An administrator's reset is a way to take an account back, so a link has to choose a new
    // password, which the temporary one can't be kept around for. It's still good afterwards.
    let (_, _) = invited_account(&env, &smtp, "bob@example.com").await;
    let bob = user_named(&env, "bob@example.com").await["id"].as_str().unwrap().to_string();
    let (status, _) = env.api_json("POST", &format!("/api/v1/users/{bob}/password"), Some(&token), serde_json::json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let code = ask_for_a_link("bob@example.com", 2).await;
    let must = env.ui("/login/link", None, Some(&[("code", code.as_str())])).await;
    assert!(must.status == StatusCode::BAD_REQUEST && must.html.contains("choose your own") && must.cookie.is_none(), "{}", must.html);
    let chosen = env.ui("/login/link", None, Some(&[("code", code.as_str()), ("new", new), ("repeat", new)])).await;
    assert_eq!(chosen.location.as_deref(), Some("/?done=password-changed"), "{}", chosen.html);
    assert_eq!(user_named(&env, "bob@example.com").await["must_change_password"].as_bool(), Some(false));

    // Disabling someone ends their links.
    let (_, _) = invited_account(&env, &smtp, "cy@example.com").await;
    let code = ask_for_a_link("cy@example.com", 2).await;
    let cy = user_named(&env, "cy@example.com").await["id"].as_str().unwrap().to_string();
    env.api_json("PATCH", &format!("/api/v1/users/{cy}"), Some(&token), serde_json::json!({ "disabled": true })).await;
    assert_eq!(env.ui("/login/link", None, Some(&[("code", code.as_str())])).await.status, StatusCode::UNAUTHORIZED);
}

/// What's between `start` and `end` in a page.
fn between<'a>(html: &'a str, start: &str, end: &str) -> &'a str {
    let at = html.find(start).unwrap_or_else(|| panic!("no {start} in {html}")) + start.len();
    &html[at..at + html[at..].find(end).expect("an end")]
}

/// Sign-in codes: set up from the Account page with the QR code's key, asked for after a password
/// and with an emailed link, each code and recovery code good once, wrong ones limited per
/// account, and turned off by their owner or an administrator's reset.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sign_in_codes_are_asked_for_after_the_password() {
    let smtp = common::FakeSmtp::start().await;
    let env = Env::with_config(Tls::DevCa, &smtp.config()).await;
    let email = "ann@example.com";
    let (password, session) = invited_account(&env, &smtp, email).await;
    let now = magicpipes_now;

    // Setting up: a QR code, the key to type, and a form that keeps the key when something's wrong.
    let account = env.ui("/account", Some(&session), None).await;
    assert!(account.html.contains("<h2>Sign-in codes</h2>") && account.html.contains(r#"href="/account/codes">Set up</a>"#), "{}", account.html);
    let setup = env.ui("/account/codes", Some(&session), None).await;
    assert!(setup.html.contains(r#"<svg class="qr""#) && setup.html.contains("otpauth://totp/MagicPipes%20%28localhost%29%3Aann%40example.com?secret="), "{}", setup.html);
    let key = between(&setup.html, r#"<code class="key">"#, "</code>").replace(' ', "");
    let sealed = between(&setup.html, r#"name="key" value=""#, "\"").to_string();
    let turn_on = async |code: &str, password: &str| {
        env.ui("/account/codes", Some(&session), Some(&[("csrf", &setup.csrf()), ("key", &sealed), ("code", code), ("password", password)])).await
    };
    let wrong = turn_on(&common::totp_code(&key, now() + 300), &password).await;
    assert!(wrong.status == StatusCode::BAD_REQUEST && wrong.html.contains("That code isn&#39;t right; enter the one the app shows now.") && wrong.html.contains(&format!(r#"<code class="key">{}"#, &key[..4])), "{}", wrong.html);
    let bad_password = turn_on(&common::totp_code(&key, now()), "not my password").await;
    assert!(bad_password.status == StatusCode::BAD_REQUEST && bad_password.html.contains("The password is not correct."), "{}", bad_password.html);
    let on = turn_on(&common::totp_code(&key, now()), &password).await;
    assert_eq!(on.status, StatusCode::OK, "{}", on.html);
    let recovery: Vec<String> = between(&on.html, r#"<pre class="term">"#, "</pre>").lines().map(str::to_string).collect();
    assert_eq!(recovery.len(), 10, "{}", on.html);
    let current = on.cookie.clone().expect("a new session");
    assert_eq!(env.ui("/account", Some(&session), None).await.status, StatusCode::SEE_OTHER, "other sessions ended");
    let account = env.ui("/account", Some(&current), None).await;
    assert!(account.html.contains("10 recovery codes left") && account.html.contains(r#"href="/account/codes">Manage</a>"#), "{}", account.html);
    assert_eq!(user_named(&env, email).await["has_totp"], true);

    // The password alone signs nobody in: a code finishes it, once.
    let password_then = async |code: &str| {
        let first = env.ui("/login", None, Some(&[("email", email), ("password", &password), ("next", "/account")])).await;
        assert_eq!(first.location.as_deref(), Some("/login/code?next=%2Faccount"), "{}", first.html);
        let note = first.cookie.clone().expect("the note for the code step");
        assert!(note.starts_with("__Host-mp_code="), "{note}");
        assert!(env.ui("/login/code", Some(&note), None).await.html.contains(r#"autocomplete="one-time-code""#));
        env.ui("/login/code", Some(&note), Some(&[("code", code), ("next", "/account")])).await
    };
    let refused = password_then(&common::totp_code(&key, now() + 300)).await;
    assert!(refused.status == StatusCode::UNAUTHORIZED && refused.html.contains("That code isn&#39;t right") && refused.cookie.is_none(), "{}", refused.html);
    let code = common::totp_code(&key, now() + 30);
    let signed_in = password_then(&code).await;
    assert!(signed_in.refresh.as_deref() == Some("0;url=/account") && signed_in.cookie.as_deref().is_some_and(|c| c.starts_with("__Host-mp_session=")), "{} {}", signed_in.status, signed_in.html);
    assert_eq!(password_then(&code).await.status, StatusCode::UNAUTHORIZED, "a code works once");
    assert_eq!(env.ui("/login/code", None, Some(&[("code", &code)])).await.status, StatusCode::UNAUTHORIZED, "nothing to finish without the note");

    // A recovery code, however it's typed, works once.
    let first = env.ui("/login", None, Some(&[("email", email), ("password", &password)])).await;
    let note = first.cookie.expect("note");
    let used = env.ui("/login/code", Some(&note), Some(&[("code", &recovery[0].to_uppercase().replace('-', " "))])).await;
    assert_eq!(used.location.as_deref(), Some("/?done=recovery-code-used"), "{}", used.html);
    let again = env.ui("/login/code", Some(&note), Some(&[("code", &recovery[0])])).await;
    assert!(again.status == StatusCode::UNAUTHORIZED && again.html.contains("isn&#39;t one of your recovery codes") && again.html.contains("<details class=\"more\" open"), "{}", again.html);

    // An emailed link takes a code too, and is still good while it hasn't had the right one.
    env.ui("/login/email", None, Some(&[("email", email)])).await;
    let link = smtp.wait_for(email, 2).await.code();
    let asked = env.ui("/login/link", None, Some(&[("code", link.as_str())])).await;
    assert!(asked.status == StatusCode::BAD_REQUEST && asked.html.contains("takes a code from your authenticator app") && asked.html.contains(r#"name="second""#) && asked.cookie.is_none(), "{}", asked.html);
    let with_code = env.ui("/login/link", None, Some(&[("code", link.as_str()), ("second", &recovery[1])])).await;
    assert_eq!(with_code.location.as_deref(), Some("/"), "{}", with_code.html);

    // New recovery codes replace the old; wrong codes stop being checked for a while.
    let manage = env.ui("/account/codes", Some(&current), None).await;
    assert!(manage.html.contains("8 recovery codes left"), "{}", manage.html);
    let fresh = env.ui("/account/codes/recovery", Some(&current), Some(&[("csrf", &manage.csrf()), ("password", &password)])).await;
    assert_eq!(between(&fresh.html, r#"<pre class="term">"#, "</pre>").lines().count(), 10, "{}", fresh.html);
    let first = env.ui("/login", None, Some(&[("email", email), ("password", &password)])).await;
    let note = first.cookie.expect("note");
    assert_eq!(env.ui("/login/code", Some(&note), Some(&[("code", &recovery[2])])).await.status, StatusCode::UNAUTHORIZED, "replaced");
    for _ in 0..4 {
        assert_eq!(env.ui("/login/code", Some(&note), Some(&[("code", &common::totp_code(&key, now() + 300))])).await.status, StatusCode::UNAUTHORIZED);
    }
    let held = env.ui("/login/code", Some(&note), Some(&[("code", &common::totp_code(&key, now()))])).await;
    assert!(held.status == StatusCode::TOO_MANY_REQUESTS && held.html.contains("Too many wrong codes for this account"), "{}", held.html);

    // Turning them off, and an administrator's reset, which takes an account back.
    let off = env.ui("/account/codes/off", Some(&current), Some(&[("csrf", &manage.csrf()), ("password", &password)])).await;
    assert_eq!(off.location.as_deref(), Some("/account?done=codes-off"), "{}", off.html);
    assert_eq!(env.ui("/login", None, Some(&[("email", email), ("password", &password)])).await.location.as_deref(), Some("/"));
    let setup = env.ui("/account/codes", Some(&current), None).await;
    let key = between(&setup.html, r#"<code class="key">"#, "</code>").replace(' ', "");
    let sealed = between(&setup.html, r#"name="key" value=""#, "\"").to_string();
    let form = [("csrf", setup.csrf()), ("key", sealed), ("code", common::totp_code(&key, now())), ("password", password.clone())];
    let pairs: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
    assert_eq!(env.ui("/account/codes", Some(&current), Some(&pairs)).await.status, StatusCode::OK);
    let id = user_named(&env, email).await["id"].as_str().unwrap().to_string();
    let (status, _) = env.api_json("POST", &format!("/api/v1/users/{id}/password"), Some(&env.admin_token()), serde_json::json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(user_named(&env, email).await["has_totp"], false);
    let (_, audit) = env.api("GET", "/api/v1/audit?limit=50", Some(&env.admin_token())).await;
    let actions: Vec<&str> = audit["entries"].as_array().unwrap().iter().filter_map(|e| e["action"].as_str()).collect();
    assert!(actions.contains(&"user.totp_on") && actions.contains(&"user.totp_off") && actions.contains(&"user.recovery_codes"), "{audit}");
}

/// A public page that sends mail needs limits of its own: per address and per client.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sign_in_links_are_limited() {
    let smtp = common::FakeSmtp::start().await;
    let env = Env::with_config(Tls::DevCa, &smtp.config()).await;
    invited_account(&env, &smtp, "ann@example.com").await;
    invited_account(&env, &smtp, "bob@example.com").await;
    let ask = async |address: &str| env.ui("/login/email", None, Some(&[("email", address)])).await;

    for _ in 0..5 {
        assert_eq!(ask("ann@example.com").await.status, StatusCode::OK, "the answer doesn't change");
    }
    assert_eq!(ask("bob@example.com").await.status, StatusCode::OK);
    smtp.wait_for("bob@example.com", 2).await;
    assert_eq!(smtp.sent_to("ann@example.com").len(), 4, "an invitation and three links, however many were asked for");

    for _ in 0..4 {
        assert_eq!(ask("nobody@example.com").await.status, StatusCode::OK);
    }
    let too_many = ask("nobody@example.com").await;
    assert!(too_many.status == StatusCode::TOO_MANY_REQUESTS && too_many.html.contains("Too many requests from here"), "{}", too_many.html);
    let elsewhere = env.ui_with("/login/link", None, None, &[]).await;
    assert_eq!(elsewhere.status, StatusCode::OK, "someone with a link already can still use it");
}

/// Getting a message doesn't prove an account is yours: if an administrator mistyped the address,
/// whoever owns the typo must not be able to confirm it and then ask for sign-in links to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confirming_an_address_takes_the_accounts_own_session() {
    let smtp = common::FakeSmtp::start().await;
    let env = Env::with_config(Tls::DevCa, &smtp.config()).await;
    let token = env.admin_token();
    let (_, other) = invited_account(&env, &smtp, "ann@example.com").await;
    let password = "a long enough password";
    env.api_json("POST", "/api/v1/users", Some(&token), serde_json::json!({ "email": "pat@example.com", "password": password })).await;
    let pat = sign_in(&env, "pat@example.com", password).await;

    // Nothing shows the address is Pat's yet, so no sign-in link goes there.
    assert_eq!(user_named(&env, "pat@example.com").await["email_verified"].as_bool(), Some(false));
    env.ui("/login/email", None, Some(&[("email", "pat@example.com")])).await;
    env.ui("/login/email", None, Some(&[("email", "ann@example.com")])).await;
    smtp.wait_for("ann@example.com", 2).await;
    assert!(smtp.sent_to("pat@example.com").is_empty());

    // Someone who has already proved theirs isn't asked to.
    assert!(!env.ui("/account", Some(&other), None).await.html.contains("Confirm your address"));
    let account = env.ui("/account", Some(&pat), None).await;
    assert!(account.html.contains("Confirm your address") && account.html.contains(r#"action="/account/address""#), "{}", account.html);
    let sent = env.ui("/account/address", Some(&pat), Some(&[("csrf", &account.csrf())])).await;
    assert_eq!(sent.location.as_deref(), Some("/account?done=confirmation-sent"), "{}", sent.html);
    let mail = smtp.wait_for("pat@example.com", 1).await;
    assert!(mail.text.contains(&format!("https://localhost:{}/account/address/confirm#code=", env.mgmt_port)), "{}", mail.text);
    let code = mail.code();

    // Not signed in: to the sign-in page. Signed in as someone else: refused, and it isn't used up.
    assert_eq!(env.ui("/account/address/confirm", None, None).await.status, StatusCode::SEE_OTHER);
    let form = env.ui("/account/address/confirm", Some(&other), None).await;
    assert!(form.status == StatusCode::OK && form.html.contains("data-code-field"), "{}", form.html);
    let wrong_person = env.ui("/account/address/confirm", Some(&other), Some(&[("csrf", &form.csrf()), ("code", code.as_str())])).await;
    assert!(wrong_person.status == StatusCode::BAD_REQUEST && wrong_person.html.contains("for another account"), "{}", wrong_person.html);
    assert_eq!(user_named(&env, "pat@example.com").await["email_verified"].as_bool(), Some(false));
    // A link for this can't sign anyone in either.
    assert_eq!(env.ui("/login/link", None, Some(&[("code", code.as_str())])).await.status, StatusCode::UNAUTHORIZED);

    let csrf = env.ui("/account/address/confirm", Some(&pat), None).await.csrf();
    let done = env.ui("/account/address/confirm", Some(&pat), Some(&[("csrf", &csrf), ("code", code.as_str())])).await;
    assert_eq!(done.location.as_deref(), Some("/account?done=address-confirmed"), "{}", done.html);
    assert_eq!(user_named(&env, "pat@example.com").await["email_verified"].as_bool(), Some(true));
    assert!(!env.ui("/account", Some(&pat), None).await.html.contains("Confirm your address"));

    // Now one goes there.
    env.ui("/login/email", None, Some(&[("email", "pat@example.com")])).await;
    assert!(smtp.wait_for("pat@example.com", 2).await.text.contains("/login/link#code="));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settings_page_sets_up_email() {
    let smtp = common::FakeSmtp::start().await;
    let mut env = Env::new(Tls::DevCa).await;
    let token = env.admin_token();
    let admin = admin_session(&env).await;
    let port = smtp.port.to_string();

    let settings = env.ui("/settings", Some(&admin), None).await;
    assert!(settings.html.contains(r#"id="email""#) && settings.html.contains(r#"href="/settings/email""#) && settings.html.contains("Set up email"), "{}", settings.html);
    let form = env.ui("/settings/email", Some(&admin), None).await;
    assert!(form.html.contains(r#"action="/settings/email""#) && form.html.contains("Check and save"), "{}", form.html);
    let csrf = form.csrf();
    let save = async |fields: &[(&str, &str)]| {
        let mut all = vec![("csrf", csrf.as_str())];
        all.extend_from_slice(fields);
        env.ui("/settings/email", Some(&admin), Some(&all)).await
    };

    // What can't work is refused and the form comes back as typed, without the password.
    let secret = "the-password-nobody-should-see";
    let plain_with_password = save(&[("host", "127.0.0.1"), ("port", &port), ("tls", "none"), ("username", "u"), ("password", secret), ("from", "a@example.com")]).await;
    assert!(plain_with_password.status == StatusCode::BAD_REQUEST && plain_with_password.html.contains("never sent without encryption") && plain_with_password.html.contains(r#"value="u""#) && !plain_with_password.html.contains(secret), "{}", plain_with_password.html);
    let bad_from = save(&[("host", "127.0.0.1"), ("port", &port), ("tls", "none"), ("from", "nobody")]).await;
    assert!(bad_from.status == StatusCode::BAD_REQUEST && bad_from.html.contains("not an address to send from"), "{}", bad_from.html);
    let bad_port = save(&[("host", "127.0.0.1"), ("port", "seventy"), ("tls", "none"), ("from", "a@example.com")]).await;
    assert!(bad_port.status == StatusCode::BAD_REQUEST && bad_port.html.contains("port must be a number"), "{}", bad_port.html);
    // Checked for real: nothing is listening there.
    let dead = common::free_port().to_string();
    let nothing_there = save(&[("host", "127.0.0.1"), ("port", &dead), ("tls", "none"), ("from", "MagicPipes <a@example.com>")]).await;
    assert!(nothing_there.status == StatusCode::BAD_REQUEST && nothing_there.html.contains("can&#39;t be used") && nothing_there.html.contains(&format!(r#"value="{dead}""#)), "{}", nothing_there.html);
    // A certificate nobody vouches for, and a password that goes nowhere.
    let (_, chain, key) = common::own_certificate(&["localhost"], None);
    let untrusted = common::FakeSmtp::offering(common::SmtpTlsOffer::Starttls { cert_pem: chain, key_pem: key }).await;
    let cert_refused = save(&[("host", "localhost"), ("port", &untrusted.port.to_string()), ("tls", "starttls"), ("username", "u"), ("password", secret), ("from", "a@example.com")]).await;
    assert!(cert_refused.status == StatusCode::BAD_REQUEST && cert_refused.html.contains("can&#39;t be used") && !cert_refused.html.contains(secret), "{}", cert_refused.html);
    assert!(untrusted.commands.lock().unwrap().is_empty(), "{:?}", untrusted.commands.lock().unwrap());
    assert!(!env.root.join("server/smtp-password").exists(), "a password is only kept once it has worked");
    assert!(env.ui("/settings", Some(&admin), None).await.html.contains("Set up email"), "nothing saved");

    let saved = save(&[("host", "127.0.0.1"), ("port", &port), ("tls", "none"), ("from", "MagicPipes <mp@example.com>")]).await;
    assert_eq!(saved.location.as_deref(), Some("/settings?done=email-saved"), "{}", saved.html);
    let settings = env.ui(saved.location.as_deref().unwrap(), Some(&admin), None).await;
    assert!(settings.html.contains("Send a test message") && settings.html.contains(&format!("127.0.0.1:{port}")) && settings.html.contains("Send test message"), "{}", settings.html);
    assert!(settings.html.contains("[smtp]") && settings.html.contains(r#"host = &quot;127.0.0.1&quot;"#), "the configuration in effect: {}", settings.html);
    assert!(env.ui("/login", None, None).await.html.contains("Forgot your password"), "in effect at once");
    let edit = env.ui("/settings/email", Some(&admin), None).await;
    assert!(edit.html.contains(&format!(r#"value="{port}""#)) && edit.html.contains(r#"value="none" selected"#) && edit.html.contains("Leave it empty to keep"), "{}", edit.html);

    // A test message says whether mail gets out.
    let csrf_now = settings.csrf();
    let test = env.ui("/settings/email/test", Some(&admin), Some(&[("csrf", &csrf_now), ("to", "me@example.com")])).await;
    assert_eq!(test.location.as_deref(), Some("/settings?done=test-message-sent"), "{}", test.html);
    assert!(smtp.wait_for("me@example.com", 1).await.text.contains("so email works"));
    smtp.refuse.store(true, std::sync::atomic::Ordering::Relaxed);
    let refused = env.ui("/settings/email/test", Some(&admin), Some(&[("csrf", &csrf_now), ("to", "me@example.com")])).await;
    assert!(refused.status == StatusCode::BAD_GATEWAY && refused.html.contains("no such mailbox"), "{}", refused.html);
    smtp.refuse.store(false, std::sync::atomic::Ordering::Relaxed);

    // It survives a restart, and an invitation sent before it's removed can still be accepted.
    env.stop_server().await;
    env.start_server().await;
    assert!(env.ui("/login", None, None).await.html.contains("Forgot your password"));
    let (status, _) = env.api_json("POST", "/api/v1/invitations", Some(&token), serde_json::json!({ "email": "a@example.com" })).await;
    assert_eq!(status, StatusCode::CREATED);
    let code = smtp.wait_for("a@example.com", 1).await.code();

    let admin = admin_session(&env).await;
    let csrf_now = env.ui("/settings", Some(&admin), None).await.csrf();
    let removed = env.ui("/settings/email/delete", Some(&admin), Some(&[("csrf", &csrf_now)])).await;
    assert_eq!(removed.location.as_deref(), Some("/settings?done=email-removed"), "{}", removed.html);
    assert!(!env.ui("/login", None, None).await.html.contains("Forgot your password"));
    assert!(env.ui("/settings", Some(&admin), None).await.html.contains("Set up email"));
    assert_eq!(env.ui("/invite", None, Some(&[("code", code.as_str())])).await.status, StatusCode::OK);

    // A member can't get at any of it.
    let password = "a long enough password";
    env.ui("/invite/accept", None, Some(&[("code", code.as_str()), ("password", password), ("repeat", password)])).await.cookie.expect("accepted");
    let member = env.ui("/login", None, Some(&[("email", "a@example.com"), ("password", password)])).await.cookie.expect("signed in");
    assert_eq!(env.ui("/settings/email", Some(&member), None).await.location.as_deref(), Some("/account"));
}

/// In the configuration file it's locked on the page, like a provider there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mail_server_in_the_configuration_file_is_locked_on_the_page() {
    let smtp = common::FakeSmtp::start().await;
    let env = Env::with_config(Tls::DevCa, &smtp.config()).await;
    let admin = admin_session(&env).await;
    let settings = env.ui("/settings", Some(&admin), None).await;
    assert!(settings.html.contains("in the configuration file") && settings.html.contains("Send test message") && !settings.html.contains(r#"action="/settings/email/delete""#), "{}", settings.html);
    assert_eq!(env.ui("/settings/email", Some(&admin), None).await.location.as_deref(), Some("/settings"));
    let fields = [("csrf", settings.csrf()), ("host", "other.example.com".to_string()), ("tls", "none".to_string()), ("from", "a@example.com".to_string())];
    let fields: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
    assert_eq!(env.ui("/settings/email", Some(&admin), Some(&fields)).await.location.as_deref(), Some("/settings"));
    assert!(env.ui("/settings", Some(&admin), None).await.html.contains(&format!("127.0.0.1:{}", smtp.port)));
}

/// With STARTTLS, the password and the message go over TLS to a server whose certificate checks out,
/// or nowhere at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mail_is_encrypted_or_not_sent() {
    let dir = std::env::temp_dir().join(format!("mp-smtp-tls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (ca, chain, key) = common::own_certificate(&["localhost"], None);
    let (ca_file, password_file) = (dir.join("ca.pem"), dir.join("password"));
    std::fs::write(&ca_file, &ca).unwrap();
    std::fs::write(&password_file, "smtp secret\n").unwrap();
    let config = |port: u16, trusted: bool| {
        let ca = if trusted { format!("ca_file = \"{}\"\n", ca_file.display()) } else { String::new() };
        format!("[smtp]\nhost = \"localhost\"\nport = {port}\nusername = \"mp@example.com\"\npassword_file = \"{}\"\nfrom = \"MagicPipes <mp@example.com>\"\n{ca}", password_file.display())
    };
    let invite = async |env: &Env| env.api_json("POST", "/api/v1/invitations", Some(&env.admin_token()), serde_json::json!({ "email": "ann@example.com" })).await;
    let offer = common::SmtpTlsOffer::Starttls { cert_pem: chain, key_pem: key };

    let good = common::FakeSmtp::offering(offer.clone()).await;
    let env = Env::with_config(Tls::DevCa, &config(good.port, true)).await;
    let (status, v) = invite(&env).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    let mail = good.wait_for("ann@example.com", 1).await;
    assert!(mail.encrypted, "{mail:?}");
    assert_eq!(mail.auth.as_deref(), Some("\0mp@example.com\0smtp secret"), "{mail:?}");
    drop(env);

    // A server that doesn't offer STARTTLS is told nothing, not even who it's for.
    let no_tls = common::FakeSmtp::start().await;
    let env = Env::with_config(Tls::DevCa, &config(no_tls.port, true)).await;
    let (status, v) = invite(&env).await;
    assert_eq!((status, v["error"]["code"].as_str()), (StatusCode::BAD_GATEWAY, Some("mail_failed")), "{v}");
    assert!(no_tls.commands.lock().unwrap().is_empty() && no_tls.messages.lock().unwrap().is_empty(), "{:?}", no_tls.commands.lock().unwrap());
    assert!(!env.server_log().contains("smtp secret"));
    drop(env);

    // Nor one whose certificate nobody vouches for.
    let untrusted = common::FakeSmtp::offering(offer).await;
    let env = Env::with_config(Tls::DevCa, &config(untrusted.port, false)).await;
    let (status, v) = invite(&env).await;
    assert_eq!((status, v["error"]["code"].as_str()), (StatusCode::BAD_GATEWAY, Some("mail_failed")), "{v}");
    assert!(untrusted.commands.lock().unwrap().is_empty(), "{:?}", untrusted.commands.lock().unwrap());
    drop(env);

    // A password that can't be read stops a server from starting with half its settings.
    let missing = config(no_tls.port, true).replace(&password_file.display().to_string(), "/no/such/password");
    let root = std::env::temp_dir().join(format!("mp-smtp-bad-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("server.toml");
    let text = format!("base_domain = \"{BASE}\"\ndata_dir = \"{}\"\n[management]\nlisten = \"127.0.0.1:{}\"\nhostname = \"localhost\"\n[tls]\nmode = \"dev-ca\"\n{missing}", root.join("data").display(), common::free_port());
    std::fs::write(&path, text).unwrap();
    let out = std::process::Command::new(common::bin("magicpipesd")).arg("--config").arg(&path).output().unwrap();
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success() && said.contains("/no/such/password"), "{said}");
    std::fs::remove_dir_all(&root).ok();
    std::fs::remove_dir_all(&dir).ok();
}

/// Behind an authenticating proxy, people sign in and get in there: email has nothing to do.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn behind_an_authenticating_proxy_nothing_offers_email() {
    let smtp = common::FakeSmtp::start().await;
    let dir = std::env::temp_dir().join(format!("mp-proxy-mail-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let secret = dir.join("proxy-secret");
    std::fs::write(&secret, "a shared secret for the proxy\n").unwrap();
    let proxy = format!("[proxy_auth]\nmode = \"headers\"\nuser_header = \"X-Forwarded-Email\"\nsecret_header = \"X-Proxy-Secret\"\nsecret_file = \"{}\"\ntrust_email = true\nauto_create = true\n", secret.display());
    let env = Env::with_settings(Tls::DevCa, "trusted_proxies = [\"127.0.0.1/32\"]\n", &format!("{proxy}{}", smtp.config())).await;
    let (status, v) = env.api_json("POST", "/api/v1/invitations", Some(&env.admin_token()), serde_json::json!({ "email": "a@example.com" })).await;
    assert_eq!((status, v["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("mail_not_configured")), "{v}");
    assert!(!env.ui("/login", None, None).await.html.contains("Forgot your password"));
    for path in ["/login/email"] {
        assert_eq!(env.ui(path, None, Some(&[("email", "a@example.com")])).await.location.as_deref(), Some("/login"), "{path}");
    }
    for path in ["/invite", "/invite/accept", "/login/link"] {
        assert_eq!(env.ui(path, None, Some(&[("code", "c")])).await.location.as_deref(), Some("/"), "{path}");
    }
    let admin = admin_session(&env).await;
    let settings = env.ui("/settings", Some(&admin), None).await;
    assert!(settings.html.contains("no use for email") && !settings.html.contains("Set up email"), "{}", settings.html);
    assert!(smtp.messages.lock().unwrap().is_empty());
    std::fs::remove_dir_all(&dir).ok();
}

/// What only a browser does: moving a code from the fragment into the form and out of the address,
/// and leaving for a provider from a form under `form-action 'self'`. Run it like
/// `browser_signs_in_to_private_tunnels`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Chrome and Node"]
async fn browser_signs_in_with_emailed_links() {
    let chrome = std::env::var("MAGICPIPES_CHROME").unwrap_or_else(|_| {
        if cfg!(target_os = "macos") { "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into() } else { "google-chrome".into() }
    });
    let idp = common::FakeOidc::start().await;
    let smtp = common::FakeSmtp::start().await;
    let dir = std::env::temp_dir().join(format!("mp-links-browser-{}", std::process::id()));
    let env = Env::with_config(Tls::DevCa, &format!("{}{}", idp.config(&dir, "", false), smtp.config())).await;
    let token = env.admin_token();

    invited_account(&env, &smtp, "ann@example.com").await;
    env.ui("/login/email", None, Some(&[("email", "ann@example.com")])).await;
    let sign_in_link = smtp.wait_for("ann@example.com", 2).await.code();
    env.api_json("POST", "/api/v1/invitations", Some(&token), serde_json::json!({ "email": "bob@example.com" })).await;
    let invitation = smtp.wait_for("bob@example.com", 1).await.code();

    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/browser-email-links.mjs");
    let profile = std::env::temp_dir().join(format!("mp-chrome-links-{}", std::process::id()));
    let opts = serde_json::json!({
        "chrome": chrome,
        "sign_in_link": format!("{}/login/link#code={sign_in_link}", env.server_url()),
        "invitation": format!("{}/invite#code={invitation}", env.server_url()),
        "provider": "Continue with Fake ID",
        "resolve": format!("MAP *.{BASE} 127.0.0.1"),
        "profile": profile,
    });
    let out = tokio::process::Command::new("node").arg(&script).arg(opts.to_string()).output().await.expect("run node");
    std::fs::remove_dir_all(&profile).ok();
    let result: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&out.stderr)));

    // The code went into the form, out of sight, and out of the address.
    for page in ["sign_in_page", "invitation_page"] {
        assert_eq!(result[page]["hash"], "", "{result}");
        assert_eq!(result[page]["field_hidden"], true, "{result}");
    }
    assert_eq!(result["sign_in_page"]["field_value"], sign_in_link.as_str(), "{result}");
    assert_eq!(result["invitation_page"]["field_value"], invitation.as_str(), "{result}");
    // Pressing the button signed in.
    assert_eq!(result["signed_in"]["path"], "/", "{result}");
    assert!(result["signed_in"]["text"].as_str().unwrap_or("").contains("ann@example.com"), "{result}");
    // Leaving for the provider from a form got there and back, and made the account.
    assert!(result["invitation_opened"]["text"].as_str().unwrap_or("").contains("invited you"), "{result}");
    assert_eq!(result["joined"]["path"], "/", "{result}");
    assert!(result["joined"]["text"].as_str().unwrap_or("").contains("bob@example.com"), "{result}");
    assert_eq!(user_named(&env, "bob@example.com").await["has_password"].as_bool(), Some(false));
    assert!(result["errors"].as_array().unwrap().is_empty(), "the browser reported errors: {result}");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- Unix sockets -------------------------------------------------------------------------------

/// What a failing `add --json` said: its exit code, error code and message.
async fn add_fails(env: &Env, args: &[&str]) -> (i32, String, String) {
    let mut a = vec!["add"];
    a.extend_from_slice(args);
    a.push("--json");
    let out = env.cli(&a).await;
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{args:?}: {}", String::from_utf8_lossy(&out.stderr)));
    (out.status.code().unwrap_or(-1), v["error"]["code"].as_str().unwrap_or("").to_string(), v["error"]["message"].as_str().unwrap_or("").to_string())
}

/// Passes TCP connections on to a local port, and cuts them on request, as a network failure would.
struct Relay {
    port: u16,
    live: Arc<std::sync::Mutex<Vec<tokio::task::AbortHandle>>>,
    _task: tokio::task::JoinHandle<()>,
}

impl Relay {
    async fn start(to: u16) -> Relay {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let live: Arc<std::sync::Mutex<Vec<tokio::task::AbortHandle>>> = Arc::default();
        let task = tokio::spawn({
            let live = live.clone();
            async move {
                while let Ok((mut inbound, _)) = listener.accept().await {
                    let pass = tokio::spawn(async move {
                        let Ok(mut outbound) = tokio::net::TcpStream::connect(("127.0.0.1", to)).await else { return };
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    });
                    let mut live = live.lock().unwrap();
                    live.retain(|h| !h.is_finished());
                    live.push(pass.abort_handle());
                }
            }
        });
        Relay { port, live, _task: task }
    }

    /// Cuts the connection open longest.
    fn cut_one(&self) {
        let mut live = self.live.lock().unwrap();
        live.retain(|h| !h.is_finished());
        if !live.is_empty() {
            live.remove(0).abort();
        }
    }

    fn cut_all(&self) {
        for h in self.live.lock().unwrap().drain(..) {
            h.abort();
        }
    }
}

/// How many connections the agent holds, as it and the server see them.
async fn connections(env: &Env, admin: &str) -> (u64, u64) {
    let agent = env.cli_json(&["status", "--json"]).await["connections"].as_u64().unwrap_or(0);
    let server = env.api("GET", "/api/v1/agents", Some(admin)).await.1["agents"][0]["connections"].as_u64().unwrap_or(0);
    (agent, server)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_agents_connections_carry_on_when_one_is_cut() {
    let env = Env::new(Tls::DevCa).await;
    let admin = env.admin_token();
    // The agent reaches the server through a relay that can cut its connections.
    let relay = Relay::start(env.mgmt_port).await;
    let (url, ca) = (format!("https://localhost:{}", relay.port), env.ca_path.to_string_lossy().to_string());
    env.cli_ok(&["login", "--server", &url, "--token", &env.enrollment_token(), "--ca-cert", &ca, "--name", "relayed"]).await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let t = add_json(&env, &[&app.port.to_string(), "--name", "lanes"]).await;
    assert_eq!(t["status"], "ready", "{t}");
    let host = format!("lanes.{BASE}");
    env.eventually("four connections, as both ends see them", Duration::from_secs(20), async || connections(&env, &admin).await == (4, 4)).await;

    // One is cut: the others go on serving while it comes back.
    relay.cut_one();
    env.eventually("the server to see three", Duration::from_secs(10), async || connections(&env, &admin).await.1 == 3).await;
    for _ in 0..20 {
        assert_eq!(env.get_public(&host, "/").await, (StatusCode::OK, None, "hello from app".to_string()));
    }
    env.eventually("the fourth back", Duration::from_secs(20), async || connections(&env, &admin).await == (4, 4)).await;

    // All are cut: the agent is offline for a moment, then back with its tunnel.
    relay.cut_all();
    env.eventually("the tunnel back", Duration::from_secs(30), async || env.get_public(&host, "/").await.0 == StatusCode::OK).await;
    env.eventually("all four back", Duration::from_secs(30), async || connections(&env, &admin).await == (4, 4)).await;
    env.cli_ok(&["agent", "stop"]).await;
}

/// Holds `n` requests open at once from `n` clients (named by X-Forwarded-For from a trusted proxy,
/// or all one client): what each got, the responses kept so their streams stay in use.
async fn hold_open(env: &Env, host: &str, n: usize, one_client: bool) -> (Vec<StatusCode>, Vec<http::Response<hyper::body::Incoming>>) {
    let requests = (0..n).map(|i| {
        let client = if one_client { "10.9.9.9".to_string() } else { format!("10.{}.{}.1", i / 250, i % 250) };
        let req = Request::get("/stream")
            .header(header::HOST, format!("{host}:{}", env.https_port))
            .header("x-forwarded-for", client)
            .body(Full::new(Bytes::new()))
            .unwrap();
        env.send(host, env.https_port, req)
    });
    let responses = futures_util::future::join_all(requests).await;
    (responses.iter().map(|r| r.status()).collect(), responses)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn several_connections_carry_more_than_one_can() {
    use magicpipes_core::mux::{MAX_DATA_STREAMS, MAX_DATA_STREAMS_PER_CLIENT};
    let env = Env::with_settings(Tls::DevCa, "trusted_proxies = [\"127.0.0.1/32\"]", "").await;
    env.login().await;
    let release = Arc::new(tokio::sync::Notify::new());
    let app = common::http_app(release.clone()).await;
    let host = format!("many.{BASE}");
    let n = MAX_DATA_STREAMS + 76;

    // One connection carries its 224 streams, and refuses the rest.
    let out = env.cli_with(&[("MAGICPIPES_CONNECTIONS", "1")], &["add", &app.port.to_string(), "--name", "many", "--json"]).await;
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let (statuses, held) = hold_open(&env, &host, n, false).await;
    let ok = statuses.iter().filter(|s| **s == StatusCode::OK).count();
    assert_eq!((ok, statuses.iter().filter(|s| **s == StatusCode::SERVICE_UNAVAILABLE).count()), (MAX_DATA_STREAMS, n - MAX_DATA_STREAMS));
    release.notify_waiters();
    drop(held);
    env.cli_ok(&["agent", "stop"]).await;

    // Four carry all of them.
    let t = add_json(&env, &[&app.port.to_string(), "--name", "many"]).await;
    assert_eq!(t["status"], "ready", "{t}");
    let admin = env.admin_token();
    env.eventually("four connections", Duration::from_secs(20), async || connections(&env, &admin).await == (4, 4)).await;
    let (statuses, held) = hold_open(&env, &host, n, false).await;
    assert!(statuses.iter().all(|s| *s == StatusCode::OK), "{:?}", statuses.iter().filter(|s| **s != StatusCode::OK).collect::<Vec<_>>());
    release.notify_waiters();
    drop(held);

    // And one client's share is the agent's, not each connection's.
    let (statuses, held) = hold_open(&env, &host, MAX_DATA_STREAMS_PER_CLIENT + 6, true).await;
    assert_eq!(statuses.iter().filter(|s| **s == StatusCode::OK).count(), MAX_DATA_STREAMS_PER_CLIENT);
    release.notify_waiters();
    drop(held);
    env.cli_ok(&["agent", "stop"]).await;
}

/// A web app that only speaks HTTPS, with a new self-signed certificate, on `port` (0: any). It
/// answers every request on a connection with `body`. Returns its port, its certificate's
/// fingerprint as browsers show it, and the task serving it.
async fn https_app(port: u16, body: &'static str) -> (u16, String, tokio::task::JoinHandle<()>) {
    use sha2::Digest;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["app.local".into()]).unwrap().self_signed(&key).unwrap();
    let fingerprint = sha2::Sha256::digest(cert.der()).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":");
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], rustls_pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()))
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // Its connections end with it, as when a real app restarts.
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            connections.spawn(async move {
                // The agent's checks connect and close without a word.
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let mut tls = BufReader::new(tls);
                loop {
                    let mut line = String::new();
                    // A request's head, to its empty line; GETs only, so no body follows.
                    loop {
                        line.clear();
                        match tls.read_line(&mut line).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) if line == "\r\n" => break,
                            Ok(_) => {}
                        }
                    }
                    let answer = format!("HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n{body}", body.len());
                    if tls.get_mut().write_all(answer.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (port, fingerprint, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn https_apps() {
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    let host = format!("pve.{BASE}");

    // The agent speaks TLS to the app and keeps the certificate it shows.
    let (port, pin, app) = https_app(0, "hello over https").await;
    let t = add_json(&env, &[&port.to_string(), "--local-https", "--name", "pve"]).await;
    assert_eq!((t["status"].as_str(), t["target"].as_str()), (Some("ready"), Some(format!("https://127.0.0.1:{port}").as_str())), "{t}");
    assert_eq!(t["local_certificate"].as_str(), Some(pin.as_str()));
    assert!(t.get("replaced_certificate").is_none(), "{t}");
    for _ in 0..3 {
        assert_eq!(env.get_public(&host, "/").await, (StatusCode::OK, None, "hello over https".to_string()));
    }
    let human = env.cli_ok(&["add", &port.to_string(), "--local-https", "--name", "pve"]).await;
    assert!(String::from_utf8_lossy(&human.stdout).contains(&format!("(SHA-256 {pin})")));

    // Another app on that port, with another certificate: refused until it's added again.
    app.abort();
    let _ = app.await;
    let (_, other, _app) = https_app(port, "the new one").await;
    env.eventually("the old pooled connections to go", Duration::from_secs(10), async || {
        env.get_public(&host, "/").await.0 == StatusCode::BAD_GATEWAY
    })
    .await;
    let t = add_json(&env, &[&port.to_string(), "--local-https", "--name", "pve"]).await;
    assert_eq!((t["local_certificate"].as_str(), t["replaced_certificate"].as_str()), (Some(other.as_str()), Some(pin.as_str())), "{t}");
    env.eventually("the new certificate to be accepted", Duration::from_secs(10), async || {
        env.get_public(&host, "/").await == (StatusCode::OK, None, "the new one".to_string())
    })
    .await;

    // Something that doesn't speak TLS isn't taken for an HTTPS app.
    let plain = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let plain_port = plain.local_addr().unwrap().port();
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        while let Ok((mut tcp, _)) = plain.accept().await {
            let _ = tcp.write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n").await;
        }
    });
    let (code, error, message) = add_fails(&env, &[&plain_port.to_string(), "--local-https"]).await;
    assert_eq!((code, error.as_str()), (4, "local_unreachable"), "{message}");
    assert!(message.contains("didn't answer with TLS"), "{message}");
    env.cli_ok(&["agent", "stop"]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unix_socket_tunnels() {
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    let path = env.root.join("app.sock");
    let p = path.to_str().unwrap();

    // Options that make no sense together are refused before anything happens.
    for args in [
        vec!["add", "--unix", p, "--udp"],
        vec!["add", "8080", "--unix", p],
        vec!["add", "--unix", p, "--host", "other"],
        vec!["add", "--unix", p, "--serve", "."],
        vec!["add", "--unix", p, "--shell"],
        vec!["add", "8080", "--allow-sensitive-socket"],
    ] {
        assert_eq!(env.cli(&args).await.status.code(), Some(2), "{args:?}");
    }

    // Nothing there, as with a port nothing listens on. Nothing gets registered.
    let (code, error, message) = add_fails(&env, &["--unix", p, "--name", "sock"]).await;
    assert_eq!((code, error.as_str()), (4, "local_unreachable"), "{message}");
    assert!(message.contains("Start your application") && message.contains(p), "{message}");

    // A file that isn't a socket.
    let file = env.root.join("plain.txt");
    std::fs::write(&file, "not a socket").unwrap();
    let (code, error, message) = add_fails(&env, &["--unix", file.to_str().unwrap()]).await;
    assert_eq!((code, error.as_str()), (4, "invalid_socket"), "{message}");

    // A socket file an application left behind, with nothing accepting on it.
    let stale = common::unix_echo_app(&path);
    stale.stop();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (code, error, message) = add_fails(&env, &["--unix", p]).await;
    assert_eq!((code, error.as_str()), (4, "local_unreachable"), "{message}");
    assert_eq!(env.cli_json(&["list", "--json"]).await["tunnels"], serde_json::json!([]));

    // An application there is verified end to end, like any other.
    let app = common::unix_http_app(&path, "the first socket");
    let out = env.cli_ok(&["add", "--unix", p, "--name", "sock"]).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Checking socket...") && stderr.contains("Verifying public endpoint...  ✓"), "{stderr}");
    assert!(stderr.contains("Connections reach this socket as you"), "says what that means: {stderr}");
    assert!(String::from_utf8_lossy(&out.stdout).contains(&format!("Local:  unix:{p}")), "{}", String::from_utf8_lossy(&out.stdout));
    let t = add_json(&env, &["--unix", p, "--name", "sock"]).await;
    assert_eq!((t["created"].as_bool(), t["status"].as_str(), t["kind"].as_str()), (Some(false), Some("ready"), Some("http")), "running it again changes nothing: {t}");
    assert_eq!(t["target"], format!("unix:{p}"), "{t}");
    let host = hostname(t["public_url"].as_str().unwrap());
    let get = async |h: &str| env.get_public(h, "/").await;
    let (status, error, body) = get(&host).await;
    assert_eq!((status, error, body.as_str()), (StatusCode::OK, None, "hello over the first socket"));

    // A body too big for the socket's buffers comes back whole.
    let big = "0123456789abcdef".repeat(128 * 1024);
    let echoed = env.tunnel_post(&host, "/echo", "", &big).await;
    assert!(echoed.status == StatusCode::OK && echoed.body == big, "{} bytes back", echoed.body.len());

    // The server sees the tunnel, and the file's name, not the path that says whose machine it is.
    let (_, tunnels) = env.api("GET", "/api/v1/tunnels", Some(&env.admin_token())).await;
    assert_eq!(tunnels["tunnels"][0]["target"], "unix:app.sock", "{tunnels}");
    assert!(!tunnels.to_string().contains(env.root.to_str().unwrap()), "{tunnels}");
    let listed = env.cli_json(&["list", "--json"]).await;
    assert_eq!((listed["tunnels"][0]["target"].as_str(), listed["tunnels"][0]["status"].as_str()), (Some(format!("unix:{p}").as_str()), Some("connected")), "{listed}");

    // One name, one target.
    let other = env.root.join("other.sock");
    let other_app = common::unix_http_app(&other, "the other socket");
    let (code, error, message) = add_fails(&env, &["--unix", other.to_str().unwrap(), "--name", "sock"]).await;
    assert_eq!((code, error.as_str()), (6, "name_conflict"), "{message}");

    // The application going away looks the same as a port's, and the tunnel stays.
    app.stop();
    env.eventually("the tunnel says it can't reach the application", Duration::from_secs(5), async || {
        get(&host).await.1.as_deref() == Some("local_unreachable")
    })
    .await;
    // It comes back, with a new socket file at the same path, and nobody has to do anything.
    let app = common::unix_http_app(&path, "the restarted socket");
    env.eventually("the tunnel reaches the application again", Duration::from_secs(5), async || get(&host).await.2 == "hello over the restarted socket").await;

    // Tunnels come back with the agent, from what it saved.
    env.cli_ok(&["agent", "stop"]).await;
    env.cli_ok(&["agent", "start"]).await;
    env.eventually("the tunnel is back", Duration::from_secs(10), async || get(&host).await.2 == "hello over the restarted socket").await;
    drop(app);

    // Links are followed when connecting, so a deploy can repoint one under a running tunnel. A
    // connection already open keeps going until the old release stops, as it would with a port.
    let link = env.root.join("current.sock");
    let (one, two) = (env.root.join("release-1.sock"), env.root.join("release-2.sock"));
    let first = common::unix_http_app(&one, "release 1");
    let _second = common::unix_http_app(&two, "release 2");
    std::os::unix::fs::symlink(&one, &link).unwrap();
    let t = add_json(&env, &["--unix", link.to_str().unwrap(), "--name", "linked"]).await;
    assert_eq!(t["target"], format!("unix:{}", link.display()), "kept as given: {t}");
    let linked = hostname(t["public_url"].as_str().unwrap());
    assert_eq!(get(&linked).await.2, "hello over release 1");
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&two, &link).unwrap();
    first.stop();
    env.eventually("the new release answers", Duration::from_secs(5), async || get(&linked).await.2 == "hello over release 2").await;

    // A relative path means where the command was run, not where the agent runs.
    let sub = env.root.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    let _rel = common::unix_http_app(&sub.join("r.sock"), "a relative path");
    let out = env.cli_in(&sub, &["add", "--unix", "./r.sock", "--name", "rel", "--json"]).await;
    let t: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&out.stderr)));
    assert_eq!(get(&hostname(t["public_url"].as_str().unwrap())).await.2, "hello over a relative path", "{t}");

    // Private works the same way: no public probe, and a sign-in in front of it.
    let t = add_json(&env, &["--unix", other.to_str().unwrap(), "--name", "secret", "--private"]).await;
    assert_eq!((t["visibility"].as_str(), t["status"].as_str()), (Some("private"), Some("ready")), "{t}");
    let anonymous = env.tunnel_get(&hostname(t["public_url"].as_str().unwrap()), "/", "", true).await;
    assert_eq!(anonymous.status, StatusCode::SEE_OTHER, "{}", anonymous.body);
    let out = env.cli_ok(&["add", "--unix", other.to_str().unwrap(), "--name", "secret", "--private"]).await;
    assert!(!String::from_utf8_lossy(&out.stderr).contains("Connections reach this socket as you"), "signing in is what it would suggest");
    drop(other_app);

    // A raw port in front of a socket: asked for like any other, and the bytes get through.
    let echo = env.root.join("echo.sock");
    let _echo_app = common::unix_echo_app(&echo);
    let e = echo.to_str().unwrap();
    let (code, error, message) = add_fails(&env, &["--unix", e, "--tcp"]).await;
    assert_eq!((code, error.as_str()), (1, "invalid_request"), "{message}");
    assert!(message.contains("--allow-any"), "{message}");
    let t = add_json(&env, &["--unix", e, "--tcp", "--allow-any", "--name", "echo"]).await;
    assert_eq!((t["kind"].as_str(), t["reachable"].as_bool()), (Some("tcp"), Some(true)), "{t}");
    let port = t["public_port"].as_u64().unwrap() as u16;
    assert_eq!(tcp_roundtrip(port, b"over a raw port").await, b"over a raw port");

    // Sockets that would hand over the machine, or this agent, need saying twice.
    let docker = env.root.join("docker.sock");
    let _docker = common::unix_http_app(&docker, "docker");
    let d = docker.to_str().unwrap();
    let (code, error, message) = add_fails(&env, &["--unix", d, "--name", "docker"]).await;
    assert_eq!((code, error.as_str()), (4, "invalid_socket"), "{message}");
    assert!(message.contains("--allow-sensitive-socket") && message.contains("containers"), "{message}");
    let own = env.root.join("a.sock");
    let (code, error, message) = add_fails(&env, &["--unix", own.to_str().unwrap()]).await;
    assert_eq!((code, error.as_str()), (4, "invalid_socket"), "the agent's own control socket: {message}");
    assert!(message.contains("this agent"), "{message}");
    // Through a link it's the same socket.
    let hidden = env.root.join("harmless.sock");
    std::os::unix::fs::symlink(&docker, &hidden).unwrap();
    assert_eq!(add_fails(&env, &["--unix", hidden.to_str().unwrap()]).await.1, "invalid_socket");
    let t = add_json(&env, &["--unix", d, "--name", "docker", "--allow-sensitive-socket", "--private"]).await;
    assert_eq!(t["status"], "ready", "{t}");

    // Removed by name, or by the path it was added with.
    let out = env.cli_ok(&["remove", p]).await;
    assert!(String::from_utf8_lossy(&out.stdout).contains("Removed tunnel sock"), "{}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(get(&host).await.0, StatusCode::NOT_FOUND);
    env.cli_ok(&["agent", "stop"]).await;
}

/// A person's public key, added on the Account page.
async fn add_ssh_key(env: &Env, cookie: &str, name: &str, key: &str) -> common::UiResponse {
    let account = env.ui("/account", Some(cookie), None).await;
    env.ui("/account/ssh-keys", Some(cookie), Some(&[("csrf", &account.csrf()), ("name", name), ("public_key", key)])).await
}

/// A real sshd and a real `ssh -J`, through the gateway and a tunnel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssh_gateway() {
    let gateway = common::free_port();
    let env = Env::with_config(Tls::DevCa, &format!("[ssh]\nlisten = \"127.0.0.1:{gateway}\"\n")).await;
    let Some(mut sshd) = common::Sshd::start(&env.root, "").await else {
        // CI must really run this: a skipped test looks the same as a passing one there.
        assert!(std::env::var_os("CI").is_none(), "CI needs OpenSSH's server and client for this test");
        return eprintln!("no OpenSSH here: skipping");
    };
    let admin = env.admin_token();
    env.api_json("POST", "/api/v1/tags", Some(&admin), serde_json::json!({ "name": "team:dev" })).await;
    let mut ids = std::collections::HashMap::new();
    for (email, tags) in [("ann@example.com", vec!["team:dev"]), ("bob@example.com", vec![]), ("cy@example.com", vec!["team:dev"])] {
        let body = serde_json::json!({ "email": email, "password": "correct horse battery" });
        let (_, v) = env.api_json("POST", "/api/v1/users", Some(&admin), body).await;
        let id = v["user"]["id"].as_str().unwrap().to_string();
        env.api_json("PATCH", &format!("/api/v1/users/{id}"), Some(&admin), serde_json::json!({ "tags": tags })).await;
        ids.insert(email, id);
    }
    let ann_cookie = sign_in(&env, "ann@example.com", "correct horse battery").await;
    let bob_cookie = sign_in(&env, "bob@example.com", "correct horse battery").await;
    let cy_cookie = sign_in(&env, "cy@example.com", "correct horse battery").await;
    let (ann, bob, cy, stranger) = (
        sshd.person("ann", gateway, true).await,
        sshd.person("bob", gateway, true).await,
        sshd.person("cy", gateway, true).await,
        sshd.person("stranger", gateway, true).await,
    );

    // Keys go on the Account page. What can't be used is explained, and a private key isn't repeated.
    let page = env.ui("/account", Some(&ann_cookie), None).await;
    assert!(page.html.contains("No SSH keys yet") && page.html.contains(&format!("ssh -J localhost:{gateway}")), "{}", page.html);
    let private = "-----BEGIN OPENSSH PRIVATE KEY-----\nc2VjcmV0LWtleS1ib2R5\n-----END OPENSSH PRIVATE KEY-----\n";
    let refused = add_ssh_key(&env, &ann_cookie, "oops", private).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert!(refused.html.contains("private key") && !refused.html.contains("c2VjcmV0"), "{}", refused.html);
    let refused = add_ssh_key(&env, &ann_cookie, "typo", "ssh-ed25519 nonsense").await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert!(refused.html.contains("ssh-ed25519 nonsense"), "the form keeps what was typed: {}", refused.html);
    assert_eq!(add_ssh_key(&env, &ann_cookie, "laptop", &ann.public).await.status, StatusCode::SEE_OTHER);
    let refused = add_ssh_key(&env, &bob_cookie, "mine", &ann.public).await;
    assert!(refused.status == StatusCode::BAD_REQUEST && refused.html.contains("already on an account"), "{}", refused.html);
    assert_eq!(add_ssh_key(&env, &bob_cookie, "", &bob.public).await.status, StatusCode::SEE_OTHER);
    assert_eq!(add_ssh_key(&env, &cy_cookie, "cy", &cy.public).await.status, StatusCode::SEE_OTHER);
    assert!(env.ui("/account", Some(&ann_cookie), None).await.html.contains("SHA256:"));

    // Ann's machine. The options that don't apply are refused before anything happens.
    let body = serde_json::json!({ "owner_user_id": ids["ann@example.com"] });
    let (_, v) = env.api_json("POST", "/api/v1/enrollments", Some(&admin), body).await;
    let (url, ca) = (env.server_url(), env.ca_path.to_string_lossy().to_string());
    env.cli_ok(&["login", "--server", &url, "--token", v["enrollment_token"].as_str().unwrap(), "--ca-cert", &ca, "--name", "dev"]).await;
    let port = sshd.port.to_string();
    for args in [vec!["add", "--ssh"], vec!["add", &port, "--ssh", "--public"], vec!["add", &port, "--ssh", "--tcp"], vec!["add", &port, "--ssh", "--allow-any"]] {
        assert_eq!(env.cli(&args).await.status.code(), Some(2), "{args:?}");
    }
    let t = add_json(&env, &[&port, "--ssh", "--name", "dev-box", "--tag", "team:dev"]).await;
    assert_eq!((t["status"].as_str(), t["kind"].as_str(), t["visibility"].as_str()), (Some("ready"), Some("ssh"), Some("private")), "{t}");
    assert_eq!(t["public_url"], format!("ssh -J localhost:{gateway} dev-box"), "{t}");
    assert_eq!(env.cli_json(&["list", "--json"]).await["tunnels"][0]["kind"], "ssh");
    let solo = add_json(&env, &[&port, "--ssh", "--name", "anns-only"]).await;
    assert_eq!(solo["visibility"], "private", "with no options, still private: {solo}");

    // The owner, and someone sharing the tag, log in to the real sshd. The bare name and the full
    // hostname both work.
    let (out, err, ok) = ann.ssh(&["dev-box", "echo hello from sshd"]).await;
    assert!(ok && out == "hello from sshd\n", "{out} {err}");
    let (out, err, ok) = cy.ssh(&[&format!("dev-box.{BASE}"), "echo hello again"]).await;
    assert!(ok && out == "hello again\n", "{out} {err}");
    assert!(ann.ssh(&["anns-only", "true"]).await.2);

    // Nobody can tell a machine they can't reach from one that doesn't exist.
    let (_, shared_not, ok) = bob.ssh(&["dev-box", "true"]).await;
    assert!(!ok && shared_not.contains("no such machine"), "{shared_not}");
    let (_, no_such, ok) = bob.ssh(&["ghost", "true"]).await;
    assert!(!ok && no_such.contains("no such machine"), "{no_such}");
    assert!(!cy.ssh(&["anns-only", "true"]).await.2, "her personal tag isn't Cy's");
    // A key nobody registered gets no further, though sshd itself would have taken it.
    let (_, err, ok) = stranger.ssh(&["dev-box", "true"]).await;
    assert!(!ok && err.contains("Permission denied"), "{err}");

    // Data in both directions, a half-close, and file copies, which is what -J is for.
    let big = env.root.join("big.bin");
    let contents: Vec<u8> = (0..16 * 1024 * 1024u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8).collect();
    std::fs::write(&big, &contents).unwrap();
    let copy = env.root.join("copied.bin");
    let copied = ann.command("scp").arg(&big).arg(format!("dev-box:{}", copy.display())).output().await.unwrap();
    assert!(copied.status.success(), "{}", String::from_utf8_lossy(&copied.stderr));
    assert!(std::fs::read(&copy).unwrap() == contents, "scp changed the file");
    let piped = ann.command("ssh").args(["dev-box", "cat"]).stdin(std::fs::File::open(&big).unwrap()).output().await.unwrap();
    assert!(piped.status.success() && piped.stdout == contents, "{} bytes back: {}", piped.stdout.len(), String::from_utf8_lossy(&piped.stderr));

    // The gateway itself runs nothing, says what you can reach and writes the configuration.
    let (out, err, ok) = cy.ssh(&["gw"]).await;
    assert!(ok && out.contains("dev-box") && !out.contains("anns-only"), "{out} {err}");
    assert!(out.contains(&format!("ssh -J localhost:{gateway} dev-box")), "{out}");
    let (out, _, ok) = bob.ssh(&["gw"]).await;
    assert!(ok && out.contains("No machines are shared with you"), "{out}");
    let (out, _, ok) = cy.ssh(&["gw", "config"]).await;
    assert!(ok && out == format!("Host dev-box\n    ProxyJump localhost:{gateway}\n\n"), "{out}");
    let (out, _, ok) = cy.ssh(&["gw", "cat /etc/passwd"]).await;
    assert!(!ok && out.contains("runs no commands"), "{out}");
    let (_, err, ok) = cy.ssh(&["-N", "-o", "ExitOnForwardFailure=yes", "-R", "127.0.0.1:9:127.0.0.1:9", "gw"]).await;
    assert!(!ok, "no forwarding back in: {err}");

    // It's written down, and the key shows when it was used.
    env.eventually("the audit log says who connected", Duration::from_secs(5), async || {
        env.api("GET", "/api/v1/audit", Some(&admin)).await.1.to_string().contains("ssh.connect")
    })
    .await;
    assert!(!env.ui("/account", Some(&ann_cookie), None).await.html.contains(">never<"), "last used");

    // A session ends as soon as the tag that let them in goes.
    let mut held = cy.command("ssh").args(["dev-box", "sleep 300"]).spawn().unwrap();
    let cy_id = ids["cy@example.com"].clone();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(held.try_wait().unwrap().is_none(), "the session is open");
    env.api_json("PATCH", &format!("/api/v1/users/{cy_id}"), Some(&admin), serde_json::json!({ "tags": [] })).await;
    let ended = tokio::time::timeout(Duration::from_secs(10), held.wait()).await;
    assert!(ended.is_ok(), "the session outlived the tag");
    let (_, err, ok) = cy.ssh(&["dev-box", "true"]).await;
    assert!(!ok && err.contains("no such machine"), "{err}");

    // So does one whose key is deleted, and the key is no use after that.
    let mut held = ann.command("ssh").args(["dev-box", "sleep 300"]).spawn().unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(held.try_wait().unwrap().is_none(), "the session is open");
    let account = env.ui("/account", Some(&ann_cookie), None).await;
    let id = account.html.split("/account/ssh-keys/").nth(1).and_then(|s| s.split('/').next()).expect("a key to delete").to_string();
    let gone = env.ui(&format!("/account/ssh-keys/{id}/delete"), Some(&ann_cookie), Some(&[("csrf", &account.csrf())])).await;
    assert_eq!(gone.status, StatusCode::SEE_OTHER);
    let ended = tokio::time::timeout(Duration::from_secs(10), held.wait()).await;
    assert!(ended.is_ok(), "the session outlived the key");
    let (_, err, ok) = ann.ssh(&["dev-box", "true"]).await;
    assert!(!ok && err.contains("Permission denied"), "{err}");
    assert_eq!(add_ssh_key(&env, &ann_cookie, "again", &ann.public).await.status, StatusCode::SEE_OTHER);

    // Someone who may reach a machine hears why they can't.
    sshd.stop().await;
    let (_, err, ok) = ann.ssh(&["dev-box", "true"]).await;
    assert!(!ok && err.contains("did not answer"), "{err}");
    let (code, error, _) = add_fails(&env, &[&port, "--ssh", "--name", "dev-box"]).await;
    assert_eq!((code, error.as_str()), (4, "local_unreachable"));
    env.cli_ok(&["agent", "stop"]).await;
    env.eventually("the machine shows as offline", Duration::from_secs(10), async || ann.ssh(&["dev-box", "true"]).await.1.contains("dev-box is offline")).await;
}

/// A server without a gateway says so, and offers no keys.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssh_tunnels_need_a_gateway() {
    let env = Env::new(Tls::DevCa).await;
    env.login().await;
    let app = common::tcp_echo_app().await;
    let (code, error, message) = add_fails(&env, &[&app.port.to_string(), "--ssh"]).await;
    assert_eq!((code, error.as_str()), (6, "ssh_disabled"), "{message}");
    let admin = env.admin_token();
    let body = serde_json::json!({ "email": "ann@example.com", "password": "correct horse battery" });
    env.api_json("POST", "/api/v1/users", Some(&admin), body).await;
    let cookie = sign_in(&env, "ann@example.com", "correct horse battery").await;
    assert!(!env.ui("/account", Some(&cookie), None).await.html.contains("SSH keys"));
}


/// A browser opening the terminal of the SSH tunnel `name`, signed in with `cookie`, on a page with
/// this `origin` (`None`: the management host's). The status the server refused with, if it did.
async fn open_terminal(env: &Env, cookie: &str, name: &str, origin: Option<&str>) -> Result<Terminal, StatusCode> {
    let tls = env.connect("localhost", env.mgmt_port).await;
    let mut req = format!("wss://localhost:{}/terminal/{name}/ws", env.mgmt_port).into_client_request().unwrap();
    req.headers_mut().insert(header::COOKIE, cookie.parse().unwrap());
    let here = format!("https://localhost:{}", env.mgmt_port);
    req.headers_mut().insert(header::ORIGIN, origin.unwrap_or(&here).parse().unwrap());
    match tokio_tungstenite::client_async(req, tls).await {
        Ok((ws, _)) => Ok(ws),
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => Err(resp.status()),
        Err(e) => panic!("{e}"),
    }
}

/// Logs in as `login`, and returns once a shell is ready, or the message saying why not.
async fn log_in(ws: &mut Terminal, login: &str) -> Result<(), Value> {
    ws.send(Message::text(serde_json::json!({ "type": "hello", "login": login, "cols": 100, "rows": 30 }).to_string())).await.unwrap();
    loop {
        match tokio::time::timeout(Duration::from_secs(30), ws.next()).await.expect("an answer").expect("open") {
            Ok(Message::Text(t)) => {
                let m: Value = serde_json::from_str(&t).unwrap();
                return if m["type"] == "ready" { Ok(()) } else { Err(m) };
            }
            Ok(_) => {}
            Err(e) => panic!("{e}"),
        }
    }
}

/// Types `line` and waits for `want` in the output. Returns the last JSON message instead if the
/// session ends first.
async fn type_and_see(ws: &mut Terminal, line: &str, want: &str) -> Result<(), Value> {
    ws.send(Message::binary(format!("{line}\r").into_bytes())).await.unwrap();
    let mut seen = String::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(20), ws.next()).await.unwrap_or_else(|_| panic!("never saw {want:?}: {seen}")) {
            Some(Ok(Message::Binary(b))) => {
                seen.push_str(&String::from_utf8_lossy(&b));
                if seen.contains(want) {
                    return Ok(());
                }
            }
            Some(Ok(Message::Text(t))) => return Err(serde_json::from_str(&t).unwrap()),
            Some(Ok(_)) => {}
            Some(Err(_)) | None => return Err(Value::Null),
        }
    }
}

/// The next JSON message, skipping output: how a session ended.
async fn ending(ws: &mut Terminal) -> Value {
    loop {
        match tokio::time::timeout(Duration::from_secs(15), ws.next()).await.expect("it ended") {
            Some(Ok(Message::Text(t))) => return serde_json::from_str(&t).unwrap(),
            Some(Ok(_)) => {}
            Some(Err(_)) | None => return Value::Null,
        }
    }
}

/// A browser terminal on a real sshd that trusts the server's certificates: each person logs in as
/// the account that lists them, and loses the session with their access.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn browser_ssh_terminal() {
    let gateway = common::free_port();
    let env = Env::with_config(Tls::DevCa, &format!("[ssh]\nlisten = \"127.0.0.1:{gateway}\"\n")).await;
    let admin = env.admin_token();
    let (_, ca) = env.api("GET", "/api/v1/ssh-ca", Some(&admin)).await;
    let ca = ca["public_key"].as_str().expect("a CA").to_string();
    assert!(ca.starts_with("ssh-ed25519 "), "{ca}");
    let me = common::Sshd::login();
    let principals = env.root.join("principals");
    std::fs::create_dir_all(&principals).unwrap();
    std::fs::write(env.root.join("ca.pub"), format!("{ca}\n")).unwrap();
    std::fs::write(principals.join(&me), "ann@example.com\n").unwrap();
    let extra = format!("TrustedUserCAKeys {}\nAuthorizedPrincipalsFile {}/%u\n", env.root.join("ca.pub").display(), principals.display());
    let Some(mut sshd) = common::Sshd::start(&env.root, &extra).await else {
        assert!(std::env::var_os("CI").is_none(), "CI needs OpenSSH's server for this test");
        return eprintln!("no OpenSSH here: skipping");
    };
    env.api_json("POST", "/api/v1/tags", Some(&admin), serde_json::json!({ "name": "team:dev" })).await;
    let mut ids = std::collections::HashMap::new();
    for (email, tags) in [("ann@example.com", vec!["team:dev"]), ("bob@example.com", vec![]), ("cy@example.com", vec!["team:dev"])] {
        let body = serde_json::json!({ "email": email, "password": "correct horse battery" });
        let (_, v) = env.api_json("POST", "/api/v1/users", Some(&admin), body).await;
        let id = v["user"]["id"].as_str().unwrap().to_string();
        env.api_json("PATCH", &format!("/api/v1/users/{id}"), Some(&admin), serde_json::json!({ "tags": tags })).await;
        ids.insert(email, id);
    }
    let ann = sign_in(&env, "ann@example.com", "correct horse battery").await;
    let bob = sign_in(&env, "bob@example.com", "correct horse battery").await;
    let cy = sign_in(&env, "cy@example.com", "correct horse battery").await;
    let body = serde_json::json!({ "owner_user_id": ids["ann@example.com"] });
    let (_, v) = env.api_json("POST", "/api/v1/enrollments", Some(&admin), body).await;
    let (url, ca_cert) = (env.server_url(), env.ca_path.to_string_lossy().to_string());
    env.cli_ok(&["login", "--server", &url, "--token", v["enrollment_token"].as_str().unwrap(), "--ca-cert", &ca_cert, "--name", "dev"]).await;
    let t = add_json(&env, &[&sshd.port.to_string(), "--ssh", "--name", "dev-box", "--tag", "team:dev"]).await;
    assert_eq!(t["status"], "ready", "{t}");
    let id = t["id"].as_str().unwrap().to_string();

    // The page, linked from the tunnel, and what the machine needs, on the tunnel's own page.
    let page = env.ui("/terminal/dev-box", Some(&ann), None).await;
    assert!(page.status == 200 && page.html.contains(r#"data-access="login""#) && page.html.contains("ann@example.com"), "{}", page.html);
    assert_eq!(env.ui("/terminal/dev-box", Some(&bob), None).await.status, StatusCode::NOT_FOUND, "Bob can't reach it");
    let script = env.ui("/assets/terminal/page.mjs", None, None).await;
    assert!(script.status == 200 && script.html.contains(r#"from "/assets/terminal/xterm.mjs""#));
    assert!(env.ui("/", Some(&ann), None).await.html.contains(r#"href="/terminal/dev-box""#));
    let detail = env.ui(&format!("/tunnels/{id}"), Some(&ann), None).await;
    assert!(detail.html.contains("TrustedUserCAKeys") && detail.html.contains(ca.split(' ').nth(1).unwrap()), "{}", detail.html);

    // Only from this host's pages, and only for people who may reach the machine.
    assert_eq!(open_terminal(&env, &ann, "dev-box", Some("https://evil.example")).await.err(), Some(StatusCode::FORBIDDEN));
    assert_eq!(open_terminal(&env, &bob, "dev-box", None).await.err(), Some(StatusCode::NOT_FOUND));
    assert_eq!(open_terminal(&env, &ann, "ghost", None).await.err(), Some(StatusCode::NOT_FOUND));

    // Ann's own shell, on the real sshd, logged in with a certificate.
    let mut ws = open_terminal(&env, &ann, "dev-box", None).await.unwrap();
    log_in(&mut ws, &me).await.expect("logged in");
    type_and_see(&mut ws, "echo hello-$((6*7)) $(whoami)", &format!("hello-42 {me}")).await.expect("a shell");
    ws.send(Message::text(r#"{"type":"resize","cols":120,"rows":40}"#)).await.unwrap();
    type_and_see(&mut ws, "stty size", "40 120").await.expect("resized");
    ws.send(Message::binary(b"exit 3\r".to_vec())).await.unwrap();
    let end = ending(&mut ws).await;
    assert_eq!((end["type"].as_str(), end["code"].as_u64()), (Some("exit"), Some(3)), "{end}");

    // The machine decides who may be which account: Cy shares the tag but isn't listed, and nobody
    // is listed for another account.
    let mut ws = open_terminal(&env, &cy, "dev-box", None).await.unwrap();
    let refused = log_in(&mut ws, &me).await.unwrap_err();
    assert!(refused["message"].as_str().unwrap().contains("authorized_principals"), "{refused}");
    let mut ws = open_terminal(&env, &ann, "dev-box", None).await.unwrap();
    assert!(log_in(&mut ws, "nobody-here").await.is_err());
    let mut ws = open_terminal(&env, &ann, "dev-box", None).await.unwrap();
    let refused = log_in(&mut ws, "-oProxyCommand=sh").await.unwrap_err();
    assert_eq!(refused["code"], "invalid_request", "{refused}");

    // Listed, Cy gets in, and is out as soon as the tag that let her reach the machine goes.
    std::fs::write(principals.join(&me), "ann@example.com\ncy@example.com\n").unwrap();
    let mut ws = open_terminal(&env, &cy, "dev-box", None).await.unwrap();
    log_in(&mut ws, &me).await.expect("logged in");
    type_and_see(&mut ws, "echo cy-$((1+1))", "cy-2").await.unwrap();
    env.api_json("PATCH", &format!("/api/v1/users/{}", ids["cy@example.com"]), Some(&admin), serde_json::json!({ "tags": [] })).await;
    assert_eq!(ending(&mut ws).await["type"], "ended");

    // Signing out everywhere ends Ann's terminals too.
    let mut ws = open_terminal(&env, &ann, "dev-box", None).await.unwrap();
    log_in(&mut ws, &me).await.expect("logged in");
    let account = env.ui("/account", Some(&ann), None).await;
    env.ui("/account/logout-everywhere", Some(&ann), Some(&[("csrf", &account.csrf())])).await;
    assert_eq!(ending(&mut ws).await["type"], "ended");
    let ann = sign_in(&env, "ann@example.com", "correct horse battery again").await;

    // The machine's host key was kept, and a different one is refused until its owner forgets it.
    let detail = env.ui(&format!("/tunnels/{id}"), Some(&ann), None).await;
    assert!(detail.html.contains("Forget host key"), "{}", detail.html);
    sshd.reinstall().await;
    let mut ws = open_terminal(&env, &ann, "dev-box", None).await.unwrap();
    let refused = log_in(&mut ws, &me).await.unwrap_err();
    assert!(refused["message"].as_str().unwrap().contains("host key"), "{refused}");
    let forget = env.ui(&format!("/tunnels/{id}/host-key/forget"), Some(&ann), Some(&[("csrf", &detail.csrf())])).await;
    assert_eq!(forget.status, StatusCode::SEE_OTHER);
    let mut ws = open_terminal(&env, &ann, "dev-box", None).await.unwrap();
    log_in(&mut ws, &me).await.expect("the new key is kept");

    env.eventually("the audit log says who logged in where", Duration::from_secs(5), async || {
        env.api("GET", "/api/v1/audit", Some(&admin)).await.1.to_string().contains("ssh.terminal")
    })
    .await;
}

/// A browser SSH terminal in a real browser (headless Chrome via `scripts/browser-terminal.mjs`):
/// the page's modules, its CSP and its WebSocket, and typing with real key presses. Needs Chrome,
/// Node 22+ and OpenSSH's server:
///
/// ```text
/// cargo test -p magicpipes-cli --test e2e browser_opens_an_ssh_terminal -- --ignored
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Chrome, Node and sshd"]
async fn browser_opens_an_ssh_terminal() {
    let chrome = std::env::var("MAGICPIPES_CHROME").unwrap_or_else(|_| {
        if cfg!(target_os = "macos") { "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into() } else { "google-chrome".into() }
    });
    let gateway = common::free_port();
    let env = Env::with_config(Tls::DevCa, &format!("[ssh]\nlisten = \"127.0.0.1:{gateway}\"\n")).await;
    let admin = env.admin_token();
    let ca = env.api("GET", "/api/v1/ssh-ca", Some(&admin)).await.1["public_key"].as_str().unwrap().to_string();
    let me = common::Sshd::login();
    std::fs::write(env.root.join("ca.pub"), format!("{ca}\n")).unwrap();
    std::fs::write(env.root.join("principals"), "ann@example.com\n").unwrap();
    let extra = format!("TrustedUserCAKeys {}\nAuthorizedPrincipalsFile {}\n", env.root.join("ca.pub").display(), env.root.join("principals").display());
    let sshd = common::Sshd::start(&env.root, &extra).await.expect("OpenSSH's server");
    let body = serde_json::json!({ "email": "ann@example.com", "password": "correct horse battery" });
    let (_, v) = env.api_json("POST", "/api/v1/users", Some(&admin), body).await;
    let ann = v["user"]["id"].as_str().unwrap().to_string();
    sign_in(&env, "ann@example.com", "correct horse battery").await;
    let (_, v) = env.api_json("POST", "/api/v1/enrollments", Some(&admin), serde_json::json!({ "owner_user_id": ann })).await;
    let (url, ca_cert) = (env.server_url(), env.ca_path.to_string_lossy().to_string());
    env.cli_ok(&["login", "--server", &url, "--token", v["enrollment_token"].as_str().unwrap(), "--ca-cert", &ca_cert, "--name", "dev"]).await;
    add_json(&env, &[&sshd.port.to_string(), "--ssh", "--name", "dev-box"]).await;

    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/browser-terminal.mjs");
    let profile = std::env::temp_dir().join(format!("mp-chrome-terminal-{}", std::process::id()));
    let opts = serde_json::json!({
        "chrome": chrome,
        "management": url,
        "terminal": "/terminal/dev-box",
        "email": "ann@example.com",
        "password": "correct horse battery again",
        "login": me,
        "command": "echo hello-$((6*7))",
        "want": "hello-42",
        "profile": profile,
        // MAGICPIPES_SCREENSHOTS=<dir>: pictures of the terminal and the pages linking to it.
        "shots": std::env::var("MAGICPIPES_SCREENSHOTS").map(|dir| {
            [(1180, false), (1180, true), (1024, false), (320, true), (320, false)]
                .iter()
                .flat_map(|&(width, dark)| {
                    let shade = if dark { "dark" } else { "light" };
                    [("terminal", "/terminal/dev-box"), ("tunnels", "/"), ("detail", "/tunnels/dev-box")].map(|(what, url)| {
                        serde_json::json!({ "path": format!("{dir}/{what}-{width}-{shade}.png"), "url": url, "width": width, "dark": dark, "full": what != "terminal" })
                    })
                })
                .collect::<Vec<_>>()
        }).unwrap_or_default(),
    });
    let out = tokio::process::Command::new("node").arg(&script).arg(opts.to_string()).output().await.expect("run node");
    std::fs::remove_dir_all(&profile).ok();
    let result: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&out.stderr)));
    assert!(result["errors"].as_array().unwrap().is_empty(), "the browser reported errors: {result}");
    if let Some(measured) = result["measured"].as_array() {
        eprintln!("{}", measured.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n"));
    }
    assert!(result["screen"].as_str().unwrap().contains("hello-42"), "{result}");
    assert_eq!(result["status"], "Running", "{result}");
    env.cli_ok(&["agent", "stop"]).await;
}

/// What a probe on the agent's health port gets: `None` until something listens there.
async fn health_get(port: u16, path: &str) -> Option<(u16, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.ok()?;
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n").as_bytes()).await.ok()?;
    let mut text = String::new();
    s.read_to_string(&mut text).await.ok()?;
    let status = text.split(' ').nth(1)?.parse().ok()?;
    Some((status, text.split_once("\r\n\r\n").map(|(_, body)| body.to_string()).unwrap_or_default()))
}

/// In a container: `agent run` enrolls itself from its environment the first time, serves the
/// tunnels declared there (trying again while an app is still starting), says when it's ready, and
/// at its next start removes what isn't declared any more. A mistake in a declaration stops it at
/// once, and another home can run as the same machine from a config file kept elsewhere, as a
/// Kubernetes Secret would hold it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_agent_in_a_container_serves_what_its_environment_declares() {
    let env = Env::new(Tls::DevCa).await;
    let app = common::http_app(Arc::new(tokio::sync::Notify::new())).await;
    let late_port = common::free_port();
    let health = common::free_port();
    let run = |home: &str, vars: &[(&str, String)]| {
        let home = env.root.join(home);
        let mut cmd = tokio::process::Command::new(common::bin("magicpipes"));
        cmd.args(["agent", "run"])
            .env("MAGICPIPES_HOME", &home)
            .env("MAGICPIPES_SOCKET", env.root.join(format!("{}.sock", home.file_name().unwrap().to_string_lossy())))
            .env("MAGICPIPES_PROBE_ADDR", "127.0.0.1")
            .env("MAGICPIPES_LOG", "info,magicpipes=debug")
            .env("MAGICPIPES_HEALTH_LISTEN", format!("127.0.0.1:{health}"))
            .env_remove("MAGICPIPES_TOKEN")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::fs::File::create(env.root.join(format!("{}.log", home.file_name().unwrap().to_string_lossy()))).unwrap())
            .kill_on_drop(true);
        for (k, v) in vars {
            cmd.env(k, v);
        }
        cmd.spawn().expect("start the agent")
    };
    let stop = async |mut agent: tokio::process::Child| {
        unsafe { libc::kill(agent.id().unwrap() as i32, libc::SIGTERM) };
        tokio::time::timeout(Duration::from_secs(15), agent.wait()).await.expect("the agent stops").unwrap();
    };
    let ready = async || health_get(health, "/readyz").await;
    let host = |name: &str| format!("{name}.{BASE}");

    // The first start enrolls, and serves the shop at once; the other app isn't up yet.
    let declared = format!("# the shop, and one whose app starts later\n{} --name shop --public\n{late_port} --name late --public\n", app.port);
    let first = run("pod", &[
        ("MAGICPIPES_SERVER", env.server_url()),
        ("MAGICPIPES_TOKEN", env.enrollment_token()),
        ("MAGICPIPES_CA_CERT", env.ca_path.to_string_lossy().to_string()),
        ("MAGICPIPES_AGENT_NAME", "pod-1".to_string()),
        ("MAGICPIPES_TUNNELS", declared),
    ]);
    env.eventually("the agent to be live", Duration::from_secs(20), || async { health_get(health, "/livez").await.is_some_and(|(s, _)| s == 200) }).await;
    env.eventually("the shop", Duration::from_secs(30), || async { env.get_public(&host("shop"), "/").await.0 == StatusCode::OK }).await;
    env.eventually("the late app to be waited for", Duration::from_secs(20), || async {
        ready().await.is_some_and(|(s, body)| s == 503 && body.contains(r#"{"error":"local_unreachable","tunnel":"late"}"#))
    })
    .await;
    let (_, agents) = env.api("GET", "/api/v1/agents", Some(&env.admin_token())).await;
    assert!(agents["agents"].as_array().unwrap().iter().any(|a| a["name"] == "pod-1"), "{agents}");

    // Once its app is up, the next try serves it, and the agent is ready.
    let _late = common::http_app_at(late_port).await;
    env.eventually("the agent to be ready", Duration::from_secs(30), || async { ready().await.is_some_and(|(s, _)| s == 200) }).await;
    assert_eq!(env.get_public(&host("late"), "/").await.0, StatusCode::OK);
    stop(first).await;

    // Started again with one tunnel fewer: enrolled already, it removes the other.
    let second = run("pod", &[("MAGICPIPES_TUNNELS", format!("{} --name shop --public", app.port))]);
    env.eventually("the agent to be ready again", Duration::from_secs(30), || async { ready().await.is_some_and(|(s, _)| s == 200) }).await;
    env.eventually("the late tunnel to go", Duration::from_secs(15), || async { env.get_public(&host("late"), "/").await.0 == StatusCode::NOT_FOUND }).await;
    assert_eq!(env.get_public(&host("shop"), "/").await.0, StatusCode::OK);
    stop(second).await;

    // A mistake stops it at once, saying where.
    let wrong = run("pod", &[("MAGICPIPES_TUNNELS", format!("{} --name shop --public\n8080 --public", app.port))]);
    let out = tokio::time::timeout(Duration::from_secs(10), wrong.wait_with_output()).await.expect("it stops").unwrap();
    assert!(!out.status.success());
    let log = std::fs::read_to_string(env.root.join("pod.log")).unwrap();
    assert!(log.contains("MAGICPIPES_TUNNELS, line 2: give it a --name or --hostname"), "{log}");

    // Another home, with the same machine's config kept elsewhere.
    let config = env.root.join("pod").join("config.json");
    let elsewhere = run("other-pod", &[("MAGICPIPES_CONFIG", config.to_string_lossy().to_string()), ("MAGICPIPES_TUNNELS", format!("{} --name shop --public", app.port))]);
    env.eventually("the same machine to be ready from another home", Duration::from_secs(30), || async { ready().await.is_some_and(|(s, _)| s == 200) }).await;
    assert!(!env.root.join("other-pod").join("config.json").exists());
    stop(elsewhere).await;
}
