//! End-to-end lifecycle tests with real `magicpipesd` and `magicpipes` processes.

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

fn hostname(public_url: &str) -> String {
    public_url.trim_start_matches("https://").split(':').next().unwrap().to_string()
}

async fn add_json(env: &Env, args: &[&str]) -> Value {
    let mut a = vec!["add"];
    a.extend_from_slice(args);
    a.push("--json");
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
    assert!(resp.headers()[header::SET_COOKIE].to_str().unwrap().contains("HttpOnly"));
    let page = |cookie: String| {
        Request::get("/").header(header::HOST, format!("localhost:{}", env.mgmt_port)).header(header::COOKIE, cookie).body(Full::new(Bytes::new())).unwrap()
    };
    let resp = env.send("localhost", env.mgmt_port, page(cookie.clone())).await;
    assert_eq!(resp.status(), 200);
    let html = String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(html.contains(&host1) && html.contains("sockets") && html.contains("connected"), "{html}");
    // Without a session the UI redirects to the login page.
    let resp = env.send("localhost", env.mgmt_port, page("mp_session=bogus".into())).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

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
