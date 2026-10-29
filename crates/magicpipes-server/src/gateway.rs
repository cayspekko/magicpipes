//! Agent gateway: authenticates the agent's upgrade request, runs the yamux session, attaches it
//! to the control plane (which publishes it to the data plane) and answers agent RPCs.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};
use hyper_util::rt::TokioIo;
use magicpipes_core::mux::{self, Mode, MuxStream};
use magicpipes_core::proto::{self, Request as Rpc, Response as RpcResponse, UPGRADE_PROTOCOL};
use tokio::io::AsyncWriteExt;

use crate::control::ControlPlane;
use crate::mgmt::{AppState, PeerAddr, bearer_token};

const RPC_READ_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn connect(State(app): State<AppState>, mut req: Request) -> Response {
    let wants_mux = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case(UPGRADE_PROTOCOL));
    if !wants_mux {
        return (StatusCode::BAD_REQUEST, "expected Upgrade: magicpipes-mux/1").into_response();
    }
    let peer = req.extensions().get::<PeerAddr>().map(|p| p.0).unwrap_or_else(|| ([0, 0, 0, 0], 0).into());
    let Some(agent_id) = bearer_token(req.headers()).and_then(|t| app.control.authenticate_agent(t)) else {
        tracing::warn!(%peer, "rejected agent connection: invalid credentials");
        tokio::time::sleep(Duration::from_millis(250)).await;
        return (StatusCode::UNAUTHORIZED, "invalid agent credentials").into_response();
    };
    let Some(on_upgrade) = req.extensions_mut().remove::<hyper::upgrade::OnUpgrade>() else {
        return (StatusCode::BAD_REQUEST, "connection is not upgradable").into_response();
    };
    let control = app.control.clone();
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => run_session(control, agent_id, peer, TokioIo::new(upgraded)).await,
            Err(e) => tracing::warn!(%peer, error = %e, "agent upgrade failed"),
        }
    });
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    resp.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    resp.headers_mut().insert(header::UPGRADE, HeaderValue::from_static(UPGRADE_PROTOCOL));
    resp
}

async fn run_session(
    control: Arc<ControlPlane>,
    agent_id: String,
    peer: SocketAddr,
    io: TokioIo<hyper::upgrade::Upgraded>,
) {
    let (handle, mut inbound) = mux::spawn(io, Mode::Server);
    let conn_id = control.attach_session(&agent_id, handle.clone(), peer);
    loop {
        tokio::select! {
            _ = handle.closed() => break,
            stream = inbound.recv() => match stream {
                Some(stream) => {
                    let control = control.clone();
                    let agent_id = agent_id.clone();
                    tokio::spawn(async move { serve_rpc(control, agent_id, conn_id, stream).await });
                }
                None => break,
            },
        }
    }
    handle.close();
    control.detach_session(&agent_id, conn_id);
}

async fn serve_rpc(control: Arc<ControlPlane>, agent_id: String, conn_id: u64, mut stream: MuxStream) {
    let req: Rpc = match tokio::time::timeout(RPC_READ_TIMEOUT, proto::read_frame(&mut stream)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            tracing::debug!(agent = %agent_id, error = %e, "bad agent RPC");
            return;
        }
        Err(_) => return,
    };
    let resp = match req {
        Rpc::Ping => {
            control.touch(&agent_id, conn_id);
            RpcResponse::Pong
        }
        Rpc::Register(r) => match control.register(&agent_id, &r) {
            Ok(info) => RpcResponse::Tunnel(info),
            Err(e) => RpcResponse::Error(e),
        },
        Rpc::Unregister { id } => match control.unregister(&agent_id, &id) {
            Ok(()) => RpcResponse::Ok,
            Err(e) => RpcResponse::Error(e),
        },
        Rpc::CertStatus { hostname, wait_ms } => {
            match control.cert_status(&agent_id, &hostname, Duration::from_millis(wait_ms)).await {
                Ok(s) => RpcResponse::Cert(s),
                Err(e) => RpcResponse::Error(e),
            }
        }
    };
    if proto::write_frame(&mut stream, &resp).await.is_ok() {
        let _ = stream.shutdown().await;
    }
}
