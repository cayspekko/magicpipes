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
use magicpipes_core::error::ErrorCode;
use magicpipes_core::mux::{self, Mode, MuxStream};
use magicpipes_core::proto::{
    self, ErrorBody, PROTOCOL_HEADER, PROTOCOL_VERSION, Request as Rpc, Response as RpcResponse, UPGRADE_PROTOCOL,
};
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
    let protocol = proto::peer_protocol(req.headers().get(PROTOCOL_HEADER).and_then(|v| v.to_str().ok()));
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
            Ok(upgraded) => run_session(control, agent_id, peer, protocol, TokioIo::new(upgraded)).await,
            Err(e) => tracing::warn!(%peer, error = %e, "agent upgrade failed"),
        }
    });
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    resp.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    resp.headers_mut().insert(header::UPGRADE, HeaderValue::from_static(UPGRADE_PROTOCOL));
    resp.headers_mut().insert(PROTOCOL_HEADER, HeaderValue::from(PROTOCOL_VERSION));
    resp
}

async fn run_session(
    control: Arc<ControlPlane>,
    agent_id: String,
    peer: SocketAddr,
    protocol: u32,
    io: TokioIo<hyper::upgrade::Upgraded>,
) {
    let (handle, mut inbound) = mux::spawn(io, Mode::Server);
    let Some(conn_id) = control.attach_session(&agent_id, handle.clone(), peer, protocol) else {
        tracing::warn!(agent = %agent_id, %peer, "closing session of revoked agent");
        handle.close();
        return;
    };
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
    let body = match tokio::time::timeout(RPC_READ_TIMEOUT, proto::read_frame_bytes(&mut stream)).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            tracing::debug!(agent = %agent_id, error = %e, "bad agent RPC");
            return;
        }
        Err(_) => return,
    };
    let resp = match serde_json::from_slice::<Rpc>(&body) {
        Ok(req) => answer(&control, &agent_id, conn_id, req).await,
        // Well-formed but unknown: a newer agent. Old servers dropped these, which the agent saw
        // as an unreachable server.
        Err(e) => {
            tracing::debug!(agent = %agent_id, error = %e, "unsupported agent RPC");
            RpcResponse::Error(ErrorBody::new(ErrorCode::Unsupported, "this server does not support the request; update magicpipesd"))
        }
    };
    if proto::write_frame(&mut stream, &resp).await.is_ok() {
        let _ = stream.shutdown().await;
    }
}

async fn answer(control: &ControlPlane, agent_id: &str, conn_id: u64, req: Rpc) -> RpcResponse {
    match req {
        Rpc::Ping => {
            control.touch(agent_id, conn_id);
            RpcResponse::Pong
        }
        Rpc::Register(r) => match control.register(agent_id, &r) {
            Ok(info) => RpcResponse::Tunnel(info),
            Err(e) => RpcResponse::Error(e),
        },
        Rpc::Unregister { id } => match control.unregister(agent_id, &id) {
            Ok(()) => RpcResponse::Ok,
            Err(e) => RpcResponse::Error(e),
        },
        Rpc::Check { id } => match control.check(agent_id, &id).await {
            Ok(()) => RpcResponse::Ok,
            Err(e) => RpcResponse::Error(e),
        },
        Rpc::CertStatus { hostname, wait_ms } => {
            match control.cert_status(agent_id, &hostname, Duration::from_millis(wait_ms)).await {
                Ok(s) => RpcResponse::Cert(s),
                Err(e) => RpcResponse::Error(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unknown_rpcs_are_answered_unsupported() {
        let f = crate::control::tests::fixture();
        let agent = f.agent("a");
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (client, _pushes) = mux::spawn(a, Mode::Client);
        let (_server, mut inbound) = mux::spawn(b, Mode::Server);
        let control = f.cp.clone();
        tokio::spawn(async move {
            while let Some(s) = inbound.recv().await {
                tokio::spawn(serve_rpc(control.clone(), agent.clone(), 0, s));
            }
        });

        // A request from a newer agent gets an answer instead of a dropped stream.
        let mut s = client.open(Duration::from_secs(5)).await.unwrap();
        proto::write_frame(&mut s, &serde_json::json!({ "op": "from_the_future" })).await.unwrap();
        let resp: RpcResponse = proto::read_frame(&mut s).await.unwrap();
        assert!(matches!(&resp, RpcResponse::Error(e) if e.is(ErrorCode::Unsupported)), "{resp:?}");

        // Known requests still work on the same session.
        let mut s = client.open(Duration::from_secs(5)).await.unwrap();
        proto::write_frame(&mut s, &Rpc::Ping).await.unwrap();
        assert_eq!(proto::read_frame::<_, RpcResponse>(&mut s).await.unwrap(), RpcResponse::Pong);
    }
}
