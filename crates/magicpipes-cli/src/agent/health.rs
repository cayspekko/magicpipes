//! `MAGICPIPES_HEALTH_LISTEN`: plain HTTP for a container's probes. `/livez` answers while the agent
//! runs. `/readyz` answers 200 once it's connected and serving every declared tunnel (without
//! declarations, every tunnel it has), and 503 until then, saying what it's waiting for. That's no
//! more than tunnel names, which are in their public addresses anyway, and error codes.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use super::declared::Declarations;
use super::ops::Agent;

pub const HEALTH_ENV: &str = "MAGICPIPES_HEALTH_LISTEN";
/// Probes come one at a time; anything past this is turned away.
const MAX_CONNECTIONS: usize = 16;
/// A probe that hasn't finished in this long is cut off.
const CONNECTION_DEADLINE: Duration = Duration::from_secs(10);

/// Where to listen: `9090` or `:9090` is every interface (the kubelet probes the pod's address),
/// `127.0.0.1:9090` or `[::]:9090` just that one.
pub fn address(text: &str) -> Result<SocketAddr, String> {
    let text = text.trim();
    let port = text.strip_prefix(':').unwrap_or(text);
    if let Ok(port) = port.parse::<u16>() {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
    }
    text.parse().map_err(|_| format!("{HEALTH_ENV} is '{text}', which isn't a port or address:port"))
}

/// Answers probes on `listener` until `shutdown`.
pub fn spawn(listener: TcpListener, agent: Arc<Agent>, declared: Option<Arc<Declarations>>, shutdown: CancellationToken) {
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    tokio::spawn(async move {
        loop {
            let (stream, _) = tokio::select! {
                _ = shutdown.cancelled() => return,
                accepted = listener.accept() => match accepted {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::debug!(error = %e, "health listener accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                },
            };
            let Ok(slot) = slots.clone().try_acquire_owned() else { continue };
            let (agent, declared) = (agent.clone(), declared.clone());
            tokio::spawn(async move {
                let _slot = slot;
                let svc = service_fn(move |req: Request<Incoming>| {
                    let answer = answer(&req, &agent, declared.as_deref());
                    async move { Ok::<_, std::convert::Infallible>(answer) }
                });
                let conn = hyper::server::conn::http1::Builder::new()
                    .timer(TokioTimer::new())
                    .header_read_timeout(Duration::from_secs(5))
                    .keep_alive(false)
                    .serve_connection(TokioIo::new(stream), svc);
                let _ = tokio::time::timeout(CONNECTION_DEADLINE, conn).await;
            });
        }
    });
}

fn answer(req: &Request<Incoming>, agent: &Agent, declared: Option<&Declarations>) -> Response<Full<Bytes>> {
    let reply = |status: StatusCode, body: String| {
        let body = if req.method() == Method::HEAD { Bytes::new() } else { Bytes::from(body) };
        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CACHE_CONTROL, "no-store")
            .body(Full::new(body))
            .expect("a valid response")
    };
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return reply(StatusCode::METHOD_NOT_ALLOWED, r#"{"error":"only GET"}"#.into());
    }
    match req.uri().path() {
        "/livez" => reply(StatusCode::OK, r#"{"live":true}"#.into()),
        "/readyz" => {
            let (ready, body) = agent.readiness(declared);
            reply(if ready { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE }, body.to_string())
        }
        _ => reply(StatusCode::NOT_FOUND, r#"{"error":"try /livez or /readyz"}"#.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_a_port_or_an_address() {
        assert_eq!(address("9090").unwrap(), "0.0.0.0:9090".parse().unwrap());
        assert_eq!(address(":9090").unwrap(), "0.0.0.0:9090".parse().unwrap());
        assert_eq!(address("127.0.0.1:9090").unwrap(), "127.0.0.1:9090".parse().unwrap());
        assert_eq!(address("[::]:9090").unwrap(), "[::]:9090".parse().unwrap());
        assert!(address("localhost:9090").is_err());
        assert!(address("99999").is_err());
    }
}
