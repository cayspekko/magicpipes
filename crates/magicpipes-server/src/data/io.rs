//! I/O adapters used by the proxy.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use magicpipes_core::proto::StreamStatus;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::listen::Activity;

/// Error surfaced when the agent reports that it could not serve a data stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamStatus {
    LocalUnreachable,
    UnknownTunnel,
    Closed,
    Other(u8),
}

impl std::fmt::Display for UpstreamStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpstreamStatus::LocalUnreachable => f.write_str("local application unreachable"),
            UpstreamStatus::UnknownTunnel => f.write_str("agent does not serve this tunnel"),
            UpstreamStatus::Closed => f.write_str("agent closed the stream"),
            UpstreamStatus::Other(c) => write!(f, "agent stream error {c}"),
        }
    }
}

impl std::error::Error for UpstreamStatus {}

/// Finds an [`UpstreamStatus`] anywhere in an error's source chain.
pub fn find_status(err: &(dyn std::error::Error + 'static)) -> Option<UpstreamStatus> {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if let Some(s) = e.downcast_ref::<UpstreamStatus>() {
            return Some(*s);
        }
        if let Some(ioe) = e.downcast_ref::<io::Error>()
            && let Some(s) = ioe.get_ref().and_then(|i| i.downcast_ref::<UpstreamStatus>()) {
                return Some(*s);
            }
        cur = e.source();
    }
    None
}

/// Consumes the agent's one-byte stream status before exposing the byte stream.
///
/// The request is written immediately (pipelined); the status byte is only awaited when the
/// HTTP client first reads the response, so a successful stream costs no extra round trip.
pub struct StatusPrefixed<S> {
    inner: S,
    open: bool,
}

impl<S> StatusPrefixed<S> {
    pub fn new(inner: S) -> Self {
        Self { inner, open: false }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for StatusPrefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if !self.open {
            let mut b = [0u8; 1];
            let mut rb = ReadBuf::new(&mut b);
            std::task::ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
            let status = match rb.filled() {
                [] => UpstreamStatus::Closed,
                [c, ..] => match StreamStatus::from_byte(*c) {
                    Some(StreamStatus::Ok) => {
                        self.open = true;
                        return Pin::new(&mut self.inner).poll_read(cx, buf);
                    }
                    Some(StreamStatus::LocalUnreachable) => UpstreamStatus::LocalUnreachable,
                    Some(StreamStatus::UnknownTunnel) => UpstreamStatus::UnknownTunnel,
                    Some(StreamStatus::Unsupported) | None => UpstreamStatus::Other(*c),
                },
            };
            return Poll::Ready(Err(io::Error::other(status)));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for StatusPrefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Copies bytes in both directions until either side closes, no byte moves for `idle` (if set), or
/// `stop` is cancelled (access was revoked). Backpressure is inherent: each direction only reads
/// when the previous write completed.
pub async fn bridge<A, B>(a: A, b: B, idle: Option<Duration>, stop: tokio_util::sync::CancellationToken)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let activity = Activity::new();
    let (mut a, mut b) = (activity.track(a), activity.track(b));
    let stalled = async {
        match idle {
            Some(limit) => activity.stalled(limit).await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        res = tokio::io::copy_bidirectional(&mut a, &mut b) => {
            if let Err(e) = res {
                tracing::debug!(error = %e, "bridged connection ended");
            }
        }
        _ = stop.cancelled() => tracing::debug!("closing a bridged connection: access revoked"),
        _ = stalled => tracing::debug!(?idle, "closing an idle bridged connection"),
    }
}

