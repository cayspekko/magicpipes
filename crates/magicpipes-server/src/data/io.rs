//! I/O adapters used by the proxy.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use magicpipes_core::proto::StreamStatus;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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

/// Records the time of the last successful read in a shared clock.
struct Tracked<S> {
    inner: S,
    last: Arc<AtomicU64>,
    epoch: Instant,
}

impl<S: AsyncRead + Unpin> AsyncRead for Tracked<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(res, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.last.store(self.epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tracked<S> {
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

/// Copies bytes in both directions until both sides finish or no data flows for `idle`.
/// Backpressure is inherent: each direction only reads when the previous write completed.
/// Copies both ways until either side closes, the connection idles for `idle`, or `stop` is
/// cancelled (access was revoked).
pub async fn bridge<A, B>(a: A, b: B, idle: Duration, stop: tokio_util::sync::CancellationToken)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let last = Arc::new(AtomicU64::new(0));
    let epoch = Instant::now();
    let mut a = Tracked { inner: a, last: last.clone(), epoch };
    let mut b = Tracked { inner: b, last: last.clone(), epoch };
    let copy = tokio::io::copy_bidirectional(&mut a, &mut b);
    tokio::pin!(copy);
    let mut tick = tokio::time::interval((idle / 4).clamp(Duration::from_millis(100), Duration::from_secs(30)));
    loop {
        tokio::select! {
            res = &mut copy => {
                if let Err(e) = res {
                    tracing::debug!(error = %e, "upgraded connection ended");
                }
                return;
            }
            _ = stop.cancelled() => {
                tracing::debug!("closing upgraded connection: access revoked");
                return;
            }
            _ = tick.tick() => {
                let idle_for = epoch.elapsed().saturating_sub(Duration::from_millis(last.load(Ordering::Relaxed)));
                if idle_for >= idle {
                    tracing::debug!(?idle, "closing idle upgraded connection");
                    return;
                }
            }
        }
    }
}
