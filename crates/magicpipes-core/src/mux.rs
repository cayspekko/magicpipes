//! Runs a yamux session on its own Tokio task and exposes it through a cloneable handle.
//!
//! yamux's `Connection` must be polled continuously (inbound polling drives all I/O), so a
//! single driver task owns it. Other tasks open outbound streams through [`MuxHandle::open`]
//! and receive inbound streams from the returned channel. Every stream is flow-controlled by
//! yamux (256 KiB initial window, auto-tuned), which gives per-stream backpressure.

use std::future::poll_fn;
use std::io;
use std::task::Poll;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;

pub use yamux::Mode;

/// A yamux stream adapted to Tokio's I/O traits.
pub type MuxStream = Compat<yamux::Stream>;

/// Maximum concurrent streams per session (each public request uses one).
pub const MAX_STREAMS: usize = 256;
/// Inbound streams buffered before new ones are refused.
const INBOUND_QUEUE: usize = 64;

type OpenReply = oneshot::Sender<io::Result<MuxStream>>;

#[derive(Clone, Debug)]
pub struct MuxHandle {
    open_tx: mpsc::Sender<OpenReply>,
    closed: CancellationToken,
}

impl MuxHandle {
    /// Opens a new outbound stream, failing after `timeout`.
    pub async fn open(&self, timeout: Duration) -> io::Result<MuxStream> {
        let (tx, rx) = oneshot::channel();
        let fut = async {
            self.open_tx.send(tx).await.map_err(|_| closed())?;
            rx.await.map_err(|_| closed())?
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "timed out opening stream"))?
    }

    /// Resolves when the session has terminated.
    pub async fn closed(&self) {
        self.closed.cancelled().await
    }

    pub fn is_closed(&self) -> bool {
        self.closed.is_cancelled()
    }

    /// Terminates the session (all streams are reset).
    pub fn close(&self) {
        self.closed.cancel()
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "tunnel session closed")
}

fn config() -> yamux::Config {
    let mut cfg = yamux::Config::default();
    cfg.set_max_connection_receive_window(Some(MAX_STREAMS * 256 * 1024 * 2));
    cfg.set_max_num_streams(MAX_STREAMS);
    cfg
}

/// Starts a yamux session over `io`. Returns a handle for opening streams and a receiver of
/// inbound streams. Dropping the receiver makes the driver refuse inbound streams.
pub fn spawn<T>(io: T, mode: Mode) -> (MuxHandle, mpsc::Receiver<MuxStream>)
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let mut conn = yamux::Connection::new(io.compat(), config(), mode);
    let (open_tx, mut open_rx) = mpsc::channel::<OpenReply>(32);
    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE);
    let token = CancellationToken::new();
    let handle = MuxHandle { open_tx, closed: token.clone() };

    tokio::spawn(async move {
        let mut pending: Option<OpenReply> = None;
        let drive = poll_fn(|cx| {
            loop {
                if pending.is_none()
                    && let Poll::Ready(Some(reply)) = open_rx.poll_recv(cx) {
                        pending = Some(reply);
                    }
                if let Some(reply) = pending.take() {
                    match conn.poll_new_outbound(cx) {
                        Poll::Ready(res) => {
                            let _ = reply.send(res.map(|s| s.compat()).map_err(io::Error::other));
                            continue;
                        }
                        Poll::Pending => pending = Some(reply),
                    }
                }
                match conn.poll_next_inbound(cx) {
                    Poll::Ready(Some(Ok(stream))) => {
                        // A full queue means the consumer is overloaded: dropping the stream
                        // resets it, which the peer observes as a refused stream.
                        let _ = inbound_tx.try_send(stream.compat());
                        continue;
                    }
                    Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                    Poll::Ready(None) => return Poll::Ready(Ok(())),
                    Poll::Pending => return Poll::Pending,
                }
            }
        });
        tokio::select! {
            res = drive => {
                if let Err(e) = res {
                    tracing::debug!(error = %e, "mux session ended with error");
                }
            }
            _ = token.cancelled() => {
                let _ = tokio::time::timeout(Duration::from_secs(2), poll_fn(|cx| conn.poll_close(cx))).await;
            }
        }
        token.cancel();
    });

    (handle, inbound_rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn streams_both_directions() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let (client, mut client_in) = spawn(a, Mode::Client);
        let (server, mut server_in) = spawn(b, Mode::Server);

        let mut s = client.open(Duration::from_secs(5)).await.unwrap();
        s.write_all(b"hello").await.unwrap();
        let mut r = server_in.recv().await.unwrap();
        let mut buf = [0u8; 5];
        r.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        let mut s2 = server.open(Duration::from_secs(5)).await.unwrap();
        s2.write_all(b"back").await.unwrap();
        s2.shutdown().await.unwrap();
        let mut r2 = client_in.recv().await.unwrap();
        let mut out = Vec::new();
        r2.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"back");

        client.close();
        tokio::time::timeout(Duration::from_secs(5), server.closed()).await.unwrap();
    }
}
