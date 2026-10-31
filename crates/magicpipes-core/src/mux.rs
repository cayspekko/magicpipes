//! Runs a yamux session on its own Tokio task and exposes it through a cloneable handle.
//!
//! yamux's `Connection` must be polled continuously (inbound polling drives all I/O), so a
//! single driver task owns it. Other tasks open outbound streams through [`MuxHandle::open`]
//! and receive inbound streams from the returned channel. Every stream is flow-controlled by
//! yamux (256 KiB initial window, auto-tuned), which gives per-stream backpressure.

use std::collections::HashMap;
use std::future::poll_fn;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;

pub use yamux::Mode;

/// A yamux stream adapted to Tokio's I/O traits. A stream opened with
/// [`MuxHandle::open_data`] keeps its place in the session's data budget until dropped.
pub struct MuxStream {
    io: Compat<yamux::Stream>,
    _slot: Option<DataSlot>,
}

impl MuxStream {
    fn new(s: yamux::Stream) -> Self {
        Self { io: s.compat(), _slot: None }
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

/// Maximum concurrent streams per session, in both directions together.
pub const MAX_STREAMS: usize = 256;
/// Streams the server may open for public traffic per session. The remainder stays free for
/// the agent's RPCs and pings, so public clients can slow a tunnel but never cut its session.
pub const MAX_DATA_STREAMS: usize = 224;
/// Data streams one client may hold per session, so one client cannot take all of them.
pub const MAX_DATA_STREAMS_PER_CLIENT: usize = 64;
/// Inbound streams buffered before new ones are refused.
const INBOUND_QUEUE: usize = 64;

type OpenReply = oneshot::Sender<io::Result<MuxStream>>;

#[derive(Clone, Debug)]
pub struct MuxHandle {
    open_tx: mpsc::Sender<OpenReply>,
    closed: CancellationToken,
    data: Arc<DataBudget>,
}

/// Open data streams: in total and per client.
#[derive(Debug, Default)]
struct DataBudget(Mutex<(usize, HashMap<IpAddr, usize>)>);

/// One data stream's place in the budget; released on drop.
struct DataSlot(Arc<DataBudget>, IpAddr);

impl DataBudget {
    fn acquire(self: &Arc<Self>, client: IpAddr) -> Option<DataSlot> {
        let mut guard = self.0.lock().unwrap();
        let (total, per_client) = &mut *guard;
        let n = per_client.entry(client).or_insert(0);
        if *total >= MAX_DATA_STREAMS || *n >= MAX_DATA_STREAMS_PER_CLIENT {
            if *n == 0 {
                per_client.remove(&client);
            }
            return None;
        }
        *n += 1;
        *total += 1;
        Some(DataSlot(self.clone(), client))
    }
}

impl Drop for DataSlot {
    fn drop(&mut self) {
        let mut guard = self.0.0.lock().unwrap();
        let (total, per_client) = &mut *guard;
        *total -= 1;
        if let Some(n) = per_client.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                per_client.remove(&self.1);
            }
        }
    }
}

impl MuxHandle {
    /// Opens a stream for public traffic from `client` (callers group addresses, e.g. an IPv6
    /// /64, before passing them), within the session's data budget. Fails at once with
    /// `WouldBlock` when the budget is used up.
    pub async fn open_data(&self, timeout: Duration, client: IpAddr) -> io::Result<MuxStream> {
        let slot = self.data.acquire(client).ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "agent stream budget used up"))?;
        let mut stream = self.open(timeout).await?;
        stream._slot = Some(slot);
        Ok(stream)
    }

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
    let handle = MuxHandle { open_tx, closed: token.clone(), data: Arc::default() };

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
                            let _ = reply.send(res.map(MuxStream::new).map_err(io::Error::other));
                            continue;
                        }
                        Poll::Pending => pending = Some(reply),
                    }
                }
                match conn.poll_next_inbound(cx) {
                    Poll::Ready(Some(Ok(stream))) => {
                        // A full queue means the consumer is overloaded: dropping the stream
                        // resets it, which the peer observes as a refused stream.
                        let _ = inbound_tx.try_send(MuxStream::new(stream));
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

    #[test]
    fn data_budget_limits_clients_and_total() {
        let budget = Arc::new(DataBudget::default());
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        let mut held: Vec<DataSlot> = (0..MAX_DATA_STREAMS_PER_CLIENT).map(|_| budget.acquire(a).unwrap()).collect();
        assert!(budget.acquire(a).is_none(), "per-client limit");
        held.pop();
        assert!(budget.acquire(a).is_some(), "released on drop");
        let mut i = 0u32;
        while let Some(slot) = budget.acquire(IpAddr::from((i + 1).to_be_bytes())) {
            held.push(slot);
            i += 1;
        }
        assert_eq!(budget.0.lock().unwrap().0, MAX_DATA_STREAMS);
        drop(held);
        assert_eq!(budget.0.lock().unwrap().0, 0);
        assert!(budget.0.lock().unwrap().1.is_empty());
    }
}
