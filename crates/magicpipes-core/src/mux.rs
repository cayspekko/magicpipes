//! Runs a yamux session on its own Tokio task and exposes it through a cloneable handle.
//!
//! yamux's `Connection` must be polled continuously (inbound polling drives all I/O), so a
//! single driver task owns it. Other tasks open outbound streams through [`MuxHandle::open`]
//! and receive inbound streams from the returned channel. Every stream is flow-controlled by
//! yamux (256 KiB initial window, auto-tuned), which gives per-stream backpressure. Frames
//! reach the connection in batches ([`Batched`]).
//!
//! An agent may hold several sessions at once, one per connection ([`MuxHandle::join`]): each
//! keeps its own limit of data streams, which yamux's own limit per connection requires, while
//! clients' shares and the pool's connections on their way back count across all of them.

use std::collections::HashMap;
use std::future::poll_fn;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;

pub use yamux::Mode;

/// A yamux stream adapted to Tokio's I/O traits. A stream opened with
/// [`MuxHandle::open_data`] or [`MuxHandle::open_shared`] keeps its place in the session's data
/// budget until dropped.
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
/// Data streams one client may hold per agent (across its sessions), or requests it may have in
/// flight on shared streams, so one client cannot take all of them.
pub const MAX_DATA_STREAMS_PER_CLIENT: usize = 64;
/// Inbound streams buffered before new ones are refused.
const INBOUND_QUEUE: usize = 64;
/// Bytes of frames collected for one write to the connection, per session.
const WRITE_BATCH: usize = 64 * 1024;
/// Per direction, for copying between a stream and a socket: yamux and TLS both move up to 16 KiB
/// at a time, so a buffer of a few of those takes one system call and one wake-up to fill where
/// the default 8 KiB takes several. A connection holds a stream, so this is bounded with them.
pub const COPY_BUFFER: usize = 64 * 1024;
/// How much unsent data the kernel keeps for a session's connection (`TCP_NOTSENT_LOWAT`). Every
/// stream shares that queue, and by itself it grows to megabytes: on a slow link, seconds of a
/// download that a page's next request has to wait behind. Kept here instead, data waits per
/// stream, so what gets sent next is still undecided. In-flight data isn't limited by this, so it
/// costs no throughput; on a fast link it was measured to make no difference.
pub const SEND_QUEUE: u32 = 128 * 1024;

type OpenReply = oneshot::Sender<io::Result<MuxStream>>;

#[derive(Clone, Debug)]
pub struct MuxHandle {
    open_tx: mpsc::Sender<OpenReply>,
    closed: CancellationToken,
    /// This session's data streams.
    streams: Arc<AtomicUsize>,
    /// What this session shares with the agent's others ([`MuxHandle::join`]).
    group: Arc<Group>,
}

/// What an agent's sessions count together: each client's uses, and the pool's connections on
/// their way back.
#[derive(Debug, Default)]
struct Group {
    clients: Mutex<HashMap<IpAddr, usize>>,
    lent: Lent,
}

/// Shared streams in use by a request, which will be idle again (or closed) once its response
/// has been read to the end: the server's connection pool counts them here, so that a request
/// finding the budget full can wait for one rather than be refused. Lock-free, since every
/// pooled request passes through it; the [`Notify`] is touched only when someone waits.
#[derive(Debug, Default)]
struct Lent {
    out: AtomicUsize,
    /// How many have come back, ever.
    back: AtomicU64,
    waiting: AtomicUsize,
    returned: Notify,
}

/// A place in the budget: a stream on a session, a client's use across the agent's sessions, or
/// both; released on drop.
struct DataSlot {
    stream: Option<Arc<AtomicUsize>>,
    client: Option<(Arc<Group>, IpAddr)>,
}

/// One client's use of a shared data stream, for as long as it is held ([`MuxHandle::client_use`]).
pub struct ClientUse(#[allow(dead_code)] DataSlot);

/// Takes a stream on `streams` (if `stream`) and a use for `client` in `group`, or neither.
fn acquire(streams: &Arc<AtomicUsize>, group: &Arc<Group>, stream: bool, client: Option<IpAddr>) -> Option<DataSlot> {
    let mut slot = DataSlot { stream: None, client: None };
    if stream {
        streams.try_update(Ordering::SeqCst, Ordering::SeqCst, |n| (n < MAX_DATA_STREAMS).then_some(n + 1)).ok()?;
        slot.stream = Some(streams.clone());
    }
    if let Some(c) = client {
        let mut clients = group.clients.lock().unwrap();
        let n = clients.entry(c).or_insert(0);
        if *n >= MAX_DATA_STREAMS_PER_CLIENT {
            // Dropping `slot` gives back the stream, if it took one.
            return None;
        }
        *n += 1;
        slot.client = Some((group.clone(), c));
    }
    Some(slot)
}

impl Drop for DataSlot {
    fn drop(&mut self) {
        if let Some(streams) = &self.stream {
            streams.fetch_sub(1, Ordering::SeqCst);
        }
        if let Some((group, c)) = &self.client {
            let mut clients = group.clients.lock().unwrap();
            if let Some(n) = clients.get_mut(c) {
                *n -= 1;
                if *n == 0 {
                    clients.remove(c);
                }
            }
        }
    }
}

impl MuxHandle {
    /// Opens a stream for public traffic from `client` (callers group addresses, e.g. an IPv6
    /// /64, before passing them), within the session's data budget. Fails at once with
    /// `WouldBlock` when the budget is used up.
    pub async fn open_data(&self, timeout: Duration, client: IpAddr) -> io::Result<MuxStream> {
        let slot = acquire(&self.streams, &self.group, true, Some(client)).ok_or_else(busy)?;
        let mut stream = self.open(timeout).await?;
        stream._slot = Some(slot);
        Ok(stream)
    }

    /// Opens a stream for public traffic that several clients use in turn (a pooled HTTP
    /// connection), within the session's total data budget; each use takes a [`Self::client_use`].
    /// Fails at once with `WouldBlock` when the budget is used up.
    pub async fn open_shared(&self, timeout: Duration) -> io::Result<MuxStream> {
        let slot = acquire(&self.streams, &self.group, true, None).ok_or_else(busy)?;
        let mut stream = self.open(timeout).await?;
        stream._slot = Some(slot);
        Ok(stream)
    }

    /// A place for one request from `client` on a shared stream; `None` when the client already
    /// has [`MAX_DATA_STREAMS_PER_CLIENT`] in flight on the agent's sessions.
    pub fn client_use(&self, client: IpAddr) -> Option<ClientUse> {
        acquire(&self.streams, &self.group, false, Some(client)).map(ClientUse)
    }

    /// Whether all of the session's data streams are in use, so another client's stream has to
    /// wait for one to be given back. Idle pooled connections can give theirs back at once.
    pub fn data_streams_full(&self) -> bool {
        self.data_streams() >= MAX_DATA_STREAMS
    }

    /// How many of the session's data streams are in use.
    pub fn data_streams(&self) -> usize {
        self.streams.load(Ordering::SeqCst)
    }

    /// Whether both handles belong to the same session.
    pub fn same_session(&self, other: &MuxHandle) -> bool {
        Arc::ptr_eq(&self.streams, &other.streams)
    }

    /// Whether both handles belong to the same agent's sessions ([`MuxHandle::join`]).
    pub fn same_group(&self, other: &MuxHandle) -> bool {
        Arc::ptr_eq(&self.group, &other.group)
    }

    /// This session, counted with `other`'s from now on: a client's share and the connections on
    /// their way back are the agent's, whichever of its sessions they're on. For a session that
    /// has no data streams yet.
    pub fn join(&self, other: &MuxHandle) -> MuxHandle {
        MuxHandle { group: other.group.clone(), ..self.clone() }
    }

    /// Counts a shared stream as lent to a request, until [`MuxHandle::came_back`].
    pub fn lend(&self) {
        self.group.lent.out.fetch_add(1, Ordering::SeqCst);
    }

    /// A stream [`MuxHandle::lend`] counted is idle again, or closed. Wakes the requests
    /// waiting for one.
    pub fn came_back(&self) {
        let lent = &self.group.lent;
        lent.out.fetch_sub(1, Ordering::SeqCst);
        lent.back.fetch_add(1, Ordering::SeqCst);
        if lent.waiting.load(Ordering::SeqCst) > 0 {
            lent.returned.notify_waiters();
        }
    }

    /// How many lent streams have come back so far, to pass to [`MuxHandle::wait_for_return`].
    pub fn returns(&self) -> u64 {
        self.group.lent.back.load(Ordering::SeqCst)
    }

    /// Waits for a lent stream to come back, as long as any are out and `deadline` hasn't
    /// passed. `true` when one has come back since `seen` ([`MuxHandle::returns`]), so another try
    /// may find it idle; `false` when there's nothing to wait for.
    pub async fn wait_for_return(&self, seen: u64, deadline: tokio::time::Instant) -> bool {
        let lent = &self.group.lent;
        lent.waiting.fetch_add(1, Ordering::SeqCst);
        let returned = lent.returned.notified();
        tokio::pin!(returned);
        returned.as_mut().enable();
        // Counted as waiting before looking: one coming back after this either shows here, or
        // sees the waiter and wakes it.
        let woke = if self.returns() != seen {
            true
        } else if lent.out.load(Ordering::SeqCst) == 0 {
            false
        } else {
            tokio::time::timeout_at(deadline, returned).await.is_ok()
        };
        lent.waiting.fetch_sub(1, Ordering::SeqCst);
        woke
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

fn busy() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "agent stream budget used up")
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "tunnel session closed")
}

/// Collects yamux's writes so that they reach the connection together.
///
/// yamux writes each frame's header and body separately and flushes after every frame, which over
/// TLS means two records and two system calls per frame. But it reads from the connection only once
/// it has nothing more to send, so that is when this writes what it has collected. A full batch
/// goes out at once, which bounds both the memory and how long a frame can wait.
struct Batched<T> {
    io: T,
    batch: Vec<u8>,
    /// How much of `batch` the connection has taken.
    written: usize,
    /// There is something the peer may not have been sent yet: in `batch`, or inside `io`.
    unsent: bool,
}

impl<T> Batched<T> {
    fn new(io: T) -> Self {
        Self { io, batch: Vec::with_capacity(WRITE_BATCH), written: 0, unsent: false }
    }
}

impl<T: AsyncWrite + Unpin> Batched<T> {
    /// Hands the batch to the connection and flushes it. While this is pending, the caller's waker
    /// is registered for when the connection can take more.
    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.batch.len() {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, &self.batch[self.written..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += n;
        }
        self.batch.clear();
        self.written = 0;
        ready!(Pin::new(&mut self.io).poll_flush(cx))?;
        self.unsent = false;
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for Batched<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // If this is pending the driver is woken when it can go on, and reads meanwhile: the peer
        // may be waiting for us to read before it can read what we send.
        if this.unsent
            && let Poll::Ready(Err(e)) = this.poll_send(cx)
        {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut this.io).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Batched<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.batch.len() >= WRITE_BATCH {
            ready!(this.poll_send(cx))?;
        }
        let n = data.len().min(WRITE_BATCH - this.batch.len());
        this.batch.extend_from_slice(&data[..n]);
        this.unsent = true;
        Poll::Ready(Ok(n))
    }

    /// yamux flushes after every frame; the batch goes out when it next reads.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_send(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
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
    let mut conn = yamux::Connection::new(Batched::new(io).compat(), config(), mode);
    let (open_tx, mut open_rx) = mpsc::channel::<OpenReply>(32);
    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE);
    let token = CancellationToken::new();
    let handle = MuxHandle { open_tx, closed: token.clone(), streams: Arc::default(), group: Arc::default() };

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

    /// Counts the writes that reach the connection.
    struct Counted {
        io: tokio::io::DuplexStream,
        writes: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl AsyncRead for Counted {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Counted {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.writes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Pin::new(&mut this.io).poll_write(cx, data)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().io).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
        }
    }

    const WAIT: Duration = Duration::from_secs(20);

    #[tokio::test]
    async fn frames_share_a_write_and_a_lone_frame_still_goes_out() {
        let writes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (a, b) = tokio::io::duplex(1 << 20);
        let (client, _client_in) = spawn(Counted { io: a, writes: writes.clone() }, Mode::Client);
        let (_server, mut server_in) = spawn(b, Mode::Server);

        // Nothing follows this frame, and nobody writes anything back: it has to go out by itself.
        let mut s = client.open(WAIT).await.unwrap();
        s.write_all(b"hello").await.unwrap();
        let mut r = tokio::time::timeout(WAIT, server_in.recv()).await.unwrap().unwrap();
        let mut got = [0u8; 5];
        tokio::time::timeout(WAIT, r.read_exact(&mut got)).await.unwrap().unwrap();
        assert_eq!(&got, b"hello");

        // Queued together, these go out together: yamux makes a header and a body write of each.
        let mut streams = Vec::new();
        for _ in 0..8 {
            streams.push(client.open(WAIT).await.unwrap());
        }
        let before = writes.load(std::sync::atomic::Ordering::Relaxed);
        for s in &mut streams {
            s.write_all(&[7u8; 1000]).await.unwrap();
        }
        for _ in 0..8 {
            let mut r = tokio::time::timeout(WAIT, server_in.recv()).await.unwrap().unwrap();
            let mut got = [0u8; 1000];
            tokio::time::timeout(WAIT, r.read_exact(&mut got)).await.unwrap().unwrap();
        }
        let used = writes.load(std::sync::atomic::Ordering::Relaxed) - before;
        assert!(used < 16, "{used} writes for 8 frames");
    }

    /// Both sides send more than the connection holds, on many streams at once, so each has to keep
    /// reading while its own batch waits to go out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sending_both_ways_over_a_small_pipe_never_stalls() {
        const STREAMS: usize = 8;
        const BYTES: usize = 4 << 20;
        let (a, b) = tokio::io::duplex(1024);
        let (client, mut client_in) = spawn(a, Mode::Client);
        let (server, mut server_in) = spawn(b, Mode::Server);
        // Sends `BYTES` of a pattern and reads the same back, checking each byte.
        async fn exchange(mut s: MuxStream) {
            let (mut read, mut write) = tokio::io::split(&mut s);
            let send = async {
                let block: Vec<u8> = (0..4099).map(|i| (i % 251) as u8).collect();
                let mut left = BYTES;
                while left > 0 {
                    let n = left.min(block.len());
                    write.write_all(&block[..n]).await.unwrap();
                    left -= n;
                }
                write.shutdown().await.unwrap();
            };
            let receive = async {
                let mut seen = 0usize;
                let mut buf = vec![0u8; 8192];
                loop {
                    let n = read.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    for (i, b) in buf[..n].iter().enumerate() {
                        assert_eq!(*b, (((seen + i) % 4099) % 251) as u8, "byte {}", seen + i);
                    }
                    seen += n;
                }
                assert_eq!(seen, BYTES);
            };
            tokio::join!(send, receive);
        }
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..STREAMS {
            let (c, s) = (client.open(WAIT).await.unwrap(), server.open(WAIT).await.unwrap());
            tasks.spawn(exchange(c));
            tasks.spawn(exchange(s));
        }
        for _ in 0..STREAMS {
            tasks.spawn(exchange(tokio::time::timeout(WAIT, server_in.recv()).await.unwrap().unwrap()));
            tasks.spawn(exchange(tokio::time::timeout(WAIT, client_in.recv()).await.unwrap().unwrap()));
        }
        while let Some(done) = tokio::time::timeout(WAIT, tasks.join_next()).await.expect("the session stalled") {
            done.unwrap();
        }
    }

    #[tokio::test]
    async fn what_is_batched_goes_out_before_the_connection_closes() {
        let (a, b) = tokio::io::duplex(1 << 20);
        let (client, _client_in) = spawn(a, Mode::Client);
        let (server, mut server_in) = spawn(b, Mode::Server);
        let mut s = client.open(WAIT).await.unwrap();
        s.write_all(b"last words").await.unwrap();
        s.shutdown().await.unwrap();
        client.close();
        let mut r = tokio::time::timeout(WAIT, server_in.recv()).await.unwrap().unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(WAIT, r.read_to_end(&mut got)).await.unwrap().unwrap();
        assert_eq!(got, b"last words");
        tokio::time::timeout(WAIT, server.closed()).await.unwrap();
    }

    /// The budget of a session that hasn't joined another: its own streams and clients.
    fn alone() -> (Arc<AtomicUsize>, Arc<Group>) {
        (Arc::default(), Arc::default())
    }

    #[test]
    fn data_budget_limits_clients_and_total() {
        let (streams, group) = alone();
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        let mut held: Vec<DataSlot> = (0..MAX_DATA_STREAMS_PER_CLIENT).map(|_| acquire(&streams, &group, true, Some(a)).unwrap()).collect();
        assert!(acquire(&streams, &group, true, Some(a)).is_none(), "per-client limit");
        assert_eq!(streams.load(Ordering::SeqCst), MAX_DATA_STREAMS_PER_CLIENT, "a refused client takes no stream");
        assert!(acquire(&streams, &group, false, Some(a)).is_none(), "uses of shared streams count too");
        held.pop();
        assert!(acquire(&streams, &group, true, Some(a)).is_some(), "released on drop");
        let mut i = 0u32;
        while let Some(slot) = acquire(&streams, &group, true, Some(IpAddr::from((i + 1).to_be_bytes()))) {
            held.push(slot);
            i += 1;
        }
        assert_eq!(streams.load(Ordering::SeqCst), MAX_DATA_STREAMS);
        assert!(acquire(&streams, &group, true, None).is_none(), "shared streams count toward the total");
        let b: IpAddr = "203.0.113.2".parse().unwrap();
        let used = acquire(&streams, &group, false, Some(b)).expect("a use takes no stream");
        drop(held);
        assert_eq!(streams.load(Ordering::SeqCst), 0);
        drop(used);
        assert!(group.clients.lock().unwrap().is_empty());
    }

    /// An agent's sessions each have their own streams, which yamux limits per connection, but a
    /// client's share is the agent's, and a connection coming back on one wakes a request on another.
    #[tokio::test]
    async fn joined_sessions_share_clients_and_returns_but_not_streams() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let (c, d) = tokio::io::duplex(1 << 16);
        let ((first, _in1), (_peer1, _in2)) = (spawn(a, Mode::Server), spawn(b, Mode::Client));
        let ((second, _in3), (_peer2, _in4)) = (spawn(c, Mode::Server), spawn(d, Mode::Client));
        let second = second.join(&first);
        assert!(second.same_group(&first) && !second.same_session(&first));

        let client: IpAddr = "203.0.113.9".parse().unwrap();
        let mut uses: Vec<ClientUse> = (0..MAX_DATA_STREAMS_PER_CLIENT / 2).map(|_| first.client_use(client).unwrap()).collect();
        uses.extend((0..MAX_DATA_STREAMS_PER_CLIENT / 2).map(|_| second.client_use(client).unwrap()));
        assert!(first.client_use(client).is_none() && second.client_use(client).is_none(), "one share across the agent's sessions");
        drop(uses);

        // Each session's streams are its own.
        let held: Vec<DataSlot> = (0..MAX_DATA_STREAMS).map(|_| acquire(&first.streams, &first.group, true, None).unwrap()).collect();
        assert!(first.data_streams_full() && !second.data_streams_full());
        assert_eq!((first.data_streams(), second.data_streams()), (MAX_DATA_STREAMS, 0));
        drop(held);

        // A request waiting on one session is woken by a connection coming back on the other.
        let far = tokio::time::Instant::now() + Duration::from_secs(3600);
        first.lend();
        let seen = first.returns();
        let back = async {
            tokio::task::yield_now().await;
            second.came_back();
        };
        let (woke, ()) = tokio::join!(first.wait_for_return(seen, far), back);
        assert!(woke);
    }

    #[tokio::test]
    async fn a_request_waits_only_for_a_stream_on_its_way_back() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let ((s1, _in1), (s2, _in2)) = (spawn(a, Mode::Server), spawn(b, Mode::Client));
        // Never reached: each answer below comes at once, or from a stream coming back.
        let far = tokio::time::Instant::now() + Duration::from_secs(3600);
        assert!(!s1.wait_for_return(s1.returns(), far).await, "nothing lent");
        s1.lend();
        assert!(!s2.wait_for_return(s2.returns(), far).await, "only on another session");
        // One that came back since the request last looked is worth another try at once.
        let seen = s1.returns();
        s1.came_back();
        assert!(s1.wait_for_return(seen, far).await);
        assert!(!s1.wait_for_return(s1.returns(), far).await, "counted back");
        // And one coming back wakes a request waiting for it.
        s1.lend();
        let seen = s1.returns();
        let back = async {
            tokio::task::yield_now().await;
            s1.came_back();
        };
        let (woke, ()) = tokio::join!(s1.wait_for_return(seen, far), back);
        assert!(woke);
        assert_eq!(s1.group.lent.waiting.load(Ordering::SeqCst), 0, "no waiter left behind");
    }
}
