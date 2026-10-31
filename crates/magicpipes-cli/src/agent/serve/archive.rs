//! Bulk download: selected entries of one directory as a `.tar.gz`, streamed while it is built.
//!
//! The archive is written on a blocking thread into a bounded channel, so nothing touches the
//! disk, memory stays flat for any size, and a client that stops reading pauses the writer (and
//! stops it once it disconnects). The same rules as serving apply: hidden entries are skipped,
//! everything must resolve inside the root, and directory symlinks are not followed (which also
//! rules out cycles). Unreadable files are skipped; a failure while streaming aborts the response
//! so the client sees a broken download rather than a silently truncated archive.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use flate2::Compression;
use flate2::write::GzEncoder;
use hyper::body::{Body, Frame};
use tokio::sync::mpsc;

use super::servable_name;

const CHUNK: usize = 64 * 1024;

/// Starts writing the archive and returns its body. `names` are entries of `dir` (already
/// validated as servable names); `root` is the canonical served root.
pub fn stream(root: PathBuf, dir: PathBuf, names: Vec<String>) -> ChannelBody {
    let (tx, rx) = mpsc::channel(8);
    tokio::task::spawn_blocking(move || {
        let mut out = ChannelWriter { tx: tx.clone(), buf: Vec::with_capacity(CHUNK) };
        let result = write(&root, &dir, &names, &mut out).and_then(|()| out.send());
        if let Err(e) = result {
            tracing::debug!(error = %e, "archive download ended early");
            let _ = tx.blocking_send(Err(e));
        }
    });
    ChannelBody(rx)
}

fn write(root: &Path, dir: &Path, names: &[String], out: &mut ChannelWriter) -> io::Result<()> {
    let mut tar = tar::Builder::new(GzEncoder::new(out, Compression::default()));
    for name in names {
        add(&mut tar, root, &dir.join(name), Path::new(name))?;
    }
    tar.into_inner()?.finish()?;
    Ok(())
}

fn add<W: Write>(tar: &mut tar::Builder<W>, root: &Path, path: &Path, name: &Path) -> io::Result<()> {
    let (Ok(link), Ok(real)) = (std::fs::symlink_metadata(path), std::fs::canonicalize(path)) else { return Ok(()) };
    if !real.starts_with(root) {
        return Ok(());
    }
    let Ok(meta) = std::fs::metadata(&real) else { return Ok(()) };
    if meta.is_file() {
        // Opened before the header is written: an unreadable file is skipped, not half-written.
        let Ok(mut f) = File::open(&real) else { return Ok(()) };
        return tar.append_file(name, &mut f);
    }
    if !meta.is_dir() || link.file_type().is_symlink() {
        return Ok(());
    }
    tar.append_dir(name, &real)?;
    let Ok(rd) = std::fs::read_dir(&real) else { return Ok(()) };
    let mut children: Vec<String> =
        rd.filter_map(|e| e.ok()?.file_name().into_string().ok()).filter(|n| servable_name(n)).collect();
    children.sort();
    for child in children {
        add(tar, root, &real.join(&child), &name.join(&child))?;
    }
    Ok(())
}

/// Collects writes into chunks and hands them to the response body.
struct ChannelWriter {
    tx: mpsc::Sender<io::Result<Bytes>>,
    buf: Vec<u8>,
}

impl ChannelWriter {
    fn send(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let chunk = Bytes::from(std::mem::replace(&mut self.buf, Vec::with_capacity(CHUNK)));
        self.tx.blocking_send(Ok(chunk)).map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "client went away"))
    }
}

impl Write for ChannelWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        if self.buf.len() >= CHUNK {
            self.send()?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct ChannelBody(mpsc::Receiver<io::Result<Bytes>>);

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        self.0.poll_recv(cx).map(|item| item.map(|r| r.map(Frame::data)))
    }
}
