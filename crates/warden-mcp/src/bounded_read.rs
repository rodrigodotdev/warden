//! A byte budget per MCP frame, applied before the SDK ever sees a line.
//!
//! rmcp 3.2.0 reads stdin with `read_until(b'\n')` into a `Vec<u8>` that grows until
//! a newline arrives (`transport/async_rw.rs`). A peer that never sends one can make
//! the process allocate without bound. This reader sits underneath the SDK's
//! `BufReader` and counts bytes since the last `\n`; past `MAX_MCP_FRAME_BYTES` it
//! returns `InvalidData`, the SDK stops reading, and the session ends
//! (`docs/mcp.md` section 5.1, ADR-0052). It never looks at the bytes.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, ReadBuf};

/// The most bytes one newline-delimited MCP frame may carry.
pub(crate) const MAX_MCP_FRAME_BYTES: usize = 1024 * 1024;

/// A frame grew past [`MAX_MCP_FRAME_BYTES`] without a newline.
///
/// Carries nothing: at this point no JSON has been decoded, so there is no request id
/// to correlate and no field to name, and copying bytes of the frame into a message
/// is exactly what must not happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("an MCP frame exceeded the accepted size")]
pub(crate) struct FrameTooLarge;

/// Bytes seen since the last newline, and whether the budget has already failed.
#[derive(Debug)]
struct LineBudget {
    limit: usize,
    used: usize,
    failed: bool,
}

impl LineBudget {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            used: 0,
            failed: false,
        }
    }

    /// Accounts for bytes as they arrive, in whatever chunks they arrive in.
    ///
    /// Every byte but `\n` counts — `\r`, a BOM, whitespace — because the SDK keeps
    /// every one of them until the newline. A failed budget is terminal: the reader
    /// is about to be dropped with the session, and no later newline may revive it.
    fn observe(&mut self, bytes: &[u8]) -> Result<(), FrameTooLarge> {
        if self.failed {
            return Err(FrameTooLarge);
        }
        let mut segments = bytes.split(|byte| *byte == b'\n').peekable();
        while let Some(segment) = segments.next() {
            match self.used.checked_add(segment.len()) {
                Some(used) if used <= self.limit => self.used = used,
                _ => {
                    self.failed = true;
                    return Err(FrameTooLarge);
                }
            }
            // `split` yields one more segment than there are newlines, so a segment
            // with a successor was terminated by one: the next line starts at zero.
            if segments.peek().is_some() {
                self.used = 0;
            }
        }
        Ok(())
    }
}

/// An [`AsyncRead`] that refuses to deliver a line longer than its budget.
///
/// The budget lives on the reader, not on any one `poll_read` future: the SDK polls
/// its read inside a `select!` and drops the future whenever another branch is ready,
/// and a count kept on the future would restart at zero on every such drop.
#[derive(Debug)]
pub(crate) struct BoundedRead<R> {
    inner: R,
    budget: LineBudget,
}

impl<R> BoundedRead<R> {
    /// Wraps `inner`, allowing at most `max_frame_bytes` between newlines.
    pub(crate) fn new(inner: R, max_frame_bytes: usize) -> Self {
        Self {
            inner,
            budget: LineBudget::new(max_frame_bytes),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for BoundedRead<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.budget.failed {
            return Poll::Ready(Err(frame_too_large()));
        }
        let already_filled = buf.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        // Only the bytes this call added are new; `buf` may have been partly filled
        // by the caller before it reached us. On failure the caller discards what was
        // read — tokio's `BufReader` leaves its cursor untouched on an error — and the
        // SDK ends the session on the next line read, so nothing is delivered twice.
        match this.budget.observe(&buf.filled()[already_filled..]) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(FrameTooLarge) => Poll::Ready(Err(frame_too_large())),
        }
    }
}

fn frame_too_large() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, FrameTooLarge)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn the_budget_survives_chunks_and_resets_only_at_a_newline() {
        let mut budget = LineBudget::new(4);
        assert!(budget.observe(b"ab").is_ok());
        // "cd" completes a four-byte line; "x" starts the next one.
        assert!(budget.observe(b"cd\nx").is_ok());
        assert!(budget.observe(b"yzq").is_ok());
        // The fifth byte of the second line.
        assert_eq!(budget.observe(b"!"), Err(FrameTooLarge));
        // A failed budget stays failed, even across a newline.
        assert_eq!(budget.observe(b"\n{}"), Err(FrameTooLarge));
    }

    #[test]
    fn a_complete_oversized_line_inside_one_chunk_is_still_refused() {
        let mut budget = LineBudget::new(2);
        assert_eq!(budget.observe(b"a\nbcd\ne"), Err(FrameTooLarge));
    }

    #[test]
    fn carriage_returns_count_and_newlines_do_not() {
        let mut budget = LineBudget::new(3);
        assert!(budget.observe(b"ab\r\n").is_ok());
        assert!(budget.observe(b"\n\n\n").is_ok());
        assert_eq!(budget.used, 0);
    }

    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};

    #[tokio::test]
    async fn a_frame_split_byte_by_byte_arrives_intact() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut lines = BufReader::new(BoundedRead::new(reader, 4));
        tokio::spawn(async move {
            for byte in b"ab\n" {
                writer.write_all(&[*byte]).await.unwrap();
                writer.flush().await.unwrap();
            }
        });
        let mut line = String::new();
        lines.read_line(&mut line).await.unwrap();
        assert_eq!(line, "ab\n");
    }

    #[tokio::test]
    async fn a_line_past_the_budget_is_invalid_data_and_the_reader_stays_failed() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut bounded = BoundedRead::new(reader, 4);
        writer.write_all(b"abcde\n").await.unwrap();
        let mut sink = [0_u8; 64];
        let error = bounded.read(&mut sink).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), FrameTooLarge.to_string());
        // Whatever arrives next, the reader is done.
        writer.write_all(b"{}\n").await.unwrap();
        assert_eq!(
            bounded.read(&mut sink).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn two_frames_in_one_chunk_each_get_their_own_budget() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut lines = BufReader::new(BoundedRead::new(reader, 4));
        writer.write_all(b"abcd\nwxyz\n").await.unwrap();
        let mut first = String::new();
        let mut second = String::new();
        lines.read_line(&mut first).await.unwrap();
        lines.read_line(&mut second).await.unwrap();
        assert_eq!((first.as_str(), second.as_str()), ("abcd\n", "wxyz\n"));
    }
}
