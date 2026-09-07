//! Serialized writes and the persistence boundary of one audit file.

use std::io;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use warden_ports::{AuditError, BoxFuture};

/// The file operations needed by a record, including the attempt's durability step.
pub(super) trait DurableWrite: AsyncWrite + Unpin {
    fn sync_data(&mut self) -> BoxFuture<'_, io::Result<()>>;
}

impl DurableWrite for tokio::fs::File {
    fn sync_data(&mut self) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(tokio::fs::File::sync_data(self))
    }
}

/// One writer, accessed only while the sink holds its serialization mutex.
pub(super) struct Writer<W> {
    inner: W,
    /// Set before I/O so an error or cancellation cannot permit another append.
    uncertain: bool,
}

impl<W: DurableWrite> Writer<W> {
    pub(super) fn new(inner: W) -> Self {
        Self {
            inner,
            uncertain: false,
        }
    }

    pub(super) async fn write(&mut self, line: &str, durable: bool) -> Result<(), AuditError> {
        if self.uncertain {
            return Err(unavailable(io::Error::other(
                "the audit writer requires recovery",
            )));
        }
        self.uncertain = true;
        self.inner
            .write_all(line.as_bytes())
            .await
            .map_err(unavailable)?;
        self.inner.flush().await.map_err(unavailable)?;
        if durable {
            self.inner.sync_data().await.map_err(unavailable)?;
        }
        self.uncertain = false;
        Ok(())
    }
}

fn unavailable(error: io::Error) -> AuditError {
    AuditError::Unavailable {
        detail: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    use super::*;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Phase {
        Write,
        Flush,
        Sync,
    }

    /// Fault injection below the real serialized writer. A write fault leaves a
    /// prefix, and every error is transient so only Warden can prevent a retry.
    struct FaultingFile {
        bytes: Vec<u8>,
        fault: Option<Phase>,
        stall: bool,
        syncs: usize,
    }

    impl FaultingFile {
        fn step(&mut self, phase: Phase) -> Poll<io::Result<()>> {
            if self.fault == Some(phase) {
                if self.stall {
                    return Poll::Pending;
                }
                self.fault = None;
                return Poll::Ready(Err(io::Error::other("private disk failure")));
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for FaultingFile {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.fault == Some(Phase::Write) && self.bytes.is_empty() {
                self.bytes.extend_from_slice(&bytes[..3]);
                return Poll::Ready(Ok(3));
            }
            match self.step(Phase::Write) {
                Poll::Ready(Ok(())) => {
                    self.bytes.extend_from_slice(bytes);
                    Poll::Ready(Ok(bytes.len()))
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        }

        fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.step(Phase::Flush)
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl DurableWrite for FaultingFile {
        fn sync_data(&mut self) -> BoxFuture<'_, io::Result<()>> {
            self.syncs += 1;
            Box::pin(std::future::poll_fn(|_| self.step(Phase::Sync)))
        }
    }

    fn writer(fault: Option<Phase>, stall: bool) -> Writer<FaultingFile> {
        Writer::new(FaultingFile {
            bytes: Vec::new(),
            fault,
            stall,
            syncs: 0,
        })
    }

    async fn assert_error_poisons(phase: Phase) {
        let mut writer = writer(Some(phase), false);
        let error = writer.write("{\"first\":1}\n", true).await.unwrap_err();
        assert_eq!(error.to_string(), "the audit sink is unavailable");
        let before = writer.inner.bytes.clone();
        let retry = writer.write("{\"second\":2}\n", true).await;
        assert!(
            retry.is_err(),
            "uncertain I/O must permanently poison the writer"
        );
        assert_eq!(
            writer.inner.bytes, before,
            "no bytes may follow uncertain I/O"
        );
    }

    #[tokio::test]
    async fn a_partial_write_poisons_later_records() {
        assert_error_poisons(Phase::Write).await;
    }

    #[tokio::test]
    async fn a_flush_error_poisons_later_records() {
        assert_error_poisons(Phase::Flush).await;
    }

    #[tokio::test]
    async fn a_sync_error_poisons_later_records() {
        assert_error_poisons(Phase::Sync).await;
    }

    #[tokio::test]
    async fn cancellation_at_each_io_phase_poisons_later_records() {
        for phase in [Phase::Write, Phase::Flush, Phase::Sync] {
            let mut writer = writer(Some(phase), true);
            let mut write = Box::pin(writer.write("{\"first\":1}\n", true));
            assert!(
                write
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            drop(write);
            writer.inner.fault = None;
            let before = writer.inner.bytes.clone();
            assert!(writer.write("{\"second\":2}\n", true).await.is_err());
            assert_eq!(writer.inner.bytes, before);
        }
    }

    #[tokio::test]
    async fn completed_writes_can_continue_and_only_attempts_sync() {
        let mut writer = writer(None, false);
        writer.write("{\"attempt\":1}\n", true).await.unwrap();
        writer.write("{\"outcome\":1}\n", false).await.unwrap();
        assert_eq!(writer.inner.bytes, b"{\"attempt\":1}\n{\"outcome\":1}\n");
        assert_eq!(writer.inner.syncs, 1);
    }
}
