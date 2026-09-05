//! What Warden says when something panics.
//!
//! `docs/security.md` section 14 requires two controls, and Milestone 12 shipped
//! only the first. Containment is `WardenServer::run_in_task`: a panicking request
//! becomes `internal_error` rather than the end of a stdio session. This is the
//! second: the default hook prints the payload, a payload can be whatever the
//! panicking expression formatted into it — an `expect` on a row value is the
//! document's own example — and stderr is where Warden's operator log lives.
//!
//! The report keeps what names **code**: the source location, the thread, and the
//! payload's *type*. It never keeps what could name **data**: the payload itself.
//! A backtrace is included only when the runtime captured one, which needs
//! `RUST_BACKTRACE`; a backtrace holds symbol names and addresses and no value a
//! panicking expression formatted.

use std::any::Any;
use std::backtrace::{Backtrace, BacktraceStatus};
use std::panic::Location;

/// A panic, described by everything except what it said.
#[derive(Debug)]
pub(crate) struct PanicReport {
    /// `file:line:column`, when the panic carried a location.
    pub(crate) location: Option<String>,
    /// The panicking thread's name, or `unnamed`.
    pub(crate) thread: String,
    /// `&str`, `String`, or `other` — the shape, never the content.
    pub(crate) payload_type: &'static str,
}

impl PanicReport {
    /// Describes a panic without reading its payload.
    pub(crate) fn describe(
        payload: &dyn Any,
        location: Option<&Location<'_>>,
        thread: Option<&str>,
    ) -> Self {
        let payload_type = if payload.is::<&str>() {
            "&str"
        } else if payload.is::<String>() {
            "String"
        } else {
            "other"
        };

        Self {
            location: location.map(|location| {
                format!(
                    "{}:{}:{}",
                    location.file(),
                    location.line(),
                    location.column()
                )
            }),
            thread: thread.unwrap_or("unnamed").to_owned(),
            payload_type,
        }
    }
}

/// Installs the process-level hook that reports panics without their payloads.
pub(crate) fn install() {
    std::panic::set_hook(Box::new(|info| {
        let thread = std::thread::current();
        let report = PanicReport::describe(info.payload(), info.location(), thread.name());
        let captured = Backtrace::capture();
        let backtrace =
            (captured.status() == BacktraceStatus::Captured).then(|| captured.to_string());

        tracing::error!(
            target: "warden.panic",
            location = report.location.as_deref().unwrap_or("unknown"),
            thread = %report.thread,
            payload_type = report.payload_type,
            backtrace = backtrace.as_deref(),
            "a thread panicked"
        );
    }));
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::any::Any;

    use super::PanicReport;

    #[test]
    fn a_string_payload_is_described_by_its_type_and_never_by_its_content() {
        // `docs/security.md` section 14: a panic message can contain data — an
        // `expect` that formatted a row value is the example the document gives — and
        // stderr is the log destination.
        let payload: Box<dyn Any + Send> = Box::new("card 4111111111111111".to_owned());
        let report = PanicReport::describe(payload.as_ref(), None, Some("tokio-runtime-worker"));
        let rendered = format!("{report:?}");
        assert!(!rendered.contains("4111111111111111"), "{rendered}");
        assert_eq!(report.payload_type, "String");
        assert_eq!(report.thread, "tokio-runtime-worker");
        assert_eq!(report.location, None);
    }

    #[test]
    fn every_payload_shape_is_classified_without_being_read() {
        let borrowed: Box<dyn Any + Send> = Box::new("secret");
        assert_eq!(
            PanicReport::describe(borrowed.as_ref(), None, None).payload_type,
            "&str"
        );
        let other: Box<dyn Any + Send> = Box::new(42_u32);
        assert_eq!(
            PanicReport::describe(other.as_ref(), None, None).payload_type,
            "other"
        );
    }

    #[test]
    fn a_location_is_kept_because_it_names_code_and_not_data() {
        let location = std::panic::Location::caller();
        let payload: Box<dyn Any + Send> = Box::new("x");
        let report = PanicReport::describe(payload.as_ref(), Some(location), None);
        let named = report.location.unwrap();
        assert!(named.contains("panic.rs"), "{named}");
        assert!(named.contains(':'), "{named}");
    }
}
