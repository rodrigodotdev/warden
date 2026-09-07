//! One answer to "a scoped subscriber must not lose a span to a callsite some sibling
//! test reached first" (ADR-0049).
//!
//! `tracing-core` caches one `Interest` per callsite for the whole program and computes
//! it the first time *any* thread reaches that callsite. While exactly one dispatcher is
//! registered it takes a fast path that asks whichever subscriber is default on that
//! thread — so a span callsite first reached by a sibling test thread, which has none,
//! is cached as `never` for every thread, including the one that scopes a capturing
//! subscriber over the same code a moment later. That is a lost span here and nowhere
//! in production, where the process installs a subscriber before it serves anything.
//!
//! The tree solved that three different ways: two leaked dispatchers plus
//! `rebuild_interest_cache()` in three places, `set_global_default` behind a hand-rolled
//! spinlock in a fourth, and `set_global_default` behind a `OnceLock` in a fifth. The
//! first two shared a test binary, and `set_global_default` succeeds once per process,
//! so they were already mutually exclusive — whichever test ran first decided.
//!
//! [`ask_every_callsite`] is the one answer. Scoped subscribers stay: `with_subscriber`
//! attaches a dispatcher to the *future*, which is correct across threads and tasks by
//! construction, and one call site injects a panic rather than capturing, which no
//! global layer could do.

use std::sync::OnceLock;

/// Installs the test binary's one global subscriber, once.
///
/// It registers interest in every callsite and enables none of them, so interest is
/// `sometimes` process-wide and `enabled` is asked per call on the emitting thread. A
/// subscriber scoped over a future afterwards is therefore always consulted, whatever
/// order the callsites were first reached in.
///
/// Idempotent, and the only `set_global_default` a test binary may call.
///
/// # Panics
///
/// If something else already installed a global subscriber in this process. That is a
/// real conflict rather than a race: two global subscribers cannot both be default, and
/// a test binary that wants one of its own should scope it instead.
pub fn ask_every_callsite() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        tracing::subscriber::set_global_default(AlwaysAsk)
            .expect("the test binary installs no other global subscriber");
    });
}

/// Registers interest in every callsite and enables none of them.
///
/// This subscriber exists to be counted, not to record. `max_level_hint` returns
/// `TRACE` so the static maximum-level filter stays open; `register_callsite` returns
/// `sometimes` so the per-call `enabled` path is used; `enabled` returns `false` so
/// nothing is recorded through this subscriber itself.
#[derive(Debug)]
struct AlwaysAsk;

impl tracing::Subscriber for AlwaysAsk {
    fn register_callsite(
        &self,
        _metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        false
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }

    fn new_span(&self, _attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, _event: &tracing::Event<'_>) {}

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}
