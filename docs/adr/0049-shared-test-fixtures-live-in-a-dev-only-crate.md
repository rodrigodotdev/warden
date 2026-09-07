# ADR-0049 — Shared test fixtures live in a dev-only crate

**Status:** Accepted · 2026-09-06

## Context

Four crates carry a `testing` module — `warden-service` (1 166 lines),
`warden-ports` (576), `warden-mcp` (490) and `warden-policy` (202) — and a token-level
clone scan found real overlap between them. `connection(dialect)`, `capabilities()`,
`parts(dialect)` and `result_set()` are **byte-identical** across three or four of
them. Four crates independently deciding what a `ConnectionMetadata` fixture looks like
is four chances to drift on what the tests are testing against.

There is also a second, sharper problem in the same modules.
`keep_callsite_interest_dynamic` exists three times — `warden-service/src/testing.rs`,
`warden-service/tests/service_rules.rs` and `warden-mcp/src/server.rs` — and what it
does is worse than that it is triplicated. It leaks two `Dispatch`es for the process
lifetime so that `tracing-core`'s single-dispatcher fast path stays off, then calls
`rebuild_interest_cache()`. Every callsite in the binary becomes `Interest::sometimes()`
for the rest of the run, and it depends on an interest-union rule across live
dispatchers that `tracing-core` does not document as a contract. The most recent commit
on `main` before this work — `f6a3a4d fix(tests): make span capture independent of
callsite registration order` — is that fragility having already bitten once.

Worse, it is the *third* technique in the tree for one problem.
`warden-service/src/audit.rs` calls `set_global_default` behind a hand-rolled
`AtomicBool` spinlock and `.unwrap()`s the result; the audit sink's own tests call it
behind a `OnceLock`. `set_global_default` succeeds once per process, and the first two
of those live in the same test binary — so "install one global subscriber per test
binary" was already taken, and any second attempt would have panicked depending on
which test ran first.

## Decision

Shared test fixtures live in `crates/warden-testing`, a dev-only workspace member
reached from `[dev-dependencies]` alone.

**Not a `testing` feature on `warden-ports`.** A feature can reach a release build
through one mistyped manifest line, and `FakeAuditSink` in production is an audit sink
that records nothing. A crate that appears in no normal dependency edge cannot, and the
architecture assertion that checks it is a simpler statement than one about feature
unification. It also keeps `tracing-subscriber`-shaped test machinery out of the crate
whose job is to declare traits. `warden-guards` already establishes the shape.

**The fakes stay where their tests are.** The clone scan reported `FakeExecutor`,
`FakeInspector` and `FakeAuditSink` in three crates, and the first revision of the
review read that as duplication to remove. It is not. `FakeExecutor` holds one field in
`warden-ports`, seven in `warden-service` — failure, result, call count, observed
deadlines and tokens, observed limits, a panic switch — and two in `warden-mcp`. They
are three different observation surfaces over one trait, and each is exactly what its
own crate's tests need to assert. Merging them means either giving every crate the
union, most of which it never reads, or making two crates test through a poorer fake.
Both are worse code than the duplication, so only what is genuinely identical moves.

**Callsite interest gets one primitive.** `warden_testing::ask_every_callsite` installs
one global subscriber that registers interest in every callsite and enables none, so
interest is `sometimes` process-wide and `enabled` is asked per call on the emitting
thread. It replaces all three techniques. `warden-service/src/audit.rs` converts from
global to scoped, which frees the global slot and removes its spinlock with it.

Scoped subscribers stay. `with_subscriber` attaches a dispatcher to the *future*, which
is correct across threads and tasks by construction; a capture layer keyed by
`ThreadId` would be correct only while every test remained a current-thread
`#[tokio::test]`. It is also load-bearing at
`warden-service/src/schema.rs`: `PanicOnRedaction` is a fault injector, not a capture,
and a global layer cannot inject a panic into one test.

## Consequences

One definition of each shared fixture, so a change to what a test's world looks like is
one edit rather than four that may not all happen.

`tests/architecture.rs` asserts that `warden-testing` appears in no normal dependency
edge, which is what makes the fakes structurally unable to ship.

The interest hack, its two leaked dispatchers, its `rebuild_interest_cache()` call and
its dependence on `tracing-core` internals are gone. One assumption replaces them —
that registering a dispatcher rebuilds the interest of callsites already known — and it
is pinned by a test that touches a callsite *before* installing, so it fails loudly
rather than silently losing a span if that ever stops holding.
