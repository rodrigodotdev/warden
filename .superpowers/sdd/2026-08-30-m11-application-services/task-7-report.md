# Task 7: SchemaService report

## Summary

Implemented Milestone 11's bounded schema-discovery orchestration. `SchemaService`
resolves the requested runtime, refuses unsupported search before the inspector,
builds the adapter's `ObjectFilter` from that runtime and request context, derives the
client deadline from the runtime's own limits, and supplies a real child of the root
shutdown token. Search results remain unchanged; descriptions have only matching
column defaults and comments redacted before returning.

The path deliberately has no audit collaborator and does not enter `ExecutionGate` or
acquire a `QueryPermit`. Catalog reads use adapter-owned static SQL on `control_pool`,
not agent SQL on `agent_pool`, and the current audit event is statement-shaped.

## Files

- Created `crates/warden-service/src/schema.rs`:
  - public `SchemaService`, constructor, sanitized hand-written `Debug`, `search`, and
    `describe`;
  - 13 focused service tests.
- Modified `crates/warden-service/src/lib.rs`:
  - registered the public schema module and re-exported `SchemaService`.
- Modified `crates/warden-service/src/testing.rs`:
  - added bounded search/description fixtures;
  - made `FakeInspector` return realistic values and record exact requests, filters,
    deadlines, tokens, and call cardinality;
  - added capability/inspector fields and a schema-service fixture.
- Created this report.

## RED, GREEN, and mutation evidence

The initial RED command was:

```text
rtk cargo test -p warden-service schema
```

It failed with the expected six `E0432`/`E0425`/`E0433` diagnostics because
`SchemaService` did not exist in the new module or public export. There was no fixture
or assertion failure masking the missing feature.

After the minimal implementation, the same command passed 14 schema-filtered tests
(the 13 new service tests plus the existing schema error-map test). The full
`warden-service` suite passed 88 tests across two suites.

Mutation checks were applied to production, observed RED, restored with
`apply_patch`, and followed by a fresh 13/13 module GREEN:

- bypassed the capability check: the unsupported-search test received success and
  observed an inspector call;
- derived both deadlines from default limits: the search and describe tests observed
  6 seconds instead of the literal runtime-derived 42 and 74 seconds;
- discarded the adapter's search result: the exact result fixture test observed an
  empty match list;
- omitted description redaction: the description test observed `hunter2` and the
  production comment instead of `[REDACTED]`;
- replaced the describe child token with a clone of the root: cancelling the observed
  token cancelled the root, failing child-to-root isolation.

The complementary root-to-child test also rejects an unrelated token. Exact filter
observations for both methods assert the selected runtime metadata and a literal
denial produced by the supplied engine; the two-runtime test rejects dispatch to the
wrong inspector.

## Architecture and tests

- `search` order is resolve, capability check, build filter/deadline, dispatch, return
  unredacted result.
- `describe` order is resolve, build filter/deadline, dispatch, redact description,
  return.
- Both filters use `PolicyContext::new(context, runtime.metadata())`; filtering is at
  the source under ADR-0036, never post-response trimming.
- Both deadlines use `RequestBudget::new(runtime.limits())` and Tokio `Instant`.
- Both calls receive `shutdown.child_token()`, preserving root-to-child cancellation
  without child-to-root propagation.
- A saturated runtime test holds the only query permit and proves schema description
  still reaches the inspector immediately.
- Missing connections for both methods and false search capability have exact zero
  inspector cardinality.
- Search output is asserted literally and remains unredacted. Description assertions
  prove the allowed column remains unchanged while only the configured column's
  default and comment are redacted.
- All four current `SchemaError` variants are propagated exactly and checked against
  literal public codes; the database detail remains absent from public `Display`.
  Existing exhaustive service-error tests independently cover connection variants,
  `SearchUnsupported`, and sanitized database/rejection displays.
- `SchemaService::Debug` exposes only `redactor_is_empty`; registry/port types, engine,
  shutdown token, and token state are absent.

## Commands and results

```text
rtk cargo test -p warden-service schema
rtk cargo test -p warden-service
rtk cargo clippy -p warden-service --all-targets --all-features -- -D warnings
rtk cargo fmt --all
rtk taplo fmt
rtk cargo fmt --check
rtk cargo clippy --workspace --all-targets --all-features -- -D warnings
rtk cargo test --workspace
rtk cargo clippy --workspace --all-targets -- -D warnings
```

Results:

- focused schema filter: 14 passed;
- `warden-service`: 88 passed across two suites;
- focused and workspace all-feature Clippy: no issues;
- Rustfmt check and Taplo formatting: success;
- workspace: 690 passed, 1599 filtered out, across 43 suites.

The additional literal AGENTS.md Clippy spelling without `--all-features` remains
blocked by the same three pre-existing PostgreSQL test-only `dead_code` diagnostics:
`PostgreSqlQueryExecutor::with_unconfirmed_cleanup`, `CleanupFault::Unconfirmed`, and
`PostgreSqlSchemaInspector::with_cache_for_tests`. `git diff --exit-code --
crates/warden-postgres` returned success, confirming Task 7 did not modify that crate.
No lint was suppressed and no adapter was changed.

## Self-review

- Re-read the complete production module and supporting diff after restoring every
  mutation.
- Confirmed every request resolves by its own connection name, capability is checked
  before any search-port call, and both filter/deadline observations come from the
  selected runtime.
- Confirmed search performs no redaction and describe redacts only defaults/comments.
- Confirmed no audit field, audit call, `ExecutionGate`, or production permit call was
  introduced; the sole permit reference is the negative behavior test.
- Confirmed error `Display` and service `Debug` do not disclose internal driver, port,
  or cancellation state.
- Confirmed no `sqlx`, `sqlparser`, `rmcp`, async-trait, unsafe code, production
  `unwrap`/`expect`, panic shortcut, wildcard security match, or architectural
  dependency change was introduced.
- Confirmed all edits are limited to Task 7's `warden-service` module, test support,
  public export, and this report.

## Deviations and concerns

There are no specification deviations and no unresolved Task 7 implementation
concerns. The only failing requested command is the documented, pre-existing
no-feature PostgreSQL Clippy staging issue above; Task 7 neither changes nor suppresses
it.

## Independent review fix round 1

The independent review approved production but identified three test-strength gaps.
This round changed only `schema.rs`'s test module and this report; no production code,
public API, fixture implementation, adapter, or dependency changed.

Coverage was strengthened as follows:

- search and describe now each independently prove both cancellation-token
  directions: root cancellation reaches the observed inspector child, while
  cancelling that child does not cancel the root;
- search and describe now each hold the runtime's sole `QueryPermit`, complete at
  zero elapsed Tokio time, and assert the exact inspector cardinality tuple;
- search and describe each exercise independent literal matrices for all four current
  `SchemaError` variants, asserting the exact propagated error, literal public code,
  and absence of connection/driver details from public display.

Representative mutations were applied one at a time to production and restored with
`apply_patch` after observing RED:

- cloning the root token in search failed
  `cancelling_the_search_child_does_not_cancel_the_root` (0 passed, 1 failed);
- supplying an unrelated token to describe failed
  `root_cancellation_reaches_the_describe_child_token` (0 passed, 1 failed);
- acquiring a query permit in both paths failed both permit-independence tests with
  `Connection(Busy)` before an inspector call (0 passed, 2 failed);
- mapping every search inspector error to timeout failed the search matrix on its
  first exact-error assertion (0 passed, 1 failed).

Post-restoration GREEN and final gates:

```text
rtk cargo test -p warden-service schema::tests
rtk cargo test -p warden-service
rtk cargo clippy -p warden-service --all-targets --all-features -- -D warnings
rtk cargo fmt --all
rtk taplo fmt
rtk cargo fmt --check
rtk cargo clippy --workspace --all-targets --all-features -- -D warnings
rtk cargo test -p warden-service audit::tests::a_broken_outcome_write_raises_a_sanitized_alarm_without_failing_the_request
rtk cargo test --workspace
```

Results were 17/17 focused schema tests, 92/92 `warden-service` tests, clean focused
and workspace all-feature Clippy, clean Rustfmt/Taplo, and 694 workspace tests passed
across 43 suites (1599 filtered). One earlier workspace execution encountered two
captured tracing events where an unrelated audit test expected one; its shared mutex
then poisoned five subsequent tests. The originating test passed alone immediately,
and a fresh full workspace execution passed all 694 tests. No schema test installs a
tracing subscriber or touches that shared capture state, so no out-of-scope change was
made for the transient isolation failure.

Self-review confirmed every source hunk is under `schema.rs`'s `#[cfg(test)]` module,
all production mutations were restored, the production diff is empty, and the new
expectations remain method-specific and literal. There are no new specification
deviations or unresolved Task 7 concerns in this fix round.
