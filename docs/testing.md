# Test strategy

Testing is part of the security architecture, not a later phase.

```text
unit -> parser corpus -> policy -> adapter integration
     -> database privileges -> MCP E2E -> fuzz -> load/concurrency
     -> security regression
```

## 1. Unit tests without a database

Cover dialect parsing, `ConnectionName` validation, result-byte accounting, redaction,
execution-limit validation, error mapping, policy-input construction, security-state
constructors, schema-search ranking, rejection of unrepresentable JSON numbers, and
array-depth limits.

Section 1's unit rows now include schema-search ranking, which
`warden_core::schema::search` covers without a database, and cache expiry, which takes
the current time as a parameter rather than sleeping.
`MatchReason::Description` remains unproduced because configured human descriptions
are deferred schema-intelligence work.

Milestone 11 adds these no-database unit rows:

| Area | Evidence |
|---|---|
| Registry | resolution, missing names, duplicate and empty startup rejection, and deterministic sorted listing |
| Redaction | ASCII case-insensitive wildcard/qualified matching, both strategies, all three response shapes, and result-byte recomputation |
| Request budget | client-deadline selection, aggregate arithmetic, and saturating overflow behavior |
| Auditing | bounded writes, fail-closed attempts, fail-open outcomes, and the `NotStarted` distinction |
| Execution gate | attempt-before-permit ordering, same-runtime dispatch, by-value permit release, and the exclusive AST/token-aware call-site guard |

## 2. Policy

Use synthetic `QueryAnalysis`. Test each policy separately **and** composed in the
engine.

Required properties:

- any denial wins;
- **all** denials are collected, not only the first;
- unknown `StatementKind`, `FunctionClassification`, and `RiskFlag` variants are
  denied, with an explicit test for each;
- client-visible `DenyCode` never contains a query identifier or policy configuration.

## 3. Parser corpus

Use easy-to-review declarative fixtures:

```text
sql
expected_parse
expected_root_kind
expected_nested_kinds
expected_tables
expected_functions
expected_risks
default_policy
```

**Do not hide security expectations inside one large procedural test.**

### 3.1 MySQL

Basic `SELECT`; `JOIN`; subqueries; CTEs; `UNION`; comments; optimizer hints; quoted
identifiers; strings containing SQL keywords; semicolons inside literals; multiple
statements; `INSERT`/`UPDATE`/`DELETE`; DDL; locking `SELECT`; `OUTFILE`/`DUMPFILE`;
`SLEEP`; `BENCHMARK`; `GET_LOCK`; `LOAD_FILE`; variable assignment; malformed SQL;
unknown functions; and identifier case variation.

### 3.2 PostgreSQL

Basic `SELECT`; `JOIN`; CTEs; recursive CTEs; `UNION`; quoted identifiers; comments;
dollar-quoted strings; multiple statements; DML; DDL; data-modifying CTEs;
`SELECT INTO`; `FOR UPDATE`/`FOR SHARE`; `COPY`; `CALL`; `pg_sleep`; advisory locks;
`nextval`/`setval`; unknown functions; malformed SQL; and unquoted mixed-case
identifiers to test folding.

### 3.3 Upgrade rule

Upgrading `sqlparser` requires running the complete corpus **and** reviewing new AST
variants. This process step is mandatory.

## 4. Adapter integration with Testcontainers

Initial images are MySQL 8.4 and a currently supported PostgreSQL release.
Compatibility matrices can grow later.

Milestone 6 covers the connection itself: TLS handshake and private-CA verification,
the server-side deadline on both pools, PostgreSQL's startup options reaching the
server while a DSN that would relax them is refused, `default_transaction_read_only` refusing DDL outside any
policy, statement-cache behaviour on both engines, the exact pool defaults under
saturation, and readiness surviving a saturated agent pool. Milestone 7 adds MySQL's
query-level rows below—read-only transactions, deadlines, cancellation, row/byte
truncation, an oversized `max_rows + 1` sentinel preserving the valid bounded rows,
concurrency, and privilege rejection, each proven against a real container.
**Milestone 8 added PostgreSQL's equivalent rows**, each proven against a real
PostgreSQL 17 container: a read-only transaction refusing tested `INSERT`,
`UPDATE`, `DELETE`, `CREATE TABLE`, a data-modifying CTE, `SELECT INTO`, `nextval` and
`setval`; `SET LOCAL statement_timeout` reaching the transaction and only ever
tightening it; the pinned `search_path` resolving the query; parameter binding,
including an unsigned value above `i64::MAX`; the fixture's supported scalar families
(`bool`, integers, text/varchar, numeric, floats, JSON/JSONB, UUID, calendar/time, and
`bytea`) plus `text[]`, `integer[]`, `numeric[]`, and `uuid[]` round-tripping; tested
unrepresentable values failing with a cast suggestion rather than a panic; `JSON` and
`JSONB` preserving an integer above `u64` and a high-precision decimal through final
serialization; a `max_rows + 1` unrepresentable sentinel yielding the valid bounded
rows plus `truncated: true`; row and byte truncation plus a mid-stream per-value failure
each cancelling the orphaned query; the server deadline firing before the client one;
explicit cancellation reaching the server; connection reuse after a timeout, a
cancellation and a database error; no session state surviving a request; the
concurrency bound; and RLS restricting what the role can read.

**Milestone 9 added the schema rows on both engines.** MySQL, against a real 8.4
container: a described table's columns, types, nullability, defaults, comments,
composite primary key, foreign key and indexes; an unqualified selector resolving
through the default database; a view keeping its kind; a relation the role cannot see
being skipped rather than reported; deterministic ranking; the response limit and its
`truncated` flag; a denied table invisible to search and refused by describe; an
unqualified selector refused after it resolves into a denied schema; a cache hit
answering with pre-mutation metadata while the table remains resolvable and an expired
entry refetching; the deadline and the cancellation token each stopping a catalog
read; and a describe answering while `agent_pool` is saturated, which is what
ADR-0025's second pool is for.

PostgreSQL, against a real 17 container: the same rows, plus a materialized view
keeping its own kind, an expression index reported as a partial description rather
than as an invented column name, a quoted mixed-case relation that a lowercase deny
rule does not reach, a relation whose `SELECT` was revoked being invisible to both
tools, and no session state surviving a catalog read.

The mixed-case PostgreSQL distinction is proven by search over resolved catalog
identifiers. Plain-text describe remains fail-closed because `TableSelector` carries
no quoting marker.

PostgreSQL foreign-key metadata uses
`ROWS FROM (pg_catalog.unnest(con.conkey), pg_catalog.unnest(con.confkey)) WITH
ORDINALITY` for valid positional pairing.

PostgreSQL's official container image serves no TLS certificate chain. Its M6 test
therefore proves that required TLS refuses a cleartext downgrade, while MySQL's private
CA tests cover certificate verification; a TLS-serving PostgreSQL fixture remains M15
hardening work. Because non-verifying `Required` is development-only, that refusal
case runs in development; staging and production require `VerifyCa` or
`VerifyIdentity`. The Milestone 6 PostgreSQL DDL case proves Warden's read-only session,
not a database role's write refusal. Milestone 8 adds the second: because
`default_transaction_read_only` would otherwise mask the privilege refusal with
`25006`, the privilege tests turn that session default off on one pinned connection so
the `GRANT` is the only barrier left, and then observe `42501`
`insufficient_privilege` for three DML statements, four DDL statements (including
temporary-table creation), `nextval`, `setval`, and the explicitly revoked
`pg_sleep(double precision)` function. The Task 5 analyzer/policy matrix separately
covers those classes plus a data-modifying CTE and `SELECT INTO` before execution.

Fixture administration uses one scoped `BEGIN READ WRITE` transaction on a held
`control_pool` connection, then verifies the returned physical session is still
read-only. It does not change `default_transaction_read_only` at session scope.

**Milestone 10 added the plan rows on both engines.** On MySQL 8.4 and PostgreSQL 17:
a bound `SELECT` producing the engine's own structured document; a statement whose
execution would take three seconds — `SLEEP(3)`, `pg_sleep(3)` — returning a plan in
milliseconds, which is the measurement behind "EXPLAIN does not execute"; twenty
consecutive plans leaving no prepared statement on either engine and no escaped
`statement_timeout` on PostgreSQL; a cancelled token and an elapsed deadline each
stopping the call with the right variant; a missing relation failing without the
driver's message reaching `Display`; and the connection still serving after a failed
plan.

PostgreSQL adds three of its own: the root node's `Plan Rows` reaching
`summary.estimated_rows` while MySQL's stays empty; the returned document carrying
none of `Actual Rows`, `Actual Total Time` or `Actual Loops`, which exist only in an
executed plan and are therefore the direct server-side proof that no `ANALYZE` was
sent; and a user-defined enum in the inner statement's projection still planning
through an unnamed statement, which is the measurement `bind::plan_statement` rests
on.

The prefix verification itself needs no database and is covered in section 1: both
`ANALYZE` spellings, a decorated or differently-formatted prefix, a second statement
after the prefix, a different inner statement, and an unparseable string are each
refused, while a plain `SELECT`, a read-only CTE and a statement ending in a line
comment each verify. A separate unit test proves that `EXPLAIN` submitted as agent
SQL is denied by the analyzer and the policy engine before any explainer sees it
(ADR-0020).

**Milestone 11 added application-service coverage against fake ports.** The tests
prove registry selection; analyze/authorize ordering and use of the runtime's own
limits; fail-closed attempt writes and fail-open outcome writes; permit ordering and
release for query and explain; exact audit outcomes for denial, timeout,
cancellation, failure and `server_busy`; child cancellation-token propagation;
capability-driven schema search; object filters and deadlines reaching inspectors;
redaction of normalized results, schema descriptions and plans; byte recomputation;
and sanitized typed error mappings. No database, MCP handler, real audit sink, span,
or panic-containment claim is made by these fakes.

**A read-only transaction does not refuse to plan a write, and the tests say so.**
`EXPLAIN (FORMAT JSON) INSERT ...` succeeds inside `BEGIN READ ONLY` on PostgreSQL,
because planning writes nothing. The barrier is `ReadOnlyRootStatementPolicy`, and
the test asserts the rejection there rather than pretending the transaction is doing
the work.

Coverage uses `cargo llvm-cov --workspace --all-features --no-report --
--test-threads=1`: all features include these container cases, while the serial test
harness avoids intermittent PostgreSQL startup contention under LLVM instrumentation.
The dedicated Docker gate (`docs/operations.md` section 12.2) is a separate CI job
from coverage and does not inherit that `--test-threads=1`, so serial coverage does
not mask normal container-test concurrency there.

**Milestone 7 measured a limit on that job's own concurrency.** `warden-mysql`'s
`docker`-gated unit tests each start their own MySQL testcontainer; run at Rust's
default test-thread count (`std::thread::available_parallelism()`, not unbounded),
that many simultaneous containers still exhaust Docker and host resources on a
standard CI runner and produce spurious `PoolTimedOut` failures, not a defect in the
tests themselves. This is host capacity, not test isolation, so the fix belongs in how
the job invokes `cargo test`, not as a per-test workaround: the dedicated Docker job
passes `--test-threads=4`, which removed the contention when measured.

The PostgreSQL deadline/cancellation tests do not compare the whole executor call with
a query deadline. The call can legitimately continue through separately bounded
cancellation, rollback, and statement deallocation. Instead, each query is first
observed active in `pg_stat_activity`; the server-deadline marker must disappear before
the client deadline, and explicit-cancellation markers must disappear under the
trigger's own absolute two-second deadline while cleanup runs concurrently. The test
then awaits the executor under its aggregate cleanup budget. This split replaced an
invalid whole-call timing assertion that could fail during legitimate cleanup and
could not identify which deadline ended the query.

**MySQL:** connection; schema discovery; safe `SELECT`; parameter binding; read-only
transaction; database user cannot write; Warden rejects writes before execution;
multiple statements rejected; server timeout fires before client timeout; concurrency
limit; row-sentinel precedence; row, total-byte, and per-value truncation; `EXPLAIN`;
normalization; connection reuse after errors, timeouts, and cancellation; no
session-variable leakage between requests.

**PostgreSQL:** the same, plus `SET LOCAL statement_timeout`; effects of
`default_transaction_read_only` at connect time; fixed `search_path`; RLS when
configured; `UUID`; `JSONB`; `NUMERIC` precision; arrays; safe cast-suggestion failures
for custom types; exact large-number digits in `JSON` and `JSONB`; row-sentinel
precedence; data-modifying CTE rejection; and sequence-mutation rejection.

## 5. Database privileges

This is the most important category and the one most projects omit.

**Do not test only that application policy rejects writes.** Directly attempt a write
with Warden's database account inside integration fixtures and verify that the
database rejects it.

This validates defense in depth instead of assuming it.

## 6. MCP E2E

Start Warden over stdio and test initialization, tool discovery,
`list_connections`, `search_schema`, `describe_schema`, `query`, `explain`, denied
query responses, sanitized errors, **protocol-only stdout**, and tool-schema snapshots.

**Shipped in Milestone 12, across two suites.**
`crates/warden-mcp/tests/protocol.rs` drives the handshake and all five tools —
`search_schema` and `describe_schema` included — over a real duplex transport against fake
ports; it asserts tool discovery, the refusal of an unimplemented version with the
supported list, a denial arriving as a readable error result, and the ADR-0040
counts-not-values result shape. `tests/mcp_database.rs` drives the real binary over stdio
against MySQL and PostgreSQL containers, where
`an_agent_can_find_a_table_describe_it_query_it_and_plan_it` runs `search_schema` and
`describe_schema` against real catalogs before querying and planning what they found, and
where a real driver error is shown to reach the agent as a code and nothing else,
protocol-only stdout is measured on a real process, and the database role itself is shown
to refuse a write with every Warden layer removed. Tool-schema snapshots live in
`crates/warden-mcp/tests/tool_schema.rs`, against
`crates/warden-mcp/tests/snapshots/tools.json`.

Once Streamable HTTP exists, test protocol negotiation, authorization, unauthenticated
request rejection, principal propagation, concurrent requests, shutdown, malformed
messages, and request-size limits.

## 7. Fuzzing

Targets: MySQL analyzer, PostgreSQL analyzer, result-normalization helpers, and the
redaction matcher.

Invariants:

- arbitrary bytes and strings **do not terminate the process**;
- Warden code has no undefined behavior;
- parse failures produce safe errors;
- analysis never returns an empty or invalid "safe" state for an unknown statement.

Every security-relevant parser bug becomes a permanent regression fixture.

## 8. Property testing

Optional for redaction invariants, result-size accounting, `ConnectionName`
validation, policy monotonicity, and normalization helpers.

Do not add `proptest` before a concrete property test exists.

## 9. Concurrency

Verify that `max_concurrent_queries = N` never produces more than N active executions
per connection. Test cancellation while waiting for a permit. Verify that
`max_queue_wait` returns `server_busy` instead of waiting indefinitely.

## 10. Load

Measure memory under maximum-sized results, many simultaneous denied queries, heavy
schema reads, pool pressure, cancellation behavior, slow and unavailable databases,
and pool exhaustion under repeated timeouts.

**The performance goal is predictability, not a benchmark score.**
