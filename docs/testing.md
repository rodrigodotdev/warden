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
the server-side deadline on both pools, PostgreSQL's startup options surviving a DSN
that tries to relax them, `default_transaction_read_only` refusing DDL outside any
policy, statement-cache behaviour on both engines, the exact pool defaults under
saturation, and readiness surviving a saturated agent pool. Milestones 7 and 8 add the
query-level rows below.

PostgreSQL's official container image serves no TLS certificate chain. Its M6 test
therefore proves that required TLS refuses a cleartext downgrade, while MySQL's private
CA tests cover certificate verification; a TLS-serving PostgreSQL fixture remains M15
hardening work. Because non-verifying `Required` is development-only, that refusal
case runs in development; staging and production require `VerifyCa` or
`VerifyIdentity`. The PostgreSQL DDL case proves Warden's read-only session, not a
database role's write refusal, which remains M7 privilege-test work.

Coverage uses `cargo llvm-cov --workspace --all-features --no-report --
--test-threads=1`: all features include these container cases, while the serial test
harness avoids intermittent PostgreSQL startup contention under LLVM instrumentation.
The dedicated Docker gate remains parallel, so serial coverage does not mask normal
container-test concurrency.

**MySQL:** connection; schema discovery; safe `SELECT`; parameter binding; read-only
transaction; database user cannot write; Warden rejects writes before execution;
multiple statements rejected; server timeout fires before client timeout; concurrency
limit; row, total-byte, and per-value truncation; `EXPLAIN`; normalization; connection
reuse after errors, timeouts, and cancellation; no session-variable leakage between
requests.

**PostgreSQL:** the same, plus `SET LOCAL statement_timeout`; effects of
`default_transaction_read_only` at connect time; fixed `search_path`; RLS when
configured; `UUID`; `JSONB`; `NUMERIC` precision; arrays; safe cast-suggestion failures
for custom types; data-modifying CTE rejection; and sequence-mutation rejection.

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
