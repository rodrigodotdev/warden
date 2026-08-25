# Open questions and future work

## 1. Resolved in v0.3

These remain listed because they were open in v0.2 and someone may search for them.

| v0.2 question | Resolution |
|---|---|
| 5 — best MySQL server-side timeout strategy without rewriting SQL | `SET SESSION MAX_EXECUTION_TIME` through `after_connect`—ADR-0024 |
| 13 — do views automatically inherit table policy? | No. `GRANT` is the read boundary; the allowlist reduces attack surface—ADR-0023 |
| 1 — does `AuthorizedQuery` live in policy or core? | In `warden-policy` with the `AllowDecision` token—ADR-0010 |
| 14 (permit half) — does anything besides convention stop an adapter from bypassing the query permit? | No longer convention: `execute_read_only` and `explain` both take `&QueryPermit` as a parameter—ADR-0032 |

## 2. Still open

Resolve these from implementation evidence, not speculation. Unless evidence shows
otherwise, none blocks M0–M5.

1. **Which exact subset of `sqlparser` AST variants requires recursive inspection per
   backend?** The corpus will answer. The `visitor` feature, if adopted, makes this
   less critical by making traversal exhaustive by construction.

2. **How broad should the safe-function registry be?** Too narrow creates false
   positives and frustrates the agent; too broad weakens default deny. Calibrate with
   real use.

3. **Should functions use an explicit allowlist or a category table derived from a
   reviewed source?** The latter scales better but is harder to audit. Decide after
   measuring the explicit allowlist.

4. **Which custom PostgreSQL types should normalize automatically rather than require
   explicit casts?** Enums are the most likely candidate. Measure against real
   databases.

5. **Should the schema cache remain a simple map or become a dedicated crate?** Only
   after profiling; do not anticipate.

6. **Should normalized SQL enter audits after literal-redaction fuzzing?** It may
   materially improve auditability but risks creating a second sensitive-data store.
   The answer depends on proven redaction quality.

7. **Should a future adapter use PostgreSQL's real parser (`libpg_query`)?** The seam
   exists by design (ADR-0007). It is justified if the corpus shows a significant
   false-positive parse rate.

8. **For the first HTTP release, does remote authentication terminate in Warden or a
   trusted reverse proxy?** A proxy is simpler and common; in-process termination
   provides more faithful principal context. Decide in M14.

9. **Typed MCP parameters before 1.0?** The current `ParameterValue` set is
   deliberately small. Expand only for concrete demand.

10. **Is MariaDB a separate dialect or treated as MySQL?** Syntax and function
    differences exist. Treating it as MySQL is convenient and risky; ADR-0011 default
    deny limits but does not eliminate the risk.

11. **Should PostgreSQL RLS state appear in schema metadata?** Exposure helps the
    agent understand partial results but also reveals security-policy structure.

12. **Which license?** This blocks the `deny.toml` license allowlist. Apache-2.0
    provides a patent grant and is common for security infrastructure; AGPL prevents
    closed-source SaaS resale. This is a product decision.

13. **Can `SchemaInspector` filter objects at the source without changing its
    signature?** No. `docs/security.md` §5.2 requires the inspector to receive the
    allowed set and filter at the source rather than return the whole catalog for a
    service to filter afterward, but `search_schema`/`describe_schema`
    (`crates/warden-ports/src/inspector.rs`) take only a request, a deadline, and a
    cancellation token — no allowed set and no `RequestContext`. `SchemaError::Rejected`
    carries a `PolicyRejection`, whose constructor is reachable only from
    `PolicyEngine::authorize` or `check_object`, and both need per-request identity
    that never reaches an adapter holding only a startup `Arc<PolicyEngine>`.
    `describe_schema` could call `check_object` per table before dispatch, but that is
    the "service filters afterward" shape §5.2 rejects, and it leaves
    `SchemaError::Rejected` unproducible by any adapter; `search_schema` cannot be
    salvaged that way at all, since a denied match the adapter already found would
    consume an allowed match's slot under the request's `limit` before anything could
    filter it back out. The fix is a signature change — add `context: &'a
    RequestContext` or an explicit allowed-set parameter to both methods — and
    Milestone 9 is expected to make it, so it lands there as an accepted change
    rather than a surprise.

14. **Does anything besides convention stop an adapter from bypassing the audit
    attempt?** No. ADR-0022 requires the attempt to be recorded before the
    concurrency permit is acquired, and that ordering lives only in a doc comment:
    nothing in the types stops a caller from acquiring a permit and executing before
    `AuditSink::record_attempt` has run, or from never calling it at all. The permit
    half of this question is resolved — ADR-0032 makes `&QueryPermit` a parameter of
    `execute_read_only` and `explain`, so a missing permit is now a compile error —
    but ADR-0032 explicitly does not order the permit against the audit attempt; it
    only proves a permit exists. Milestone 11's service layer is expected to make the
    attempt-before-execution ordering structural rather than left to the caller.

15. **Should the session time zone be pinned?** MySQL's `TIMESTAMP` is currently
    emitted in whatever zone the server session uses, unpinned. Setting
    `time_zone = '+00:00'` in `after_connect` would make it deterministic, but it is a
    real behavioral change — it changes what an agent's own `NOW()` query returns, not
    only how a stored value is displayed — so Milestone 7 left it undone rather than
    fold it into an execution milestone. It needs its own decision and its own ADR.

16. **Should `ResultColumn` carry a fractional-second precision field?** MySQL's
    `format_timestamp` and `format_time` (`crates/warden-mysql/src/normalize.rs`) omit
    the `.ffffff` suffix when microseconds are zero and always render exactly six
    digits when non-zero, so a `DATETIME(3)` column reads back as `09:07:03` where
    mysql-client prints `09:07:03.000`. No data is corrupted — every digit shown is a
    true stored microsecond and the represented instant is identical — but the
    column's declared precision is lost in the rendering. Reproducing it needs a
    fractional-precision field on `ResultColumn`, a `warden-core` model change
    Milestone 8 would inherit, and the value is available only through `describe`,
    which is the same path already rejected for `nullable`.

## 3. Future work deliberately outside v0.x

### Adapters

MariaDB, ClickHouse, SQL Server, Snowflake, and SQLite.

Each adapter provides its own dialect analyzer, executor, schema inspector, explainer,
normalizer, and capabilities. **Do not force any of them into MySQL or PostgreSQL
semantics.**

### Policy capabilities

OPA/Rego adapter; per-principal table rules; organizational policies; access windows;
query budgets; per-fingerprint rate limits; approval flows; per-tool policies.

**Per-principal concurrency limits** deserve earlier attention than the rest. Current
limits are per connection; in a multi-principal HTTP deployment, one principal can
consume everyone else's budget.

### Schema intelligence

Human table descriptions, relationship graphs, search weights, cached cardinality,
and optional semantic embeddings.

**Schema intelligence remains separate from SQL authorization.**

### Query cost control

Estimated rows from `EXPLAIN`; cost baselines; historical duration by fingerprint;
per-connection thresholds; denial of known pathological plans.

```text
analyze -> static policy -> non-executing EXPLAIN
        -> estimated-cost evaluation -> allow/deny
```

**Do not assume costs are comparable across engines.** Units are connection- and
backend-specific.

### Secret providers

Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and operating-system
keychains. Environment variables and files remain adequate for local development.

### Administration surface

If Warden gains an administrative API or UI, keep it separate from agent query tools,
with separate authorization scopes. By default, **an AI tool call must never change
production security policy.**

### Streaming and export

Version 0.x returns a bounded, buffered `ResultSet`. MCP streaming and export are
separate work with their own limit model.

### Removing `warden-tracer`

`crates/warden-tracer` is a disposable Milestone 0.5 tracer bullet. It validates rmcp
3.x, SQLx 0.9, Testcontainers, and TLS before M6–M12 depend on those APIs. Remove it at
the end of Milestone 12, once `warden-mcp`, `warden-mysql`, and `warden-postgres` cover
the same ground using the real SPEC boundaries.

`tests/architecture.rs` forces this decision through `EXPECTED_MEMBERS`: removing the
crate without removing the list entry breaks the test. Also remove the `test:docker`
mise task unless it already points to adapter integration tests.
