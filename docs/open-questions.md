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

5. **Should the schema cache remain a simple map or become a dedicated crate?** The
   cache is a `HashMap` behind an `RwLock` with a five-minute TTL and a 512-entry
   ceiling, and stays one until profiling says otherwise.

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
    PostgreSQL RLS state is still not exposed in schema metadata; Milestone 9 did not
    change that.

12. **Which license?** This blocks the `deny.toml` license allowlist. Apache-2.0
    provides a patent grant and is common for security infrastructure; AGPL prevents
    closed-source SaaS resale. This is a product decision.

13. **Can `SchemaInspector` filter objects at the source without changing its
    signature?** No — **resolved in Milestone 9 by ADR-0036.** `docs/security.md`
    §5.2 requires the inspector to receive the
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
    filter it back out. The signature now takes `filter: ObjectFilter<'a>`, a `Copy`
    view over `PolicyEngine::check_object` and one request's `PolicyContext`;
    `search_schema` drops a refused relation before the limit is applied and
    `describe_schema` returns `SchemaError::Rejected`.

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

17. **Should `ResultValue::Json` apply the big-integer string rule recursively?**
    `docs/data-model.md` section 8.1, rule 6 quotes an `I64`/`U64` outside ±2^53 as a
    string so a JavaScript MCP client cannot silently round it. `ResultValue::Json`
    does not: its `Serialize` impl hands the driver's `serde_json::Value` straight to
    `serde_json::Value::serialize`. The workspace enables `arbitrary_precision`, so
    Warden preserves every digit of `{"order_id": 9007199254740993}` rather than
    changing it through `f64`, but the value still reaches a JavaScript client as a
    raw JSON number and can suffer the rounding rule 6 exists to prevent. Byte
    accounting already treats a `Json` value
    consistently either way — `json_value_bytes` counts an embedded large integer
    unquoted, matching what actually gets emitted — so this is a semantic gap in the
    precision guarantee, not a budget bug. Fixing it means rewriting the document
    recursively at normalization time to re-quote out-of-range integers, which is a
    `warden-core` decision affecting every adapter, not a MySQL one, so Milestone 7
    left it unfixed and only documented it. Milestone 8's PostgreSQL `JSON` and
    `JSONB` paths inherit the same client-side gap, although real-server regressions
    now prove that Warden itself preserves both integers above `u64` and
    high-precision decimal digits before that boundary.

18. **Should the adapter decode calendar array elements itself?** `warden-postgres`
    decodes `date`, `timestamp` and `timestamptz` from their wire integers with
    checked arithmetic, because `sqlx`'s own decoders hand the value to `time`'s
    panicking `Add` and PostgreSQL's calendar is wider than `time`'s (SPEC section 6,
    invariant 31). `sqlx` decodes *array* elements internally, so that guard cannot
    reach them, and Milestone 8 therefore refuses `DATE[]`, `TIMESTAMP[]` and
    `TIMESTAMPTZ[]` with a `::text` cast suggestion rather than risk the panic.
    Supporting them means decoding the array's binary layout — dimension header,
    element lengths, element bytes — inside the adapter instead of through `Decode for
    Vec<T>`. That is real code with a real fuzzing obligation, in exchange for a column
    type an investigation query rarely selects unformatted. Decide it against measured
    demand, not in advance.

19. **Should a PostgreSQL `time` of `24:00:00` be an error?** PostgreSQL accepts
    `'24:00:00'::time`, and `sqlx` decodes it as `Time::MIDNIGHT + 86_400_000_000`
    microseconds, which `time` wraps to `00:00:00`. No data is corrupted in Warden's
    own code and nothing panics, but the agent is shown a value one day earlier than
    the one stored, which is the kind of silent wrongness the rest of the normalization
    rules exist to prevent. The fix is a bounds check on the wire integer before the
    decode, the same shape as the calendar guard; Milestone 8 left it undone because it
    is a correctness question about a rare value rather than a panic, and folding it
    into an execution milestone would have widened the guard's scope without a
    measurement behind it.

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

20. **Should MySQL's `PlanSummary` carry a row estimate?** Milestone 10 leaves
    `estimated_rows` empty on MySQL. `EXPLAIN FORMAT=JSON` reports
    `rows_examined_per_scan` and `rows_produced_per_join` per table and per join
    step under `query_block`, and states no figure for the statement as a whole:
    a single-table plan has one obvious candidate, a nested loop has one per step,
    and `UNION`, `ordering_operation`, `grouping_operation` and
    `materialized_from_subquery` each change the shape again. Filling the field only
    where the shape is obvious would leave an agent unable to distinguish "this
    engine reports no estimate" from "this plan was too complex to summarize", which
    is worse than a consistently empty field. Deciding otherwise means walking the
    document per shape, with a fuzzing obligation over database-controlled JSON, in
    exchange for a number the full document already contains. Decide it against
    measured demand.
