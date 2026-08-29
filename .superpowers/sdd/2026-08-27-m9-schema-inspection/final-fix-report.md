# Milestone 9 final fix report

Date: 2026-08-29  
Branch: `feat/m9-schema-inspection`  
Baseline SHA: `a3e14399a218a5cd3e5bec1b7559665ff78b6107`  
Final fix commit: the single commit containing this report. Its exact SHA is
reported in the handoff because a Git commit cannot embed its own hash without
changing that hash.

## Outcome

The four confirmed final-review findings are fixed as one security and bounds
hardening wave:

1. Foreign keys whose targets are denied by `ObjectFilter` are silently omitted
   from every cold or warm response and mark the source table as truncated. The
   cache remains canonical and policy-unfiltered. PostgreSQL additionally
   requires target-schema `USAGE` and target-table `SELECT`; a name-free sentinel
   reports partial metadata without revealing the hidden target.
2. Both adapters propagate the per-relation 64-column search-index bound into
   `SchemaSearchResult.truncated`, including when only an omitted column matches.
3. Catalog defaults and comments are bounded at 64 KiB per value and 256 KiB per
   cached table and per complete response. Core performs deterministic UTF-8-safe
   byte truncation; static SQL applies an earlier character cap to avoid needless
   materialization. This is bounding, not redaction, preserving the Milestone 9
   ruling that these fields remain unredacted until Milestone 11.
4. Cache expiry uses `Instant::checked_add`. An overflowing TTL refuses insertion
   because caching is only an optimization, avoiding both panic and stale state.

## RED evidence

- FK response filtering: the new adapter unit regressions failed to compile with
  unresolved `filter_foreign_keys`; the PostgreSQL SQL assertion failed before
  target privilege predicates existed. The MySQL cold-cache Docker regression
  then failed because the denied target FK was still returned. Equivalent
  PostgreSQL cold/warm and revoked-target regressions failed before response and
  SQL wiring.
- Search-index truncation: updated unit tests failed with a tuple/`Vec` type
  mismatch against the old `group_index` API. A temporary mutation removing the
  inspector's truncation combination made both engines' wide-catalog Docker
  regressions fail, proving the integration assertion detects the omission.
- Metadata byte bounds: focused tests initially failed with missing
  `MAX_SCHEMA_VALUE_BYTES`, `MAX_SCHEMA_DESCRIPTION_BYTES`, and
  `SchemaMetadataBudget`, plus the deliberately changed catalog mapping
  signature.
- TTL overflow: the `Duration::MAX` regression panicked at `now + self.ttl`
  before `checked_add` was introduced.

## Files changed

- `crates/warden-core/src/schema.rs`: documented byte constants, UTF-8-safe
  metadata budget, truncation semantics, and core regressions.
- `crates/warden-core/src/schema/cache.rs`: checked TTL expiry and overflow
  regression.
- `crates/warden-mysql/src/catalog.rs`: search-index partiality, static SQL text
  pre-cap, bounded mapping, and unit regressions.
- `crates/warden-mysql/src/inspector.rs`: partial search propagation, per-response
  FK filtering, and per-table/per-response metadata budgets.
- `crates/warden-mysql/src/container_tests/inspection.rs`: denied-target cold/warm
  cache and wide-index Docker regressions.
- `crates/warden-postgres/src/catalog.rs`: search-index partiality, static SQL text
  pre-cap, target privilege checks with name-free partiality sentinel, and unit
  regressions.
- `crates/warden-postgres/src/inspector.rs`: partial search propagation,
  per-response FK filtering, sentinel handling, and metadata budgets.
- `crates/warden-postgres/src/container_tests/inspection.rs`: denied-target
  cold/warm cache, revoked target privilege, and wide-index Docker regressions.
- `docs/architecture.md`, `docs/data-model.md`, `docs/security.md`: cache/filter,
  privilege, truncation, and byte-bound invariants.
- This report.

## Architectural choices

- Raw table cache entries stay independent of request policy. FK target policy is
  applied only to a cloned response, so alternating filters cannot poison or
  broaden later cache hits.
- The PostgreSQL hidden-target signal contains no constraint, schema, table, or
  column names. A denied FK is never converted to `SchemaError::Rejected`.
- Text is bounded once while building a cacheable table and again with one shared
  budget across a response. This gives deterministic limits without storing
  policy-specific or request-order-specific cache entries.
- MySQL relies on `information_schema` for database-role visibility and still
  applies `ObjectFilter` to every FK target. PostgreSQL repeats role privilege
  checks for the target because `pg_catalog` itself is broadly readable.
- Existing static SQL, control-pool routing, row/list limits, deadlines,
  cancellation, and public port surfaces are unchanged. No dependency was added.

## Tests and verification

Focused GREEN runs during TDD:

- `rtk cargo test -p warden-core metadata_budget`: 2 passed.
- `rtk cargo test -p warden-core schema::cache::tests::a_ttl_that_overflows_instant_refuses_the_cache_entry_without_panicking`: 1 passed.
- `rtk cargo test -p warden-mysql -p warden-postgres --lib foreign_key`: 5 passed.
- Both adapters' focused `group_index` regressions: 2 passed.
- Both catalog unit suites after metadata bounding: 28 passed.
- `rtk cargo test -p warden-core -p warden-mysql -p warden-postgres --lib`: 337 passed.
- MySQL focused Docker FK policy, wide-catalog, and ordinary description tests:
  passed.
- PostgreSQL focused Docker FK policy, revoked target privilege, wide-catalog,
  and ordinary description tests: passed.

Fresh final gates:

- `rtk cargo fmt --all --check`: passed.
- `rtk taplo fmt --check`: passed (15 TOML files checked).
- `rtk cargo clippy --workspace --all-targets --all-features -- -D warnings`:
  passed with no issues.
- `rtk cargo test --workspace`: 560 passed across 43 suites; 1,417 filtered out.
- `rtk cargo test -p warden-mysql --features docker -- --nocapture --test-threads=4`:
  172 passed across 4 suites in 166.01 s.
- `rtk cargo test -p warden-postgres --features docker -- --nocapture --test-threads=4`:
  210 passed across 17 suites in 43.95 s.
- `rtk git diff --check`: passed.

## Deviations and concerns

- Intentional deviations from `SPEC.md`: none.
- Existing Milestone 9 rulings are preserved, including unredacted catalog
  defaults/comments, canonical policy-unfiltered caches, and PostgreSQL name
  resolution behavior.
- The PostgreSQL name-free sentinel is an internal static-SQL implementation
  detail; it does not alter a public model or reveal the hidden target.
- Remaining concern: none known after the focused, workspace, Clippy, formatting,
  MySQL Docker, and PostgreSQL Docker gates above.
