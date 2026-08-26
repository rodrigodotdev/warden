# ADR-0035 — PostgreSQL parameter typing

**Status:** Accepted · 2026-08-25 · **New in Milestone 8**

## Context

`warden_core::parameter::ParameterValue` is deliberately small: `Null`, `Bool`,
`I64`, `U64`, `F64`, `String` (`docs/data-model.md` section 3). Two of those variants
have no obvious PostgreSQL binding.

`U64` is not an edge case. `ParameterValue`'s hand-written deserializer routes every
non-negative JSON integer through `visit_u64`, so `{"parameters": [42]}` arrives as
`U64(42)` — and PostgreSQL has no unsigned integer type at all. `sqlx-postgres`
implements `Encode<Postgres>` for `i8`, `i16`, `i32` and `i64` and for no unsigned
type, so there is nothing to bind `U64` to directly.

`Null` carries no type, and PostgreSQL's `Parse` message declares a type OID for
every parameter. Some type has to be chosen.

## Decision

**`U64` binds as `int8` when `i64::try_from` succeeds, and as `numeric` otherwise.**
Every value up to `i64::MAX` is exact as an `int8` and compares against `int2`,
`int4` and `int8` columns through PostgreSQL's own implicit numeric promotion. Above
that, `numeric` is the only PostgreSQL type that holds the value without loss, and
`sqlx`'s mandatory `bigdecimal` feature (`docs/operations.md` section 2.2) already
provides the encoder.

**`Null` binds as a `text` NULL.** This is consistent with the rule
`docs/data-model.md` section 3 already states for PostgreSQL: callers cast
explicitly, as in `WHERE id = $1::uuid`. A NULL compared against a non-text column
needs the same explicit cast every non-NULL parameter of that shape needs.

## Consequences

Both decisions are visible to the agent and neither is silent. A `U64` above
`i64::MAX` reaches the server as `numeric`, so `WHERE id = $1` against a `bigint`
column resolves through numeric comparison rather than integer comparison — correct,
and marginally slower on an index the planner can no longer use directly. An agent
that needs the index writes `WHERE id = $1::bigint`, which is the same explicit-cast
advice this document already gives.

Warden does **not** widen `ParameterValue`. Typed MCP parameters remain
`docs/open-questions.md` section 2, item 9: expand the set for concrete demand, not
to avoid a cast.

Nothing here applies to MySQL, whose driver encodes `u64` natively as an unsigned
`BIGINT` and whose type system is permissive about a `text` NULL.
