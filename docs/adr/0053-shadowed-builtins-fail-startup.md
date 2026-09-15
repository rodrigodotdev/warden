# ADR-0053 — A shadowed built-in fails the connection at startup

**Status:** Accepted · 2026-09-15 · **New in Milestone 13.2 · Refines ADR-0029**

## Context

ADR-0029 classifies an unqualified PostgreSQL call by its bare name against the
built-in registry. That is correct only if the call resolves to the built-in. PostgreSQL
resolves an unqualified name across every schema on the `search_path`, considers
candidates of different argument types on an equal footing regardless of path
position, and picks an exact match — so `lower(1)` runs `app.lower(integer)` when that
function exists on the path and the role may execute it, which PostgreSQL grants to
`PUBLIC` by default. `crates/warden-postgres/src/container_tests/identity.rs` measures
this.

Two remedies were rejected. Requiring `pg_catalog.` on every call denies `count(*)`,
`now()` and `sum(x)` — the SQL an agent writes — with a message that names no function
(`unknown_function` is fixed text), so the agent cannot correct itself. Resolving names
against the catalog per query puts I/O and a TOCTOU cache into policy (ADR-0012,
ADR-0023).

## Decision

The premise is proved once, at startup, by the composition root:
`PostgreSqlConnectionPools::verify_function_identity` reads `pg_proc` on the control
pool for functions the role can execute, in schemas on the effective `search_path`,
whose name is in the `SAFE` registry. Any row fails the connection with every offending
`schema.name(arguments)` and the remediation. `warden check` fails the same way. There
is no configuration key to skip it (ADR-0026).

`REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA … FROM PUBLIC` and the matching
`ALTER DEFAULT PRIVILEGES` join the role contract: `warden role` prints them and
`docs/security.md` section 4.2 requires them. They are also what stops a domain
`CHECK` or a user-defined cast from running code, which is why no static cast
allowlist is added.

## Consequences

Analyzer behaviour is unchanged; ordinary unqualified SQL keeps working. A deployment
whose role can execute a shadowing function does not start until the operator revokes
`EXECUTE`, renames the function, or removes its schema from `search_path`. The check
is not repeated per request: a function created after startup by a privileged role is
outside this proof and is documented as such. MySQL needs no check: an unqualified name
there always means the built-in.
