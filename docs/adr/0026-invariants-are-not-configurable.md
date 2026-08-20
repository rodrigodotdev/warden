# ADR-0026 — Invariants have no configuration keys

**Status:** Accepted · 2026-08-19 · **New in v0.3**

## Context

Version 0.2 said that `query` accepts exactly one statement per call and that the
product must not gain bypass flags such as `--allow-write` or `--skip-policy`.

At the same time, its configuration example contained:

```toml
allow_multiple_statements = false
```

A boolean that can become `true` **is** the forbidden bypass flag, only hidden in a
configuration file where it attracts less scrutiny than a command-line option.

## Decision

**If a rule appears in the SPEC section 6 invariant list, it has no corresponding
configuration key.** Remove `allow_multiple_statements` from the configuration model.

Policies remain configurable because they represent legitimate tradeoffs:
`allow_locking_reads` and `allow_unknown_functions` remain, but `warden check` warns
when a `production` profile enables them.

Apply `#[serde(deny_unknown_fields)]` to every configuration struct. Without it, a
misspelled `allow_locking_read` would be silently ignored and fall back to the default,
leaving the operator falsely confident that configuration had been hardened.

## Consequences

The invariant/policy distinction becomes testable: comparing the section 6 list with
the configuration schema is a mechanical check.

Relaxing an invariant requires an ADR and a code change instead of one TOML line,
which is the appropriate cost.
