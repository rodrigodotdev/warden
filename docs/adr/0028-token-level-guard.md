# ADR-0028 — A token-level guard for constructs the parser rejects

**Status:** Accepted · 2026-08-22

## Context

SPEC section 6, invariant 9 denies MySQL file access and output, and
`docs/security.md` section 7.2 requires the analyzer to **detect**
`SELECT ... INTO OUTFILE` and `SELECT ... INTO DUMPFILE`.

sqlparser 0.62 with `MySqlDialect` cannot parse either form. Both are therefore
already denied, as `query_parse_error`, but the analyzer produces no evidence: the
audit record reads `unknown_construct`, and `RiskFlag::FileOutput` — which
`RiskEvidencePolicy` maps to `DenyCode::WriteStatement` — has no producer at all.

The denial also depends on a parser limitation rather than on a rule. A future
sqlparser that learns the syntax would move the statement from "parse error" to "an
ordinary `SELECT`", and nothing in the AST rules would object.

## Decision

`warden-mysql` runs a token-level scan alongside parsing. It tokenizes with the same
dialect and reports `RiskFlag::FileOutput` when an unquoted `INTO` word is
immediately followed by an unquoted `OUTFILE` or `DUMPFILE` word.

The scan runs on tokens, never on the raw string: a string literal and a comment
produce no word tokens, so neither can trip it.

When the guard fires and the grammar also rejected the statement, the analyzer
returns an analysis rather than an `AnalyzeError` — root kind `Unknown`, the guard's
flags, and `UnknownConstruct` — so the attempt is audited with the risk it actually
carries.

The guard covers these two constructs only. `LOCK IN SHARE MODE` also fails to
parse, but `FOR UPDATE` and `FOR SHARE` parse into `Query::locks`, so
`RiskFlag::LockingRead` already has an AST path, a test, and a corpus row that fails
loudly if an upgrade changes the behavior.

## Consequences

An attempted file write is audited as `file_output` rather than as an unclassifiable
statement, and the denial survives a parser upgrade.

The scan is a second, independent reading of the input, which is a small cost — one
tokenizer pass over at most 64 KiB — and a surface that must stay small. Adding an
entry requires showing that the construct has no AST path, not merely that a token
pattern is convenient.
