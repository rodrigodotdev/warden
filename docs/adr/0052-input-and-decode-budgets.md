# ADR-0052 — Input and decode budgets are separate from the response budget

**Status:** Accepted · 2026-09-14 · **New in Milestone 13.1**

## Context

ADR-0047 bounds what leaves Warden (`max_value_bytes`, `max_result_bytes`). Three
inputs had no bound of their own: a bound parameter (`InputLimits` counted parameters
but not their size), an MCP frame (rmcp 3.2.0 reads a line into a growing `Vec<u8>`
until `\n`, `transport/async_rw.rs:137`), and a compound PostgreSQL value (`json`,
`jsonb`, arrays), which SQLx decodes into `serde_json::Value` or `Vec<Option<T>>`
before the normalizer could measure it.

## Decision

Three independent budgets, all constants, none configurable (ADR-0026):

- **Parameters:** 64 KiB per parameter and 256 KiB for all parameters, measured as
  `ParameterValue::input_bytes` (UTF-8 bytes of text, 8 per number, 1 per boolean, 0
  per null). Checked by `QueryRequest::new` before parsing; reported as
  `query_too_large`.
- **Frame:** 1 MiB per newline-delimited MCP frame, counted by an `AsyncRead` wrapper
  ahead of rmcp's reader. Exceeding it is `io::ErrorKind::InvalidData`; rmcp stops
  reading and the session ends. No error is correlated to a frame that was never
  decoded, and no byte of it is logged.
- **Raw decode:** before decoding a compound PostgreSQL value, its raw wire size must
  fit `min(max_value_bytes × factor + 64, 16 MiB)`, with factor 2 for `json`/`jsonb`
  and 16 for arrays. Exceeding it is `ResultBuildError::ValueTooLarge` carrying the
  raw budget as `limit`. The `ResultBuilder` remains the authority on normalized bytes.

## Consequences

Inputs previously accepted are refused: a parameter over 64 KiB, a frame over 1 MiB,
a `json` value whose raw text is more than twice `max_value_bytes` even if whitespace
made it so. None of these budgets claims an absolute memory ceiling: the driver still
materializes a row before Warden sees it, and the frame budget is per line, not per
session. A parameter budget is not a guarantee that its JSON encoding fits one frame:
escaping can expand a legal 256 KiB of control characters past 1 MiB on the wire, and
the frame cap then ends the session rather than answering `query_too_large`.
