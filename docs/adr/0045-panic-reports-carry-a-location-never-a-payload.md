# ADR-0045 — Panic reports carry a location, never a payload

**Status:** Accepted · 2026-09-05 · **New in Milestone 13**

## Context

Warden's operator logs go to stderr. Rust's default panic hook also writes to stderr,
but includes the panic payload. That payload is whatever the panicking expression
formatted: an `expect` that includes a row value can therefore disclose data even when
the request is contained and becomes `internal_error`.

## Decision

Install a process-level panic hook after the tracing subscriber. Its report records the
source location, panicking thread name, and payload shape (`&str`, `String`, or
`other`). It classifies the shape with `Any::is` and never downcasts to or otherwise
reads the payload.

The hook logs a backtrace only when `Backtrace::capture` reports that the runtime
captured one. `RUST_BACKTRACE` is therefore the operator-controlled diagnostic switch.
The hook writes through `tracing` and consequently uses the stderr subscriber; stdout
remains reserved for MCP.

## Consequences

A panic is diagnosable by code position and execution context rather than by its
message. Losing that message is a deliberate loss of convenience because it can contain
production data. Operators who need more code-level context can enable
`RUST_BACKTRACE`; the resulting backtrace contains symbols and addresses, not a value
the panicking expression formatted into its payload.
