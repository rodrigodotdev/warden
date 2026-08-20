# ADR-0013 — No `async-trait`; use explicit boxed futures

**Status:** Accepted · 2026-08-19

## Context

`async fn` in traits is stable but not dyn-compatible. Warden needs dynamic dispatch
because the connection is selected at runtime.

## Decision

Dynamically dispatched asynchronous ports use an explicit alias:

```rust
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
```

Do not use `async-trait`.

## Consequences

Allocation and dispatch remain visible at the call site, which matters at a
human-reviewed security boundary, and no macro rewrites signatures.

Port signatures are more verbose. Warden has few explicit ports, so the cost is
contained. Revisit this decision if ergonomics deteriorate materially.
