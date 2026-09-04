# ADR-0043 — The persistent audit sink

**Status:** Accepted · 2026-09-04 · **New in Milestone 13**

## Context

ADR-0022 defines a fail-closed attempt, and Milestone 12's sink writes `tracing`
events — a macro that returns unit. A sink that cannot fail cannot demonstrate
failing closed, which is why two definition-of-done boxes stayed unticked.

## Decision

An append-only JSON Lines file sink, one record per line, stamped `warden.audit.v1`;
the attempt phase is `sync_data`'d before it reports success and the outcome phase is
not; every IO or serialization failure becomes `AuditError::Unavailable`, whose
`Display` prints no path or errno.

## Consequences

The attempt phase now costs one fsync, bounded by `AUDIT_WRITE_TIMEOUT` (2s) like
every other write, and a saturated audit volume denies queries — which is the
intended direction and must be stated in the operations documentation. Rotation is
the operator's job through the usual tools; Warden appends and never truncates, so a
`copytruncate` rotation loses nothing already synced. No log-shipping format is
invented: a JSON line is what every collector already reads.
