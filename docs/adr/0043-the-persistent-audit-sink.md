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

At startup, validate the opened handle as a regular file distinct from stdout
and reject a nonempty file whose final byte is not a newline. Read access is
required for this check. Synchronize the file and its containing directory before
accepting requests, including when the file already exists. On Unix, resolve the
target and open it relative to the retained directory handle, refusing a replaced
final symlink; synchronize that same directory. This ties creation and persistence
to the same directory even if its pathname changes. Parents must already exist
and the operator must protect the directory and file from concurrent modification.

File auditing remains compilable across platforms. Outside Unix, startup fails
with `Unsupported`: the implementation does not have an equivalent safe directory
handle persistence protocol there. This explicitly limits the file destination
at runtime, including on Windows; stderr tracing remains available. Supporting
those file destinations requires a platform-specific persistence implementation,
not silently skipping the durability step. On Unix too, a filesystem that rejects
directory synchronization causes startup failure. Successful synchronization is
only as reliable as the filesystem and storage device's durability contract.

Before starting any record I/O, mark the live writer uncertain. Only a complete
write, flush, and required sync makes it usable again. Any error or cancellation
permanently poisons it, so later attempts fail closed without appending to an
unknown prefix. Recovery requires stopping Warden, inspecting and preserving the
trail, repairing or rotating it explicitly, and restarting; startup never silently
truncates evidence. A terminated final line is a boundary check, not full forensic
validation of an externally modified trail.

## Consequences

The attempt phase now costs one fsync, bounded by `AUDIT_WRITE_TIMEOUT` (2s) like
every other write, and a saturated audit volume denies queries — which is the
intended direction and must be stated in the operations documentation. Rotation is
the operator's job: stop accepting requests, drain outstanding requests and audit
outcomes, stop Warden, rotate the closed file, then restart Warden. Preserve and
synchronize the rotated archive and directory according to the storage platform's
contract before deleting any backup. `copytruncate` is not lossless: an attempt
synced between the copy and truncate can be erased. Do not rotate a live writer
until coordinated reopening is implemented. No log-shipping format is invented:
a JSON line is what every collector already reads.
