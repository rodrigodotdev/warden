# ADR-0054 — A refusal before the attempt is audited as a rejection

**Status:** Accepted · 2026-09-15 · **New in Milestone 13.3 · Resolves open question 25**

## Context

Two-phase auditing (ADR-0022) starts at the attempt, which needs a resolved
connection. A call refused earlier — arguments that do not deserialize, a parameter
over budget, an unknown connection name, a connection without the capability — left no
record at all: `ServiceCore::preflight` returned before `audit::attempt` could be built,
and rmcp answered a deserialization failure with its own text before Warden ran.
Fabricating an attempt with a fallback dialect was rejected: an audit record must not
describe a resolution that never happened.

## Decision

`AuditSink` gains a third, terminal record: `AuditRejection` (`event = rejection`,
same `warden.audit.v1` schema) with request identity, operation, a stage (`input`,
`connection_resolution`, `capability`), the connection name when it validated, and the
public code. It has no dialect, environment, fingerprint or statement kind. The file
sink writes it durably, like an attempt; a failed write is an alarm.

The service is the only producer. The MCP adapter's four database tools take their
arguments as a raw `JsonObject` with an explicit `input_schema` derived from the same
typed DTO, deserialize them themselves, and report a failure as the new public code
`invalid_arguments` through `Services::reject_request`. The schema an agent reads does
not change (`tests/snapshots/tools.json`).

## Consequences

Every identifiable, admitted call of a database tool leaves exactly one terminal
record: a rejection, or an attempt with its outcome. Readers of the audit file must
accept a third `event` value. The deserializer's text — which can quote the agent's
own submitted value — no longer reaches the agent, the log, or the trail. What is
still outside the trail: unreadable JSON-RPC, a frame over the transport budget, and a
call for which no identity could be built, all of which fail before a request exists.
