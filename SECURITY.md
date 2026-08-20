# Security policy

## Reporting a vulnerability

Do not open a public issue. Use GitHub [private vulnerability
reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
or email the address listed in `Cargo.toml`.

Include the affected version, database engine and version, relevant configuration
with credentials removed, and the SQL or MCP call sequence that reproduces the issue.

## Scope

Anything that violates one of the 32 invariants in [`SPEC.md` section 6](SPEC.md)
is in scope—especially SQL that reaches execution without analysis, any form of
write, multiple statements, resource-limit bypasses, or credentials leaked through
a tool response, log, or audit record.

Anything that [`SPEC.md` section 7](SPEC.md) explicitly excludes from its guarantees
is **not** in scope. In particular, the table allowlist does not bound read scope,
column redaction is not access control, and database contents are not sanitized.
These boundaries are documented deliberately; they are not oversights.

## Practice

Every confirmed bypass becomes a permanent regression fixture (`SPEC.md` section 6,
invariant 32). The test case is part of the fix, not an optional follow-up.
