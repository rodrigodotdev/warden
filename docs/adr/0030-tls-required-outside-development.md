# ADR-0030 — TLS is required outside development

**Status:** Accepted · 2026-08-24 · **New in Milestone 6**

## Context

SQLx's TLS modes include a preferring mode that attempts TLS and falls back to
cleartext when the server declines. It is the default in both drivers:
`MySqlSslMode::Preferred` and `PgSslMode::Prefer`. A deployment that inherits it works,
reports no error, and sends the database password over the network in the open.

`docs/operations.md` section 8 already requires TLS in production and forbids
disabling certificate verification to simplify setup. It did not say how the type
system should express that, and a plain pass-through of the driver enum would let the
weakest mode be the one an operator reaches by not choosing.

Cleartext cannot simply be unrepresentable. The Testcontainers PostgreSQL image serves
no TLS, and local development against a loopback socket has no certificate to verify.

## Decision

`warden_core::tls::TlsMode` is a closed enum of `Disabled`, `Required`, `VerifyCa` and
`VerifyIdentity`. There is no preferring variant, in configuration or in code, and each
adapter maps the enum exhaustively onto its driver's mode and always calls `ssl_mode`
explicitly, so no driver default is ever the value in effect.

`TlsSettings::validate` takes the connection's `Environment` and rejects
`TlsMode::Disabled` for every environment except `Development`. It also rejects a
configured root certificate alongside a disabled mode, because that shape reads as
hardened and is not. `TlsMode::Required` encrypts without authenticating the server,
so it is also legal only in `Development`; staging, production, and operator-defined
environments require `VerifyCa` or `VerifyIdentity`. `TlsSettings::default()` chooses
`VerifyIdentity`.

## Consequences

A silent cleartext fallback is not expressible. An operator who wants cleartext or
non-verifying TLS must both spell it out and declare the connection to be development.

This is not the bypass flag SPEC section 9 prohibits: it cannot be applied to a
staging or production connection at all, and no configuration key relaxes the
environment check.

Adding a TLS mode is a deliberate act: the enum is matched exhaustively in both
adapters, so a new variant breaks two builds rather than falling through to something
weaker.
