# ADR-0031 — A DSN names only the connection target

**Status:** Accepted · 2026-08-24 · **New in Milestone 6**

## Context

A DSN looks like one string and is really two things: where to connect and as whom,
which only the operator knows, and how to connect, which Warden decides. Both SQLx
drivers read the second kind out of the query string.

`MySqlConnectOptions::from_str` honours `ssl-mode`, `ssl-ca`, `sslcert`, `sslkey`,
`socket`, `statement-cache-capacity`, `charset` and `timezone`.
`PgConnectOptions::from_str` honours `sslmode`, `sslrootcert`, `sslcert`, `sslkey`,
`options`, `host`, `hostaddr`, `port`, `dbname`, `user`, `password` and
`application_name`, and it **appends** to `options`, so a DSN can add
`-c row_security=off` — a setting Warden pins nothing against — and every later `-c`
Warden writes leaves it in place.

Applying Warden's hardening after the parse, which is what Milestone 6 first did,
only covers the settings Warden happens to overwrite. It leaves the trust anchor, the
client certificate, the character set, the time zone and every unpinned startup
option decided by whatever an operator pasted, with nothing in Warden's configuration
saying so.

PostgreSQL adds two failures the ordering cannot reach at all. Every
`PgConnectOptions` constructor seeds itself from `PGHOST`, `PGUSER`, `PGPASSWORD`,
`PGSSLROOTCERT`, `PGSSLCERT`, `PGSSLKEY`, `PGOPTIONS` and their siblings, and there is
no setter that clears the three certificate fields once a constructor has filled them
in. `PgConnectOptions::from_str` also logs: `tracing::warn!(%key, %value)` for every
query parameter it does not recognize, and the whole malformed line — password
included — when `~/.pgpass` does not parse. Both run before
`disable_statement_logging` can, so a secret can reach an operator log before the
connection exists (SPEC section 6, invariants 20–22).

## Decision

`warden_core::secret::Dsn` parses and validates the entire connection string once, at
construction. A DSN must name a scheme, a TCP host, a user and a database; it may
name a port and a password; and it may carry **no query string and no fragment**.
Anything else is a `DsnError` before an adapter sees it, and before startup completes.

No adapter hands a connection string to a driver's URL parser. Both build their
connect options field by field from the validated target, and `warden-postgres`
starts from `PgConnectOptions::new_without_pgpass` so that `~/.pgpass` is never read.

`warden-postgres` additionally refuses to build a connection while any `PG*` variable
its driver reads is present in the environment, and names the variable in
`ConnectError::AmbientConnectionInput`. Refusing is the only available answer for the
certificate fields, and a partial rule — refuse three variables, tolerate ten — is one
a reader would have to check against the driver's source to trust.

Each adapter's own tests parse its `options.rs` and fail if the chain that builds
connect options starts anywhere but the intended constructor, or if the driver's URL
parser is called at all.

## Consequences

A pasted `?sslmode=require` is now a startup error rather than a silently ignored
parameter. That is the intended trade: one source of truth for connection policy, and
an operator who has to resolve the contradiction rather than believing both halves of
it. `docs/operations.md` section 3 documents the accepted DSN shape.

Unix-domain sockets are not addressable in Milestone 6. They have no certificate to
verify, and a TCP host is what makes ADR-0030's TLS policy mean anything.

A deployment that relies on `PGHOST` or `PGPASSWORD` must move those values into
Warden's configuration. Client certificates are not a Milestone 6 feature; when they
arrive they arrive as configuration, not as a DSN parameter, and this ADR is what says
where they go.
