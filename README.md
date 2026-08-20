# Warden

> Warden lets AI agents investigate production databases through a narrow,
> deterministic, least-privilege, read-only interface without exposing database
> credentials to the model.

A **Model Context Protocol** server written in Rust, for MySQL and PostgreSQL.

**Status:** under development. There is no usable release yet; see
[`docs/milestones.md`](docs/milestones.md).

## What Warden does and does not guarantee

A security product must state both. The complete list is in
[`SPEC.md` section 7](SPEC.md); in summary:

Warden **prevents** write SQL, multiple statements, locking reads, unknown side
effects, and unparseable SQL from reaching the database. It limits time, volume,
and concurrency, keeps credentials out of model context, and audits every attempt.

Warden **is not the final write boundary**. That boundary is the dedicated role's
`GRANT`; SQL analysis reduces attack surface. The table allowlist **does not** bound
read scope—only the role's `SELECT` privileges do. Column redaction **is not** access
control. Warden also does not sanitize database contents: a hostile stored value can
try to influence the agent.

> Warden provides defense-in-depth controls, but production security still requires
> least-privilege database credentials and appropriate infrastructure isolation.

## Documentation

| Document | Contents |
|---|---|
| [`SPEC.md`](SPEC.md) | Product, 32 security invariants, guarantee boundaries |
| [`AGENTS.md`](AGENTS.md) | Contract for implementation agents |
| [`docs/architecture.md`](docs/architecture.md) | Layers, crates, ports, dependency direction |
| [`docs/security.md`](docs/security.md) | Threat model, threat-to-control matrix, privileges |
| [`docs/operations.md`](docs/operations.md) | Configuration, pools, TLS, observability, CLI, CI |
| [`docs/testing.md`](docs/testing.md) | Test strategy, corpus, fuzzing |
| [`docs/adr/`](docs/adr/) | Architectural decisions, one per file |

## Development

The Rust toolchain is declared in `rust-toolchain.toml` and provisioned by
rustup. [mise](https://mise.jdx.dev) reads that file and manages only auxiliary
tools and development shortcuts.

```bash
mise trust
mise install          # Rust from rust-toolchain.toml plus tools from mise.lock
mise run ci           # the same gate run by CI
mise run test:docker  # integration tests; requires a Docker daemon
mise run coverage     # coverage report in coverage/
```

`mise tasks` lists the shortcuts. They are conveniences; the Cargo commands in
`AGENTS.md` and `docs/operations.md` remain the canonical gate interface.

`rust-version = "1.94"` in `Cargo.toml` is the supported floor (MSRV), verified
by a dedicated job. The development toolchain comes from `rust-toolchain.toml`,
the only hand-written source for its version and components. These are distinct;
see [ADR-0002](docs/adr/0002-edition-2024-msrv.md).

## License

Not yet selected; see [`docs/open-questions.md`](docs/open-questions.md), item 12.
Until then, all rights reserved.
