# Code review — remediation plan

**Date:** 2026-09-06 · **Revision 3** · **Scope:** whole workspace (58 089 lines of
Rust, 9 crates, 1 050 tests) · **Baseline:** `cargo clippy --workspace --all-targets
-- -D warnings` exits 0 at `f6a3a4d`.

Revision 3 verified every claim and every proposed remedy against the tree. The
findings survived; several of the remedies did not. Three would not have compiled,
one rested on an inverted fact, and two traded readable parallel structure for a
line count. Those are corrected or withdrawn in place, and §8 records each one.

The governing rule of this revision: **a change earns its place by making the
codebase healthier, not by removing lines.** Where duplication is the price of a
structure that a reviewer can check side by side, it stays, and the entry says so.

Each item states what is wrong, why it matters, and the change to make, with an
effort estimate and a line delta where the change removes code.

---

## 0. Assessment

The codebase is unusually disciplined. Default-deny is structural rather than
conventional, the capability tokens (`AllowDecision`, `QueryPermit`,
`VerifiedExplain`, `ExecutionGate`) make the dangerous operations unreachable without
the preceding check, and the mechanical guards catch what the compiler cannot.
Nothing below is an exploitable bypass of the query pipeline.

What the review found falls into four buckets:

1. **Seven defects** (§1) — one of which, `warden-mysql` failing to compile
   standalone, is a hard build error that CI structurally cannot see.
2. **Consistency drift** (§2) — the same problem solved two ways, which is the
   failure mode this project is most exposed to because it leans so heavily on
   mechanical guards. One of those guards already has a blind spot.
3. **A placement error** (§3) — `AuditSink`'s two adapters live in the binary crate,
   the only port in the system whose implementations do.
4. **Structural duplication** (§4, §5) — 82 exact-clone function groups across the
   tree, measured rather than estimated. Roughly two thirds of it is worth removing;
   the rest is deliberate and is recorded as such.

`docs/open-questions.md` already tracks 17 items. Nothing below duplicates one.

---

## 1. Defects

### 1.1 `warden-mysql` does not compile on its own — `crates/warden-mysql/Cargo.toml:31`

```
$ cargo build -p warden-mysql --lib
error[E0433]: cannot find `select` in `tokio`
   --> crates/warden-mysql/src/execute.rs:291:12
error[E0433]: cannot find `select` in `tokio`
   --> crates/warden-mysql/src/explain.rs:227:12
```

The crate declares `tokio = { workspace = true, features = ["time"] }` and then uses
`tokio::select!`, which is gated behind `macros`. It builds today only because
feature unification supplies `macros` from somewhere else — the root binary in a
workspace build, or the crate's own dev-dependencies (line 64) during `cargo test`.

`warden-postgres/Cargo.toml:41` declares `["macros", "time"]` correctly. Every other
workspace member builds standalone; this is the only one that does not.

**CI cannot catch this.** Every command in `.github/workflows/ci.yml` is
`--workspace`, `--workspace --all-targets`, or `--all-features`, and all three unify
features across the graph. The MSRV job is `cargo +1.94.0 check --workspace
--all-targets`. The container job's `cargo test -p warden-mysql --features docker`
looks per-package but is not: `cargo test` pulls the crate's dev-dependencies, which
supply `macros`.

This is latent rather than currently harmful — `publish = false` means nobody
consumes the crate alone — but it is an undeclared dependency on a feature, which is
exactly the class of error `deny.toml`'s `[[bans.features]]` block exists to prevent
in the other direction.

**Fix.**

1. `crates/warden-mysql/Cargo.toml:31` → `features = ["macros", "time"]`, and update
   the comment above it, which currently explains a `time`-only choice that is no
   longer true. §1.6 removes the other two comments resting on the same assumption.
2. Close the CI gap. Add to the `gate` job, after `cargo check --workspace`:
   ```yaml
   - name: Each crate must build on its own
     run: |
       for c in $(cargo metadata --no-deps --format-version 1 \
                  | jq -r '.packages[].name'); do
         cargo check -p "$c" || exit 1
       done
   ```
   **Not `--lib`.** The root package `warden` has only a `bin` target, so
   `cargo check -p warden --lib` fails with `error: no library targets found in
   package 'warden'`. Without the flag the loop checks each crate's real targets,
   builds the binary too, and still catches this bug — verified: `cargo check -p
   warden-mysql` reproduces the error above.

   `jq` is already required by the repository's tooling. `cargo hack check
   --each-feature --workspace` is the more thorough option and also covers the
   `docker` feature matrix; it is a new tool dependency in `mise.toml`, so the loop
   above is the cheaper first step.

*Effort: 30 min. This is the highest value-per-minute item in the plan.*

### 1.2 The audit trail is created world-writable — `src/audit/file.rs:128`

```rust
Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
```

`0666` before umask. Under the umask most container images and systemd units run with
(`0022`) the file lands at `0644`; under `0002` — common in shared-group deployments —
`0664`; under `0000`, world-writable. The audit trail is the evidence ADR-0022 fails
closed to protect, and its integrity is the entire argument for `sync_data` on the
attempt phase. Creating it with the most permissive mode the API offers contradicts
everything around it.

ADR-0043 says "the operator must protect the directory and file from concurrent
modification" but never fixes a mode. This is a default nobody decided.

**Fix.** `Mode::RUSR | Mode::WUSR` (`0600`).

Note that this is the right default *and* does not block a log shipper: the mode
applies only at `O_CREAT`, so an existing file keeps whatever mode it has. An operator
whose collector runs as another user pre-creates the file at `0640` with the group
they need, and Warden appends to it unchanged. Document that in ADR-0043 rather than
adding a configuration key — a configurable audit-file mode is a knob whose only
correct setting is "as tight as your collector allows".

Add a test asserting `metadata().permissions().mode() & 0o177 == 0` on a freshly
created trail (`0o177` rather than `0o077`, so a stray owner-execute bit also fails).

*Effort: 30 min. Lines: +12.*

### 1.3 The DSN read buffer is never zeroized — `crates/warden-config/src/secrets.rs:44-63`

`warden_core::secret`'s header states the model: the string a `Dsn` is built from "is
wrapped in `secrecy::SecretString` for the length of the parse and zeroed when it
drops." That holds for the string `Dsn::try_from` receives. It does not hold for the
buffer that produced it:

```rust
let raw = match source {
    SecretSource::Environment(variable) => std::env::var(variable)...?,
    SecretSource::File(path)            => std::fs::read_to_string(path)...?,
};
Dsn::try_from(raw.trim().to_owned())
```

`raw` is a plain `String` holding the full DSN including the password and is dropped
without zeroization. Defence-in-depth rather than a leak path, but the module's own
documentation asserts a property it does not have.

**Fix.** Two parts.

1. Wrap what Warden controls:
   ```rust
   let raw = SecretString::from(match source { ... });
   Dsn::try_from(raw.expose_secret().trim().to_owned())
   ```
   `secrecy` is **already** a `warden-config` dependency, so this is a use, not a new
   edge.
2. State the residual in the module header: `dsn_env` leaves the DSN in the process
   environment block for the process lifetime, readable through `/proc/self/environ`
   by anything that can read the process — which is exactly the local agent
   `docs/mcp.md` §7 already warns about. `dsn_file` is therefore the stronger of the
   two sources, and the documentation should say so rather than presenting them as
   equivalent.

**Withdrawn from revision 2:** a third part proposed replacing `fs::read_to_string`
with `File::open` + `read_to_end` into a pre-sized `Vec`, on the grounds that
`read_to_string` reallocates and strands copies of the prefix in freed heap. It does
not: `std::fs::read_to_string` reserves from `metadata.len()` before reading. The
change would have added a manual read loop for no security gain, which is the
opposite of what this plan is for.

*Effort: 30 min. Lines: ~+8.*

### 1.4 The adapter source guards go blind at the first `#[cfg(test)]` — `crates/warden-{mysql,postgres}/tests/adapter_rules.rs:100-109`

```rust
fn code_lines(path: &Path) -> Vec<(usize, String)> {
    ...
        .take_while(|(_, line)| line != "#[cfg(test)]")
```

Every scan in that file — the export guard, the `sqlparser`- and
`sqlx`-in-public-signature guards, the wildcard-arm guard, the buffering-fetch guard,
the `format!` guards — sees only the lines *before* the first line that is exactly
`#[cfg(test)]`. The comment above it explains why a substring match would be unsound;
the chosen cutoff has the same shape of problem, because it assumes the first
`#[cfg(test)]` in a file is the trailing `mod tests`.

It is not, in both adapters:

- `crates/warden-mysql/src/connection.rs:187` — `#[cfg(test)] impl MySqlConnectionPools`
  (`lazy_for_tests`), with the real `mod tests` at line 200.
- `crates/warden-postgres/src/connection.rs:305` — the same shape, `mod tests` at 328.

`connection.rs` is in `SOURCE_FILES` (line 20), so this is inside the scanned set: the
last 89 lines of one file and 153 of the other are outside every scan. Today that
region holds only test-only code, so no rule is currently violated — but the guard
cannot tell, and a production item written below such an attribute would pass
silently. In a project whose security argument is "the guard is mechanical", a guard
with an invisible region is the finding.

**Fix.** Replace the line scanner with `syn`, folded into §2.1's shared crate. Three
details that matter for correctness of the replacement:

1. Strip **any** `cfg` predicate whose token stream mentions `test`, not just the bare
   spelling — both adapters carry `#[cfg(all(test, feature = "docker"))]`
   (`execute.rs`, `inspector.rs`) and `#[cfg_attr]` must be handled too.
2. Add `proc-macro2` to both adapters' dev-dependencies. `syn::Macro` leaves its body
   as an opaque token stream, and three of the guards in `adapter_rules.rs`
   (`the_only_format_in_{execute,explain,plan}_rs_*`) assert on `format!` contents.
   `warden-service/tests/service_rules.rs` already walks token trees this way;
   the adapters would need the same dependency, which they do not have today.
3. Keep `the_scans_are_alive` and the four `driver_surface_scan_*` negative controls.
   They are what makes this a fixable gap rather than a systemic one, and they must be
   ported, not dropped.

*Effort: 1 day (both adapters), inside §2.1. Lines: −300 to −400 net.*

### 1.5 Redaction can push a result past `max_result_bytes` — `crates/warden-service/src/redaction.rs:141-164`

`ResultBuilder` enforces `max_result_bytes` while rows arrive, which is the point of
`docs/operations.md` §6.6. Redaction runs *after* that and replaces matched values
with `"[REDACTED]"` — 12 encoded bytes. A redacted `NULL` (4 bytes) or small integer
(1–3) grows. `redact_result` recomputes `result.stats.bytes` faithfully but nothing
re-checks it, so the response can exceed the bound Warden reported enforcing.

Not agent-controllable — the rules are operator configuration — so this is a
correctness defect, not a resource vector.

**Fix.** Document rather than truncate, and say why. Truncating rows after the fact
would discard data the agent was authorised to see because of a redaction rule that
did not apply to it, which is a worse outcome than a slightly over-budget response.
Add to `docs/security.md` §8:

> The byte budget bounds the result as the database produced it. Redaction runs after
> the budget and may grow a response: `RedactionStrategy::Replace` costs at most 12
> bytes per matched cell. A deployment that needs the bound to hold post-redaction
> uses `strategy = "null"`, which can only shrink a response.

That last sentence is the real answer for an operator who cares, and it needs no code.
Add a test pinning the worst case so the "at most 12 bytes" figure stays true.

*Effort: 1 h. Lines: +15.*

### 1.6 Three cancellation races, two shapes, one stale justification

`guarded` exists six times — `execute.rs`, `explain.rs` and `inspector.rs` in each
adapter — in two different shapes:

| Site | Shape |
|---|---|
| `{mysql,postgres}/src/execute.rs` | `tokio::select! { biased; cancel.cancelled(), timeout_at(...) }` |
| `{mysql,postgres}/src/explain.rs` | same |
| `{mysql,postgres}/src/inspector.rs` | `cancel.run_until_cancelled(timeout_at(...))` |

The MySQL inspector justifies the odd one out:

> `CancellationToken::run_until_cancelled` rather than `tokio::select!`: this crate
> depends on `tokio` with the `time` feature only, and reaching for `select!` would
> enable `macros` for a race the token already expresses.

That reason is false — `execute.rs` and `explain.rs` in the same crate use
`tokio::select!`, which is why §1.1 exists — and the PostgreSQL inspector gives an
entirely different reason for the identical code ("keeps the cancellation race
consistent with the MySQL adapter and avoids a third branch"). Two adapters, one
control, two contradictory explanations, one of them provably wrong.

The shapes are also not behaviourally identical: `select!` with `biased` polls
cancellation first every time; `run_until_cancelled` polls the inner future first.
For a race whose whole purpose is deterministic cancellation under a deadline, that
difference should be a decision, not an accident.

**Fix.** Pick one shape and use it in all six places. `select! { biased; }` is the
better choice: the `biased` keyword makes the priority explicit in the code rather
than implicit in a combinator's polling order, which is what the execute/explain
comment already argues. Align the argument order too — `inspector.rs` takes
`(future, deadline, cancel)` and the other two take `(deadline, cancel, future)`.
Delete both justification comments and write one that describes the actual reason.

**Correction to revision 2:** it claimed `expired` and `finish` then "collapse to one
helper per adapter". Only `expired` does — it returns `bool` and has no error type.
`finish` maps a `timeout_at` result into `ExecuteError` in `execute.rs` and
`ExplainError` in `explain.rs`, so unifying it needs exactly the generic over an
error-constructor that this entry declines to build across adapters. Leave `finish`
duplicated per module; it is four lines of exhaustive `match` that names its own error
type, and that is the readable form.

Do **not** try to share `guarded` across the two adapters either: the three error types
(`ExecuteError`, `ExplainError`, `SchemaError`) differ, and the machinery costs more
than the ~40 lines it saves.

*Effort: half a day. Lines: −40.*

### 1.7 Agent session transcripts are untracked in the working tree

```
?? 2026-09-04-195651-local-command-caveatcaveat-the-messages-below.txt    23 KB
?? codex-session-01a06deb-8c76-7753-b8c0-a365147738b8.md                 916 KB
```

Neither is covered by `.gitignore`. A `git add -A` commits nearly a megabyte of agent
transcript into a public security-product repository, and transcripts of sessions that
touched configuration and DSN handling are the artefact most likely to have a
connection string pasted into them.

**Fix.** Delete both after checking they hold nothing you need, and extend
`.gitignore`:

```gitignore
# Agent session artefacts — transcripts can quote configuration and DSNs
/codex-session-*.md
/*-local-command-caveat*.txt
/.codex/sessions/
```

*Effort: 10 min.*

---

## 2. Consistency

### 2.1 Two implementations of "mechanical source guard"

Nine test files enforce rules the compiler cannot express, split across two
incompatible techniques:

| File | Technique | Lines |
|---|---|---|
| `tests/architecture.rs` | `syn` AST walk | 1 332 |
| `crates/warden-service/tests/service_rules.rs` | `syn` (81 refs) | 1 653 |
| `crates/warden-mcp/tests/mcp_rules.rs` | `syn` (25 refs) | 501 |
| `crates/warden-config/tests/config_rules.rs` | `syn` (11 refs) | 309 |
| `crates/warden-mysql/tests/adapter_rules.rs` | line scanning | 855 |
| `crates/warden-postgres/tests/adapter_rules.rs` | line scanning | 830 |
| `crates/warden-ports/tests/port_rules.rs` | line scanning | 416 |
| `crates/warden-policy/tests/policy_rules.rs` | line scanning | 412 |
| `crates/warden-core/tests/newtype_rules.rs` | line scanning | 229 |

The line-scanning half re-derives Rust lexing by hand — `brace_delta`, `is_exported`,
`names_type`, `declaration_header_end` — and every one of those is a place where a
string literal, a macro body, or unusual formatting can produce a false negative.
§1.4 is one such false negative that already exists. `fn source_files` is byte-identical
across three of them (`adapter_rules.rs` ×2, `newtype_rules.rs`), 26 lines each.

The sharpest form of the inconsistency: `warden-mysql` and `warden-postgres` use `syn`
correctly inside `src/options.rs` (`hardening_chain`, 61 lines, duplicated between
them) and hand-rolled scanning in `tests/adapter_rules.rs`. Two techniques inside one
crate.

**Fix.** Standardise on `syn` and extract the machinery once, into a dev-only
workspace member:

```
crates/warden-guards/          # publish = false, referenced only from [dev-dependencies]
  src/lib.rs
    pub fn production_items(crate_src: &Path) -> Vec<(PathBuf, syn::Item)>;
    pub fn public_signatures(items: &[syn::Item]) -> Vec<Signature>;
    pub fn wildcard_arms(items: &[syn::Item]) -> Vec<Location>;
    pub fn macro_token_trees(items: &[syn::Item]) -> Vec<(Path, TokenStream)>;
    pub fn span_name_literals(items: &[syn::Item]) -> BTreeSet<String>;
    pub fn source_files(crate_src: &Path) -> Vec<PathBuf>;
```

`tests/architecture.rs` already contains most of this and would be its first consumer.

Four things the extraction must get right:

1. **`production_items` is the security-critical function.** It is what strips
   `#[cfg(test)]`, and §1.4 is what happens when that logic is wrong. It gets its own
   negative-control tests: a file with a mid-file `#[cfg(test)] impl`, one with
   `#[cfg(all(test, feature = "x"))]`, one with `#[cfg_attr(test, ...)]`.
2. **`warden-guards` depends on nothing but `syn`, `proc-macro2` and `std`.** Add it
   to `EXPECTED_MEMBERS` and to `FORBIDDEN_EDGES` in `tests/architecture.rs` so that
   stays true. `no_workspace_member_is_publishable` covers it already.
3. **The crate must not depend on any Warden crate**, including for its own tests — a
   guard that can see the code it guards is a guard that can be made to pass.
4. **Keep every negative control.** `the_scans_are_alive`, the four
   `driver_surface_scan_*` tests, and `the_scans_detect_the_violations_they_exist_to_catch`
   are what prove the guards can still fail.

This is the largest single item in the plan and the one with the best ratio: it fixes a
real blind spot, deletes ~800 lines of hand-rolled lexing, and makes every future guard
cheaper to write — including the three new ones this plan adds (§2.2, §4.3, §5.1).

*Effort: 2–3 days. Lines: −700 to −900 net.*

### 2.2 `#[allow]` attribute ordering — 9 files

127 files write `#![allow(clippy::unwrap_used, clippy::expect_used)]`; 9, all in
`warden-postgres`, write the pair reversed. `AGENTS.md` names this attribute as "the
one standing exception" — the single allow anyone may grep for. Two spellings means a
grep, or a future guard, has to know both.

Files: `container_tests.rs`, `connection.rs`, `pool.rs`, `execute/cleanup_tests.rs`,
`container_tests/{privileges,execution,inspection}.rs`, `options.rs`, `error.rs`.

**Fix.** Normalise with `sed`, then add the rule to `warden-guards`: every `#![allow]`
in the workspace must be exactly that one string, and every other allow must be one of
the **four** `#![allow(dead_code)]` attributes, one per `testing.rs`
(`warden-{service,ports,mcp,policy}`). Revision 2 said three; there are four, and a
guard written to the wrong count fails on the first run.

That turns `AGENTS.md`'s prose rule into a mechanical one, which is the pattern the
rest of the project already follows — and it is the guard that makes §5.1 safe to
review, since promoting `testing.rs` to a feature moves those allows into a
non-`cfg(test)` build.

*Effort: 15 min + 30 min for the guard. Lines: +15.*

### 2.3 `Config::resolve` indexes a map it already holds — `crates/warden-config/src/resolve.rs:156-171`

```rust
if let Some((first_name, rest)) = referenced_profiles.split_first() {
    let first = &self.policies[first_name];          // 158
    ...
}
...
let representative = &self.policies[&referenced_profiles[0]];   // 171
```

`representative` is the value `first` already was, re-derived by two `Index` lookups
that panic on a miss. There are four `Index` uses in this function (158, 160, 167,
171). All are provably safe today, but `Index` is the one panic shape
`clippy::unwrap_used`/`expect_used` does not catch — which is precisely why
`AGENTS.md` bans the others.

**Fix.** Replace the four `Index` uses with `get()`. Three of them (158, 160, 167)
have a natural error: `ConfigError::UnknownProfile`, the same variant the loop above
already produces, so the fallback is a real error rather than an unreachable branch.
For 171, hoist the `representative` binding out of the `if let` so it is the `first`
the loop already resolved, and let the `None` arm return `ConfigError::NoConnections`
— `self.connections` was proved non-empty at the top of the function, so an empty
`referenced_profiles` is the same impossible state that check already names.

Then enable `clippy::indexing_slicing` where it pays: scope it with
`#![cfg_attr(not(test), warn(clippy::indexing_slicing))]` in `warden-config` and
`warden-core` rather than workspace-wide. It is noisy in test code, which indexes
assertions freely; the goal is to catch a panic on the startup path, not to fight
assertions.

**Withdrawn from revision 2:** merging the three `for connection in &self.connections`
loops at 133–154 into one pass. It changes observable behaviour — today a config with
both a duplicate connection *and* an unknown profile always reports
`DuplicateConnection`, and a merged loop would report whichever the first offending
connection carries. No test pins that ordering, which makes it a silent change rather
than a safe one. Three named single-purpose loops over a vector that is at most a
handful of entries are also easier to read than one loop doing three jobs. The
micro-optimisation buys nothing on a startup path that runs once.

*Effort: 1 h. Lines: −8.*

### 2.4 Redaction rules are lowercased at parse, then compared case-insensitively — `crates/warden-service/src/redaction.rs:86-98`

`Rule::parse` stores `table` and `column` already ASCII-lowercased, and `matches`
still calls `eq_ignore_ascii_case` on both, so the reader cannot tell which side is
authoritative.

**Fix.** Make the stored side authoritative and say so: lowercase the *incoming*
identifier once, then compare with `==`. In `redact_result` that is once per column;
in `redact_description`, once per table and once per column, hoisted out of the rule
loop. Today the cost is `rules × columns` fold operations per result and after the
change it is `columns` — but the reason to do it is that one invariant ("everything
compared here is already lowercase") is easier to hold than two.

*Effort: 30 min. Lines: −4.*

### 2.5 Two copies of SHA-256 in the production binary

`Cargo.lock` carries `sha2 0.11.0` (Warden's own, used by both adapters'
`fingerprint.rs`) and `sha2 0.10.9` (pulled by `sqlx-core 0.9.0`). Both are in the
release graph. `deny.toml` sets `multiple-versions = "warn"`, so this is reported and
tolerated rather than decided.

**Fix — record the decision, keep 0.11.** Revision 2 recommended pinning
`sha2 = "0.10"` to unify with `sqlx-core`. That is the wrong default for this
dependency: it downgrades the one crate Warden uses to compute audit fingerprints in
order to silence a duplicate-version warning, and it has to be reverted the moment
`sqlx` moves to 0.11. The duplicate costs binary size, not correctness, and neither
copy is reachable from the other's call sites.

Record it in `docs/operations.md` §2.7 next to the `webpki-roots` exception: Warden
pins `sha2 0.11` for `v1:<sha256-hex>` fingerprints, `sqlx-core 0.9` pins `0.10`, the
duplicate is accepted, and it disappears when `sqlx` upgrades. Then add a
`[[bans.skip]]` entry for `sha2` in `deny.toml` so the exception is expressed where
the tool reads it, rather than surviving as a warning nobody has decided about.

`base64 0.22.1` is also duplicated but only through `bollard`, a dev-dependency, so it
never enters the release binary and needs nothing.

*Effort: 30 min including a `cargo deny` re-run. Lines: +5 of documentation.*

---

## 3. Architecture: the audit sinks belong in a crate

**`src/audit/` is 1 517 of the binary's 3 468 lines — 44 %.**

```
477  file.rs        428  tracing_sink.rs      367  record.rs
202  file/writer.rs  43  mod.rs
```

`AuditSink` is a port declared in `warden-ports`, exactly like `QueryExecutor`,
`Explainer` and `SchemaInspector`. Those three have their implementations in adapter
crates. `AuditSink`'s two implementations — stderr and append-only JSONL — live in the
composition root. It is the only port in the system whose adapters do.

No ADR places them there. ADR-0043 describes the sink's *behaviour*, not its location.
A comment in the root `Cargo.toml` gives the history away: *"the audit module is no
longer test-only code that can borrow the dev-dependency."* It grew in place from
Milestone 12 by inertia.

### What the extraction buys

1. **`main.rs` becomes what its own header claims it is** — "the only process-level
   code that resolves `std::env::args()`, selects real descriptors, and maps errors to
   exit codes." Today the binary also hosts `rustix` syscalls, symlink and TOCTOU
   handling, an fsync durability protocol, and a poisonable writer. That is an
   adapter, not composition. `src/audit/mod.rs::build` — 12 lines choosing a sink from
   configuration — genuinely is composition and stays.
2. **`tests/architecture.rs` gains a boundary it currently cannot express.**
   `warden-audit` must not depend on `sqlx`, `rmcp`, `sqlparser`, an adapter,
   `warden-service`, `warden-policy` or `warden-config`. Today none of that is
   enforceable, because the binary legitimately depends on everything.
3. **The audit record format gets the crate-level guard every other boundary has.**
   `FORBIDDEN_FIELDS` is currently a `#[cfg(test)] const` *inside the module it
   guards*. This is the single most security-sensitive format in the product
   (`docs/security.md` §11.3, SPEC §6 invariants 22–23) and it has the weakest
   mechanical protection of any boundary — every other one has `adapter_rules.rs`,
   `port_rules.rs`, `mcp_rules.rs`, `config_rules.rs` or `policy_rules.rs`. A
   `crates/warden-audit/tests/audit_rules.rs` would assert, from outside, that no
   forbidden field name is reachable from any serialised type and that both sinks
   project the same field set.
4. **Dependencies move to where they are used.** `rustix`, `same-file`, `serde_json`,
   `time`, and tokio's `fs`/`io-util`/`sync` features leave the binary's manifest.
   `unreachable_pub`, `missing_docs` and `missing_errors_doc` then apply to a real
   public surface instead of a `pub(crate)` one rustdoc never renders.
5. **The file sink gets tested through its public API.** `file.rs:380` builds a
   `FileAuditSink` by struct literal because the test is inside the module; a crate
   forces that seam.

### The design question extraction forces, and its answer

`AuditMode` is defined in `warden-config` (`model.rs:342`) and used by `record.rs`,
`tracing_sink.rs` and `file.rs`. A `warden-audit` crate that depended on
`warden-config` would be **the first non-binary consumer of the configuration crate** —
verified: `AuditMode`, `AuditDestination` and `ResolvedAudit` are today used only by
`src/audit/*`, and every other `warden-config` export goes to `startup.rs`/`check.rs`.
That edge directly contradicts the rule `src/startup.rs`'s header states:

> `warden-config` emits core types and plain strings and depends on neither
> `warden-policy` nor `warden-service`, so something has to turn a resolved profile
> into `PolicySettings` and `RedactionSettings`. Doing it in the composition root is
> what a composition root is for.

So the correct shape is:

- **`AuditMode` moves to `warden-core`**, beside `TlsMode`, and `warden-config`
  consumes it. Revision 2 sent it to `warden-ports` and cited `TlsMode` as the
  precedent; the precedent points the other way. `TlsMode` lives in
  `warden-core/src/tls.rs:63` with `#[derive(serde::Serialize, serde::Deserialize)]`
  and `#[serde(try_from = "String", into = "String")]`, and `warden-config` merely
  deserializes into it. `warden-core` already depends on `serde`; **`warden-ports`
  does not**, and adding it there would put a serialization format into the crate
  whose entire job is to declare traits. `warden-core` is where a validated domain
  newtype that configuration parses and adapters read already belongs.
- **`AuditDestination` stays in `warden-config`**, and `startup.rs` maps it to the
  right sink — the same shape as `policy_settings()` and `redaction_settings()`.
- **`warden-audit` depends on** `warden-ports`, `warden-core`, `serde`, `serde_json`,
  `time`, `tracing`, `tokio` (`fs`, `io-util`, `sync`), `rustix`, `same-file`.
  Not `anyhow`: it returns `io::Error` and `AuditError`, and `main` adds the context.

```
crates/warden-audit/
  src/lib.rs           the two sinks, and nothing that chooses between them
  src/record.rs        the one record format
  src/tracing_sink.rs
  src/file.rs  src/file/writer.rs
  tests/audit_rules.rs the guard §3 point 3 describes
src/audit.rs           ~15 lines: ResolvedAudit -> Arc<dyn AuditSink>
```

Binary drops from 3 468 to ~1 970 lines.

### Cost, honestly

One day, plus entries in `EXPECTED_MEMBERS`, `FORBIDDEN_EDGES` and the `cargo deny`
graph. Moving `AuditMode` is a public API change to both `warden-core` and
`warden-config`, so it needs an ADR before the code (`AGENTS.md` process rule 4) —
*ADR-0048 — the audit sink is an adapter*, whose Context is the port/adapter rule
ADR-0018 already establishes and whose precedent for the type move is `TlsMode`.

`AGENTS.md` process rule 3 — "do not simplify the architecture to reduce the file
count" — does not oppose this. Extracting a crate adds structure. The rule guards
against collapsing boundaries, and this creates one.

*Effort: 1 day + ADR. Lines: binary −1 500, workspace ±0 (moved, not deleted), plus
~120 for the new guard test.*

---

## 4. Duplication — production code

A token-level clone scan over the whole tree finds **82 groups of byte-identical
function bodies** (after whitespace and comment normalisation), and the top 40 alone
account for ~857 redundant lines. Most of that list is not worth acting on. The items
below are the ones that are, plus the ones that are deliberately not — recorded so a
future reader does not "fix" them.

### 4.1 `QueryService`, `ExplainService` and `SchemaService` share their whole shell

All three hold the identical five fields:

```rust
registry: Arc<dyn ConnectionRegistry>,
engine:   Arc<PolicyEngine>,
audit:    Arc<dyn AuditSink>,
redactor: Arc<Redactor>,
shutdown: CancellationToken,
```

and their `new()` is duplicated three times verbatim (`query.rs:67`, `explain.rs:67`,
`schema.rs:71`, 15 lines each). `refuse` (`query.rs:265` / `explain.rs:251`) and
`complete` (`query.rs:286` / `explain.rs:272`) are byte-identical apart from one log
sentence. And `QueryService::execute` (`query.rs:96-260`) and
`ExplainService::explain` (`explain.rs:97-250`) share, verbatim modulo
`AuditOperation::Query`/`Explain`:

- connection resolution and the `connection.resolve` span
- analysis, the `sql.analyze` span, and the whole analyse-failure arm
- authorisation, the `policy.evaluate` span, and the whole rejection arm
- attempt construction and `ExecutionGate::enter`'s two-arm error match

The right extraction is a struct, because all three services need the same
collaborators and two of them need the same preflight:

```rust
pub(crate) struct ServiceCore {
    registry: Arc<dyn ConnectionRegistry>,
    engine:   Arc<PolicyEngine>,
    audit:    Arc<dyn AuditSink>,
    redactor: Arc<Redactor>,
    shutdown: CancellationToken,
}
```

**The preflight must be two calls, not one.** Revision 2 proposed a single
`preflight(...) -> Result<(ExecutionGate<'_>, OutcomeGuard, AuditAttempt), _>`. That
cannot compile. `ExecutionGate<'a>` borrows `runtime: &'a ConnectionRuntime`
(`pipeline.rs:89`), and `runtime` comes from `ConnectionRegistry::get`, which returns
an **owned** `Arc<ConnectionRuntime>` (`crates/warden-ports/src/registry.rs:24`). A
`preflight` that resolves the connection owns that `Arc` locally, so returning a gate
that borrows it is returning a borrow of a local.

Split it where the ownership boundary already is:

```rust
/// Everything decided before a permit is taken, in ADR-0022 order:
/// resolve -> analyze -> authorize -> build the attempt.
pub(crate) struct Preflight {
    runtime:    Arc<ConnectionRuntime>,
    attempt:    AuditAttempt,
    authorized: AuthorizedQuery,
}

impl ServiceCore {
    async fn refuse(&self, attempt: &AuditAttempt, outcome: AuditOutcome, code: PublicErrorCode);
    async fn complete(&self, ...);

    /// Refuses and audits on every failing arm, so a caller cannot forget to.
    async fn preflight(&self, context: &RequestContext, request: QueryRequest,
                       operation: AuditOperation) -> Result<Preflight, PreflightError>;

    /// Records the attempt, arms the guard, takes the permit.
    async fn gate<'a>(&self, pre: &'a Preflight, parent: tracing::Span)
        -> Result<(ExecutionGate<'a>, OutcomeGuard), GateError>;
}
```

The caller holds the `Preflight`; the gate borrows from it. This compiles, and it is
also the more honest shape: the two calls are the two halves ADR-0022 already
distinguishes — everything before the audited attempt, and the attempt-then-permit
sequence the gate exists to make unskippable.

The three services become thin wrappers holding one `ServiceCore`. Each keeps only
what genuinely differs: the operation constant, the `warden.query`/`warden.explain`
span, the post-gate call (`gate.execute()` vs `gate.explain()`), the
error→`AuditOutcome` match, and the redaction call. `SchemaService` uses
`refuse`/`complete` but not `preflight` — it has no statement to analyse — which the
struct handles naturally and a shared free function would not.

Keep the three services as separate public types. They are separate tools with
separate error enums, and `docs/security.md` §10 wants the error map readable. This
deduplicates a body, not a concept. `PreflightError` carries only the shared arms
(`ConnectionError`, `AnalyzeError`, `Rejection`, `AuditError`), and each service's
error type gets a `From<PreflightError>`.

`ServiceCore::preflight` and `::gate` must live in or beside `crate::pipeline` so
`tests/service_rules.rs`'s ADR-0038 guard — "only `pipeline.rs` may name
`executor()`, `explainer()` or `acquire_query_permit()`" — keeps holding. Update the
guard's allowed-module list in the same commit, not after.

*Effort: 2 days including moving the tests. Lines: −280 to −380.*

### 4.2 `QueryServiceError` and `ExplainServiceError` — leave them

`error.rs:22-92`. Same five variants, same `#[from]`s, same `PublicError` impl shape;
only `Execute(ExecuteError)` vs `Explain(ExplainError)` differ. A generic
`ServiceError<E: PublicError>` would work and would make the error map harder to read,
which is the exact property the module header protects. 40 lines of duplication that
is *evidence*. Recorded here so a future reader does not "fix" it.

### 4.3 The four MCP tool runners — add the guard, not the abstraction

`run_query`, `run_explain`, `run_search_schema` and `run_describe_schema`
(`server.rs:286-375`) are the same nine lines four times: build the span, convert the
input, clone the services `Arc`, run the future through `Self::run_in_task`, and match
the three outcomes.

**Revision 2 proposed a generic `dispatch`. Withdrawn.** Two reasons, and the second
is the one that matters.

1. The sketch did not compile: it moved `span` into `dispatch` as the first argument
   and then called `span.in_scope(...)` in the second (arguments evaluate left to
   right), and it declared an output type parameter it never used, so it had no way to
   produce `QueryOutput` for one tool and `ExplainOutput` for another.
2. Fixed, it would be a function with three type parameters and two closures replacing
   four flat nine-line functions, for a net saving of roughly twenty lines. That is the
   same trade this plan refuses in §4.2 and §5.6 — parallel structure a reviewer can
   check side by side is worth more than the lines. Four tool runners that each read
   top to bottom are the reviewable form of an MCP boundary.

**The real finding is that nothing enforces the containment.** `Self::run_in_task`
spawns each tool body into its own task so a panic becomes `internal_error` instead of
taking the connection down (`docs/security.md` §14, ADR-0045). It is duplicated four
times, and `crates/warden-mcp/tests/mcp_rules.rs` has **no guard** that a fifth tool
would get it — verified: the file's scans cover error construction, `format!` usage,
driver names and tool descriptions, and nothing else. Duplication is safe when a guard
watches it; here it is not watched.

**Fix.** Add to `mcp_rules.rs`, on `warden-guards`' `production_items`:

> every `async fn run_*` in `server.rs` contains exactly one call to `run_in_task`,
> and every arm of the `call_tool` dispatch reaches one of them.

Plus the negative control this project always pairs with a scan: a fixture runner
without `run_in_task` must make the test fail.

**Also recorded:** revision 2 justified its rewrite by claiming that moving a span
name out of `info_span!` would silently empty `tests/architecture.rs`'s span guard.
It would not. `the_documented_span_tree_is_the_one_the_workspace_creates` (line 1014)
asserts `assert_eq!(created, documented)` against `docs/operations.md`, so a dropped
name makes the sets unequal and the test fails loudly — and
`span_source_parser_reads_the_name_slot_for_every_supported_macro` (line 1045) already
pins the dynamic-name case explicitly, as a documented non-collection. The constraint
is real and worth knowing: **a span name must be a string literal in the macro.** It
is already enforced.

`run_list_connections` stays separate — it awaits nothing and deliberately spawns no
task, which the guard must allow by name.

*Effort: half a day. Lines: +40 (guard), production code unchanged.*

### 4.4 The two `SchemaInspector` implementations — take one extraction, not the crate

`crates/warden-{mysql,postgres}/src/inspector.rs` are 552 and 568 lines differing in
96. The clone scan localises it: `describe` (47 lines, identical), `search` (43,
near-identical), `resolve` (30), `guarded` (24, and see §1.6),
`a_denied_foreign_key_target_is_omitted_without_mutating_cached_metadata` (24),
`table_with_foreign_key` (18). `parse.rs` is a stronger case still: 31 differing lines
out of 111/120, and 20 of them are doc comments. `plan.rs` (`VerifiedExplain`) differs
in 113 of 236/249 with an identical shape.

**Recommendation: do not merge the adapters.** `AGENTS.md` rule 3 and ADR-0018 keep
them independent on purpose: they are the two places a dialect assumption is allowed
to live, and a shared abstraction is exactly what would let a MySQL assumption leak
into the PostgreSQL path. `visit.rs`, `normalize.rs`, `functions.rs`, `catalog.rs` and
`plan.rs` look duplicated and are not — each encodes a per-dialect security decision,
and the parallel structure is what makes them reviewable side by side. This is the
same judgement as §4.2 and §4.3, applied to the largest surface in the tree.

Take the one extraction that carries no dialect semantics and removes a real drift
risk:

**`RECURSION_LIMIT` moves to `warden-core` as one `pub const`.** Both
`parse.rs` files declare `pub(crate) const RECURSION_LIMIT: usize = 50;`
(`mysql:20`, `postgres:21`) and each carries a doc comment promising it equals the
other adapter's bound — a promise nothing checks. It is a plain `usize` with no
`sqlparser` dependency, so `warden-core` can hold it without gaining one. Both files
then read `warden_core::RECURSION_LIMIT`, the two doc comments become true by
construction, and `parse.rs` keeps its dialect-specific parser and its own tests.

Add one behavioural test per adapter asserting a statement nested one level past the
shared bound is refused, so the constant is pinned by behaviour and not only by
reference.

**Withdrawn from revision 2:** a shared `warden-sql` crate for `parse::statements`.
The only thing that can actually drift is the number.

`hardening_chain` and `crate_sources` (`options.rs`, 89 lines duplicated between the
adapters) are `syn`-based guards with no dialect content and move to `warden-guards`
as part of §2.1, not as a separate item.

*Effort: 2 h. Lines: −3, +15 of test. Risk: low.*

---

## 5. Duplication — tests

### 5.1 Four `testing.rs` fixture modules — 2 434 lines

| Crate | Lines |
|---|---|
| `warden-service/src/testing.rs` | 1 166 |
| `warden-ports/src/testing.rs` | 576 |
| `warden-mcp/src/testing.rs` | 490 |
| `warden-policy/src/testing.rs` | 202 |

All four are `#[cfg(test)]`, so nothing ships. The clone scan quantifies the overlap:
`result_set` (16 lines, 3×), `parts` (14, 3×), `connection` (8, 3×), `capabilities`
(8, 3×), `request_context` (7, 3×), plus `FakeAnalyzer`, `FakeExecutor`,
`FakeExplainer`, `FakeInspector` and `FakeAuditSink` implemented separately in
`warden-ports`, `warden-service` and `warden-mcp`, each with its own
`new`/`failing`/`taking`/`calls` surface.

This one is worth doing on architecture grounds rather than line count: **the fakes
belong with the traits.** `warden-ports` declares `QueryExecutor`, `Explainer`,
`SchemaInspector`, `AuditSink` and `QueryAnalyzer`; a fake of each is a property of
the port, and three crates independently deciding what `FakeExecutor::failing` means
is three chances for a test to prove something the port does not promise.

**Fix.** A `testing` feature on `warden-ports` that promotes `src/testing.rs` from
`#[cfg(test)]` to `#[cfg(any(test, feature = "testing"))]` and makes the fakes and the
shared fixtures `pub`. `warden-service` and `warden-mcp` take
`warden-ports = { workspace = true, features = ["testing"] }` as a **dev-dependency**
only. `tests/architecture.rs` already excludes dev-dependency edges (line 657), so the
enforced graph is unchanged.

Three details:

- `warden-policy` also has a `testing.rs`, and `warden-ports` depends on
  `warden-policy`. Policy's fixtures need their own `testing` feature, which
  `warden-ports/testing` enables and re-exports. Otherwise `warden-ports` would
  duplicate `analysis()`/`analyzed()` a third time.
- **Add an architecture assertion that no `testing` feature appears in any normal
  dependency edge.** Without it, the fakes can reach a release build through a single
  mis-typed `Cargo.toml` line, and `FakeAuditSink` in production is an audit sink that
  records nothing. This assertion is the reason the feature is acceptable at all, and
  it must land in the same commit as the feature.
- Clippy is already handled: all four `testing.rs` files carry
  `#![allow(clippy::unwrap_used, clippy::expect_used)]` and `#![allow(dead_code)]`
  at module level, so promoting them out of `#[cfg(test)]` does not trip the
  workspace denials. §2.2's guard is what keeps that true.

Each crate's `testing.rs` then keeps only what is genuinely local —
`warden-service`'s `secret_result()` and `rejection_with_internal_detail()`,
`warden-mcp`'s wire fixtures.

*Effort: 2 days. Lines: −800 to −1 000.*

### 5.2 Callsite interest — three techniques for one problem, and two of them collide

The tree solves "a scoped subscriber must not lose a span to a callsite some sibling
test reached first" in **three different ways**, in three crates:

| Site | Technique |
|---|---|
| `warden-service/src/testing.rs:1119` · `tests/service_rules.rs:849` · `warden-mcp/src/server.rs:563` | `keep_callsite_interest_dynamic` — leak two `Dispatch`es, then `rebuild_interest_cache()` |
| `warden-service/src/audit.rs:331` (`alarm_events`) | `set_global_default(AuditAlarmSubscriber).unwrap()` behind a hand-rolled `AtomicBool` spinlock |
| `src/audit/tracing_sink.rs:311` (`install_capture`) | `set_global_default(CapturingSubscriber)` behind a `OnceLock` |

**The first two are in the same test binary and are mutually exclusive.**
`set_global_default` succeeds once per process. `alarm_events` takes that slot and
`.unwrap()`s the result; any second global install in `warden-service`'s lib test
binary fails. Test order is not fixed, so the only reason this has not fired is that
nothing else has tried. Revision 2's fix — "install one global default subscriber per
test binary" — would have tried, and would have panicked nondeterministically.

The third, in the binary crate, is the one that gets it right, and its doc comment
already states the correct rationale in full.

#### Why `keep_callsite_interest_dynamic` is the wrong shape

1. **It permanently mutates global process state.** `OnceLock<[Dispatch; 2]>`
   deliberately leaks two dispatchers for the process lifetime so that
   `tracing-core`'s single-dispatcher fast path stays off and interest resolves to the
   union — which is `sometimes`. Every callsite in the binary then pays `enabled()`
   per macro invocation for the rest of the run, and a test asserting "no span was
   emitted" can behave differently depending on whether some earlier test called this.
2. **It depends on `tracing-core` internals** — the interest-union rule across ≥2 live
   dispatchers — which is not a public contract. Three copies are three sites that
   break on a `tracing-core` change, and nobody will be able to answer *why two
   dispatchers and not one* in a year.
3. **The fragility already bit once.** `f6a3a4d fix(tests): make span capture
   independent of callsite registration order` is the most recent commit on `main`.

#### The fix: one primitive, and keep the scoping that already works

The defect is narrow — it is the interest cache, nothing else. `with_subscriber` is
already the right way to scope a capture, so it stays. What replaces all three
techniques is one function in `warden-ports`' `testing` feature:

```rust
/// Installs the test binary's one global subscriber: it registers interest in every
/// callsite and enables none of them. Interest is then `sometimes` process-wide, so
/// `enabled` is asked per call on the emitting thread, and a scoped subscriber never
/// loses a span to a callsite a sibling test reached first.
///
/// Idempotent, and the only `set_global_default` a test binary may call.
pub fn ask_every_callsite() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        tracing::subscriber::set_global_default(AlwaysAsk)
            .expect("the test binary installs no other global subscriber");
    });
}
```

`AlwaysAsk` is the subscriber the three copies already define: `register_callsite`
returns `Interest::sometimes()`, `enabled` returns `false`, `max_level_hint` returns
`TRACE`. It is ~35 lines once instead of ~55 three times.

Then each site changes by one line, except the two that were doing something else:

- **`service_rules.rs` and `warden-mcp/src/server.rs`** — `SpanCapture::new()` calls
  `ask_every_callsite()` instead of `keep_callsite_interest_dynamic()`, and keeps
  `.with_subscriber(capture.dispatch())`. `SpanCapture`, `CapturingSubscriber` and
  `CaptureState` are themselves duplicated between these two files
  (`service_rules.rs:725/731/899`, `server.rs:486/610`) and contain no Warden types,
  so they move to `warden-ports` beside the primitive.
- **`warden-service/src/schema.rs:390`** keeps its scoped subscriber. It is not a
  capture: `PanicOnRedaction` asserts inside `new_span` that the span is not
  `result.redact`, injecting a panic at the redaction boundary to prove the outcome is
  recorded as `Abandoned`. A global capture layer cannot inject that panic, so the
  `with_subscriber` there is load-bearing and only the interest call changes.
- **`warden-service/src/audit.rs:331`** converts from global to scoped. Its
  `AuditAlarmSubscriber` becomes a `Dispatch` scoped over the emitting code, which is
  what frees the global slot — and the hand-rolled `ALARM_TEST_LOCK` spinlock and its
  `Drop` guard go away with it, because scoped subscribers do not contend for a
  process-wide slot. That is ~20 lines of concurrency machinery deleted as a side
  effect.
- **`src/audit/tracing_sink.rs:311`** moves to `warden-audit` with §3 and adopts the
  same primitive, so all four crates express the rule the same way.

#### The one assumption, and the test that pins it

`tracing-core` rebuilds the interest of every already-registered callsite when a
dispatcher is registered, which is what lets `ask_every_callsite()` be called from the
first test that needs it rather than before anything else in the binary. **Pin it with
a negative control:** a test that touches a span callsite, *then* calls
`ask_every_callsite()`, then scopes a capture over the same callsite and asserts the
span arrives. If that assumption is ever false, the fix is one
`tracing::callsite::rebuild_interest_cache()` inside `ask_every_callsite` — one call in
one place instead of three.

#### What this costs and what it does not

`warden-ports` gains a `tracing` dependency behind the `testing` feature. It does
**not** gain `tracing-subscriber`: `AlwaysAsk` is a bare `Subscriber`, not a `Layer`,
so no registry is involved.

**Withdrawn from revision 2:** a global `CaptureLayer` holding
`RwLock<HashMap<ThreadId, Arc<CaptureState>>>`, with `with_subscriber` deleted at every
call site. Three problems. It needs `tracing-subscriber` in `warden-ports`. It keys
capture by thread, which is correct only because every one of these tests happens to be
a current-thread `#[tokio::test]` — one `flavor = "multi_thread"` and spans vanish
silently, which is the exact bug class being fixed. And it cannot express
`PanicOnRedaction` at all. `with_subscriber` attaches the dispatcher to the *future*,
which is correct across threads and tasks by construction; there was never a reason to
remove it.

**Do not replace the runtime capture with an AST check.** `tests/architecture.rs`
already checks span *names* via `syn`; these tests check the span *tree* (parent,
child, level) and that no statement leaked into a field. `syn` cannot answer those.
The division is correct.

*Effort: 1 day (folded into §5.1). Lines: −180.*

### 5.3 `pipeline.rs` repeats its gate setup 19 times

`ExecutionGate::enter(...)` appears **19 times** in
`crates/warden-service/src/pipeline.rs`, 17 of them with the byte-identical argument
list:

```rust
let (gate, _guard) = ExecutionGate::enter(
    &runtime,
    Arc::new(testing::FakeAuditSink::new()),
    &testing::attempt(),
    testing::authorized(&runtime),
    CancellationToken::new(),
    tracing::Span::none(),
)
.await
.unwrap();
```

Nine lines of ceremony before every assertion, in a file whose tests are about what
happens *after* the gate opens. The signal-to-noise ratio is the defect; the line
count is a side effect.

**Fix.** One fixture in the test module:

```rust
/// A gate entered on `runtime` with the default fakes, for tests about what the
/// gate does once it is open.
async fn entered(runtime: &ConnectionRuntime) -> (ExecutionGate<'_>, audit::OutcomeGuard)
```

Seventeen call sites become one line each and every test's first line becomes its
actual subject. The two sites that pass a non-default token or sink keep the explicit
call — they are testing the argument they vary, and inlining it is the point.

**Narrowed from revision 2**, which proposed one closure-taking helper per
execute/explain pair (three pairs, ~136 lines). That fixes less, adds an indirection
between the reader and the assertion, and leaves the same nine-line block in every
other test in the file. A plain fixture is simpler and covers more.

Apply the same fixture treatment to `schema.rs:777/808`
(`{describe,search}_propagates_every_schema_error_with_its_public_code`, 29 lines
each), keeping two named `#[test]` functions rather than a loop over a slice — a
failing test should name the tool it failed for.

*Effort: half a day. Lines: −150.*

### 5.4 Container-test fixtures — `fn context` ×10, `fn metadata` ×6

`fn context` is byte-identical across ten files: both adapters' `tests/corpus.rs` and
all four `container_tests/*` modules in each. `fn metadata` appears three times per
adapter.

`context`/`metadata` go to each adapter's `container_tests.rs` root, which every
`container_tests/*` submodule already imports from — a one-file change per adapter, no
cross-crate machinery. `fn source_files` (26 lines, identical in `adapter_rules.rs` ×2
and `newtype_rules.rs`) goes to `warden-guards` as part of §2.1.

*Effort: 2 h. Lines: −120.*

### 5.5 Two `tempdir()` helpers in `warden-config` never clean up

`crates/warden-config/src/secrets.rs:84` and `resolve.rs:356` each create a directory
under `std::env::temp_dir()` and return it. Neither removes it, so every
`cargo test -p warden-config` leaves directories behind.

**Fix.** Give the two helpers a `TempDir` newtype with a `Drop` that calls
`remove_dir_all`, in whichever of the two modules ends up owning it — they are in the
same crate, so this is one type and two call sites. Do not add `tempfile`; the
hand-rolled version is eight lines and the workspace's dependency budget is
deliberate.

**Corrected from revision 2**, which claimed eight duplicated temp-directory helpers
of which "the other six leak their directories into `/tmp` on every test run". The
opposite is true. Six of the eight already clean up —
`tests/architecture.rs:1330` (`remove_dir_all` in `Drop`), `tests/cli.rs:143/187/236`
(explicit removal at each call site), `tests/mcp_database.rs:166/197` (`Drop`),
`crates/warden-mysql/src/container_tests.rs:110` (`Drop`), `src/audit/file.rs:474`
(`Drop`) — and only these two do not. The eight are also not one helper: they are a
temp *file* path, a config-file writer, a source-tree fixture, a container CA copy and
two temp directories, sharing three lines of `temp_dir().join(format!(...))` idiom and
nothing else. Unifying them behind one type would have replaced five purpose-named
fixtures with one general one, which is worse code for about twenty lines.

*Effort: 20 min. Lines: +10, and it stops leaking.*

### 5.6 `corpus.rs`'s `check` harness — 71 lines, twice

`crates/warden-{mysql,postgres}/tests/corpus.rs` share a 71-line `check` function that
runs one `Case` against the analyser and then against a default `PolicyEngine`. Only
the analyser type and dialect differ.

This one is worth **leaving duplicated**. The corpus is the security fixture set, and
`docs/testing.md` §3.3 requires reviewing every row on a `sqlparser` upgrade. A shared
harness would put a level of indirection between a reviewer and what a row asserts,
which is the property the file exists to have. Recorded so it is a decision.

### 5.7 What the test suite gets right

- **1 050 tests, zero `#[ignore]`.** Everything runs in CI, on the fast gate and the
  container gate, with coverage floored at 95 % lines under `--all-features` so the
  container paths count.
- **The corpus tests** are the right shape: declarative rows carrying the whole
  expected verdict — root kind, nested kinds, objects, functions, risks, *and* the
  default engine's `DenyCode` — so one row proves both what the analyser saw and what
  the agent would be told. Rows asserting a parse *failure* are deliberate upgrade
  alarms.
- **`#[tokio::test(start_paused = true)]`** is used consistently for deadline and
  queue-wait tests.
- **Negative controls exist.** `the_scans_are_alive`, the four
  `driver_surface_scan_*` tests, and
  `the_scans_detect_the_violations_they_exist_to_catch` test the guards themselves.
  That is rare, and it is what makes §1.4 a fixable gap rather than a systemic one.
- **Container tests prove the database role refuses a write**, not only that policy
  does — the half of `AGENTS.md`'s rule most projects skip.

Substantive test gaps found: no assertion on the audit file's permission bits (§1.2),
no behavioural assertion that the two adapters share a nesting bound (§4.4), no
per-crate build in CI (§1.1), and no guard that every MCP tool runner is contained by
`run_in_task` (§4.3).

---

## 6. Execution order

Sequenced so each phase is independently shippable and the risky items land after the
guards that would catch a mistake in them.

| Phase | Items | Effort | Line delta |
|---|---|---|---|
| **1 — Defects** | 1.1 mysql feature + CI loop · 1.2 audit mode · 1.3 DSN zeroization · 1.5 redaction doc · 1.7 gitignore | ~1 day | +42 |
| **2 — Guards** | 2.1 `warden-guards` · 1.4 adapter guards to `syn` · 2.2 allow ordering + guard · 4.3 `run_in_task` guard | 3–4 days | −645 to −845 |
| **3 — Small consistency** | 1.6 `guarded` · 2.3 `resolve` · 2.4 redaction folding · 2.5 `sha2` decision · 4.4 `RECURSION_LIMIT` | ~1.5 days | −35 |
| **4 — Audit crate** | 3 `warden-audit` + ADR + `AuditMode` to `warden-core` | 1.5 days | +120 (guard) |
| **5 — Service dedup** | 4.1 `ServiceCore` + `Preflight` | 2 days | −280 to −380 |
| **6 — Test fixtures** | 5.1 `warden-ports/testing` · 5.2 `ask_every_callsite` · 5.3 gate fixture · 5.4 container fixtures · 5.5 `TempDir` | 3–4 days | −1 240 to −1 440 |

**Total: ~11–14 days, −2 000 to −2 500 lines** against 58 089, with no change to any
security invariant.

Phases 1 and 3 are safe in any order, except that **1.1 and 1.6 touch the same stale
assumption** about tokio's `macros` feature and should be one commit or 1.1 first.
**Phase 2 must precede phases 4, 5 and 6** — the guards are what prove those refactors
did not widen a public surface, introduce a wildcard arm, or lose a containment call.

Each phase needs, per `AGENTS.md`: `cargo fmt --all --check`, `taplo fmt --check`,
`cargo clippy --workspace --all-targets --all-features -- -D warnings`,
`cargo test --workspace`, `cargo deny --workspace check`, the new per-crate build loop,
and the container gate for phases 3, 4 and 5.

**ADRs required before code** (`AGENTS.md` process rule 4). ADR-0045 is the highest in
`docs/adr/`, so:

- **ADR-0046 — mechanical guards share one AST implementation** (§2.1), before phase 2.
- **ADR-0047 — the redaction budget bounds the database result** (§1.5), before phase 1.
- **ADR-0048 — the audit sink is an adapter** (§3, covering the crate and the
  `AuditMode` move to `warden-core`), before phase 4.
- **ADR-0049 — port fakes ship behind a testing feature** (§5.1, covering the
  `tracing` edge §5.2 adds and the rule that a test binary installs exactly one
  global subscriber), before phase 6.

---

## 7. Checked and found clean

**SQL and policy.** The `sqlparser` `visitor`-derived walk is exhaustive by
construction; every wildcard arm in `visit.rs` maps to `Unknown`, which every policy
denies. `is_write_kind` is an exhaustive `match` rather than `matches!` specifically so
a new `StatementKind` breaks the build — and the comment explains that the wildcard
scanner could not see a `matches!`. CTE subtraction is documented as deliberately blunt
and errs toward reporting fewer objects. The MySQL token guard runs on the token
stream, so a string literal or comment can neither trip nor satisfy it.
Schema-qualified function calls bypass the built-in registry, closing the
`schema.now()` laundering path.

**The `explain` string.** `VerifiedExplain` is the only exception to "executed SQL is
analysed SQL"; its single constructor reparses and slice-matches exactly one
`Statement::Explain` with every executing flag false, and both adapters refuse both
`EXPLAIN ANALYZE` spellings.

**Secrets.** `Dsn` implements no `Display`, no `AsRef<str>`, no `Serialize`, no
`Clone`, no `Deref`, redacts `Debug` to the dialect alone, and has five `compile_fail`
doctests proving it. Query strings and fragments are refused (ADR-0031). The only
read-back is `expose_password`.

**The MCP boundary.** `crates/warden-mcp/src/error.rs` takes a `PublicErrorCode` and
never a message, so no driver string has a parameter to travel through; the fourteen
sentences are asserted ASCII and placeholder-free. Identity is transport-constructed —
the agent cannot supply a principal, and a client name carrying a newline falls back to
`unknown-client`. `ParameterValue`'s `Deserialize` handles `serde_json`'s
`arbitrary_precision` number protocol correctly and refuses an integer-syntax token
that fits neither `i64` nor `u64` rather than rounding it.

**Observability.** `the_documented_span_tree_is_the_one_the_workspace_creates` parses
every `info_span!`/`debug_span!`/… in the workspace and asserts set equality against
`docs/operations.md` §10.1, so a span added, renamed or removed without the document
fails the build. The parser's one documented limitation — a span name must be a string
literal inside the macro, not a variable — is itself pinned by test.

**Resource bounds.** `ResultBuilder` enforces rows, per-value bytes and total bytes
*while rows arrive*. `json_bytes` is computed rather than serialised, walks
iteratively, accounts for JSON escaping, and is pinned against the serialiser's own
output by test. `MAX_ARRAY_DEPTH` and the parser recursion limit are both explicit. The
schema cache has a TTL, a hard 512-entry ceiling that refuses rather than evicts, and
recovers from a poisoned lock instead of propagating a panic.

**Process.** `unsafe_code = "forbid"`, `missing_docs`, `unwrap_used`, `expect_used`,
`print_stdout`, `dbg_macro`, `todo`, `unimplemented` and `disallowed_methods` are
denied workspace-wide; the only `#[allow]`s are the sanctioned test-module pair (127
files, plus the 9 §2.2 normalises) and four `#![allow(dead_code)]`, one per
`testing.rs`. Every panic in the workspace is inside a `#[cfg(test)]` module. CI pins
third-party actions to commit SHAs and runs `cargo deny` with a feature ban on
`sqlx/any` and `sqlx/migrate`. The panic hook records location, thread and payload
*type*, never the payload.

---

## 8. Method: what each pass missed, and why

Recorded so the gaps do not recur, and so a later reviewer knows which methods have
actually been run against this tree.

**Revision 1 used:** file-level diffing between paired files (`mysql` vs `postgres`),
grep sweeps for known anti-patterns, full reads of the security-critical path,
dependency-graph inspection, and a clippy run. It missed duplication that is not
file-shaped, and it never asked whether a module was in the right crate.

**Revision 2 added:** token-level clone detection over every `.rs` file including
`#[cfg(test)]` modules, and a module-placement audit against the project's own
port/adapter rule. Those produced §5.2, §5.4, §5.3, the six `guarded` variants, and
§3 — none of which file diffing could surface. It also found that revision 1 had
never built anything except the whole workspace (§1.1).

**Revision 3 added the method both earlier passes lacked: executing the proposed
remedies against the tree instead of only the findings.** Six did not survive.

- **§1.1's CI loop would have failed on its first run.** `cargo check -p warden --lib`
  errors with `no library targets found in package 'warden'` — the root package is a
  binary. Verified, and the flag is dropped.
- **§4.1's `preflight` could not compile.** `ExecutionGate<'a>` borrows the
  `ConnectionRuntime`, and `ConnectionRegistry::get` returns an owned `Arc`, so the
  proposed signature returned a borrow of a local. Split into `preflight` + `gate`.
- **§4.3's `dispatch` could not compile either** (a use after move, and an unused
  output type parameter), and once fixed it was not worth having. Replaced by the
  guard the finding actually calls for. Its stated justification was also wrong: the
  span guard fails loudly, it does not fail open.
- **§5.5 was inverted.** Six of the eight "leaking" helpers already clean up; two do
  not, and the eight are five different things. Scope cut from half a day to twenty
  minutes.
- **§1.3 part 2 rested on a false premise** — `fs::read_to_string` pre-reserves from
  file metadata. Withdrawn.
- **§3 sent `AuditMode` to the wrong crate.** The `TlsMode` precedent it cited lives
  in `warden-core`, which already has `serde`; `warden-ports` does not, and the port
  crate is the wrong place for a serialization format.
- **§5.2's fix would have panicked nondeterministically.** It proposed installing one
  global default subscriber per test binary. `warden-service`'s lib test binary
  already installs one at `src/audit.rs:335` and `.unwrap()`s the result, and
  `set_global_default` succeeds once per process — so which test ran first would have
  decided whether the suite passed. Revision 2 had counted three copies of one
  function; there are three *different techniques* across three crates, and finding
  the collision required reading what each one scopes rather than what each one
  duplicates. Its replacement was also wrong on its own terms: a `ThreadId`-keyed
  capture layer is correct only while every test stays a current-thread
  `#[tokio::test]`, and it cannot express the fault injection at `schema.rs:390` at
  all.

Two smaller corrections: §1.6's `finish` does not collapse (its error type differs per
module), and §2.2's guard spec named three `dead_code` allows where there are four.

**A principle the corrections converged on**, worth stating because three separate
items reached it independently (§4.2, §4.3, §4.4, §5.6): in this codebase, duplication
between deliberately parallel structures is not debt — it is what makes a security
boundary reviewable side by side. The right response to unwatched duplication is a
mechanical guard, not an abstraction. Every remaining deduplication item in this plan
removes ceremony (§5.3), shared collaborators (§4.1), or hand-rolled machinery (§2.1),
never a parallel structure.

**Methods still not run against this tree**, listed so the gap is known: fuzzing the
analyser beyond the existing `arbitrary_bytes_never_panic_the_analyzer` corpus test;
`cargo-mutants` or equivalent mutation testing against the policy engine, which is the
one component where "the tests pass" and "the tests would catch a regression" are
genuinely different claims; and a review of the `docs/` set for drift against the code
(spot checks found none — SECURITY.md's "32 invariants" matches SPEC §6 exactly — but
it was not systematic).
