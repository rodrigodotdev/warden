//! Mechanical guards for rules the Rust compiler cannot express.
//!
//! AGENTS.md listed "a `sqlparser` AST type appears in an adapter's public
//! signature" as enforced by manual review, with tooling planned for Milestone 4.
//! This is that tooling. It runs as a separate crate so it sees exactly the surface
//! `warden-service` will see.
//!
//! Every scan reads the parsed tree through `warden-guards` rather than the file's
//! text (ADR-0046). The predecessor cut each file at the first line reading exactly
//! `#[cfg(test)]`, on the assumption that it introduced the trailing `mod tests`. In
//! this crate it does not — `src/connection.rs:305` carries a `#[cfg(test)] impl`
//! a hundred and fifty-three lines above the real test module — so the tail of that
//! file was outside every scan below, and no scan could have said so. There is no
//! cutoff now:
//! `production_items` prunes on parsed attributes, at every level.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use warden_guards::{
    Finding, TraitImpls, aliases_of, exported_names, literals, macro_calls, method_calls,
    production_items, public_signature_types, source_files, string_literals, wildcard_arms,
};

/// The only files allowed to declare a `pub` item. Everything else is internal.
const PUBLIC_FILES: &[&str] = &[
    "lib.rs",
    "analyzer.rs",
    "connection.rs",
    "error.rs",
    "execute.rs",
    "explain.rs",
    "inspector.rs",
];

/// Type names that would carry a parser AST across the crate boundary.
const AST_TYPES: &[&str] = &[
    "sqlparser",
    "Statement",
    "Expr",
    "ObjectName",
    "ObjectNamePart",
    "Ident",
    "TableFactor",
    "SetExpr",
    "Visitor",
    "VisitorMut",
    "Parser",
    "ParserError",
    "Token",
    "Tokenizer",
];

/// Type names that would carry a driver handle across the crate boundary.
///
/// These match whole path segments, so `PgConnectionPools` is not `PgConnection` and
/// `PoolSettings` is not `Pool`. That precision is why the list can name `Pool` at all.
const DRIVER_TYPES: &[&str] = &[
    "sqlx",
    "Postgres",
    "PgPool",
    "PgPoolOptions",
    "PgConnectOptions",
    "PgConnection",
    "PgSslMode",
    "PgRow",
    "Pool",
    "PoolOptions",
    "PoolConnection",
    "Transaction",
    "Executor",
];

/// `warden-core` security enums. A wildcard over one of these must not compile away a
/// new variant (ADR-0021).
const GUARDED_ENUMS: &[&str] = &[
    "StatementKind",
    "RiskFlag",
    "FunctionClassification",
    "ObjectKind",
];

fn crate_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn sources() -> Vec<PathBuf> {
    source_files(&crate_src())
}

fn is_public_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| PUBLIC_FILES.contains(&name))
}

fn file(name: &str) -> PathBuf {
    crate_src().join(name)
}

/// Renders findings for an assertion message, one per line.
fn report(path: &Path, findings: &[Finding]) -> Vec<String> {
    findings
        .iter()
        .map(|finding| format!("  {}:{}: {}", path.display(), finding.line, finding.detail))
        .collect()
}

#[test]
fn only_the_analyzer_and_the_crate_root_export_anything() {
    let mut violations = Vec::new();
    for path in sources() {
        if is_public_file(&path) {
            continue;
        }
        violations.extend(report(&path, &exported_names(&production_items(&path))));
    }

    assert!(
        violations.is_empty(),
        "these internal items are exported:\n{}\n\n\
         Keeping the crate's public surface to the seven reviewed files is what \
         makes \"no parser AST and no driver handle leaves the adapter\" checkable \
         at all (ADR-0007, ADR-0005). Use `pub(crate)`.",
        violations.join("\n")
    );
}

#[test]
fn no_public_signature_names_a_parser_type() {
    // `TraitImpls::Included`: Rust forbids `pub` inside a trait-impl block, so
    // `impl QueryAnalyzer for PostgresAnalyzer`'s methods — the actual public contract
    // `warden-service` calls — never write `pub` and would be invisible to a
    // visibility-gated scan. The predecessor approximated this by reading every line of
    // the public files; reading the signatures themselves is the same intent without
    // the collateral, so a doc comment or a local binding that happens to name
    // `Statement` no longer has to be reasoned about.
    let banned: BTreeSet<&str> = AST_TYPES.iter().copied().collect();
    let mut violations = Vec::new();
    for path in sources().into_iter().filter(|path| is_public_file(path)) {
        let items = production_items(&path);
        let named: Vec<Finding> = public_signature_types(&items, TraitImpls::Included)
            .into_iter()
            .filter(|finding| banned.contains(finding.detail.as_str()))
            .collect();
        violations.extend(report(&path, &named));
    }

    assert!(
        violations.is_empty(),
        "a `sqlparser` type appears in the crate's public surface:\n{}\n\n\
         SPEC section 6, invariant 28 and ADR-0007 keep parser ASTs inside adapter \
         crates; that is the seam that lets a future adapter replace `sqlparser` \
         without touching MCP, core, policy, or audit models. Trait-impl methods are \
         included, because `QueryAnalyzer::analyze` is public without ever writing \
         the word `pub`.",
        violations.join("\n")
    );
}

#[test]
fn no_public_signature_names_a_driver_type() {
    // `TraitImpls::Excluded`, unlike the parser scan above. A driver type could only
    // reach a trait-impl signature if a `warden-ports` trait named one, and
    // `warden-ports` cannot depend on `sqlx` at all (`tests/architecture.rs`). The
    // narrower scope is what lets `pub(crate) fn agent(&self) -> &PgPool` — the
    // accessor that exists precisely so the type stays inside — live in a public file.
    //
    // `aliases_of` is what keeps the ban from being one `use sqlx::MySqlPool as P;`
    // away from decorative: it follows import renames and type-alias chains to a fixed
    // point, per file.
    let mut violations = Vec::new();
    for path in sources().into_iter().filter(|path| is_public_file(path)) {
        let items = production_items(&path);
        let banned = aliases_of(&items, DRIVER_TYPES);
        let named: Vec<Finding> = public_signature_types(&items, TraitImpls::Excluded)
            .into_iter()
            .filter(|finding| banned.contains(&finding.detail))
            .collect();
        violations.extend(report(&path, &named));
    }

    assert!(
        violations.is_empty(),
        "a SQLx type appears in the crate's public surface:\n{}\n\n\
         ADR-0005 keeps concrete pools inside the adapter. Nothing above this crate \
         needs a `PgPool`: the composition root builds a `PgConnectionPools`, \
         hands it to the executor, and never names a driver type. Use `pub(crate)`.",
        violations.join("\n")
    );
}

#[test]
fn no_wildcard_arm_matches_a_warden_core_security_enum() {
    // Wildcards over `sqlparser` enums are required (AGENTS.md, "Modeling") and map to
    // `Unknown`. Wildcards over a `warden-core` security enum are forbidden: a new
    // variant must break this build (ADR-0021).
    //
    // The two are told apart by the *sibling* arms of the same `match`. The predecessor
    // read the immediately preceding line and documented the blind spot that follows
    // from it: an arm whose body is a braced block leaves a bare `}` on that line, with
    // the enum name several lines up, and neither it nor a whole-line scan saw that
    // shape. Every named pattern in the `match` is available here, so the shape of an
    // arm's body cannot hide what is being matched.
    let mut violations = Vec::new();
    for path in sources() {
        for arm in wildcard_arms(&production_items(&path)) {
            let over_guarded_enum = arm.sibling_patterns.iter().any(|pattern| {
                GUARDED_ENUMS
                    .iter()
                    .any(|enumeration| pattern.contains(&format!("{enumeration} ::")))
            });
            if over_guarded_enum {
                violations.push(format!(
                    "  {}:{}: catch-all over `{}`",
                    path.display(),
                    arm.line,
                    arm.subject
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "a catch-all arm covers a `warden-core` security enum:\n{}\n\n\
         Adding a variant there must break this crate's build, not slip through a \
         wildcard (ADR-0021).",
        violations.join("\n")
    );
}

/// Calls that would read a whole result into memory before any bound applied.
const BUFFERING_FETCHES: &[&str] = &["fetch_all", "fetch_one", "fetch_optional"];

#[test]
fn agent_sql_is_never_read_into_memory_before_it_is_bounded() {
    // `docs/operations.md` section 6.6: the row, value, and byte budgets apply while
    // rows arrive. A buffering call spends the memory first and truncates afterwards,
    // and the difference is invisible in a passing functional test.
    //
    // Warden's own `SELECT pg_backend_pid()` is finite and single-row, so `fetch_one`
    // is correct there and wrong only for agent SQL. That call is exempted by its
    // receiver, which names `pg_backend_pid` in the very expression that buffers;
    // reading the receiver rather than the line is what makes the exemption immune to
    // how rustfmt happens to wrap the call.
    let path = file("execute.rs");
    let items = production_items(&path);
    for buffering in BUFFERING_FETCHES {
        for call in method_calls(&items, buffering) {
            assert!(
                call.detail.contains("pg_backend_pid"),
                "src/execute.rs:{} buffers a result with {buffering} on `{}`",
                call.line,
                call.detail
            );
        }
    }
    assert!(
        !method_calls(&items, "fetch").is_empty(),
        "src/execute.rs never calls `.fetch`, so the ban above passed on an absence"
    );
}

/// Whether the control-pool cancellation statement binds its backend pid.
///
/// The SQL literal alone cannot satisfy this: what is checked is that `.bind` is called
/// on the expression that built `pg_cancel_backend($1)`, so a statement that names the
/// function and never binds anything is a failure. The predecessor followed the fluent
/// chain line by line to its terminating semicolon; the chain is one expression in the
/// tree, so there is nothing left to follow.
fn binds_the_cancellation_pid(items: &[syn::Item]) -> bool {
    method_calls(items, "bind")
        .iter()
        .any(|call| call.detail.contains("pg_cancel_backend"))
}

#[test]
fn cancellation_guard_rejects_a_pidless_statement() {
    let bound = warden_guards::production_items_of(
        r#"
        fn cancel(backend_pid: i32) {
            let _ = sqlx::query("SELECT pg_cancel_backend($1)")
                .bind(backend_pid)
                .execute(self.pools.control());
        }
        "#,
    );
    let pidless = warden_guards::production_items_of(
        r#"
        fn cancel() {
            let _ = sqlx::query("SELECT pg_cancel_backend($1)")
                .execute(self.pools.control());
        }
        "#,
    );

    assert!(binds_the_cancellation_pid(&bound));
    assert!(!binds_the_cancellation_pid(&pidless));
}

#[test]
fn execute_rs_interpolates_nothing_at_all() {
    // PostgreSQL has no audited exception to the bind-only rule: its cancellation binds
    // a pid and its deadline binds a value (`docs/operations.md` section 6.3).
    let items = production_items(&file("execute.rs"));
    for call in macro_calls(&items) {
        assert!(
            call.name != "format",
            "src/execute.rs:{} interpolates with format!; PostgreSQL has no audited \
             exception to the bind-only rule",
            call.line
        );
    }
    assert!(
        binds_the_cancellation_pid(&items),
        "src/execute.rs no longer binds the cancellation pid into \
         `pg_cancel_backend($1)`"
    );
}

#[test]
fn executor_closes_the_named_agent_statement_after_each_request() {
    let items = production_items(&file("execute.rs"));
    assert!(
        literals(&items)
            .iter()
            .any(|literal| literal.detail.contains("DEALLOCATE ALL")),
        "src/execute.rs does not close the temporary named agent statement"
    );
}

#[test]
fn explain_rs_interpolates_nothing_at_all() {
    // The strict rule this crate already applies to `execute.rs`: its cancellation
    // binds a pid and its deadline binds a value, and the plan path binds its
    // parameters, so nothing here needs `format!` (`docs/operations.md` section 6.3).
    for call in macro_calls(&production_items(&file("explain.rs"))) {
        assert!(
            call.name != "format",
            "src/explain.rs:{} interpolates with format!; PostgreSQL's plan path needs \
             no exception and gaining one needs its own review",
            call.line
        );
    }
}

/// Every `format!` invocation in `path`, with the literals it interpolates into.
fn formats(path: &Path) -> Vec<(usize, Vec<String>)> {
    macro_calls(&production_items(path))
        .into_iter()
        .filter(|call| call.name == "format")
        .map(|call| (call.line, string_literals(call.tokens)))
        .collect()
}

#[test]
fn the_only_format_in_plan_rs_builds_the_non_executing_prefix() {
    // The other side of the same rule. `plan.rs` interpolates agent SQL after a prefix,
    // which *is* SPEC section 6, invariant 19's exception; the compensating control is
    // the reparse in the same file. A second, unrelated `format!` here would be a new
    // exception rather than this one.
    let path = file("plan.rs");
    let items = production_items(&path);
    let formats = formats(&path);
    for (line, literals) in &formats {
        assert!(
            literals
                .iter()
                .any(|text| text.contains("{EXPLAIN_PREFIX}"))
                || literals.is_empty(),
            "src/plan.rs:{line} interpolates with format! outside the verified \
             EXPLAIN prefix"
        );
    }
    assert!(
        !formats.is_empty(),
        "src/plan.rs builds no prefixed string at all"
    );

    // The constant itself, read as a constant rather than as a line of text: the value
    // is what matters, and `EXPLAIN ANALYZE` runs the statement (SPEC section 6,
    // invariant 11, ADR-0017), so this changes only through a failing test.
    let prefix = items.iter().find_map(|item| match item {
        syn::Item::Const(declaration) if declaration.ident == "EXPLAIN_PREFIX" => {
            Some(declaration.expr.as_ref())
        }
        _ => None,
    });
    let Some(syn::Expr::Lit(literal)) = prefix else {
        panic!("src/plan.rs declares no `EXPLAIN_PREFIX` string constant");
    };
    let syn::Lit::Str(value) = &literal.lit else {
        panic!("`EXPLAIN_PREFIX` is not a string literal");
    };
    assert_eq!(value.value(), "EXPLAIN (FORMAT JSON) ");

    assert!(
        declares_function(&items, "verify"),
        "src/plan.rs declares no verification, so the prefix would reach the server \
         unchecked (docs/mcp.md section 3.2)"
    );
}

/// Whether `items` declares a function of this name, free or associated.
fn declares_function(items: &[syn::Item], name: &str) -> bool {
    items.iter().any(|item| match item {
        syn::Item::Fn(function) => function.sig.ident == name,
        syn::Item::Impl(block) => block.items.iter().any(
            |impl_item| matches!(impl_item, syn::ImplItem::Fn(method) if method.sig.ident == name),
        ),
        _ => false,
    })
}

#[test]
fn a_plan_is_read_as_one_row_and_bounded_before_it_is_returned() {
    // `EXPLAIN FORMAT=JSON` is one row of one column, so `fetch_one` is right here and
    // `docs/operations.md` section 6.6's streaming rule does not apply. Pinning the
    // absence of `fetch_all` and `.fetch(` keeps that from widening into an unbounded
    // read, and pinning the `validate()` call keeps the byte budget of
    // `docs/data-model.md` section 10 from being dropped in a refactor.
    let items = production_items(&file("explain.rs"));
    for banned in ["fetch_all", "fetch"] {
        let calls = method_calls(&items, banned);
        assert!(
            calls.is_empty(),
            "src/explain.rs:{} reads a plan as a stream or a vector",
            calls[0].line
        );
    }
    assert!(
        !method_calls(&items, "fetch_one").is_empty(),
        "src/explain.rs never fetches anything, so the ban above passed on an absence"
    );
    assert!(
        !method_calls(&items, "validate").is_empty(),
        "src/explain.rs returns a plan without bounding it"
    );
}

#[test]
fn the_scans_are_alive() {
    // A scan that finds nothing because its inputs are empty passes forever.
    assert!(
        sources().iter().any(|path| path.ends_with("analyzer.rs")),
        "the analyzer module moved; the public-surface scan needs updating"
    );
    assert!(
        sources().len() >= 7,
        "fewer modules than Milestone 4 shipped; the scans may be reading the wrong \
         directory"
    );

    // The blind spot that produced ADR-0046: `connection.rs` carries a `#[cfg(test)]`
    // item well above its `mod tests`, and everything below it used to be invisible.
    let connection = production_items(&file("connection.rs"));
    assert!(
        !connection.is_empty(),
        "connection.rs has no production items, so every scan over it is vacuous"
    );

    // Each scan's detection primitive, exercised on a fixture rather than on the crate,
    // so a passing suite means the scans can still fail.
    let fixture = warden_guards::production_items_of(
        r#"
        use sqlx::PgPool as Handle;
        type Alias = Handle;
        pub struct Leaked {
            pub pool: Alias,
        }
        pub fn parser_leak(statement: &sqlparser::ast::Statement) {}
        pub trait Contract {
            fn analyze(&self, s: &Statement) -> Result<Foo, Bar>;
        }
        fn classify(kind: StatementKind) {
            match kind {
                StatementKind::Select => {}
                _ => {}
            }
        }
        "#,
    );

    let driver_banned = aliases_of(&fixture, DRIVER_TYPES);
    assert!(
        public_signature_types(&fixture, TraitImpls::Excluded)
            .iter()
            .any(|finding| driver_banned.contains(&finding.detail)),
        "a driver type reached through an import rename and a type alias must be caught"
    );

    let ast_banned: BTreeSet<&str> = AST_TYPES.iter().copied().collect();
    assert!(
        public_signature_types(&fixture, TraitImpls::Included)
            .iter()
            .any(|finding| ast_banned.contains(finding.detail.as_str())),
        "a parser type in a trait method signature, which never starts with `pub`, \
         must still be caught"
    );

    let arms = wildcard_arms(&fixture);
    assert_eq!(arms.len(), 1, "the catch-all scan found no arm to judge");
    assert!(
        arms[0]
            .sibling_patterns
            .iter()
            .any(|pattern| pattern.contains("StatementKind ::")),
        "a catch-all whose siblings name a warden-core enum must be recognisable"
    );

    // And the direction that must not fire: a catch-all over a `sqlparser` enum, whose
    // sibling patterns name no warden-core type, is required rather than forbidden.
    let permitted = warden_guards::production_items_of(
        r#"
        fn visit(expression: Expr) {
            match expression {
                Expr::Identifier(_) => {}
                _ => {}
            }
        }
        "#,
    );
    let permitted_arms = wildcard_arms(&permitted);
    assert_eq!(permitted_arms.len(), 1);
    assert!(
        !permitted_arms[0]
            .sibling_patterns
            .iter()
            .any(|pattern| GUARDED_ENUMS
                .iter()
                .any(|guarded| pattern.contains(&format!("{guarded} ::")))),
        "a wildcard over a sqlparser enum must not be flagged"
    );
}
