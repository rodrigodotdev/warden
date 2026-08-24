//! The PostgreSQL security corpus.
//!
//! `docs/testing.md` section 3 requires easy-to-review declarative fixtures with the
//! expected parse, root kind, nested kinds, tables, functions, risks, and default
//! policy outcome — and requires that security expectations not be hidden inside one
//! large procedural test. Each row below is one statement and its whole expected
//! verdict; each themed slice runs under its own test.
//!
//! `root_kind: None` is how a row says "the grammar rejects this and the analyzer
//! produces nothing at all"; every other field is then unused and the row is judged
//! entirely by the code its `AnalyzeError` converts to.
//!
//! Every row runs twice: once against the analyzer, and once through the default
//! `PolicyEngine` that a production deployment builds, so a row records both what
//! the analyzer saw and what an agent would actually be told.
//!
//! `docs/testing.md` section 3.3: upgrading `sqlparser` requires running this whole
//! file and reviewing every new AST variant. Several rows deliberately assert a
//! parse **failure**; if an upgrade starts parsing one, this file fails, which is
//! the intended alarm.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use warden_core::analysis::{FunctionClassification, RiskFlag, StatementKind};
use warden_core::connection::{ConnectionMetadata, Environment};
use warden_core::context::RequestContext;
use warden_core::dialect::Dialect;
use warden_core::limits::ExecutionLimits;
use warden_core::query::{InputLimits, QueryRequest};
use warden_policy::{DenyCode, PolicyEngine, PolicySettings};
use warden_ports::analyzer::QueryAnalyzer;
use warden_postgres::PostgreSqlAnalyzer;

/// What the analyzer must say about one statement, and what the agent must be told.
struct Case {
    /// The statement, exactly as an agent would send it.
    sql: &'static str,
    /// The root statement kind, or `None` when analysis produces nothing at all.
    root_kind: Option<StatementKind>,
    /// Kinds found inside the root, in visit order.
    nested_kinds: &'static [StatementKind],
    /// `qualified_name()` of every object, in order, after CTE subtraction.
    objects: &'static [&'static str],
    /// Every function name, in order, with its classification.
    functions: &'static [(&'static str, FunctionClassification)],
    /// Every risk, in any order.
    risks: &'static [RiskFlag],
    /// The single code the default engine reports, or `None` when it authorizes.
    verdict: Option<DenyCode>,
}

const READS: &[Case] = &[
    Case {
        sql: "SELECT id, total FROM orders WHERE customer_id = $1",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["orders"],
        functions: &[],
        risks: &[],
        verdict: None,
    },
    Case {
        sql: "SELECT o.id FROM orders o JOIN customers c ON c.id = o.customer_id",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["orders", "customers"],
        functions: &[],
        risks: &[],
        verdict: None,
    },
    Case {
        sql: "SELECT * FROM t1 UNION SELECT * FROM t2",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["t1", "t2"],
        functions: &[],
        risks: &[],
        verdict: None,
    },
    Case {
        sql: "SELECT * FROM (SELECT id FROM inner_t) AS s",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["inner_t"],
        functions: &[],
        risks: &[],
        verdict: None,
    },
    Case {
        sql: "SELECT 1 FROM t WHERE EXISTS (SELECT 1 FROM u)",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["t", "u"],
        functions: &[],
        risks: &[],
        verdict: None,
    },
    Case {
        // The CTE alias is not an object; what it reads is.
        sql: "WITH x AS (SELECT * FROM secrets) SELECT * FROM x",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["secrets"],
        functions: &[],
        risks: &[],
        verdict: None,
    },
    Case {
        // A recursive CTE's self-reference is the CTE, not a base table.
        sql: "WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM t WHERE n < 10) \
              SELECT * FROM t",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: None,
    },
    Case {
        // An unquoted alias folds, so a differently cased reference is still the CTE.
        sql: "WITH Report AS (SELECT * FROM secrets) SELECT * FROM report",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["secrets"],
        functions: &[],
        risks: &[],
        verdict: None,
    },
    Case {
        // A quoted alias does not fold, so `report` is a real relation. PostgreSQL
        // resolves it to a base table, and so must the analyzer; the MySQL
        // analyzer's case-insensitive subtraction would wrongly drop it.
        sql: r#"WITH "Report" AS (SELECT * FROM secrets) SELECT * FROM report"#,
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["secrets", "report"],
        functions: &[],
        risks: &[],
        verdict: None,
    },
    Case {
        sql: "SELECT count(*), max(total) FROM orders",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["orders"],
        functions: &[
            ("count", FunctionClassification::KnownSafe),
            ("max", FunctionClassification::KnownSafe),
        ],
        risks: &[],
        verdict: None,
    },
    Case {
        // Qualifying a built-in by `pg_catalog` is idiomatic PostgreSQL and reaches
        // the registry (ADR-0029). The MySQL analyzer denies every qualified call.
        sql: "SELECT pg_catalog.count(1) FROM orders",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["orders"],
        functions: &[("count", FunctionClassification::KnownSafe)],
        risks: &[],
        verdict: None,
    },
    Case {
        // A relation called with arguments is a function call and a relation name.
        sql: "SELECT * FROM generate_series(1, 10)",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["generate_series"],
        functions: &[("generate_series", FunctionClassification::KnownSafe)],
        risks: &[],
        verdict: None,
    },
    Case {
        // JSON operators reach named `BinaryOperator` variants and say nothing.
        sql: "SELECT data -> 'a' ->> 'b' FROM events",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["events"],
        functions: &[],
        risks: &[],
        verdict: None,
    },
    Case {
        // A semicolon inside a literal is not a statement separator.
        sql: "SELECT 'a; DROP TABLE t' AS lit",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: None,
    },
    Case {
        // Neither is one inside a dollar-quoted string, PostgreSQL's other spelling.
        sql: "SELECT $$a; DROP TABLE t$$ AS lit",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: None,
    },
    Case {
        sql: "/* leading */ SELECT 1 -- trailing",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: None,
    },
    Case {
        sql: "SELECT * FROM app.orders",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["app.orders"],
        functions: &[],
        risks: &[],
        verdict: None,
    },
    Case {
        // Unquoted identifier case is preserved as written, not folded; folding is
        // policy's job (ADR-0027).
        sql: "SELECT id FROM Orders",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["Orders"],
        functions: &[],
        risks: &[],
        verdict: None,
    },
    Case {
        sql: r#"SELECT * FROM "public"."Users""#,
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["public.Users"],
        functions: &[],
        risks: &[],
        verdict: None,
    },
];

const WRITES: &[Case] = &[
    Case {
        // `Insert.table` is a `TableObject`, not a `TableFactor`, so
        // `pre_visit_table_factor` never sees it — the same shape `warden-mysql`
        // records.
        sql: "INSERT INTO orders (id) VALUES (1)",
        root_kind: Some(StatementKind::Insert),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::WriteStatement],
        verdict: Some(DenyCode::WriteStatement),
    },
    Case {
        sql: "UPDATE orders SET total = 0",
        root_kind: Some(StatementKind::Update),
        nested_kinds: &[],
        objects: &["orders"],
        functions: &[],
        risks: &[RiskFlag::WriteStatement],
        verdict: Some(DenyCode::WriteStatement),
    },
    Case {
        sql: "DELETE FROM orders",
        root_kind: Some(StatementKind::Delete),
        nested_kinds: &[],
        objects: &["orders"],
        functions: &[],
        risks: &[RiskFlag::WriteStatement],
        verdict: Some(DenyCode::WriteStatement),
    },
    Case {
        sql: "TRUNCATE orders",
        root_kind: Some(StatementKind::Ddl),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::Ddl],
        verdict: Some(DenyCode::Ddl),
    },
    Case {
        sql: "CREATE TABLE t (a INT)",
        root_kind: Some(StatementKind::Ddl),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::Ddl],
        verdict: Some(DenyCode::Ddl),
    },
    Case {
        sql: "CREATE TABLE t2 AS SELECT * FROM t1",
        root_kind: Some(StatementKind::Ddl),
        nested_kinds: &[],
        objects: &["t1"],
        functions: &[],
        risks: &[RiskFlag::Ddl],
        verdict: Some(DenyCode::Ddl),
    },
    Case {
        sql: "COPY orders FROM '/tmp/x'",
        root_kind: Some(StatementKind::Copy),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::WriteStatement],
        verdict: Some(DenyCode::WriteStatement),
    },
    Case {
        // `COPY ... TO PROGRAM` runs a shell command as the server account. It is a
        // read of `orders` and an arbitrary execution; `Copy` is a write kind, so
        // both halves are denied by one rule.
        sql: "COPY (SELECT * FROM orders) TO PROGRAM 'sh -c whoami'",
        root_kind: Some(StatementKind::Copy),
        nested_kinds: &[],
        objects: &["orders"],
        functions: &[],
        risks: &[RiskFlag::WriteStatement],
        verdict: Some(DenyCode::WriteStatement),
    },
    Case {
        // PostgreSQL's `SELECT INTO` creates a relation.
        sql: "SELECT * INTO backup FROM orders",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["orders"],
        functions: &[],
        risks: &[RiskFlag::SelectInto],
        verdict: Some(DenyCode::Ddl),
    },
    Case {
        // The `INTO` sits on the left arm of a set operation, where reading only
        // `Query::body` would miss it.
        sql: "SELECT a INTO t2 FROM t1 UNION SELECT b FROM t3",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["t1", "t3"],
        functions: &[],
        risks: &[RiskFlag::SelectInto],
        verdict: Some(DenyCode::Ddl),
    },
];

/// The shape `docs/security.md` section 6.3 exists for.
const DATA_MODIFYING_CTES: &[Case] = &[
    Case {
        // `WriteStatement` precedes `NestedWrite` in `DenyCode`'s declaration order,
        // so that is the code the agent hears; both denials are still recorded.
        sql: "WITH c AS (DELETE FROM orders RETURNING *) SELECT * FROM c",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[StatementKind::Delete],
        objects: &["orders"],
        functions: &[],
        risks: &[RiskFlag::WriteStatement, RiskFlag::DataModifyingCte],
        verdict: Some(DenyCode::WriteStatement),
    },
    Case {
        sql: "WITH c AS (INSERT INTO orders VALUES (1) RETURNING *) SELECT * FROM c",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[StatementKind::Insert],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::WriteStatement, RiskFlag::DataModifyingCte],
        verdict: Some(DenyCode::WriteStatement),
    },
    Case {
        sql: "WITH c AS (UPDATE orders SET total = 0 RETURNING *) SELECT * FROM c",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[StatementKind::Update],
        objects: &["orders"],
        functions: &[],
        risks: &[RiskFlag::WriteStatement, RiskFlag::DataModifyingCte],
        verdict: Some(DenyCode::WriteStatement),
    },
];

const SHAPE: &[Case] = &[
    Case {
        sql: "SELECT 1; SELECT 2",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[StatementKind::Select],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::MultipleStatements],
        verdict: Some(DenyCode::MultipleStatements),
    },
    Case {
        // A second top-level statement is a root write at depth 1, not a nested one,
        // so `DataModifyingCte` is deliberately absent here.
        sql: "SELECT 1; DELETE FROM orders",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[StatementKind::Delete],
        objects: &["orders"],
        functions: &[],
        risks: &[RiskFlag::MultipleStatements, RiskFlag::WriteStatement],
        verdict: Some(DenyCode::MultipleStatements),
    },
    Case {
        sql: "SHOW search_path",
        root_kind: Some(StatementKind::Show),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: Some(DenyCode::StatementNotAllowed),
    },
    Case {
        sql: "EXPLAIN SELECT 1",
        root_kind: Some(StatementKind::Explain),
        nested_kinds: &[StatementKind::Select],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: Some(DenyCode::StatementNotAllowed),
    },
    Case {
        sql: "EXPLAIN ANALYZE SELECT 1",
        root_kind: Some(StatementKind::Explain),
        nested_kinds: &[StatementKind::Select],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::ExplainAnalyze],
        verdict: Some(DenyCode::StatementNotAllowed),
    },
    Case {
        // The idiomatic PostgreSQL spelling. sqlparser leaves
        // `Statement::Explain::analyze` false here and records the option list
        // separately, so a port of the MySQL check would have missed it (ADR-0017).
        sql: "EXPLAIN (ANALYZE, BUFFERS) SELECT 1",
        root_kind: Some(StatementKind::Explain),
        nested_kinds: &[StatementKind::Select],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::ExplainAnalyze],
        verdict: Some(DenyCode::StatementNotAllowed),
    },
    Case {
        // An option list without `ANALYZE` does not run the query.
        sql: "EXPLAIN (FORMAT JSON) SELECT 1",
        root_kind: Some(StatementKind::Explain),
        nested_kinds: &[StatementKind::Select],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: Some(DenyCode::StatementNotAllowed),
    },
    Case {
        sql: "CALL rebuild_report(1)",
        root_kind: Some(StatementKind::Call),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::StoredRoutine],
        verdict: Some(DenyCode::StatementNotAllowed),
    },
    Case {
        sql: "BEGIN",
        root_kind: Some(StatementKind::TransactionControl),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: Some(DenyCode::StatementNotAllowed),
    },
    Case {
        sql: "VACUUM",
        root_kind: Some(StatementKind::Utility),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: Some(DenyCode::StatementNotAllowed),
    },
    Case {
        // Parses, and names no `Statement` variant `statement.rs` maps. The wildcard
        // must reach `Unknown`, never something permissive.
        sql: "CREATE SERVER s FOREIGN DATA WRAPPER w",
        root_kind: Some(StatementKind::Unknown),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::UnknownConstruct],
        verdict: Some(DenyCode::UnknownConstruct),
    },
];

const SESSION_AND_LOCKING: &[Case] = &[
    Case {
        sql: "SET search_path = app",
        root_kind: Some(StatementKind::SessionControl),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::SessionMutation],
        verdict: Some(DenyCode::SessionMutation),
    },
    Case {
        sql: "SET LOCAL statement_timeout = '1s'",
        root_kind: Some(StatementKind::SessionControl),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::SessionMutation],
        verdict: Some(DenyCode::SessionMutation),
    },
    Case {
        sql: "RESET ALL",
        root_kind: Some(StatementKind::SessionControl),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::SessionMutation],
        verdict: Some(DenyCode::SessionMutation),
    },
    Case {
        sql: "LISTEN alerts",
        root_kind: Some(StatementKind::SessionControl),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::SessionMutation],
        verdict: Some(DenyCode::SessionMutation),
    },
    Case {
        sql: "NOTIFY alerts, 'x'",
        root_kind: Some(StatementKind::SessionControl),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::SessionMutation],
        verdict: Some(DenyCode::SessionMutation),
    },
    Case {
        sql: "SELECT * FROM orders FOR UPDATE",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["orders"],
        functions: &[],
        risks: &[RiskFlag::LockingRead],
        verdict: Some(DenyCode::LockingRead),
    },
    Case {
        sql: "SELECT * FROM orders FOR SHARE",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["orders"],
        functions: &[],
        risks: &[RiskFlag::LockingRead],
        verdict: Some(DenyCode::LockingRead),
    },
    Case {
        // A lock hidden inside a CTE body is still a lock.
        sql: "WITH c AS (SELECT * FROM orders FOR UPDATE) SELECT * FROM c",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["orders"],
        functions: &[],
        risks: &[RiskFlag::LockingRead],
        verdict: Some(DenyCode::LockingRead),
    },
];

const FUNCTIONS: &[Case] = &[
    Case {
        sql: "SELECT pg_sleep(30)",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[("pg_sleep", FunctionClassification::KnownDangerous)],
        risks: &[RiskFlag::DelayFunction],
        verdict: Some(DenyCode::DangerousFunction),
    },
    Case {
        sql: "SELECT pg_advisory_lock(1)",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[("pg_advisory_lock", FunctionClassification::KnownDangerous)],
        risks: &[RiskFlag::AdvisoryLock],
        verdict: Some(DenyCode::DangerousFunction),
    },
    Case {
        sql: "SELECT pg_advisory_xact_lock(1)",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[(
            "pg_advisory_xact_lock",
            FunctionClassification::KnownDangerous,
        )],
        risks: &[RiskFlag::AdvisoryLock],
        verdict: Some(DenyCode::DangerousFunction),
    },
    Case {
        // SPEC section 6, invariant 10. `SequenceMutation` maps to
        // `DenyCode::WriteStatement`, which precedes `DangerousFunction`: advancing
        // a sequence is a write, and the audit record says so.
        sql: "SELECT nextval('orders_id_seq')",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[("nextval", FunctionClassification::KnownDangerous)],
        risks: &[RiskFlag::SequenceMutation],
        verdict: Some(DenyCode::WriteStatement),
    },
    Case {
        sql: "SELECT setval('orders_id_seq', 1)",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[("setval", FunctionClassification::KnownDangerous)],
        risks: &[RiskFlag::SequenceMutation],
        verdict: Some(DenyCode::WriteStatement),
    },
    Case {
        sql: "SELECT pg_read_file('/etc/passwd')",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[("pg_read_file", FunctionClassification::KnownDangerous)],
        risks: &[RiskFlag::FileAccess],
        verdict: Some(DenyCode::DangerousFunction),
    },
    Case {
        // `FileOutput` is a write, like `SequenceMutation`.
        sql: "SELECT lo_export(1, '/tmp/x')",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[("lo_export", FunctionClassification::KnownDangerous)],
        risks: &[RiskFlag::FileOutput],
        verdict: Some(DenyCode::WriteStatement),
    },
    Case {
        sql: "SELECT pg_notify('alerts', 'x')",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[("pg_notify", FunctionClassification::KnownDangerous)],
        risks: &[RiskFlag::SessionMutation],
        verdict: Some(DenyCode::SessionMutation),
    },
    Case {
        sql: "SELECT set_config('search_path', 'evil', false)",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[("set_config", FunctionClassification::KnownDangerous)],
        risks: &[RiskFlag::SessionMutation],
        verdict: Some(DenyCode::SessionMutation),
    },
    Case {
        // A dangerous call nested in a subquery is still found.
        sql: "SELECT * FROM orders WHERE id = (SELECT pg_advisory_lock(1))",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["orders"],
        functions: &[("pg_advisory_lock", FunctionClassification::KnownDangerous)],
        risks: &[RiskFlag::AdvisoryLock],
        verdict: Some(DenyCode::DangerousFunction),
    },
    Case {
        sql: "SELECT my_udf(1) FROM orders",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["orders"],
        functions: &[("my_udf", FunctionClassification::Unknown)],
        risks: &[RiskFlag::UserDefinedFunction],
        verdict: Some(DenyCode::UnknownFunction),
    },
    Case {
        // `count` is on the allowlist, but `public` is not `pg_catalog`, so this is
        // a user-defined function shadowing a safe name and must not inherit its
        // classification (ADR-0029).
        sql: "SELECT public.count(1) FROM orders",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["orders"],
        functions: &[("count", FunctionClassification::Unknown)],
        risks: &[RiskFlag::UserDefinedFunction],
        verdict: Some(DenyCode::UnknownFunction),
    },
    Case {
        // Deliberately unclassified: reads account state.
        sql: "SELECT current_user",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[("current_user", FunctionClassification::Unknown)],
        risks: &[RiskFlag::UserDefinedFunction],
        verdict: Some(DenyCode::UnknownFunction),
    },
    Case {
        // Deliberately unclassified: reports server topology.
        sql: "SELECT version()",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[("version", FunctionClassification::Unknown)],
        risks: &[RiskFlag::UserDefinedFunction],
        verdict: Some(DenyCode::UnknownFunction),
    },
    Case {
        // Reads a sequence rather than advancing it, so `SequenceMutation` would be
        // a false statement; it is denied on the honest code instead.
        sql: "SELECT currval('orders_id_seq')",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[("currval", FunctionClassification::Unknown)],
        risks: &[RiskFlag::UserDefinedFunction],
        verdict: Some(DenyCode::UnknownFunction),
    },
    Case {
        // A quoted name that is already lowercase folds to the same registry entry
        // an unquoted call would: PostgreSQL itself would resolve both to `count`.
        sql: r#"SELECT "count"(1)"#,
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[("count", FunctionClassification::KnownSafe)],
        risks: &[],
        verdict: None,
    },
    Case {
        // A quoted, mixed-case name is a different identifier from `count` and must
        // not launder into `KnownSafe` by being lowercased on the way to the
        // registry. This is the laundering ADR-0029 exists to close, achieved with
        // quote characters instead of a schema qualifier.
        sql: r#"SELECT "Count"(1)"#,
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[("Count", FunctionClassification::Unknown)],
        risks: &[RiskFlag::UserDefinedFunction],
        verdict: Some(DenyCode::UnknownFunction),
    },
];

/// Shapes that exist only in this dialect, or that sqlparser reads unusually.
const DIALECT_HAZARDS: &[Case] = &[
    Case {
        // sqlparser reads the reserved word as the relation. Recording `ONLY` would
        // make the object rules evaluate a relation that does not exist, so the
        // statement is refused instead.
        sql: "SELECT * FROM ONLY orders",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::UnknownConstruct],
        verdict: Some(DenyCode::UnknownConstruct),
    },
    Case {
        // A user-defined operator is a function call under another spelling, and
        // produces no function node at all.
        sql: "SELECT 1 OPERATOR(public.evil) 2",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::UnknownConstruct],
        verdict: Some(DenyCode::UnknownConstruct),
    },
    Case {
        // `UNNEST` in relation position is its own `TableFactor` variant, reached
        // only through the wildcard. A deliberate false positive: `unnest(...)` in
        // expression position is on the allowlist.
        sql: "SELECT * FROM unnest(ARRAY[1, 2])",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::UnknownConstruct],
        verdict: Some(DenyCode::UnknownConstruct),
    },
    Case {
        // A `LATERAL` call is classified as a call, not merely named as a relation:
        // recording only the name would lose `FileAccess`.
        sql: "SELECT * FROM orders, LATERAL pg_read_file('/etc/passwd') f",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["orders", "pg_read_file"],
        functions: &[("pg_read_file", FunctionClassification::KnownDangerous)],
        risks: &[RiskFlag::FileAccess, RiskFlag::UnknownConstruct],
        verdict: Some(DenyCode::DangerousFunction),
    },
    Case {
        // More parts than catalog.schema.name: guessing which slot the extra one
        // belongs to would encode a dialect assumption.
        sql: "SELECT * FROM a.b.c.d",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::UnknownConstruct],
        verdict: Some(DenyCode::UnknownConstruct),
    },
];

/// sqlparser 0.62 rejects these. Each row is an upgrade alarm: if one starts
/// parsing, this file fails and the new AST shape gets reviewed
/// (`docs/testing.md` section 3.3).
const UNPARSEABLE: &[Case] = &[
    Case {
        // A locking read that is denied today only because the grammar cannot read
        // it. `FOR UPDATE` and `FOR SHARE` do parse, so `RiskFlag::LockingRead` has
        // a real producer and this row does not need a token guard (ADR-0028).
        sql: "SELECT * FROM orders FOR NO KEY UPDATE",
        root_kind: None,
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: Some(DenyCode::UnknownConstruct),
    },
    Case {
        sql: "SELECT * FROM orders FOR KEY SHARE",
        root_kind: None,
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: Some(DenyCode::UnknownConstruct),
    },
    Case {
        // Sequence mutation through DDL. If an upgrade starts parsing it, the new
        // `Statement` variant must be classified rather than fall to `Unknown` by
        // accident (SPEC section 6, invariant 10).
        sql: "ALTER SEQUENCE orders_id_seq RESTART WITH 1",
        root_kind: None,
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: Some(DenyCode::UnknownConstruct),
    },
    Case {
        sql: "REFRESH MATERIALIZED VIEW mv",
        root_kind: None,
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: Some(DenyCode::UnknownConstruct),
    },
    Case {
        // An anonymous PL/pgSQL block: arbitrary procedural code inside a string the
        // visitor cannot read. A parser that accepted it would need a decision, not
        // a wildcard.
        sql: "DO $$ BEGIN PERFORM 1; END $$",
        root_kind: None,
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: Some(DenyCode::UnknownConstruct),
    },
    Case {
        sql: "SELECT FROM",
        root_kind: None,
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: Some(DenyCode::UnknownConstruct),
    },
    Case {
        sql: "SELECT 'unterminated",
        root_kind: None,
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: Some(DenyCode::UnknownConstruct),
    },
];

fn request(sql: &str) -> QueryRequest {
    QueryRequest::new(
        "production-postgres".parse().unwrap(),
        sql.to_owned(),
        Vec::new(),
        &InputLimits::default(),
    )
    .unwrap()
}

fn connection() -> ConnectionMetadata {
    ConnectionMetadata {
        name: "production-postgres".parse().unwrap(),
        dialect: Dialect::PostgreSql,
        environment: Environment::Production,
        database: "app".to_owned(),
    }
}

fn context() -> RequestContext {
    RequestContext::new(
        "req-1".parse().unwrap(),
        "alice@example.com".parse().unwrap(),
        "Claude Code".parse().unwrap(),
    )
}

/// Checks one row against the analyzer and against the default engine.
fn check(case: &Case) {
    let sql = case.sql;
    let analyzed = match PostgreSqlAnalyzer::new().analyze(request(sql)) {
        Ok(analyzed) => analyzed,
        Err(error) => {
            assert!(
                case.root_kind.is_none(),
                "`{sql}` produced no analysis but the row expects one: {error}"
            );
            assert_eq!(
                Some(error.deny_reason().code()),
                case.verdict,
                "`{sql}` failed analysis with the wrong code"
            );
            return;
        }
    };

    assert!(
        case.root_kind.is_some(),
        "`{sql}` produced an analysis but the row expects none"
    );

    let analysis = analyzed.analysis();
    assert_eq!(analysis.dialect(), Dialect::PostgreSql, "{sql}");
    assert_eq!(Some(analysis.root_kind()), case.root_kind, "{sql}");
    assert_eq!(analysis.nested_kinds(), case.nested_kinds, "{sql}");

    let objects: Vec<String> = analysis
        .objects()
        .iter()
        .map(|object| object.qualified_name())
        .collect();
    assert_eq!(objects, case.objects, "objects for `{sql}`");

    let functions: Vec<(&str, FunctionClassification)> = analysis
        .functions()
        .iter()
        .map(|function| (function.name.value(), function.classification))
        .collect();
    assert_eq!(functions, case.functions, "functions for `{sql}`");

    let mut risks = analysis.risks().to_vec();
    risks.sort_unstable();
    let mut expected = case.risks.to_vec();
    expected.sort_unstable();
    assert_eq!(risks, expected, "risks for `{sql}`");

    assert_eq!(
        analysis.has_side_effects(),
        !case.risks.is_empty(),
        "`{sql}` must never report an unnamed side effect"
    );
    assert_eq!(
        analysis.has_locking_clause(),
        case.risks.contains(&RiskFlag::LockingRead),
        "locking clause for `{sql}`"
    );

    let engine = PolicyEngine::with_defaults(&PolicySettings::default()).unwrap();
    let verdict = engine
        .authorize(
            &context(),
            &connection(),
            analyzed,
            ExecutionLimits::default(),
        )
        .err()
        .map(|rejection| rejection.primary_code());
    assert_eq!(verdict, case.verdict, "default policy verdict for `{sql}`");
}

fn run(cases: &[Case]) {
    for case in cases {
        check(case);
    }
}

#[test]
fn ordinary_reads_are_authorized() {
    run(READS);
}

#[test]
fn every_write_shape_is_denied() {
    run(WRITES);
}

#[test]
fn a_write_inside_a_cte_is_denied() {
    run(DATA_MODIFYING_CTES);
}

#[test]
fn statement_shape_rules_hold() {
    run(SHAPE);
}

#[test]
fn session_mutation_and_locking_reads_are_denied() {
    run(SESSION_AND_LOCKING);
}

#[test]
fn dangerous_and_unclassified_functions_are_denied() {
    run(FUNCTIONS);
}

#[test]
fn dialect_specific_hazards_are_denied() {
    run(DIALECT_HAZARDS);
}

#[test]
fn statements_the_grammar_rejects_are_denied_not_executed() {
    run(UNPARSEABLE);
}

#[test]
fn no_analysis_ever_carries_the_statement_or_a_literal() {
    // SPEC section 6, invariants 22 and 23: an audit record built from this analysis
    // must not become a second store of the data an agent searched for.
    let secret = "s3cret-value";
    let sql = format!("SELECT * FROM users WHERE token = '{secret}' AND name = $$bob$$");
    let analyzed = PostgreSqlAnalyzer::new().analyze(request(&sql)).unwrap();
    let rendered = format!("{:?}", analyzed.analysis());
    assert!(!rendered.contains(secret), "{rendered}");
    assert!(!rendered.contains("bob"), "{rendered}");
    assert!(
        !analyzed
            .analysis()
            .fingerprint()
            .unwrap()
            .as_str()
            .contains(secret)
    );
}

#[test]
fn arbitrary_bytes_never_panic_the_analyzer() {
    // `docs/testing.md` section 7's fuzzing invariant, as a deterministic smoke test
    // ahead of the Milestone 15 fuzz targets: every input either analyzes or fails
    // safely, and none terminates the process.
    let analyzer = PostgreSqlAnalyzer::new();
    for sql in [
        "\u{0}\u{1}\u{2}",
        "'",
        "\"",
        "$$",
        "$tag$",
        "/*",
        "--",
        "SELECT",
        &"(".repeat(10_000),
        &"SELECT ".repeat(1_000),
        "SELECT '\u{1F600}' FROM \"\u{4F60}\u{597D}\"",
        &format!("SELECT {}", "a,".repeat(20_000)),
    ] {
        let _ = analyzer.analyze(request(sql));
    }
}
