//! The MySQL security corpus.
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
use warden_mysql::MySqlAnalyzer;
use warden_policy::{DenyCode, PolicyEngine, PolicySettings};
use warden_ports::analyzer::QueryAnalyzer;

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
        sql: "SELECT id, total FROM orders WHERE customer_id = ?",
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
        sql: "SELECT COUNT(*), MAX(total) FROM orders",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["orders"],
        functions: &[
            ("COUNT", FunctionClassification::KnownSafe),
            ("MAX", FunctionClassification::KnownSafe),
        ],
        risks: &[],
        verdict: None,
    },
    Case {
        sql: "SELECT /*+ MAX_EXECUTION_TIME(1000) */ id FROM `Orders`",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["Orders"],
        functions: &[],
        risks: &[],
        verdict: None,
    },
    Case {
        // A semicolon inside a literal is not a statement separator.
        sql: "SELECT 'a; DROP TABLE t' AS literal",
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
        // Unquoted identifier case is preserved as written, not folded.
        sql: "SELECT id FROM Orders",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["Orders"],
        functions: &[],
        risks: &[],
        verdict: None,
    },
    Case {
        // The CTE alias is declared `Report` and referenced as `report`. CTE
        // subtraction in `visit::collect` compares names with
        // `eq_ignore_ascii_case`, so the alias is still recognized and dropped
        // across the case difference; only the real relation the CTE reads
        // survives. If that comparison were ever tightened to an exact match,
        // `report` would leak into the object list as if it were a real table,
        // and this row would catch it.
        sql: "WITH Report AS (SELECT * FROM secrets) SELECT * FROM report",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["secrets"],
        functions: &[],
        risks: &[],
        verdict: None,
    },
];

const WRITES: &[Case] = &[
    Case {
        // Correction 2: `Insert.table` is a `TableObject::TableName(ObjectName)`,
        // not a `TableFactor`, so `pre_visit_table_factor` never sees it. Reporting
        // it would need `pre_visit_relation`, which routes `TableFactor::Table`
        // through the same hook and would double-report every `FROM` relation.
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
        sql: "CREATE TABLE t (a INT)",
        root_kind: Some(StatementKind::Ddl),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::Ddl],
        verdict: Some(DenyCode::Ddl),
    },
    Case {
        sql: "DROP TABLE orders",
        root_kind: Some(StatementKind::Ddl),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::Ddl],
        verdict: Some(DenyCode::Ddl),
    },
    Case {
        sql: "SELECT * INTO backup FROM orders",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["orders"],
        functions: &[],
        risks: &[RiskFlag::SelectInto],
        verdict: Some(DenyCode::Ddl),
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
        // Declaration order in `DenyCode` decides which of several denials the agent
        // hears; `MultipleStatements` is the most categorical.
        //
        // Correction 3: `DataModifyingCte` is not expected here. It is raised from
        // real nesting depth tracked across `pre_visit_statement`/
        // `post_visit_statement` (`visit.rs`), not from a flat batch index, so a
        // second top-level statement is a root write at depth 1, not a nested one.
        // A genuinely nested write (`WITH x AS (DELETE FROM t) SELECT * FROM x`)
        // still flags it; `visit.rs`'s own tests prove both directions.
        sql: "SELECT 1; DELETE FROM orders",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[StatementKind::Delete],
        objects: &["orders"],
        functions: &[],
        risks: &[RiskFlag::MultipleStatements, RiskFlag::WriteStatement],
        verdict: Some(DenyCode::MultipleStatements),
    },
    Case {
        sql: "SHOW TABLES",
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
        sql: "CALL rebuild_report(1)",
        root_kind: Some(StatementKind::Call),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::StoredRoutine],
        verdict: Some(DenyCode::StatementNotAllowed),
    },
    Case {
        sql: "START TRANSACTION",
        root_kind: Some(StatementKind::TransactionControl),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: Some(DenyCode::StatementNotAllowed),
    },
];

const SESSION_AND_LOCKING: &[Case] = &[
    Case {
        sql: "SET @x = 1",
        root_kind: Some(StatementKind::SessionControl),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::SessionMutation],
        verdict: Some(DenyCode::SessionMutation),
    },
    Case {
        sql: "SET SESSION sql_mode = 'ANSI'",
        root_kind: Some(StatementKind::SessionControl),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::SessionMutation],
        verdict: Some(DenyCode::SessionMutation),
    },
    Case {
        // Assignment hides inside an ordinary-looking projection.
        sql: "SELECT @counter := @counter + 1 FROM orders",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["orders"],
        functions: &[],
        risks: &[RiskFlag::SessionMutation],
        verdict: Some(DenyCode::SessionMutation),
    },
    Case {
        // Reading a variable is not mutating one.
        sql: "SELECT @@version, @x FROM orders",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["orders"],
        functions: &[],
        risks: &[],
        verdict: None,
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
];

const FUNCTIONS: &[Case] = &[
    Case {
        sql: "SELECT SLEEP(30)",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[("SLEEP", FunctionClassification::KnownDangerous)],
        risks: &[RiskFlag::DelayFunction],
        verdict: Some(DenyCode::DangerousFunction),
    },
    Case {
        sql: "SELECT BENCHMARK(100000000, MD5('x'))",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[
            ("BENCHMARK", FunctionClassification::KnownDangerous),
            ("MD5", FunctionClassification::KnownSafe),
        ],
        risks: &[RiskFlag::DelayFunction],
        verdict: Some(DenyCode::DangerousFunction),
    },
    Case {
        sql: "SELECT GET_LOCK('a', 10)",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[("GET_LOCK", FunctionClassification::KnownDangerous)],
        risks: &[RiskFlag::AdvisoryLock],
        verdict: Some(DenyCode::DangerousFunction),
    },
    Case {
        sql: "SELECT LOAD_FILE('/etc/passwd')",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[("LOAD_FILE", FunctionClassification::KnownDangerous)],
        risks: &[RiskFlag::FileAccess],
        verdict: Some(DenyCode::DangerousFunction),
    },
    Case {
        // A dangerous call nested in a subquery is still found.
        sql: "SELECT * FROM orders WHERE id = (SELECT SLEEP(5))",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["orders"],
        functions: &[("SLEEP", FunctionClassification::KnownDangerous)],
        risks: &[RiskFlag::DelayFunction],
        verdict: Some(DenyCode::DangerousFunction),
    },
    Case {
        sql: "SELECT sys_exec('rm -rf /')",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &[],
        functions: &[("sys_exec", FunctionClassification::Unknown)],
        risks: &[RiskFlag::UserDefinedFunction],
        verdict: Some(DenyCode::UnknownFunction),
    },
    Case {
        sql: "SELECT app.custom_metric(1) FROM orders",
        root_kind: Some(StatementKind::Select),
        nested_kinds: &[],
        objects: &["orders"],
        functions: &[("custom_metric", FunctionClassification::Unknown)],
        risks: &[RiskFlag::UserDefinedFunction],
        verdict: Some(DenyCode::UnknownFunction),
    },
];

/// sqlparser 0.62 rejects these. Each row is an upgrade alarm: if one starts
/// parsing, this file fails and the new AST shape gets reviewed
/// (`docs/testing.md` section 3.3).
const UNPARSEABLE: &[Case] = &[
    Case {
        sql: "SELECT * FROM orders LOCK IN SHARE MODE",
        root_kind: None,
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: Some(DenyCode::UnknownConstruct),
    },
    Case {
        sql: "SELECT * FROM orders INTO @a, @b",
        root_kind: None,
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: Some(DenyCode::UnknownConstruct),
    },
    Case {
        sql: "LOAD DATA INFILE '/tmp/x' INTO TABLE t",
        root_kind: None,
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: Some(DenyCode::UnknownConstruct),
    },
    Case {
        sql: "SELECT FROM WHERE",
        root_kind: None,
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: Some(DenyCode::UnknownConstruct),
    },
    Case {
        // A future parser that accepts `PREPARE` would hide a second statement
        // inside a string literal the visitor cannot read, so this row is a
        // deliberate upgrade alarm rather than an oversight.
        sql: "PREPARE s FROM 'SELECT 1'",
        root_kind: None,
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[],
        verdict: Some(DenyCode::UnknownConstruct),
    },
];

/// `INTO OUTFILE` and `INTO DUMPFILE` do not parse, yet must still be named.
const FILE_OUTPUT: &[Case] = &[
    Case {
        sql: "SELECT * FROM users INTO OUTFILE '/tmp/dump.csv'",
        root_kind: Some(StatementKind::Unknown),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::FileOutput, RiskFlag::UnknownConstruct],
        verdict: Some(DenyCode::WriteStatement),
    },
    Case {
        sql: "SELECT * FROM users INTO DUMPFILE '/tmp/dump.bin'",
        root_kind: Some(StatementKind::Unknown),
        nested_kinds: &[],
        objects: &[],
        functions: &[],
        risks: &[RiskFlag::FileOutput, RiskFlag::UnknownConstruct],
        verdict: Some(DenyCode::WriteStatement),
    },
];

fn request(sql: &str) -> QueryRequest {
    QueryRequest::new(
        "production-mysql".parse().unwrap(),
        sql.to_owned(),
        Vec::new(),
        &InputLimits::default(),
    )
    .unwrap()
}

fn connection() -> ConnectionMetadata {
    ConnectionMetadata {
        name: "production-mysql".parse().unwrap(),
        dialect: Dialect::MySql,
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
    let analyzed = match MySqlAnalyzer::new().analyze(request(sql)) {
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
    assert_eq!(analysis.dialect(), Dialect::MySql, "{sql}");
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
fn statements_the_grammar_rejects_are_denied_not_executed() {
    run(UNPARSEABLE);
}

#[test]
fn file_output_is_named_even_though_it_does_not_parse() {
    run(FILE_OUTPUT);
}

#[test]
fn no_analysis_ever_carries_the_statement_or_a_literal() {
    // SPEC section 6, invariants 22 and 23: an audit record built from this analysis
    // must not become a second store of the data an agent searched for.
    let secret = "s3cret-value";
    let sql = format!("SELECT * FROM users WHERE token = '{secret}' AND name = 'bob'");
    let analyzed = MySqlAnalyzer::new().analyze(request(&sql)).unwrap();
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
    let analyzer = MySqlAnalyzer::new();
    for sql in [
        "\u{0}\u{1}\u{2}",
        "'",
        "`",
        "/*",
        "--",
        "SELECT",
        &"(".repeat(10_000),
        &"SELECT ".repeat(1_000),
        "SELECT '\u{1F600}' FROM `\u{4F60}\u{597D}`",
        &format!("SELECT {}", "a,".repeat(20_000)),
    ] {
        let _ = analyzer.analyze(request(sql));
    }
}
