//! The AST walk that turns a parsed statement into evidence.
//!
//! Traversal uses sqlparser's derived [`Visitor`], so every `Statement`, `Query`,
//! `TableFactor`, `ObjectName`, and `Expr` in the tree is reached without a
//! handwritten recursion that could forget a variant — the property
//! `docs/security.md` section 7.1 asks for. Classification is where the wildcards
//! live, and every one of them maps to something denied.

use core::ops::ControlFlow;
use std::borrow::Cow;

use sqlparser::ast::{
    BinaryOperator, Expr, ObjectName, Query, Select, Statement, TableFactor, UtilityOption, Visit,
    Visitor,
};
use warden_core::analysis::{
    FunctionClassification, FunctionRef, IdentifierQuoting, ObjectKind, ObjectRef, RiskFlag,
    SqlIdentifier, StatementKind,
};
use warden_core::dialect::Dialect;
use warden_policy::folding::rule_matches;

use crate::functions;
use crate::statement::kind_of;

/// The one schema whose functions may be classified against the built-in registry.
///
/// PostgreSQL reserves the `pg_` schema-name prefix, so an unprivileged role cannot
/// create a schema that would be trusted here. `public` is deliberately absent: it
/// is on the default `search_path` and it is the one schema an ordinary role can
/// usually write to (ADR-0029).
const TRUSTED_FUNCTION_SCHEMA: &str = "pg_catalog";

/// Everything one walk of the tree saw.
///
/// Not a `QueryAnalysis`: the analyzer still has to add the statement count and the
/// fingerprint, and to subtract the CTE names. Keeping those steps outside the
/// visitor keeps the visitor a pure observer.
#[derive(Debug, Default)]
pub(crate) struct Evidence {
    /// Statement kinds in visit order. The first is the root.
    pub(crate) kinds: Vec<StatementKind>,
    /// Relations, before CTE names are subtracted.
    pub(crate) objects: Vec<ObjectRef>,
    /// CTE aliases the query declared, with the quoting each was written under.
    cte_aliases: Vec<SqlIdentifier>,
    /// Functions the statement invokes.
    pub(crate) functions: Vec<FunctionRef>,
    /// Risks, deduplicated in insertion order.
    pub(crate) risks: Vec<RiskFlag>,
    /// Whether any query carried a row-locking clause.
    pub(crate) has_locking_clause: bool,
    /// Current statement nesting depth during the walk. The root statement is
    /// depth 1; a statement reached only by descending into another statement,
    /// such as the `DELETE` inside `WITH x AS (DELETE ... RETURNING *) SELECT ...`,
    /// is deeper than that.
    depth: usize,
    /// Whether a write statement was seen at a depth greater than the root.
    has_nested_write: bool,
}

/// Whether a statement kind is a write, for nested-write detection during the walk.
///
/// Written as an exhaustive `match`, not `matches!`, because `matches!` silently
/// returns `false` for any variant its pattern does not name. ADR-0021 requires a
/// new `warden-core` enum variant to break the build rather than slip through, and
/// `adapter_rules.rs`'s wildcard scan only looks for `_ =>` / `_ if` arms — a
/// `matches!` call is invisible to it.
fn is_write_kind(kind: StatementKind) -> bool {
    match kind {
        StatementKind::Insert
        | StatementKind::Update
        | StatementKind::Delete
        | StatementKind::Merge
        | StatementKind::Copy => true,
        StatementKind::Select
        | StatementKind::Explain
        | StatementKind::Show
        | StatementKind::Ddl
        | StatementKind::TransactionControl
        | StatementKind::SessionControl
        | StatementKind::Call
        | StatementKind::Utility
        | StatementKind::Unknown => false,
    }
}

/// One identifier as PostgreSQL itself would resolve it.
///
/// An unquoted identifier is folded to lowercase by the server; a quoted one is the
/// literal characters between the quotes (ADR-0027). ASCII-only on purpose: Unicode
/// case folding is locale-dependent and has no place in a security comparison.
///
/// This is **not** `warden_policy::folding::rule_matches`, and cannot be: that
/// comparison is asymmetric between an operator-written rule, which has no quoting,
/// and an identifier a statement wrote. Here both sides came from the statement.
fn folded(identifier: &SqlIdentifier) -> Cow<'_, str> {
    match identifier.quoting() {
        IdentifierQuoting::Unquoted => Cow::Owned(identifier.value().to_ascii_lowercase()),
        IdentifierQuoting::Quoted => Cow::Borrowed(identifier.value()),
    }
}

/// Every part of a name as a [`SqlIdentifier`], or `None` if one is not an
/// identifier.
fn identifiers(name: &ObjectName) -> Option<Vec<SqlIdentifier>> {
    name.0
        .iter()
        .map(|part| {
            part.as_ident().map(|ident| match ident.quote_style {
                Some(_) => SqlIdentifier::quoted(ident.value.clone()),
                None => SqlIdentifier::unquoted(ident.value.clone()),
            })
        })
        .collect()
}

/// Whether this relation name is sqlparser reading `FROM ONLY t`'s keyword as the
/// relation.
///
/// sqlparser 0.62 parses `SELECT * FROM ONLY t` as a relation literally named `ONLY`
/// aliased `t`. Recording that would put a relation that does not exist into the
/// audit record and make `TableAllowDenyPolicy` evaluate the wrong name — a false
/// negative, not merely an inaccuracy. `ONLY` is a PostgreSQL reserved word, so an
/// unquoted single-part relation of that name can only be this misparse; a real
/// table so named must be written `"only"`, which this does not match.
fn is_inheritance_only(name: &ObjectName) -> bool {
    let [part] = name.0.as_slice() else {
        return false;
    };
    part.as_ident().is_some_and(|ident| {
        ident.quote_style.is_none() && ident.value.eq_ignore_ascii_case("only")
    })
}

/// Whether an `EXPLAIN` will run the statement it claims to describe.
///
/// Two spellings reach two different places in sqlparser 0.62. `EXPLAIN ANALYZE
/// SELECT ...` sets the `analyze` flag; `EXPLAIN (ANALYZE, BUFFERS) SELECT ...` —
/// the idiomatic PostgreSQL form — leaves `analyze` **false** and puts the option
/// list in `options`. Reading only the flag, as the MySQL analyzer does because
/// MySQL has no parenthesized form, would miss it (ADR-0017; SPEC section 6,
/// invariant 11).
///
/// The argument is ignored on purpose: `EXPLAIN (ANALYZE false)` is reported as a
/// risk too. PostgreSQL accepts several spellings of falsehood there, and the cost
/// of the false positive is nothing — no tool offers the agent a hand-written
/// `EXPLAIN` in the first place (ADR-0020).
fn runs_the_query(analyze: bool, options: Option<&Vec<UtilityOption>>) -> bool {
    analyze
        || options.is_some_and(|options| {
            options
                .iter()
                .any(|option| option.name.value.eq_ignore_ascii_case("analyze"))
        })
}

impl Evidence {
    /// Records a risk once.
    fn flag(&mut self, risk: RiskFlag) {
        if !self.risks.contains(&risk) {
            self.risks.push(risk);
        }
    }

    /// Splits an `ObjectName` into at most catalog, schema, and name.
    ///
    /// A part that is not a plain identifier cannot be compared against a rule, so
    /// the whole reference becomes `UnknownConstruct` instead of being silently
    /// dropped. So does a name with more than three parts: guessing which slot the
    /// extra one belongs to would encode a dialect assumption in the one place that
    /// must not hold any.
    fn record_object(&mut self, name: &ObjectName, kind: ObjectKind) {
        let Some(mut parts) = identifiers(name) else {
            self.flag(RiskFlag::UnknownConstruct);
            return;
        };
        let Some(object) = parts.pop() else {
            self.flag(RiskFlag::UnknownConstruct);
            return;
        };
        let (catalog, schema) = match parts.len() {
            0 => (None, None),
            1 => (None, parts.pop()),
            2 => {
                let schema = parts.pop();
                (parts.pop(), schema)
            }
            _ => {
                self.flag(RiskFlag::UnknownConstruct);
                return;
            }
        };
        self.objects.push(ObjectRef {
            catalog,
            schema,
            name: object,
            kind,
        });
    }

    /// Classifies one function call and records both halves of the evidence.
    ///
    /// A call qualified by anything other than `pg_catalog` is `Unknown` before its
    /// bare name is compared against the registry, so a user-defined function cannot
    /// inherit a built-in's classification by sharing its name. A call qualified by
    /// `pg_catalog` *is* the built-in, which is the whole difference from
    /// `warden-mysql` (ADR-0029). The schema is recorded on the `FunctionRef` either
    /// way: `FunctionSafetyPolicy::qualified()` renders `schema.name` in its audit
    /// detail.
    ///
    /// The bare name is folded by [`folded`] — the same helper CTE subtraction uses —
    /// before it reaches the registry. Without this, `"Count"(1)` would be lowercased
    /// on its way into `functions::classify` and match the `count` entry despite
    /// being a different, quoted identifier: exactly the laundering ADR-0029 exists to
    /// close, achieved with quote characters instead of a schema qualifier.
    fn record_function(&mut self, name: &ObjectName) {
        let Some(mut parts) = identifiers(name) else {
            self.flag(RiskFlag::UnknownConstruct);
            return;
        };
        let Some(function) = parts.pop() else {
            self.flag(RiskFlag::UnknownConstruct);
            return;
        };
        let schema = parts.pop();
        let trusted = schema.as_ref().is_none_or(|schema| {
            rule_matches(Dialect::PostgreSql, TRUSTED_FUNCTION_SCHEMA, schema)
        });
        let (classification, risk) = if trusted {
            functions::classify(&folded(&function))
        } else {
            (
                FunctionClassification::Unknown,
                Some(RiskFlag::UserDefinedFunction),
            )
        };
        if let Some(risk) = risk {
            self.flag(risk);
        }
        self.functions.push(FunctionRef {
            name: function,
            schema,
            classification,
        });
    }
}

impl Visitor for Evidence {
    type Break = ();

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<()> {
        self.depth += 1;
        let kind = kind_of(statement);
        if self.depth > 1 && is_write_kind(kind) {
            // Reached only by descending into another statement, not by being one
            // of the top-level statements in the batch: the `WITH x AS (DELETE
            // ... RETURNING *)` shape of `docs/security.md` section 6.3, whatever
            // syntax produced it.
            self.has_nested_write = true;
        }
        self.kinds.push(kind);
        if let Statement::Explain {
            analyze, options, ..
        } = statement
            && runs_the_query(*analyze, options.as_ref())
        {
            // ADR-0017: `EXPLAIN ANALYZE` runs the query it claims to describe.
            self.flag(RiskFlag::ExplainAnalyze);
        }
        ControlFlow::Continue(())
    }

    fn post_visit_statement(&mut self, _statement: &Statement) -> ControlFlow<()> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
        if let Some(with) = &query.with {
            for cte in &with.cte_tables {
                let alias = &cte.alias.name;
                self.cte_aliases.push(match alias.quote_style {
                    Some(_) => SqlIdentifier::quoted(alias.value.clone()),
                    None => SqlIdentifier::unquoted(alias.value.clone()),
                });
            }
        }
        if !query.locks.is_empty() {
            self.has_locking_clause = true;
            self.flag(RiskFlag::LockingRead);
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_select(&mut self, select: &Select) -> ControlFlow<()> {
        if select.into.is_some() {
            // PostgreSQL's `SELECT ... INTO` creates a relation, in every one of its
            // `TEMP`, `TEMPORARY` and `UNLOGGED` spellings. This hook fires for every
            // `Select`, including one that is only an arm of a
            // `UNION`/`EXCEPT`/`INTERSECT`, so `SELECT ... INTO t FROM a UNION
            // SELECT ...` is not missed the way reading only `Query::body` would
            // miss it.
            self.flag(RiskFlag::SelectInto);
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<()> {
        match factor {
            TableFactor::Table { name, .. } if is_inheritance_only(name) => {
                self.flag(RiskFlag::UnknownConstruct);
            }
            TableFactor::Table { name, args, .. } => {
                // An analyzer sees names, not catalog entries: it cannot tell a table
                // from a view, and claiming otherwise would be wrong about every
                // view. Only a relation called with arguments is provably a function.
                let kind = match args {
                    Some(_) => ObjectKind::Function,
                    None => ObjectKind::Unknown,
                };
                self.record_object(name, kind);
                if args.is_some() {
                    // `FROM pg_read_file('/etc/passwd')` calls a function in relation
                    // position. The relation is recorded above; this also classifies
                    // the call itself, exactly as the same name in expression
                    // position would be (SPEC section 6, invariant 7).
                    self.record_function(name);
                }
            }
            // A derived table and a nested join contain relations the visitor reaches
            // on its own; they name nothing themselves.
            TableFactor::Derived { .. } | TableFactor::NestedJoin { .. } => {}
            TableFactor::Function { name, .. } => {
                // `FROM t, LATERAL f(t.n) g`. This is a real function call and is
                // classified as one — a `LATERAL pg_read_file(...)` that recorded
                // only a relation would lose the `FileAccess` flag. The construct
                // itself still counts as one this analyzer cannot fully describe.
                self.record_object(name, ObjectKind::Function);
                self.record_function(name);
                self.flag(RiskFlag::UnknownConstruct);
            }
            // Every remaining form — UNNEST, JSON_TABLE, PIVOT, MATCH_RECOGNIZE and
            // the rest — is a relation source this analyzer cannot describe. The
            // wildcard denies rather than ignores (AGENTS.md, "Modeling").
            _ => self.flag(RiskFlag::UnknownConstruct),
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
        match expr {
            Expr::Function(function) => self.record_function(&function.name),
            // `1 OPERATOR(public.evil) 2` invokes a user-defined operator, and a
            // PostgreSQL operator is a call to an arbitrary function under another
            // spelling, with no `Expr::Function` anywhere in the tree. sqlparser
            // reports this variant only for the explicit `OPERATOR(...)` syntax —
            // every built-in spelling (`->`, `@>`, `~`, `||`, `#`, `<->`, ...)
            // reaches a named `BinaryOperator` variant — so the arm has no false
            // positives on ordinary SQL.
            Expr::BinaryOp {
                op: BinaryOperator::PGCustomBinaryOperator(_),
                ..
            } => self.flag(RiskFlag::UnknownConstruct),
            // No wildcard-to-Unknown arm here, deliberately: see the crate note in
            // `lib.rs`. Side effects reach a PostgreSQL expression as a function
            // call, a custom operator, or a nested statement the visitor descends
            // into, and all three are classified above. PostgreSQL has no
            // expression-level assignment operator in SQL: `f(a := 1)` is argument
            // naming inside a call that is itself classified, not session mutation
            // the way MySQL's `@x := 1` is.
            _ => {}
        }
        ControlFlow::Continue(())
    }
}

/// Walks the statements and returns what the walk saw, with CTE names subtracted.
///
/// **The CTE subtraction is not scope-aware.** `docs/security.md` section 5.1
/// requires that CTE names and subquery aliases are not `ObjectRef` values, and this
/// analyzer implements it by dropping every *unqualified* relation whose folded name
/// equals a folded CTE alias anywhere in the input. A query that declares a CTE named
/// `orders` and also reads a real table `orders` in a different scope therefore loses
/// the real reference. That errs toward reporting fewer objects, which weakens the
/// allowlist and not the boundary: ADR-0023 makes the role's `GRANT SELECT` the read
/// boundary, and the allowlist reduces attack surface.
///
/// The folding *is* accurate, unlike `warden-mysql`'s case-insensitive comparison:
/// PostgreSQL's rule is fixed, so `WITH "Report" AS (...) SELECT * FROM report` keeps
/// `report` as a real relation, which is what the server would resolve.
pub(crate) fn collect(statements: &[Statement]) -> Evidence {
    let mut evidence = Evidence::default();
    for statement in statements {
        let _ = statement.visit(&mut evidence);
    }

    if statements.len() > 1 {
        evidence.flag(RiskFlag::MultipleStatements);
    }

    for index in 0..evidence.kinds.len() {
        let kind = evidence.kinds[index];
        // Exhaustive over `StatementKind`: a new variant must be decided here rather
        // than fall through a wildcard (ADR-0021).
        match kind {
            StatementKind::Select | StatementKind::Explain | StatementKind::Show => {}
            StatementKind::Insert
            | StatementKind::Update
            | StatementKind::Delete
            | StatementKind::Merge
            | StatementKind::Copy => evidence.flag(RiskFlag::WriteStatement),
            StatementKind::Ddl => evidence.flag(RiskFlag::Ddl),
            StatementKind::SessionControl => evidence.flag(RiskFlag::SessionMutation),
            StatementKind::Call => evidence.flag(RiskFlag::StoredRoutine),
            StatementKind::TransactionControl | StatementKind::Utility => {}
            StatementKind::Unknown => evidence.flag(RiskFlag::UnknownConstruct),
        }
    }

    if evidence.has_nested_write {
        // Depth is tracked during the walk itself (`pre_visit_statement` /
        // `post_visit_statement`), not inferred from a flat batch position, so a
        // write that is merely the second statement of a batch — `SELECT 1;
        // DELETE FROM t` — does not trip this, while a write actually nested
        // inside another statement — `WITH x AS (DELETE ... RETURNING *) SELECT
        // ...` — does.
        evidence.flag(RiskFlag::DataModifyingCte);
    }

    let aliases = std::mem::take(&mut evidence.cte_aliases);
    evidence.objects.retain(|object| {
        let unqualified = object.catalog.is_none() && object.schema.is_none();
        let is_cte = aliases
            .iter()
            .any(|alias| folded(alias) == folded(&object.name));
        !(unqualified && is_cte)
    });
    evidence.cte_aliases = aliases;
    evidence
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::parse;

    fn evidence(sql: &str) -> Evidence {
        collect(&parse::statements(sql).expect("fixture must parse"))
    }

    fn names(evidence: &Evidence) -> Vec<String> {
        evidence
            .objects
            .iter()
            .map(ObjectRef::qualified_name)
            .collect()
    }

    fn classifications(evidence: &Evidence) -> Vec<(&str, FunctionClassification)> {
        evidence
            .functions
            .iter()
            .map(|function| (function.name.value(), function.classification))
            .collect()
    }

    #[test]
    fn a_cte_name_is_not_an_object_but_what_it_reads_is() {
        let evidence = evidence("WITH x AS (SELECT * FROM secrets) SELECT * FROM x");
        assert_eq!(names(&evidence), ["secrets"]);
        assert!(evidence.risks.is_empty());
    }

    #[test]
    fn a_recursive_cte_self_reference_is_still_the_cte() {
        let evidence = evidence(
            "WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM t WHERE n < 10) \
             SELECT * FROM t",
        );
        assert!(names(&evidence).is_empty());
        assert!(evidence.risks.is_empty());
    }

    #[test]
    fn cte_subtraction_folds_each_side_by_its_own_quoting() {
        // An unquoted alias folds, so a differently cased reference is the CTE.
        assert_eq!(
            names(&evidence(
                "WITH Report AS (SELECT * FROM secrets) SELECT * FROM report"
            )),
            ["secrets"]
        );
        // A quoted alias does not fold, so `report` names a real relation and must
        // survive — PostgreSQL would resolve it to a base table.
        assert_eq!(
            names(&evidence(
                r#"WITH "Report" AS (SELECT * FROM secrets) SELECT * FROM report"#
            )),
            ["secrets", "report"]
        );
    }

    #[test]
    fn a_qualified_name_fills_the_slots_from_the_right() {
        assert_eq!(names(&evidence("SELECT * FROM tbl")), ["tbl"]);
        assert_eq!(names(&evidence("SELECT * FROM sch.tbl")), ["sch.tbl"]);
        assert_eq!(names(&evidence("SELECT * FROM db.sch.tbl")), ["db.sch.tbl"]);
    }

    #[test]
    fn a_name_with_more_than_three_parts_is_unknown_construct_not_dropped_silently() {
        let evidence = evidence("SELECT * FROM db.sch.tbl.extra");
        assert!(evidence.objects.is_empty());
        assert!(evidence.risks.contains(&RiskFlag::UnknownConstruct));
    }

    #[test]
    fn an_inheritance_only_relation_is_denied_rather_than_recorded_as_only() {
        // sqlparser reads the reserved word as the relation. Recording `ONLY` would
        // make the object policy evaluate a relation that does not exist.
        let only = evidence("SELECT * FROM ONLY t");
        assert!(only.objects.is_empty());
        assert!(only.risks.contains(&RiskFlag::UnknownConstruct));

        // A quoted relation genuinely named `only` is not the keyword.
        let quoted = evidence(r#"SELECT * FROM "only" t"#);
        assert_eq!(names(&quoted), ["only"]);
        assert!(quoted.risks.is_empty());
    }

    #[test]
    fn a_table_factor_this_analyzer_cannot_describe_is_unknown_construct() {
        // `UNNEST` in relation position is its own `TableFactor` variant, reached
        // only through the wildcard. Denying it is a deliberate false positive:
        // the alternative is describing a relation source the analyzer cannot see
        // into.
        let evidence = evidence("SELECT * FROM unnest(ARRAY[1, 2])");
        assert!(evidence.objects.is_empty());
        assert!(evidence.risks.contains(&RiskFlag::UnknownConstruct));
    }

    #[test]
    fn a_relation_called_with_arguments_is_classified_as_a_call_too() {
        let evidence = evidence("SELECT * FROM pg_read_file('/etc/passwd')");
        assert_eq!(names(&evidence), ["pg_read_file"]);
        assert_eq!(
            classifications(&evidence),
            [("pg_read_file", FunctionClassification::KnownDangerous)]
        );
        assert!(evidence.risks.contains(&RiskFlag::FileAccess));
    }

    #[test]
    fn a_lateral_function_is_classified_and_not_merely_named() {
        let evidence = evidence("SELECT * FROM t, LATERAL pg_read_file('/etc/passwd') f");
        assert_eq!(names(&evidence), ["t", "pg_read_file"]);
        assert!(evidence.risks.contains(&RiskFlag::FileAccess));
        assert!(evidence.risks.contains(&RiskFlag::UnknownConstruct));
    }

    #[test]
    fn only_pg_catalog_qualification_reaches_the_registry() {
        for sql in [
            "SELECT count(1) FROM t",
            "SELECT pg_catalog.count(1) FROM t",
            r#"SELECT "pg_catalog".count(1) FROM t"#,
        ] {
            let evidence = evidence(sql);
            assert_eq!(
                classifications(&evidence),
                [("count", FunctionClassification::KnownSafe)],
                "{sql}"
            );
            assert!(evidence.risks.is_empty(), "{sql}");
        }

        // Any other schema is user-defined, and the bare name is never consulted.
        for sql in [
            "SELECT public.count(1) FROM t",
            r#"SELECT "PG_CATALOG".count(1) FROM t"#,
        ] {
            let evidence = evidence(sql);
            assert_eq!(
                classifications(&evidence),
                [("count", FunctionClassification::Unknown)],
                "{sql}"
            );
            assert!(
                evidence.risks.contains(&RiskFlag::UserDefinedFunction),
                "{sql}"
            );
        }
    }

    #[test]
    fn a_dangerous_function_is_still_dangerous_when_qualified_by_pg_catalog() {
        let evidence = evidence("SELECT pg_catalog.pg_sleep(1)");
        assert!(evidence.risks.contains(&RiskFlag::DelayFunction));
    }

    #[test]
    fn a_write_nested_in_a_cte_is_a_data_modifying_cte() {
        for sql in [
            "WITH c AS (DELETE FROM orders RETURNING *) SELECT * FROM c",
            "WITH c AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM c",
            "WITH c AS (UPDATE t SET a = 1 RETURNING *) SELECT * FROM c",
        ] {
            let evidence = evidence(sql);
            assert!(
                evidence.risks.contains(&RiskFlag::DataModifyingCte),
                "{sql}"
            );
            assert!(evidence.risks.contains(&RiskFlag::WriteStatement), "{sql}");
        }
    }

    #[test]
    fn a_second_top_level_write_is_not_a_nested_write() {
        let evidence = evidence("SELECT 1; DELETE FROM t");
        assert!(evidence.risks.contains(&RiskFlag::MultipleStatements));
        assert!(evidence.risks.contains(&RiskFlag::WriteStatement));
        assert!(!evidence.risks.contains(&RiskFlag::DataModifyingCte));
    }

    #[test]
    fn a_locking_clause_is_seen_wherever_the_query_sits() {
        for sql in [
            "SELECT * FROM t FOR UPDATE",
            "SELECT * FROM t FOR SHARE",
            "WITH x AS (SELECT * FROM t FOR UPDATE) SELECT * FROM x",
            "SELECT * FROM (SELECT * FROM t FOR UPDATE) s",
        ] {
            let evidence = evidence(sql);
            assert!(evidence.has_locking_clause, "{sql}");
            assert!(evidence.risks.contains(&RiskFlag::LockingRead), "{sql}");
        }
    }

    #[test]
    fn select_into_is_seen_on_a_set_operation_arm() {
        let evidence = evidence("SELECT a INTO t2 FROM t1 UNION SELECT b FROM t3");
        assert!(evidence.risks.contains(&RiskFlag::SelectInto));
        assert_eq!(names(&evidence), ["t1", "t3"]);
    }

    #[test]
    fn both_spellings_of_explain_analyze_are_reported() {
        // The parenthesized form leaves `analyze` false and is the idiomatic one.
        for sql in [
            "EXPLAIN ANALYZE SELECT 1",
            "EXPLAIN (ANALYZE) SELECT 1",
            "EXPLAIN (ANALYZE, BUFFERS) SELECT 1",
            "EXPLAIN (analyze false) SELECT 1",
        ] {
            assert!(
                evidence(sql).risks.contains(&RiskFlag::ExplainAnalyze),
                "{sql}"
            );
        }

        for sql in ["EXPLAIN SELECT 1", "EXPLAIN (FORMAT JSON) SELECT 1"] {
            assert!(
                !evidence(sql).risks.contains(&RiskFlag::ExplainAnalyze),
                "{sql}"
            );
        }
    }

    #[test]
    fn a_custom_operator_is_an_unclassifiable_call() {
        let custom_operator = evidence("SELECT 1 OPERATOR(public.evil) 2");
        assert!(custom_operator.risks.contains(&RiskFlag::UnknownConstruct));

        // Every built-in operator spelling reaches a named variant and is silent.
        for sql in [
            "SELECT a -> 'x' FROM t",
            "SELECT a @> b FROM t",
            "SELECT a ~ 'x' FROM t",
            "SELECT a || b FROM t",
            "SELECT a <-> b FROM t",
        ] {
            assert!(evidence(sql).risks.is_empty(), "{sql}");
        }
    }

    #[test]
    fn a_named_argument_is_not_session_mutation() {
        // MySQL's `:=` assigns a user variable; PostgreSQL's names an argument
        // inside a call that is classified on its own terms.
        let evidence = evidence("SELECT f(a := 1)");
        assert!(!evidence.risks.contains(&RiskFlag::SessionMutation));
        assert!(evidence.risks.contains(&RiskFlag::UserDefinedFunction));
    }

    #[test]
    fn every_statement_kind_reaches_a_decided_risk() {
        // Iterating the shapes rather than the enum, because `collect` matches
        // `StatementKind` exhaustively and the compiler already guards that; this
        // proves the mapping is the intended one.
        for (sql, expected) in [
            ("DELETE FROM t", Some(RiskFlag::WriteStatement)),
            ("COPY t FROM '/tmp/x'", Some(RiskFlag::WriteStatement)),
            ("CREATE TABLE t (a INT)", Some(RiskFlag::Ddl)),
            ("SET search_path = app", Some(RiskFlag::SessionMutation)),
            ("NOTIFY channel, 'x'", Some(RiskFlag::SessionMutation)),
            ("CALL p(1)", Some(RiskFlag::StoredRoutine)),
            (
                "CREATE SERVER s FOREIGN DATA WRAPPER w",
                Some(RiskFlag::UnknownConstruct),
            ),
            ("BEGIN", None),
            ("VACUUM", None),
            ("SELECT 1", None),
        ] {
            let risks = evidence(sql).risks;
            match expected {
                Some(flag) => assert!(risks.contains(&flag), "{sql}"),
                None => assert!(risks.is_empty(), "{sql}: {risks:?}"),
            }
        }
    }
}
