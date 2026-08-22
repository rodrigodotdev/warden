//! The AST walk that turns a parsed statement into evidence.
//!
//! Traversal uses sqlparser's derived [`Visitor`], so every `Statement`, `Query`,
//! `TableFactor`, `ObjectName`, and `Expr` in the tree is reached without a
//! handwritten recursion that could forget a variant — the property
//! `docs/security.md` section 7.1 asks for. Classification is where the wildcards
//! live, and every one of them maps to something denied.

// This module's `pub(crate)` item gains its first caller in Task 5's analyzer.
// Until then only this file's own `#[cfg(test)]` block reaches it, which the
// non-test build cannot see, so `dead_code` would otherwise fire here.
#![allow(dead_code)]

use core::ops::ControlFlow;

use sqlparser::ast::{
    BinaryOperator, Expr, ObjectName, Query, Select, Statement, TableFactor, Visit, Visitor,
};
use warden_core::analysis::{
    FunctionRef, ObjectKind, ObjectRef, RiskFlag, SqlIdentifier, StatementKind,
};

use crate::functions;
use crate::statement::kind_of;

/// Everything one walk of the tree saw.
///
/// Not a `QueryAnalysis`: the analyzer still has to add the statement count, the
/// fingerprint, and the token-guard risks, and to subtract the CTE names. Keeping
/// those steps outside the visitor keeps the visitor a pure observer.
#[derive(Debug, Default)]
pub(crate) struct Evidence {
    /// Statement kinds in visit order. The first is the root.
    pub(crate) kinds: Vec<StatementKind>,
    /// Relations, before CTE names are subtracted.
    pub(crate) objects: Vec<ObjectRef>,
    /// CTE aliases the query declared.
    pub(crate) cte_names: Vec<String>,
    /// Functions the statement invokes.
    pub(crate) functions: Vec<FunctionRef>,
    /// Risks, deduplicated in insertion order.
    pub(crate) risks: Vec<RiskFlag>,
    /// Whether any query carried a row-locking clause.
    pub(crate) has_locking_clause: bool,
    /// Current statement nesting depth during the walk. The root statement is
    /// depth 1; a statement reached only by descending into another statement,
    /// such as the `DELETE` inside `WITH x AS (DELETE ...) SELECT ...`, is
    /// deeper than that.
    depth: usize,
    /// Whether a write statement was seen at a depth greater than the root.
    has_nested_write: bool,
}

/// Whether a statement kind is a write, for nested-write detection during the walk.
///
/// This is the same set of kinds `collect`'s exhaustive match treats as a write; kept
/// as its own function because the walk needs the answer before that match runs.
fn is_write_kind(kind: StatementKind) -> bool {
    matches!(
        kind,
        StatementKind::Insert
            | StatementKind::Update
            | StatementKind::Delete
            | StatementKind::Merge
            | StatementKind::Copy
    )
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
    /// A part that is not a plain identifier — sqlparser models Snowflake's
    /// `IDENTIFIER('...')` as a function-valued part — cannot be compared against a
    /// rule, so the whole reference becomes `UnknownConstruct` instead of being
    /// silently dropped. So does a name with more than three parts: guessing which
    /// slot the extra one belongs to would encode a dialect assumption in the one
    /// place that must not hold any.
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
        let (classification, risk) = functions::classify(function.value());
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

impl Visitor for Evidence {
    type Break = ();

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<()> {
        self.depth += 1;
        let kind = kind_of(statement);
        if self.depth > 1 && is_write_kind(kind) {
            // Reached only by descending into another statement, not by being one
            // of the top-level statements in the batch: the `WITH x AS (DELETE
            // ...)` shape of `docs/security.md` section 6.3, whatever syntax
            // produced it.
            self.has_nested_write = true;
        }
        self.kinds.push(kind);
        if let Statement::Explain { analyze: true, .. } = statement {
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
                self.cte_names.push(cte.alias.name.value.clone());
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
            // On MySQL every `SELECT ... INTO` form writes somewhere: a table, a
            // file, or a session variable. Only the table form parses here. This
            // hook fires for every `Select`, including one that is only an arm of
            // a `UNION`/`EXCEPT`/`INTERSECT`, so `SELECT ... INTO t FROM a UNION
            // SELECT ...` is not missed the way reading only `Query::body` would
            // miss it.
            self.flag(RiskFlag::SelectInto);
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<()> {
        match factor {
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
                    // `FROM sleep(5)` calls a function in relation position. The
                    // relation is recorded above; this also classifies the call
                    // itself, exactly as `sleep(5)` in expression position would be
                    // (SPEC section 6, invariant 7; `functions.rs`'s own header).
                    self.record_function(name);
                }
            }
            // A derived table and a nested join contain relations the visitor reaches
            // on its own; they name nothing themselves.
            TableFactor::Derived { .. } | TableFactor::NestedJoin { .. } => {}
            TableFactor::Function { name, .. } => {
                self.record_object(name, ObjectKind::Function);
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
            // `SELECT @x := 1` assigns a user variable, which survives on a pooled
            // connection and is therefore session mutation, not arithmetic
            // (SPEC section 6, invariant 8).
            Expr::BinaryOp {
                op: BinaryOperator::Assignment,
                ..
            } => self.flag(RiskFlag::SessionMutation),
            // No wildcard-to-Unknown arm here, deliberately: see the crate note in
            // `lib.rs`. Side effects reach a MySQL expression as a function call, a
            // nested statement the visitor descends into, or `:=`, and all three are
            // classified above.
            _ => {}
        }
        ControlFlow::Continue(())
    }
}

/// Walks the statements and returns what the walk saw, with CTE names subtracted.
///
/// **The CTE subtraction is deliberately blunt.** `docs/security.md` section 5.1
/// requires that CTE names and subquery aliases are not `ObjectRef` values, and this
/// analyzer implements it by dropping every *unqualified* relation whose name folds
/// equal to any CTE alias anywhere in the input — it does not track which
/// subquery each alias is visible in. A query that declares a CTE named `orders` and
/// also reads a real table `orders` in a different scope therefore loses the real
/// reference from the object list. That errs toward reporting fewer objects, which
/// weakens the allowlist and not the boundary: ADR-0023 makes the role's
/// `GRANT SELECT` the read boundary, and the allowlist reduces attack surface.
/// Scope-accurate resolution needs name resolution the analyzer does not have.
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
        // inside another statement — `WITH x AS (DELETE ...) SELECT ...` — does.
        evidence.flag(RiskFlag::DataModifyingCte);
    }

    let cte_names = std::mem::take(&mut evidence.cte_names);
    evidence.objects.retain(|object| {
        let unqualified = object.catalog.is_none() && object.schema.is_none();
        let is_cte = cte_names
            .iter()
            .any(|alias| alias.eq_ignore_ascii_case(object.name.value()));
        !(unqualified && is_cte)
    });
    evidence.cte_names = cte_names;
    evidence
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use warden_core::analysis::{FunctionClassification, IdentifierQuoting};

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

    #[test]
    fn a_cte_name_is_not_an_object_but_what_it_reads_is() {
        let evidence = evidence("WITH x AS (SELECT * FROM secrets) SELECT * FROM x");
        assert_eq!(names(&evidence), ["secrets"]);
        assert!(evidence.risks.is_empty());
    }

    #[test]
    fn a_chain_of_ctes_leaves_only_the_real_relations() {
        let evidence =
            evidence("WITH a AS (SELECT 1), b AS (SELECT * FROM a) SELECT * FROM b JOIN t ON 1=1");
        assert_eq!(names(&evidence), ["t"]);
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
    fn a_table_factor_this_analyzer_cannot_describe_is_unknown_construct() {
        // `JSON_TABLE` is its own `TableFactor` variant, distinct from `Table`,
        // `Derived`, `NestedJoin` and `Function` — it can only be reached through
        // the wildcard arm, which is what this test exercises.
        assert!(
            evidence("SELECT * FROM JSON_TABLE('[1,2]', '$[*]' COLUMNS(a INT PATH '$')) AS jt")
                .risks
                .contains(&RiskFlag::UnknownConstruct)
        );
    }

    #[test]
    fn the_visitor_descends_into_an_expression_subquery() {
        // Nothing else in this suite proves the walk reaches a relation that is
        // reachable only through an `Expr`, not through `Query`/`TableFactor`
        // directly.
        assert_eq!(
            names(&evidence(
                "SELECT * FROM t WHERE id IN (SELECT id FROM secrets)"
            )),
            ["t", "secrets"]
        );
    }

    #[test]
    fn quoting_survives_into_the_object_reference() {
        let quoted = evidence("SELECT * FROM `Orders`");
        assert_eq!(quoted.objects[0].name.value(), "Orders");
        assert_eq!(quoted.objects[0].name.quoting(), IdentifierQuoting::Quoted);
        assert_eq!(
            evidence("SELECT * FROM Orders").objects[0].name.quoting(),
            IdentifierQuoting::Unquoted
        );
    }

    #[test]
    fn a_relation_is_unknown_unless_it_is_provably_a_function() {
        assert_eq!(
            evidence("SELECT * FROM t").objects[0].kind,
            ObjectKind::Unknown
        );
        assert_eq!(
            evidence("SELECT * FROM my_func(1)").objects[0].kind,
            ObjectKind::Function
        );
    }

    #[test]
    fn a_function_carries_its_classification_and_its_risk() {
        let evidence = evidence("SELECT SLEEP(5), COUNT(*) FROM t");
        let sleep = &evidence.functions[0];
        assert_eq!(sleep.name.value(), "SLEEP");
        assert_eq!(sleep.classification, FunctionClassification::KnownDangerous);
        assert!(evidence.risks.contains(&RiskFlag::DelayFunction));
        assert_eq!(
            evidence.functions[1].classification,
            FunctionClassification::KnownSafe
        );
    }

    #[test]
    fn a_qualified_function_keeps_its_schema() {
        let evidence = evidence("SELECT sch.fn(1) FROM t");
        let function = &evidence.functions[0];
        assert_eq!(function.name.value(), "fn");
        assert_eq!(
            function.schema.as_ref().map(SqlIdentifier::value),
            Some("sch")
        );
        assert_eq!(function.classification, FunctionClassification::Unknown);
        assert!(evidence.risks.contains(&RiskFlag::UserDefinedFunction));
    }

    #[test]
    fn a_function_called_in_relation_position_is_classified() {
        let evidence = evidence("SELECT * FROM sleep(5)");
        assert_eq!(evidence.objects[0].kind, ObjectKind::Function);
        let sleep = &evidence.functions[0];
        assert_eq!(sleep.name.value(), "sleep");
        assert_eq!(sleep.classification, FunctionClassification::KnownDangerous);
        assert!(evidence.risks.contains(&RiskFlag::DelayFunction));
    }

    #[test]
    fn an_unknown_function_called_in_relation_position_is_still_denied() {
        let evidence = evidence("SELECT * FROM my_udf(1)");
        assert_eq!(
            evidence.functions[0].classification,
            FunctionClassification::Unknown
        );
        assert!(evidence.risks.contains(&RiskFlag::UserDefinedFunction));
    }

    #[test]
    fn a_function_name_is_never_reported_as_a_relation() {
        assert!(
            evidence("SELECT LOAD_FILE('/etc/passwd')")
                .objects
                .is_empty()
        );
    }

    #[test]
    fn a_locking_clause_is_recorded_as_a_fact_and_as_a_risk() {
        for sql in ["SELECT * FROM t FOR UPDATE", "SELECT * FROM t FOR SHARE"] {
            let evidence = evidence(sql);
            assert!(evidence.has_locking_clause, "{sql}");
            assert!(evidence.risks.contains(&RiskFlag::LockingRead), "{sql}");
        }
    }

    #[test]
    fn a_variable_assignment_inside_a_select_is_session_mutation() {
        assert!(
            evidence("SELECT @x := 1")
                .risks
                .contains(&RiskFlag::SessionMutation)
        );
    }

    #[test]
    fn reading_a_session_variable_is_not_mutating_one() {
        assert!(evidence("SELECT @@version, @x").risks.is_empty());
    }

    #[test]
    fn a_select_into_a_relation_is_flagged() {
        assert!(
            evidence("SELECT * INTO newtbl FROM t")
                .risks
                .contains(&RiskFlag::SelectInto)
        );
    }

    #[test]
    fn a_select_into_inside_a_set_operation_is_still_flagged() {
        // `into` lives on `Select`, not on `Query::body` directly: the left arm of
        // a `UNION` is a `Select` reached only through `pre_visit_select`.
        assert!(
            evidence("SELECT * INTO newtbl FROM t UNION SELECT 1")
                .risks
                .contains(&RiskFlag::SelectInto)
        );
    }

    #[test]
    fn explain_analyze_is_flagged_and_its_inner_statement_is_still_seen() {
        let evidence = evidence("EXPLAIN ANALYZE SELECT 1");
        assert_eq!(
            evidence.kinds,
            [StatementKind::Explain, StatementKind::Select]
        );
        assert!(evidence.risks.contains(&RiskFlag::ExplainAnalyze));
    }

    #[test]
    fn every_write_shape_produces_a_write_risk() {
        for (sql, kind) in [
            ("INSERT INTO t VALUES (1)", StatementKind::Insert),
            ("UPDATE t SET a = 1", StatementKind::Update),
            ("DELETE FROM t", StatementKind::Delete),
        ] {
            let evidence = evidence(sql);
            assert_eq!(evidence.kinds[0], kind, "{sql}");
            assert!(evidence.risks.contains(&RiskFlag::WriteStatement), "{sql}");
            assert!(
                !evidence.risks.contains(&RiskFlag::DataModifyingCte),
                "a root write is not a nested one: {sql}"
            );
        }
    }

    #[test]
    fn a_write_that_is_the_second_statement_of_a_batch_is_not_a_nested_write() {
        // Depth is tracked during the walk, not inferred from batch position: the
        // second statement of a batch is still a root statement, at depth 1.
        let evidence = evidence("SELECT 1; DELETE FROM t");
        assert!(evidence.risks.contains(&RiskFlag::MultipleStatements));
        assert!(evidence.risks.contains(&RiskFlag::WriteStatement));
        assert!(!evidence.risks.contains(&RiskFlag::DataModifyingCte));
    }

    #[test]
    fn a_write_reached_by_descending_into_a_cte_is_a_data_modifying_cte() {
        let evidence = evidence("WITH x AS (DELETE FROM t) SELECT * FROM x");
        assert!(evidence.risks.contains(&RiskFlag::WriteStatement));
        assert!(evidence.risks.contains(&RiskFlag::DataModifyingCte));
    }

    #[test]
    fn two_statements_are_reported_as_a_risk_not_only_as_a_count() {
        assert!(
            evidence("SELECT 1; SELECT 2")
                .risks
                .contains(&RiskFlag::MultipleStatements)
        );
    }

    #[test]
    fn ddl_session_and_routine_statements_each_name_their_own_risk() {
        assert!(
            evidence("CREATE TABLE t (a INT)")
                .risks
                .contains(&RiskFlag::Ddl)
        );
        assert!(
            evidence("SET @x = 1")
                .risks
                .contains(&RiskFlag::SessionMutation)
        );
        assert!(
            evidence("CALL p(1)")
                .risks
                .contains(&RiskFlag::StoredRoutine)
        );
    }

    #[test]
    fn a_risk_is_recorded_once_however_many_times_it_occurs() {
        let evidence = evidence("SELECT SLEEP(1), SLEEP(2)");
        assert_eq!(
            evidence
                .risks
                .iter()
                .filter(|risk| **risk == RiskFlag::DelayFunction)
                .count(),
            1
        );
        assert_eq!(evidence.functions.len(), 2);
    }
}
