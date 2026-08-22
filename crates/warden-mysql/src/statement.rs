//! Mapping a parsed MySQL statement to its security category.

// This module's `pub(crate)` item gains its first caller in Task 5's analyzer.
// Until then only this file's own `#[cfg(test)]` block reaches it, which the
// non-test build cannot see, so `dead_code` would otherwise fire here.
#![allow(dead_code)]

use sqlparser::ast::Statement;
use warden_core::analysis::StatementKind;

/// Classifies one statement.
///
/// The wildcard maps to [`StatementKind::Unknown`], which every policy denies
/// (AGENTS.md, "Modeling"; ADR-0011). `sqlparser::ast::Statement` has roughly 150
/// variants covering nine dialects, so an exhaustive match would be unreviewable and
/// would break on every upgrade for statements MySQL cannot even express. What the
/// named arms buy is not permission — only `Select` is ever permitted, by
/// `ReadOnlyRootStatementPolicy` — but an audit record that says `delete` or
/// `session_control` instead of `unknown`.
pub(crate) fn kind_of(statement: &Statement) -> StatementKind {
    use Statement as S;
    use StatementKind as K;

    match statement {
        S::Query(_) => K::Select,
        S::Insert(_) => K::Insert,
        S::Update(_) => K::Update,
        S::Delete(_) => K::Delete,
        S::Merge(_) => K::Merge,
        S::Call(_) => K::Call,
        S::Copy { .. } | S::CopyIntoSnowflake { .. } => K::Copy,
        S::Explain { .. } | S::ExplainTable { .. } => K::Explain,
        S::ShowTables { .. }
        | S::ShowColumns { .. }
        | S::ShowDatabases { .. }
        | S::ShowSchemas { .. }
        | S::ShowVariable { .. }
        | S::ShowVariables { .. }
        | S::ShowStatus { .. }
        | S::ShowCreate { .. }
        | S::ShowFunctions { .. }
        | S::ShowCollation { .. }
        | S::ShowCharset(_)
        | S::ShowObjects(_)
        | S::ShowViews { .. }
        | S::ShowCatalogs { .. }
        | S::ShowProcessList { .. } => K::Show,
        // `USE db` changes which database an unqualified name resolves in, which is
        // session state on a pooled connection exactly as `SET` is.
        S::Set(_) | S::Use(_) => K::SessionControl,
        S::StartTransaction { .. }
        | S::Commit { .. }
        | S::Rollback { .. }
        | S::Savepoint { .. }
        | S::ReleaseSavepoint { .. } => K::TransactionControl,
        S::CreateTable(_)
        | S::CreateView(_)
        | S::CreateIndex(_)
        | S::CreateSchema { .. }
        | S::CreateDatabase { .. }
        | S::CreateFunction(_)
        | S::CreateProcedure { .. }
        | S::CreateTrigger(_)
        | S::CreateSequence { .. }
        | S::CreateRole(_)
        | S::CreateUser(_)
        | S::AlterTable(_)
        | S::AlterView { .. }
        | S::AlterIndex { .. }
        | S::AlterSchema(_)
        | S::AlterRole { .. }
        | S::AlterUser(_)
        | S::AlterFunction(_)
        | S::AlterType(_)
        | S::Drop { .. }
        | S::DropFunction(_)
        | S::DropProcedure { .. }
        | S::DropTrigger(_)
        | S::Truncate(_)
        | S::RenameTable(_)
        | S::Grant(_)
        | S::Revoke(_) => K::Ddl,
        S::Analyze(_)
        | S::Flush { .. }
        | S::Kill { .. }
        | S::OptimizeTable { .. }
        | S::LockTables { .. }
        | S::UnlockTables
        | S::Lock(_)
        | S::Prepare { .. }
        | S::Execute { .. }
        | S::Deallocate { .. }
        | S::Declare { .. }
        | S::Fetch { .. }
        | S::Close { .. }
        | S::Discard { .. }
        | S::Comment { .. }
        | S::Pragma { .. } => K::Utility,
        _ => K::Unknown,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::parse;

    fn kind(sql: &str) -> StatementKind {
        let statements = parse::statements(sql).expect("fixture must parse");
        kind_of(&statements[0])
    }

    #[test]
    fn a_select_is_the_only_kind_the_query_tool_can_accept() {
        assert_eq!(kind("SELECT 1"), StatementKind::Select);
        assert_eq!(
            kind("WITH x AS (SELECT 1) SELECT * FROM x"),
            StatementKind::Select
        );
    }

    #[test]
    fn writes_are_named_individually_so_an_audit_can_say_which() {
        assert_eq!(kind("INSERT INTO t VALUES (1)"), StatementKind::Insert);
        assert_eq!(kind("UPDATE t SET a = 1"), StatementKind::Update);
        assert_eq!(kind("DELETE FROM t"), StatementKind::Delete);
    }

    #[test]
    fn the_recognized_but_unoffered_categories_are_not_unknown() {
        assert_eq!(kind("SHOW TABLES"), StatementKind::Show);
        assert_eq!(kind("EXPLAIN SELECT 1"), StatementKind::Explain);
        assert_eq!(kind("CALL p(1)"), StatementKind::Call);
        assert_eq!(kind("CREATE TABLE t (a INT)"), StatementKind::Ddl);
        assert_eq!(kind("SET @x = 1"), StatementKind::SessionControl);
        assert_eq!(
            kind("SET SESSION sql_mode = 'X'"),
            StatementKind::SessionControl
        );
        assert_eq!(kind("START TRANSACTION"), StatementKind::TransactionControl);
        assert_eq!(kind("FLUSH TABLES"), StatementKind::Utility);
        assert_eq!(kind("KILL 1"), StatementKind::Utility);
    }

    #[test]
    fn an_unmapped_variant_is_unknown_and_never_ignored() {
        // A statement that parses and is outside the mapped set must reach a denied
        // kind through the wildcard rather than something permissive. `LISTEN` does
        // not parse under `MySqlDialect` (it is gated behind
        // `Dialect::supports_listen_notify`, which MySQL does not implement);
        // `VACUUM` parses under any dialect and names no `Statement` variant this
        // module maps.
        let statements = parse::statements("VACUUM").expect("fixture must parse");
        assert_eq!(kind_of(&statements[0]), StatementKind::Unknown);
    }
}
