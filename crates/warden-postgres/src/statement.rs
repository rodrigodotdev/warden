//! Mapping a parsed PostgreSQL statement to its security category.

use sqlparser::ast::Statement;
use warden_core::analysis::StatementKind;

/// Classifies one statement.
///
/// The wildcard maps to [`StatementKind::Unknown`], which every policy denies
/// (AGENTS.md, "Modeling"; ADR-0011). `sqlparser::ast::Statement` has roughly 150
/// variants covering nine dialects, so an exhaustive match would be unreviewable and
/// would break on every upgrade for statements PostgreSQL cannot even express. What
/// the named arms buy is not permission — only `Select` is ever permitted, by
/// `ReadOnlyRootStatementPolicy` — but an audit record that says `delete` or
/// `session_control` instead of `unknown`.
///
/// `RESET`, `LISTEN`, `UNLISTEN` and `NOTIFY` are session control: the first two
/// change session configuration and the session's subscription set, and `NOTIFY`
/// queues a notification on the current transaction. All four survive on a pooled
/// connection exactly as `SET` does. `VACUUM` is maintenance, so it joins `ANALYZE`
/// in `Utility`.
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
        S::Set(_)
        | S::Reset(_)
        | S::Use(_)
        | S::LISTEN { .. }
        | S::UNLISTEN { .. }
        | S::NOTIFY { .. } => K::SessionControl,
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
        | S::CreateExtension { .. }
        | S::CreateDomain(_)
        | S::CreateType { .. }
        | S::CreatePolicy { .. }
        | S::AlterTable(_)
        | S::AlterView { .. }
        | S::AlterIndex { .. }
        | S::AlterSchema(_)
        | S::AlterRole { .. }
        | S::AlterUser(_)
        | S::AlterFunction(_)
        | S::AlterType(_)
        | S::AlterPolicy { .. }
        | S::Drop { .. }
        | S::DropFunction(_)
        | S::DropProcedure { .. }
        | S::DropTrigger(_)
        | S::DropDomain(_)
        | S::DropExtension { .. }
        | S::DropPolicy { .. }
        | S::Truncate(_)
        | S::RenameTable(_)
        | S::Grant(_)
        | S::Revoke(_) => K::Ddl,
        S::Analyze(_)
        | S::Vacuum(_)
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
        assert_eq!(
            kind("WITH RECURSIVE t(n) AS (SELECT 1) SELECT * FROM t"),
            StatementKind::Select
        );
    }

    #[test]
    fn writes_are_named_individually_so_an_audit_can_say_which() {
        assert_eq!(kind("INSERT INTO t VALUES (1)"), StatementKind::Insert);
        assert_eq!(kind("UPDATE t SET a = 1"), StatementKind::Update);
        assert_eq!(kind("DELETE FROM t"), StatementKind::Delete);
        assert_eq!(kind("COPY t FROM '/tmp/x'"), StatementKind::Copy);
    }

    #[test]
    fn the_recognized_but_unoffered_categories_are_not_unknown() {
        assert_eq!(kind("SHOW search_path"), StatementKind::Show);
        assert_eq!(kind("EXPLAIN SELECT 1"), StatementKind::Explain);
        assert_eq!(kind("CALL p(1)"), StatementKind::Call);
        assert_eq!(kind("CREATE TABLE t (a INT)"), StatementKind::Ddl);
        assert_eq!(kind("TRUNCATE t"), StatementKind::Ddl);
        assert_eq!(kind("BEGIN"), StatementKind::TransactionControl);
        assert_eq!(kind("ANALYZE t"), StatementKind::Utility);
        assert_eq!(kind("VACUUM"), StatementKind::Utility);
        assert_eq!(kind("DISCARD ALL"), StatementKind::Utility);
        assert_eq!(
            kind("LOCK TABLE t IN ACCESS EXCLUSIVE MODE"),
            StatementKind::Utility
        );
    }

    #[test]
    fn every_session_scoped_statement_is_session_control() {
        // All four survive on a pooled connection, which is what the kind records.
        for sql in [
            "SET search_path = app",
            "SET LOCAL statement_timeout = '1s'",
            "SET ROLE admin",
            "RESET ALL",
            "LISTEN channel",
            "UNLISTEN channel",
            "NOTIFY channel, 'payload'",
        ] {
            assert_eq!(kind(sql), StatementKind::SessionControl, "{sql}");
        }
    }

    #[test]
    fn an_unmapped_variant_is_unknown_and_never_ignored() {
        // A statement that parses and is outside the mapped set must reach a denied
        // kind through the wildcard rather than something permissive.
        // `CREATE SERVER` parses under `PostgreSqlDialect` and names no `Statement`
        // variant this module maps.
        let statements = parse::statements("CREATE SERVER s FOREIGN DATA WRAPPER w")
            .expect("fixture must parse");
        assert_eq!(kind_of(&statements[0]), StatementKind::Unknown);
    }
}
