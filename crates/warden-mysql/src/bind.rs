//! The one place agent SQL becomes a statement the driver will run.
//!
//! `AssertSqlSafe` is unavoidable here and it is honest: the string is agent SQL,
//! and SQLx asks the caller to say so out loud. What makes it safe is not this call
//! but everything before it — the statement was parsed in the MySQL dialect, every
//! policy evaluated the evidence, and the text is byte-for-byte the analyzed text
//! because every field between the two is private (SPEC section 6, invariant 19).
//!
//! `sqlx::raw_sql`, the multi-statement API, stays banned by `clippy.toml`, and
//! nothing here interpolates a value into the statement: parameters are bound
//! (`docs/operations.md` section 6.3).

use sqlx::mysql::{MySql, MySqlArguments};
use sqlx::query::Query;
use sqlx::{AssertSqlSafe, query};
use warden_core::parameter::ParameterValue;

/// Builds the bound statement for one authorized query.
///
/// The statement is left `persistent` — SQLx's default — deliberately. With
/// `statement_cache_capacity(0)` on `agent_pool`, `sqlx-mysql` takes the uncached
/// path, which sends `StmtClose` immediately after execution, so nothing accumulates
/// on the server. `.persistent(false)` is PostgreSQL's control and is redundant here
/// (`docs/operations.md` section 4).
pub(crate) fn statement<'q>(
    sql: &str,
    parameters: &[ParameterValue],
) -> Query<'q, MySql, MySqlArguments> {
    let mut statement = query(AssertSqlSafe(sql.to_owned()));
    for parameter in parameters {
        statement = match parameter {
            // Typed as an absent string so the driver sends a NULL of a definite
            // type rather than inferring one.
            ParameterValue::Null => statement.bind(Option::<String>::None),
            ParameterValue::Bool(value) => statement.bind(*value),
            ParameterValue::I64(value) => statement.bind(*value),
            ParameterValue::U64(value) => statement.bind(*value),
            ParameterValue::F64(value) => statement.bind(*value),
            ParameterValue::String(value) => statement.bind(value.clone()),
        };
    }
    statement
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use sqlx::Execute;

    use super::*;

    #[test]
    fn the_bound_statement_is_the_analyzed_statement() {
        let sql = "SELECT id FROM orders WHERE customer_id = ? LIMIT 5";
        let statement = statement(sql, &[ParameterValue::String("c-1".to_owned())]);
        // `Query` also has an inherent `persistent(self, bool)` *setter*, which
        // shadows `Execute::persistent(&self) -> bool` in ordinary method-call
        // syntax. Fully qualified syntax reaches the getter instead.
        assert!(Execute::persistent(&statement));
        // `Execute::sql` takes `self` by value, so it runs last.
        assert_eq!(Execute::sql(statement).as_str(), sql);
    }
}
