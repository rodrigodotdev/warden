//! The one constructor for a statement that may run on `agent_pool`.
//!
//! PostgreSQL retains uncached named prepared statements. The cache capacity alone
//! therefore cannot enforce cleanup: each agent statement must be non-persistent.

use sqlx::postgres::PgArguments;
use sqlx::query::Query;
use sqlx::{Postgres, SqlSafeStr};

/// Builds a statement that leaves no named prepared statement behind.
pub(crate) fn agent_query(sql: impl SqlSafeStr) -> Query<'static, Postgres, PgArguments> {
    sqlx::query(sql).persistent(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Execute;

    #[test]
    fn agent_statements_are_not_persistent() {
        assert!(!Execute::persistent(&agent_query("SELECT 1")));
    }
}
