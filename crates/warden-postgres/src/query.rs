//! The one constructor for a statement that may run on `agent_pool`.
//!
//! PostgreSQL retains uncached named prepared statements. The cache capacity alone
//! therefore cannot enforce cleanup: [`agent_query`] defaults every statement to
//! non-persistent. The sole override is the authorized parameter-bound query built
//! by [`crate::bind::statement`], which temporarily uses a named statement so SQLx
//! can resolve custom result metadata; the executor removes it before the connection
//! returns to the pool or retires that connection when cleanup is unconfirmed.

use sqlx::postgres::PgArguments;
use sqlx::query::Query;
use sqlx::{Postgres, SqlSafeStr};

/// Builds an agent-pool statement that is non-persistent by default.
pub(crate) fn agent_query(sql: impl SqlSafeStr) -> Query<'static, Postgres, PgArguments> {
    sqlx::query(sql).persistent(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Execute;

    #[test]
    fn agent_queries_default_to_non_persistent() {
        assert!(!Execute::persistent(&agent_query("SELECT 1")));
    }
}
