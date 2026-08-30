//! The one place agent SQL becomes a statement the driver will run.
//!
//! `AssertSqlSafe` is unavoidable here and it is honest: the string is agent SQL,
//! and SQLx asks the caller to say so out loud. What makes it safe is not this call
//! but everything before it — the statement was parsed in the PostgreSQL dialect,
//! every policy evaluated the evidence, and the text is byte-for-byte the analyzed
//! text because every field between the two is private (SPEC section 6, invariant
//! 19).
//!
//! Everything begins at [`crate::query::agent_query`], never `sqlx::query`.
//! [`crate::execute`] deliberately makes this one bound statement persistent until
//! its transaction ends: SQLx resolves custom result metadata with a simple query,
//! and PostgreSQL destroys an unnamed statement when it receives that query. The
//! executor holds the same connection and follows every confirmed-cleanup path with
//! `DEALLOCATE ALL`; if cleanup cannot be confirmed or the request future is dropped,
//! its armed owner retires that connection, so the temporary named statement does not
//! survive a request.
//!
//! `sqlx::raw_sql`, the multi-statement API, stays banned by `clippy.toml`, and
//! nothing here interpolates a value into the statement: parameters are bound
//! (`docs/operations.md` section 6.3).

use sqlx::AssertSqlSafe;
use sqlx::postgres::{PgArguments, Postgres};
use sqlx::query::Query;
use sqlx::types::BigDecimal;
use warden_core::parameter::ParameterValue;

use crate::query::agent_query;

/// Builds the bound statement for one authorized query.
///
/// The two PostgreSQL-specific decisions are ADR-0035's:
///
/// * **`U64`.** PostgreSQL has no unsigned integer type and `sqlx` implements
///   `Encode<Postgres>` for no unsigned type at all, while `U64` is the variant
///   *every* non-negative JSON integer deserializes into. Anything up to
///   `i64::MAX` binds as `int8` exactly; above that, `numeric` is the only
///   PostgreSQL type that still holds the value without loss.
/// * **`Null`.** A parameter carries no declared type, so a NULL has to be sent as
///   *some* type; `text` is the choice, which is consistent with the rule
///   `docs/data-model.md` section 3 already states for PostgreSQL — callers cast
///   explicitly, as in `WHERE id = $1::uuid`.
pub(crate) fn statement(
    sql: &str,
    parameters: &[ParameterValue],
) -> Query<'static, Postgres, PgArguments> {
    bind_all(
        agent_query(AssertSqlSafe(sql.to_owned())).persistent(true),
        parameters,
    )
}

/// Builds the bound statement for one plan request.
///
/// Unlike [`statement`], this one keeps `agent_query`'s non-persistent default. The
/// single output column of `EXPLAIN (FORMAT JSON)` is `json`, a type SQLx already
/// knows, so nothing makes it resolve custom result metadata through a simple query
/// — which is the only reason the executed form needs a named statement and the
/// `DEALLOCATE ALL` that follows it. Confirmed against a PostgreSQL 17 container
/// with a user-defined enum in the inner statement's projection, so this is a
/// measurement rather than an inference (`docs/testing.md` section 4). No named
/// statement means nothing to clean up and no connection to retire.
pub(crate) fn plan_statement(
    sql: &str,
    parameters: &[ParameterValue],
) -> Query<'static, Postgres, PgArguments> {
    bind_all(agent_query(AssertSqlSafe(sql.to_owned())), parameters)
}

/// Binds every parameter in placeholder order, under ADR-0035's two rules.
fn bind_all<'q>(
    mut statement: Query<'q, Postgres, PgArguments>,
    parameters: &[ParameterValue],
) -> Query<'q, Postgres, PgArguments> {
    for parameter in parameters {
        statement = match parameter {
            ParameterValue::Null => statement.bind(Option::<String>::None),
            ParameterValue::Bool(value) => statement.bind(*value),
            ParameterValue::I64(value) => statement.bind(*value),
            ParameterValue::U64(value) => match i64::try_from(*value) {
                Ok(signed) => statement.bind(signed),
                Err(_too_large) => statement.bind(BigDecimal::from(*value)),
            },
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
    fn the_bound_statement_is_the_analyzed_statement_and_keeps_metadata_available() {
        let sql = "SELECT id FROM orders WHERE customer_id = $1 LIMIT 5";
        let statement = statement(sql, &[ParameterValue::String("c-1".to_owned())]);
        assert!(
            Execute::persistent(&statement),
            "a bound agent statement needs a named statement while SQLx resolves custom metadata"
        );
        assert_eq!(Execute::sql(statement).as_str(), sql);
    }

    #[test]
    fn every_parameter_variant_binds_and_the_count_is_right() {
        let mut statement = statement(
            "SELECT $1, $2, $3, $4, $5, $6",
            &[
                ParameterValue::Null,
                ParameterValue::Bool(true),
                ParameterValue::I64(-7),
                ParameterValue::U64(42),
                ParameterValue::F64(1.5),
                ParameterValue::String("x".to_owned()),
            ],
        );
        let arguments = Execute::take_arguments(&mut statement).unwrap().unwrap();
        assert_eq!(sqlx::Arguments::len(&arguments), 6);
    }

    #[test]
    fn an_unsigned_value_above_the_signed_range_still_binds_exactly() {
        // The boundary, both sides. Below it the value is an `int8`; above it there
        // is no PostgreSQL integer type left, and `numeric` is what keeps the value
        // exact rather than wrapping it into a negative `int8` (ADR-0035).
        for value in [
            u64::try_from(i64::MAX).unwrap(),
            u64::try_from(i64::MAX).unwrap() + 1,
            u64::MAX,
        ] {
            let mut statement = statement("SELECT $1", &[ParameterValue::U64(value)]);
            let arguments = Execute::take_arguments(&mut statement).unwrap().unwrap();
            assert_eq!(sqlx::Arguments::len(&arguments), 1, "{value}");
        }
    }

    #[test]
    fn a_plan_statement_needs_no_named_statement() {
        let sql = "EXPLAIN (FORMAT JSON) SELECT id FROM orders WHERE id = $1";
        let statement = plan_statement(sql, &[ParameterValue::I64(1)]);
        assert!(
            !Execute::persistent(&statement),
            "a plan has one json column, so nothing makes SQLx resolve custom \
             result metadata and no named statement is needed"
        );
        assert_eq!(Execute::sql(statement).as_str(), sql);
    }
}
