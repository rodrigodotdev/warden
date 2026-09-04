//! Size-validated query input.

use std::fmt;

use crate::connection::ConnectionName;
use crate::error::{PublicError, PublicErrorCode};
use crate::parameter::ParameterValue;

/// Hard input bounds, applied **before** any parsing
/// (`docs/data-model.md` section 2).
///
/// These are configurable, unlike the SPEC section 6 invariants, because they are
/// capacity limits rather than security rules (ADR-0026).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputLimits {
    /// Maximum SQL length in bytes.
    pub max_sql_bytes: usize,
    /// Maximum number of bound parameters.
    pub max_parameters: usize,
}

impl Default for InputLimits {
    fn default() -> Self {
        Self {
            max_sql_bytes: 64 * 1024,
            max_parameters: 100,
        }
    }
}

/// Input rejected before parsing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QueryRequestError {
    /// The SQL text was empty or contained only whitespace.
    #[error("sql is empty")]
    EmptySql,
    /// The SQL text exceeded the byte budget.
    #[error("sql is {actual} bytes; the maximum is {max}")]
    SqlTooLarge {
        /// Size of the rejected SQL in bytes.
        actual: usize,
        /// Configured maximum.
        max: usize,
    },
    /// Too many parameters were supplied.
    #[error("request carries {actual} parameters; the maximum is {max}")]
    TooManyParameters {
        /// Number of parameters supplied.
        actual: usize,
        /// Configured maximum.
        max: usize,
    },
}

impl PublicError for QueryRequestError {
    fn public_code(&self) -> PublicErrorCode {
        match self {
            Self::EmptySql => PublicErrorCode::QueryParseError,
            Self::SqlTooLarge { .. } | Self::TooManyParameters { .. } => {
                PublicErrorCode::QueryTooLarge
            }
        }
    }
}

/// One agent statement with its parameters.
///
/// Fields are private so the SQL text cannot be replaced after analysis: SPEC
/// section 6, invariant 19 requires the executed statement to be byte-for-byte the
/// analyzed statement, and the only way to keep that promise is for nothing to be
/// able to edit it in between.
#[derive(Clone, PartialEq)]
pub struct QueryRequest {
    connection: ConnectionName,
    sql: String,
    parameters: Vec<ParameterValue>,
}

impl QueryRequest {
    /// Validates size limits and takes ownership of the input.
    ///
    /// Limits are passed explicitly rather than read from a default so that no call
    /// site can silently use a looser bound than the operator configured
    /// (SPEC section 4, "explicit paths").
    ///
    /// # Errors
    ///
    /// - [`QueryRequestError::EmptySql`] if `sql` is empty or only whitespace.
    /// - [`QueryRequestError::SqlTooLarge`] if `sql` exceeds
    ///   `limits.max_sql_bytes`.
    /// - [`QueryRequestError::TooManyParameters`] if `parameters` exceeds
    ///   `limits.max_parameters`.
    ///
    /// No variant quotes the statement or a bound parameter (SPEC section 6,
    /// invariants 22–23).
    pub fn new(
        connection: ConnectionName,
        sql: String,
        parameters: Vec<ParameterValue>,
        limits: &InputLimits,
    ) -> Result<Self, QueryRequestError> {
        if sql.trim().is_empty() {
            return Err(QueryRequestError::EmptySql);
        }
        if sql.len() > limits.max_sql_bytes {
            return Err(QueryRequestError::SqlTooLarge {
                actual: sql.len(),
                max: limits.max_sql_bytes,
            });
        }
        if parameters.len() > limits.max_parameters {
            return Err(QueryRequestError::TooManyParameters {
                actual: parameters.len(),
                max: limits.max_parameters,
            });
        }
        Ok(Self {
            connection,
            sql,
            parameters,
        })
    }

    /// The connection this statement targets.
    #[must_use]
    pub fn connection(&self) -> &ConnectionName {
        &self.connection
    }

    /// The exact SQL that analysis and execution must both see.
    #[must_use]
    pub fn sql(&self) -> &str {
        &self.sql
    }

    /// The bound parameters, in placeholder order.
    #[must_use]
    pub fn parameters(&self) -> &[ParameterValue] {
        &self.parameters
    }
}

/// Prints shape, never the statement. Raw SQL is off by default in logs, traces,
/// and audits (SPEC section 6, invariant 22), and a derived `Debug` would defeat
/// that on the first `{:?}` in a log line or a panic message.
impl fmt::Debug for QueryRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueryRequest")
            .field("connection", &self.connection)
            .field("sql_bytes", &self.sql.len())
            .field("parameters", &self.parameters.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn connection() -> ConnectionName {
        "production-mysql".parse().unwrap()
    }

    fn request(sql: &str) -> Result<QueryRequest, QueryRequestError> {
        QueryRequest::new(
            connection(),
            sql.to_owned(),
            Vec::new(),
            &InputLimits::default(),
        )
    }

    #[test]
    fn default_limits_match_the_data_model() {
        let limits = InputLimits::default();
        assert_eq!(limits.max_sql_bytes, 65_536);
        assert_eq!(limits.max_parameters, 100);
    }

    #[test]
    fn accepts_a_statement_at_the_byte_boundary() {
        let limits = InputLimits::default();
        let sql = "-".repeat(limits.max_sql_bytes);
        assert!(QueryRequest::new(connection(), sql, Vec::new(), &limits).is_ok());
    }

    #[test]
    fn rejects_empty_oversized_and_overloaded_requests() {
        assert_eq!(
            request("   \n\t ").unwrap_err(),
            QueryRequestError::EmptySql
        );

        let limits = InputLimits::default();
        let too_long = "x".repeat(limits.max_sql_bytes + 1);
        assert_eq!(
            QueryRequest::new(connection(), too_long, Vec::new(), &limits).unwrap_err(),
            QueryRequestError::SqlTooLarge {
                actual: limits.max_sql_bytes + 1,
                max: limits.max_sql_bytes,
            }
        );

        let parameters = vec![ParameterValue::Null; limits.max_parameters + 1];
        assert_eq!(
            QueryRequest::new(connection(), "SELECT 1".to_owned(), parameters, &limits)
                .unwrap_err(),
            QueryRequestError::TooManyParameters {
                actual: limits.max_parameters + 1,
                max: limits.max_parameters,
            }
        );
    }

    #[test]
    fn size_limits_count_bytes_not_characters() {
        let limits = InputLimits {
            max_sql_bytes: 4,
            max_parameters: 1,
        };
        // Four characters, eight bytes.
        assert!(QueryRequest::new(connection(), "áéíó".to_owned(), Vec::new(), &limits).is_err());
    }

    #[test]
    fn accessors_return_the_input_unchanged() {
        let sql = "SELECT id FROM orders WHERE customer_id = ?";
        let query = QueryRequest::new(
            connection(),
            sql.to_owned(),
            vec![ParameterValue::String("c-1".to_owned())],
            &InputLimits::default(),
        )
        .unwrap();
        assert_eq!(query.sql(), sql);
        assert_eq!(query.connection().as_str(), "production-mysql");
        assert_eq!(query.parameters().len(), 1);
    }

    #[test]
    fn debug_hides_the_statement() {
        let query = request("SELECT password_hash FROM users").unwrap();
        let rendered = format!("{query:?}");
        assert!(!rendered.contains("password_hash"), "{rendered}");
        assert!(rendered.contains("sql_bytes: 31"), "{rendered}");
    }

    #[test]
    fn errors_never_echo_the_statement() {
        let limits = InputLimits::default();
        let sql = format!("SELECT '{}'", "secret".repeat(20_000));
        let error = QueryRequest::new(connection(), sql, Vec::new(), &limits).unwrap_err();
        assert!(!error.to_string().contains("secret"), "{error}");
        assert_eq!(error.public_code(), PublicErrorCode::QueryTooLarge);
    }
}
