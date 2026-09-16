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
    /// Maximum size of one bound parameter, as `ParameterValue::input_bytes` measures it.
    pub max_parameter_bytes: usize,
    /// Maximum size of every bound parameter added together.
    pub max_total_parameter_bytes: usize,
}

impl Default for InputLimits {
    fn default() -> Self {
        Self {
            max_sql_bytes: 64 * 1024,
            max_parameters: 100,
            max_parameter_bytes: 64 * 1024,
            max_total_parameter_bytes: 256 * 1024,
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
    /// One parameter exceeded the per-parameter byte budget.
    #[error("parameter {index} is {actual} bytes; the maximum is {max}")]
    ParameterTooLarge {
        /// Zero-based position of the parameter.
        index: usize,
        /// Its size as `ParameterValue::input_bytes` measures it.
        actual: usize,
        /// Configured maximum.
        max: usize,
    },
    /// The parameters together exceeded the total byte budget.
    ///
    /// Carries no total: the sum is abandoned the moment it passes `max`, and an
    /// addition that would overflow is reported here rather than as an invented figure.
    #[error("the parameters together exceed {max} bytes")]
    ParametersTooLarge {
        /// Configured maximum.
        max: usize,
    },
}

impl PublicError for QueryRequestError {
    fn public_code(&self) -> PublicErrorCode {
        match self {
            Self::EmptySql => PublicErrorCode::QueryParseError,
            Self::SqlTooLarge { .. }
            | Self::TooManyParameters { .. }
            | Self::ParameterTooLarge { .. }
            | Self::ParametersTooLarge { .. } => PublicErrorCode::QueryTooLarge,
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
    /// - [`QueryRequestError::ParameterTooLarge`] if any one parameter exceeds
    ///   `limits.max_parameter_bytes`.
    /// - [`QueryRequestError::ParametersTooLarge`] if every parameter added together
    ///   exceeds `limits.max_total_parameter_bytes`.
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
        let mut total: usize = 0;
        for (index, parameter) in parameters.iter().enumerate() {
            let actual = parameter.input_bytes();
            if actual > limits.max_parameter_bytes {
                return Err(QueryRequestError::ParameterTooLarge {
                    index,
                    actual,
                    max: limits.max_parameter_bytes,
                });
            }
            total = total
                .checked_add(actual)
                .filter(|total| *total <= limits.max_total_parameter_bytes)
                .ok_or(QueryRequestError::ParametersTooLarge {
                    max: limits.max_total_parameter_bytes,
                })?;
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
    use crate::error::{PublicError, PublicErrorCode};

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
            ..InputLimits::default()
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

    #[test]
    fn parameter_limits_use_utf8_bytes_and_include_the_boundary() {
        let limits = InputLimits {
            max_parameter_bytes: 4,
            max_total_parameter_bytes: 4,
            ..InputLimits::default()
        };
        // "éé" is two characters and four bytes: exactly the budget.
        let accepted = QueryRequest::new(
            connection(),
            "SELECT $1".to_owned(),
            vec![ParameterValue::String("éé".to_owned())],
            &limits,
        );
        assert!(accepted.is_ok());
        let rejected = QueryRequest::new(
            connection(),
            "SELECT $1".to_owned(),
            vec![ParameterValue::String("ééa".to_owned())],
            &limits,
        )
        .unwrap_err();
        assert_eq!(
            rejected,
            QueryRequestError::ParameterTooLarge {
                index: 0,
                actual: 5,
                max: 4
            }
        );
        assert_eq!(rejected.public_code(), PublicErrorCode::QueryTooLarge);
    }

    #[test]
    fn the_total_budget_is_checked_after_every_parameter() {
        let limits = InputLimits {
            max_parameter_bytes: 8,
            max_total_parameter_bytes: 8,
            ..InputLimits::default()
        };
        // One number is eight bytes: exactly the total.
        assert!(
            QueryRequest::new(
                connection(),
                "SELECT $1".to_owned(),
                vec![ParameterValue::I64(1)],
                &limits
            )
            .is_ok()
        );
        // A boolean after it is the ninth byte.
        let error = QueryRequest::new(
            connection(),
            "SELECT $1, $2".to_owned(),
            vec![ParameterValue::I64(1), ParameterValue::Bool(true)],
            &limits,
        )
        .unwrap_err();
        assert_eq!(error, QueryRequestError::ParametersTooLarge { max: 8 });
        assert_eq!(error.public_code(), PublicErrorCode::QueryTooLarge);
    }

    #[test]
    fn nulls_and_empty_strings_cost_no_bytes_but_still_count_as_parameters() {
        let limits = InputLimits {
            max_total_parameter_bytes: 0,
            ..InputLimits::default()
        };
        let free = vec![ParameterValue::Null, ParameterValue::String(String::new())];
        assert!(QueryRequest::new(connection(), "SELECT $1, $2".to_owned(), free, &limits).is_ok());
        let too_many = vec![ParameterValue::Null; 101];
        assert_eq!(
            QueryRequest::new(connection(), "SELECT 1".to_owned(), too_many, &limits).unwrap_err(),
            QueryRequestError::TooManyParameters {
                actual: 101,
                max: 100
            }
        );
    }

    #[test]
    fn every_parameter_shape_has_a_documented_input_size() {
        assert_eq!(ParameterValue::Null.input_bytes(), 0);
        assert_eq!(ParameterValue::Bool(false).input_bytes(), 1);
        assert_eq!(ParameterValue::I64(-1).input_bytes(), 8);
        assert_eq!(ParameterValue::U64(u64::MAX).input_bytes(), 8);
        assert_eq!(ParameterValue::F64(0.5).input_bytes(), 8);
        assert_eq!(ParameterValue::String("héllo".to_owned()).input_bytes(), 6);
    }
}
