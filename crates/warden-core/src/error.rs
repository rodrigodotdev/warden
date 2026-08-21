//! The error codes a model is allowed to see.
//!
//! Internal errors are typed per crate with `thiserror` and sanitized at the MCP
//! boundary. A raw driver error can contain hostnames, users, database names, and
//! SQL, so nothing but one of these codes and fixed-table text crosses that
//! boundary (`docs/security.md` section 10).

use std::fmt;

/// The complete, closed set of codes an MCP client can observe.
///
/// No `#[non_exhaustive]`: adding a variant must break every consumer that maps
/// codes, which is the only guaranteed moment to review that mapping (ADR-0021).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicErrorCode {
    /// The named connection is not configured.
    ConnectionNotFound,
    /// The connection exists but cannot currently serve requests.
    ConnectionUnavailable,
    /// The input exceeded an accepted size before parsing.
    QueryTooLarge,
    /// The dialect parser rejected the statement.
    QueryParseError,
    /// Policy denied the statement.
    QueryRejected,
    /// The concurrency queue was full within `max_queue_wait`.
    ServerBusy,
    /// Execution exceeded its deadline.
    QueryTimeout,
    /// Execution was cancelled.
    QueryCancelled,
    /// The result exceeded the byte budget.
    QueryResultTooLarge,
    /// A value could not be normalized safely.
    QueryNormalizationError,
    /// The database rejected or failed the statement.
    QueryExecutionError,
    /// Schema metadata could not be read.
    SchemaLookupError,
    /// A plan could not be produced.
    ExplainError,
    /// An unexpected internal failure, including a contained panic.
    InternalError,
}

impl PublicErrorCode {
    /// Every code, in the order `docs/security.md` section 10 lists them.
    ///
    /// Keep this array in step with the enum; the unit tests below fail loudly if
    /// it drifts.
    pub const ALL: [Self; 14] = [
        Self::ConnectionNotFound,
        Self::ConnectionUnavailable,
        Self::QueryTooLarge,
        Self::QueryParseError,
        Self::QueryRejected,
        Self::ServerBusy,
        Self::QueryTimeout,
        Self::QueryCancelled,
        Self::QueryResultTooLarge,
        Self::QueryNormalizationError,
        Self::QueryExecutionError,
        Self::SchemaLookupError,
        Self::ExplainError,
        Self::InternalError,
    ];

    /// The wire spelling of this code.
    ///
    /// The match is exhaustive on purpose: a new variant must not compile until it
    /// has a documented spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionNotFound => "connection_not_found",
            Self::ConnectionUnavailable => "connection_unavailable",
            Self::QueryTooLarge => "query_too_large",
            Self::QueryParseError => "query_parse_error",
            Self::QueryRejected => "query_rejected",
            Self::ServerBusy => "server_busy",
            Self::QueryTimeout => "query_timeout",
            Self::QueryCancelled => "query_cancelled",
            Self::QueryResultTooLarge => "query_result_too_large",
            Self::QueryNormalizationError => "query_normalization_error",
            Self::QueryExecutionError => "query_execution_error",
            Self::SchemaLookupError => "schema_lookup_error",
            Self::ExplainError => "explain_error",
            Self::InternalError => "internal_error",
        }
    }
}

impl fmt::Display for PublicErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An internal error that has a safe public representation.
///
/// Implemented only by errors that can reach a model. Startup and configuration
/// errors deliberately do not implement it: they are operator-facing and never
/// cross the MCP boundary.
pub trait PublicError {
    /// The code the model receives instead of the internal message.
    fn public_code(&self) -> PublicErrorCode;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn every_code_serializes_to_its_documented_spelling() {
        for code in PublicErrorCode::ALL {
            assert_eq!(
                serde_json::to_string(&code).unwrap(),
                format!("\"{}\"", code.as_str())
            );
        }
    }

    #[test]
    fn the_code_list_matches_the_security_document() {
        let actual: BTreeSet<&str> = PublicErrorCode::ALL.iter().map(|c| c.as_str()).collect();
        let documented: BTreeSet<&str> = BTreeSet::from([
            "connection_not_found",
            "connection_unavailable",
            "explain_error",
            "internal_error",
            "query_cancelled",
            "query_execution_error",
            "query_normalization_error",
            "query_parse_error",
            "query_rejected",
            "query_result_too_large",
            "query_timeout",
            "query_too_large",
            "schema_lookup_error",
            "server_busy",
        ]);
        assert_eq!(actual, documented);
        assert_eq!(
            actual.len(),
            PublicErrorCode::ALL.len(),
            "duplicate spelling"
        );
    }
}
