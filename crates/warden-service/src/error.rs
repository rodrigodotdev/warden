//! Every failure a service can return, and the public code each one becomes.
//!
//! One module rather than one file per service, for the reason
//! `crates/warden-ports/src/error.rs` gives: `docs/security.md` section 10 fixes a
//! closed set of codes an agent may observe, and the only way to review "no internal
//! failure reaches the model unsanitized" is to read the whole map at once.
//! `tests/service_rules.rs` checks the same map mechanically.
//!
//! Each variant delegates `public_code` to the port error it wraps, so this file adds
//! no new mapping decisions of its own — except for a failed audit attempt, which is
//! the one failure this layer invents (ADR-0022) and which is deliberately an
//! `internal_error`: the agent must not learn that Warden's audit sink is down.

use warden_core::error::{PublicError, PublicErrorCode};
use warden_policy::PolicyRejection;
use warden_ports::{
    AnalyzeError, AuditError, ConnectionError, ExecuteError, ExplainError, SchemaError,
};

use crate::redaction::RedactionRuleError;

/// Why a query produced no result.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum QueryServiceError {
    /// The connection could not serve the request.
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    /// Analysis produced no evidence at all.
    #[error(transparent)]
    Analyze(#[from] AnalyzeError),
    /// Policy denied the statement.
    #[error(transparent)]
    Rejected(#[from] PolicyRejection),
    /// The audit attempt could not be recorded, so nothing ran (ADR-0022).
    #[error("the audit attempt could not be recorded")]
    Audit {
        /// The sink's failure. Its `Display` prints no detail field.
        #[from]
        source: AuditError,
    },
    /// The database rejected, failed, or could not finish the statement.
    #[error(transparent)]
    Execute(#[from] ExecuteError),
}

impl PublicError for QueryServiceError {
    fn public_code(&self) -> PublicErrorCode {
        match self {
            Self::Connection(error) => error.public_code(),
            Self::Analyze(error) => error.public_code(),
            Self::Rejected(error) => error.public_code(),
            Self::Audit { source } => source.public_code(),
            Self::Execute(error) => error.public_code(),
        }
    }
}

/// Why a query plan could not be produced.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ExplainServiceError {
    /// The connection could not serve the request.
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    /// Analysis produced no evidence at all.
    #[error(transparent)]
    Analyze(#[from] AnalyzeError),
    /// Policy denied the statement.
    #[error(transparent)]
    Rejected(#[from] PolicyRejection),
    /// The audit attempt could not be recorded, so nothing ran (ADR-0022).
    #[error("the audit attempt could not be recorded")]
    Audit {
        /// The sink's failure. Its `Display` prints no detail field.
        #[from]
        source: AuditError,
    },
    /// The database rejected, failed, or could not finish planning the statement.
    #[error(transparent)]
    Explain(#[from] ExplainError),
}

impl PublicError for ExplainServiceError {
    fn public_code(&self) -> PublicErrorCode {
        match self {
            Self::Connection(error) => error.public_code(),
            Self::Analyze(error) => error.public_code(),
            Self::Rejected(error) => error.public_code(),
            Self::Audit { source } => source.public_code(),
            Self::Explain(error) => error.public_code(),
        }
    }
}

/// Why schema metadata could not be returned.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum SchemaServiceError {
    /// The connection could not serve the request.
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    /// The database could not return schema metadata.
    #[error(transparent)]
    Schema(#[from] SchemaError),
    /// The adapter does not implement schema search on this connection.
    ///
    /// Read from `Capabilities`, not from `Dialect`: services inspect capabilities
    /// (`docs/architecture.md` section 7), and this is the reader that keeps the flag
    /// honest.
    #[error("this connection does not support schema search")]
    SearchUnsupported,
}

impl PublicError for SchemaServiceError {
    fn public_code(&self) -> PublicErrorCode {
        match self {
            Self::Connection(error) => error.public_code(),
            Self::Schema(error) => error.public_code(),
            Self::SearchUnsupported => PublicErrorCode::SchemaLookupError,
        }
    }
}

/// Why the services could not be assembled.
///
/// Deliberately **not** a [`PublicError`]: the composition root raises this before any
/// transport is serving, so it never crosses the MCP boundary — the same distinction
/// `warden_ports::RuntimeError` draws. `tests/service_rules.rs` enforces it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServiceBuildError {
    /// A configured redaction rule could not be parsed.
    #[error(transparent)]
    Redaction(#[from] RedactionRuleError),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use warden_core::error::{PublicError, PublicErrorCode};
    use warden_core::result::NormalizationError;
    use warden_ports::{
        AnalyzeError, AuditError, ConnectionError, ExecuteError, ExplainError, SchemaError,
    };

    use super::*;
    use crate::testing;

    #[test]
    fn every_query_failure_maps_to_the_documented_public_code() {
        let rejection = testing::rejection_with_internal_detail();
        let cases: Vec<(QueryServiceError, PublicErrorCode)> = vec![
            (
                ConnectionError::NotFound {
                    name: "gone".parse().unwrap(),
                }
                .into(),
                PublicErrorCode::ConnectionNotFound,
            ),
            (
                ConnectionError::Unavailable {
                    name: "down".parse().unwrap(),
                }
                .into(),
                PublicErrorCode::ConnectionUnavailable,
            ),
            (
                ConnectionError::Busy {
                    name: "busy".parse().unwrap(),
                }
                .into(),
                PublicErrorCode::ServerBusy,
            ),
            (
                AnalyzeError::Parse {
                    detail: "parser.internal".to_owned(),
                }
                .into(),
                PublicErrorCode::QueryParseError,
            ),
            (
                AnalyzeError::RecursionLimit.into(),
                PublicErrorCode::QueryParseError,
            ),
            (rejection.into(), PublicErrorCode::QueryRejected),
            (
                AuditError::Unavailable {
                    detail: "audit.internal".to_owned(),
                }
                .into(),
                PublicErrorCode::InternalError,
            ),
            (AuditError::Timeout.into(), PublicErrorCode::InternalError),
            (ExecuteError::Timeout.into(), PublicErrorCode::QueryTimeout),
            (
                ExecuteError::Cancelled.into(),
                PublicErrorCode::QueryCancelled,
            ),
            (
                ExecuteError::ResultTooLarge { limit: 4096 }.into(),
                PublicErrorCode::QueryResultTooLarge,
            ),
            (
                ExecuteError::Normalization(NormalizationError::NonFiniteFloat {
                    column: "amount".to_owned(),
                })
                .into(),
                PublicErrorCode::QueryNormalizationError,
            ),
            (
                ExecuteError::Database {
                    detail: "db.internal".to_owned(),
                }
                .into(),
                PublicErrorCode::QueryExecutionError,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.public_code(), expected, "{error}");
        }
    }

    #[test]
    fn every_explain_failure_maps_to_the_documented_public_code() {
        let rejection = testing::rejection_with_internal_detail();
        let cases: Vec<(ExplainServiceError, PublicErrorCode)> = vec![
            (
                ConnectionError::NotFound {
                    name: "gone".parse().unwrap(),
                }
                .into(),
                PublicErrorCode::ConnectionNotFound,
            ),
            (
                ConnectionError::Unavailable {
                    name: "down".parse().unwrap(),
                }
                .into(),
                PublicErrorCode::ConnectionUnavailable,
            ),
            (
                ConnectionError::Busy {
                    name: "busy".parse().unwrap(),
                }
                .into(),
                PublicErrorCode::ServerBusy,
            ),
            (
                AnalyzeError::Parse {
                    detail: "parser.internal".to_owned(),
                }
                .into(),
                PublicErrorCode::QueryParseError,
            ),
            (
                AnalyzeError::RecursionLimit.into(),
                PublicErrorCode::QueryParseError,
            ),
            (rejection.into(), PublicErrorCode::QueryRejected),
            (
                AuditError::Unavailable {
                    detail: "audit.internal".to_owned(),
                }
                .into(),
                PublicErrorCode::InternalError,
            ),
            (AuditError::Timeout.into(), PublicErrorCode::InternalError),
            (
                ExplainError::PrefixVerificationFailed.into(),
                PublicErrorCode::ExplainError,
            ),
            (
                ExplainError::MalformedPlan {
                    detail: "plan.internal".to_owned(),
                }
                .into(),
                PublicErrorCode::ExplainError,
            ),
            (
                ExplainError::PlanTooLarge { limit: 4096 }.into(),
                PublicErrorCode::ExplainError,
            ),
            (ExplainError::Timeout.into(), PublicErrorCode::QueryTimeout),
            (
                ExplainError::Cancelled.into(),
                PublicErrorCode::QueryCancelled,
            ),
            (
                ExplainError::Database {
                    detail: "db.internal".to_owned(),
                }
                .into(),
                PublicErrorCode::ExplainError,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.public_code(), expected, "{error}");
        }
    }

    #[test]
    fn every_schema_failure_maps_to_the_documented_public_code() {
        let rejection = testing::rejection_with_internal_detail();
        let cases: Vec<(SchemaServiceError, PublicErrorCode)> = vec![
            (
                ConnectionError::NotFound {
                    name: "gone".parse().unwrap(),
                }
                .into(),
                PublicErrorCode::ConnectionNotFound,
            ),
            (
                ConnectionError::Unavailable {
                    name: "down".parse().unwrap(),
                }
                .into(),
                PublicErrorCode::ConnectionUnavailable,
            ),
            (
                ConnectionError::Busy {
                    name: "busy".parse().unwrap(),
                }
                .into(),
                PublicErrorCode::ServerBusy,
            ),
            (
                SchemaError::Rejected(rejection).into(),
                PublicErrorCode::QueryRejected,
            ),
            (SchemaError::Timeout.into(), PublicErrorCode::QueryTimeout),
            (
                SchemaError::Cancelled.into(),
                PublicErrorCode::QueryCancelled,
            ),
            (
                SchemaError::Database {
                    detail: "db.internal".to_owned(),
                }
                .into(),
                PublicErrorCode::SchemaLookupError,
            ),
            (
                SchemaServiceError::SearchUnsupported,
                PublicErrorCode::SchemaLookupError,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.public_code(), expected, "{error}");
        }
    }

    #[test]
    fn every_internal_detail_is_sanitized_by_its_local_display() {
        let rejection = testing::rejection_with_internal_detail();
        assert!(
            rejection
                .reasons()
                .iter()
                .any(|reason| reason.internal_detail().is_some_and(|detail| {
                    detail.contains("staging-db") && detail.contains("production-db")
                }))
        );
        let normalization = NormalizationError::NonFiniteFloat {
            column: "safe_column".to_owned(),
        };
        let normalization_display = normalization.to_string();
        let rendered_and_hidden = vec![
            (
                QueryServiceError::from(rejection.clone()).to_string(),
                "staging-db",
            ),
            (
                ExplainServiceError::from(rejection.clone()).to_string(),
                "staging-db",
            ),
            (
                SchemaServiceError::from(SchemaError::Rejected(rejection)).to_string(),
                "staging-db",
            ),
            (
                QueryServiceError::from(AuditError::Unavailable {
                    detail: "audit.internal".to_owned(),
                })
                .to_string(),
                "audit.internal",
            ),
            (
                ExplainServiceError::from(AuditError::Unavailable {
                    detail: "audit.internal".to_owned(),
                })
                .to_string(),
                "audit.internal",
            ),
            (
                QueryServiceError::from(AnalyzeError::Parse {
                    detail: "parser.internal".to_owned(),
                })
                .to_string(),
                "parser.internal",
            ),
            (
                ExplainServiceError::from(AnalyzeError::Parse {
                    detail: "parser.internal".to_owned(),
                })
                .to_string(),
                "parser.internal",
            ),
            (
                QueryServiceError::from(ExecuteError::Database {
                    detail: "execute.internal".to_owned(),
                })
                .to_string(),
                "execute.internal",
            ),
            (
                ExplainServiceError::from(ExplainError::MalformedPlan {
                    detail: "plan.internal".to_owned(),
                })
                .to_string(),
                "plan.internal",
            ),
            (
                ExplainServiceError::from(ExplainError::Database {
                    detail: "explain-db.internal".to_owned(),
                })
                .to_string(),
                "explain-db.internal",
            ),
            (
                SchemaServiceError::from(SchemaError::Database {
                    detail: "schema-db.internal".to_owned(),
                })
                .to_string(),
                "schema-db.internal",
            ),
        ];
        for (rendered, hidden) in rendered_and_hidden {
            assert!(!rendered.contains(hidden), "{rendered}");
        }

        let error = QueryServiceError::from(ExecuteError::Normalization(normalization));
        assert_eq!(error.to_string(), normalization_display);
    }
}
