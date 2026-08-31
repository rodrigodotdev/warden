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
    use warden_ports::{AnalyzeError, AuditError, ConnectionError, ExecuteError};

    use super::*;

    #[test]
    fn every_query_failure_maps_to_the_documented_public_code() {
        let cases: Vec<(QueryServiceError, PublicErrorCode)> = vec![
            (
                ConnectionError::NotFound {
                    name: "gone".parse().unwrap(),
                }
                .into(),
                PublicErrorCode::ConnectionNotFound,
            ),
            (
                ConnectionError::Busy {
                    name: "busy".parse().unwrap(),
                }
                .into(),
                PublicErrorCode::ServerBusy,
            ),
            (
                AnalyzeError::RecursionLimit.into(),
                PublicErrorCode::QueryParseError,
            ),
            (AuditError::Timeout.into(), PublicErrorCode::InternalError),
            (ExecuteError::Timeout.into(), PublicErrorCode::QueryTimeout),
        ];
        for (error, expected) in cases {
            assert_eq!(error.public_code(), expected, "{error}");
        }
    }

    #[test]
    fn a_failure_never_prints_a_detail_field() {
        let error = QueryServiceError::from(ExecuteError::Database {
            detail: "connection to db.internal as warden failed".to_owned(),
        });
        assert!(!error.to_string().contains("db.internal"), "{error}");
    }
}
