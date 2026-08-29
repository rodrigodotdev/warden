//! Every failure a port can return, and the public code each one becomes.
//!
//! One module rather than one file per port, deliberately. `docs/security.md`
//! section 10 fixes a closed set of codes an agent may observe, and the only way to
//! review "no internal failure reaches the model unsanitized" is to read the whole
//! map at once. `tests/port_rules.rs` checks the same map mechanically.
//!
//! # Two rules every error here follows
//!
//! * **`Display` never prints a `detail` field.** A driver or parser message can
//!   contain a hostname, a database user, a database name, or a fragment of the
//!   statement, and `tracing::warn!(%error)` would then write it into the operator
//!   log that SPEC section 6, invariants 21 and 22 keep clean. The detail stays
//!   reachable through the field for a deliberate diagnostic path, exactly as
//!   `warden_policy::DenyReason::internal_detail` does.
//! * **Only a failure a model can observe implements [`PublicError`].** Startup
//!   failures are operator-facing and never cross the MCP boundary, so they carry no
//!   public code — the same distinction `warden_core::error` draws for
//!   configuration errors.

use warden_core::connection::ConnectionName;
use warden_core::error::{PublicError, PublicErrorCode};
use warden_core::explain::PlanError;
use warden_core::result::{NormalizationError, ResultBuildError};
use warden_policy::{DenyCode, DenyReason, PolicyRejection};

/// Why analysis produced no evidence at all.
///
/// Deliberately short. An analyzer that *understood* a statement and distrusted it
/// does not fail here: it reports evidence — an `Unknown` statement kind, a risk
/// flag, an unclassified function — and `warden-policy` denies it with a code an
/// auditor can read (ADR-0011). Only a statement that yielded nothing to evaluate
/// belongs in this enum.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnalyzeError {
    /// The dialect parser rejected the statement.
    #[error("the statement could not be parsed")]
    Parse {
        /// The parser's own message, for a deliberate diagnostic path only.
        ///
        /// `sqlparser` quotes the offending token, so this can contain a fragment of
        /// the statement. `Display` never prints it and [`AnalyzeError::deny_reason`]
        /// never copies it into an audit record.
        detail: String,
    },
    /// The parser hit its recursion limit before it finished.
    ///
    /// `sqlparser`'s default `recursive-protection` feature turns a deeply nested
    /// statement into this instead of a stack overflow
    /// (`docs/operations.md` section 2.4).
    #[error("the statement is nested too deeply to analyze")]
    RecursionLimit,
}

impl AnalyzeError {
    /// The denial this failure records in the audit attempt.
    ///
    /// SPEC section 6, invariant 24 requires an audit record for every attempt,
    /// including one that never reached policy. The mapping lives here rather than in
    /// the service because `DenyCode::ParserRecursionLimit` has no other possible
    /// producer: a failed analysis leaves no evidence for a policy to evaluate.
    ///
    /// The reason carries no detail. `internal_detail` would be the parser's message,
    /// and that message can quote the statement, which `docs/security.md` section
    /// 11.3 keeps out of audit records by default.
    #[must_use]
    pub fn deny_reason(&self) -> DenyReason {
        match self {
            Self::Parse { .. } => DenyReason::new(DenyCode::UnknownConstruct),
            Self::RecursionLimit => DenyReason::new(DenyCode::ParserRecursionLimit),
        }
    }
}

impl PublicError for AnalyzeError {
    fn public_code(&self) -> PublicErrorCode {
        match self {
            Self::Parse { .. } | Self::RecursionLimit => PublicErrorCode::QueryParseError,
        }
    }
}

/// Why an authorized statement did not produce a result.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecuteError {
    /// The query exceeded its deadline.
    ///
    /// The server timeout is set shorter than the client one, so the ordinary path
    /// reaches this through a clean server error with an intact connection returned
    /// to the pool (`docs/operations.md` section 5.3).
    #[error("the query exceeded its deadline")]
    Timeout,
    /// The query was cancelled through its `CancellationToken`.
    #[error("the query was cancelled")]
    Cancelled,
    /// The normalized result reached its byte budget.
    #[error("the result exceeded its byte budget")]
    ResultTooLarge {
        /// The configured budget in bytes.
        limit: usize,
    },
    /// A value could not be normalized safely.
    ///
    /// Transparent because `NormalizationError` is already model-safe: it carries a
    /// column name and a database type name and nothing else
    /// (`docs/data-model.md` section 8.1).
    #[error(transparent)]
    Normalization(#[from] NormalizationError),
    /// The database rejected or failed the statement.
    #[error("the database rejected or failed the statement")]
    Database {
        /// The driver's own message, for a deliberate diagnostic path only.
        ///
        /// A `sqlx` error can name the host, the user, the database, and the SQL, so
        /// `Display` never prints it (`docs/security.md` section 10).
        detail: String,
    },
}

impl PublicError for ExecuteError {
    fn public_code(&self) -> PublicErrorCode {
        match self {
            Self::Timeout => PublicErrorCode::QueryTimeout,
            Self::Cancelled => PublicErrorCode::QueryCancelled,
            Self::ResultTooLarge { .. } => PublicErrorCode::QueryResultTooLarge,
            Self::Normalization(error) => error.public_code(),
            Self::Database { .. } => PublicErrorCode::QueryExecutionError,
        }
    }
}

/// A row the core refused becomes the execution failure the model sees.
///
/// Both size variants collapse into one public code: `docs/security.md` section 10
/// has a single `query_result_too_large`, and telling the agent which of the two
/// budgets it hit would be a distinction it cannot act on differently.
impl From<ResultBuildError> for ExecuteError {
    fn from(error: ResultBuildError) -> Self {
        match error {
            ResultBuildError::Normalization(source) => Self::Normalization(source),
            ResultBuildError::ValueTooLarge { limit, .. }
            | ResultBuildError::ResultTooLarge { limit, .. } => Self::ResultTooLarge { limit },
        }
    }
}

/// Why schema metadata could not be returned.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SchemaError {
    /// The object rules denied the requested object.
    ///
    /// Object policy applies at the source, so a table an agent may not query is
    /// also a table it may not describe (`docs/security.md` section 5.2).
    #[error(transparent)]
    Rejected(#[from] PolicyRejection),
    /// The lookup exceeded its deadline.
    #[error("the schema lookup exceeded its deadline")]
    Timeout,
    /// The lookup was cancelled through its `CancellationToken`.
    #[error("the schema lookup was cancelled")]
    Cancelled,
    /// The catalog query failed.
    #[error("schema metadata could not be read")]
    Database {
        /// The driver's own message, for a deliberate diagnostic path only.
        detail: String,
    },
}

impl PublicError for SchemaError {
    fn public_code(&self) -> PublicErrorCode {
        match self {
            Self::Rejected(rejection) => rejection.public_code(),
            Self::Timeout => PublicErrorCode::QueryTimeout,
            Self::Cancelled => PublicErrorCode::QueryCancelled,
            Self::Database { .. } => PublicErrorCode::SchemaLookupError,
        }
    }
}

/// Why a plan could not be produced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExplainError {
    /// The prefixed string did not reparse to an `EXPLAIN` of the analyzed statement.
    ///
    /// `explain` is the one place where the string sent to the database differs from
    /// the analyzed one, so the adapter reparses the result and compares
    /// (`docs/mcp.md` section 3.2). This is that comparison failing, and it is a
    /// denial, never a warning.
    #[error("the explained statement did not match the analyzed statement")]
    PrefixVerificationFailed,
    /// The engine's plan document could not be understood.
    #[error("the plan could not be interpreted")]
    MalformedPlan {
        /// What the adapter could not interpret, for a deliberate diagnostic path.
        detail: String,
    },
    /// The engine's plan document is larger than one response may carry.
    ///
    /// Refused rather than truncated (`docs/data-model.md` section 10): a shortened
    /// plan document is not a smaller plan.
    #[error("the plan exceeded its byte budget")]
    PlanTooLarge {
        /// The configured budget in bytes.
        limit: usize,
    },
    /// Planning exceeded its deadline.
    #[error("planning exceeded its deadline")]
    Timeout,
    /// Planning was cancelled through its `CancellationToken`.
    #[error("planning was cancelled")]
    Cancelled,
    /// The database refused to plan the statement.
    #[error("a plan could not be produced")]
    Database {
        /// The driver's own message, for a deliberate diagnostic path only.
        detail: String,
    },
}

impl PublicError for ExplainError {
    fn public_code(&self) -> PublicErrorCode {
        match self {
            Self::PrefixVerificationFailed
            | Self::MalformedPlan { .. }
            | Self::PlanTooLarge { .. }
            | Self::Database { .. } => PublicErrorCode::ExplainError,
            Self::Timeout => PublicErrorCode::QueryTimeout,
            Self::Cancelled => PublicErrorCode::QueryCancelled,
        }
    }
}

/// A plan the core refused becomes the explain failure the model sees.
///
/// `actual` is dropped deliberately. `docs/security.md` section 10 gives the agent a
/// fixed `explain_error`, and the exact size of a document it never received is a
/// fact about the data rather than something it can act on — the same reason
/// `ExecuteError::ResultTooLarge` keeps only the budget.
impl From<PlanError> for ExplainError {
    fn from(error: PlanError) -> Self {
        match error {
            PlanError::TooLarge { limit, .. } => Self::PlanTooLarge { limit },
        }
    }
}

/// Why an audit record could not be written.
///
/// The consequence depends on the phase, not on the variant: a failed attempt denies
/// the query and a failed outcome raises an alarm (ADR-0022). The service enforces
/// that in Milestone 11; this type only says that the write did not happen.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditError {
    /// The sink could not accept the record.
    #[error("the audit sink is unavailable")]
    Unavailable {
        /// The sink's own message, for a deliberate diagnostic path only.
        detail: String,
    },
    /// The sink did not answer within the caller's bound.
    #[error("the audit sink did not respond in time")]
    Timeout,
}

impl PublicError for AuditError {
    fn public_code(&self) -> PublicErrorCode {
        match self {
            Self::Unavailable { .. } | Self::Timeout => PublicErrorCode::InternalError,
        }
    }
}

/// Why a connection could not serve a request.
///
/// These messages name the connection, and that is intentional: a connection name is
/// already public metadata that `list_connections` returns
/// (`docs/mcp.md` section 2). The agent still receives only the fixed text of the
/// public code, never this string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectionError {
    /// No connection with this name is configured.
    #[error("connection {name} is not configured")]
    NotFound {
        /// The requested name.
        name: ConnectionName,
    },
    /// The connection exists but cannot currently serve requests.
    #[error("connection {name} cannot currently serve requests")]
    Unavailable {
        /// The affected connection.
        name: ConnectionName,
    },
    /// The concurrency queue was still full when `max_queue_wait` elapsed.
    ///
    /// Produced only by permit acquisition. Bounding the wait is what keeps a burst
    /// of callers from turning into unbounded client-perceived latency
    /// (SPEC section 6, invariant 16).
    #[error("connection {name} is at its concurrency limit")]
    Busy {
        /// The affected connection.
        name: ConnectionName,
    },
}

impl PublicError for ConnectionError {
    fn public_code(&self) -> PublicErrorCode {
        match self {
            Self::NotFound { .. } => PublicErrorCode::ConnectionNotFound,
            Self::Unavailable { .. } => PublicErrorCode::ConnectionUnavailable,
            Self::Busy { .. } => PublicErrorCode::ServerBusy,
        }
    }
}

/// Why a connection could not be assembled at startup.
///
/// Deliberately **not** a [`PublicError`]. This is an operator-facing failure raised
/// by the composition root before any transport is serving, so it never crosses the
/// MCP boundary and has no code an agent could observe — the same distinction
/// `warden_core::error` draws for configuration errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeError {
    /// The connection's execution limits are not usable.
    #[error("connection {name} has invalid execution limits: {source}")]
    Limits {
        /// The affected connection.
        name: ConnectionName,
        /// Which bound was rejected.
        source: warden_core::limits::LimitsError,
    },
    /// The analyzer parses a different dialect than the connection speaks.
    ///
    /// A composition-root bug that would otherwise stay invisible until an agent
    /// asked a question and got PostgreSQL syntax parsed by the MySQL grammar.
    #[error("connection {name} is {expected} but its analyzer parses {actual}")]
    DialectMismatch {
        /// The affected connection.
        name: ConnectionName,
        /// The dialect the connection declares.
        expected: warden_core::dialect::Dialect,
        /// The dialect the analyzer reports.
        actual: warden_core::dialect::Dialect,
    },
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::testing;

    /// Stands in for everything a driver or parser message can carry.
    const LEAKY: &str = "near 'alice@example.com' on host db-01.internal";

    fn name() -> ConnectionName {
        "production-db".parse().unwrap()
    }

    #[test]
    fn every_variant_maps_to_a_documented_public_code() {
        let mapped = [
            AnalyzeError::Parse {
                detail: LEAKY.to_owned(),
            }
            .public_code(),
            AnalyzeError::RecursionLimit.public_code(),
            ExecuteError::Timeout.public_code(),
            ExecuteError::Cancelled.public_code(),
            ExecuteError::ResultTooLarge { limit: 1 }.public_code(),
            ExecuteError::Normalization(NormalizationError::ArrayTooDeep { max: 8 }).public_code(),
            ExecuteError::Database {
                detail: LEAKY.to_owned(),
            }
            .public_code(),
            SchemaError::Rejected(testing::rejection()).public_code(),
            SchemaError::Timeout.public_code(),
            SchemaError::Cancelled.public_code(),
            SchemaError::Database {
                detail: LEAKY.to_owned(),
            }
            .public_code(),
            ExplainError::PrefixVerificationFailed.public_code(),
            ExplainError::MalformedPlan {
                detail: LEAKY.to_owned(),
            }
            .public_code(),
            ExplainError::PlanTooLarge { limit: 1 }.public_code(),
            ExplainError::Timeout.public_code(),
            ExplainError::Cancelled.public_code(),
            ExplainError::Database {
                detail: LEAKY.to_owned(),
            }
            .public_code(),
            AuditError::Unavailable {
                detail: LEAKY.to_owned(),
            }
            .public_code(),
            AuditError::Timeout.public_code(),
            ConnectionError::NotFound { name: name() }.public_code(),
            ConnectionError::Unavailable { name: name() }.public_code(),
            ConnectionError::Busy { name: name() }.public_code(),
        ];

        assert_eq!(
            mapped,
            [
                PublicErrorCode::QueryParseError,
                PublicErrorCode::QueryParseError,
                PublicErrorCode::QueryTimeout,
                PublicErrorCode::QueryCancelled,
                PublicErrorCode::QueryResultTooLarge,
                PublicErrorCode::QueryNormalizationError,
                PublicErrorCode::QueryExecutionError,
                PublicErrorCode::QueryRejected,
                PublicErrorCode::QueryTimeout,
                PublicErrorCode::QueryCancelled,
                PublicErrorCode::SchemaLookupError,
                PublicErrorCode::ExplainError,
                PublicErrorCode::ExplainError,
                PublicErrorCode::ExplainError,
                PublicErrorCode::QueryTimeout,
                PublicErrorCode::QueryCancelled,
                PublicErrorCode::ExplainError,
                PublicErrorCode::InternalError,
                PublicErrorCode::InternalError,
                PublicErrorCode::ConnectionNotFound,
                PublicErrorCode::ConnectionUnavailable,
                PublicErrorCode::ServerBusy,
            ]
        );
        // Every code above must be one the security document already lists; a new
        // code has to be added to `warden-core` and to `docs/security.md` first.
        for code in mapped {
            assert!(
                PublicErrorCode::ALL.contains(&code),
                "{code} is undocumented"
            );
        }
    }

    #[test]
    fn display_never_repeats_an_internal_detail() {
        for rendered in [
            AnalyzeError::Parse {
                detail: LEAKY.to_owned(),
            }
            .to_string(),
            ExecuteError::Database {
                detail: LEAKY.to_owned(),
            }
            .to_string(),
            SchemaError::Database {
                detail: LEAKY.to_owned(),
            }
            .to_string(),
            ExplainError::Database {
                detail: LEAKY.to_owned(),
            }
            .to_string(),
            ExplainError::MalformedPlan {
                detail: LEAKY.to_owned(),
            }
            .to_string(),
            AuditError::Unavailable {
                detail: LEAKY.to_owned(),
            }
            .to_string(),
            // Both `#[error(transparent)]` variants delegate `Display` to another
            // crate's type. They are safe today because `PolicyRejection` prints only
            // its fixed-table `DenyCode` and `NormalizationError` prints only a
            // column and type name, but neither fact is checked here without an
            // entry in this loop — a future `warden-policy` or `warden-core` change
            // would otherwise leak past this guard unnoticed.
            SchemaError::Rejected(testing::rejection()).to_string(),
            ExecuteError::Normalization(NormalizationError::ArrayTooDeep { max: 8 }).to_string(),
        ] {
            assert!(!rendered.contains("alice@example.com"), "{rendered}");
            assert!(!rendered.contains("db-01.internal"), "{rendered}");
        }
    }

    #[test]
    fn a_connection_failure_names_the_connection_it_is_about() {
        assert_eq!(
            ConnectionError::Busy { name: name() }.to_string(),
            "connection production-db is at its concurrency limit"
        );
    }

    #[test]
    fn an_analysis_failure_is_auditable_as_a_denial() {
        assert_eq!(
            AnalyzeError::RecursionLimit.deny_reason().code(),
            DenyCode::ParserRecursionLimit
        );
        let reason = AnalyzeError::Parse {
            detail: LEAKY.to_owned(),
        }
        .deny_reason();
        assert_eq!(reason.code(), DenyCode::UnknownConstruct);
        // The parser's message quotes the statement, so it must not become audit
        // detail (`docs/security.md` section 11.3).
        assert_eq!(reason.internal_detail(), None);
    }

    #[test]
    fn a_normalization_failure_keeps_its_own_public_code_and_text() {
        let error = ExecuteError::from(NormalizationError::UnsupportedType {
            column: "custom_state".to_owned(),
            dialect: warden_core::dialect::Dialect::PostgreSql,
            database_type: "order_state".to_owned(),
        });
        assert_eq!(
            error.public_code(),
            PublicErrorCode::QueryNormalizationError
        );
        assert!(error.to_string().contains("order_state"), "{error}");
    }

    #[test]
    fn a_result_build_failure_maps_by_kind_not_by_which_budget() {
        let too_large = ExecuteError::from(ResultBuildError::ValueTooLarge {
            column: "payload".to_owned(),
            actual: 100,
            limit: 64,
        });
        assert_eq!(
            too_large.public_code(),
            PublicErrorCode::QueryResultTooLarge
        );

        let result_too_large = ExecuteError::from(ResultBuildError::ResultTooLarge {
            actual: 1000,
            limit: 256,
        });
        assert_eq!(
            result_too_large.public_code(),
            PublicErrorCode::QueryResultTooLarge
        );

        let normalization = ExecuteError::from(ResultBuildError::Normalization(
            NormalizationError::ArrayTooDeep { max: 8 },
        ));
        assert_eq!(
            normalization.public_code(),
            PublicErrorCode::QueryNormalizationError
        );
    }

    #[test]
    fn a_startup_failure_has_no_public_code_to_leak() {
        // `RuntimeError` deliberately does not implement `PublicError`. This test
        // documents the intent; `tests/port_rules.rs` proves it mechanically.
        let error = RuntimeError::DialectMismatch {
            name: name(),
            expected: warden_core::dialect::Dialect::PostgreSql,
            actual: warden_core::dialect::Dialect::MySql,
        };
        assert_eq!(
            error.to_string(),
            "connection production-db is postgresql but its analyzer parses mysql"
        );
    }

    #[test]
    fn an_oversized_plan_maps_to_the_explain_code_without_naming_its_size() {
        let error = ExplainError::from(warden_core::explain::PlanError::TooLarge {
            actual: 900_000,
            limit: warden_core::explain::MAX_PLAN_BYTES,
        });
        assert_eq!(
            error,
            ExplainError::PlanTooLarge {
                limit: warden_core::explain::MAX_PLAN_BYTES
            }
        );
        assert_eq!(error.public_code(), PublicErrorCode::ExplainError);
        // `actual` is the engine's document size, which is a fact about the data the
        // agent asked for. The public text says only that a budget was exceeded, the
        // same distinction `ExecuteError::ResultTooLarge` draws.
        assert!(!error.to_string().contains("900000"), "{error}");
    }
}
