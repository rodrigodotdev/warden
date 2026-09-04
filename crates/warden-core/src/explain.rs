//! Non-executing query plans.

use crate::dialect::Dialect;
use crate::error::{PublicError, PublicErrorCode};
use crate::query::QueryRequest;

/// A request to plan a statement without running it.
///
/// It carries a full [`QueryRequest`] so an explained statement passes exactly the
/// same size validation, analysis, and policy evaluation as an executed one
/// (`docs/mcp.md` section 3.1): PostgreSQL's planner constant-folds `IMMUTABLE`
/// functions, so a malicious immutable function can run during planning.
#[derive(Debug, Clone, PartialEq)]
pub struct ExplainRequest {
    query: QueryRequest,
}

impl ExplainRequest {
    /// Wraps a validated query.
    #[must_use]
    pub fn new(query: QueryRequest) -> Self {
        Self { query }
    }

    /// The statement to plan.
    #[must_use]
    pub fn query(&self) -> &QueryRequest {
        &self.query
    }
}

/// The largest JSON length one plan document may carry into model context.
///
/// The same figure and the same reasoning as `ExecutionLimits::max_result_bytes`
/// (`docs/data-model.md` section 7): the consumer is an MCP client's context window.
/// A planner document is database-controlled text whose size follows the statement's
/// complexity, and PostgreSQL emits one JSON object per plan node, so a heavily
/// partitioned statement well inside the 64 KiB SQL cap can still plan into
/// megabytes.
///
/// Fixed rather than configurable: `explain` carries no `ExecutionLimits` field of
/// its own, and a bound that exists to satisfy SPEC section 6, invariant 15 does not
/// get a configuration key (ADR-0026).
pub const MAX_PLAN_BYTES: usize = 256 * 1024;

/// Why a plan could not be returned as the engine produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    /// The engine's document is larger than one response may carry.
    #[error("the plan is {actual} bytes, above the {limit}-byte budget")]
    TooLarge {
        /// The document's own JSON length.
        actual: usize,
        /// The budget it exceeded.
        limit: usize,
    },
}

impl PublicError for PlanError {
    fn public_code(&self) -> PublicErrorCode {
        match self {
            Self::TooLarge { .. } => PublicErrorCode::ExplainError,
        }
    }
}

/// The engine-independent part of a plan.
///
/// There is no cost field. MySQL and PostgreSQL cost units are not comparable, and
/// inventing a universal metric would be a fabricated number in a diagnostic tool
/// (`docs/mcp.md` section 2; `docs/architecture.md` section 11). Every field is
/// optional: when an engine does not report one, the summary omits it rather than
/// guessing.
///
/// **PostgreSQL fills `estimated_rows`; MySQL leaves it empty.** `EXPLAIN (FORMAT
/// JSON)` states one `Plan Rows` for the statement's root node, while `EXPLAIN
/// FORMAT=JSON` states estimates per table and per join step and nothing that
/// summarizes the statement. Choosing one of MySQL's per-step figures would be
/// Warden stating a number the server never stated
/// (`docs/open-questions.md` item 20). The complete document reaches the agent
/// either way, through [`QueryPlan::plan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub struct PlanSummary {
    /// The planner's row estimate, when it reports one.
    pub estimated_rows: Option<u64>,
}

/// A structured, non-executing plan.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct QueryPlan {
    /// The dialect that produced the plan.
    pub dialect: Dialect,
    /// The comparable summary.
    pub summary: PlanSummary,
    /// The engine's own plan document, passed through unchanged.
    ///
    /// Engine-specific detail belongs here rather than in `summary`, so adding a
    /// field for one engine never forces an invented value for the other.
    pub plan: serde_json::Value,
}

impl QueryPlan {
    /// The exact JSON length of the engine's own document.
    ///
    /// Computed without producing the text, by the same counter
    /// `ResultValue::json_bytes` uses, so the figure always matches what
    /// `serde_json::to_string` would write. The walk is iterative because a plan is
    /// database-controlled and a recursive one over a deep document is the stack
    /// overflow SPEC section 6, invariant 31 forbids.
    #[must_use]
    pub fn plan_bytes(&self) -> usize {
        crate::result::json_value_bytes(&self.plan)
    }

    /// Refuses a plan larger than [`MAX_PLAN_BYTES`].
    ///
    /// The adapter calls this before returning, exactly as `ResultSet::validate`
    /// guards a result set. There is no truncating variant: a partial plan document
    /// is not a smaller plan, it is a wrong one.
    ///
    /// # Errors
    ///
    /// [`PlanError::TooLarge`] if the serialized plan exceeds [`MAX_PLAN_BYTES`].
    pub fn validate(&self) -> Result<(), PlanError> {
        let actual = self.plan_bytes();
        if actual > MAX_PLAN_BYTES {
            return Err(PlanError::TooLarge {
                actual,
                limit: MAX_PLAN_BYTES,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::error::{PublicError, PublicErrorCode};
    use crate::query::InputLimits;

    #[test]
    fn a_request_carries_the_validated_query_unchanged() {
        let query = QueryRequest::new(
            "production-postgres".parse().unwrap(),
            "SELECT 1".to_owned(),
            Vec::new(),
            &InputLimits::default(),
        )
        .unwrap();
        let request = ExplainRequest::new(query);
        assert_eq!(request.query().sql(), "SELECT 1");
    }

    #[test]
    fn a_plan_serializes_with_an_omittable_summary() {
        let plan = QueryPlan {
            dialect: Dialect::PostgreSql,
            summary: PlanSummary {
                estimated_rows: Some(1200),
            },
            plan: serde_json::json!({ "Node Type": "Seq Scan" }),
        };
        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains(r#""dialect":"postgresql""#), "{json}");
        assert!(json.contains(r#""estimated_rows":1200"#), "{json}");

        // MySQL reports no row estimate in this shape; the field is null, never a
        // fabricated number.
        let bare = QueryPlan {
            dialect: Dialect::MySql,
            summary: PlanSummary::default(),
            plan: serde_json::json!({}),
        };
        assert!(
            serde_json::to_string(&bare)
                .unwrap()
                .contains(r#""estimated_rows":null"#)
        );
    }

    #[test]
    fn a_plan_within_the_budget_validates() {
        let plan = QueryPlan {
            dialect: Dialect::PostgreSql,
            summary: PlanSummary {
                estimated_rows: Some(6),
            },
            plan: serde_json::json!([{ "Plan": { "Node Type": "Seq Scan", "Plan Rows": 6 } }]),
        };
        assert_eq!(plan.validate(), Ok(()));
    }

    #[test]
    fn an_oversized_plan_is_refused_rather_than_truncated() {
        // Half a JSON document is not a plan, and a silently shortened one would be
        // read as a complete one, so the only safe answer is a refusal.
        let node = serde_json::json!({ "Node Type": "Seq Scan", "Relation Name": "orders" });
        let plan = QueryPlan {
            dialect: Dialect::PostgreSql,
            summary: PlanSummary::default(),
            plan: serde_json::Value::Array(vec![node; 8_000]),
        };
        let error = plan
            .validate()
            .expect_err("the document is far above the budget");
        let PlanError::TooLarge { actual, limit } = error;
        assert_eq!(limit, MAX_PLAN_BYTES);
        assert!(actual > MAX_PLAN_BYTES, "{actual}");
        assert_eq!(error.public_code(), PublicErrorCode::ExplainError);
    }

    #[test]
    fn the_measured_length_is_the_length_that_would_be_serialized() {
        let plan = QueryPlan {
            dialect: Dialect::MySql,
            summary: PlanSummary::default(),
            plan: serde_json::json!({ "query_block": { "select_id": 1, "cost_info": null } }),
        };
        let serialized = serde_json::to_string(&plan.plan).expect("a document serializes");
        assert_eq!(plan.plan_bytes(), serialized.len());
    }
}
