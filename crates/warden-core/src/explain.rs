//! Non-executing query plans.

use crate::dialect::Dialect;
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

/// The engine-independent part of a plan.
///
/// There is no cost field. MySQL and PostgreSQL cost units are not comparable, and
/// inventing a universal metric would be a fabricated number in a diagnostic tool
/// (`docs/mcp.md` section 2; `docs/architecture.md` section 11). Every field is
/// optional: when an engine does not report one, the summary omits it rather than
/// guessing.
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
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
}
