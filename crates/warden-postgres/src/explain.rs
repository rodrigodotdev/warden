//! Plans one authorized statement without running it.
//!
//! ```text
//! verify the prefixed string           before anything reaches the server
//!     ↓ agent_pool + BEGIN READ ONLY
//!     ↓ SET LOCAL statement_timeout     tightened to this request's own limits
//!     ↓ SELECT pg_backend_pid()         so a cancellation has somewhere to go
//!     ↓ EXPLAIN (FORMAT JSON) <sql>     parameters bound, one row, one json column
//!     ↓ read the summary and bound it   QueryPlan::validate is the authority
//!     ↓ ROLLBACK
//! ```
//!
//! Planning is real server work: PostgreSQL's planner constant-folds `IMMUTABLE`
//! functions, so a malicious immutable function runs here (`docs/mcp.md` section
//! 3.1). This path therefore takes the same permit, deadline and cancellation token
//! as the executor and shares `agent_pool` with it.
//!
//! **The read-only transaction is not what keeps a write out of `explain`.**
//! Measured against a PostgreSQL 17 container: `EXPLAIN (FORMAT JSON) INSERT ...`
//! succeeds inside `BEGIN READ ONLY`, because planning writes nothing. What refuses
//! a write here is `ReadOnlyRootStatementPolicy` authorizing only `SELECT` roots
//! (ADR-0020), and the transaction is ADR-0024's second barrier kept so the plan
//! path has no weaker session than the query path.
//!
//! Unlike [`crate::execute`], nothing here needs a named prepared statement: the one
//! output column is `json`, so no custom result metadata is resolved, and
//! `crate::bind::plan_statement` keeps `agent_query`'s non-persistent default. There
//! is no `DEALLOCATE ALL` and no connection to retire.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use sqlx::Row as _;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;
use warden_core::dialect::Dialect;
use warden_core::explain::{PlanSummary, QueryPlan};
use warden_policy::AuthorizedQuery;
use warden_ports::error::ExplainError;
use warden_ports::{BoxFuture, Explainer, QueryPermit};

use crate::connection::PostgreSqlConnectionPools;
use crate::plan::VerifiedExplain;
use crate::query::agent_query;
use crate::{bind, options};

/// The statement that opens the planning transaction.
const READ_ONLY_TRANSACTION: &str = "BEGIN READ ONLY";

/// `query_canceled`: a statement timeout or a cancel request (ADR-0034).
const SQLSTATE_QUERY_CANCELED: &str = "57014";

/// How long the cancellation statement gets, on its own budget.
const CANCEL_TIMEOUT: Duration = Duration::from_secs(2);

/// How long the transaction's own rollback gets once an outcome exists.
const ROLLBACK_TIMEOUT: Duration = Duration::from_secs(2);

/// Plans authorized statements on one PostgreSQL connection's `agent_pool`.
#[derive(Debug)]
pub struct PostgreSqlExplainer {
    pools: Arc<PostgreSqlConnectionPools>,
}

impl PostgreSqlExplainer {
    /// Builds an explainer over one connection's pools.
    #[must_use]
    pub fn new(pools: Arc<PostgreSqlConnectionPools>) -> Self {
        Self { pools }
    }
}

impl Explainer for PostgreSqlExplainer {
    /// The permit proves that the caller holds its concurrency slot for `'a`.
    fn explain<'a>(
        &'a self,
        query: &'a AuthorizedQuery,
        _permit: &'a QueryPermit,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<QueryPlan, ExplainError>> {
        Box::pin(async move { self.run(query, deadline, &cancel).await })
    }
}

impl PostgreSqlExplainer {
    /// One call, from the verification to the rollback.
    async fn run(
        &self,
        query: &AuthorizedQuery,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<QueryPlan, ExplainError> {
        // Before the pool, before the transaction: a string that does not verify
        // never becomes a connection's problem.
        let verified = VerifiedExplain::build(query.sql())?;

        let mut transaction = guarded(
            deadline,
            cancel,
            self.pools.agent().begin_with(READ_ONLY_TRANSACTION),
        )
        .await?;

        // `set_config(..., true)` is SET LOCAL in its parameterizable form, and it
        // can only tighten the per-connection server-side deadline. It applies to
        // planning as it applies to execution.
        let timeout = query
            .limits()
            .server_timeout()
            .min(self.pools.statement_timeout());
        guarded(
            deadline,
            cancel,
            agent_query("SELECT set_config('statement_timeout', $1, true)")
                .bind(options::millis(timeout))
                .execute(&mut *transaction),
        )
        .await?;

        // A busy backend cannot identify itself during cancellation, so capture its
        // id before planning begins.
        let row = guarded(
            deadline,
            cancel,
            agent_query("SELECT pg_backend_pid()").fetch_one(&mut *transaction),
        )
        .await?;
        let backend_pid: i32 = row.try_get(0).map_err(|error| explain_error(&error))?;

        let outcome = collect(&mut transaction, &verified, query, deadline, cancel).await;

        if outcome.is_err() {
            // A timeout or a cancellation leaves the server still planning for
            // nobody. Best effort: this call's own failure is never reported in
            // place of the failure the agent needs.
            self.cancel_backend(backend_pid).await;
        }

        // Rollback on its own short budget, its outcome discarded: a read-only
        // transaction has nothing to commit, and a slow rollback must not replace a
        // valid plan with a timeout.
        let rollback_deadline = Instant::now() + ROLLBACK_TIMEOUT;
        let _rollback_outcome = bounded(rollback_deadline, transaction.rollback()).await;
        outcome
    }

    /// Asks the control pool to stop the backend that is still planning.
    async fn cancel_backend(&self, backend_pid: i32) {
        let deadline = Instant::now() + CANCEL_TIMEOUT;
        let statement = sqlx::query("SELECT pg_cancel_backend($1)")
            .bind(backend_pid)
            .execute(self.pools.control());
        let _outcome = timeout_at(deadline, statement).await;
    }
}

/// Reads the single plan document and bounds it before it becomes a response.
///
/// `fetch_one` rather than `.fetch`: `EXPLAIN (FORMAT JSON)` answers with exactly one
/// row of one column, so `docs/operations.md` section 6.6's streaming discipline —
/// which exists for an unbounded agent result set — does not apply.
/// `tests/adapter_rules.rs` pins that this file calls neither `fetch_all` nor
/// `.fetch`, so the exemption cannot widen into an unbounded read.
async fn collect(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    verified: &VerifiedExplain,
    query: &AuthorizedQuery,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<QueryPlan, ExplainError> {
    let row = guarded(
        deadline,
        cancel,
        bind::plan_statement(verified.as_str(), query.parameters()).fetch_one(&mut **transaction),
    )
    .await?;

    // The column is `json`, so the driver decodes the document directly and
    // serde_json's `arbitrary_precision` keeps the planner's digits exact
    // (`docs/data-model.md` section 8.3).
    let document: serde_json::Value = row.try_get(0).map_err(|error| explain_error(&error))?;

    let plan = QueryPlan {
        dialect: Dialect::PostgreSql,
        summary: summary(&document),
        plan: document,
    };
    plan.validate()?;
    Ok(plan)
}

/// PostgreSQL's comparable summary.
///
/// `EXPLAIN (FORMAT JSON)` answers with a one-element array whose element carries the
/// root node under `Plan`, and that node's `Plan Rows` is the planner's estimate for
/// the statement as a whole. Any other shape — a missing key, a negative or
/// fractional number, a different container after a server upgrade — leaves the field
/// empty rather than guessing (`docs/architecture.md` section 11).
fn summary(document: &serde_json::Value) -> PlanSummary {
    PlanSummary {
        estimated_rows: document
            .get(0)
            .and_then(|root| root.get("Plan"))
            .and_then(|plan| plan.get("Plan Rows"))
            .and_then(serde_json::Value::as_u64),
    }
}

/// Awaits a driver future under both the deadline and the cancellation token.
async fn guarded<T>(
    deadline: Instant,
    cancel: &CancellationToken,
    future: impl Future<Output = Result<T, sqlx::Error>>,
) -> Result<T, ExplainError> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(ExplainError::Cancelled),
        result = timeout_at(deadline, future) => finish(result),
    }
}

/// Awaits a driver future under the deadline only.
async fn bounded<T>(
    deadline: Instant,
    future: impl Future<Output = Result<T, sqlx::Error>>,
) -> Result<T, ExplainError> {
    finish(timeout_at(deadline, future).await)
}

/// Collapses a timed driver operation into the port's error type.
fn finish<T>(
    result: Result<Result<T, sqlx::Error>, tokio::time::error::Elapsed>,
) -> Result<T, ExplainError> {
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(explain_error(&error)),
        Err(_elapsed) => Err(ExplainError::Timeout),
    }
}

/// Classifies a PostgreSQL failure by SQLSTATE (ADR-0034).
fn explain_error(error: &sqlx::Error) -> ExplainError {
    if let Some(database) = error.as_database_error()
        && database.code().as_deref() == Some(SQLSTATE_QUERY_CANCELED)
    {
        return ExplainError::Timeout;
    }
    ExplainError::Database {
        detail: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;

    use warden_core::explain::PlanSummary;
    use warden_ports::Explainer;

    use super::{PostgreSqlExplainer, summary};

    #[test]
    fn the_explainer_is_send_sync_and_coerces_to_its_port() {
        fn assert_send_sync<T: Send + Sync>() {}
        fn as_explainer(explainer: Arc<PostgreSqlExplainer>) -> Arc<dyn Explainer> {
            explainer
        }

        assert_send_sync::<PostgreSqlExplainer>();
        let _ = as_explainer as fn(Arc<PostgreSqlExplainer>) -> Arc<dyn Explainer>;
    }

    #[test]
    fn the_root_nodes_row_estimate_becomes_the_summary() {
        let document =
            serde_json::json!([{ "Plan": { "Node Type": "Seq Scan", "Plan Rows": 1200 } }]);
        assert_eq!(
            summary(&document),
            PlanSummary {
                estimated_rows: Some(1200)
            }
        );
    }

    #[test]
    fn an_unexpected_document_shape_leaves_the_summary_empty() {
        // A missing key, a different container, a negative or fractional estimate
        // after a server upgrade: each leaves the field empty rather than guessing
        // (`docs/architecture.md` section 11).
        for document in [
            serde_json::json!([]),
            serde_json::json!([{ "Plan": {} }]),
            serde_json::json!([{ "Plan": { "Plan Rows": -1 } }]),
            serde_json::json!([{ "Plan": { "Plan Rows": 1.5 } }]),
            serde_json::json!([{ "Plan": { "Plan Rows": "many" } }]),
            serde_json::json!({ "Plan": { "Plan Rows": 3 } }),
        ] {
            assert_eq!(summary(&document), PlanSummary::default(), "{document}");
        }
    }
}
