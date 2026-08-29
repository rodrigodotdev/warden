//! Plans one authorized statement without running it.
//!
//! ```text
//! verify the prefixed string           before anything reaches the server
//!     ↓ agent_pool + START TRANSACTION READ ONLY
//!     ↓ SELECT CONNECTION_ID()          so a cancellation has somewhere to go
//!     ↓ EXPLAIN FORMAT=JSON <sql>       parameters bound, one row, one column
//!     ↓ parse and bound the document    QueryPlan::validate is the authority
//!     ↓ ROLLBACK                        a read-only transaction has nothing to commit
//! ```
//!
//! Planning is real server work — PostgreSQL's planner constant-folds `IMMUTABLE`
//! functions and MySQL's optimizer searches join orders — so this path takes the
//! same `QueryPermit`, the same deadline and the same cancellation token the
//! executor takes, and shares `agent_pool` with it (`docs/mcp.md` section 3.1;
//! ADR-0025, ADR-0032).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use sqlx::mysql::MySqlDatabaseError;
use sqlx::{AssertSqlSafe, Row as _};
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;
use warden_core::dialect::Dialect;
use warden_core::explain::{PlanSummary, QueryPlan};
use warden_policy::AuthorizedQuery;
use warden_ports::error::ExplainError;
use warden_ports::{BoxFuture, Explainer, QueryPermit};

use crate::bind;
use crate::connection::MySqlConnectionPools;
use crate::plan::VerifiedExplain;

/// The statement that opens the planning transaction.
///
/// The same Warden-written literal `execute.rs` uses, and the same honest scope:
/// MySQL's read-only transaction is not what keeps a write out of `explain` — the
/// policy engine authorizes only `SELECT` roots (ADR-0020). It is ADR-0024's second
/// barrier, kept here so the plan path has no weaker session than the query path.
const READ_ONLY_TRANSACTION: &str = "START TRANSACTION READ ONLY";

/// `ER_QUERY_TIMEOUT`: `MAX_EXECUTION_TIME` aborted the statement.
const ER_QUERY_TIMEOUT: u16 = 3024;
/// `ER_QUERY_INTERRUPTED`: a `KILL QUERY` reached the statement.
const ER_QUERY_INTERRUPTED: u16 = 1317;

/// How long the cancellation statement gets, on its own budget.
///
/// A fresh budget rather than the request's deadline, which has usually passed by
/// the time this runs; reusing it would make every timeout skip its own kill.
const KILL_TIMEOUT: Duration = Duration::from_secs(2);

/// How long the transaction's own `ROLLBACK` gets once an outcome exists.
const ROLLBACK_TIMEOUT: Duration = Duration::from_secs(2);

/// Plans authorized statements on one MySQL connection's `agent_pool`.
#[derive(Debug)]
pub struct MySqlExplainer {
    pools: Arc<MySqlConnectionPools>,
}

impl MySqlExplainer {
    /// Builds an explainer over one connection's pools.
    #[must_use]
    pub fn new(pools: Arc<MySqlConnectionPools>) -> Self {
        Self { pools }
    }
}

impl Explainer for MySqlExplainer {
    /// The permit is named `_permit` because this adapter reads nothing from it.
    /// Its whole job is to exist: the borrow lives for `'a`, so a caller cannot drop
    /// its concurrency slot while planning runs, and a call site that never acquired
    /// one does not compile (ADR-0032).
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

impl MySqlExplainer {
    /// One call, from the verification to the rollback.
    async fn run(
        &self,
        query: &AuthorizedQuery,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<QueryPlan, ExplainError> {
        // Before the pool, before the transaction, before anything is spent: a
        // string that does not verify never becomes a connection's problem.
        let verified = VerifiedExplain::build(query.sql())?;

        let mut transaction = guarded(
            deadline,
            cancel,
            self.pools.agent().begin_with(READ_ONLY_TRANSACTION),
        )
        .await?;

        // One extra round trip, for the reason `execute.rs` accepts the same one: a
        // cancellation cannot ask a busy connection for its own id
        // (`docs/operations.md` section 5.4). Whether `MAX_EXECUTION_TIME` bounds
        // planning at all is unverified, so this is the half of ADR-0024 that is
        // known to work here.
        let connection_id: u64 = guarded(
            deadline,
            cancel,
            sqlx::query_scalar("SELECT CONNECTION_ID()").fetch_one(&mut *transaction),
        )
        .await?;

        let outcome = collect(&mut transaction, &verified, query, deadline, cancel).await;

        match outcome {
            Ok(plan) => {
                // Rollback, not commit: a read-only transaction has nothing to
                // commit. Its own outcome is discarded rather than propagated, on
                // its own short budget, for the same reason `execute.rs` discards
                // it on its own success path — a slow `ROLLBACK` must not replace a
                // valid plan with a timeout. Awaiting it here is safe precisely
                // because `outcome` is `Ok`: the statement already finished, so
                // there is nothing still running on the connection for `ROLLBACK`
                // to wait behind.
                let rollback_deadline = Instant::now() + ROLLBACK_TIMEOUT;
                let _rollback_outcome = bounded(rollback_deadline, transaction.rollback()).await;
                Ok(plan)
            }
            Err(error) => {
                // A timeout or a cancellation leaves the server still planning a
                // statement nobody is waiting for, so the kill is unconditional on
                // every failure here, not only `Timeout`/`Cancelled`. Best effort:
                // its own failure is never reported in place of `error`, which is
                // the failure the agent actually needs.
                self.kill(connection_id).await;
                // Dropping queues a ROLLBACK without awaiting it, exactly as
                // `execute.rs`'s own error path does and for the same reason:
                // awaiting one on a connection whose statement may still be
                // running would hang, holding the caller's `QueryPermit` for up to
                // `KILL_TIMEOUT` plus `ROLLBACK_TIMEOUT` behind a plan nobody is
                // waiting for. `test_before_acquire` — sqlx's own default, which
                // `pool.rs` never overrides — discards anything unusable before
                // the pool hands it out again. The kill above runs first so the
                // connection cannot return to the pool, and its id be reused,
                // before `KILL QUERY` lands.
                drop(transaction);
                Err(error)
            }
        }
    }

    /// Asks the server to stop planning on `connection_id`.
    ///
    /// On `control_pool`, because the agent connection is busy. The interpolation is
    /// the exemption `docs/operations.md` section 6.3 already grants `execute.rs`
    /// and for the identical reason: a bound `KILL QUERY ?` does not kill anything
    /// on MySQL, and `connection_id`'s `u64` type makes the formatted value always
    /// `[0-9]+`, so there is no injection surface by construction.
    /// `tests/adapter_rules.rs` pins this file to exactly this one interpolation.
    async fn kill(&self, connection_id: u64) {
        let deadline = Instant::now() + KILL_TIMEOUT;
        let statement = sqlx::query(AssertSqlSafe(format!("KILL QUERY {connection_id}")))
            .execute(self.pools.control());
        let _outcome = timeout_at(deadline, statement).await;
    }
}

/// Reads the single plan document and bounds it before it becomes a response.
///
/// `fetch_one` rather than `.fetch`: `EXPLAIN FORMAT=JSON` answers with exactly one
/// row of one column, so `docs/operations.md` section 6.6's streaming discipline —
/// which exists for an unbounded agent result set — does not apply.
/// `tests/adapter_rules.rs` pins that this file calls neither `fetch_all` nor
/// `.fetch`, so the exemption cannot widen into an unbounded read.
async fn collect(
    transaction: &mut sqlx::Transaction<'static, sqlx::MySql>,
    verified: &VerifiedExplain,
    query: &AuthorizedQuery,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<QueryPlan, ExplainError> {
    let row = guarded(
        deadline,
        cancel,
        bind::statement(verified.as_str(), query.parameters()).fetch_one(&mut **transaction),
    )
    .await?;

    // MySQL 8.4 returns the document in a `VARCHAR` column, so it arrives as text.
    // serde_json's `arbitrary_precision` keeps every digit the planner wrote
    // (`docs/data-model.md` section 8.3).
    let text: String = row.try_get(0).map_err(|error| explain_error(&error))?;
    let document: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| ExplainError::MalformedPlan {
            detail: error.to_string(),
        })?;

    let plan = QueryPlan {
        dialect: Dialect::MySql,
        // Deliberately empty. MySQL states estimates per table and per join step and
        // nothing for the statement as a whole, so naming one of them would be
        // Warden stating a number the server never stated
        // (`docs/architecture.md` section 11; `docs/open-questions.md` item 20).
        // The complete document is returned below either way.
        summary: PlanSummary::default(),
        plan: document,
    };
    plan.validate()?;
    Ok(plan)
}

/// Awaits a driver future under both the deadline and the cancellation token.
async fn guarded<T>(
    deadline: Instant,
    cancel: &CancellationToken,
    future: impl Future<Output = Result<T, sqlx::Error>>,
) -> Result<T, ExplainError> {
    tokio::select! {
        // Deterministic ordering: a cancelled request must not depend on which
        // arm the scheduler happened to poll first.
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

/// Collapses a `timeout_at` result into the port's error type.
fn finish<T>(
    result: Result<Result<T, sqlx::Error>, tokio::time::error::Elapsed>,
) -> Result<T, ExplainError> {
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(explain_error(&error)),
        Err(_elapsed) => Err(ExplainError::Timeout),
    }
}

/// Classifies a driver failure by MySQL's own error number (ADR-0033).
///
/// The message never reaches `Display`; it stays in `detail` for the deliberate
/// diagnostic path, exactly as `execute.rs` does.
fn explain_error(error: &sqlx::Error) -> ExplainError {
    if let Some(database) = error.as_database_error()
        && let Some(mysql) = database.try_downcast_ref::<MySqlDatabaseError>()
    {
        match mysql.number() {
            ER_QUERY_TIMEOUT => return ExplainError::Timeout,
            ER_QUERY_INTERRUPTED => return ExplainError::Cancelled,
            _ => {}
        }
    }
    ExplainError::Database {
        detail: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;

    use warden_ports::Explainer;

    use super::MySqlExplainer;
    use crate::connection::MySqlConnectionPools;

    #[test]
    fn the_explainer_is_send_sync_and_coerces_to_its_port() {
        fn assert_send_sync<T: Send + Sync>() {}
        fn as_explainer(explainer: Arc<MySqlExplainer>) -> Arc<dyn Explainer> {
            explainer
        }

        assert_send_sync::<MySqlExplainer>();
        let _ = as_explainer as fn(Arc<MySqlExplainer>) -> Arc<dyn Explainer>;
    }

    #[tokio::test]
    async fn an_explainer_builds_over_a_connection_without_touching_it() {
        // `lazy_for_tests` opens no socket, so a fresh pool's own connection count
        // is zero before anything runs on it. That count is the observable witness
        // for "without touching it": if `MySqlExplainer::new` acquired or opened a
        // connection merely to construct itself, this would no longer be zero.
        let pools = Arc::new(MySqlConnectionPools::lazy_for_tests());
        assert_eq!(pools.agent().size(), 0);

        let _explainer = MySqlExplainer::new(Arc::clone(&pools));

        assert_eq!(pools.agent().size(), 0);
    }
}
