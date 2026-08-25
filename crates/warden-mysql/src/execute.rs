//! Runs one authorized statement in a read-only transaction and streams its result.
//!
//! ```text
//! acquire agent_pool connection + START TRANSACTION READ ONLY
//!     ↓ SELECT CONNECTION_ID()          so a cancellation has somewhere to go
//!     ↓ fetch, one row at a time        racing the deadline and the token
//!     ↓ normalize + bound each row      ResultBuilder is the authority
//!     ↓ ROLLBACK                        a read-only transaction has nothing to commit
//! ```

use std::future::Future;
use std::sync::Arc;

use futures_util::TryStreamExt as _;
use sqlx::mysql::MySqlDatabaseError;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;
use warden_core::result::{ResultBuilder, ResultSet, RowOutcome};
use warden_policy::AuthorizedQuery;
use warden_ports::error::ExecuteError;
use warden_ports::{BoxFuture, QueryExecutor, QueryPermit};

use crate::connection::MySqlConnectionPools;
use crate::{bind, normalize};

/// The statement that opens every agent transaction.
///
/// A literal Warden wrote, never agent text: `Pool::begin_with` accepts
/// `impl SqlSafeStr`, and `&'static str` is the only type that satisfies it without
/// an assertion. MySQL's read-only transaction blocks table writes and does **not**
/// block `SELECT ... INTO OUTFILE`, `GET_LOCK` or `SLEEP`, which is exactly why the
/// analyzer, the policy engine and the role's `GRANT` all still exist
/// (`docs/operations.md` section 6.1).
const READ_ONLY_TRANSACTION: &str = "START TRANSACTION READ ONLY";

/// `ER_QUERY_TIMEOUT`: `MAX_EXECUTION_TIME` aborted the statement.
const ER_QUERY_TIMEOUT: u16 = 3024;
/// `ER_QUERY_INTERRUPTED`: a `KILL QUERY` reached the statement.
const ER_QUERY_INTERRUPTED: u16 = 1317;

/// How long the cancellation statement gets.
///
/// A fresh budget rather than the query's deadline, which has usually already passed
/// by the time this runs — reusing it would make every timeout skip its own kill.
const KILL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// How long the read-only transaction's own `ROLLBACK` gets, once a result already
/// exists.
///
/// Also a fresh budget rather than the query's `deadline`, for the same reason as
/// `KILL_TIMEOUT`: a query that finishes right at its deadline would otherwise get
/// zero time to release its connection. `ROLLBACK` is connection hygiene, not part of
/// the agent's query, and its own outcome is never propagated (see `run`'s success
/// arm), so this budget only bounds how long a cleanup step is allowed to hold the
/// connection — it does not gate whether the caller gets its result.
const ROLLBACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Runs authorized statements on one MySQL connection's `agent_pool`.
#[derive(Debug)]
pub struct MySqlQueryExecutor {
    pools: Arc<MySqlConnectionPools>,
}

impl MySqlQueryExecutor {
    /// Builds an executor over one connection's pools.
    #[must_use]
    pub fn new(pools: Arc<MySqlConnectionPools>) -> Self {
        Self { pools }
    }
}

impl QueryExecutor for MySqlQueryExecutor {
    /// The permit is named `_permit` because this adapter reads nothing from it.
    /// Its whole job is to exist: the borrow lives for `'a`, so the caller cannot
    /// drop its concurrency slot while this future is still running, and a call site
    /// that never acquired one does not compile (ADR-0032).
    fn execute_read_only<'a>(
        &'a self,
        query: &'a AuthorizedQuery,
        _permit: &'a QueryPermit,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<ResultSet, ExecuteError>> {
        Box::pin(async move { self.run(query, deadline, &cancel).await })
    }
}

impl MySqlQueryExecutor {
    /// One call, from the transaction to the rollback.
    async fn run(
        &self,
        query: &AuthorizedQuery,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<ResultSet, ExecuteError> {
        let started = std::time::Instant::now();

        let mut transaction = guarded(
            deadline,
            cancel,
            self.pools.agent().begin_with(READ_ONLY_TRANSACTION),
        )
        .await?;

        // One extra round trip, accepted deliberately: a cancellation cannot ask a
        // busy connection for its own id, so the id has to be known before the agent
        // statement starts (`docs/operations.md` section 5.4).
        let connection_id: u64 = guarded(
            deadline,
            cancel,
            sqlx::query_scalar("SELECT CONNECTION_ID()").fetch_one(&mut *transaction),
        )
        .await?;

        let outcome = collect(&mut transaction, query, deadline, cancel, started).await;

        match outcome {
            Ok(result) => {
                // MySQL sends a result set with no cursor: breaking out of
                // `collect`'s row loop at the row budget does not tell the server to
                // stop sending, it only stops Warden from reading further. A
                // truncated result therefore still has rows in flight, and a real
                // `KILL QUERY` is the only thing that stops them — without it the
                // connection would go back to the pool, or close, while the
                // statement is still producing rows on the wire, exactly the
                // orphaned-query gap ADR-0024 closes.
                if result.truncated {
                    self.kill(connection_id).await;
                }

                // Rollback, not commit: a read-only transaction has nothing to
                // commit. Its own outcome is deliberately discarded rather than
                // propagated with `?`: `result` already exists and is already
                // correct, and a slow or failed `ROLLBACK` has no bearing on data
                // already collected, so it must never overwrite a valid result with
                // `ExecuteError::Timeout`. (When the branch above killed the query,
                // this `ROLLBACK` is also what drains and observes the resulting
                // `ER_QUERY_INTERRUPTED` — a second reason its error must never
                // surface as this call's error.) It gets its own short budget rather
                // than the query's `deadline` for the same reason `kill` does: a
                // query that finishes right at its deadline would otherwise get no
                // time at all to release its connection. The cancellation token is
                // deliberately not consulted either: a request that was cancelled
                // still wants its connection back intact.
                let rollback_deadline = Instant::now() + ROLLBACK_TIMEOUT;
                let _rollback_outcome = bounded(rollback_deadline, transaction.rollback()).await;
                Ok(result)
            }
            Err(error) => {
                // Every non-success exit from `collect` — a timeout, a
                // cancellation, or a row/value/byte budget failure discovered
                // mid-stream — can leave the server still sending rows for a
                // statement Warden has stopped reading, for the same no-cursor
                // reason as the truncated case above, so the kill is unconditional
                // here rather than limited to `Timeout`/`Cancelled`. Best effort:
                // its own failure is never reported in place of `error`, which is
                // the failure the agent actually needs.
                self.kill(connection_id).await;
                // Dropping queues a ROLLBACK without awaiting it. Awaiting one on a
                // connection whose statement may still be running would hang.
                // `test_before_acquire` — sqlx's own default, which `pool.rs` never
                // overrides — discards anything unusable before the pool hands it
                // out again. The kill above runs first so the connection cannot
                // return to the pool, and its id be reused, before `KILL QUERY`
                // lands.
                drop(transaction);
                Err(error)
            }
        }
    }

    /// Asks the server to stop the statement running on `connection_id`.
    ///
    /// On `control_pool`, because the agent connection is busy — the second reason
    /// ADR-0025's split pays for itself. Called whenever Warden stops reading a
    /// result the server may still be writing: a truncated result on the ordinary
    /// success path, and every `ExecuteError` variant on the failure path, not only
    /// a timeout or a cancellation — MySQL's protocol has no cursor, so nothing else
    /// tells the server Warden has stopped. Best effort in every case: its own
    /// failure is never reported in place of the outcome — `Ok` or `Err` — that
    /// triggered it.
    async fn kill(&self, connection_id: u64) {
        let deadline = Instant::now() + KILL_TIMEOUT;
        let statement = sqlx::query("KILL QUERY ?")
            .bind(connection_id)
            .execute(self.pools.control());
        let _outcome = timeout_at(deadline, statement).await;
    }
}

/// Reads the result one row at a time, under the row, value, and byte budgets.
///
/// Never `fetch_all`: `docs/operations.md` section 6.6 forbids building an unbounded
/// response and truncating it afterwards, because the memory is already spent by
/// then.
async fn collect(
    transaction: &mut sqlx::Transaction<'static, sqlx::MySql>,
    query: &AuthorizedQuery,
    deadline: Instant,
    cancel: &CancellationToken,
    started: std::time::Instant,
) -> Result<ResultSet, ExecuteError> {
    let limits = query.limits();
    let mut rows = bind::statement(query.sql(), query.parameters()).fetch(&mut **transaction);
    let mut builder: Option<ResultBuilder> = None;

    loop {
        let next = tokio::select! {
            // Deterministic ordering: a cancelled request must not depend on which
            // arm the scheduler happened to poll first.
            biased;
            () = cancel.cancelled() => return Err(ExecuteError::Cancelled),
            next = timeout_at(deadline, rows.try_next()) => next,
        };
        let row = match next {
            Ok(Ok(Some(row))) => row,
            Ok(Ok(None)) => break,
            Ok(Err(error)) => return Err(execute_error(&error)),
            Err(_elapsed) => return Err(ExecuteError::Timeout),
        };

        // Column metadata comes from the first row: the driver exposes it nowhere
        // else, and the alternative — preparing the statement separately — would
        // prepare it twice on a pool whose statement cache is disabled and leak the
        // first (`docs/operations.md` section 4).
        let builder =
            builder.get_or_insert_with(|| ResultBuilder::new(normalize::columns(&row), limits));
        let values = normalize::row(&row, builder.columns(), limits.max_value_bytes)?;
        if builder.push_row(values)? == RowOutcome::Truncated {
            break;
        }
    }

    // A result with no rows has no columns, because the driver never sent any.
    // Nothing is invented (`docs/architecture.md` section 11).
    let result = builder
        .unwrap_or_else(|| ResultBuilder::new(Vec::new(), limits))
        .finish(started.elapsed());
    result.validate()?;
    Ok(result)
}

/// Awaits a driver future under both the deadline and the cancellation token.
async fn guarded<T>(
    deadline: Instant,
    cancel: &CancellationToken,
    future: impl Future<Output = Result<T, sqlx::Error>>,
) -> Result<T, ExecuteError> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(ExecuteError::Cancelled),
        result = timeout_at(deadline, future) => finish(result),
    }
}

/// Awaits a driver future under the deadline only.
async fn bounded<T>(
    deadline: Instant,
    future: impl Future<Output = Result<T, sqlx::Error>>,
) -> Result<T, ExecuteError> {
    finish(timeout_at(deadline, future).await)
}

/// Collapses a `timeout_at` result into the port's error type.
fn finish<T>(
    result: Result<Result<T, sqlx::Error>, tokio::time::error::Elapsed>,
) -> Result<T, ExecuteError> {
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(execute_error(&error)),
        Err(_elapsed) => Err(ExecuteError::Timeout),
    }
}

/// Classifies a driver failure by MySQL's own error number (ADR-0033).
///
/// The server deadline is configured to fire before the client one, so the ordinary
/// timeout arrives here as a clean `ER_QUERY_TIMEOUT` with the connection intact
/// (`docs/operations.md` section 5.3). Reporting it as a generic execution failure
/// would give the agent `query_execution_error` for the one case it can actually act
/// on. SQLSTATE cannot make this distinction: `ER_QUERY_TIMEOUT` is `HY000`, which
/// MySQL uses as a general category.
///
/// The message never reaches `Display`; it stays in `detail` for the deliberate
/// diagnostic path, exactly as `ConnectError::Driver` does.
fn execute_error(error: &sqlx::Error) -> ExecuteError {
    if let Some(database) = error.as_database_error()
        && let Some(mysql) = database.try_downcast_ref::<MySqlDatabaseError>()
    {
        match mysql.number() {
            ER_QUERY_TIMEOUT => return ExecuteError::Timeout,
            ER_QUERY_INTERRUPTED => return ExecuteError::Cancelled,
            _ => {}
        }
    }
    ExecuteError::Database {
        detail: error.to_string(),
    }
}
