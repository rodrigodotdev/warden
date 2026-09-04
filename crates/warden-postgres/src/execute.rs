//! Runs one authorized statement in a read-only transaction and streams its result.
//!
//! ```text
//! acquire agent_pool connection + BEGIN READ ONLY
//!     ↓ SET LOCAL statement_timeout     tightened to this request's own limits
//!     ↓ SELECT pg_backend_pid()         so a cancellation has somewhere to go
//!     ↓ fetch, one row at a time        racing the deadline and the token
//!     ↓ normalize + bound each row      ResultBuilder is the authority
//!     ↓ ROLLBACK                        a read-only transaction has nothing to commit
//! ```
//!
//! Every statement here is either a static Warden statement or a bound parameter.

use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::Duration;

use futures_util::TryStreamExt as _;
use sqlx::Connection as _;
use sqlx::pool::PoolConnection;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;
use warden_core::result::{ResultBuilder, ResultSet, RowOutcome};
use warden_policy::AuthorizedQuery;
use warden_ports::error::ExecuteError;
use warden_ports::{BoxFuture, QueryExecutor, QueryPermit};

use crate::connection::PostgreSqlConnectionPools;
use crate::query::agent_query;
use crate::{bind, normalize, options};

/// The statement that opens every agent transaction.
///
/// It is Warden-written rather than agent text. This is the second of ADR-0024's
/// write barriers: the connection startup packet pins the default, while a pooler
/// that discards that option still receives a read-only transaction.
const READ_ONLY_TRANSACTION: &str = "BEGIN READ ONLY";

/// `query_canceled`: a statement timeout or a cancel request (ADR-0034).
const SQLSTATE_QUERY_CANCELED: &str = "57014";

/// How long the cancellation statement gets.
const CANCEL_TIMEOUT: Duration = Duration::from_secs(2);

/// How long the read-only transaction's own rollback gets after a result exists.
const ROLLBACK_TIMEOUT: Duration = Duration::from_secs(2);

/// How long removal of the temporary named agent statement gets.
const DEALLOCATE_TIMEOUT: Duration = Duration::from_secs(2);

/// A checked-out agent connection that cannot return until cleanup is confirmed.
///
/// SQLx queues a rollback when a dropped `Transaction` is still open, but ordinary
/// pool return only pings that session; it does not remove our temporary named
/// statement. Arming this owner immediately after acquisition makes task aborts and
/// future drops close the physical connection. Only a confirmed rollback followed by
/// `DEALLOCATE ALL` disarms it.
struct RetiringConnection {
    connection: PoolConnection<sqlx::Postgres>,
    armed: bool,
}

impl RetiringConnection {
    /// Arms connection retirement before any agent statement can be persistent.
    fn new(connection: PoolConnection<sqlx::Postgres>) -> Self {
        Self {
            connection,
            armed: true,
        }
    }

    /// Allows a known-clean connection to return to its pool normally.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Deref for RetiringConnection {
    type Target = sqlx::PgConnection;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

impl DerefMut for RetiringConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connection
    }
}

impl Drop for RetiringConnection {
    fn drop(&mut self) {
        if self.armed {
            self.connection.close_on_drop();
        }
    }
}

/// Runs authorized statements on one PostgreSQL connection's `agent_pool`.
#[derive(Debug)]
pub struct PostgreSqlQueryExecutor {
    pools: Arc<PostgreSqlConnectionPools>,
    #[cfg(test)]
    cleanup_fault: CleanupFault,
}

impl PostgreSqlQueryExecutor {
    /// Builds an executor over one connection's pools.
    #[must_use]
    pub fn new(pools: Arc<PostgreSqlConnectionPools>) -> Self {
        Self {
            pools,
            #[cfg(test)]
            cleanup_fault: CleanupFault::None,
        }
    }

    /// Builds a test-only executor whose cleanup cannot be confirmed.
    #[cfg(test)]
    fn with_unconfirmed_cleanup(pools: Arc<PostgreSqlConnectionPools>) -> Self {
        Self {
            pools,
            cleanup_fault: CleanupFault::Unconfirmed,
        }
    }
}

/// The narrowly scoped fault needed to prove that unknown cleanup retires a session.
#[cfg(test)]
#[derive(Debug)]
enum CleanupFault {
    /// Run the ordinary production cleanup.
    None,
    /// Make the cleanup status unknown without relying on timing a real server.
    Unconfirmed,
}

impl QueryExecutor for PostgreSqlQueryExecutor {
    /// The permit proves that the caller holds its concurrency slot for `'a`.
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

impl PostgreSqlQueryExecutor {
    /// Runs the transaction from acquisition through cleanup.
    async fn run(
        &self,
        query: &AuthorizedQuery,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<ResultSet, ExecuteError> {
        let started = std::time::Instant::now();

        // Keep the pool connection so the named statement required for custom type
        // metadata can be removed before this exact connection returns to the pool.
        let connection = guarded(deadline, cancel, self.pools.agent().acquire()).await?;
        let mut connection = RetiringConnection::new(connection);
        let mut transaction = guarded(
            deadline,
            cancel,
            connection.begin_with(READ_ONLY_TRANSACTION),
        )
        .await?;

        // `set_config(..., true)` is SET LOCAL in its parameterizable form. It can
        // only tighten the per-connection server-side deadline.
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
        // id before the agent statement begins.
        let row = guarded(
            deadline,
            cancel,
            agent_query("SELECT pg_backend_pid()").fetch_one(&mut *transaction),
        )
        .await?;
        let backend_pid: i32 =
            sqlx::Row::try_get(&row, 0).map_err(|error| execute_error(&error))?;

        let outcome = collect(&mut transaction, query, deadline, cancel, started).await;

        match &outcome {
            // Stopping at a result limit leaves PostgreSQL producing the rest of
            // the portal. Any error or cancellation can do the same.
            Ok(result) if result.truncated => self.cancel_backend(backend_pid).await,
            Err(_) => self.cancel_backend(backend_pid).await,
            Ok(_) => {}
        }

        // The physical connection owns the temporary named statement. It is safe
        // to return only after both the transaction boundary and its removal have
        // answered successfully. A timed rollback drops its Transaction and queues
        // a rollback in SQLx, but that is still unknown session state, so this pool
        // connection is retired rather than being made available to another query.
        let rollback_deadline = Instant::now() + ROLLBACK_TIMEOUT;
        let rollback_confirmed = bounded(rollback_deadline, transaction.rollback())
            .await
            .is_ok();
        let cleanup_confirmed = if rollback_confirmed {
            self.deallocate_agent_statement(&mut connection).await
        } else {
            false
        };
        if cleanup_confirmed {
            connection.disarm();
        }
        outcome
    }

    /// Asks the control pool to stop the backend that is still executing.
    async fn cancel_backend(&self, backend_pid: i32) {
        let deadline = Instant::now() + CANCEL_TIMEOUT;
        let statement = sqlx::query("SELECT pg_cancel_backend($1)")
            .bind(backend_pid)
            .execute(self.pools.control());
        let _outcome = timeout_at(deadline, statement).await;
    }

    /// Removes the temporary named statement from the pinned agent connection.
    ///
    /// A custom result type makes SQLx resolve metadata through a simple query, which
    /// PostgreSQL documents as destroying the unnamed statement. The bound agent query
    /// is therefore named for this one request; this static, non-persistent cleanup
    /// runs only after rollback has restored the session. A false return retires the
    /// physical connection rather than returning unknown state to the pool.
    async fn deallocate_agent_statement(&self, connection: &mut sqlx::PgConnection) -> bool {
        #[cfg(test)]
        if matches!(self.cleanup_fault, CleanupFault::Unconfirmed) {
            return false;
        }

        let deadline = Instant::now() + DEALLOCATE_TIMEOUT;
        let statement = agent_query("DEALLOCATE ALL").execute(connection);
        bounded(deadline, statement).await.is_ok()
    }
}

/// Reads the result one row at a time under its row, value, and byte budgets.
async fn collect(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    query: &AuthorizedQuery,
    deadline: Instant,
    cancel: &CancellationToken,
    started: std::time::Instant,
) -> Result<ResultSet, ExecuteError> {
    let limits = query.limits();
    let mut rows = bind::statement(query.sql(), query.parameters()).fetch(&mut **transaction);
    let mut builder: Option<ResultBuilder> = None;

    loop {
        // Each fetch goes through the same guard as the statements before it, so an
        // expired deadline stops the next row rather than being outrun by one the
        // driver had already buffered.
        let row = match guarded(deadline, cancel, rows.try_next()).await? {
            Some(row) => row,
            None => break,
        };

        let builder =
            builder.get_or_insert_with(|| ResultBuilder::new(normalize::columns(&row), limits));
        if builder.admit_row() == RowOutcome::Truncated {
            break;
        }
        let values = normalize::row(&row, builder.columns(), limits.max_value_bytes)?;
        if builder.push_row(values)? == RowOutcome::Truncated {
            break;
        }
    }

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
    if expired(deadline) {
        return Err(ExecuteError::Timeout);
    }
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
    if expired(deadline) {
        return Err(ExecuteError::Timeout);
    }
    finish(timeout_at(deadline, future).await)
}

/// Whether the deadline has already passed, checked before any work begins.
///
/// `timeout_at` polls its inner future *before* it consults the deadline and
/// reports success whenever that first poll is ready, so a driver call whose reply
/// is already buffered outruns a deadline that expired long ago. A pooled
/// connection answers that fast whenever the runtime was descheduled long enough
/// for the server's reply to arrive. Refusing up front is what keeps expired work
/// from reaching the connection at all; the deadline still bounds the call itself
/// once it starts.
fn expired(deadline: Instant) -> bool {
    Instant::now() >= deadline
}

/// Collapses a timed driver operation into the port's error type.
fn finish<T>(
    result: Result<Result<T, sqlx::Error>, tokio::time::error::Elapsed>,
) -> Result<T, ExecuteError> {
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(execute_error(&error)),
        Err(_elapsed) => Err(ExecuteError::Timeout),
    }
}

/// Classifies a PostgreSQL failure by SQLSTATE (ADR-0034).
fn execute_error(error: &sqlx::Error) -> ExecuteError {
    if let Some(database) = error.as_database_error()
        && database.code().as_deref() == Some(SQLSTATE_QUERY_CANCELED)
    {
        return ExecuteError::Timeout;
    }
    ExecuteError::Database {
        detail: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::time::Duration;

    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;
    use warden_ports::error::ExecuteError;

    use super::{bounded, guarded};

    /// An answer that is already buffered must not outrank an expired deadline.
    ///
    /// This is the unit-level form of the race that let an expired request reach a
    /// real server: `timeout_at` reports success whenever the first poll of its
    /// inner future is ready, and a pooled connection is ready exactly that fast
    /// once the runtime has been descheduled long enough for the reply to arrive.
    #[tokio::test]
    async fn an_expired_deadline_outranks_work_that_could_answer_at_once() {
        let expired = Instant::now() - Duration::from_millis(1);
        let cancel = CancellationToken::new();

        let guarded_outcome = guarded(expired, &cancel, async { Ok::<_, sqlx::Error>(()) }).await;
        let bounded_outcome = bounded(expired, async { Ok::<_, sqlx::Error>(()) }).await;

        assert_eq!(guarded_outcome.unwrap_err(), ExecuteError::Timeout);
        assert_eq!(bounded_outcome.unwrap_err(), ExecuteError::Timeout);
    }

    /// The guard refuses only expired deadlines, never a live one.
    #[tokio::test]
    async fn a_live_deadline_still_lets_the_work_run() {
        let live = Instant::now() + Duration::from_secs(30);
        let cancel = CancellationToken::new();

        let guarded_outcome = guarded(live, &cancel, async { Ok::<_, sqlx::Error>(7) }).await;
        let bounded_outcome = bounded(live, async { Ok::<_, sqlx::Error>(7) }).await;

        assert_eq!(guarded_outcome.unwrap(), 7);
        assert_eq!(bounded_outcome.unwrap(), 7);
    }
}

#[cfg(all(test, feature = "docker"))]
mod cleanup_tests;
