//! The five tools, and the one task each request runs in.
//!
//! Each `#[tool]` method does three things and no more: build the per-call identity,
//! convert the arguments into a `warden-core` request, and hand both to a
//! `warden-service` service. It reads no pool, opens no transaction, and never sees a
//! `sqlx` type — SPEC section 6, invariants 26 and 27, and the reason `warden-mcp` may
//! not depend on either adapter.
//!
//! # One task per request
//!
//! `docs/architecture.md` section 8 and ADR-0038 both assign this to Milestone 12: a
//! recorded audit attempt receives its terminal outcome only if the request future is
//! polled to completion, and `docs/security.md` section 14 calls per-request containment
//! critical for the single-process stdio transport, where one panic would otherwise end
//! the whole session. [`WardenServer::run_in_task`] spawns, awaits, and turns a
//! `JoinError` into `internal_error`. It does not read the panic payload: a payload can
//! contain a row value, and Milestone 13 owns the payload-free hook that records the
//! location instead.
//!
//! What the spawn buys is containment, not a complete record of the request that
//! panicked. ADR-0038's consequences say so directly: it keeps an ordinary request on
//! the path that writes its outcome *and* contains a panic to the one request that
//! raised it, but a task that panics still leaves its audit attempt without a terminal
//! outcome. Closing that last gap is not this milestone's.
//!
//! # Client cancellation is not wired through, deliberately
//!
//! rmcp hands each call a `CancellationToken` that fires on a `notifications/cancelled`,
//! but `warden-service` derives its per-request token from the process-wide shutdown
//! token it was built with, and there is no seam to pass another one in. Aborting the
//! spawned task instead would strand the audit attempt without an outcome, which is
//! precisely the hole ADR-0038 names. Every request is already bounded by
//! `warden_service::RequestBudget::total`, so the exposure is one budget, not an
//! unbounded wait. Open question 23 carries the seam to the milestone that needs it.

use std::future::Future;
use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::service::RequestContext as McpRequestContext;
use rmcp::{RoleServer, tool, tool_router};
use warden_core::context::RequestContext;
use warden_core::error::{PublicError, PublicErrorCode};
use warden_service::Services;

use crate::error::failure;
use crate::input::{DescribeInput, ExplainInput, QueryInput, SearchInput};
use crate::output::ToolResponse;
use crate::{identity, output};

/// The MCP server: five tools over one set of application services.
pub struct WardenServer {
    services: Arc<Services>,
    tool_router: ToolRouter<Self>,
}

/// Prints only safe composition metadata.
///
/// `Services`' own `Debug` already hides its collaborators; the router is repeated
/// structure with nothing to inspect.
impl std::fmt::Debug for WardenServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WardenServer")
            .field("tools", &self.tool_router.list_all().len())
            .finish_non_exhaustive()
    }
}

#[tool_router]
impl WardenServer {
    /// Wires the tools to the services the composition root assembled.
    #[must_use]
    pub fn new(services: Arc<Services>) -> Self {
        Self {
            services,
            tool_router: Self::tool_router(),
        }
    }

    /// Lists the connections this server can reach, with the dialect each one speaks.
    ///
    /// Call this first. The connection you pick decides which SQL dialect the `query`
    /// and `explain` tools accept and which placeholder syntax they take: `?` on MySQL
    /// and `$1` on PostgreSQL. The response carries public metadata only — never a
    /// host, a user, or a connection string.
    #[tool(
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        ),
        output_schema = rmcp::handler::server::tool::schema_for_output::<output::ConnectionsOutput>()
    )]
    async fn list_connections(&self, context: McpRequestContext<RoleServer>) -> CallToolResult {
        match identity::for_request(&context) {
            Ok(identity) => self.run_list_connections(identity).await,
            Err(code) => failure(code),
        }
    }

    /// Finds relations by name, before you write a statement against them.
    ///
    /// Run `search_schema` before `query`: it is how you discover the relation names
    /// this connection actually has. Its `query` argument accepts several free-text
    /// terms in one string, separated by whitespace. Results are bounded and ranked by
    /// how each relation matched, so even a broad search returns the best matches
    /// rather than the whole catalog; narrow the terms when what you need is not among
    /// them. Follow it with `describe_schema` for the columns and keys of the relations
    /// you picked.
    #[tool(
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        ),
        output_schema = rmcp::handler::server::tool::schema_for_output::<output::SearchOutput>()
    )]
    async fn search_schema(
        &self,
        Parameters(input): Parameters<SearchInput>,
        context: McpRequestContext<RoleServer>,
    ) -> CallToolResult {
        match identity::for_request(&context) {
            Ok(identity) => self.run_search_schema(identity, input).await,
            Err(code) => failure(code),
        }
    }

    /// Returns the columns, keys, and indexes of relations `search_schema` found.
    ///
    /// Run this after `search_schema`, naming at most 20 tables per call, each written
    /// as `schema.table` or as a bare `table`. Every relation comes back with its
    /// columns, its primary key, its foreign keys, and its indexes. A relation marked
    /// `truncated` had metadata left out by a bound or by the database privileges the
    /// read-only role holds: what is present is accurate, but it is not everything.
    #[tool(
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        ),
        output_schema = rmcp::handler::server::tool::schema_for_output::<output::DescribeOutput>()
    )]
    async fn describe_schema(
        &self,
        Parameters(input): Parameters<DescribeInput>,
        context: McpRequestContext<RoleServer>,
    ) -> CallToolResult {
        match identity::for_request(&context) {
            Ok(identity) => self.run_describe_schema(identity, input).await,
            Err(code) => failure(code),
        }
    }

    /// Runs a single read-only `SELECT` and returns the rows it produced.
    ///
    /// Only a single `SELECT` is accepted, read-only CTEs included. `INSERT`, `UPDATE`,
    /// `DELETE`, DDL, and several statements in one call are rejected, and so are
    /// `SHOW`, `EXPLAIN`, and `SET`: planning has the `explain` tool, and the other two
    /// are unavailable here. Placeholders are dialect-native — `?` on MySQL, `$1` on
    /// PostgreSQL — with one value per placeholder, in the statement's own order.
    /// Results are bounded: when the response reports `truncated`, refine the statement
    /// — a narrower projection, a filter, a smaller `LIMIT` — rather than repeating it
    /// unchanged.
    #[tool(
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        ),
        output_schema = rmcp::handler::server::tool::schema_for_output::<output::QueryOutput>()
    )]
    async fn query(
        &self,
        Parameters(input): Parameters<QueryInput>,
        context: McpRequestContext<RoleServer>,
    ) -> CallToolResult {
        match identity::for_request(&context) {
            Ok(identity) => self.run_query(identity, input).await,
            Err(code) => failure(code),
        }
    }

    /// Returns the engine's plan for a statement without executing it.
    ///
    /// The statement is planned, never run. Every policy `query` applies is applied
    /// here too, because planning is real work on the server rather than a dry run.
    /// The plan is the engine's own document: its costs are that engine's units, and
    /// they are not comparable between dialects.
    #[tool(
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        ),
        output_schema = rmcp::handler::server::tool::schema_for_output::<output::ExplainOutput>()
    )]
    async fn explain(
        &self,
        Parameters(input): Parameters<ExplainInput>,
        context: McpRequestContext<RoleServer>,
    ) -> CallToolResult {
        match identity::for_request(&context) {
            Ok(identity) => self.run_explain(identity, input).await,
            Err(code) => failure(code),
        }
    }
}

impl WardenServer {
    /// Runs one future in its own task and maps a lost task to `internal_error`.
    async fn run_in_task<T, F>(future: F) -> Result<T, PublicErrorCode>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        match tokio::spawn(future).await {
            Ok(value) => Ok(value),
            Err(join) => {
                // No payload: it can contain a row value, and Milestone 13 owns the
                // hook that records location and type instead (`docs/security.md`
                // section 14).
                tracing::error!(
                    target: "warden.mcp",
                    panicked = join.is_panic(),
                    "a tool task did not complete"
                );
                Err(PublicErrorCode::InternalError)
            }
        }
    }

    /// Answers `list_connections` from the registry the composition root supplied.
    ///
    /// The one runner that spawns no task: it reads an in-memory map through
    /// `Services::registry()` and awaits nothing, so a task would add a hop and a
    /// failure mode without containing anything.
    ///
    /// It takes the identity it does not read so that every tool builds one on the same
    /// path — a call this transport cannot identify must fail here exactly as it does
    /// for the other four — and because Milestone 13's audit event needs it.
    async fn run_list_connections(&self, _identity: RequestContext) -> CallToolResult {
        output::ConnectionsOutput::from_metadata(&self.services.registry().list()).into_result()
    }

    /// Answers `query`: validate the arguments, then run one statement in its own task.
    async fn run_query(&self, identity: RequestContext, input: QueryInput) -> CallToolResult {
        let request = match input.into_request() {
            Ok(request) => request,
            Err(code) => return failure(code),
        };
        let services = Arc::clone(&self.services);
        let outcome =
            Self::run_in_task(async move { services.query().execute(&identity, request).await })
                .await;
        match outcome {
            Ok(Ok(result)) => output::QueryOutput::from(&result).into_result(),
            Ok(Err(error)) => failure(error.public_code()),
            Err(code) => failure(code),
        }
    }

    /// Answers `explain`: the same validation and containment, without execution.
    async fn run_explain(&self, identity: RequestContext, input: ExplainInput) -> CallToolResult {
        let request = match input.into_request() {
            Ok(request) => request,
            Err(code) => return failure(code),
        };
        let services = Arc::clone(&self.services);
        let outcome =
            Self::run_in_task(async move { services.explain().explain(&identity, request).await })
                .await;
        match outcome {
            Ok(Ok(plan)) => output::ExplainOutput::from(&plan).into_result(),
            Ok(Err(error)) => failure(error.public_code()),
            Err(code) => failure(code),
        }
    }

    /// Answers `search_schema` through the schema service's bounded catalog read.
    async fn run_search_schema(
        &self,
        identity: RequestContext,
        input: SearchInput,
    ) -> CallToolResult {
        let request = match input.into_request() {
            Ok(request) => request,
            Err(code) => return failure(code),
        };
        let services = Arc::clone(&self.services);
        let outcome =
            Self::run_in_task(async move { services.schema().search(&identity, request).await })
                .await;
        match outcome {
            Ok(Ok(found)) => output::SearchOutput::from(&found).into_result(),
            Ok(Err(error)) => failure(error.public_code()),
            Err(code) => failure(code),
        }
    }

    /// Answers `describe_schema` through the same bounded, policy-filtered read.
    async fn run_describe_schema(
        &self,
        identity: RequestContext,
        input: DescribeInput,
    ) -> CallToolResult {
        let request = match input.into_request() {
            Ok(request) => request,
            Err(code) => return failure(code),
        };
        let services = Arc::clone(&self.services);
        let outcome =
            Self::run_in_task(async move { services.schema().describe(&identity, request).await })
                .await;
        match outcome {
            Ok(Ok(described)) => output::DescribeOutput::from(&described).into_result(),
            Ok(Err(error)) => failure(error.public_code()),
            Err(code) => failure(code),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::testing;

    fn identity() -> warden_core::context::RequestContext {
        warden_core::context::RequestContext::new(
            "req-1".parse().unwrap(),
            crate::identity::STDIO_PRINCIPAL.parse().unwrap(),
            "warden-mcp-test".parse().unwrap(),
        )
    }

    fn query_input(connection: &str, sql: &str) -> QueryInput {
        QueryInput {
            connection: connection.to_owned(),
            sql: sql.to_owned(),
            parameters: Vec::new(),
        }
    }

    fn explain_input(connection: &str, sql: &str) -> ExplainInput {
        ExplainInput {
            connection: connection.to_owned(),
            sql: sql.to_owned(),
            parameters: Vec::new(),
        }
    }

    fn search_input(query: &str) -> SearchInput {
        SearchInput {
            connection: testing::CONNECTION.to_owned(),
            query: query.to_owned(),
            limit: None,
        }
    }

    fn describe_input(tables: &[&str]) -> DescribeInput {
        DescribeInput {
            connection: testing::CONNECTION.to_owned(),
            tables: tables.iter().map(|table| (*table).to_owned()).collect(),
        }
    }

    #[tokio::test]
    async fn listing_connections_returns_the_registry_and_no_dsn() {
        let server = WardenServer::new(testing::services());
        let result = server.run_list_connections(identity()).await;
        let structured = result.structured_content.unwrap();
        assert_eq!(
            structured["connections"][0]["name"],
            serde_json::json!("production-db")
        );
        let rendered = serde_json::to_string(&structured).unwrap();
        for forbidden in ["://", "password", "@"] {
            assert!(!rendered.contains(forbidden), "{rendered}");
        }
    }

    #[tokio::test]
    async fn a_safe_select_returns_rows_as_structured_content() {
        let server = WardenServer::new(testing::services());
        let result = server
            .run_query(
                identity(),
                query_input("production-db", "SELECT id FROM orders"),
            )
            .await;
        assert_eq!(result.is_error, Some(false));
        assert!(result.structured_content.unwrap()["rows"].is_array());
    }

    #[tokio::test]
    async fn a_denied_statement_reaches_the_agent_as_query_rejected_and_nothing_else() {
        let server = WardenServer::new(testing::services_from(testing::FakeParts::writing()));
        let result = server
            .run_query(
                identity(),
                query_input("production-db", "DELETE FROM orders"),
            )
            .await;
        assert_eq!(result.is_error, Some(true));
        let structured = result.structured_content.unwrap();
        assert_eq!(
            structured["error"]["code"],
            serde_json::json!("query_rejected")
        );
        // The agent gets one code, not the list of every rule that fired: an error must
        // not become an oracle that reveals the policy one call at a time (ADR-0012).
        let rendered = serde_json::to_string(&structured).unwrap();
        assert!(!rendered.contains("nested"), "{rendered}");
    }

    #[tokio::test]
    async fn an_unknown_connection_never_reaches_an_analyzer() {
        let server = WardenServer::new(testing::services());
        let result = server
            .run_query(identity(), query_input("staging-db", "SELECT 1"))
            .await;
        assert_eq!(
            result.structured_content.unwrap()["error"]["code"],
            serde_json::json!("connection_not_found")
        );
    }

    #[tokio::test]
    async fn a_driver_failure_reaches_the_agent_as_a_code_and_never_as_its_message() {
        let server = WardenServer::new(testing::services_from(testing::FakeParts::failing(
            warden_ports::ExecuteError::Database {
                detail: "Access denied for user 'warden_ro'@'10.0.0.7'".to_owned(),
            },
        )));
        let result = server
            .run_query(identity(), query_input("production-db", "SELECT 1"))
            .await;
        let rendered = serde_json::to_string(&result).unwrap();
        assert!(rendered.contains("query_execution_error"), "{rendered}");
        for leaked in ["Access denied", "warden_ro", "10.0.0.7"] {
            assert!(!rendered.contains(leaked), "{rendered}");
        }
    }

    #[tokio::test]
    async fn a_panicking_adapter_becomes_internal_error_and_the_server_keeps_serving() {
        // Decision 8: each request runs in its own task, so a panic is a JoinError here
        // rather than the end of the process — which for stdio would be the end of the
        // session (docs/security.md section 14).
        let server = WardenServer::new(testing::services_with_a_panicking_connection());
        let result = server
            .run_query(identity(), query_input(testing::CONNECTION, "SELECT 1"))
            .await;
        assert_eq!(
            result.structured_content.clone().unwrap()["error"]["code"],
            serde_json::json!("internal_error")
        );

        // The payload is never read, so what the panicking adapter put in it reaches no
        // agent. A payload can hold a row value, which is why Decision 8 forbids reading
        // one and Milestone 13 records the location instead; this is what would catch a
        // `run_in_task` that starts formatting the `JoinError` it caught.
        let rendered = serde_json::to_string(&result).unwrap();
        assert!(!rendered.contains("hunter2"), "{rendered}");

        // Containment is a claim about *this* server: the same instance still serves the
        // sibling connection whose adapter did not panic...
        let healthy = server
            .run_query(
                identity(),
                query_input(testing::HEALTHY_CONNECTION, "SELECT id FROM orders"),
            )
            .await;
        assert_eq!(healthy.is_error, Some(false));
        assert!(healthy.structured_content.unwrap()["rows"].is_array());

        // ...and still answers on the connection that panicked, rather than hanging on a
        // permit the lost task never released.
        let again = server
            .run_query(identity(), query_input(testing::CONNECTION, "SELECT 1"))
            .await;
        assert_eq!(
            again.structured_content.unwrap()["error"]["code"],
            serde_json::json!("internal_error")
        );
    }

    #[tokio::test]
    async fn explain_plans_a_statement_and_returns_the_engine_document() {
        let server = WardenServer::new(testing::services());
        let result = server
            .run_explain(identity(), explain_input("production-db", "SELECT 1"))
            .await;
        let structured = result.structured_content.unwrap();
        assert_eq!(structured["dialect"], serde_json::json!("mysql"));
        assert!(structured["plan"].is_object() || structured["plan"].is_array());
    }

    #[tokio::test]
    async fn search_and_describe_reach_the_inspector_through_the_schema_service() {
        let server = WardenServer::new(testing::services());
        let searched = server
            .run_search_schema(identity(), search_input("orders"))
            .await;
        assert_eq!(searched.is_error, Some(false));
        let described = server
            .run_describe_schema(identity(), describe_input(&["app.orders"]))
            .await;
        assert_eq!(described.is_error, Some(false));
    }

    #[test]
    fn the_router_exposes_exactly_the_five_documented_tools() {
        let mut names: Vec<String> = WardenServer::tool_router()
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "describe_schema",
                "explain",
                "list_connections",
                "query",
                "search_schema"
            ]
        );
    }

    #[test]
    fn no_tool_name_carries_a_dialect() {
        // docs/mcp.md section 1: the selected connection chooses the backend, and adding
        // PostgreSQL must never create a second set of tool names (section 4).
        for tool in WardenServer::tool_router().list_all() {
            for dialect in ["mysql", "postgres", "postgresql", "sql_server"] {
                assert!(!tool.name.contains(dialect), "{}", tool.name);
            }
        }
    }
}
