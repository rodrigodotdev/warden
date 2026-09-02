//! Validated MCP tool arguments.
//!
//! Every struct here denies unknown fields, so a misspelled argument fails loudly
//! instead of silently taking a default (`docs/operations.md` section 3.1's rule
//! applied to tool input). Every `///` doc comment on a field becomes part of the
//! JSON schema an agent reads (`schemars`), so they are written for that audience.
//!
//! `into_request` on each type produces the already size-validated `warden-core`
//! request the service layer accepts, or the [`PublicErrorCode`] an agent should see
//! instead — never a `warden-core` or `warden-service` error type directly, which
//! would leak internal detail past the boundary [`crate::error`] owns.

use std::fmt;

use rmcp::schemars::JsonSchema;
use serde::Deserialize;
use warden_core::error::{PublicError, PublicErrorCode};
use warden_core::explain::ExplainRequest;
use warden_core::parameter::ParameterValue;
use warden_core::query::{InputLimits, QueryRequest};
use warden_core::schema::{
    SchemaDescribeRequest, SchemaRequestError, SchemaSearchRequest, TableSelector,
};

/// The default number of matches `search_schema` returns when the agent omits
/// `limit` (`docs/mcp.md` section 2).
pub const DEFAULT_SEARCH_LIMIT: usize = 20;

/// One placeholder value bound to a `query` or `explain` statement.
///
/// A transparent wrapper over the raw JSON so [`TryFrom<ParameterInput>`] can apply
/// `docs/data-model.md` section 3.1's exactness rule itself, rather than deriving a
/// schema from [`ParameterValue`], which lives in `warden-core` and takes serde and
/// nothing else (`docs/architecture.md` section 3).
#[derive(Deserialize)]
#[serde(transparent)]
pub struct ParameterInput(serde_json::Value);

/// Prints shape, never content. Parameters are not logged by default (SPEC section
/// 6, invariant 23); mirrors `warden_core::parameter::ParameterValue`'s own hand-written
/// `Debug`, so a `tracing::debug!(?input, ..)` on `QueryInput`/`ExplainInput` — both of
/// which carry a `Vec<ParameterInput>` and derive `Debug` — cannot reintroduce the leak
/// that impl closes.
impl fmt::Debug for ParameterInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            serde_json::Value::Null => f.write_str("Null"),
            serde_json::Value::Bool(_) => f.write_str("Bool(<redacted>)"),
            serde_json::Value::Number(_) => f.write_str("Number(<redacted>)"),
            serde_json::Value::String(value) => {
                write!(f, "String(<redacted {} bytes>)", value.len())
            }
            serde_json::Value::Array(_) => f.write_str("Array(<redacted>)"),
            serde_json::Value::Object(_) => f.write_str("Object(<redacted>)"),
        }
    }
}

impl JsonSchema for ParameterInput {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ParameterValue".into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_generator: &mut rmcp::schemars::SchemaGenerator) -> rmcp::schemars::Schema {
        // Derived from `ParameterValue` by hand because that enum lives in `warden-core`,
        // which takes serde and nothing else (`docs/architecture.md` section 3), and
        // because the union a parameter accepts is a wire fact rather than a Rust one.
        rmcp::schemars::json_schema!({
            "type": ["string", "number", "boolean", "null"],
            "description": "One placeholder value. Containers are not accepted: pass a \
                            scalar per placeholder in the statement's own order."
        })
    }
}

impl TryFrom<ParameterInput> for ParameterValue {
    type Error = PublicErrorCode;

    /// Delegates to [`ParameterValue`]'s own `Deserialize`, which already implements
    /// `docs/data-model.md` section 3.1's number classification: an integer that
    /// fits `i64` or `u64` remains exact, and every other number — decimal **and**
    /// exponent syntax alike — routes through `ParameterValue::float`, which refuses
    /// an integral magnitude at or above 2^53 regardless of which syntax produced
    /// it. An array or object is refused the same way `warden-core` refuses one.
    ///
    /// This delegates rather than re-implementing the classification so the
    /// workspace keeps exactly one number classifier
    /// (`warden-core/src/parameter.rs`'s `from_json_number`); a second copy at this
    /// boundary is exactly the kind of drift that let `1e300` and `9007199254740994.0`
    /// disagree in an earlier version of this conversion.
    fn try_from(input: ParameterInput) -> Result<Self, Self::Error> {
        serde_json::from_value(input.0).map_err(|_| PublicErrorCode::QueryParseError)
    }
}

/// Builds the size-validated statement `query` and `explain` share.
///
/// Decision 12: [`InputLimits::default`] — the 64 KiB / 100-parameter bounds of
/// `docs/data-model.md` section 2 — because no configuration key exposes them yet.
fn build_query_request(
    connection: String,
    sql: String,
    parameters: Vec<ParameterInput>,
) -> Result<QueryRequest, PublicErrorCode> {
    let connection = connection
        .parse()
        .map_err(|_| PublicErrorCode::ConnectionNotFound)?;
    let parameters = parameters
        .into_iter()
        .map(ParameterValue::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    QueryRequest::new(connection, sql, parameters, &InputLimits::default())
        .map_err(|error| error.public_code())
}

/// Arguments to the `query` tool (`docs/mcp.md` section 2).
///
/// `query` accepts only `SELECT`, including read-only CTEs. Placeholders are
/// dialect-native: `?` on MySQL, `$1` on PostgreSQL.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct QueryInput {
    /// The configured connection to run against; determines the dialect and
    /// placeholder syntax. See `list_connections`.
    pub connection: String,
    /// The statement to execute, using the connection's own placeholder syntax.
    pub sql: String,
    /// Values bound to the statement's placeholders, in the statement's own order.
    /// Omit for a statement with no placeholders.
    #[serde(default)]
    pub parameters: Vec<ParameterInput>,
}

impl QueryInput {
    /// Builds the validated request `warden-service` accepts, or the public code an
    /// agent should see instead.
    ///
    /// # Errors
    ///
    /// Returns the [`PublicErrorCode`] `warden-core`'s own validation names — never
    /// the internal error it came from.
    pub fn into_request(self) -> Result<QueryRequest, PublicErrorCode> {
        build_query_request(self.connection, self.sql, self.parameters)
    }
}

/// Arguments to the `explain` tool (`docs/mcp.md` section 2).
///
/// `explain` inspects a plan without executing the statement. It carries exactly the
/// fields `query` does: an explained statement passes the same size validation,
/// analysis, and policy evaluation as an executed one, because PostgreSQL's planner
/// can run an `IMMUTABLE` function while planning (`docs/mcp.md` section 3.1).
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct ExplainInput {
    /// The connection to plan against; determines the dialect and placeholder syntax.
    pub connection: String,
    /// The statement to plan. Never executed.
    pub sql: String,
    /// Values bound to the statement's placeholders, in the statement's own order.
    #[serde(default)]
    pub parameters: Vec<ParameterInput>,
}

impl ExplainInput {
    /// Builds the validated request, wrapping the same query `query` would run.
    ///
    /// # Errors
    ///
    /// Returns the [`PublicErrorCode`] `warden-core`'s own validation names.
    pub fn into_request(self) -> Result<ExplainRequest, PublicErrorCode> {
        build_query_request(self.connection, self.sql, self.parameters).map(ExplainRequest::new)
    }
}

/// Arguments to the `search_schema` tool (`docs/mcp.md` section 2).
///
/// Run `search_schema` before `query` to discover table names; it accepts multiple
/// free-text terms and never returns the whole catalog.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct SearchInput {
    /// The connection to search.
    pub connection: String,
    /// Free-text search terms, separated by whitespace.
    pub query: String,
    /// The largest number of matches to return. Defaults to 20 when omitted.
    pub limit: Option<usize>,
}

impl SearchInput {
    /// Builds the validated request, defaulting `limit` to [`DEFAULT_SEARCH_LIMIT`].
    ///
    /// # Errors
    ///
    /// Returns the [`PublicErrorCode`] `warden-core`'s own validation names.
    pub fn into_request(self) -> Result<SchemaSearchRequest, PublicErrorCode> {
        let connection = self
            .connection
            .parse()
            .map_err(|_| PublicErrorCode::ConnectionNotFound)?;
        let limit = self.limit.unwrap_or(DEFAULT_SEARCH_LIMIT);
        SchemaSearchRequest::new(connection, &self.query, limit)
            .map_err(|error| error.public_code())
    }
}

/// Arguments to the `describe_schema` tool (`docs/mcp.md` section 2).
///
/// Follows `search_schema` and accepts at most 20 tables per call.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct DescribeInput {
    /// The connection to describe.
    pub connection: String,
    /// Tables to describe, as `schema.table` or a bare `table`; at most 20 per call.
    pub tables: Vec<String>,
}

impl DescribeInput {
    /// Builds the validated request, or the public code an agent should see instead.
    ///
    /// # Errors
    ///
    /// Returns the [`PublicErrorCode`] `warden-core`'s own validation names.
    pub fn into_request(self) -> Result<SchemaDescribeRequest, PublicErrorCode> {
        let connection = self
            .connection
            .parse()
            .map_err(|_| PublicErrorCode::ConnectionNotFound)?;
        let tables = self
            .tables
            .into_iter()
            .map(|table| {
                TableSelector::try_from(table)
                    .map_err(|error: SchemaRequestError| error.public_code())
            })
            .collect::<Result<Vec<_>, _>>()?;
        SchemaDescribeRequest::new(connection, tables).map_err(|error| error.public_code())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn query_input(json: serde_json::Value) -> Result<QueryInput, serde_json::Error> {
        serde_json::from_value(json)
    }

    #[test]
    fn a_documented_query_call_becomes_a_validated_request() {
        // The exact payload from docs/mcp.md section 2.
        let input = query_input(serde_json::json!({
            "connection": "production-mysql",
            "sql": "SELECT id, status FROM orders WHERE customer_id = ? LIMIT 20",
            "parameters": ["customer_123"]
        }))
        .unwrap();
        let request = input.into_request().unwrap();
        assert_eq!(request.connection().as_str(), "production-mysql");
        assert_eq!(request.parameters().len(), 1);
        assert!(request.sql().starts_with("SELECT id, status"));
    }

    #[test]
    fn parameters_are_optional_and_default_to_none_at_all() {
        let input = query_input(serde_json::json!({
            "connection": "db",
            "sql": "SELECT 1"
        }))
        .unwrap();
        assert!(input.into_request().unwrap().parameters().is_empty());
    }

    #[test]
    fn parameter_input_debug_never_prints_a_value() {
        // Finding 3: derived Debug over the raw serde_json::Value would put every
        // bound parameter into a tracing::debug!(?input, ..) line in plaintext.
        let secret: ParameterInput = serde_json::from_value(serde_json::json!("hunter2")).unwrap();
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert_eq!(rendered, "String(<redacted 7 bytes>)");
    }

    #[test]
    fn a_misspelled_argument_is_refused_rather_than_defaulted() {
        assert!(
            query_input(serde_json::json!({
                "connection": "db",
                "sql": "SELECT 1",
                "params": ["x"]
            }))
            .is_err()
        );
    }

    #[test]
    fn every_scalar_parameter_maps_to_its_own_value_and_no_container_does() {
        for (json, expected) in [
            (serde_json::json!(null), ParameterValue::Null),
            (serde_json::json!(true), ParameterValue::Bool(true)),
            (serde_json::json!(-7), ParameterValue::I64(-7)),
            (
                serde_json::json!("c-1"),
                ParameterValue::String("c-1".to_owned()),
            ),
        ] {
            let parameter: ParameterInput = serde_json::from_value(json.clone()).unwrap();
            assert_eq!(
                ParameterValue::try_from(parameter).unwrap(),
                expected,
                "{json}"
            );
        }
        for rejected in [serde_json::json!([1]), serde_json::json!({"a": 1})] {
            let parameter: ParameterInput = serde_json::from_value(rejected.clone()).unwrap();
            assert_eq!(
                ParameterValue::try_from(parameter).unwrap_err(),
                PublicErrorCode::QueryParseError,
                "{rejected}"
            );
        }
    }

    #[test]
    fn a_float_json_cannot_carry_exactly_is_refused_rather_than_rounded() {
        // ParameterValue::float owns this rule (docs/data-model.md section 3.1): an
        // integral magnitude at or above 2^53 is refused in decimal AND exponent
        // syntax alike. This test proves the MCP boundary routes through that one
        // classifier instead of forking it, so the two syntaxes cannot disagree.
        let parameter: ParameterInput = serde_json::from_value(serde_json::json!(1e300)).unwrap();
        assert!(ParameterValue::try_from(parameter).is_err());

        let decimal: ParameterInput =
            serde_json::from_value(serde_json::json!(9_007_199_254_740_994.0_f64)).unwrap();
        let exponent: ParameterInput =
            serde_json::from_value(serde_json::json!(9.007199254740994e15)).unwrap();
        assert!(ParameterValue::try_from(decimal).is_err());
        assert!(ParameterValue::try_from(exponent).is_err());
    }

    #[test]
    fn an_invalid_connection_name_reads_as_a_missing_connection() {
        // A name that cannot exist has not been found. The alternative would tell the
        // agent about Warden's identifier charset for no operational benefit.
        let input = query_input(serde_json::json!({
            "connection": "not a name",
            "sql": "SELECT 1"
        }))
        .unwrap();
        assert_eq!(
            input.into_request().unwrap_err(),
            PublicErrorCode::ConnectionNotFound
        );
    }

    #[test]
    fn an_oversized_statement_is_refused_before_it_can_be_parsed() {
        let input = query_input(serde_json::json!({
            "connection": "db",
            "sql": "-".repeat(InputLimits::default().max_sql_bytes + 1)
        }))
        .unwrap();
        assert_eq!(
            input.into_request().unwrap_err(),
            PublicErrorCode::QueryTooLarge
        );
    }

    #[test]
    fn a_search_without_a_limit_uses_the_documented_default() {
        let input: SearchInput = serde_json::from_value(serde_json::json!({
            "connection": "db",
            "query": "customer invoice subscription"
        }))
        .unwrap();
        let request = input.into_request().unwrap();
        assert_eq!(request.limit(), DEFAULT_SEARCH_LIMIT);
        assert_eq!(request.terms().len(), 3);
    }

    #[test]
    fn describing_more_than_twenty_tables_is_refused_by_the_core_bound() {
        let tables: Vec<String> = (0..21).map(|index| format!("app.t{index}")).collect();
        let input: DescribeInput = serde_json::from_value(serde_json::json!({
            "connection": "db",
            "tables": tables
        }))
        .unwrap();
        assert_eq!(
            input.into_request().unwrap_err(),
            PublicErrorCode::SchemaLookupError
        );
    }
}
