//! The one place an internal failure becomes something a model may see.
//!
//! `docs/security.md` section 10 fixes a closed set of fourteen codes and says raw SQLx
//! errors — which can carry hostnames, users, database names, SQL, and server details —
//! must never reach the model. Every service error already knows its own
//! [`warden_core::error::PublicErrorCode`], so this module takes a *code* and never a
//! message: there is no parameter here that a driver string could be passed through.
//!
//! # Why a failure is a result rather than a JSON-RPC error
//!
//! A denied statement, a busy connection, and a truncated-too-large result are things the
//! agent should read and act on — refine the query, retry shortly, narrow the projection.
//! MCP carries those as a tool result with `is_error`, leaving JSON-RPC errors for
//! protocol faults, which is what rmcp itself does for malformed arguments and an
//! unsupported protocol version.
//!
//! # Why this result repeats itself and a successful one does not
//!
//! ADR-0040 keeps database rows out of the free-text channel. An error payload is a fixed
//! code and a fixed sentence — no database content at all — so repeating it in a text
//! block costs nothing and helps a client that reads only text.
//!
//! `failure` and `public_message` have no live caller yet. `output.rs`'s
//! `ToolResponse::into_result` already calls `failure` in its serialization-failure
//! branch, but `ToolResponse` itself is not wired into any tool method until Task 5, so
//! the call is not yet reachable either. Each function below carries its own
//! `#[expect(dead_code, ..)]` rather than a module-wide allow, so the moment Task 5 wires
//! one in, the unfulfilled expectation fails the `-D warnings` gate and forces its
//! removal.

use rmcp::model::CallToolResult;
use warden_core::error::PublicErrorCode;

/// Builds the failed result for one public code.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "reachable once Task 5 wires ToolResponse into a #[tool] method"
    )
)]
pub(crate) fn failure(code: PublicErrorCode) -> CallToolResult {
    CallToolResult::structured_error(serde_json::json!({
        "error": { "code": code.as_str(), "message": public_message(code) }
    }))
}

/// The fixed sentence that accompanies each code.
///
/// The match is exhaustive with no wildcard: a new code must not compile until someone has
/// written the sentence an agent will read (ADR-0021).
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "reachable once Task 5 wires ToolResponse into a #[tool] method, via failure"
    )
)]
pub(crate) fn public_message(code: PublicErrorCode) -> &'static str {
    match code {
        PublicErrorCode::ConnectionNotFound => {
            "no connection with that name is configured; call list_connections"
        }
        PublicErrorCode::ConnectionUnavailable => {
            "the connection is configured but cannot serve requests right now"
        }
        PublicErrorCode::QueryTooLarge => {
            "the statement or its parameter list exceeds the accepted size"
        }
        PublicErrorCode::QueryParseError => {
            "the statement could not be parsed in this connection's dialect"
        }
        PublicErrorCode::QueryRejected => "policy denied this statement; it was not executed",
        PublicErrorCode::ServerBusy => "this connection is at its concurrency limit; retry shortly",
        PublicErrorCode::QueryTimeout => {
            "the statement exceeded its deadline; narrow it or add a filter"
        }
        PublicErrorCode::QueryCancelled => "the statement was cancelled",
        PublicErrorCode::QueryResultTooLarge => {
            "the result exceeds the byte budget; select fewer columns or rows"
        }
        PublicErrorCode::QueryNormalizationError => {
            "a value has no safe representation; cast it explicitly, for example to text"
        }
        PublicErrorCode::QueryExecutionError => "the database rejected or failed the statement",
        PublicErrorCode::SchemaLookupError => "schema metadata could not be read",
        PublicErrorCode::ExplainError => "a plan could not be produced for this statement",
        PublicErrorCode::InternalError => "an internal error occurred",
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn every_public_code_has_a_failure_result_that_names_it() {
        for code in PublicErrorCode::ALL {
            let result = failure(code);
            assert_eq!(result.is_error, Some(true), "{code}");
            let content = result.structured_content.clone().unwrap();
            assert_eq!(content["error"]["code"], serde_json::json!(code.as_str()));
            assert!(
                content["error"]["message"]
                    .as_str()
                    .is_some_and(|m| !m.is_empty()),
                "{code} has no message"
            );
        }
    }

    #[test]
    fn no_public_message_carries_anything_but_fixed_text() {
        // docs/security.md section 10: the model receives one of these codes and
        // fixed-table text. A message with a placeholder is a message that will one day
        // be filled with a hostname.
        for code in PublicErrorCode::ALL {
            let message = public_message(code);
            for forbidden in ['{', '}', '%'] {
                assert!(!message.contains(forbidden), "{code}: {message}");
            }
            assert!(message.is_ascii(), "{code}: {message}");
        }
    }

    #[test]
    fn a_failure_result_carries_its_text_as_well_as_its_structure() {
        // The one place a text block repeats the structured payload, and it is safe
        // because the payload is a fixed code and fixed text, never database content
        // (ADR-0040 states the asymmetry).
        let result = failure(PublicErrorCode::QueryRejected);
        assert_eq!(result.content.len(), 1);
        assert!(
            serde_json::to_string(&result.content[0])
                .unwrap()
                .contains("query_rejected")
        );
    }
}
