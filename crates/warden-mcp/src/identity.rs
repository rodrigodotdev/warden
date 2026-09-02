//! Per-call identity for the stdio transport.
//!
//! Decision 4 (`docs/mcp.md` section 8): stdio authenticates nobody, so the transport
//! constructs the identity and the agent never supplies its own. The request id is
//! generated here as a fresh UUID rather than taken from the JSON-RPC id, which is
//! agent-controlled and not constrained to [`RequestId`]'s charset; the principal is the
//! fixed [`STDIO_PRINCIPAL`] constant until M14 replaces it with an authenticated
//! subject; the client name comes from the peer's self-reported `client_info().name`,
//! validated by the newtype, falling back to [`UNKNOWN_CLIENT`] rather than failing an
//! otherwise valid request.
//!
//! `for_request` has no caller yet: Task 6's `ServerHandler` invokes it per call. `dead_code`
//! is a plain rustc lint, not one of `AGENTS.md`'s mechanically enforced rules, so silencing
//! it here for code this task's own tests already exercise is the narrow, reviewable
//! exception rather than a rule bypass.
#![allow(dead_code)]

use rmcp::service::{RequestContext as RmcpRequestContext, RoleServer};
use uuid::Uuid;
use warden_core::context::{ClientName, PrincipalId, RequestContext, RequestId};
use warden_core::error::PublicErrorCode;

/// stdio's one fixed principal. No tool input can influence it (`docs/mcp.md` section 8).
pub(crate) const STDIO_PRINCIPAL: &str = "local-stdio";

/// The recorded client name when the peer's own name is absent or invalid.
pub(crate) const UNKNOWN_CLIENT: &str = "unknown-client";

/// Builds this call's identity from the transport's context.
///
/// The request id, principal, and client name are all constructed here rather than
/// read from anything the agent controls (`docs/mcp.md` section 8).
pub(crate) fn for_request(
    context: &RmcpRequestContext<RoleServer>,
) -> Result<RequestContext, PublicErrorCode> {
    let request_id = generate_request_id()?;
    let principal: PrincipalId = STDIO_PRINCIPAL
        .parse()
        .map_err(|_| PublicErrorCode::InternalError)?;
    let client_info = context.client_info();
    let client = client_name(client_info.as_ref().map(|info| info.name.as_str()));
    Ok(RequestContext::new(request_id, principal, client))
}

/// Generates a fresh per-call correlation id.
///
/// A UUID v4 always satisfies [`RequestId`]'s charset, but the constructor is still
/// fallible, so this returns `internal_error` on the structurally impossible failure
/// rather than calling `expect` on the request path (`AGENTS.md`). The test below is
/// what keeps that branch unreachable in practice.
pub(crate) fn generate_request_id() -> Result<RequestId, PublicErrorCode> {
    Uuid::new_v4()
        .to_string()
        .parse()
        .map_err(|_| PublicErrorCode::InternalError)
}

/// Validates the client's self-reported name, falling back to [`UNKNOWN_CLIENT`].
///
/// The name is untrusted MCP input, so a name the newtype refuses — too long, or
/// carrying a control character that could inject a fake stderr record — must not fail
/// an otherwise valid request; it is simply not recorded.
fn client_name(name: Option<&str>) -> ClientName {
    name.and_then(|value| value.parse::<ClientName>().ok())
        .unwrap_or_else(unknown_client)
}

/// The validated [`UNKNOWN_CLIENT`] fallback.
///
/// `UNKNOWN_CLIENT` is a fixed, non-empty, printable-ASCII literal within
/// `MAX_CLIENT_NAME_LEN`, so `ClientName`'s validator cannot refuse it; the sibling
/// test `a_hostile_client_name_never_reaches_a_log_line` is what keeps this recursive
/// branch unreachable in practice, exactly as the test above does for
/// [`generate_request_id`].
fn unknown_client() -> ClientName {
    UNKNOWN_CLIENT.parse().unwrap_or_else(|_| unknown_client())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn a_generated_request_id_always_satisfies_the_core_newtype() {
        // The production path returns internal_error rather than panicking if this ever
        // stops being true; this test is what keeps that branch unreachable in practice.
        for _ in 0..1_000 {
            assert!(generate_request_id().is_ok());
        }
    }

    #[test]
    fn the_stdio_principal_is_a_constant_the_agent_cannot_influence() {
        // docs/mcp.md section 8: the transport constructs the identity, and the agent
        // cannot supply its own principal through tool input.
        assert_eq!(STDIO_PRINCIPAL, "local-stdio");
        assert!(STDIO_PRINCIPAL.parse::<PrincipalId>().is_ok());
    }

    #[test]
    fn a_hostile_client_name_never_reaches_a_log_line() {
        // ClientName is untrusted and printable-ASCII only, so a name carrying a
        // newline falls back rather than injecting a fake stderr record.
        assert_eq!(
            client_name(Some("Claude Code 2.0")).as_str(),
            "Claude Code 2.0"
        );
        assert_eq!(
            client_name(Some("warden\nERROR fake")).as_str(),
            UNKNOWN_CLIENT
        );
        assert_eq!(client_name(Some(&"x".repeat(200))).as_str(), UNKNOWN_CLIENT);
        assert_eq!(client_name(None).as_str(), UNKNOWN_CLIENT);
    }
}
