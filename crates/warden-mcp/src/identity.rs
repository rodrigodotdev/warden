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
//! [`for_request`] is called by every one of `server.rs`'s five `#[tool]` methods, and
//! everything else here exists to serve it.

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
    let client = client_name(client_info.as_ref().map(|info| info.name.as_str()))?;
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
/// an otherwise valid request; [`UNKNOWN_CLIENT`] is recorded instead. The fallback
/// conversion is itself fallible in principle (`UNKNOWN_CLIENT`'s validation could stop
/// holding), so this returns `Result` rather than looping or recursing to manufacture a
/// value with no failure path — the same `internal_error`-on-impossible-failure shape
/// [`generate_request_id`] uses, and composes into [`for_request`] with one `?`.
fn client_name(name: Option<&str>) -> Result<ClientName, PublicErrorCode> {
    match name.and_then(|value| value.parse::<ClientName>().ok()) {
        Some(client) => Ok(client),
        None => UNKNOWN_CLIENT
            .parse()
            .map_err(|_| PublicErrorCode::InternalError),
    }
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
        // newline falls back rather than injecting a fake stderr record. The fallback
        // itself always succeeds (proved here 1,000 times over, mirroring the
        // generate_request_id test above), which is what keeps client_name's own
        // internal_error branch unreachable in practice.
        assert_eq!(
            client_name(Some("Claude Code 2.0")).unwrap().as_str(),
            "Claude Code 2.0"
        );
        assert_eq!(
            client_name(Some("warden\nERROR fake")).unwrap().as_str(),
            UNKNOWN_CLIENT
        );
        assert_eq!(
            client_name(Some(&"x".repeat(200))).unwrap().as_str(),
            UNKNOWN_CLIENT
        );
        assert_eq!(client_name(None).unwrap().as_str(), UNKNOWN_CLIENT);
    }

    #[test]
    fn the_unknown_client_fallback_always_succeeds() {
        // client_name's fallback conversion is fallible in principle; this is what
        // keeps its internal_error branch unreachable in practice, exactly as the
        // generate_request_id test above does for that function's own guard.
        for _ in 0..1_000 {
            assert!(client_name(None).is_ok());
        }
    }
}
