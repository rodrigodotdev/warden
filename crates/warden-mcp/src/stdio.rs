//! Serving MCP over stdio.
//!
//! stdout carries protocol data and nothing else (`docs/mcp.md` section 5.1). Two
//! mechanisms keep that true and neither is a convention: `clippy::print_stdout = "deny"`
//! makes a stray `println!` a build failure, and this module is the only place in the
//! workspace that touches the process's stdout handle. Logging goes to stderr, and the
//! server prints no banner.
//!
//! Shutdown has two triggers. `stdin` reaching EOF means the client is gone, which is the
//! ordinary end of a local session. The cancellation token means the process was asked to
//! stop; `rmcp`'s `serve_with_ct` already threads it through the service loop, so an
//! in-flight request sees the same root token every service child token descends from.

use rmcp::service::ServerInitializeError;
use rmcp::transport::IntoTransport;
use rmcp::{RoleServer, ServiceExt};
use tokio_util::sync::CancellationToken;

use crate::server::WardenServer;

/// Why a stdio session could not start or could not be shut down.
///
/// An operator-facing startup and teardown error, deliberately not a
/// [`warden_core::error::PublicError`]: no tool response can reach it, so it carries the
/// SDK's own message for the terminal rather than a code for the agent.
#[derive(Debug, thiserror::Error)]
pub enum StdioError {
    /// The initialize handshake never completed, so no session ever ran.
    #[error("the MCP session could not start: {0}")]
    Start(String),
    /// The session task itself was lost — it panicked or was aborted mid-loop.
    #[error("the MCP session did not shut down cleanly: {0}")]
    Shutdown(String),
}

/// Serves the five tools over the process's stdin and stdout until EOF or cancellation.
///
/// # Errors
///
/// Returns [`StdioError`] when the handshake fails on the transport or the service task is
/// lost. A cancelled token is not an error: it is how the process is asked to stop.
pub async fn serve_stdio(
    server: WardenServer,
    shutdown: CancellationToken,
) -> Result<(), StdioError> {
    serve(server, rmcp::transport::stdio(), shutdown).await
}

/// Serves the same session over an in-memory duplex stream.
///
/// Splitting this from [`serve_stdio`] is what makes the transport testable without
/// touching the process's real descriptors; [`serve_stdio`] is the one-line production
/// caller that passes `rmcp::transport::stdio()` instead.
#[cfg(test)]
async fn serve_duplex<S>(
    server: WardenServer,
    stream: S,
    shutdown: CancellationToken,
) -> Result<(), StdioError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
{
    serve(server, stream, shutdown).await
}

/// Runs one session on `transport`, ending on EOF or on the root cancellation token.
async fn serve<T, E, A>(
    server: WardenServer,
    transport: T,
    shutdown: CancellationToken,
) -> Result<(), StdioError>
where
    T: IntoTransport<RoleServer, E, A>,
    E: std::error::Error + Send + Sync + 'static,
{
    let service = match server.serve_with_ct(transport, shutdown).await {
        Ok(service) => service,
        // Cancelled before any client initialized: the process was asked to stop, which is
        // a shutdown and not a startup failure. `rmcp` reports it on the same channel as a
        // broken handshake, and only here is it distinguished from one.
        Err(ServerInitializeError::Cancelled) => return Ok(()),
        Err(cause) => return Err(StdioError::Start(cause.to_string())),
    };
    let reason = service
        .waiting()
        .await
        .map_err(|join| StdioError::Shutdown(join.to_string()))?;
    // stderr, never stdout, and a quit reason carries no request data.
    tracing::debug!(target: "warden.mcp", ?reason, "the MCP session ended");
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::time::Duration;

    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::server::WardenServer;
    use crate::testing;

    #[tokio::test(start_paused = true)]
    async fn a_cancelled_token_ends_the_service_without_waiting_for_eof() {
        // stdin never closes in this test; only the token ends it. The binary relies on
        // this for signal-driven shutdown (`docs/architecture.md` section 13).
        let shutdown = CancellationToken::new();
        let (server_side, _client_side) = tokio::io::duplex(4096);
        let server = WardenServer::new(testing::services());
        let handle = tokio::spawn(serve_duplex(server, server_side, shutdown.clone()));
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("serving did not stop within five seconds of cancellation")
            .expect("the serving task panicked")
            .expect("serving returned an error");
    }
}
