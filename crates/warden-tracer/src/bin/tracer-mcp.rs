//! DISPOSABLE—see the `warden-tracer` crate documentation.
//!
//! An MCP stdio server with one constant-returning tool, used before Milestone 12 to
//! verify that rmcp macros work on this toolchain, stdout remains protocol-only, and
//! the process exits cleanly when stdin closes.

use rmcp::{ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use warden_tracer::TRACER_TOOL_RESULT;

#[derive(Debug, Clone)]
struct TracerServer;

#[tool_router]
impl TracerServer {
    #[tool(description = "Returns a constant to validate the MCP handshake.")]
    async fn tracer_ping(&self) -> String {
        TRACER_TOOL_RESULT.to_owned()
    }
}

#[tool_handler(name = "warden-tracer", version = "0.0.0")]
impl ServerHandler for TracerServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A tracing subscriber added here must write only to stderr; stdout carries MCP.
    let service = TracerServer.serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
