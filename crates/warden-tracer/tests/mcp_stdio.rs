//! Tracer MCP server E2E tests using a subprocess and raw JSON-RPC.
//!
//! These deliberately avoid rmcp's client so every byte written to the descriptor is
//! under test.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use warden_tracer::{TRACER_TOOL_NAME, TRACER_TOOL_RESULT};

/// Protocol version documented in the `docs/mcp.md` preamble.
const PROTOCOL_VERSION: &str = "2026-07-28";

/// Sends requests, closes stdin, and returns `(stdout, stderr)`.
async fn exchange(requests: &[Value]) -> (String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tracer-mcp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Reap the process if timeout drops the consuming `wait_with_output` future.
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start tracer-mcp");

    let mut stdin = child.stdin.take().expect("stdin unavailable");
    for request in requests {
        let line = format!("{}\n", serde_json::to_string(request).unwrap());
        stdin.write_all(line.as_bytes()).await.unwrap();
    }
    stdin.flush().await.unwrap();
    drop(stdin); // The server should exit on EOF.

    let output = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output())
        .await
        .expect("server did not exit within 20 seconds of stdin EOF")
        .expect("failed to collect process output");

    (
        String::from_utf8(output.stdout).expect("stdout is not UTF-8"),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// rmcp's `LATEST`, used as the silent fallback for an unknown protocol version.
const RMCP_LATEST_VERSION: &str = "2025-11-25";

fn initialize() -> Value {
    initialize_with_version(PROTOCOL_VERSION)
}

fn initialize_with_version(version: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": { "name": "warden-tracer-test", "version": "0.0.0" }
        }
    })
}

fn initialized() -> Value {
    json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
}

/// Parses stdout while enforcing the protocol-only invariant on every line.
fn parse_stdout(stdout: &str) -> Vec<Value> {
    stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let value: Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("stdout contains a non-JSON-RPC line ({e}): {line:?}"));
            assert_eq!(
                value["jsonrpc"], "2.0",
                "stdout line has no jsonrpc field: {line:?}"
            );
            value
        })
        .collect()
}

#[tokio::test]
async fn initializes_and_reports_tools_capability() {
    let (stdout, stderr) = exchange(&[initialize()]).await;
    let messages = parse_stdout(&stdout);

    let response = messages
        .iter()
        .find(|m| m["id"] == 1)
        .unwrap_or_else(|| panic!("no initialize response; stdout={stdout:?} stderr={stderr:?}"));

    assert!(
        response["error"].is_null(),
        "initialize returned an error: {response}"
    );
    assert!(
        !response["result"]["capabilities"]["tools"].is_null(),
        "server did not advertise tools capability: {response}"
    );

    // Guard the negotiation behavior measured in M0.5 against silent SDK changes.
    assert_eq!(
        response["result"]["protocolVersion"], PROTOCOL_VERSION,
        "server did not echo the requested version: {response}"
    );
}

#[tokio::test]
async fn unsupported_protocol_version_is_silently_substituted() {
    // rmcp silently substitutes `LATEST` for unsupported versions. A failure means
    // negotiation changed and `docs/mcp.md` must be reviewed.
    let (stdout, stderr) = exchange(&[initialize_with_version("1999-01-01")]).await;
    let messages = parse_stdout(&stdout);

    let response = messages
        .iter()
        .find(|m| m["id"] == 1)
        .unwrap_or_else(|| panic!("no initialize response; stdout={stdout:?} stderr={stderr:?}"));

    assert!(
        response["error"].is_null(),
        "initialize rejected an unknown version instead of silently substituting; \
         negotiation changed. Full response: {response}"
    );
    assert_eq!(
        response["result"]["protocolVersion"], RMCP_LATEST_VERSION,
        "expected the M0.5 silent substitution with LATEST ({RMCP_LATEST_VERSION}), \
         but the server negotiated another version. Review docs/mcp.md. \
         Full response: {response}"
    );
}

#[tokio::test]
async fn lists_the_single_tracer_tool() {
    let (stdout, _) = exchange(&[
        initialize(),
        initialized(),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
    ])
    .await;

    let messages = parse_stdout(&stdout);
    let response = messages
        .iter()
        .find(|m| m["id"] == 2)
        .expect("no response to tools/list");
    let tools = response["result"]["tools"]
        .as_array()
        .expect("tools array missing");

    assert_eq!(tools.len(), 1, "expected exactly one tool: {tools:?}");
    assert_eq!(tools[0]["name"], TRACER_TOOL_NAME);
    assert!(
        !tools[0]["inputSchema"].is_null(),
        "tool has no inputSchema; rmcp's `schemars` feature may be inactive: {:?}",
        tools[0]
    );
}

#[tokio::test]
async fn calls_the_tool_and_gets_the_constant_back() {
    let (stdout, _) = exchange(&[
        initialize(),
        initialized(),
        json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": { "name": TRACER_TOOL_NAME, "arguments": {} }
        }),
    ])
    .await;

    let messages = parse_stdout(&stdout);
    let response = messages
        .iter()
        .find(|m| m["id"] == 3)
        .expect("no response to tools/call");

    assert!(
        response["error"].is_null(),
        "tools/call returned an error: {response}"
    );
    assert!(
        serde_json::to_string(&response["result"])
            .unwrap()
            .contains(TRACER_TOOL_RESULT),
        "result does not contain the constant: {response}"
    );
}

#[tokio::test]
async fn stdout_carries_nothing_but_protocol() {
    // `parse_stdout` rejects any banner, log, or warning that corrupts the transport.
    let (stdout, _) = exchange(&[initialize(), initialized()]).await;
    let messages = parse_stdout(&stdout);
    assert!(
        !messages.is_empty(),
        "stdout is empty; the server returned no response"
    );
}
