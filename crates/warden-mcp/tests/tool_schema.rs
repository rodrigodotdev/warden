//! The tool contract, pinned.
//!
//! `docs/mcp.md` section 1.2 asks for this by name: without snapshots the evolution rules
//! in section 4 are unenforceable, and a renamed field or a widened schema reaches agents
//! as a silent breaking change. This test writes no fixture on its own — a diff here is a
//! contract change and belongs in the pull request that made it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

use rmcp::model::Tool;
use warden_mcp::WardenServer;

/// The five tool descriptors, already sorted by name: `ToolRouter::list_all` sorts them
/// itself, so this is a documented name for that call rather than a second sort.
fn sorted_tools() -> Vec<Tool> {
    WardenServer::tool_router().list_all()
}

/// One tool's description, or a panic naming the tool if it does not exist — every
/// caller here names one of the five documented tools, so a miss is a test bug.
fn description_of(name: &str) -> String {
    sorted_tools()
        .into_iter()
        .find(|tool| tool.name == name)
        .unwrap_or_else(|| panic!("no such tool: {name}"))
        .description
        .map(|description| description.into_owned())
        .unwrap_or_default()
}

fn snapshot_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots/tools.json")
}

/// The stable JSON document this test pins: the five tools, sorted by name, pretty
/// printed. `Tool` derives `Serialize`, so this is the SDK's own wire representation,
/// not a hand-maintained mirror of it.
fn rendered_snapshot() -> String {
    serde_json::to_string_pretty(&sorted_tools()).expect("tool descriptors must serialize")
}

const CONTRACT_CHANGED_INSTRUCTION: &str = "\
The MCP tool contract changed. Tool schemas are user-facing contracts from the first \
release (SPEC section 10) and change cautiously (docs/mcp.md section 4): prefer additive \
optional fields, and treat a removal or a rename as a versioning decision. If the change \
is intended, update tests/snapshots/tools.json in the same commit so the diff is reviewable.";

/// Regenerate with `UPDATE_SNAPSHOTS=1 cargo test -p warden-mcp --test tool_schema`.
///
/// Gated on the environment variable so CI can never rewrite the fixture it exists to
/// enforce: a run without the variable can only compare, never overwrite.
#[test]
fn the_tool_contract_matches_the_committed_snapshot() {
    let rendered = rendered_snapshot();

    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        fs::write(snapshot_path(), format!("{rendered}\n")).unwrap_or_else(|error| {
            panic!("could not write {}: {error}", snapshot_path().display())
        });
        return;
    }

    let committed = fs::read_to_string(snapshot_path()).unwrap_or_else(|error| {
        panic!(
            "could not read {}: {error}\n\nRun `UPDATE_SNAPSHOTS=1 cargo test -p warden-mcp \
             --test tool_schema` to generate it.",
            snapshot_path().display()
        )
    });

    // assert_eq! prints both sides on failure; the message adds the instruction for what
    // to do about it. The committed file always ends with a trailing newline (written
    // above); `rendered` never does, so compare with it trimmed rather than requiring
    // one side to carry a newline the other cannot.
    assert_eq!(
        rendered,
        committed.trim_end(),
        "\n{CONTRACT_CHANGED_INSTRUCTION}"
    );
}

/// docs/mcp.md section 1.1. These five lines declare read-only behavior in the
/// protocol rather than only in prose, and some clients decide whether to ask the
/// user for confirmation from them.
#[test]
fn every_tool_declares_the_documented_annotations() {
    for tool in sorted_tools() {
        let annotations = tool
            .annotations
            .as_ref()
            .unwrap_or_else(|| panic!("{} has no annotations", tool.name));
        assert_eq!(annotations.read_only_hint, Some(true), "{}", tool.name);
        assert_eq!(annotations.destructive_hint, Some(false), "{}", tool.name);
        assert_eq!(
            annotations.idempotent_hint,
            Some(tool.name != "query"),
            "{}",
            tool.name
        );
    }
}

#[test]
fn every_tool_declares_an_output_schema_and_a_description() {
    for tool in sorted_tools() {
        assert!(
            tool.output_schema.is_some(),
            "{} has no output schema",
            tool.name
        );
        let description = tool.description.as_deref().unwrap_or_default();
        assert!(
            description.len() > 80,
            "{} has a stub description",
            tool.name
        );
    }
}

/// `docs/mcp.md` section 1.3: each description carries a specific obligation, not just
/// prose of some length.
#[test]
fn each_description_carries_the_obligation_docs_mcp_section_1_3_puts_on_it() {
    for (tool, required) in [
        ("query", &["SELECT", "?", "$1", "truncated"][..]),
        ("search_schema", &["before"][..]),
        ("describe_schema", &["20"][..]),
        ("explain", &["without executing"][..]),
        ("list_connections", &["dialect", "placeholder"][..]),
    ] {
        let description = description_of(tool);
        for phrase in required {
            assert!(
                description.contains(phrase),
                "{tool}'s description does not communicate {phrase:?}: {description}"
            );
        }
    }
}
