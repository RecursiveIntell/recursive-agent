//! Task 6.2 — MCP strict-translation denylist (source-level RED).
//!
//! The MCP crate must be a translation edge, not an execution owner: it must
//! not directly dispatch tools, must not read wall-clock `time_now`, and must
//! not mint run ids/receipts. This test scans the crate source and fails if any
//! forbidden surface is present.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

fn crate_src(name: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("cargo manifest dir is two levels below repo root");
    let path = root.join("crates").join(name).join("src");
    let mut all = String::new();
    for entry in std::fs::read_dir(&path).expect("crate src dir exists") {
        let entry = entry.expect("dir entry");
        if entry.path().extension().and_then(|s| s.to_str()) == Some("rs") {
            all.push_str(&std::fs::read_to_string(entry.path()).expect("read src"));
        }
    }
    all
}

#[test]
fn mcp_crate_has_no_direct_tool_dispatch_or_run_id_minting() {
    let src = crate_src("recursive-agent-mcp");
    // The MCP crate must not own a ToolRegistry / tool invocation path.
    assert!(
        !src.contains("ToolRegistry::new"),
        "MCP must not construct a tool registry (direct dispatch)"
    );
    assert!(
        !src.contains("ToolRuntime::new"),
        "MCP must not own a tool runtime (direct dispatch)"
    );
    // Must not mint run ids or receipts (those belong to runtime/ledger).
    assert!(
        !src.contains("derive_run_id") && !src.contains("RuntimeService::new"),
        "MCP must not mint run ids or own the runtime"
    );
    // Must not read wall-clock time_now directly.
    assert!(
        !src.contains("Utc::now") && !src.contains("SystemTime::now"),
        "MCP must not read wall-clock time (no time_now)"
    );
}

#[test]
fn mcp_crate_translates_via_contracts_not_own_execution() {
    let src = crate_src("recursive-agent-mcp");
    // The translation path must construct a V1 envelope (contracts), not
    // execute it.
    assert!(
        src.contains("OperationEnvelopeV1"),
        "MCP translation must construct a V1 envelope"
    );
    assert!(
        !src.contains("run_spec(") && !src.contains("replay("),
        "MCP must not execute or replay runs"
    );
}
