#[test]
fn default_phase_one_sources_expose_no_later_phase_execution_adapter() {
    let workspace = include_str!("../../../Cargo.toml");
    let mcp_lib = include_str!("../../recursive-agent-mcp/src/lib.rs");
    let mcp_server = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../recursive-agent-mcp/src/server.rs");
    let daemon_manifest = include_str!("../../recursive-agent-daemon/Cargo.toml");
    let daemon_server = include_str!("../../recursive-agent-daemon/src/server.rs");
    let skills = include_str!("../../recursive-agent-skills/src/lib.rs");
    let selector = include_str!("../../recursive-agent-mcts/src/lib.rs");

    assert!(!mcp_lib.contains("pub mod server"));
    assert!(!mcp_server.exists());

    // Phase 3 wires the daemon to the canonical `RuntimeService` over
    // authenticated native IPC. The daemon translates admitted frames to
    // runtime calls; it must not become an execution, scheduler, or run-root
    // owner itself.
    assert!(daemon_manifest.contains("recursive-agent-runner"));
    assert!(daemon_manifest.contains("recursive-agent-ledger"));
    assert!(daemon_server.contains("recursive_agent_runner"));
    assert!(!daemon_server.contains("runs_root"));

    // The autonomous planner/selector lane is now explicitly admitted. The
    // old phase-one quarantine marker is intentionally no longer required.
    assert!(skills.contains("pub struct SkillRegistry"));
    assert!(selector.contains("pub struct McstSearch"));
    assert!(workspace.contains("recursive-agent-mcp"));
}

#[test]
fn cli_operator_surface_remains_exactly_phase_one() {
    let cli = include_str!("../../recursive-agent-cli/src/main.rs");
    for forbidden in ["Serve", "McpServe", "Daemon", "Skill", "Delegate", "Mcts"] {
        assert!(!cli.contains(forbidden), "CLI exposed {forbidden}");
    }
    for required in ["Doctor", "Run", "Verify", "Replay"] {
        assert!(cli.contains(required), "CLI lost {required}");
    }
}
