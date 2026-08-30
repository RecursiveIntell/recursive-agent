use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn workspace() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("workspace root is unavailable")?
        .to_path_buf())
}

fn source(relative: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(std::fs::read_to_string(workspace()?.join(relative))?)
}

#[test]
fn default_production_surface_has_no_bare_effect_entrypoint() -> TestResult {
    let sandbox = source("crates/recursive-agent-sandbox/src/lib.rs")?;
    assert!(sandbox.contains("pub fn validate_plan"));
    assert!(!sandbox.contains("pub fn execute"));
    assert!(!sandbox.contains("Command::new"));
    assert!(!sandbox.contains(".spawn()"));
    assert!(!sandbox.contains("locate_fd_hygiene_launcher"));

    let policy = source("crates/recursive-agent-policy/src/lib.rs")?;
    assert!(!policy.contains("AuthorizedExecutionContext"));
    assert!(!policy.contains("consume_authorized"));

    let runner = source("crates/recursive-agent-runner/src/sandbox_engine.rs")?;
    assert!(runner.contains("pub(super) struct DispatchToken"));
    assert!(runner.contains("context: DispatchToken"));
    assert!(!runner.contains("impl Clone for DispatchToken"));
    assert!(!runner.contains("Serialize for DispatchToken"));
    assert!(!runner.contains("Deserialize for DispatchToken"));

    let provider = source("crates/recursive-agent-provider/src/lib.rs")?;
    assert!(provider.contains("pub trait CompletionBackend"));
    assert!(provider.contains("pub struct HttpCompletionBackend"));
    assert!(provider.contains("impl CompletionBackend for HttpCompletionBackend"));
    assert!(!provider.contains("complete_with_resolver"));
    let tools = source("crates/recursive-agent-tools/src/lib.rs")?;
    assert!(tools.contains("ToolError::Unavailable(call.tool.clone())"));

    let mcp = source("crates/recursive-agent-mcp/src/lib.rs")?;
    // Phase 6 explicitly authorizes the MCP strict-translation and client
    // correlation modules. The Phase-1 guard that MCP exposes no client is
    // superseded; the guard now is that MCP remains a translation/correlation
    // edge and never owns a tool runtime or execution surface (enforced by
    // crates/recursive-agent-mcp/tests/denylist.rs).
    assert!(mcp.contains("pub mod translate"));
    assert!(mcp.contains("pub mod client"));

    let daemon = source("crates/recursive-agent-daemon/src/lib.rs")?;
    assert!(!daemon.contains("pub fn start"));
    assert!(!daemon.contains("UnixListener"));
    assert!(!daemon.contains("UnixStream"));
    assert!(!daemon.contains("std::thread::spawn"));
    assert!(!daemon.contains("remove_file"));

    // Governed memory is now an explicitly admitted production capability.
    // The runtime still owns effect dispatch; this assertion only verifies
    // that memory is available as a bounded, provenance-bearing data plane.
    let memory = source("crates/recursive-agent-memory/src/lib.rs")?;
    assert!(memory.contains("pub struct MemoryStore"));
    assert!(memory.contains("pub fn search"));
    Ok(())
}
