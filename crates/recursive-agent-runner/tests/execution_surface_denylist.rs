//! Task 6.5 — public direct-execution surface inventory.
//!
//! This test is deliberately source-level: an adapter or downstream crate must
//! not regain a supported execution path by calling an old public convenience
//! function. Native execution is admitted only through `RuntimeService`.

use std::path::Path;

fn source(workspace: &Path, crate_name: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(std::fs::read_to_string(
        workspace.join("crates").join(crate_name).join("src/lib.rs"),
    )?)
}

#[test]
fn public_direct_execution_surfaces_are_removed_after_runtime_migration(
) -> Result<(), Box<dyn std::error::Error>> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runner = source(&workspace, "recursive-agent-runner")?;
    let tools = source(&workspace, "recursive-agent-tools")?;

    let violations = [
        (
            "recursive-agent-runner::run_spec",
            runner.contains("pub fn run_spec("),
        ),
        (
            "recursive-agent-runner::run_spec_with_clock",
            runner.contains("pub fn run_spec_with_clock("),
        ),
        (
            "recursive-agent-tools::execute",
            tools.contains("pub fn execute("),
        ),
    ]
    .into_iter()
    .filter_map(|(surface, present)| present.then_some(surface))
    .collect::<Vec<_>>();

    assert!(
        violations.is_empty(),
        "public bypass-capable execution surfaces remain: {violations:?}; use RuntimeService::submit"
    );
    Ok(())
}
