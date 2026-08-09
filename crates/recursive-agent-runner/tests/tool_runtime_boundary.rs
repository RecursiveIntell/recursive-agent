use std::path::{Path, PathBuf};

fn rust_sources_below(root: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut pending = vec![root.to_path_buf()];
    let mut sources = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory)? {
            let path = entry?.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                sources.push(path);
            }
        }
    }
    sources.sort();
    Ok(sources)
}

#[test]
fn production_direct_tool_dispatch_has_no_legacy_escape_hatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let crates = workspace.join("crates");
    let runner = crates.join("recursive-agent-runner/src/lib.rs");
    let tools_owner = crates.join("recursive-agent-tools/src/lib.rs");
    let direct_reference = "recursive_agent_tools::execute";

    let runner_source = std::fs::read_to_string(&runner)?;
    let tools_source = std::fs::read_to_string(&tools_owner)?;
    assert!(!runner_source.contains(direct_reference));
    assert!(!tools_source.contains("pub fn execute("));

    let mut violations = Vec::new();
    for path in rust_sources_below(&crates)? {
        if path == runner
            || path == tools_owner
            || path.components().any(|part| part.as_os_str() == "tests")
        {
            continue;
        }
        let source = std::fs::read_to_string(&path)?;
        if source.contains(direct_reference)
            || (source.contains("use recursive_agent_tools") && source.contains("execute"))
        {
            violations.push(path.strip_prefix(&workspace)?.display().to_string());
        }
    }

    assert!(
        violations.is_empty(),
        "direct tool dispatch escaped RuntimeService: {violations:?}"
    );
    Ok(())
}

#[test]
fn legacy_run_spec_entrypoints_are_absent_from_the_public_runner_surface() {
    let runner = include_str!("../src/lib.rs");
    for forbidden in ["pub fn run_spec(", "pub fn run_spec_with_clock("] {
        assert!(
            !runner.contains(forbidden),
            "legacy bypass-capable runner entrypoint remains public: {forbidden}"
        );
    }
}
