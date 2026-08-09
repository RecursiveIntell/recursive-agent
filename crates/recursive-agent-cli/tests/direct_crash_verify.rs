#![allow(deprecated)]

use recursive_agent_contracts::{RunSpecV1, StepSpecV1, ToolCallSpecV1};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn ra_verify_directly_reconciles_stale_metadata_projection() -> TestResult {
    let root = tempfile::tempdir()?;
    let spec = RunSpecV1 {
        name: "direct-crash-verify".into(),
        steps: vec![StepSpecV1 {
            name: "echo".into(),
            call: ToolCallSpecV1 {
                tool: "echo".into(),
                args: serde_json::json!({"text": "verified"}),
                frozen_clock: None,
            },
        }],
        frozen_clock: None,
        policy_version: "m0-2".into(),
    };
    let summary = recursive_agent_runner::run_spec(&spec, root.path())?;
    std::fs::write(summary.run_dir.join("chain.meta"), br#"{"head":"partial"}"#)?;
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ra"))
        .args(["verify", "--run"])
        .arg(&summary.run_dir)
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8(output.stdout)?.contains("verify: ok"));
    Ok(())
}
