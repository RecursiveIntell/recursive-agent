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
    let spec_path = root.path().join("direct-crash-verify.json");
    std::fs::write(&spec_path, serde_json::to_vec(&spec)?)?;
    let run_output = std::process::Command::new(env!("CARGO_BIN_EXE_ra"))
        .args(["run", "--spec"])
        .arg(&spec_path)
        .arg("--out")
        .arg(root.path())
        .output()?;
    assert!(
        run_output.status.success(),
        "{}",
        String::from_utf8_lossy(&run_output.stderr)
    );
    let summary: recursive_agent_runner::RunSummary = serde_json::from_slice(&run_output.stdout)?;
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
