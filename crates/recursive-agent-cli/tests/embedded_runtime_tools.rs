use std::process::Command;

use recursive_agent_ledger::{verify_directory_bound, RunPaths};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn embedded_cli_runs_the_advertised_frozen_time_tool() -> TestResult {
    let root = tempfile::tempdir()?;
    let spec_path = root.path().join("frozen-time.json");
    let runs = root.path().join("runs");
    std::fs::write(
        &spec_path,
        serde_json::to_vec(&serde_json::json!({
            "name": "embedded-frozen-time",
            "policy_version": "m0-2",
            "frozen_clock": "2026-07-14T00:00:00Z",
            "steps": [
                {
                    "name": "echo",
                    "call": {"tool": "echo", "args": {"text": "hello"}}
                },
                {
                    "name": "frozen-time",
                    "call": {
                        "tool": "time_now",
                        "args": {"label": "fixture"},
                        "frozen_clock": "2026-07-14T00:00:00Z"
                    }
                }
            ]
        }))?,
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_ra"))
        .args(["run", "--spec"])
        .arg(&spec_path)
        .arg("--out")
        .arg(&runs)
        .output()?;
    assert!(
        output.status.success(),
        "embedded CLI rejected its advertised time_now tool; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: recursive_agent_runner::RunSummary = serde_json::from_slice(&output.stdout)?;
    let verified = verify_directory_bound(&RunPaths::new(&summary.run_dir))?;
    assert!(verified.ok);

    let artifact_text = std::fs::read_dir(summary.run_dir.join("artifacts"))?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            if entry.path().extension().is_some() {
                return None;
            }
            std::fs::read(entry.path())
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        artifact_text.contains("\"timestamp\":\"2026-07-14T00:00:00+00:00\""),
        "stored artifacts omitted frozen timestamp"
    );
    assert!(
        artifact_text.contains("\"label\":\"fixture\""),
        "stored artifacts omitted time label"
    );
    Ok(())
}
