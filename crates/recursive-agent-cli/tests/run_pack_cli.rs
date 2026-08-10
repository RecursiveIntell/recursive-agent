//! Task 7 — the CLI renders owner results for portable Run Packs; it owns no
//! receipt, manifest, verification, or replay semantics.

use std::process::Command;

use recursive_agent_contracts::{RunSpecV1, StepSpecV1, ToolCallSpecV1};
use recursive_agent_runner::RunSummary;

use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn run_terminal_echo(root: &std::path::Path) -> TestResult<RunSummary> {
    let spec = RunSpecV1 {
        name: "run-pack-cli".into(),
        steps: vec![StepSpecV1 {
            name: "echo".into(),
            call: ToolCallSpecV1 {
                tool: "echo".into(),
                args: serde_json::json!({"text": "portable"}),
                frozen_clock: None,
            },
        }],
        frozen_clock: None,
        policy_version: "m0-2".into(),
    };
    let spec_path = root.join("spec.json");
    std::fs::write(&spec_path, serde_json::to_vec(&spec)?)?;
    let output = Command::new(env!("CARGO_BIN_EXE_ra"))
        .args(["run", "--spec"])
        .arg(spec_path)
        .arg("--out")
        .arg(root.join("runs"))
        .output()?;
    assert!(
        output.status.success(),
        "run stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn json_output(output: &std::process::Output) -> TestResult<Value> {
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[test]
fn pack_export_verify_and_replay_render_authoritative_pack_results() -> TestResult {
    let root = tempfile::tempdir()?;
    let run = run_terminal_echo(root.path())?;
    let pack = root.path().join("pack");

    let export = Command::new(env!("CARGO_BIN_EXE_ra"))
        .args(["pack", "export", "--run"])
        .arg(&run.run_dir)
        .arg("--out")
        .arg(&pack)
        .output()?;
    let exported = json_output(&export)?;
    assert_eq!(exported["pack_path"], pack.to_string_lossy().as_ref());
    assert_eq!(exported["schema_version"], 1);
    assert!(exported["manifest_digest"].as_str().is_some());
    assert_eq!(exported["manifest_ref"], "PACK_MANIFEST.json");

    let verified = Command::new(env!("CARGO_BIN_EXE_ra"))
        .args(["pack", "verify", "--pack"])
        .arg(&pack)
        .output()?;
    let verified = json_output(&verified)?;
    assert_eq!(verified["ok"], true);
    assert_eq!(verified["schema_version"], 1);

    let replayed = Command::new(env!("CARGO_BIN_EXE_ra"))
        .args(["pack", "replay", "--pack"])
        .arg(&pack)
        .output()?;
    let replayed = json_output(&replayed)?;
    assert_eq!(replayed["mode"], "recorded_evidence");
    assert_eq!(replayed["source_run_id"], run.run_id.to_string());
    assert_eq!(replayed["verification_manifest_ref"], "PACK_MANIFEST.json");

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let aliased_run = root.path().join("run-alias");
        symlink(&run.run_dir, &aliased_run)?;
        let output = Command::new(env!("CARGO_BIN_EXE_ra"))
            .args(["pack", "export", "--run"])
            .arg(&aliased_run)
            .arg("--out")
            .arg(root.path().join("aliased-pack"))
            .output()?;
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).starts_with("pack export: ERROR:"));
    }
    Ok(())
}

#[test]
fn pack_verify_and_replay_reject_tampering_with_typed_stderr() -> TestResult {
    let root = tempfile::tempdir()?;
    let run = run_terminal_echo(root.path())?;
    let pack = root.path().join("pack");
    let export = Command::new(env!("CARGO_BIN_EXE_ra"))
        .args(["pack", "export", "--run"])
        .arg(&run.run_dir)
        .arg("--out")
        .arg(&pack)
        .output()?;
    json_output(&export)?;
    std::fs::write(pack.join("receipts.ndjson"), b"tampered\n")?;

    for verb in ["verify", "replay"] {
        let output = Command::new(env!("CARGO_BIN_EXE_ra"))
            .args(["pack", verb, "--pack"])
            .arg(&pack)
            .output()?;
        assert!(
            !output.status.success(),
            "pack {verb} unexpectedly succeeded"
        );
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr).starts_with(&format!("pack {verb}: ERROR:")),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}
