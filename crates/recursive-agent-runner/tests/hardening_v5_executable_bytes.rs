mod support;

use recursive_agent_contracts::{RunSpecV1, RunTerminalStateV1, StepSpecV1, ToolCallSpecV1};
use recursive_agent_ledger::{open, verified_snapshot_directory_bound, RunPaths};
use recursive_agent_sandbox::{SandboxResult, SandboxSpec};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use support::{run_spec, TestRunSummary};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn run_shell(
    spec: SandboxSpec,
    out: &std::path::Path,
) -> Result<TestRunSummary, Box<dyn std::error::Error>> {
    run_spec(
        &RunSpecV1 {
            name: "executable-byte-gate".into(),
            steps: vec![StepSpecV1 {
                name: "shell".into(),
                call: ToolCallSpecV1 {
                    tool: "shell".into(),
                    args: serde_json::to_value(spec)
                        .map_err(recursive_agent_runner::RunError::Json)?,
                    frozen_clock: None,
                },
            }],
            frozen_clock: None,
            policy_version: "m0-2".into(),
        },
        out,
    )
}

fn observation(summary: &TestRunSummary) -> Result<SandboxResult, Box<dyn std::error::Error>> {
    let paths = RunPaths::new(summary.run_dir.clone());
    let snapshot = verified_snapshot_directory_bound(&paths)?;
    let store = open(&paths)?.artifact_store()?;
    for receipt in snapshot.receipts().iter().rev() {
        for descriptor in receipt.artifact_refs.iter().rev() {
            let bytes = store.get(descriptor)?;
            if let Ok(result) = serde_json::from_slice::<SandboxResult>(&bytes) {
                return Ok(result);
            }
        }
    }
    Err("sandbox observation missing".into())
}

#[test]
fn user_owned_rewritable_executable_is_denied_with_zero_starts() -> TestResult {
    let executable_root = tempfile::tempdir()?;
    let executable = executable_root.path().join("mutable-command");
    let marker = executable_root.path().join("started");
    std::fs::write(
        &executable,
        format!("#!/usr/bin/bash\nprintf x > {}\n", marker.display()),
    )?;
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))?;
    let output = tempfile::tempdir()?;
    let result = run_shell(
        SandboxSpec {
            command: executable.display().to_string(),
            args: Vec::new(),
            allowed_read_paths: Vec::new(),
            allowed_write_paths: vec![executable_root.path().display().to_string()],
            allow_network: false,
            timeout_ms: 2_000,
            max_output_bytes: 1_024,
        },
        output.path(),
    );
    if let Ok(summary) = result {
        assert_ne!(summary.terminal_state, RunTerminalStateV1::Succeeded);
    }
    assert!(!marker.exists(), "mutable executable reached process start");
    Ok(())
}

#[test]
fn same_inode_and_writable_hard_link_are_not_byte_authority() -> TestResult {
    let root = tempfile::tempdir()?;
    let executable = root.path().join("command");
    let alias = root.path().join("alias");
    std::fs::write(&executable, b"#!/usr/bin/bash\nprintf before\n")?;
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))?;
    std::fs::hard_link(&executable, &alias)?;
    let before = std::fs::metadata(&executable)?;
    std::fs::write(&alias, b"#!/usr/bin/bash\nprintf after!\n")?;
    let after = std::fs::metadata(&executable)?;
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    let engine = include_str!("../src/sandbox_engine.rs");
    assert!(
        engine.contains("byte_digest") && engine.contains("MAX_EXECUTABLE"),
        "metadata-only identity admits same-inode byte replacement"
    );
    Ok(())
}

#[test]
fn trusted_printf_evidence_contains_exact_command_bash_and_bwrap_digests() -> TestResult {
    let output = tempfile::tempdir()?;
    let summary = run_shell(
        SandboxSpec {
            command: "/usr/bin/printf".into(),
            args: vec!["trusted".into()],
            allowed_read_paths: Vec::new(),
            allowed_write_paths: Vec::new(),
            allow_network: false,
            timeout_ms: 2_000,
            max_output_bytes: 1_024,
        },
        output.path(),
    )?;
    assert_eq!(summary.terminal_state, RunTerminalStateV1::Succeeded);
    let value = serde_json::to_value(observation(&summary)?)?;
    let executable_evidence = value["enforcement"]["trusted_executables"]
        .as_array()
        .ok_or("exact executable evidence missing")?;
    assert_eq!(executable_evidence.len(), 3);
    assert!(executable_evidence.iter().all(|entry| {
        entry
            .get("byte_digest")
            .and_then(serde_json::Value::as_str)
            .is_some()
            && entry
                .get("descriptor_identity")
                .and_then(serde_json::Value::as_str)
                .is_some()
    }));
    Ok(())
}

#[test]
fn parent_components_are_rejected_before_run_root_creation() -> TestResult {
    let fixture = tempfile::tempdir()?;
    let descriptor_target = fixture.path().join("a/b");
    std::fs::create_dir_all(&descriptor_target)?;
    let declared = fixture.path().join("a/../b");
    let out_root = fixture.path().join("runs");

    let result = run_shell(
        SandboxSpec {
            command: "/usr/bin/printf".into(),
            args: vec!["must-not-dispatch".into()],
            allowed_read_paths: Vec::new(),
            allowed_write_paths: vec![declared.display().to_string()],
            allow_network: false,
            timeout_ms: 2_000,
            max_output_bytes: 1_024,
        },
        &out_root,
    );

    let Err(error) = result else {
        return Err("parent-component path unexpectedly reached a terminal run".into());
    };
    assert!(
        error
            .to_string()
            .contains("operation payload failed run-spec semantic validation"),
        "unexpected parent-component rejection: {error}"
    );
    assert!(!out_root.exists());
    Ok(())
}
