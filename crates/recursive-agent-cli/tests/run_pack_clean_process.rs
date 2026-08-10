use std::process::Command;

use recursive_agent_contracts::{RunSpecV1, StepSpecV1, ToolCallSpecV1};
use recursive_agent_runner::RunSummary;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn copy_tree(source: &std::path::Path, destination: &std::path::Path) -> TestResult {
    std::fs::create_dir(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let from = entry.path();
        let to = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&from, &to)?;
        } else if entry.file_type()?.is_file() {
            std::fs::copy(from, to)?;
        } else {
            return Err("pack contains a non-regular filesystem entry".into());
        }
    }
    Ok(())
}

#[test]
fn copied_pack_verifies_and_replays_from_a_clean_root_after_source_removal() -> TestResult {
    let source = tempfile::tempdir()?;
    let spec = RunSpecV1 {
        name: "clean-process-pack".into(),
        steps: vec![StepSpecV1 {
            name: "echo".into(),
            call: ToolCallSpecV1 {
                tool: "echo".into(),
                args: serde_json::json!({"text": "pack-only"}),
                frozen_clock: None,
            },
        }],
        frozen_clock: None,
        policy_version: "m0-2".into(),
    };
    let spec_path = source.path().join("spec.json");
    std::fs::write(&spec_path, serde_json::to_vec(&spec)?)?;
    let run = Command::new(env!("CARGO_BIN_EXE_ra"))
        .args(["run", "--spec"])
        .arg(&spec_path)
        .arg("--out")
        .arg(source.path().join("runs"))
        .output()?;
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let run: RunSummary = serde_json::from_slice(&run.stdout)?;

    let pack = source.path().join("pack");
    let exported = Command::new(env!("CARGO_BIN_EXE_ra"))
        .args(["pack", "export", "--run"])
        .arg(&run.run_dir)
        .arg("--out")
        .arg(&pack)
        .output()?;
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );

    let clean = tempfile::tempdir()?;
    let copied_pack = clean.path().join("only-pack");
    copy_tree(&pack, &copied_pack)?;
    std::fs::remove_dir_all(&run.run_dir)?;

    let verified = Command::new(env!("CARGO_BIN_EXE_ra"))
        .args(["pack", "verify", "--pack"])
        .arg(&copied_pack)
        .output()?;
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );

    let trace_log = clean.path().join("replay.strace");
    let replayed = Command::new("strace")
        .args(["-f", "-qq", "-e", "trace=network,process", "-o"])
        .arg(&trace_log)
        .arg(env!("CARGO_BIN_EXE_ra"))
        .args(["pack", "replay", "--pack"])
        .arg(&copied_pack)
        .output()?;
    assert!(
        replayed.status.success(),
        "{}",
        String::from_utf8_lossy(&replayed.stderr)
    );
    let trace = std::fs::read_to_string(&trace_log)?;
    let external_effects = [
        "socket(", "connect(", "accept(", "clone(", "fork(", "vfork(",
    ];
    for syscall in external_effects {
        assert!(
            !trace.contains(syscall),
            "recorded replay performed forbidden external syscall {syscall}: {trace}"
        );
    }
    let exec_count = trace.matches("execve(").count();
    assert_eq!(
        exec_count, 1,
        "only the CLI process itself may be exec'd during recorded replay: {trace}"
    );
    let result: serde_json::Value = serde_json::from_slice(&replayed.stdout)?;
    assert_eq!(result["mode"], "recorded_evidence");
    assert_eq!(result["source_run_id"], run.run_id.to_string());
    Ok(())
}
