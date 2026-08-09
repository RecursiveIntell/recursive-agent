//! Task 5.3 — resume only from a strictly-verified step boundary.
//!
//! A parent run that verifies cleanly yields a causally-linked continuation;
//! a tampered/unverified parent is a typed error (never a silent resume), and
//! the parent's evidence is never mutated.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(deprecated)]

use recursive_agent_contracts::{RunSpecV1, RunTerminalStateV1, StepSpecV1, ToolCallSpecV1};
use recursive_agent_ledger::RunPaths;
use recursive_agent_runner::{continuation_envelope, resume_from_verified_boundary, run_spec};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn echo_step(text: &str) -> StepSpecV1 {
    StepSpecV1 {
        name: "echo".into(),
        call: ToolCallSpecV1 {
            tool: "echo".into(),
            args: serde_json::json!({ "text": text }),
            frozen_clock: None,
        },
    }
}

fn run_parent(out_root: &std::path::Path) -> TestResult {
    let run = RunSpecV1 {
        name: "resume-parent".into(),
        steps: vec![echo_step("parent-step")],
        frozen_clock: None,
        policy_version: "m0-2".into(),
    };
    let summary = run_spec(&run, out_root)?;
    assert_eq!(summary.terminal_state, RunTerminalStateV1::Succeeded);
    Ok(())
}

fn newest_run_root(out_root: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    let mut entries = out_root
        .read_dir()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect::<Vec<_>>();
    entries.sort();
    entries
        .pop()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no run root produced"))
}

#[test]
fn verified_parent_yields_causally_linked_continuation() -> TestResult {
    let tmp = tempfile::tempdir()?;
    run_parent(tmp.path())?;
    let parent_root = newest_run_root(tmp.path())?;
    let parent_paths = RunPaths::new(&parent_root);

    // Resume from the verified boundary.
    let boundary = resume_from_verified_boundary(&parent_paths)?;
    assert!(boundary.verified);

    // Build a continuation envelope carrying parent lineage.
    let continuation = continuation_envelope(
        &boundary,
        "resume-child",
        vec![echo_step("child-step")],
        "m0-2",
    )?;
    let parent_id = boundary.parent_run_id;
    assert_eq!(
        continuation
            .causality
            .parent_operation_id
            .as_ref()
            .unwrap()
            .to_string(),
        parent_id
    );
    assert_eq!(
        continuation
            .causality
            .root_operation_id
            .as_ref()
            .unwrap()
            .to_string(),
        parent_id
    );
    Ok(())
}

#[test]
fn tampered_parent_boundary_is_rejected_not_resumed() -> TestResult {
    let tmp = tempfile::tempdir()?;
    run_parent(tmp.path())?;
    let parent_root = newest_run_root(tmp.path())?;
    let parent_paths = RunPaths::new(&parent_root);

    // Tamper with the parent receipt chain so strict verification fails.
    let mut bytes = std::fs::read(parent_paths.receipts_path())?;
    let text = String::from_utf8(bytes.clone())?;
    let idx = text
        .chars()
        .enumerate()
        .find(|(_, c)| c.is_ascii_hexdigit())
        .map(|(i, _)| i)
        .ok_or("no hex digit in receipt")?;
    let b = text.as_bytes()[idx];
    let flipped = if b == b'0' { b'1' } else { b'0' };
    bytes[idx] = flipped;
    std::fs::write(parent_paths.receipts_path(), &bytes)?;

    // Resume must be a typed error (or the verification itself errors) — it
    // must never silently succeed.
    let result = resume_from_verified_boundary(&parent_paths);
    assert!(
        result.is_err(),
        "resume must not succeed from a tampered parent"
    );
    Ok(())
}
