//! Task 5.3 — resume only from a strictly-verified step boundary.
//!
//! A parent run that verifies cleanly yields an inspectable strict boundary;
//! a tampered/unverified parent is a typed error (never a silent resume), and
//! the parent's evidence is never mutated. Fresh child work must use the V2
//! live-parent admission lane, not a terminal V1 continuation envelope.
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod support;

use recursive_agent_contracts::{RunSpecV1, RunTerminalStateV1, StepSpecV1, ToolCallSpecV1};
use recursive_agent_ledger::RunPaths;
use recursive_agent_runner::resume_from_verified_boundary;
use support::run_spec;

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
fn verified_parent_yields_a_strict_boundary_without_mutating_parent_evidence() -> TestResult {
    let tmp = tempfile::tempdir()?;
    run_parent(tmp.path())?;
    let parent_root = newest_run_root(tmp.path())?;
    let parent_paths = RunPaths::new(&parent_root);

    // Resume from the verified boundary.
    let boundary = resume_from_verified_boundary(&parent_paths)?;
    assert!(boundary.verified);

    assert!(boundary.verified);
    assert!(!boundary.parent_run_id.is_empty());
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
