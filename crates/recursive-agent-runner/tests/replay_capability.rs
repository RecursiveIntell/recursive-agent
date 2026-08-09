//! Task 5.4 — explicit replay-capability classification and offline replay.
//!
//! A strictly-verified run reports `RecordedEvidence` (no provider/network);
//! a tampered or unverifiable run reports `Unavailable`. Replay never invokes
//! tools or providers.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(deprecated)]

use recursive_agent_contracts::{RunSpecV1, RunTerminalStateV1, StepSpecV1, ToolCallSpecV1};
use recursive_agent_ledger::RunPaths;
use recursive_agent_runner::{replay, run_spec, ReplayCapability};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn echo_run(out_root: &std::path::Path) -> TestResult {
    let run = RunSpecV1 {
        name: "replay-capability".into(),
        steps: vec![StepSpecV1 {
            name: "echo".into(),
            call: ToolCallSpecV1 {
                tool: "echo".into(),
                args: serde_json::json!({"text": "recorded-evidence"}),
                frozen_clock: None,
            },
        }],
        frozen_clock: None,
        policy_version: "m0-2".into(),
    };
    let summary = run_spec(&run, out_root)?;
    assert_eq!(summary.terminal_state, RunTerminalStateV1::Succeeded);
    Ok(())
}

#[test]
fn verified_run_reports_recorded_evidence_replay_capability() -> TestResult {
    let tmp = tempfile::tempdir()?;
    echo_run(tmp.path())?;

    // Replay the newest run root.
    let run_root = tmp.path().read_dir()?.next().ok_or("no run root")??.path();
    let summary = replay(&RunPaths::new(&run_root))?;
    assert!(summary.ok);
    assert_eq!(
        summary.replay_capability,
        ReplayCapability::RecordedEvidence
    );
    Ok(())
}

#[test]
fn tampered_run_reports_unavailable_replay_capability() -> TestResult {
    let tmp = tempfile::tempdir()?;
    echo_run(tmp.path())?;
    let run_root = tmp.path().read_dir()?.next().ok_or("no run root")??.path();

    // Tamper with a byte inside the receipt JSON that keeps it valid UTF-8/JSON
    // but changes the material, so strict verification reports divergence (a
    // false-success summary is never produced). Flipping an arbitrary header
    // byte would make the JSON malformed and replay correctly returns Err —
    // both outcomes must be treated as Unavailable.
    let paths = RunPaths::new(&run_root);
    let mut bytes = std::fs::read(paths.receipts_path())?;
    let text = String::from_utf8(bytes.clone())?;
    // Locate the first hex digit of a 64-char digest and flip it to a different
    // hex digit, preserving valid JSON.
    let idx = text
        .chars()
        .enumerate()
        .find(|(_, c)| c.is_ascii_hexdigit())
        .map(|(i, _)| i)
        .ok_or("no hex digit in receipt")?;
    let b = text.as_bytes()[idx];
    let flipped = if b == b'0' { b'1' } else { b'0' };
    bytes[idx] = flipped;
    std::fs::write(paths.receipts_path(), &bytes)?;

    // Replay must never report success; it either returns a summary with
    // ok=false / Unavailable, or a typed Err — both are fail-closed.
    let summary = match replay(&paths) {
        Ok(s) => s,
        Err(_) => {
            // Fail-closed: tampered chain rejected outright.
            return Ok(());
        }
    };
    assert!(!summary.ok);
    assert_eq!(summary.replay_capability, ReplayCapability::Unavailable);
    Ok(())
}
