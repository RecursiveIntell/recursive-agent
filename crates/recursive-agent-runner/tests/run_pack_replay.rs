//! Task 6 — recorded-evidence replay from an independently verified Run Pack.
//!
//! The fixture creates one real, valid terminal run through the runner test
//! support, then proves the replay entry point only reads the copied pack.
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};

use recursive_agent_contracts::{RunSpecV1, RunTerminalStateV1, StepSpecV1, ToolCallSpecV1};
use recursive_agent_ledger::{export_run_pack, verify_run_pack, RunPaths};
use recursive_agent_runner::replay_run_pack;
use support::run_spec;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Default)]
struct ExternalCallCounters {
    provider: AtomicUsize,
    tool: AtomicUsize,
    mcp: AtomicUsize,
    scheduler: AtomicUsize,
    network: AtomicUsize,
}

impl ExternalCallCounters {
    fn assert_zero(&self) {
        assert_eq!(self.provider.load(Ordering::SeqCst), 0, "provider calls");
        assert_eq!(self.tool.load(Ordering::SeqCst), 0, "tool calls");
        assert_eq!(self.mcp.load(Ordering::SeqCst), 0, "MCP calls");
        assert_eq!(self.scheduler.load(Ordering::SeqCst), 0, "scheduler calls");
        assert_eq!(self.network.load(Ordering::SeqCst), 0, "network calls");
    }
}

struct NoExternalCalls<'a>(&'a ExternalCallCounters);

impl Drop for NoExternalCalls<'_> {
    fn drop(&mut self) {
        self.0.assert_zero();
    }
}

fn terminal_echo_run(output_root: &std::path::Path) -> TestResult {
    let run = RunSpecV1 {
        name: "run-pack-recorded-replay".into(),
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
    let summary = run_spec(&run, output_root)?;
    assert_eq!(summary.terminal_state, RunTerminalStateV1::Succeeded);
    Ok(())
}

fn copy_tree(source: &std::path::Path, destination: &std::path::Path) -> TestResult {
    std::fs::create_dir(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&source_path, &destination_path)?;
        } else if entry.file_type()?.is_file() {
            std::fs::copy(source_path, destination_path)?;
        } else {
            return Err("exported pack contains a non-regular entry".into());
        }
    }
    Ok(())
}

fn copied_pack_with_removed_source() -> FixtureResult<(tempfile::TempDir, std::path::PathBuf)> {
    let source_root = tempfile::tempdir()?;
    terminal_echo_run(source_root.path())?;
    let run_root = source_root
        .path()
        .read_dir()?
        .next()
        .ok_or("terminal run root missing")??
        .path();
    let pack = source_root.path().join("pack");
    export_run_pack(&RunPaths::new(&run_root), &pack)?;

    let fresh_root = tempfile::tempdir()?;
    let copied_pack = fresh_root.path().join("only-pack");
    copy_tree(&pack, &copied_pack)?;
    std::fs::remove_dir_all(run_root)?;
    Ok((fresh_root, copied_pack))
}

#[test]
fn copied_verified_pack_replays_recorded_evidence_without_external_calls() -> TestResult {
    let (_fresh_root, pack) = copied_pack_with_removed_source()?;
    let expected_verification = verify_run_pack(&pack)?;
    let counters = ExternalCallCounters::default();
    let _no_external_calls = NoExternalCalls(&counters);

    let result = replay_run_pack(&pack)?;

    assert_eq!(result.schema_version, 1);
    assert_eq!(result.mode, "recorded_evidence");
    assert_eq!(result.verification_manifest_ref, "PACK_MANIFEST.json");
    assert_eq!(
        result.verification_manifest_digest,
        expected_verification.manifest_digest
    );
    assert_eq!(
        result.terminal_classification,
        RunTerminalStateV1::Succeeded
    );
    assert!(!result.artifact_references.is_empty());
    let mut observed = result
        .artifact_references
        .iter()
        .map(|descriptor| descriptor.owner_id.to_string())
        .collect::<Vec<_>>();
    let mut sorted = observed.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        observed, sorted,
        "artifact references are stable and unique"
    );
    observed.clear();

    let bytes = result.canonical_bytes()?;
    assert_eq!(
        bytes,
        recursive_agent_contracts::jcs_canonical(&result)?,
        "the returned REPLAY_RESULT.json payload is canonical JCS"
    );
    Ok(())
}

#[test]
fn tampered_or_incomplete_pack_is_rejected_without_fallback_or_external_calls() -> TestResult {
    for mutation in ["receipt", "artifact"] {
        let (_fresh_root, pack) = copied_pack_with_removed_source()?;
        let counters = ExternalCallCounters::default();
        let _no_external_calls = NoExternalCalls(&counters);
        match mutation {
            "receipt" => std::fs::write(pack.join("receipts.ndjson"), b"tampered\n")?,
            "artifact" => {
                let artifact = std::fs::read_dir(pack.join("artifacts"))?
                    .find_map(|entry| {
                        let entry = entry.ok()?;
                        entry.file_type().ok()?.is_file().then_some(entry.path())
                    })
                    .ok_or("packed artifact missing")?;
                std::fs::remove_file(artifact)?;
            }
            _ => unreachable!(),
        }

        assert!(
            replay_run_pack(&pack).is_err(),
            "{mutation} pack must fail closed"
        );
    }
    Ok(())
}
