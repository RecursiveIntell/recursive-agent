#![allow(deprecated)]

use recursive_agent_contracts::{
    validate_runtime_event_sequence, ReceiptOutcomeV1, RunSpecV1, RuntimeEventKindV1, StepSpecV1,
    ToolCallSpecV1,
};
use recursive_agent_ledger::{
    committed_events_directory_bound, verified_snapshot_directory_bound, RunPaths,
};
use recursive_agent_runner::run_spec;

fn event_spec() -> Result<RunSpecV1, Box<dyn std::error::Error>> {
    let frozen_clock = chrono::DateTime::from_timestamp(1_700_000_000, 0)
        .ok_or("fixed event transcript time is invalid")?;
    Ok(RunSpecV1 {
        name: "phase2-committed-events".into(),
        steps: vec![StepSpecV1 {
            name: "echo".into(),
            call: ToolCallSpecV1 {
                tool: "echo".into(),
                args: serde_json::json!({"text": "committed-event"}),
                frozen_clock: Some(frozen_clock),
            },
        }],
        frozen_clock: Some(frozen_clock),
        policy_version: "m0-2".into(),
    })
}

#[test]
fn runner_event_semantics_are_deterministic_and_each_transcript_is_exactly_receipt_backed(
) -> Result<(), Box<dyn std::error::Error>> {
    let spec = event_spec()?;
    let first_root = tempfile::tempdir()?;
    let second_root = tempfile::tempdir()?;
    let first = run_spec(&spec, first_root.path())?;
    let second = run_spec(&spec, second_root.path())?;

    let first_paths = RunPaths::new(&first.run_dir);
    let second_paths = RunPaths::new(&second.run_dir);
    let first_snapshot = verified_snapshot_directory_bound(&first_paths)?;
    let second_snapshot = verified_snapshot_directory_bound(&second_paths)?;
    let first_events = committed_events_directory_bound(&first_paths, None)?;
    let second_events = committed_events_directory_bound(&second_paths, None)?;

    validate_runtime_event_sequence(&first_events, first_snapshot.receipts())?;
    validate_runtime_event_sequence(&second_events, second_snapshot.receipts())?;
    assert_eq!(first_events.len(), second_events.len());
    for (first_event, second_event) in first_events.iter().zip(&second_events) {
        assert_eq!(first_event.schema, second_event.schema);
        assert_eq!(first_event.run_id, second_event.run_id);
        assert_eq!(first_event.sequence, second_event.sequence);
        assert_eq!(first_event.kind, second_event.kind);
    }
    assert_eq!(first_events.len() as u64, first.chain_length);
    assert_eq!(second_events.len() as u64, second.chain_length);
    assert!(matches!(
        first_events.first().ok_or("missing submitted event")?.kind,
        RuntimeEventKindV1::Submitted
    ));
    assert!(matches!(
        first_events.last().ok_or("missing terminal event")?.kind,
        RuntimeEventKindV1::Completed {
            outcome: ReceiptOutcomeV1::Ok
        }
    ));
    Ok(())
}
