//! Count proof computation only in this test binary. No production counters,
//! persisted cache, or authority is introduced by this regression witness.
use super::*;
use recursive_agent_contracts::{
    derive_permit_id, derive_run_id, derive_step_id, LineageOrigin, PermitIdentityMaterialV1,
    RunSpecV1, StepSpecV1, ToolCallSpecV1,
};
use std::cell::Cell;

thread_local! {
    pub(super) static VALIDATION_CALLS: Cell<usize> = const { Cell::new(0) };
}

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fixture() -> TestResult<(tempfile::TempDir, File, CurrentRunId, ArtifactDescriptorV1)> {
    let temporary = tempfile::tempdir()?;
    let paths = RunPaths::new(temporary.path());
    let mut chain = open(&paths)?;
    let time = DateTime::from_timestamp(1_700_000_000, 0).ok_or("invalid fixture time")?;
    let call = ToolCallSpecV1 {
        tool: "echo".into(),
        args: serde_json::json!({"text": "snapshot-fixture"}),
        frozen_clock: Some(time),
    };
    let spec = RunSpecV1 {
        name: "snapshot-validation".into(),
        steps: vec![StepSpecV1 {
            name: "echo".into(),
            call: call.clone(),
        }],
        frozen_clock: Some(time),
        policy_version: "policy-v1".into(),
    };
    let run = derive_run_id(&spec)?;
    let step = derive_step_id(&run, 1, "lifecycle", &call)?;
    let permit = derive_permit_id(&PermitIdentityMaterialV1 {
        binding_digest: content_digest(&"snapshot-fixture")?,
        requested_not_before_delay_ms: 0,
        requested_validity_ms: 1_000,
    })?;
    let lineage = [
        LineageOrigin::Request,
        LineageOrigin::Plan,
        LineageOrigin::Policy,
        LineageOrigin::Tool,
        LineageOrigin::Effect,
    ]
    .into_iter()
    .map(|origin| AuthorityLineageEntryV1 {
        origin,
        principal: "test".into(),
        permit_id: Some(permit.clone()),
        policy_version: "policy-v1".into(),
    })
    .collect();
    let descriptor =
        chain
            .artifact_store()?
            .put(b"snapshot fixture", "text/plain", Some("utf-8".into()))?;
    let receipt = make_receipt(
        ReceiptDraftV1 {
            run_id: run.clone(),
            step_id: step,
            kind: ReceiptKindV1::RunStarted,
            valid_time: time,
            lineage,
            spec_digest: content_digest(&spec)?,
            args_digest: content_digest(&call.args)?,
            artifact_refs: vec![descriptor.clone()],
            outcome: ReceiptOutcomeV1::Ok,
        },
        chain.head().clone(),
    )?;
    chain.append(receipt)?;
    let root = File::open(temporary.path())?;
    Ok((temporary, root, run, descriptor))
}

#[test]
fn one_appendable_snapshot_computes_one_source_proof_under_its_lock() -> TestResult {
    let (_temporary, root, run, _descriptor) = fixture()?;
    VALIDATION_CALLS.with(|count| count.set(0));
    let snapshot = appendable_snapshot_expected_run_from_dir_fd(&root, &run)?;
    assert_eq!(snapshot.verification().length, 1);
    assert_eq!(snapshot.verification().verified_artifacts, 1);
    assert_eq!(
        VALIDATION_CALLS.with(Cell::get),
        1,
        "same immutable scan was redundantly proved"
    );
    Ok(())
}

#[test]
fn next_snapshot_reverifies_changed_artifact_instead_of_reusing_old_proof() -> TestResult {
    let (temporary, root, run, descriptor) = fixture()?;
    appendable_snapshot_expected_run_from_dir_fd(&root, &run)?;
    let artifact = temporary
        .path()
        .join("artifacts")
        .join(artifact_name(&descriptor)?);
    std::fs::write(artifact, b"tampered fixture")?;
    VALIDATION_CALLS.with(|count| count.set(0));
    assert!(matches!(
        appendable_snapshot_expected_run_from_dir_fd(&root, &run),
        Err(LedgerError::ArtifactCorrupted { .. })
    ));
    assert_eq!(VALIDATION_CALLS.with(Cell::get), 1);
    Ok(())
}

#[test]
fn one_pass_snapshot_preserves_expected_run_binding_and_metadata_reconciliation() -> TestResult {
    let (temporary, root, run, _descriptor) = fixture()?;
    let other = derive_run_id(&RunSpecV1 {
        name: "different-snapshot-fixture".into(),
        steps: vec![StepSpecV1 {
            name: "echo".into(),
            call: ToolCallSpecV1 {
                tool: "echo".into(),
                args: serde_json::json!({"text":"other"}),
                frozen_clock: None,
            },
        }],
        frozen_clock: None,
        policy_version: "policy-v1".into(),
    })?;
    assert!(matches!(
        appendable_snapshot_expected_run_from_dir_fd(&root, &other),
        Err(LedgerError::ExpectedRunMismatch { .. })
    ));
    std::fs::remove_file(temporary.path().join("chain.meta"))?;
    let snapshot = appendable_snapshot_expected_run_from_dir_fd(&root, &run)?;
    assert_eq!(snapshot.verification().verified_run_id.as_ref(), Some(&run));
    assert!(temporary.path().join("chain.meta").is_file());
    Ok(())
}
