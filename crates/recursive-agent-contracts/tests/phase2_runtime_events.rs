use chrono::{TimeZone, Utc};
use recursive_agent_contracts::{
    content_digest, derive_receipt_id, derive_run_id, derive_step_id, project_runtime_events,
    validate_receipt_sequence, validate_runtime_event_sequence, AuthorityLineageEntryV1,
    ContentDigest, CurrentRunId, CurrentStepId, LifecycleValidationMode, LineageOrigin,
    ReceiptIdentityMaterialV1, ReceiptKindV1, ReceiptOutcomeV1, ReceiptV1, RunSpecV1,
    RuntimeEventKindV1, StepSpecV1, ToolCallSpecV1,
};

fn fixture_ids() -> Result<(CurrentRunId, CurrentStepId), Box<dyn std::error::Error>> {
    let spec = RunSpecV1 {
        name: "phase2-events".into(),
        steps: vec![StepSpecV1 {
            name: "event-step".into(),
            call: ToolCallSpecV1 {
                tool: "echo".into(),
                args: serde_json::json!({"text": "event"}),
                frozen_clock: None,
            },
        }],
        frozen_clock: None,
        policy_version: "policy-v1".into(),
    };
    let run_id = derive_run_id(&spec)?;
    let step_id = derive_step_id(&run_id, 0, "runtime-events", &spec.steps[0].call)?;
    Ok((run_id, step_id))
}

fn receipt(
    run_id: &CurrentRunId,
    step_id: &CurrentStepId,
    kind: ReceiptKindV1,
    outcome: ReceiptOutcomeV1,
    predecessor: ContentDigest,
) -> Result<ReceiptV1, Box<dyn std::error::Error>> {
    let lineage = vec![
        AuthorityLineageEntryV1 {
            origin: LineageOrigin::Request,
            principal: "actor:test".into(),
            permit_id: None,
            policy_version: "policy-v1".into(),
        },
        AuthorityLineageEntryV1 {
            origin: LineageOrigin::Effect,
            principal: "actor:test".into(),
            permit_id: None,
            policy_version: "policy-v1".into(),
        },
    ];
    let spec_digest = ContentDigest::compute(b"phase2-event-spec");
    let args_digest = ContentDigest::compute(b"phase2-event-args");
    let artifact_refs = vec![];
    let receipt_id = derive_receipt_id(&ReceiptIdentityMaterialV1 {
        run_id,
        step_id,
        kind: &kind,
        lineage: &lineage,
        spec_digest: &spec_digest,
        args_digest: &args_digest,
        outcome: &outcome,
        artifact_refs: &artifact_refs,
        predecessor_chain_digest: &predecessor,
    })?;
    let at = Utc
        .with_ymd_and_hms(2026, 8, 5, 12, 0, 0)
        .single()
        .ok_or("invalid fixed timestamp")?;
    Ok(ReceiptV1 {
        receipt_id,
        run_id: run_id.clone(),
        step_id: step_id.clone(),
        kind,
        valid_time: at,
        recorded_time: at,
        lineage,
        spec_digest,
        args_digest,
        artifact_refs,
        outcome,
        prev_chain_digest: predecessor,
    })
}

fn successful_receipts() -> Result<Vec<ReceiptV1>, Box<dyn std::error::Error>> {
    let (run_id, step_id) = fixture_ids()?;
    let mut receipts = Vec::new();
    for (index, (kind, outcome)) in [
        (ReceiptKindV1::RunStarted, ReceiptOutcomeV1::Ok),
        (ReceiptKindV1::StepStarted, ReceiptOutcomeV1::Ok),
        (ReceiptKindV1::PermitIssued, ReceiptOutcomeV1::Ok),
        (ReceiptKindV1::PermitRevoked, ReceiptOutcomeV1::Ok),
        (ReceiptKindV1::RunFinalized, ReceiptOutcomeV1::Ok),
    ]
    .into_iter()
    .enumerate()
    {
        receipts.push(receipt(
            &run_id,
            &step_id,
            kind,
            outcome,
            content_digest(&format!("event-predecessor-{index}"))?,
        )?);
    }
    validate_receipt_sequence(&receipts, LifecycleValidationMode::StrictCurrent)?;
    Ok(receipts)
}

#[test]
fn committed_runtime_event_projection_is_monotonic_causal_and_receipt_backed(
) -> Result<(), Box<dyn std::error::Error>> {
    let receipts = successful_receipts()?;
    let events = project_runtime_events(&receipts)?;

    assert_eq!(events.len(), receipts.len());
    assert!(matches!(events[0].kind, RuntimeEventKindV1::Submitted));
    assert!(matches!(
        events.last().ok_or("missing terminal event")?.kind,
        RuntimeEventKindV1::Completed { .. }
    ));
    for (index, event) in events.iter().enumerate() {
        assert_eq!(event.sequence, index as u64);
        assert_eq!(event.evidence_receipt, receipts[index].receipt_id);
        assert_eq!(
            event.causal_parent,
            index
                .checked_sub(1)
                .map(|previous| receipts[previous].receipt_id.clone())
        );
    }
    validate_runtime_event_sequence(&events, &receipts)?;
    Ok(())
}

#[test]
fn runtime_event_conformance_rejects_all_sequence_defects() -> Result<(), Box<dyn std::error::Error>>
{
    let receipts = successful_receipts()?;
    let events = project_runtime_events(&receipts)?;
    let mut cases = Vec::new();

    let mut duplicate = events.clone();
    duplicate[1].sequence = duplicate[0].sequence;
    cases.push(("duplicate sequence", duplicate, receipts.clone()));

    let mut missing = events.clone();
    missing.remove(1);
    cases.push(("missing event", missing, receipts.clone()));

    let mut reordered = events.clone();
    reordered.swap(1, 2);
    cases.push(("reordered events", reordered, receipts.clone()));

    let mut wrong_parent = events.clone();
    wrong_parent[2].causal_parent = None;
    cases.push(("wrong causal parent", wrong_parent, receipts.clone()));

    let mut post_terminal = events.clone();
    let mut extra = events.last().ok_or("missing terminal fixture")?.clone();
    extra.sequence += 1;
    extra.causal_parent = Some(
        events
            .last()
            .ok_or("missing terminal fixture")?
            .evidence_receipt
            .clone(),
    );
    post_terminal.push(extra);
    cases.push(("event after terminal", post_terminal, receipts.clone()));

    let receiptless = receipts[..receipts.len() - 1].to_vec();
    cases.push(("receipt-less event", events.clone(), receiptless));

    for (label, candidate_events, candidate_receipts) in cases {
        assert!(
            validate_runtime_event_sequence(&candidate_events, &candidate_receipts).is_err(),
            "{label} was accepted"
        );
    }

    let mut missing_receipt_field = serde_json::to_value(&events[0])?;
    missing_receipt_field
        .as_object_mut()
        .ok_or("event fixture is not an object")?
        .remove("evidence_receipt");
    assert!(
        serde_json::from_value::<recursive_agent_contracts::RuntimeEventV1>(missing_receipt_field)
            .is_err()
    );
    Ok(())
}
