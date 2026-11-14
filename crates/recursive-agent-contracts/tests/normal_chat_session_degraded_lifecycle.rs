use chrono::{DateTime, TimeDelta, Utc};
use recursive_agent_contracts::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn seal(r: &mut ReceiptV1) -> Result<(), ContractError> {
    r.receipt_id = derive_receipt_id(&ReceiptIdentityMaterialV1 {
        run_id: &r.run_id,
        step_id: &r.step_id,
        kind: &r.kind,
        lineage: &r.lineage,
        spec_digest: &r.spec_digest,
        args_digest: &r.args_digest,
        outcome: &r.outcome,
        artifact_refs: &r.artifact_refs,
        predecessor_chain_digest: &r.prev_chain_digest,
    })?;
    Ok(())
}
fn fixture() -> Result<Vec<ReceiptV1>, Box<dyn std::error::Error>> {
    let run = CurrentRunId::try_new(format!("v1:recursive-agent/run/v1:det:{}", "a".repeat(64)))?;
    let step =
        CurrentStepId::try_new(format!("v1:recursive-agent/step/v1:det:{}", "a".repeat(64)))?;
    let d = ContentDigest::compute(b"root");
    let prep = ContentDigest::compute(b"prep");
    let artifact = ArtifactDescriptorV1 {
        owner_id: derive_artifact_id(b"metadata")?,
        digest: ContentDigest::compute(b"metadata"),
        byte_length: 8,
        media_type: "application/json".into(),
        encoding: None,
    };
    let lineage = vec![
        AuthorityLineageEntryV1 {
            origin: LineageOrigin::Request,
            principal: "actor:test".into(),
            permit_id: None,
            policy_version: "policy:fixture".into(),
        },
        AuthorityLineageEntryV1 {
            origin: LineageOrigin::Effect,
            principal: "actor:test".into(),
            permit_id: None,
            policy_version: "policy:fixture".into(),
        },
    ];
    let at = DateTime::<Utc>::UNIX_EPOCH;
    let mut out = Vec::new();
    for (i, (kind, phase, refs)) in [
        (ReceiptKindV1::RunStarted, None, vec![artifact.clone()]),
        (ReceiptKindV1::StepStarted, None, vec![]),
        (ReceiptKindV1::PermitIssued, None, vec![artifact.clone()]),
        (
            ReceiptKindV1::ChildAdmissionPrepared,
            Some("admission"),
            vec![],
        ),
        (
            ReceiptKindV1::ChildLinked,
            Some("link"),
            vec![artifact.clone()],
        ),
        (
            ReceiptKindV1::ChildClosed,
            Some("closure"),
            vec![artifact.clone()],
        ),
        (ReceiptKindV1::PermitRevoked, None, vec![artifact.clone()]),
        (
            ReceiptKindV1::NormalChatSessionDegradedV1,
            None,
            vec![artifact.clone()],
        ),
        (ReceiptKindV1::RunFinalized, None, vec![]),
    ]
    .into_iter()
    .enumerate()
    {
        let sid = if let Some(phase) = phase {
            derive_child_receipt_step_id(&run, &prep, phase)?
        } else {
            step.clone()
        };
        let mut row = ReceiptV1 {
            receipt_id: CurrentReceiptId::try_new(format!(
                "v1:recursive-agent/receipt/v1:det:{}",
                "a".repeat(64)
            ))?,
            run_id: run.clone(),
            step_id: sid,
            kind: kind.clone(),
            valid_time: at,
            recorded_time: at,
            lineage: lineage.clone(),
            spec_digest: if phase.is_some() {
                prep.clone()
            } else {
                d.clone()
            },
            args_digest: if phase.is_some() {
                prep.clone()
            } else {
                d.clone()
            },
            artifact_refs: refs,
            outcome: if i >= 7 {
                ReceiptOutcomeV1::Failed {
                    reason: NORMAL_CHAT_CHILD_OUTCOME_UNKNOWN_REASON_V1.into(),
                }
            } else {
                ReceiptOutcomeV1::Ok
            },
            prev_chain_digest: ContentDigest::compute(format!("prev:{i}").as_bytes()),
        };
        seal(&mut row)?;
        out.push(row);
    }
    Ok(out)
}
#[test]
fn typed_session_marker_is_a_distinct_non_provider_terminal_cause() -> TestResult {
    let rows = fixture()?;
    let v = validate_receipt_sequence(&rows, LifecycleValidationMode::StrictCurrent)?;
    assert_eq!(v.terminal_state, Some(RunTerminalStateV1::Failed));
    let events = project_runtime_events(&rows)?;
    assert!(matches!(
        events[7].kind,
        RuntimeEventKindV1::NormalChatSessionDegradedV1 { .. }
    ));
    validate_runtime_event_sequence(&events, &rows)?;
    Ok(())
}
#[test]
fn marker_lifecycle_rejects_missing_cause_group_or_root_and_wrong_marker_shape() -> TestResult {
    for mode in [
        "missing",
        "duplicate",
        "known-success",
        "degraded-enum",
        "wrong-reason",
        "missing-artifact",
        "extra-artifact",
        "before-root-close",
        "missing-child-close",
        "wrong-phase",
        "wrong-root-step",
        "wrong-root-spec",
        "wrong-time",
    ] {
        let mut rows = fixture()?;
        match mode {
            "missing" => {
                rows.remove(7);
            }
            "duplicate" => {
                rows.insert(8, rows[7].clone());
            }
            "known-success" => rows[7].outcome = ReceiptOutcomeV1::Ok,
            "degraded-enum" => {
                rows[7].outcome = ReceiptOutcomeV1::Degraded {
                    reason: "unknown".into(),
                }
            }
            "wrong-reason" => {
                rows[7].outcome = ReceiptOutcomeV1::Failed {
                    reason: "provider_failed".into(),
                }
            }
            "missing-artifact" => rows[7].artifact_refs.clear(),
            "extra-artifact" => {
                let extra = rows[6].artifact_refs[0].clone();
                rows[7].artifact_refs.push(extra);
            }
            "before-root-close" => rows.swap(6, 7),
            "missing-child-close" => {
                rows.remove(5);
            }
            "wrong-phase" => rows[4].step_id = rows[1].step_id.clone(),
            "wrong-root-step" => rows[7].step_id = rows[3].step_id.clone(),
            "wrong-root-spec" => rows[7].spec_digest = ContentDigest::compute(b"other"),
            _ => rows[7].valid_time -= TimeDelta::seconds(1),
        }
        for row in &mut rows {
            seal(row)?;
        }
        assert!(
            validate_receipt_sequence(&rows, LifecycleValidationMode::StrictCurrent).is_err(),
            "{mode}"
        );
    }
    Ok(())
}
#[test]
fn marker_finalization_binds_exact_cause_not_just_terminal_enum() -> TestResult {
    for mode in [
        "reason",
        "step",
        "spec",
        "args",
        "lineage",
        "time",
        "artifacts",
    ] {
        let mut rows = fixture()?;
        match mode {
            "reason" => {
                rows[8].outcome = ReceiptOutcomeV1::Failed {
                    reason: "different".into(),
                }
            }
            "step" => rows[8].step_id = rows[3].step_id.clone(),
            "spec" => rows[8].spec_digest = ContentDigest::compute(b"different"),
            "args" => rows[8].args_digest = ContentDigest::compute(b"different"),
            "lineage" => rows[8].lineage[0].principal = "actor:other".into(),
            "time" => rows[8].valid_time += TimeDelta::seconds(1),
            _ => rows[8].artifact_refs = rows[7].artifact_refs.clone(),
        };
        seal(&mut rows[8])?;
        assert!(
            validate_receipt_sequence(&rows, LifecycleValidationMode::StrictCurrent).is_err(),
            "{mode}"
        );
    }
    Ok(())
}
#[test]
fn marker_preserves_cancellation_and_denial_as_distinct_causes() -> TestResult {
    for outcome in [
        ReceiptOutcomeV1::Denied,
        ReceiptOutcomeV1::Cancelled {
            reason: NORMAL_CHAT_SESSION_CANCELLED_REASON_V1.into(),
        },
    ] {
        let mut rows = fixture()?;
        rows[7].outcome = outcome.clone();
        rows[8].outcome = outcome.clone();
        seal(&mut rows[7])?;
        seal(&mut rows[8])?;
        assert_eq!(
            validate_receipt_sequence(&rows, LifecycleValidationMode::StrictCurrent)?
                .terminal_state,
            outcome.terminal_state()
        );
    }
    Ok(())
}
