use super::*;
use recursive_agent_contracts::RuntimeEventKindV1;
use recursive_agent_policy::{
    parse_normal_chat_executor_report_v2_bytes, NormalChatReportedStateV2, NormalChatSettlementV2,
    PermitRevocationReasonV1,
};

fn consumed(fx: &Fixture) -> Result<ChainHandle, Box<dyn std::error::Error>> {
    let mut chain = fx.prefix(true)?;
    let store = chain.artifact_store()?;
    let issued = fx.proof.issued_effect_evidence()?;
    append(
        &mut chain,
        &issued,
        ReceiptKindV1::PermitIssued,
        vec![put(&store, &issued)?],
    )?;
    append(
        &mut chain,
        &fx.proof.preflight.evidence,
        ReceiptKindV1::PermitConsumed,
        vec![put(&store, &fx.proof.preflight.evidence)?],
    )?;
    Ok(chain)
}
fn settlement(
    fx: &Fixture,
    state: NormalChatReportedStateV2,
) -> Result<NormalChatSettlementV2, Box<dyn std::error::Error>> {
    let sent = state != NormalChatReportedStateV2::NotSent
        && state != NormalChatReportedStateV2::OutcomeUnknown;
    let report = parse_normal_chat_executor_report_v2_bytes(&serde_json::to_vec(&json!({
        "schema":"recursive-agent.normal-chat-executor-report/v2","state":state,"duration_ms":if sent { 40 } else { 0 },
        "response":if sent { json!({"projection_schema":"ares-response-json-sorted-v1","digest":HOME,"byte_length":42,"complete":true}) } else { json!(null) },
        "usage":null,
    }))?)?;
    Ok(fx.permits.settle_normal_chat_attempt_v2(
        &fx.family,
        "intent:fixture",
        &fx.proof.preflight.receipt_digest,
        &report,
        || now() + TimeDelta::hours(2),
    )?)
}
fn terminal_row(
    chain: &ChainHandle,
    fx: &Fixture,
    value: &NormalChatSettlementV2,
    artifacts: Vec<recursive_agent_contracts::ArtifactDescriptorV1>,
) -> Result<recursive_agent_contracts::ReceiptV1, Box<dyn std::error::Error>> {
    let evidence = &fx.proof.preflight.evidence;
    Ok(make_receipt(
        ReceiptDraftV1 {
            run_id: evidence.binding.run_id.clone(),
            step_id: evidence.binding.step_id.clone(),
            kind: ReceiptKindV1::NormalChatAttemptSettledV2,
            valid_time: value.outcome.recorded_at,
            lineage: build_lineage(&evidence.permit_id, &evidence.binding.policy_version),
            spec_digest: evidence.binding.action_digest.clone(),
            args_digest: evidence.binding.args_digest.clone(),
            artifact_refs: artifacts,
            outcome: value.ledger_outcome_v2(&fx.proof)?,
        },
        chain.head().clone(),
    )?)
}
fn terminal_artifacts(
    chain: &ChainHandle,
    fx: &Fixture,
    value: &NormalChatSettlementV2,
) -> Result<Vec<recursive_agent_contracts::ArtifactDescriptorV1>, Box<dyn std::error::Error>> {
    let store = chain.artifact_store()?;
    let mut artifacts = vec![put(&store, value)?];
    if let Some(degraded) = value.degradation_record_v1(&fx.proof)? {
        artifacts.push(put(&store, &degraded)?);
    }
    Ok(artifacts)
}

#[test]
fn v2_settlement_terminalizes_every_report_after_expiry_and_operator_revocation() -> TestResult {
    for state in [
        NormalChatReportedStateV2::Succeeded,
        NormalChatReportedStateV2::Failed,
        NormalChatReportedStateV2::Cancelled,
        NormalChatReportedStateV2::Interrupted,
        NormalChatReportedStateV2::TimedOut,
        NormalChatReportedStateV2::NotSent,
        NormalChatReportedStateV2::OutcomeUnknown,
    ] {
        let fx = Fixture::new()?;
        let mut chain = consumed(&fx)?;
        let value = settlement(&fx, state)?;
        let record = fx.permits.revoke(
            &fx.proof.control_evidence()?.permit_id,
            PermitRevocationReasonV1::Operator,
            value.outcome.recorded_at,
        )?;
        let closed = PermitEvidenceV1::from_record(&record)?;
        let store = chain.artifact_store()?;
        // Existing control closure is historical; reporting does not renew it.
        append(
            &mut chain,
            &closed,
            ReceiptKindV1::PermitRevoked,
            vec![put(&store, &closed)?],
        )?;
        let artifacts = terminal_artifacts(&chain, &fx, &value)?;
        chain.append(terminal_row(&chain, &fx, &value, artifacts)?)?;
        let mut final_row = terminal_row(&chain, &fx, &value, vec![])?;
        final_row = make_receipt(
            ReceiptDraftV1 {
                run_id: final_row.run_id,
                step_id: final_row.step_id,
                kind: ReceiptKindV1::RunFinalized,
                valid_time: value.outcome.recorded_at,
                lineage: final_row.lineage,
                spec_digest: final_row.spec_digest,
                args_digest: final_row.args_digest,
                artifact_refs: vec![],
                outcome: value.ledger_outcome_v2(&fx.proof)?,
            },
            chain.head().clone(),
        )?;
        chain.append(final_row)?;
        let result = recursive_agent_ledger::verify_expected_run_from_dir_fd(
            &File::open(fx.child.path())?,
            &fx.proof.preflight.evidence.binding.run_id,
        )?;
        assert_eq!(
            result.terminal_state,
            value
                .ledger_outcome_v2(&fx.proof)?
                .terminal_state()
                .ok_or("terminal absent")?
        );
        let snapshot = appendable_snapshot_expected_run_from_dir_fd(
            &File::open(fx.child.path())?,
            &fx.proof.preflight.evidence.binding.run_id,
        )?;
        let events = recursive_agent_contracts::project_runtime_events(snapshot.receipts())?;
        assert!(events.iter().any(|e| matches!(
            e.kind,
            RuntimeEventKindV1::NormalChatAttemptSettledV2 { .. }
        )));
    }
    Ok(())
}

#[test]
fn v2_terminal_requires_consumption_exact_bindings_cardinality_and_degradation() -> TestResult {
    for mode in [
        "no-consume",
        "missing",
        "extra",
        "wrong-time",
        "wrong-outcome",
        "missing-degradation",
        "extra-degradation",
        "unknown-field",
    ] {
        let fx = Fixture::new()?;
        let mut chain = if mode == "no-consume" {
            fx.prefix(true)?
        } else {
            consumed(&fx)?
        };
        let unknown = mode == "missing-degradation";
        let value = settlement(
            &fx,
            if unknown {
                NormalChatReportedStateV2::OutcomeUnknown
            } else {
                NormalChatReportedStateV2::Succeeded
            },
        )?;
        let mut artifacts = terminal_artifacts(&chain, &fx, &value)?;
        match mode {
            "missing" => artifacts.clear(),
            "extra" | "extra-degradation" => artifacts.push(artifacts[0].clone()),
            "missing-degradation" => {
                artifacts.pop();
            }
            "unknown-field" => {
                let mut raw = serde_json::to_value(&value)?;
                raw["authority"] = json!(true);
                artifacts[0] = put(&chain.artifact_store()?, &raw)?;
            }
            _ => {}
        }
        let mut row = terminal_row(&chain, &fx, &value, artifacts)?;
        if mode == "wrong-time" {
            row.valid_time += TimeDelta::milliseconds(1);
        }
        if mode == "wrong-outcome" {
            row = make_receipt(
                ReceiptDraftV1 {
                    run_id: row.run_id,
                    step_id: row.step_id,
                    kind: row.kind,
                    valid_time: row.valid_time,
                    lineage: row.lineage,
                    spec_digest: row.spec_digest,
                    args_digest: row.args_digest,
                    artifact_refs: row.artifact_refs,
                    outcome: ReceiptOutcomeV1::Failed {
                        reason: "forged".into(),
                    },
                },
                chain.head().clone(),
            )?;
        }
        let before = chain.head().clone();
        assert!(chain.append(row).is_err(), "{mode}");
        assert_eq!(chain.head(), &before);
    }
    Ok(())
}

#[test]
fn v2_duplicate_and_generic_terminal_substitutions_reject_without_chain_change() -> TestResult {
    for kind in [
        ReceiptKindV1::ArtifactStored,
        ReceiptKindV1::StepCompleted,
        ReceiptKindV1::StepFailed,
        ReceiptKindV1::NormalChatAttemptSettledV2,
    ] {
        let fx = Fixture::new()?;
        let mut chain = consumed(&fx)?;
        let value = settlement(&fx, NormalChatReportedStateV2::Succeeded)?;
        let artifacts = terminal_artifacts(&chain, &fx, &value)?;
        let mut row = terminal_row(&chain, &fx, &value, artifacts.clone())?;
        if kind == ReceiptKindV1::NormalChatAttemptSettledV2 {
            chain.append(row)?;
            row = terminal_row(&chain, &fx, &value, artifacts)?;
        } else {
            row = make_receipt(
                ReceiptDraftV1 {
                    run_id: row.run_id,
                    step_id: row.step_id,
                    kind: kind.clone(),
                    valid_time: now(),
                    lineage: row.lineage,
                    spec_digest: row.spec_digest,
                    args_digest: row.args_digest,
                    artifact_refs: row.artifact_refs,
                    outcome: if kind == ReceiptKindV1::StepFailed {
                        ReceiptOutcomeV1::Failed {
                            reason: "generic".into(),
                        }
                    } else {
                        ReceiptOutcomeV1::Ok
                    },
                },
                chain.head().clone(),
            )?;
        }
        let before = chain.head().clone();
        assert!(chain.append(row).is_err(), "{kind:?}");
        assert_eq!(chain.head(), &before);
    }
    Ok(())
}
