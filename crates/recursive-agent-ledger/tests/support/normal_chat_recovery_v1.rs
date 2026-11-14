//! Real-native recovery evidence, never an invented executor report.
use super::*;
use recursive_agent_contracts::{ReceiptV1, RunTerminalStateV1, RuntimeEventKindV1};
use recursive_agent_policy::{NormalChatRecoveryRecordV1, PermitRevocationReasonV1};

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
fn recovered(fx: &Fixture) -> Result<NormalChatRecoveryRecordV1, Box<dyn std::error::Error>> {
    Ok(fx.permits.recover_expired_normal_chat_attempt_v1(
        &fx.family,
        "intent:fixture",
        &fx.proof.preflight.receipt_digest,
        || fx.proof.preflight.evidence.binding.expires_at,
    )?)
}
fn draft(
    fx: &Fixture,
    value: &NormalChatRecoveryRecordV1,
    artifacts: Vec<recursive_agent_contracts::ArtifactDescriptorV1>,
) -> Result<ReceiptDraftV1, Box<dyn std::error::Error>> {
    let effect = &fx.proof.preflight.evidence;
    Ok(ReceiptDraftV1 {
        run_id: effect.binding.run_id.clone(),
        step_id: effect.binding.step_id.clone(),
        kind: ReceiptKindV1::NormalChatAttemptRecoveredV1,
        valid_time: value.observed_at,
        lineage: build_lineage(&effect.permit_id, &effect.binding.policy_version),
        spec_digest: effect.binding.action_digest.clone(),
        args_digest: effect.binding.args_digest.clone(),
        artifact_refs: artifacts,
        outcome: value.ledger_outcome_v1(&fx.proof)?,
    })
}
fn row(
    chain: &ChainHandle,
    draft: ReceiptDraftV1,
) -> Result<ReceiptV1, Box<dyn std::error::Error>> {
    Ok(make_receipt(draft, chain.head().clone())?)
}
fn rejects_unchanged(chain: &mut ChainHandle, fx: &Fixture, draft: ReceiptDraftV1) -> TestResult {
    let head = chain.head().clone();
    let bytes = fs::read(fx.child.path().join("receipts.ndjson"))?;
    assert!(chain.append(row(chain, draft)?).is_err());
    assert_eq!(chain.head(), &head);
    assert_eq!(fs::read(fx.child.path().join("receipts.ndjson"))?, bytes);
    Ok(())
}
fn close_control(chain: &mut ChainHandle, fx: &Fixture, at: DateTime<Utc>) -> TestResult {
    let record = fx.permits.revoke(
        &fx.proof.control_evidence()?.permit_id,
        PermitRevocationReasonV1::Operator,
        at,
    )?;
    let evidence = PermitEvidenceV1::from_record(&record)?;
    let descriptor = put(&chain.artifact_store()?, &evidence)?;
    append(
        chain,
        &evidence,
        ReceiptKindV1::PermitRevoked,
        vec![descriptor],
    )
}
fn final_draft(
    fx: &Fixture,
    value: &NormalChatRecoveryRecordV1,
) -> Result<ReceiptDraftV1, Box<dyn std::error::Error>> {
    let mut value = draft(fx, value, vec![])?;
    value.kind = ReceiptKindV1::RunFinalized;
    Ok(value)
}

#[test]
fn recovered_child_is_strict_failed_unknown_without_an_executor_report_and_verifies_offline(
) -> TestResult {
    let fx = Fixture::new()?;
    let mut chain = consumed(&fx)?;
    let value = recovered(&fx)?;
    let descriptor = put(&chain.artifact_store()?, &value)?;
    chain.append(row(&chain, draft(&fx, &value, vec![descriptor])?)?)?;
    // A recovery transition is terminal metadata, not a claimed provider failure.
    close_control(&mut chain, &fx, value.observed_at)?;
    chain.append(row(&chain, final_draft(&fx, &value)?)?)?;
    let root = File::open(fx.child.path())?;
    let snapshot = recursive_agent_ledger::verified_snapshot_expected_run_from_dir_fd(
        &root,
        &fx.proof.preflight.evidence.binding.run_id,
    )?;
    assert_eq!(snapshot.receipts().len(), 10);
    assert_eq!(
        snapshot.verification().terminal_state,
        RunTerminalStateV1::Failed
    );
    let events = recursive_agent_contracts::project_runtime_events(snapshot.receipts())?;
    assert!(
        matches!(&events[7].kind, RuntimeEventKindV1::NormalChatAttemptRecoveredV1 { outcome: ReceiptOutcomeV1::Failed { reason }, .. }
        if reason == "normal_chat_degraded:EXECUTOR_OUTCOME_MISSING_AFTER_EXPIRY")
    );
    recursive_agent_contracts::validate_runtime_event_sequence(&events, snapshot.receipts())?;
    let view = fx
        .permits
        .read_normal_chat_attempt_v2(&fx.family, "intent:fixture")?;
    assert!(view.outcome.is_none() && view.settlement.is_none());
    let bytes = String::from_utf8(jcs_canonical(&value)?)?;
    for field in ["duration_ms", "usage", "response", "report"] {
        assert!(!bytes.contains(&format!("\"{field}\"")));
    }
    drop(chain);
    // Offline ledger verification depends on retained evidence, never a live
    // grant, native permit store, provider, or replay of a model call.
    fs::rename(
        fx.child.path().join("permits"),
        fx.child.path().join("native-unavailable"),
    )?;
    recursive_agent_ledger::verify_expected_run_from_dir_fd(
        &root,
        &fx.proof.preflight.evidence.binding.run_id,
    )?;
    Ok(())
}

#[test]
fn recovery_requires_the_exact_consumed_v2_lane_and_single_metadata_slot() -> TestResult {
    for mode in [
        "no-admission",
        "no-consume",
        "missing",
        "extra",
        "wrong-time",
        "ok",
        "degraded",
        "wrong-reason",
        "wrong-spec",
        "wrong-args",
        "wrong-step",
        "wrong-lineage",
        "media",
        "encoding",
    ] {
        let fx = Fixture::new()?;
        let mut chain = match mode {
            "no-admission" => fx.prefix(false)?,
            "no-consume" => fx.prefix(true)?,
            _ => consumed(&fx)?,
        };
        let value = recovered(&fx)?;
        let mut descriptors = vec![put(&chain.artifact_store()?, &value)?];
        match mode {
            "missing" => descriptors.clear(),
            "extra" => descriptors.push(descriptors[0].clone()),
            "media" => descriptors[0].media_type = "text/plain".into(),
            "encoding" => descriptors[0].encoding = Some("gzip".into()),
            _ => {}
        }
        let mut proposed = draft(&fx, &value, descriptors)?;
        match mode {
            "wrong-time" => proposed.valid_time += TimeDelta::milliseconds(1),
            "ok" => proposed.outcome = ReceiptOutcomeV1::Ok,
            "degraded" => {
                proposed.outcome = ReceiptOutcomeV1::Degraded {
                    reason: "unknown".into(),
                }
            }
            "wrong-reason" => {
                proposed.outcome = ReceiptOutcomeV1::Failed {
                    reason: "provider_timeout".into(),
                }
            }
            "wrong-spec" => proposed.spec_digest = ContentDigest::compute(b"other-spec"),
            "wrong-args" => proposed.args_digest = ContentDigest::compute(b"other-args"),
            "wrong-step" => proposed.step_id = fx.proof.control_evidence()?.binding.step_id,
            "wrong-lineage" => {
                proposed.lineage = build_lineage(
                    &fx.proof.control_evidence()?.permit_id,
                    &fx.proof.control_evidence()?.binding.policy_version,
                )
            }
            _ => {}
        }
        rejects_unchanged(&mut chain, &fx, proposed)?;
    }
    Ok(())
}

#[test]
fn recovery_artifact_is_strict_canonical_closed_and_bound_to_consumed_expiry() -> TestResult {
    for mode in [
        "attempt",
        "permit",
        "preflight",
        "before-expiry",
        "digest",
        "schema",
        "reason",
        "send-state",
        "sdk-report",
        "duration",
        "whitespace",
        "duplicate-key",
        "oversize",
    ] {
        let fx = Fixture::new()?;
        let mut chain = consumed(&fx)?;
        let original = recovered(&fx)?;
        let mut value = original.clone();
        match mode {
            "attempt" => {
                let mut raw = serde_json::to_value(&value)?;
                raw["attempt_id"] = json!("invalid");
                let d = put(&chain.artifact_store()?, &raw)?;
                rejects_unchanged(&mut chain, &fx, draft(&fx, &original, vec![d])?)?;
                continue;
            }
            "permit" => value.permit_id = fx.proof.control_evidence()?.permit_id,
            "preflight" => value.preflight_receipt_digest = ContentDigest::compute(b"other"),
            "before-expiry" => value.observed_at -= TimeDelta::milliseconds(1),
            "digest" => value.recovery_digest = ContentDigest::compute(b"bad-digest"),
            _ => {}
        }
        if mode != "digest" {
            value.recovery_digest = value.computed_digest()?;
        }
        let mut raw = serde_json::to_value(&value)?;
        match mode {
            "schema" => raw["schema"] = json!("recursive-agent.normal-chat-recovery/v2"),
            "reason" => raw["reason"] = json!("provider_failed"),
            "send-state" => raw["provider_send_state"] = json!("not_sent"),
            "sdk-report" => raw["report"] = json!({}),
            "duration" => raw["duration_ms"] = json!(0),
            _ => {}
        }
        let mut bytes = jcs_canonical(&raw)?;
        match mode {
            "whitespace" => bytes.push(b' '),
            "duplicate-key" => {
                bytes.pop();
                bytes.extend_from_slice(b",\"reason\":\"executor_outcome_missing_after_expiry\"}");
            }
            "oversize" => bytes = vec![b' '; 16_385],
            _ => {}
        }
        let d = chain
            .artifact_store()?
            .put(&bytes, "application/json", None)?;
        rejects_unchanged(&mut chain, &fx, draft(&fx, &original, vec![d])?)?;
    }
    Ok(())
}

#[test]
fn recovery_and_executor_settlement_are_exclusive_in_both_orders_and_generic_substitutes_reject(
) -> TestResult {
    for mode in [
        "recovery-twice",
        "recovery-then-report",
        "report-then-recovery",
        "generic-artifact",
        "generic-completed",
        "generic-failed",
    ] {
        let fx = Fixture::new()?;
        let mut chain = consumed(&fx)?;
        // Both artifacts derive from the same historical proof for adversarial
        // ledger ingress. Native arbitration is already separately tested.
        let recovery = recovered(&fx)?;
        let descriptor = put(&chain.artifact_store()?, &recovery)?;
        let report_fx = Fixture::new()?;
        assert_eq!(report_fx.proof, fx.proof);
        let report = recursive_agent_policy::parse_normal_chat_executor_report_v2_bytes(
            &serde_json::to_vec(
                &json!({"schema":"recursive-agent.normal-chat-executor-report/v2",
                "state":"not_sent","duration_ms":0,"response":null,"usage":null}),
            )?,
        )?;
        let settlement = report_fx.permits.settle_normal_chat_attempt_v2(
            &report_fx.family,
            "intent:fixture",
            &report_fx.proof.preflight.receipt_digest,
            &report,
            || recovery.observed_at,
        )?;
        let report_descriptor = put(&chain.artifact_store()?, &settlement)?;
        let report_draft = || -> Result<ReceiptDraftV1, Box<dyn std::error::Error>> {
            let mut value = draft(&fx, &recovery, vec![report_descriptor.clone()])?;
            value.kind = ReceiptKindV1::NormalChatAttemptSettledV2;
            value.outcome = settlement.ledger_outcome_v2(&fx.proof)?;
            Ok(value)
        };
        if mode == "report-then-recovery" {
            chain.append(row(&chain, report_draft()?)?)?;
            rejects_unchanged(&mut chain, &fx, draft(&fx, &recovery, vec![descriptor])?)?;
        } else if mode == "recovery-then-report" {
            chain.append(row(&chain, draft(&fx, &recovery, vec![descriptor])?)?)?;
            rejects_unchanged(&mut chain, &fx, report_draft()?)?;
        } else {
            let mut proposed = draft(&fx, &recovery, vec![descriptor.clone()])?;
            proposed.kind = match mode {
                "generic-artifact" => ReceiptKindV1::ArtifactStored,
                "generic-completed" => ReceiptKindV1::StepCompleted,
                "generic-failed" => ReceiptKindV1::StepFailed,
                _ => ReceiptKindV1::NormalChatAttemptRecoveredV1,
            };
            if mode == "recovery-twice" {
                chain.append(row(&chain, draft(&fx, &recovery, vec![descriptor])?)?)?;
            }
            rejects_unchanged(&mut chain, &fx, proposed)?;
        }
    }
    Ok(())
}

#[test]
fn recovered_finalization_cannot_change_semantic_binding_outcome_or_time() -> TestResult {
    for mode in [
        "step",
        "spec",
        "args",
        "lineage",
        "artifact",
        "reason",
        "ok",
        "before-observation",
        "before-revocation",
    ] {
        let fx = Fixture::new()?;
        let mut chain = consumed(&fx)?;
        let recovery = recovered(&fx)?;
        let descriptor = put(&chain.artifact_store()?, &recovery)?;
        chain.append(row(
            &chain,
            draft(&fx, &recovery, vec![descriptor.clone()])?,
        )?)?;
        let close_at = recovery.observed_at + TimeDelta::milliseconds(10);
        close_control(&mut chain, &fx, close_at)?;
        let mut proposed = final_draft(&fx, &recovery)?;
        proposed.valid_time = close_at;
        match mode {
            "step" => proposed.step_id = fx.proof.control_evidence()?.binding.step_id,
            "spec" => proposed.spec_digest = ContentDigest::compute(b"wrong-spec"),
            "args" => proposed.args_digest = ContentDigest::compute(b"wrong-args"),
            "lineage" => {
                proposed.lineage = build_lineage(
                    &fx.proof.control_evidence()?.permit_id,
                    &fx.proof.control_evidence()?.binding.policy_version,
                )
            }
            "artifact" => proposed.artifact_refs = vec![descriptor],
            "reason" => {
                proposed.outcome = ReceiptOutcomeV1::Failed {
                    reason: "provider_failed".into(),
                }
            }
            "ok" => proposed.outcome = ReceiptOutcomeV1::Ok,
            "before-observation" => {
                proposed.valid_time = recovery.observed_at - TimeDelta::milliseconds(1)
            }
            "before-revocation" => proposed.valid_time = recovery.observed_at,
            _ => {}
        }
        rejects_unchanged(&mut chain, &fx, proposed)?;
    }
    Ok(())
}

#[test]
fn recovery_does_not_replace_the_native_control_closure_requirement() -> TestResult {
    let fx = Fixture::new()?;
    let mut chain = consumed(&fx)?;
    let value = recovered(&fx)?;
    let descriptor = put(&chain.artifact_store()?, &value)?;
    chain.append(row(&chain, draft(&fx, &value, vec![descriptor])?)?)?;
    rejects_unchanged(&mut chain, &fx, final_draft(&fx, &value)?)?;
    Ok(())
}

#[test]
fn recovery_can_follow_an_already_revoked_control_without_rewriting_its_time() -> TestResult {
    let fx = Fixture::new()?;
    let mut chain = consumed(&fx)?;
    let expiry = fx.proof.preflight.evidence.binding.expires_at;
    close_control(&mut chain, &fx, expiry)?;
    let before = fs::read(fx.child.path().join("receipts.ndjson"))?;
    let value = recovered(&fx)?;
    let descriptor = put(&chain.artifact_store()?, &value)?;
    chain.append(row(&chain, draft(&fx, &value, vec![descriptor])?)?)?;
    chain.append(row(&chain, final_draft(&fx, &value)?)?)?;
    assert!(fs::read(fx.child.path().join("receipts.ndjson"))?.starts_with(&before));
    recursive_agent_ledger::verify_expected_run_from_dir_fd(
        &File::open(fx.child.path())?,
        &fx.proof.preflight.evidence.binding.run_id,
    )?;
    Ok(())
}

#[test]
fn missing_or_same_length_tampered_recovery_artifact_fails_offline_verification() -> TestResult {
    for remove in [false, true] {
        let fx = Fixture::new()?;
        let mut chain = consumed(&fx)?;
        let value = recovered(&fx)?;
        let descriptor = put(&chain.artifact_store()?, &value)?;
        chain.append(row(&chain, draft(&fx, &value, vec![descriptor.clone()])?)?)?;
        close_control(&mut chain, &fx, value.observed_at)?;
        chain.append(row(&chain, final_draft(&fx, &value)?)?)?;
        drop(chain);
        let payload = fx
            .child
            .path()
            .join("artifacts")
            .join(descriptor.digest.hex());
        let original = fs::read(&payload)?;
        if remove {
            fs::remove_file(&payload)?;
        } else {
            let mut changed = original.clone();
            let last = changed.len() - 1;
            changed[last] = b'!';
            fs::write(&payload, &changed)?;
            assert_eq!(changed.len(), original.len());
        }
        let error = recursive_agent_ledger::verify_expected_run_from_dir_fd(
            &File::open(fx.child.path())?,
            &fx.proof.preflight.evidence.binding.run_id,
        )
        .err()
        .ok_or("tampered recovery verified")?;
        if remove {
            assert!(
                matches!(error, recursive_agent_ledger::LedgerError::ArtifactMissing(ref id)
                if id == descriptor.owner_id.as_str()),
                "{error}"
            );
        } else {
            assert!(
                matches!(error, recursive_agent_ledger::LedgerError::ArtifactCorrupted { ref artifact_id, ref reason }
                if artifact_id == descriptor.owner_id.as_str() && reason.contains("digest")),
                "{error}"
            );
        }
        fs::write(&payload, original)?;
        recursive_agent_ledger::verify_expected_run_from_dir_fd(
            &File::open(fx.child.path())?,
            &fx.proof.preflight.evidence.binding.run_id,
        )?;
    }
    Ok(())
}
