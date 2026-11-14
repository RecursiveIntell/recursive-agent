use super::*;
use recursive_agent_policy::{PermitEvidenceStateV1, PermitRevocationReasonV1};

fn marker(
    fx: &Fixture,
    chain: &ChainHandle,
) -> Result<recursive_agent_contracts::ReceiptV1, Box<dyn std::error::Error>> {
    let binding = &fx.proof.preflight.evidence.binding;
    Ok(make_receipt(
        ReceiptDraftV1 {
            run_id: binding.run_id.clone(),
            step_id: binding.step_id.clone(),
            kind: ReceiptKindV1::NormalChatAttemptAdmittedV2,
            valid_time: fx.proof.preflight.recorded_at,
            lineage: build_lineage(&fx.proof.preflight.permit_id, &binding.policy_version),
            spec_digest: binding.action_digest.clone(),
            args_digest: binding.args_digest.clone(),
            artifact_refs: vec![put(&chain.artifact_store()?, &fx.proof)?],
            outcome: ReceiptOutcomeV1::Ok,
        },
        chain.head().clone(),
    )?)
}
fn control_prefix(fx: &Fixture) -> Result<ChainHandle, Box<dyn std::error::Error>> {
    let mut chain = fx.chain()?;
    let store = chain.artifact_store()?;
    let control = fx.proof.control_evidence()?;
    append(&mut chain, &control, ReceiptKindV1::RunStarted, vec![])?;
    append(&mut chain, &control, ReceiptKindV1::StepStarted, vec![])?;
    append(
        &mut chain,
        &control,
        ReceiptKindV1::PermitIssued,
        vec![put(&store, &control)?],
    )?;
    Ok(chain)
}

#[test]
fn admission_order_cardinality_and_exact_receipt_binding_are_closed() -> TestResult {
    for mode in [
        "before_start",
        "duplicate",
        "wrong_step",
        "wrong_time",
        "wrong_args",
        "wrong_spec",
        "wrong_lineage",
        "failed",
        "zero",
        "multiple",
    ] {
        let fx = Fixture::new()?;
        let mut chain = if mode == "before_start" {
            control_prefix(&fx)?
        } else {
            fx.prefix(false)?
        };
        if mode == "duplicate" {
            let descriptor = put(&chain.artifact_store()?, &fx.proof)?;
            admission(&mut chain, &fx.proof, descriptor)?;
        }
        let mut row = marker(&fx, &chain)?;
        match mode {
            "wrong_step" => row.step_id = fx.proof.control_evidence()?.binding.step_id,
            "wrong_time" => row.valid_time += TimeDelta::milliseconds(1),
            "wrong_args" => row.args_digest = ContentDigest::compute(b"wrong"),
            "wrong_spec" => row.spec_digest = ContentDigest::compute(b"wrong"),
            "wrong_lineage" => row.lineage[0].policy_version = "wrong-version".into(),
            "failed" => row.outcome = ReceiptOutcomeV1::Denied,
            "zero" => row.artifact_refs.clear(),
            "multiple" => row.artifact_refs.push(row.artifact_refs[0].clone()),
            _ => {}
        }
        let replacement = make_receipt(
            ReceiptDraftV1 {
                run_id: row.run_id,
                step_id: row.step_id,
                kind: row.kind,
                valid_time: row.valid_time,
                lineage: row.lineage,
                spec_digest: row.spec_digest,
                args_digest: row.args_digest,
                artifact_refs: row.artifact_refs,
                outcome: row.outcome,
            },
            row.prev_chain_digest,
        )?;
        let head = chain.head().clone();
        assert!(chain.append(replacement).is_err(), "{mode}");
        assert_eq!(chain.head(), &head);
    }
    Ok(())
}

#[test]
fn consumed_metadata_cannot_change_a_self_valid_transition_time_or_lineage() -> TestResult {
    for mode in ["time", "lineage", "issued_allocation", "scope"] {
        let fx = Fixture::new()?;
        let mut chain = fx.prefix(true)?;
        let store = chain.artifact_store()?;
        let mut issued = fx.proof.issued_effect_evidence()?;
        if mode == "issued_allocation" {
            issued.child_allocations.insert(
                fx.proof.control_evidence()?.permit_id,
                issued.binding.budget.clone(),
            );
            assert!(append(
                &mut chain,
                &issued,
                ReceiptKindV1::PermitIssued,
                vec![put(&store, &issued)?]
            )
            .is_err());
            continue;
        }
        if mode == "scope" {
            issued.binding.effect.network_allowed = false;
            assert!(append(
                &mut chain,
                &issued,
                ReceiptKindV1::PermitIssued,
                vec![put(&store, &issued)?]
            )
            .is_err());
            continue;
        }
        append(
            &mut chain,
            &issued,
            ReceiptKindV1::PermitIssued,
            vec![put(&store, &issued)?],
        )?;
        let mut consumed = fx.proof.preflight.evidence.clone();
        if mode == "time" {
            consumed.state = PermitEvidenceStateV1::Consumed {
                at: fx.proof.preflight.recorded_at + TimeDelta::milliseconds(1),
            };
            consumed.validate()?;
        }
        let mut row = make_receipt(
            ReceiptDraftV1 {
                run_id: consumed.binding.run_id.clone(),
                step_id: consumed.binding.step_id.clone(),
                kind: ReceiptKindV1::PermitConsumed,
                valid_time: if mode == "time" {
                    fx.proof.preflight.recorded_at + TimeDelta::milliseconds(1)
                } else {
                    fx.proof.preflight.recorded_at
                },
                lineage: build_lineage(&consumed.permit_id, &consumed.binding.policy_version),
                spec_digest: consumed.binding.action_digest.clone(),
                args_digest: consumed.binding.args_digest.clone(),
                artifact_refs: vec![put(&store, &consumed)?],
                outcome: ReceiptOutcomeV1::Ok,
            },
            chain.head().clone(),
        )?;
        if mode == "lineage" {
            row.lineage[0].principal = "wrong-principal".into();
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
                    outcome: row.outcome,
                },
                row.prev_chain_digest,
            )?;
        }
        assert!(chain.append(row).is_err(), "{mode}");
    }
    Ok(())
}

#[test]
fn nested_context_substitution_and_noncanonical_wire_bytes_reject() -> TestResult {
    let fx = Fixture::new()?;
    let original = serde_json::to_value(&fx.proof)?;
    for part in [
        "home",
        "revision",
        "grant",
        "root",
        "session",
        "route",
        "child_id",
        "parent_receipt",
        "budget",
        "body",
        "length",
        "preflight",
    ] {
        let mut bad = original.clone();
        match part {
            "home" => {
                bad["admission"]["context"]["session"]["ares_home_digest"] =
                    json!("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            }
            "revision" => bad["admission"]["context"]["session"]["grant_revision"] = json!(2),
            "grant" => {
                let mut grant = fx.proof.admission.context.grant.clone();
                grant.caps.max_attempts += 1;
                grant.policy_digest = grant.computed_policy_digest()?;
                bad["admission"]["context"]["grant"] = serde_json::to_value(grant)?;
            }
            "root" => {
                bad["admission"]["context"]["root_control"]["binding"]["effect"]
                    ["network_allowed"] = json!(true)
            }
            "session" => {
                bad["admission"]["context"]["session"]["conversation_ref"] =
                    json!("conversation:other")
            }
            "route" => {
                bad["admission"]["reservation"]["attempt"]["operation"]["api_mode"] =
                    json!("responses")
            }
            "child_id" => {
                bad["admission"]["reservation"]["child_control"]["child_control_permit_id"] =
                    json!(fx.proof.admission.context.root_control.permit_id)
            }
            "parent_receipt" => {
                bad["admission"]["reservation"]["child_control"]["request"]
                    ["parent_admission_receipt_id"] = json!(CurrentReceiptId::try_new(format!(
                    "v1:recursive-agent/receipt/v1:det:{}",
                    "d".repeat(64)
                ))?)
            }
            "budget" => {
                bad["admission"]["reservation"]["child_control"]["request"]["requested_budget"]
                    ["max_wall_time_ms"] = json!(999)
            }
            "body" => {
                bad["admission"]["reservation"]["attempt"]["provider_request_digest"] =
                    json!(ContentDigest::compute(b"other"))
            }
            "length" => {
                bad["admission"]["reservation"]["attempt"]["provider_request_bytes"] = json!(1)
            }
            _ => bad["preflight"]["recorded_at"] = json!(now() + TimeDelta::milliseconds(1)),
        }
        assert!(
            parse_normal_chat_ledger_admission_v2_bytes(&jcs_canonical(&bad)?).is_err(),
            "{part}"
        );
    }
    let canonical = jcs_canonical(&fx.proof)?;
    let mut whitespace = canonical.clone();
    whitespace.push(b'\n');
    assert!(parse_normal_chat_ledger_admission_v2_bytes(&whitespace).is_err());
    let text = String::from_utf8(canonical)?;
    let duplicate = text.replacen("\"revision\":1", "\"revision\":1,\"revision\":1", 1);
    assert_ne!(duplicate, text);
    assert!(parse_normal_chat_ledger_admission_v2_bytes(duplicate.as_bytes()).is_err());
    Ok(())
}

#[test]
fn v2_evidence_cannot_be_used_as_v3_or_replaced_by_v3_schema() -> TestResult {
    let fx = Fixture::new()?;
    let mut chain = control_prefix(&fx)?;
    let mut row = marker(&fx, &chain)?;
    row.kind = ReceiptKindV1::ProviderEgressAdmitted;
    let row = make_receipt(
        ReceiptDraftV1 {
            run_id: row.run_id,
            step_id: row.step_id,
            kind: row.kind,
            valid_time: row.valid_time,
            lineage: row.lineage,
            spec_digest: row.spec_digest,
            args_digest: row.args_digest,
            artifact_refs: row.artifact_refs,
            outcome: row.outcome,
        },
        row.prev_chain_digest,
    )?;
    assert!(chain.append(row).is_err());
    let mut wrong = serde_json::to_value(&fx.proof)?;
    wrong["schema"] = json!("recursive-agent.provider-egress-admission/v1");
    assert!(parse_normal_chat_ledger_admission_v2_bytes(&jcs_canonical(&wrong)?).is_err());
    Ok(())
}

#[test]
fn local_control_declaration_and_issuance_lineage_must_match() -> TestResult {
    for part in ["declaration", "issuance"] {
        let fx = Fixture::new()?;
        let mut chain = fx.chain()?;
        let store = chain.artifact_store()?;
        let control = fx.proof.control_evidence()?;
        append(&mut chain, &control, ReceiptKindV1::RunStarted, vec![])?;
        let mut row = make_receipt(
            ReceiptDraftV1 {
                run_id: control.binding.run_id.clone(),
                step_id: control.binding.step_id.clone(),
                kind: ReceiptKindV1::StepStarted,
                valid_time: now(),
                lineage: build_lineage(&control.permit_id, &control.binding.policy_version),
                spec_digest: control.binding.action_digest.clone(),
                args_digest: if part == "declaration" {
                    ContentDigest::compute(b"wrong")
                } else {
                    control.binding.args_digest.clone()
                },
                artifact_refs: vec![],
                outcome: ReceiptOutcomeV1::Ok,
            },
            chain.head().clone(),
        )?;
        chain.append(row)?;
        row = make_receipt(
            ReceiptDraftV1 {
                run_id: control.binding.run_id.clone(),
                step_id: control.binding.step_id.clone(),
                kind: ReceiptKindV1::PermitIssued,
                valid_time: now(),
                lineage: {
                    let mut lineage =
                        build_lineage(&control.permit_id, &control.binding.policy_version);
                    if part == "issuance" {
                        lineage[0].principal = "wrong".into();
                    }
                    lineage
                },
                spec_digest: control.binding.action_digest.clone(),
                args_digest: control.binding.args_digest.clone(),
                artifact_refs: vec![put(&store, &control)?],
                outcome: ReceiptOutcomeV1::Ok,
            },
            chain.head().clone(),
        )?;
        chain.append(row)?;
        append(
            &mut chain,
            &fx.proof.issued_effect_evidence()?,
            ReceiptKindV1::StepStarted,
            vec![],
        )?;
        assert!(
            admission(&mut chain, &fx.proof, put(&store, &fx.proof)?).is_err(),
            "{part}"
        );
    }
    Ok(())
}

#[test]
fn historical_metadata_survives_closure_and_local_revocation_without_reauthorization() -> TestResult
{
    let fx = Fixture::new()?;
    fx.permits.revoke(
        &fx.proof.control_evidence()?.permit_id,
        PermitRevocationReasonV1::Operator,
        now() + TimeDelta::milliseconds(1),
    )?;
    fx.family
        .close_normal_chat_session(now() + TimeDelta::hours(2))?;
    let read = fx
        .permits
        .read_normal_chat_ledger_admission_v2(&fx.family, "intent:fixture")?
        .ok_or("historical evidence absent")?;
    assert_eq!(read, fx.proof);
    assert!(matches!(
        read.control_evidence()?.state,
        PermitEvidenceStateV1::Issued
    ));
    assert!(matches!(
        fx.permits
            .read_normal_chat_attempt_v2(&fx.family, "intent:fixture")?
            .local_control
            .ok_or("no current control")?
            .state,
        PermitEvidenceStateV1::Revoked { .. }
    ));
    Ok(())
}

#[test]
fn contract_rejects_late_admission_and_mixed_admission_kinds() -> TestResult {
    for mixed in [false, true] {
        let fx = Fixture::new()?;
        let chain = if mixed {
            control_prefix(&fx)?
        } else {
            fx.prefix(false)?
        };
        let run = &fx.proof.preflight.evidence.binding.run_id;
        let snapshot =
            appendable_snapshot_expected_run_from_dir_fd(&File::open(fx.child.path())?, run)?;
        let mut rows = snapshot.receipts().to_vec();
        let mut row = marker(&fx, &chain)?;
        if mixed {
            // Contract-only chronology fixture: the V3 ledger decoder would
            // reject this V2 artifact; here the discriminator collision is tested.
            row.kind = ReceiptKindV1::ProviderEgressAdmitted;
        } else {
            row.kind = ReceiptKindV1::PermitIssued;
            row.valid_time = fx.proof.preflight.evidence.binding.issued_at;
            row.artifact_refs = vec![put(
                &chain.artifact_store()?,
                &fx.proof.issued_effect_evidence()?,
            )?];
        }
        let first = make_receipt(
            ReceiptDraftV1 {
                run_id: row.run_id,
                step_id: row.step_id,
                kind: row.kind,
                valid_time: row.valid_time,
                lineage: row.lineage,
                spec_digest: row.spec_digest,
                args_digest: row.args_digest,
                artifact_refs: row.artifact_refs,
                outcome: row.outcome,
            },
            chain.head().clone(),
        )?;
        let mut head = recursive_agent_ledger::chain_digest_from_raw(
            &first.prev_chain_digest,
            &first.canonical_bytes()?,
        )?;
        rows.push(first);
        if mixed {
            let mut start = marker(&fx, &chain)?;
            start.kind = ReceiptKindV1::StepStarted;
            start.artifact_refs.clear();
            let start = make_receipt(
                ReceiptDraftV1 {
                    run_id: start.run_id,
                    step_id: start.step_id,
                    kind: start.kind,
                    valid_time: start.valid_time,
                    lineage: start.lineage,
                    spec_digest: start.spec_digest,
                    args_digest: start.args_digest,
                    artifact_refs: start.artifact_refs,
                    outcome: start.outcome,
                },
                head,
            )?;
            head = recursive_agent_ledger::chain_digest_from_raw(
                &start.prev_chain_digest,
                &start.canonical_bytes()?,
            )?;
            rows.push(start);
        }
        recursive_agent_contracts::validate_receipt_sequence(
            &rows,
            recursive_agent_contracts::LifecycleValidationMode::AppendInProgress,
        )?;
        let last = marker(&fx, &chain)?;
        rows.push(make_receipt(
            ReceiptDraftV1 {
                run_id: last.run_id,
                step_id: last.step_id,
                kind: last.kind,
                valid_time: last.valid_time,
                lineage: last.lineage,
                spec_digest: last.spec_digest,
                args_digest: last.args_digest,
                artifact_refs: last.artifact_refs,
                outcome: last.outcome,
            },
            head,
        )?);
        assert!(
            recursive_agent_contracts::validate_receipt_sequence(
                &rows,
                recursive_agent_contracts::LifecycleValidationMode::AppendInProgress
            )
            .is_err(),
            "mixed={mixed}"
        );
    }
    Ok(())
}

#[test]
fn partial_prefix_is_not_a_terminal_verified_run() -> TestResult {
    let fx = Fixture::new()?;
    fx.prefix(true)?;
    assert!(
        recursive_agent_ledger::verify_directory_bound(&RunPaths::new(fx.child.path())).is_err()
    );
    Ok(())
}
