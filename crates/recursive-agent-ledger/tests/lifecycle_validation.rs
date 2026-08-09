use chrono::{DateTime, Utc};
use recursive_agent_contracts::{
    content_digest, derive_artifact_id, derive_run_id, derive_step_id, ArtifactDescriptorV1,
    AuthorityLineageEntryV1, ContentDigest, CurrentRunId, CurrentStepId, LineageOrigin,
    ReceiptKindV1, ReceiptOutcomeV1, RunSpecV1, StepSpecV1, ToolCallSpecV1,
};
use recursive_agent_ledger::{
    chain_digest_from_raw, committed_events_directory_bound, make_receipt, open,
    verified_snapshot_directory_bound, verify_directory_bound, verify_expected_run, ArtifactStore,
    RunPaths,
};
use recursive_agent_policy::{
    ActorPrincipalV1, DelegatedActionV1, DelegationCeilingV1, DelegationTransitionV1,
    DurablePermitStore, EffectScopeV1, ExecutionPermitV1, PermitBindingV1, PermitBudgetV1,
    PermitEvidenceV1, PermitRecordV1, PermitRevocationReasonV1, PermitStateV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn artifact_store(paths: &RunPaths) -> Result<ArtifactStore, recursive_agent_ledger::LedgerError> {
    open(paths)?.artifact_store()
}

struct Fixture {
    run: CurrentRunId,
    other_run: CurrentRunId,
    lifecycle: CurrentStepId,
    effect: CurrentStepId,
    time: DateTime<Utc>,
    control_lineage: Vec<AuthorityLineageEntryV1>,
    lineage: Vec<AuthorityLineageEntryV1>,
    control: ExecutionPermitV1,
    permit: ExecutionPermitV1,
    observed: ArtifactDescriptorV1,
}

fn fixture() -> TestResultValue<Fixture> {
    let time = DateTime::from_timestamp(1_700_000_000, 0).ok_or("fixed time is invalid")?;
    let call = ToolCallSpecV1 {
        tool: "echo".into(),
        args: serde_json::json!({"text": "x"}),
        frozen_clock: Some(time),
    };
    let make_spec = |name: &str| RunSpecV1 {
        name: name.into(),
        steps: vec![StepSpecV1 {
            name: "effect".into(),
            call: call.clone(),
        }],
        frozen_clock: Some(time),
        policy_version: "policy-v1".into(),
    };
    let run = derive_run_id(&make_spec("one"))?;
    let other_run = derive_run_id(&make_spec("two"))?;
    let lifecycle = derive_step_id(&run, 1, "lifecycle", &call)?;
    let effect = derive_step_id(&run, 0, "effect", &call)?;
    let effect_scope = EffectScopeV1 {
        scope_name: "echo".into(),
        read_roots: vec![],
        write_roots: vec![],
        network_allowed: false,
    };
    let mut binding = PermitBindingV1 {
        actor: ActorPrincipalV1::try_new("test")?,
        action_digest: content_digest(&serde_json::json!({"spec": 1}))?,
        effect_digest: content_digest(&effect_scope)?,
        effect: effect_scope,
        budget: PermitBudgetV1 {
            max_wall_time_ms: 1_000,
            max_output_bytes: 1_024,
            max_artifact_bytes: 1_024,
        },
        policy_version: "policy-v1".into(),
        parent_permit_id: None,
        parent_operation_id: Some(run.clone()),
        issued_at: time,
        not_before: time,
        expires_at: time + chrono::TimeDelta::seconds(1),
        run_id: run.clone(),
        step_id: effect.clone(),
        tool: "echo".into(),
        args_digest: content_digest(&serde_json::json!({"args": 1}))?,
    };
    let control_effect = EffectScopeV1 {
        scope_name: "runner.lifecycle".into(),
        read_roots: Vec::new(),
        write_roots: Vec::new(),
        network_allowed: false,
    };
    let control_binding = PermitBindingV1 {
        actor: binding.actor.clone(),
        action_digest: binding.action_digest.clone(),
        effect_digest: content_digest(&control_effect)?,
        effect: control_effect,
        budget: binding.budget.clone(),
        policy_version: binding.policy_version.clone(),
        parent_permit_id: None,
        parent_operation_id: Some(run.clone()),
        issued_at: time,
        not_before: time,
        expires_at: binding.expires_at,
        run_id: run.clone(),
        step_id: lifecycle.clone(),
        tool: "runner.lifecycle".into(),
        args_digest: binding.args_digest.clone(),
    };
    let ceiling = DelegationCeilingV1 {
        actor: binding.actor.clone(),
        policy_version: binding.policy_version.clone(),
        run_id: run.clone(),
        transition: DelegationTransitionV1::ControlToEffect,
        audiences: vec![binding.tool.clone()],
        actions: vec![DelegatedActionV1 {
            tool: binding.tool.clone(),
            action_digest: binding.action_digest.clone(),
            args_digest: binding.args_digest.clone(),
            effect: binding.effect.clone(),
            effect_digest: binding.effect_digest.clone(),
            executable_authority: Vec::new(),
        }],
        budget: binding.budget.clone(),
        not_before: time,
        expires_at: binding.expires_at,
    };
    let root = tempfile::tempdir()?;
    let root_file = std::fs::File::open(root.path())?;
    let store = DurablePermitStore::from_dir_fd(&root_file)?;
    let control = store.issue_control(&control_binding, ceiling, time)?;
    binding.parent_permit_id = Some(control.permit_id.clone());
    let permit = store.issue_effect(&binding, Vec::new(), time)?;
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
        permit_id: Some(permit.permit_id.clone()),
        policy_version: "policy-v1".into(),
    })
    .collect();
    let observed_bytes = b"observed";
    let observed = ArtifactDescriptorV1 {
        owner_id: derive_artifact_id(observed_bytes)?,
        digest: ContentDigest::compute(observed_bytes),
        byte_length: observed_bytes.len() as u64,
        media_type: "application/json".into(),
        encoding: Some("utf-8".into()),
    };
    Ok(Fixture {
        run,
        other_run,
        lifecycle,
        effect,
        time,
        control_lineage: lineage_for(&control),
        lineage,
        control,
        permit,
        observed,
    })
}

type TestResultValue<T> = Result<T, Box<dyn std::error::Error>>;

fn make(
    fixture: &Fixture,
    run: CurrentRunId,
    step: CurrentStepId,
    kind: ReceiptKindV1,
    outcome: ReceiptOutcomeV1,
    head: recursive_agent_contracts::ContentDigest,
) -> TestResultValue<recursive_agent_contracts::ReceiptV1> {
    let artifacts = if matches!(kind, ReceiptKindV1::StepCompleted) {
        vec![fixture.observed.clone()]
    } else {
        vec![]
    };
    make_with_artifacts(fixture, run, step, kind, outcome, head, artifacts)
}

fn make_with_artifacts(
    fixture: &Fixture,
    run: CurrentRunId,
    step: CurrentStepId,
    kind: ReceiptKindV1,
    outcome: ReceiptOutcomeV1,
    head: recursive_agent_contracts::ContentDigest,
    artifact_refs: Vec<ArtifactDescriptorV1>,
) -> TestResultValue<recursive_agent_contracts::ReceiptV1> {
    Ok(make_receipt(
        recursive_agent_ledger::ReceiptDraftV1 {
            run_id: run,
            step_id: step.clone(),
            kind,
            valid_time: fixture.time,
            lineage: if step == fixture.lifecycle {
                fixture.control_lineage.clone()
            } else {
                fixture.lineage.clone()
            },
            spec_digest: content_digest(&serde_json::json!({"spec": 1}))?,
            args_digest: content_digest(&serde_json::json!({"args": 1}))?,
            artifact_refs,
            outcome,
        },
        head,
    )?)
}

fn append_prefix(chain: &mut recursive_agent_ledger::ChainHandle, fixture: &Fixture) -> TestResult {
    let store = chain.artifact_store()?;
    let observed = store.put(b"observed", "application/json", Some("utf-8".into()))?;
    assert_eq!(observed, fixture.observed);
    let control_issued = PermitEvidenceV1::from_record(&PermitRecordV1 {
        permit: fixture.control.clone(),
        state: PermitStateV1::Issued,
        child_allocations: Default::default(),
    })?;
    let issued = PermitEvidenceV1::from_record(&PermitRecordV1 {
        permit: fixture.permit.clone(),
        state: PermitStateV1::Issued,
        child_allocations: Default::default(),
    })?;
    let consumed = PermitEvidenceV1::from_record(&PermitRecordV1 {
        permit: fixture.permit.clone(),
        state: PermitStateV1::Consumed {
            consumed_at: fixture.time,
        },
        child_allocations: Default::default(),
    })?;
    let issued_ref = store.put(
        &serde_json::to_vec(&issued)?,
        "application/json",
        Some("utf-8".into()),
    )?;
    let consumed_ref = store.put(
        &serde_json::to_vec(&consumed)?,
        "application/json",
        Some("utf-8".into()),
    )?;
    let control_issued_ref = store.put(
        &serde_json::to_vec(&control_issued)?,
        "application/json",
        Some("utf-8".into()),
    )?;
    for (step, kind, artifacts) in [
        (fixture.lifecycle.clone(), ReceiptKindV1::RunStarted, vec![]),
        (
            fixture.lifecycle.clone(),
            ReceiptKindV1::StepStarted,
            vec![],
        ),
        (
            fixture.lifecycle.clone(),
            ReceiptKindV1::PermitIssued,
            vec![control_issued_ref],
        ),
        (fixture.effect.clone(), ReceiptKindV1::StepStarted, vec![]),
        (
            fixture.effect.clone(),
            ReceiptKindV1::PermitIssued,
            vec![issued_ref],
        ),
        (
            fixture.effect.clone(),
            ReceiptKindV1::PermitConsumed,
            vec![consumed_ref],
        ),
        (
            fixture.effect.clone(),
            ReceiptKindV1::ArtifactStored,
            vec![fixture.observed.clone()],
        ),
    ] {
        chain.append(make_with_artifacts(
            fixture,
            fixture.run.clone(),
            step,
            kind,
            ReceiptOutcomeV1::Ok,
            chain.head().clone(),
            artifacts,
        )?)?;
    }
    Ok(())
}

fn append_control_revoked(
    chain: &mut recursive_agent_ledger::ChainHandle,
    fixture: &Fixture,
) -> TestResult {
    let allocations = std::collections::BTreeMap::from([(
        fixture.permit.permit_id.clone(),
        fixture.permit.binding.budget.clone(),
    )]);
    let evidence = PermitEvidenceV1::from_record(&PermitRecordV1 {
        permit: fixture.control.clone(),
        state: PermitStateV1::Revoked {
            revoked_at: fixture.time,
            reason: PermitRevocationReasonV1::Operator,
        },
        child_allocations: allocations,
    })?;
    let descriptor = chain.artifact_store()?.put(
        &serde_json::to_vec(&evidence)?,
        "application/json",
        Some("utf-8".into()),
    )?;
    chain.append(make_with_artifacts(
        fixture,
        fixture.run.clone(),
        fixture.lifecycle.clone(),
        ReceiptKindV1::PermitRevoked,
        ReceiptOutcomeV1::Ok,
        chain.head().clone(),
        vec![descriptor],
    )?)?;
    Ok(())
}

#[test]
fn every_failure_terminal_dominates_successful_finalization() -> TestResult {
    for outcome in [
        ReceiptOutcomeV1::Failed { reason: "x".into() },
        ReceiptOutcomeV1::Cancelled { reason: "x".into() },
        ReceiptOutcomeV1::Denied,
        ReceiptOutcomeV1::TimedOut { reason: "x".into() },
        ReceiptOutcomeV1::SandboxFailed { reason: "x".into() },
        ReceiptOutcomeV1::Corrupted { reason: "x".into() },
    ] {
        let root = tempfile::tempdir()?;
        let paths = RunPaths::new(root.path());
        let fixture = fixture()?;
        let mut chain = open(&paths)?;
        if matches!(outcome, ReceiptOutcomeV1::Denied) {
            for (step, kind) in [
                (fixture.lifecycle.clone(), ReceiptKindV1::RunStarted),
                (fixture.effect.clone(), ReceiptKindV1::StepStarted),
            ] {
                chain.append(make(
                    &fixture,
                    fixture.run.clone(),
                    step,
                    kind,
                    ReceiptOutcomeV1::Ok,
                    chain.head().clone(),
                )?)?;
            }
        } else {
            append_prefix(&mut chain, &fixture)?;
        }
        chain.append(make(
            &fixture,
            fixture.run.clone(),
            fixture.effect.clone(),
            ReceiptKindV1::StepFailed,
            outcome,
            chain.head().clone(),
        )?)?;
        let success = make(
            &fixture,
            fixture.run.clone(),
            fixture.lifecycle.clone(),
            ReceiptKindV1::RunFinalized,
            ReceiptOutcomeV1::Ok,
            chain.head().clone(),
        )?;
        assert!(chain.append(success).is_err());
    }
    Ok(())
}

#[test]
fn duplicate_final_post_terminal_final_without_start_and_mixed_runs_fail_append() -> TestResult {
    let root = tempfile::tempdir()?;
    let paths = RunPaths::new(root.path());
    let fixture = fixture()?;
    let mut chain = open(&paths)?;
    append_prefix(&mut chain, &fixture)?;
    chain.append(make(
        &fixture,
        fixture.run.clone(),
        fixture.effect.clone(),
        ReceiptKindV1::StepCompleted,
        ReceiptOutcomeV1::Ok,
        chain.head().clone(),
    )?)?;
    append_control_revoked(&mut chain, &fixture)?;
    chain.append(make(
        &fixture,
        fixture.run.clone(),
        fixture.lifecycle.clone(),
        ReceiptKindV1::RunFinalized,
        ReceiptOutcomeV1::Ok,
        chain.head().clone(),
    )?)?;
    for kind in [ReceiptKindV1::RunFinalized, ReceiptKindV1::StepStarted] {
        assert!(chain
            .append(make(
                &fixture,
                fixture.run.clone(),
                fixture.lifecycle.clone(),
                kind,
                ReceiptOutcomeV1::Ok,
                chain.head().clone(),
            )?)
            .is_err());
    }

    let root = tempfile::tempdir()?;
    let paths = RunPaths::new(root.path());
    let mut chain = open(&paths)?;
    assert!(chain
        .append(make(
            &fixture,
            fixture.run.clone(),
            fixture.lifecycle.clone(),
            ReceiptKindV1::RunFinalized,
            ReceiptOutcomeV1::Ok,
            chain.head().clone(),
        )?)
        .is_err());

    let root = tempfile::tempdir()?;
    let paths = RunPaths::new(root.path());
    let mut chain = open(&paths)?;
    chain.append(make(
        &fixture,
        fixture.run.clone(),
        fixture.lifecycle.clone(),
        ReceiptKindV1::RunStarted,
        ReceiptOutcomeV1::Ok,
        chain.head().clone(),
    )?)?;
    assert!(chain
        .append(make(
            &fixture,
            fixture.other_run.clone(),
            fixture.effect.clone(),
            ReceiptKindV1::StepStarted,
            ReceiptOutcomeV1::Ok,
            chain.head().clone(),
        )?)
        .is_err());
    Ok(())
}

#[test]
fn canonical_failed_then_success_chain_fails_offline_verification() -> TestResult {
    let root = tempfile::tempdir()?;
    let paths = RunPaths::new(root.path());
    let fixture = fixture()?;
    let initial = open(&paths)?.head().clone();
    let mut head = initial;
    let mut receipts = Vec::new();
    for (step, kind, outcome) in [
        (
            fixture.lifecycle.clone(),
            ReceiptKindV1::RunStarted,
            ReceiptOutcomeV1::Ok,
        ),
        (
            fixture.effect.clone(),
            ReceiptKindV1::StepStarted,
            ReceiptOutcomeV1::Ok,
        ),
        (
            fixture.effect.clone(),
            ReceiptKindV1::PermitIssued,
            ReceiptOutcomeV1::Ok,
        ),
        (
            fixture.effect.clone(),
            ReceiptKindV1::PermitConsumed,
            ReceiptOutcomeV1::Ok,
        ),
        (
            fixture.effect.clone(),
            ReceiptKindV1::StepFailed,
            ReceiptOutcomeV1::Failed { reason: "x".into() },
        ),
        (
            fixture.lifecycle.clone(),
            ReceiptKindV1::RunFinalized,
            ReceiptOutcomeV1::Ok,
        ),
    ] {
        let receipt = make(&fixture, fixture.run.clone(), step, kind, outcome, head)?;
        let canonical = receipt.canonical_bytes()?;
        head = chain_digest_from_raw(&receipt.prev_chain_digest, &canonical)?;
        receipts.push(canonical);
    }
    let mut bytes = Vec::new();
    for receipt in receipts {
        bytes.extend(receipt);
        bytes.push(b'\n');
    }
    std::fs::write(paths.receipts_path(), bytes)?;
    assert!(verify_expected_run(&paths, &fixture.run).is_err());
    Ok(())
}

#[test]
fn expected_run_binding_rejects_whole_chain_transplant() -> TestResult {
    let root = tempfile::tempdir()?;
    let paths = RunPaths::new(root.path());
    let fixture = fixture()?;
    let mut chain = open(&paths)?;
    append_prefix(&mut chain, &fixture)?;
    chain.append(make(
        &fixture,
        fixture.run.clone(),
        fixture.effect.clone(),
        ReceiptKindV1::StepCompleted,
        ReceiptOutcomeV1::Ok,
        chain.head().clone(),
    )?)?;
    append_control_revoked(&mut chain, &fixture)?;
    chain.append(make(
        &fixture,
        fixture.run.clone(),
        fixture.lifecycle.clone(),
        ReceiptKindV1::RunFinalized,
        ReceiptOutcomeV1::Ok,
        chain.head().clone(),
    )?)?;
    let verified = verify_expected_run(&paths, &fixture.run)?;
    assert_eq!(verified.verified_run_id.as_ref(), Some(&fixture.run));
    assert!(verify_expected_run(&paths, &fixture.other_run).is_err());
    Ok(())
}

#[test]
fn impossible_authorization_and_outcome_sequences_are_rejected() -> TestResult {
    let fixture = fixture()?;

    let root = tempfile::tempdir()?;
    let mut chain = open(&RunPaths::new(root.path()))?;
    for (step, kind, outcome) in [
        (
            fixture.lifecycle.clone(),
            ReceiptKindV1::RunStarted,
            ReceiptOutcomeV1::Ok,
        ),
        (
            fixture.effect.clone(),
            ReceiptKindV1::StepStarted,
            ReceiptOutcomeV1::Ok,
        ),
    ] {
        chain.append(make(
            &fixture,
            fixture.run.clone(),
            step,
            kind,
            outcome,
            chain.head().clone(),
        )?)?;
    }
    assert!(chain
        .append(make(
            &fixture,
            fixture.run.clone(),
            fixture.effect.clone(),
            ReceiptKindV1::PermitRejected,
            ReceiptOutcomeV1::Denied,
            chain.head().clone(),
        )?)
        .is_err());
    assert!(chain
        .append(make(
            &fixture,
            fixture.run.clone(),
            fixture.effect.clone(),
            ReceiptKindV1::PermitIssued,
            ReceiptOutcomeV1::Failed {
                reason: "forged".into()
            },
            chain.head().clone(),
        )?)
        .is_err());

    let root = tempfile::tempdir()?;
    let mut chain = open(&RunPaths::new(root.path()))?;
    append_prefix(&mut chain, &fixture)?;
    chain.append(make(
        &fixture,
        fixture.run.clone(),
        fixture.effect.clone(),
        ReceiptKindV1::StepCompleted,
        ReceiptOutcomeV1::Ok,
        chain.head().clone(),
    )?)?;
    assert!(chain
        .append(make(
            &fixture,
            fixture.run.clone(),
            fixture.effect.clone(),
            ReceiptKindV1::StepFailed,
            ReceiptOutcomeV1::Denied,
            chain.head().clone(),
        )?)
        .is_err());
    Ok(())
}

#[test]
fn strict_lifecycle_rejects_missing_or_mismatched_permit_and_artifact_evidence() -> TestResult {
    let root = tempfile::tempdir()?;
    let paths = RunPaths::new(root.path());
    let fixture = fixture()?;
    let store = artifact_store(&paths)?;
    let observed = store.put(b"observed", "application/json", Some("utf-8".into()))?;
    assert_eq!(observed, fixture.observed);
    let mut chain = open(&paths)?;
    for (step, kind) in [
        (fixture.lifecycle.clone(), ReceiptKindV1::RunStarted),
        (fixture.effect.clone(), ReceiptKindV1::StepStarted),
    ] {
        chain.append(make_with_artifacts(
            &fixture,
            fixture.run.clone(),
            step,
            kind,
            ReceiptOutcomeV1::Ok,
            chain.head().clone(),
            vec![],
        )?)?;
    }
    assert!(chain
        .append(make_with_artifacts(
            &fixture,
            fixture.run.clone(),
            fixture.effect.clone(),
            ReceiptKindV1::PermitIssued,
            ReceiptOutcomeV1::Ok,
            chain.head().clone(),
            vec![],
        )?)
        .is_err());
    assert!(verify_expected_run(&paths, &fixture.run).is_err());

    Ok(())
}

#[test]
fn every_public_strict_api_rejects_a_transplanted_chain() -> TestResult {
    let parent = tempfile::tempdir()?;
    let fixture = fixture()?;
    let expected_name = content_digest(&fixture.run)?.to_string();
    let original = parent.path().join(expected_name);
    let paths = RunPaths::new(&original);
    let mut chain = open(&paths)?;
    append_prefix(&mut chain, &fixture)?;
    chain.append(make(
        &fixture,
        fixture.run.clone(),
        fixture.effect.clone(),
        ReceiptKindV1::StepCompleted,
        ReceiptOutcomeV1::Ok,
        chain.head().clone(),
    )?)?;
    append_control_revoked(&mut chain, &fixture)?;
    chain.append(make(
        &fixture,
        fixture.run.clone(),
        fixture.lifecycle.clone(),
        ReceiptKindV1::RunFinalized,
        ReceiptOutcomeV1::Ok,
        chain.head().clone(),
    )?)?;
    verify_expected_run(&paths, &fixture.run)?;
    verify_directory_bound(&paths)?;
    verified_snapshot_directory_bound(&paths)?;

    let transplanted = parent
        .path()
        .join(content_digest(&fixture.other_run)?.to_string());
    std::fs::rename(&original, &transplanted)?;
    let transplanted_paths = RunPaths::new(transplanted);
    assert!(verify_expected_run(&transplanted_paths, &fixture.other_run).is_err());
    assert!(verify_directory_bound(&transplanted_paths).is_err());
    assert!(verified_snapshot_directory_bound(&transplanted_paths).is_err());
    Ok(())
}

#[derive(Clone)]
struct PermitCaseEvent {
    step: CurrentStepId,
    kind: ReceiptKindV1,
    outcome: ReceiptOutcomeV1,
    valid_time: DateTime<Utc>,
    lineage: Vec<AuthorityLineageEntryV1>,
    artifact_payloads: Vec<Vec<u8>>,
}

fn lineage_for(permit: &ExecutionPermitV1) -> Vec<AuthorityLineageEntryV1> {
    [
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
        permit_id: Some(permit.permit_id.clone()),
        policy_version: "policy-v1".into(),
    })
    .collect()
}

fn evidence_bytes(permit: &ExecutionPermitV1, state: PermitStateV1) -> TestResultValue<Vec<u8>> {
    Ok(serde_json::to_vec(&PermitEvidenceV1::from_record(
        &PermitRecordV1 {
            permit: permit.clone(),
            state,
            child_allocations: Default::default(),
        },
    )?)?)
}

fn materialize_case(
    paths: &RunPaths,
    fixture: &Fixture,
    events: &[PermitCaseEvent],
) -> TestResultValue<Vec<recursive_agent_contracts::ReceiptV1>> {
    let store = artifact_store(paths)?;
    let mut head = open(paths)?.head().clone();
    let mut receipts = Vec::new();
    for event in events {
        let artifacts = event
            .artifact_payloads
            .iter()
            .map(|payload| store.put(payload, "application/json", Some("utf-8".into())))
            .collect::<Result<Vec<_>, _>>()?;
        let receipt = make_receipt(
            recursive_agent_ledger::ReceiptDraftV1 {
                run_id: fixture.run.clone(),
                step_id: event.step.clone(),
                kind: event.kind.clone(),
                valid_time: event.valid_time,
                lineage: event.lineage.clone(),
                spec_digest: content_digest(&serde_json::json!({"spec": 1}))?,
                args_digest: content_digest(&serde_json::json!({"args": 1}))?,
                artifact_refs: artifacts,
                outcome: event.outcome.clone(),
            },
            head,
        )?;
        head = chain_digest_from_raw(&receipt.prev_chain_digest, &receipt.canonical_bytes()?)?;
        receipts.push(receipt);
    }
    Ok(receipts)
}

fn assert_every_strict_verifier_and_append_reject(
    fixture: &Fixture,
    events: &[PermitCaseEvent],
) -> TestResult {
    let raw_parent = tempfile::tempdir()?;
    let raw_paths = RunPaths::new(
        raw_parent
            .path()
            .join(content_digest(&fixture.run)?.to_string()),
    );
    let receipts = materialize_case(&raw_paths, fixture, events)?;
    let mut bytes = Vec::new();
    for receipt in &receipts {
        bytes.extend(receipt.canonical_bytes()?);
        bytes.push(b'\n');
    }
    std::fs::write(raw_paths.receipts_path(), bytes)?;
    assert!(verify_expected_run(&raw_paths, &fixture.run).is_err());
    assert!(verify_directory_bound(&raw_paths).is_err());
    assert!(verified_snapshot_directory_bound(&raw_paths).is_err());

    let append_parent = tempfile::tempdir()?;
    let append_paths = RunPaths::new(
        append_parent
            .path()
            .join(content_digest(&fixture.run)?.to_string()),
    );
    let receipts = materialize_case(&append_paths, fixture, events)?;
    let mut chain = open(&append_paths)?;
    let mut rejected = false;
    for receipt in receipts {
        if chain.append(receipt).is_err() {
            rejected = true;
            break;
        }
    }
    assert!(
        rejected,
        "append-time canonical validator admitted the case"
    );
    Ok(())
}

fn successful_effect_events(
    fixture: &Fixture,
    issued: Vec<u8>,
    consumed: Vec<u8>,
    consumed_time: DateTime<Utc>,
    consumed_lineage: Vec<AuthorityLineageEntryV1>,
) -> Vec<PermitCaseEvent> {
    vec![
        PermitCaseEvent {
            step: fixture.lifecycle.clone(),
            kind: ReceiptKindV1::RunStarted,
            outcome: ReceiptOutcomeV1::Ok,
            valid_time: fixture.time,
            lineage: fixture.lineage.clone(),
            artifact_payloads: vec![],
        },
        PermitCaseEvent {
            step: fixture.effect.clone(),
            kind: ReceiptKindV1::StepStarted,
            outcome: ReceiptOutcomeV1::Ok,
            valid_time: fixture.time,
            lineage: fixture.lineage.clone(),
            artifact_payloads: vec![],
        },
        PermitCaseEvent {
            step: fixture.effect.clone(),
            kind: ReceiptKindV1::PermitIssued,
            outcome: ReceiptOutcomeV1::Ok,
            valid_time: fixture.time,
            lineage: fixture.lineage.clone(),
            artifact_payloads: vec![issued],
        },
        PermitCaseEvent {
            step: fixture.effect.clone(),
            kind: ReceiptKindV1::PermitConsumed,
            outcome: ReceiptOutcomeV1::Ok,
            valid_time: consumed_time,
            lineage: consumed_lineage,
            artifact_payloads: vec![consumed],
        },
        PermitCaseEvent {
            step: fixture.effect.clone(),
            kind: ReceiptKindV1::ArtifactStored,
            outcome: ReceiptOutcomeV1::Ok,
            valid_time: consumed_time,
            lineage: fixture.lineage.clone(),
            artifact_payloads: vec![b"observed".to_vec()],
        },
        PermitCaseEvent {
            step: fixture.effect.clone(),
            kind: ReceiptKindV1::StepCompleted,
            outcome: ReceiptOutcomeV1::Ok,
            valid_time: consumed_time,
            lineage: fixture.lineage.clone(),
            artifact_payloads: vec![b"observed".to_vec()],
        },
        PermitCaseEvent {
            step: fixture.lifecycle.clone(),
            kind: ReceiptKindV1::RunFinalized,
            outcome: ReceiptOutcomeV1::Ok,
            valid_time: consumed_time,
            lineage: fixture.lineage.clone(),
            artifact_payloads: vec![],
        },
    ]
}

#[test]
fn every_authoritative_validator_rejects_discontinuous_or_impossible_permits() -> TestResult {
    let fixture = fixture()?;
    let issued = evidence_bytes(&fixture.permit, PermitStateV1::Issued)?;
    let consumed = evidence_bytes(
        &fixture.permit,
        PermitStateV1::Consumed {
            consumed_at: fixture.time,
        },
    )?;

    let mut other_consumed: serde_json::Value = serde_json::from_slice(&consumed)?;
    other_consumed["binding"]["actor"] = serde_json::json!("other");
    assert_every_strict_verifier_and_append_reject(
        &fixture,
        &successful_effect_events(
            &fixture,
            issued.clone(),
            serde_json::to_vec(&other_consumed)?,
            fixture.time,
            fixture.lineage.clone(),
        ),
    )?;

    let mut wrong_digest: serde_json::Value = serde_json::from_slice(&consumed)?;
    wrong_digest["binding_digest"] = serde_json::to_value(content_digest(&"wrong")?)?;
    assert_every_strict_verifier_and_append_reject(
        &fixture,
        &successful_effect_events(
            &fixture,
            issued.clone(),
            serde_json::to_vec(&wrong_digest)?,
            fixture.time,
            fixture.lineage.clone(),
        ),
    )?;

    let delayed_not_before = fixture.time + chrono::TimeDelta::milliseconds(100);
    let mut delayed_issued: serde_json::Value = serde_json::from_slice(&issued)?;
    delayed_issued["binding"]["not_before"] = serde_json::to_value(delayed_not_before)?;
    let mut delayed_consumed: serde_json::Value = serde_json::from_slice(&consumed)?;
    delayed_consumed["binding"]["not_before"] = serde_json::to_value(delayed_not_before)?;
    delayed_consumed["state"]["at"] = serde_json::to_value(fixture.time)?;
    assert_every_strict_verifier_and_append_reject(
        &fixture,
        &successful_effect_events(
            &fixture,
            serde_json::to_vec(&delayed_issued)?,
            serde_json::to_vec(&delayed_consumed)?,
            fixture.time,
            fixture.lineage.clone(),
        ),
    )?;

    let mut after_expiry: serde_json::Value = serde_json::from_slice(&consumed)?;
    after_expiry["state"]["at"] = serde_json::to_value(fixture.permit.binding.expires_at)?;
    assert_every_strict_verifier_and_append_reject(
        &fixture,
        &successful_effect_events(
            &fixture,
            issued.clone(),
            serde_json::to_vec(&after_expiry)?,
            fixture.permit.binding.expires_at,
            fixture.lineage.clone(),
        ),
    )?;

    let revoked = evidence_bytes(
        &fixture.permit,
        PermitStateV1::Revoked {
            revoked_at: fixture.time,
            reason: PermitRevocationReasonV1::Operator,
        },
    )?;
    let prefix = successful_effect_events(
        &fixture,
        issued.clone(),
        consumed.clone(),
        fixture.time,
        fixture.lineage.clone(),
    );
    let run_started = prefix[0].clone();
    let step_started = prefix[1].clone();
    let issued_event = prefix[2].clone();
    let consumed_event = prefix[3].clone();
    let artifact_event = prefix[4].clone();
    let completed_event = prefix[5].clone();
    let finalized_event = prefix[6].clone();

    let revoked_event = PermitCaseEvent {
        step: fixture.effect.clone(),
        kind: ReceiptKindV1::PermitRevoked,
        outcome: ReceiptOutcomeV1::Ok,
        valid_time: fixture.time,
        lineage: fixture.lineage.clone(),
        artifact_payloads: vec![revoked.clone()],
    };
    assert_every_strict_verifier_and_append_reject(
        &fixture,
        &[
            run_started.clone(),
            step_started.clone(),
            revoked_event.clone(),
        ],
    )?;
    assert_every_strict_verifier_and_append_reject(
        &fixture,
        &[
            run_started.clone(),
            step_started.clone(),
            issued_event.clone(),
            consumed_event,
            revoked_event.clone(),
        ],
    )?;
    assert_every_strict_verifier_and_append_reject(
        &fixture,
        &[
            run_started,
            step_started,
            issued_event,
            revoked_event,
            artifact_event,
            completed_event,
            finalized_event,
        ],
    )?;

    let mut valid_time_mismatch = successful_effect_events(
        &fixture,
        issued,
        consumed,
        fixture.time,
        fixture.lineage.clone(),
    );
    valid_time_mismatch[3].valid_time = fixture.time + chrono::TimeDelta::milliseconds(1);
    assert_every_strict_verifier_and_append_reject(&fixture, &valid_time_mismatch)?;
    Ok(())
}

#[test]
fn concurrent_readers_observe_only_committed_causal_event_prefixes() -> TestResult {
    let parent = tempfile::tempdir()?;
    let fixture = fixture()?;
    let run_directory = parent
        .path()
        .join(content_digest(&fixture.run)?.to_string());
    let paths = RunPaths::new(run_directory);
    let mut chain = open(&paths)?;
    append_prefix(&mut chain, &fixture)?;

    let reader_paths = paths.clone();
    let reader = std::thread::spawn(move || -> Result<u64, String> {
        let mut maximum = 0_u64;
        for _ in 0..100 {
            let events = committed_events_directory_bound(&reader_paths, None)
                .map_err(|error| error.to_string())?;
            for (index, event) in events.iter().enumerate() {
                if event.sequence != index as u64 {
                    return Err("reader observed a sequence gap".into());
                }
                let expected_parent = index
                    .checked_sub(1)
                    .map(|previous| events[previous].evidence_receipt.clone());
                if event.causal_parent != expected_parent {
                    return Err("reader observed a broken causal parent".into());
                }
            }
            maximum = maximum.max(events.len() as u64);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        Ok(maximum)
    });

    std::thread::sleep(std::time::Duration::from_millis(2));
    chain.append(make(
        &fixture,
        fixture.run.clone(),
        fixture.effect.clone(),
        ReceiptKindV1::StepCompleted,
        ReceiptOutcomeV1::Ok,
        chain.head().clone(),
    )?)?;
    std::thread::sleep(std::time::Duration::from_millis(2));
    append_control_revoked(&mut chain, &fixture)?;
    std::thread::sleep(std::time::Duration::from_millis(2));
    chain.append(make(
        &fixture,
        fixture.run.clone(),
        fixture.lifecycle.clone(),
        ReceiptKindV1::RunFinalized,
        ReceiptOutcomeV1::Ok,
        chain.head().clone(),
    )?)?;

    let maximum = reader
        .join()
        .map_err(|_| std::io::Error::other("committed-event reader thread panicked"))?
        .map_err(std::io::Error::other)?;
    assert_eq!(
        maximum, 10,
        "reader did not observe the final committed event"
    );

    let tail = committed_events_directory_bound(&paths, Some(6))?;
    assert_eq!(tail.len(), 3);
    assert_eq!(tail[0].sequence, 7);
    assert_eq!(tail[2].sequence, 9);
    Ok(())
}
