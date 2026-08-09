use chrono::{DateTime, Utc};
use recursive_agent_contracts::{
    content_digest, derive_run_id, derive_step_id, ArtifactDescriptorV1, AuthorityLineageEntryV1,
    CurrentRunId, CurrentStepId, LineageOrigin, ReceiptKindV1, ReceiptOutcomeV1, RunSpecV1,
    StepSpecV1, ToolCallSpecV1,
};
use recursive_agent_ledger::{
    make_receipt, open, verify_expected_run, ArtifactStore, LedgerError, RunPaths,
};
use recursive_agent_policy::{
    ActorPrincipalV1, DelegatedActionV1, DelegationCeilingV1, DelegationTransitionV1,
    EffectScopeV1, ExecutionPermitV1, PermitBindingV1, PermitBudgetV1, PermitEvidenceV1,
    PermitRecordV1, PermitRevocationReasonV1, PermitStateV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn artifact_store(paths: &RunPaths) -> Result<ArtifactStore, LedgerError> {
    open(paths)?.artifact_store()
}

struct Fixture {
    run: CurrentRunId,
    lifecycle_step: CurrentStepId,
    effect_step: CurrentStepId,
    time: DateTime<Utc>,
    control_lineage: Vec<AuthorityLineageEntryV1>,
    effect_lineage: Vec<AuthorityLineageEntryV1>,
    control: ExecutionPermitV1,
    permit: ExecutionPermitV1,
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let time = DateTime::from_timestamp(1_700_000_000, 0).ok_or("fixed time is invalid")?;
    let call = ToolCallSpecV1 {
        tool: "echo".into(),
        args: serde_json::json!({"text": "evidence"}),
        frozen_clock: Some(time),
    };
    let spec = RunSpecV1 {
        name: "artifact".into(),
        steps: vec![StepSpecV1 {
            name: "effect".into(),
            call: call.clone(),
        }],
        frozen_clock: Some(time),
        policy_version: "policy-v1".into(),
    };
    let run = derive_run_id(&spec)?;
    let lifecycle_step = derive_step_id(&run, 1, "lifecycle", &call)?;
    let effect_step = derive_step_id(&run, 0, "effect", &call)?;
    let effect = EffectScopeV1 {
        scope_name: "echo".into(),
        read_roots: vec![],
        write_roots: vec![],
        network_allowed: false,
    };
    let mut binding = PermitBindingV1 {
        actor: ActorPrincipalV1::try_new("test")?,
        action_digest: content_digest(&serde_json::json!({"spec": 1}))?,
        effect_digest: content_digest(&effect)?,
        effect,
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
        step_id: effect_step.clone(),
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
        step_id: lifecycle_step.clone(),
        tool: "runner.lifecycle".into(),
        args_digest: binding.args_digest.clone(),
    };
    let ceiling = DelegationCeilingV1 {
        actor: binding.actor.clone(),
        policy_version: binding.policy_version.clone(),
        run_id: run.clone(),
        transition: DelegationTransitionV1::ControlToEffect,
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
    let control = ExecutionPermitV1::control(control_binding, ceiling)?;
    binding.parent_permit_id = Some(control.permit_id.clone());
    let permit = ExecutionPermitV1::effect(binding, Vec::new())?;
    let lineage_for = |permit: &ExecutionPermitV1| {
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
        .collect::<Vec<_>>()
    };
    Ok(Fixture {
        run,
        lifecycle_step,
        effect_step,
        time,
        control_lineage: lineage_for(&control),
        effect_lineage: lineage_for(&permit),
        control,
        permit,
    })
}

fn append(
    chain: &mut recursive_agent_ledger::ChainHandle,
    fixture: &Fixture,
    step: CurrentStepId,
    kind: ReceiptKindV1,
    artifacts: Vec<ArtifactDescriptorV1>,
    outcome: ReceiptOutcomeV1,
) -> TestResult {
    let receipt = make_receipt(
        recursive_agent_ledger::ReceiptDraftV1 {
            run_id: fixture.run.clone(),
            step_id: step.clone(),
            kind,
            valid_time: fixture.time,
            lineage: if step == fixture.lifecycle_step {
                fixture.control_lineage.clone()
            } else {
                fixture.effect_lineage.clone()
            },
            spec_digest: content_digest(&serde_json::json!({"spec": 1}))?,
            args_digest: content_digest(&serde_json::json!({"args": 1}))?,
            artifact_refs: artifacts,
            outcome,
        },
        chain.head().clone(),
    )?;
    chain.append(receipt)?;
    Ok(())
}

fn complete_chain(paths: &RunPaths, descriptor: ArtifactDescriptorV1) -> TestResult {
    let fixture = fixture()?;
    let store = artifact_store(paths)?;
    let control_issued = store.put(
        &serde_json::to_vec(&PermitEvidenceV1::from_record(&PermitRecordV1 {
            permit: fixture.control.clone(),
            state: PermitStateV1::Issued,
            child_allocations: Default::default(),
        })?)?,
        "application/json",
        Some("utf-8".into()),
    )?;
    let issued = store.put(
        &serde_json::to_vec(&PermitEvidenceV1::from_record(&PermitRecordV1 {
            permit: fixture.permit.clone(),
            state: PermitStateV1::Issued,
            child_allocations: Default::default(),
        })?)?,
        "application/json",
        Some("utf-8".into()),
    )?;
    let consumed = store.put(
        &serde_json::to_vec(&PermitEvidenceV1::from_record(&PermitRecordV1 {
            permit: fixture.permit.clone(),
            state: PermitStateV1::Consumed {
                consumed_at: fixture.time,
            },
            child_allocations: Default::default(),
        })?)?,
        "application/json",
        Some("utf-8".into()),
    )?;
    let allocations = std::collections::BTreeMap::from([(
        fixture.permit.permit_id.clone(),
        fixture.permit.binding.budget.clone(),
    )]);
    let control_revoked = store.put(
        &serde_json::to_vec(&PermitEvidenceV1::from_record(&PermitRecordV1 {
            permit: fixture.control.clone(),
            state: PermitStateV1::Revoked {
                revoked_at: fixture.time,
                reason: PermitRevocationReasonV1::Operator,
            },
            child_allocations: allocations,
        })?)?,
        "application/json",
        Some("utf-8".into()),
    )?;
    let mut chain = open(paths)?;
    append(
        &mut chain,
        &fixture,
        fixture.lifecycle_step.clone(),
        ReceiptKindV1::RunStarted,
        vec![],
        ReceiptOutcomeV1::Ok,
    )?;
    append(
        &mut chain,
        &fixture,
        fixture.lifecycle_step.clone(),
        ReceiptKindV1::StepStarted,
        vec![],
        ReceiptOutcomeV1::Ok,
    )?;
    append(
        &mut chain,
        &fixture,
        fixture.lifecycle_step.clone(),
        ReceiptKindV1::PermitIssued,
        vec![control_issued],
        ReceiptOutcomeV1::Ok,
    )?;
    append(
        &mut chain,
        &fixture,
        fixture.effect_step.clone(),
        ReceiptKindV1::StepStarted,
        vec![],
        ReceiptOutcomeV1::Ok,
    )?;
    append(
        &mut chain,
        &fixture,
        fixture.effect_step.clone(),
        ReceiptKindV1::PermitIssued,
        vec![issued],
        ReceiptOutcomeV1::Ok,
    )?;
    append(
        &mut chain,
        &fixture,
        fixture.effect_step.clone(),
        ReceiptKindV1::PermitConsumed,
        vec![consumed],
        ReceiptOutcomeV1::Ok,
    )?;
    append(
        &mut chain,
        &fixture,
        fixture.effect_step.clone(),
        ReceiptKindV1::ArtifactStored,
        vec![descriptor.clone()],
        ReceiptOutcomeV1::Ok,
    )?;
    append(
        &mut chain,
        &fixture,
        fixture.effect_step.clone(),
        ReceiptKindV1::StepCompleted,
        vec![descriptor],
        ReceiptOutcomeV1::Ok,
    )?;
    append(
        &mut chain,
        &fixture,
        fixture.lifecycle_step.clone(),
        ReceiptKindV1::PermitRevoked,
        vec![control_revoked],
        ReceiptOutcomeV1::Ok,
    )?;
    append(
        &mut chain,
        &fixture,
        fixture.lifecycle_step.clone(),
        ReceiptKindV1::RunFinalized,
        vec![],
        ReceiptOutcomeV1::Ok,
    )?;
    Ok(())
}

fn artifact_path(paths: &RunPaths, descriptor: &ArtifactDescriptorV1) -> std::path::PathBuf {
    paths.artifacts_dir().join(descriptor.digest.hex())
}

#[test]
fn strict_verify_rejects_missing_truncated_replaced_and_wrong_digest() -> TestResult {
    for mutation in ["missing", "truncated", "replaced"] {
        let root = tempfile::tempdir()?;
        let paths = RunPaths::new(root.path());
        let store = artifact_store(&paths)?;
        let descriptor = store.put(b"evidence", "text/plain", Some("utf-8".into()))?;
        complete_chain(&paths, descriptor.clone())?;
        let path = artifact_path(&paths, &descriptor);
        match mutation {
            "missing" => std::fs::remove_file(path)?,
            "truncated" => std::fs::write(path, b"evid")?,
            "replaced" => std::fs::write(path, b"tampered")?,
            _ => unreachable!(),
        }
        assert!(
            verify_expected_run(&paths, &fixture()?.run).is_err(),
            "mutation {mutation}"
        );
    }
    Ok(())
}

#[test]
fn descriptor_length_media_type_and_digest_are_bound() -> TestResult {
    let root = tempfile::tempdir()?;
    let paths = RunPaths::new(root.path());
    let store = artifact_store(&paths)?;
    let descriptor = store.put(b"evidence", "text/plain", Some("utf-8".into()))?;
    for mutate in ["length", "media", "digest"] {
        let mut changed = descriptor.clone();
        match mutate {
            "length" => changed.byte_length += 1,
            "media" => changed.media_type = "application/octet-stream".into(),
            "digest" => changed.digest = content_digest(&"wrong")?,
            _ => unreachable!(),
        }
        assert!(store.get(&changed).is_err(), "mutation {mutate}");
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlink_fifo_directory_and_sparse_file_are_rejected_without_hanging() -> TestResult {
    use std::os::unix::fs::symlink;

    for kind in ["symlink", "fifo", "directory", "sparse"] {
        let root = tempfile::tempdir()?;
        let paths = RunPaths::new(root.path());
        let store = artifact_store(&paths)?;
        let descriptor = store.put(b"evidence", "text/plain", Some("utf-8".into()))?;
        let path = artifact_path(&paths, &descriptor);
        std::fs::remove_file(&path)?;
        match kind {
            "symlink" => symlink("/etc/passwd", &path)?,
            "fifo" => {
                let status = std::process::Command::new("mkfifo").arg(&path).status()?;
                assert!(status.success());
            }
            "directory" => std::fs::create_dir(&path)?,
            "sparse" => {
                let file = std::fs::File::create(&path)?;
                file.set_len(recursive_agent_ledger::MAX_ARTIFACT_SIZE + 1)?;
            }
            _ => unreachable!(),
        }
        let started = std::time::Instant::now();
        assert!(store.get(&descriptor).is_err(), "kind {kind}");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }
    Ok(())
}

#[test]
fn artifact_directory_replacement_does_not_redirect_pinned_store() -> TestResult {
    let root = tempfile::tempdir()?;
    let paths = RunPaths::new(root.path());
    let store = artifact_store(&paths)?;
    let descriptor = store.put(b"evidence", "text/plain", Some("utf-8".into()))?;
    let pinned = root.path().join("artifacts-pinned");
    std::fs::rename(paths.artifacts_dir(), &pinned)?;
    std::fs::create_dir(paths.artifacts_dir())?;
    assert_eq!(store.get(&descriptor)?, b"evidence");
    assert_eq!(std::fs::read_dir(paths.artifacts_dir())?.count(), 0);
    Ok(())
}

#[test]
fn malformed_owner_descriptor_is_rejected() -> TestResult {
    let root = tempfile::tempdir()?;
    let paths = RunPaths::new(root.path());
    let store = artifact_store(&paths)?;
    let mut descriptor = store.put(b"evidence", "text/plain", Some("utf-8".into()))?;
    descriptor.byte_length = 99;
    assert!(matches!(
        store.get(&descriptor),
        Err(LedgerError::ArtifactCorrupted { .. }) | Err(LedgerError::ArtifactTooLarge { .. })
    ));
    Ok(())
}

#[test]
fn concurrently_growing_artifact_and_metadata_reads_remain_bounded() -> TestResult {
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let root = tempfile::tempdir()?;
    let paths = RunPaths::new(root.path());
    paths.ensure()?;
    let store = artifact_store(&paths)?;
    let descriptor = store.put(b"bounded", "text/plain", Some("utf-8".into()))?;
    let suffix = descriptor
        .owner_id
        .as_str()
        .strip_prefix("v1:recursive-agent/artifact/v1:det:")
        .ok_or("artifact suffix")?;
    let artifact = paths.artifacts_dir().join(suffix);
    let metadata = paths.artifacts_dir().join(format!("{suffix}.meta"));

    for target in [artifact, metadata] {
        let stop = Arc::new(AtomicBool::new(false));
        let ready = Arc::new(AtomicBool::new(false));
        let writer_stop = Arc::clone(&stop);
        let writer_ready = Arc::clone(&ready);
        let writer = std::thread::spawn(move || {
            if let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(target) {
                while !writer_stop.load(Ordering::Relaxed) {
                    if file.write_all(&[b'x'; 4096]).is_err() {
                        break;
                    }
                    writer_ready.store(true, Ordering::Release);
                }
            }
        });
        let ready_deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while !ready.load(Ordering::Acquire) {
            if std::time::Instant::now() >= ready_deadline {
                return Err("growth writer did not start".into());
            }
            std::thread::yield_now();
        }
        let started = std::time::Instant::now();
        assert!(store.get(&descriptor).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        stop.store(true, Ordering::Relaxed);
        writer.join().map_err(|_| "growth writer panicked")?;
    }
    Ok(())
}

#[test]
fn partial_artifact_and_descriptor_metadata_are_rejected() -> TestResult {
    let root = tempfile::tempdir()?;
    let paths = RunPaths::new(root.path());
    paths.ensure()?;
    let store = artifact_store(&paths)?;
    let descriptor = store.put(b"complete", "text/plain", Some("utf-8".into()))?;
    let suffix = descriptor
        .owner_id
        .as_str()
        .strip_prefix("v1:recursive-agent/artifact/v1:det:")
        .ok_or("artifact suffix")?;
    let artifact = paths.artifacts_dir().join(suffix);
    std::fs::write(&artifact, b"part")?;
    assert!(store.get(&descriptor).is_err());

    std::fs::write(&artifact, b"complete")?;
    let metadata = paths.artifacts_dir().join(format!("{suffix}.meta"));
    std::fs::write(metadata, br#"{"owner_id":"#)?;
    assert!(store.get(&descriptor).is_err());
    Ok(())
}

#[test]
fn active_replacement_never_returns_unverified_bytes() -> TestResult {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let root = tempfile::tempdir()?;
    let paths = RunPaths::new(root.path());
    let store = artifact_store(&paths)?;
    let descriptor = store.put(b"evidence", "text/plain", Some("utf-8".into()))?;
    let path = artifact_path(&paths, &descriptor);
    let running = Arc::new(AtomicBool::new(true));
    let worker_running = Arc::clone(&running);
    let worker_path = path.clone();
    let worker = std::thread::spawn(move || {
        while worker_running.load(Ordering::Relaxed) {
            let _ = std::fs::write(&worker_path, b"attacker-bytes");
            let _ = std::fs::write(&worker_path, b"evidence");
        }
    });
    for _ in 0..200 {
        if let Ok(bytes) = store.get(&descriptor) {
            assert_eq!(bytes, b"evidence");
        }
    }
    running.store(false, Ordering::Relaxed);
    worker.join().map_err(|_| "replacement worker panicked")?;
    Ok(())
}
