use chrono::{DateTime, TimeDelta, Utc};
use recursive_agent_contracts::{
    content_digest, derive_run_id, derive_step_id, RunSpecV1, StepSpecV1, ToolCallSpecV1,
};
use recursive_agent_policy::{
    ActorPrincipalV1, DelegatedActionV1, DelegationCeilingV1, DelegationTransitionV1,
    DurablePermitStore, EffectScopeV1, PermitBindingV1, PermitBudgetV1, PermitRejectionReasonV1,
    PermitRevocationReasonV1, PermitStateV1, PermitTransitionStage, PolicyError,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type BindingMutation = fn(&mut PermitBindingV1) -> TestResult;
type RejectionCase = (PermitRejectionReasonV1, BindingMutation);

fn open_store(path: impl AsRef<std::path::Path>) -> Result<DurablePermitStore, PolicyError> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};

    let path = path.as_ref();
    let start = if path.is_absolute() { "/" } else { "." };
    let start_fd = rustix::fs::open(
        start,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let mut directory = std::fs::File::from(start_fd);
    for component in path.components() {
        let name = match component {
            std::path::Component::RootDir | std::path::Component::CurDir => continue,
            std::path::Component::Normal(name) => name,
            std::path::Component::ParentDir | std::path::Component::Prefix(_) => {
                return Err(PolicyError::UnsafePermitRoot(
                    "test root contains an invalid component".into(),
                ));
            }
        };
        let fd = rustix::fs::openat2(
            std::os::fd::AsFd::as_fd(&directory),
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(std::io::Error::from)?;
        directory = std::fs::File::from(fd);
    }
    DurablePermitStore::from_dir_fd(&directory)
}

fn now() -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(1_700_000_000)
}

fn binding() -> Result<PermitBindingV1, Box<dyn std::error::Error>> {
    let call = ToolCallSpecV1 {
        tool: "echo".into(),
        args: serde_json::json!({"text": "hello"}),
        frozen_clock: Some(now()),
    };
    let spec = RunSpecV1 {
        name: "permit-test".into(),
        steps: vec![StepSpecV1 {
            name: "step".into(),
            call: call.clone(),
        }],
        frozen_clock: Some(now()),
        policy_version: "policy-v1".into(),
    };
    let run_id = derive_run_id(&spec)?;
    let step_id = derive_step_id(&run_id, 0, "step", &call)?;
    let effect = EffectScopeV1 {
        scope_name: "pure".into(),
        read_roots: vec![],
        write_roots: vec![],
        network_allowed: false,
    };
    Ok(PermitBindingV1 {
        actor: ActorPrincipalV1::try_new("actor:test")?,
        action_digest: content_digest(&call)?,
        effect_digest: content_digest(&effect)?,
        effect,
        budget: PermitBudgetV1 {
            max_wall_time_ms: 1000,
            max_output_bytes: 4096,
            max_artifact_bytes: 8192,
        },
        policy_version: "policy-v1".into(),
        parent_permit_id: None,
        parent_operation_id: Some(run_id.clone()),
        issued_at: now(),
        not_before: now(),
        expires_at: now() + TimeDelta::seconds(60),
        run_id,
        step_id,
        tool: "echo".into(),
        args_digest: content_digest(&serde_json::json!({"text": "hello"}))?,
    })
}

fn rejection(error: PolicyError) -> Result<PermitRejectionReasonV1, Box<dyn std::error::Error>> {
    match error {
        PolicyError::PermitRejected { reason, .. } => Ok(reason),
        other => Err(format!("unexpected policy error: {other:?}").into()),
    }
}

#[test]
fn concurrent_and_restart_double_spend_are_rejected() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open_store(root.path())?;
    let binding = binding()?;
    let permit = store.issue(&binding, now())?;
    let mut joins = Vec::new();
    for _ in 0..12 {
        let store = store.clone();
        let permit_id = permit.permit_id.clone();
        let binding = binding.clone();
        joins.push(std::thread::spawn(move || {
            store.consume(&permit_id, &binding, now())
        }));
    }
    let mut successes = 0;
    let mut consumed_rejections = 0;
    for join in joins {
        match join.join().map_err(|_| "consumer thread panicked")? {
            Ok(_) => successes += 1,
            Err(error) => {
                if rejection(error)? == PermitRejectionReasonV1::AlreadyConsumed {
                    consumed_rejections += 1;
                } else {
                    return Err("unexpected rejection reason".into());
                }
            }
        }
    }
    assert_eq!(successes, 1);
    assert_eq!(consumed_rejections, 11);
    let reopened = open_store(root.path())?;
    assert_eq!(
        rejection(
            reopened
                .consume(&permit.permit_id, &binding, now())
                .err()
                .ok_or("reused permit unexpectedly consumed")?,
        )?,
        PermitRejectionReasonV1::AlreadyConsumed
    );
    Ok(())
}

#[test]
fn wrong_binding_expiry_and_revocation_are_typed() -> TestResult {
    let cases: Vec<RejectionCase> = vec![
        (PermitRejectionReasonV1::WrongActor, |value| {
            value.actor = ActorPrincipalV1::try_new("actor:other")?;
            Ok(())
        }),
        (PermitRejectionReasonV1::WrongAction, |value| {
            value.action_digest = content_digest(&"other")?;
            Ok(())
        }),
        (PermitRejectionReasonV1::ChangedEffect, |value| {
            value.effect.scope_name = "changed".into();
            value.effect_digest = content_digest(&value.effect)?;
            Ok(())
        }),
        (PermitRejectionReasonV1::BudgetExceeded, |value| {
            value.budget.max_wall_time_ms += 1;
            Ok(())
        }),
        (PermitRejectionReasonV1::WrongParent, |value| {
            value.parent_operation_id = None;
            Ok(())
        }),
        (PermitRejectionReasonV1::WrongPolicy, |value| {
            value.policy_version = "policy-v2".into();
            Ok(())
        }),
        (PermitRejectionReasonV1::WrongArguments, |value| {
            value.args_digest = content_digest(&"changed")?;
            Ok(())
        }),
    ];
    for (expected, mutate) in cases {
        let root = tempfile::tempdir()?;
        let store = open_store(root.path())?;
        let authorized = binding()?;
        let permit = store.issue(&authorized, now())?;
        let mut changed = authorized.clone();
        mutate(&mut changed)?;
        assert_eq!(
            rejection(
                store
                    .consume(&permit.permit_id, &changed, now())
                    .err()
                    .ok_or("changed binding unexpectedly consumed")?,
            )?,
            expected
        );
        assert!(matches!(
            store.state(&permit.permit_id)?.state,
            PermitStateV1::Issued
        ));
    }

    let root = tempfile::tempdir()?;
    let store = open_store(root.path())?;
    let authorized = binding()?;
    let permit = store.issue(&authorized, now())?;
    assert_eq!(
        rejection(
            store
                .consume(&permit.permit_id, &authorized, authorized.expires_at)
                .err()
                .ok_or("expired permit unexpectedly consumed")?,
        )?,
        PermitRejectionReasonV1::Expired
    );
    store.revoke(&permit.permit_id, PermitRevocationReasonV1::Operator, now())?;
    assert_eq!(
        rejection(
            store
                .consume(&permit.permit_id, &authorized, now())
                .err()
                .ok_or("revoked permit unexpectedly consumed")?,
        )?,
        PermitRejectionReasonV1::Revoked
    );
    Ok(())
}

#[test]
fn crash_points_reconcile_to_issued_or_consumed() -> TestResult {
    for stage in [
        PermitTransitionStage::TempWrite,
        PermitTransitionStage::TempFsync,
        PermitTransitionStage::Rename,
        PermitTransitionStage::DirectoryFsync,
    ] {
        let root = tempfile::tempdir()?;
        let store = open_store(root.path())?;
        let binding = binding()?;
        let permit = store.issue(&binding, now())?;
        let _ = store.consume_with_interruption(&permit.permit_id, &binding, now(), Some(stage));
        let reopened = open_store(root.path())?;
        match reopened.state(&permit.permit_id)?.state {
            PermitStateV1::Issued => {
                reopened.consume(&permit.permit_id, &binding, now())?;
            }
            PermitStateV1::Consumed { .. } => {
                assert_eq!(
                    rejection(
                        reopened
                            .consume(&permit.permit_id, &binding, now())
                            .err()
                            .ok_or("consumed permit unexpectedly reused")?,
                    )?,
                    PermitRejectionReasonV1::AlreadyConsumed
                );
            }
            PermitStateV1::Revoked { .. } => return Err("unexpected revoked state".into()),
        }
    }

    for stage in [
        PermitTransitionStage::TempWrite,
        PermitTransitionStage::TempFsync,
        PermitTransitionStage::Rename,
        PermitTransitionStage::DirectoryFsync,
    ] {
        let root = tempfile::tempdir()?;
        let store = open_store(root.path())?;
        let binding = binding()?;
        let permit = store.issue(&binding, now())?;
        let _ = store.revoke_with_interruption(
            &permit.permit_id,
            PermitRevocationReasonV1::Operator,
            now(),
            Some(stage),
        );
        let reopened = open_store(root.path())?;
        match reopened.state(&permit.permit_id)?.state {
            PermitStateV1::Issued => {
                reopened.revoke(&permit.permit_id, PermitRevocationReasonV1::Operator, now())?;
            }
            PermitStateV1::Revoked { .. } => {}
            PermitStateV1::Consumed { .. } => return Err("unexpected consumed state".into()),
        }
    }
    Ok(())
}

#[test]
fn revoked_parent_cannot_authorize_child_dispatch() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open_store(root.path())?;
    let parent_binding = binding()?;
    let mut child_binding = binding()?;
    let ceiling = DelegationCeilingV1 {
        actor: parent_binding.actor.clone(),
        policy_version: parent_binding.policy_version.clone(),
        run_id: parent_binding.run_id.clone(),
        transition: DelegationTransitionV1::ControlToEffect,
        audiences: vec![child_binding.tool.clone()],
        actions: vec![DelegatedActionV1 {
            tool: child_binding.tool.clone(),
            action_digest: child_binding.action_digest.clone(),
            args_digest: child_binding.args_digest.clone(),
            effect: child_binding.effect.clone(),
            effect_digest: child_binding.effect_digest.clone(),
            executable_authority: Vec::new(),
        }],
        budget: parent_binding.budget.clone(),
        not_before: parent_binding.not_before,
        expires_at: parent_binding.expires_at,
    };
    let parent = store.issue_control(&parent_binding, ceiling, now())?;
    child_binding.parent_permit_id = Some(parent.permit_id.clone());
    child_binding.parent_operation_id = Some(parent_binding.run_id.clone());
    let child = store.issue_effect(&child_binding, Vec::new(), now())?;
    store.revoke(&parent.permit_id, PermitRevocationReasonV1::Operator, now())?;
    let error = store
        .consume(&child.permit_id, &child_binding, now())
        .err()
        .ok_or("child dispatched after parent revocation")?;
    assert_eq!(rejection(error)?, PermitRejectionReasonV1::WrongParent);
    assert!(matches!(
        store.state(&child.permit_id)?.state,
        PermitStateV1::Issued
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn root_is_pinned_and_symlink_roots_are_rejected() -> TestResult {
    use std::os::unix::fs::symlink;

    let parent = tempfile::tempdir()?;
    let root = parent.path().join("permits");
    let pinned = parent.path().join("pinned");
    let attacker = parent.path().join("attacker");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(&attacker)?;
    let store = open_store(&root)?;
    std::fs::rename(&root, &pinned)?;
    symlink(&attacker, &root)?;
    let binding = binding()?;
    let permit = store.issue(&binding, now())?;
    assert!(store.state(&permit.permit_id).is_ok());
    assert_eq!(std::fs::read_dir(&attacker)?.count(), 0);
    assert!(open_store(&root).is_err());

    let intermediate_parent = tempfile::tempdir()?;
    let real_parent = intermediate_parent.path().join("real");
    let linked_parent = intermediate_parent.path().join("linked");
    std::fs::create_dir(&real_parent)?;
    symlink(&real_parent, &linked_parent)?;
    assert!(open_store(linked_parent.join("permits")).is_err());
    assert_eq!(std::fs::read_dir(&real_parent)?.count(), 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn permit_state_symlink_swap_is_rejected() -> TestResult {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir()?;
    let store = open_store(root.path())?;
    let binding = binding()?;
    let permit = store.issue(&binding, now())?;
    let entries = std::fs::read_dir(root.path())?.collect::<Result<Vec<_>, _>>()?;
    let state_path = entries
        .into_iter()
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("permit-") && name.ends_with(".json"))
        })
        .ok_or("permit state file missing")?;
    let attacker = root.path().join("attacker.json");
    std::fs::write(
        &attacker,
        serde_json::to_vec(&store.state(&permit.permit_id)?)?,
    )?;
    std::fs::remove_file(&state_path)?;
    symlink(&attacker, &state_path)?;
    assert!(store.consume(&permit.permit_id, &binding, now()).is_err());
    Ok(())
}

#[test]
fn unissued_parent_lease_is_rejected() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open_store(root.path())?;
    let mut child = binding()?;
    let parent_material = binding()?.identity_material()?;
    child.parent_permit_id = Some(recursive_agent_contracts::derive_permit_id(
        &parent_material,
    )?);
    assert!(store.issue(&child, now()).is_err());
    Ok(())
}

fn reported_success() -> recursive_agent_policy::ReportedEffectOutcomeV1 {
    recursive_agent_policy::ReportedEffectOutcomeV1 {
        state: recursive_agent_policy::ReportedEffectStateV1::Succeeded,
        duration_ms: 1,
        error_type: None,
    }
}

fn receipt_record(
    store: &DurablePermitStore,
    actor: &str,
    with_outcome: bool,
) -> Result<recursive_agent_policy::PermitRecordV1, Box<dyn std::error::Error>> {
    let mut binding = binding()?;
    binding.actor = ActorPrincipalV1::try_new(actor)?;
    let permit = store.issue(&binding, now())?;
    let preflight = store.consume_with_preflight(&permit.permit_id, &binding, now)?;
    if with_outcome {
        store.record_reported_outcome(
            &permit.permit_id,
            &preflight.receipt_digest,
            reported_success(),
            now() + TimeDelta::seconds(1),
        )?;
    }
    Ok(store.state(&permit.permit_id)?)
}

// Corruption fixtures only: locate a real owner-issued record in the TempDir.
fn record_path(
    root: &std::path::Path,
    record: &recursive_agent_policy::PermitRecordV1,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let stored: recursive_agent_policy::PermitRecordV1 =
                serde_json::from_slice(&std::fs::read(&path)?)?;
            if stored.permit.permit_id == record.permit.permit_id {
                return Ok(path);
            }
        }
    }
    Err("test-owned permit record not found".into())
}

fn assert_corrupt_record_rejected(
    root: &std::path::Path,
    record: recursive_agent_policy::PermitRecordV1,
) -> TestResult {
    let path = record_path(root, &record)?;
    let bytes = serde_json::to_vec(&record)?;
    std::fs::write(&path, &bytes)?;
    let reopened = open_store(root)?;
    let permit_id = &record.permit.permit_id;
    let digest = record.preflight_receipt.as_ref().map_or_else(
        || content_digest(&"missing preflight"),
        |preflight| Ok(preflight.receipt_digest.clone()),
    )?;
    for error in [
        reopened.state(permit_id).err(),
        reopened.normal_chat_preflight(permit_id).err(),
        reopened
            .record_reported_outcome(permit_id, &digest, reported_success(), now())
            .err(),
    ] {
        assert_eq!(
            rejection(error.ok_or("corrupt record was accepted")?)?,
            PermitRejectionReasonV1::StateCorrupted
        );
    }
    assert_eq!(
        std::fs::read(&path)?,
        bytes,
        "readback must not repair history"
    );
    Ok(())
}

#[test]
fn receipt_readback_rejects_same_root_preflight_substitution() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open_store(root.path())?;
    let mut selected = receipt_record(&store, "actor:selected", false)?;
    let other = receipt_record(&store, "actor:other", false)?;
    other
        .preflight_receipt
        .as_ref()
        .ok_or("missing preflight")?
        .validate()?;
    selected.preflight_receipt = other.preflight_receipt;
    assert_corrupt_record_rejected(root.path(), selected)
}

#[test]
fn receipt_readback_rejects_same_root_outcome_substitution() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open_store(root.path())?;
    let mut selected = receipt_record(&store, "actor:selected", true)?;
    let other = receipt_record(&store, "actor:other", true)?;
    other
        .outcome_receipt
        .as_ref()
        .ok_or("missing outcome")?
        .validate()?;
    selected.outcome_receipt = other.outcome_receipt;
    assert_corrupt_record_rejected(root.path(), selected)
}

#[test]
fn receipt_readback_rejects_outcome_without_preflight() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open_store(root.path())?;
    let mut selected = receipt_record(&store, "actor:selected", true)?;
    selected.preflight_receipt = None;
    assert_corrupt_record_rejected(root.path(), selected)
}

#[test]
fn receipt_readback_rejects_bad_receipt_digests() -> TestResult {
    for preflight in [true, false] {
        let root = tempfile::tempdir()?;
        let store = open_store(root.path())?;
        let mut selected = receipt_record(&store, "actor:selected", true)?;
        if preflight {
            selected
                .preflight_receipt
                .as_mut()
                .ok_or("missing preflight")?
                .receipt_digest = content_digest(&"bad preflight")?;
        } else {
            selected
                .outcome_receipt
                .as_mut()
                .ok_or("missing outcome")?
                .receipt_digest = content_digest(&"bad outcome")?;
        }
        assert_corrupt_record_rejected(root.path(), selected)?;
    }
    Ok(())
}

#[test]
fn receipt_readback_rejects_preflight_in_nonconsumed_states() -> TestResult {
    for state in [
        PermitStateV1::Issued,
        PermitStateV1::Revoked {
            revoked_at: now(),
            reason: PermitRevocationReasonV1::Operator,
        },
    ] {
        let root = tempfile::tempdir()?;
        let store = open_store(root.path())?;
        let mut selected = receipt_record(&store, "actor:selected", false)?;
        selected.state = state;
        assert_corrupt_record_rejected(root.path(), selected)?;
    }
    Ok(())
}

#[test]
fn receipt_readback_rejects_rehashed_preflight_timestamp_or_evidence() -> TestResult {
    for change_recorded_at in [true, false] {
        let root = tempfile::tempdir()?;
        let store = open_store(root.path())?;
        let mut selected = receipt_record(&store, "actor:selected", false)?;
        let preflight = selected
            .preflight_receipt
            .as_mut()
            .ok_or("missing preflight")?;
        if change_recorded_at {
            preflight.recorded_at += TimeDelta::seconds(1);
        } else {
            preflight.evidence.state = recursive_agent_policy::PermitEvidenceStateV1::Consumed {
                at: now() + TimeDelta::seconds(1),
            };
        }
        preflight.receipt_digest = content_digest(&(
            &preflight.permit_id,
            &preflight.evidence,
            preflight.recorded_at,
        ))?;
        preflight.validate()?;
        assert_corrupt_record_rejected(root.path(), selected)?;
    }
    Ok(())
}

#[test]
fn receipt_readback_rejects_rehashed_outcome_link_or_time() -> TestResult {
    for change_link in [true, false] {
        let root = tempfile::tempdir()?;
        let store = open_store(root.path())?;
        let mut selected = receipt_record(&store, "actor:selected", true)?;
        let outcome = selected.outcome_receipt.as_mut().ok_or("missing outcome")?;
        if change_link {
            outcome.preflight_receipt_digest = content_digest(&"other preflight")?;
        } else {
            outcome.recorded_at = now() - TimeDelta::seconds(1);
        }
        outcome.receipt_digest = content_digest(&(
            &outcome.permit_id,
            &outcome.preflight_receipt_digest,
            &outcome.reported,
            outcome.recorded_at,
        ))?;
        outcome.validate()?;
        assert_corrupt_record_rejected(root.path(), selected)?;
    }
    Ok(())
}

#[test]
fn receipt_outcome_refuses_clock_regression_without_writing() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open_store(root.path())?;
    let selected = receipt_record(&store, "actor:selected", false)?;
    let preflight = selected
        .preflight_receipt
        .as_ref()
        .ok_or("missing preflight")?;
    let path = record_path(root.path(), &selected)?;
    let before = std::fs::read(&path)?;
    assert!(store
        .record_reported_outcome(
            &selected.permit.permit_id,
            &preflight.receipt_digest,
            reported_success(),
            now() - TimeDelta::seconds(1),
        )
        .is_err());
    assert_eq!(std::fs::read(&path)?, before);
    Ok(())
}

#[test]
fn receipt_roundtrip_preserves_idempotency_and_legacy_consumption() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open_store(root.path())?;
    let selected = receipt_record(&store, "actor:selected", true)?;
    let reopened = open_store(root.path())?;
    assert_eq!(reopened.state(&selected.permit.permit_id)?, selected);
    let preflight = selected
        .preflight_receipt
        .as_ref()
        .ok_or("missing preflight")?;
    let outcome = selected.outcome_receipt.as_ref().ok_or("missing outcome")?;
    assert_eq!(
        reopened.record_reported_outcome(
            &selected.permit.permit_id,
            &preflight.receipt_digest,
            outcome.reported.clone(),
            outcome.recorded_at,
        )?,
        *outcome
    );
    assert_eq!(
        reopened.record_reported_outcome(
            &selected.permit.permit_id,
            &preflight.receipt_digest,
            outcome.reported.clone(),
            outcome.recorded_at + TimeDelta::seconds(1),
        )?,
        *outcome
    );
    assert_eq!(reopened.state(&selected.permit.permit_id)?, selected);
    let legacy_binding = binding()?;
    let legacy = store.issue(&legacy_binding, now())?;
    store.consume(&legacy.permit_id, &legacy_binding, now())?;
    let legacy_record = reopened.state(&legacy.permit_id)?;
    assert!(matches!(
        legacy_record.state,
        PermitStateV1::Consumed { .. }
    ));
    assert!(legacy_record.preflight_receipt.is_none());
    assert!(legacy_record.outcome_receipt.is_none());
    assert!(reopened
        .record_reported_outcome(
            &legacy.permit_id,
            &preflight.receipt_digest,
            reported_success(),
            now(),
        )
        .is_err());
    Ok(())
}

#[test]
fn external_readback_reconciles_reopen_without_consuming_or_replaying() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open_store(root.path())?;
    let binding = binding()?;
    let permit = store.issue(&binding, now())?;
    let issued = store.read_external_permit(&permit.permit_id, &binding, None)?;
    assert_eq!(issued.state, PermitStateV1::Issued);
    assert!(issued.preflight.is_none() && issued.outcome.is_none());
    let preflight = store.consume_with_preflight(&permit.permit_id, &binding, now)?;
    drop(store); // Consumption ACK was lost. Readback grants no second consumption.
    let reopened = open_store(root.path())?;
    let readback = reopened.read_external_permit(
        &permit.permit_id,
        &binding,
        Some(&preflight.receipt_digest),
    )?;
    assert_eq!(readback.preflight, Some(preflight.clone()));
    assert!(readback.outcome.is_none());
    assert!(reopened
        .consume_with_preflight(&permit.permit_id, &binding, now)
        .is_err());
    let outcome = reopened.record_reported_outcome(
        &permit.permit_id,
        &preflight.receipt_digest,
        reported_success(),
        now(),
    )?;
    let after = open_store(root.path())?.read_external_permit(
        &permit.permit_id,
        &binding,
        Some(&preflight.receipt_digest),
    )?;
    assert_eq!(after.outcome, Some(outcome));
    let mut wrong_binding = binding.clone();
    wrong_binding.actor = ActorPrincipalV1::try_new("actor:other")?;
    assert!(reopened
        .read_external_permit(&permit.permit_id, &wrong_binding, None)
        .is_err());
    assert!(reopened
        .read_external_permit(
            &permit.permit_id,
            &binding,
            Some(&content_digest(&"foreign")?),
        )
        .is_err());
    let mut conflicting = reported_success();
    conflicting.duration_ms += 1;
    assert!(matches!(
        reopened.record_reported_outcome(
            &permit.permit_id,
            &preflight.receipt_digest,
            conflicting,
            now() + TimeDelta::seconds(3),
        ),
        Err(PolicyError::PermitStateConflict)
    ));
    assert_eq!(
        reopened.read_external_permit(&permit.permit_id, &binding, None)?,
        after
    );
    Ok(())
}

#[test]
fn external_preflight_clock_is_sampled_after_store_lock_wait() -> TestResult {
    use std::os::fd::AsFd;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    };
    use std::time::Duration;
    let root = tempfile::tempdir()?;
    let store = open_store(root.path())?;
    let binding = binding()?;
    let permit = store.issue(&binding, now())?;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.path().join(".permit.lock"))?;
    rustix::fs::flock(lock.as_fd(), rustix::fs::FlockOperation::LockExclusive)?;
    let expired = Arc::new(AtomicBool::new(false));
    let selected_expired = Arc::clone(&expired);
    let selected_id = permit.permit_id.clone();
    let selected_binding = binding.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let (sample_tx, sample_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let _ = started_tx.send(());
        store.consume_with_preflight(&selected_id, &selected_binding, || {
            let _ = sample_tx.send(());
            if selected_expired.load(Ordering::SeqCst) {
                selected_binding.expires_at
            } else {
                now()
            }
        })
    });
    started_rx.recv_timeout(Duration::from_secs(2))?;
    assert!(matches!(
        sample_rx.recv_timeout(Duration::from_millis(50)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    expired.store(true, Ordering::SeqCst);
    rustix::fs::flock(lock.as_fd(), rustix::fs::FlockOperation::Unlock)?;
    assert!(matches!(
        worker.join().map_err(|_| "consume thread panicked")?,
        Err(PolicyError::PermitRejected {
            reason: PermitRejectionReasonV1::Expired,
            ..
        })
    ));
    assert_eq!(
        open_store(root.path())?.state(&permit.permit_id)?.state,
        PermitStateV1::Issued
    );
    Ok(())
}

#[test]
fn external_preflight_rechecks_final_clock_and_rejects_regression() -> TestResult {
    use std::cell::Cell;
    for final_time in [
        now() + TimeDelta::seconds(60),
        now() - TimeDelta::seconds(1),
    ] {
        let root = tempfile::tempdir()?;
        let store = open_store(root.path())?;
        let binding = binding()?;
        let permit = store.issue(&binding, now())?;
        let calls = Cell::new(0);
        assert!(store
            .consume_with_preflight(&permit.permit_id, &binding, || {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    now()
                } else {
                    final_time
                }
            })
            .is_err());
        assert_eq!(calls.get(), 2);
        assert_eq!(store.state(&permit.permit_id)?.state, PermitStateV1::Issued);
    }
    Ok(())
}
