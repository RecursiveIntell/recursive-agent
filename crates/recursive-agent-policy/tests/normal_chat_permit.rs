use chrono::{DateTime, TimeDelta, Utc};
use recursive_agent_contracts::{
    content_digest, derive_run_id, derive_step_id, ContentDigest, NormalChatAttemptV1,
    NormalChatBudgetV1, NormalChatOperationSchemaV1, NormalChatOperationV1, NormalChatReplayV1,
    ProvenanceRefV1, RunSpecV1, StepSpecV1, ToolCallSpecV1,
};
use recursive_agent_policy::{
    authorize_normal_chat, ActorPrincipalV1, DelegatedActionV1, DelegationCeilingV1,
    DelegationTransitionV1, DurablePermitStore, EffectScopeV1, NormalChatAdmissionRequestV1,
    NormalChatAdmissionVerifier, NormalChatPolicyValidityV1, PermitBindingV1, PermitBudgetV1,
    PermitEvidenceStateV1, PolicyError, ValidatedNormalChatAdmissionV1,
};

fn open_store(path: &std::path::Path) -> Result<DurablePermitStore, PolicyError> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let directory = std::fs::File::from(fd);
    let _ = ResolveFlags::NO_SYMLINKS;
    DurablePermitStore::from_dir_fd(&directory)
}

fn now() -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(1_700_000_000)
}

struct AllowCurrentEgress;

impl NormalChatAdmissionVerifier for AllowCurrentEgress {
    fn authorize(
        &self,
        _admission: &ValidatedNormalChatAdmissionV1,
    ) -> Result<NormalChatPolicyValidityV1, PolicyError> {
        Ok(NormalChatPolicyValidityV1 {
            not_before: now(),
            not_after: now() + TimeDelta::seconds(120),
        })
    }
}

#[test]
fn normal_chat_permit_is_current_bound_single_use_and_restart_safe(
) -> Result<(), Box<dyn std::error::Error>> {
    run_fixture(false, false)
}

#[test]
fn normal_chat_admission_cannot_issue_under_unrelated_run() -> Result<(), Box<dyn std::error::Error>>
{
    let error = run_fixture(true, false)
        .err()
        .ok_or("same admission issued under unrelated run")?;
    assert!(
        matches!(error.downcast_ref::<PolicyError>(), Some(PolicyError::InvalidLease(reason)) if reason == "normal-chat permit run identity differs from admitted attempt")
    );
    Ok(())
}

#[test]
fn normal_chat_attempt_cannot_reissue_with_changed_validity(
) -> Result<(), Box<dyn std::error::Error>> {
    let error = run_fixture(false, true)
        .err()
        .ok_or("same attempt consumed through two distinct permits")?;
    assert!(
        matches!(error.downcast_ref::<PolicyError>(), Some(PolicyError::InvalidLease(reason)) if reason == "normal-chat attempt already has an effect permit")
    );
    Ok(())
}

#[test]
fn competing_normal_chat_issuers_share_durable_uniqueness() -> Result<(), Box<dyn std::error::Error>>
{
    run_fixture_mode(false, false, true, false)
}

#[test]
fn normal_chat_retry_family_allows_distinct_attempts_under_one_run(
) -> Result<(), Box<dyn std::error::Error>> {
    run_fixture_mode(false, false, false, true)
}

fn run_fixture(unrelated_run: bool, reissue: bool) -> Result<(), Box<dyn std::error::Error>> {
    run_fixture_mode(unrelated_run, reissue, false, false)
}

fn run_fixture_mode(
    unrelated_run: bool,
    reissue: bool,
    race: bool,
    retry_family: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let store = open_store(root.path())?;
    let request = serde_json::json!({
        "kind": "ollama",
        "model": "fixture-model",
        "prompt": "exact sealed prompt",
        "max_tokens": 8
    });
    let operation = NormalChatOperationV1 {
        schema: NormalChatOperationSchemaV1::V1,
        conversation_ref: "conversation:permit-test".into(),
        parent_run_id: None,
        materialization_ref: "materialization:test".into(),
        materialization_digest: format!("sha256:{}", "a".repeat(64)),
        policy_basis_ref: "policy:test".into(),
        policy_basis_digest: format!("blake3:{}", "b".repeat(64)),
        source_revision: "source:test".into(),
        route_class: "candidate".into(),
        provider_identity: "ollama:http://127.0.0.1:11434".into(),
        model_ref: "model:fixture-model".into(),
        request_digest: format!("sha256:{}", "c".repeat(64)),
        budget: NormalChatBudgetV1 {
            max_attempts: if retry_family { 2 } else { 1 },
            input_tokens: 4,
            output_reserve: 8,
            max_wall_time_ms: 1000,
        },
        replay: NormalChatReplayV1::RecordedResponseOnly,
        provenance: vec![ProvenanceRefV1 {
            source: "urn:test:normal-chat-permit".into(),
            digest: ContentDigest::compute(b"fixture"),
        }],
    };
    let operation_for_retry = operation.clone();
    let attempt = NormalChatAttemptV1::new(operation, 1, content_digest(&request)?)?;
    let tool_args = serde_json::json!({"attempt": attempt.clone(), "request": request.clone()});
    let args_digest = content_digest(&tool_args)?;
    let admission_request =
        NormalChatAdmissionRequestV1::new("normal_chat", attempt.clone(), args_digest.clone())?;
    let admission = authorize_normal_chat(&AllowCurrentEgress, &admission_request, now())?;

    let call = ToolCallSpecV1 {
        tool: "normal_chat".into(),
        args: tool_args,
        frozen_clock: None,
    };
    let spec = RunSpecV1 {
        name: "provider-egress-permit-fixture".into(),
        steps: vec![StepSpecV1 {
            name: "normal_chat".into(),
            call: call.clone(),
        }],
        frozen_clock: None,
        policy_version: "candidate-egress-v1".into(),
    };
    let run_id = if unrelated_run {
        derive_run_id(&spec)?
    } else {
        admission.attempt().run_id()?
    };
    let step_id = derive_step_id(&run_id, 0, "normal_chat", &call)?;
    let effect = EffectScopeV1 {
        scope_name: "normal_chat".into(),
        read_roots: Vec::new(),
        write_roots: Vec::new(),
        network_allowed: true,
    };
    let budget = PermitBudgetV1 {
        max_wall_time_ms: 1_000,
        max_output_bytes: 4_096,
        max_artifact_bytes: 4_096,
    };
    let lifecycle_call = ToolCallSpecV1 {
        tool: "runner.lifecycle".into(),
        args: serde_json::json!({"operation": "provider-egress-v3"}),
        frozen_clock: None,
    };
    let lifecycle_step_id = derive_step_id(&run_id, 1, "run-lifecycle", &lifecycle_call)?;
    let lifecycle_effect = EffectScopeV1 {
        scope_name: "runner.lifecycle".into(),
        read_roots: Vec::new(),
        write_roots: Vec::new(),
        network_allowed: false,
    };
    let actor = ActorPrincipalV1::try_new("recursive-agent")?;
    let control_binding = PermitBindingV1 {
        actor: actor.clone(),
        action_digest: content_digest(&lifecycle_call)?,
        effect_digest: content_digest(&lifecycle_effect)?,
        effect: lifecycle_effect,
        budget: PermitBudgetV1 {
            max_wall_time_ms: 2000,
            max_output_bytes: 8192,
            max_artifact_bytes: 8192,
        },
        policy_version: "candidate-egress-v1".into(),
        parent_permit_id: None,
        parent_operation_id: Some(run_id.clone()),
        issued_at: now(),
        not_before: now(),
        expires_at: now() + TimeDelta::seconds(60),
        run_id: run_id.clone(),
        step_id: lifecycle_step_id,
        tool: "runner.lifecycle".into(),
        args_digest: content_digest(&lifecycle_call.args)?,
    };
    let ceiling = DelegationCeilingV1 {
        actor: actor.clone(),
        policy_version: "candidate-egress-v1".into(),
        run_id: run_id.clone(),
        transition: DelegationTransitionV1::ControlToEffect,
        audiences: vec!["normal_chat".into()],
        actions: vec![DelegatedActionV1 {
            tool: "normal_chat".into(),
            action_digest: content_digest(&call)?,
            args_digest: args_digest.clone(),
            effect: effect.clone(),
            effect_digest: content_digest(&effect)?,
            executable_authority: Vec::new(),
        }],
        budget: PermitBudgetV1 {
            max_wall_time_ms: 2000,
            max_output_bytes: 8192,
            max_artifact_bytes: 8192,
        },
        not_before: now(),
        expires_at: now() + TimeDelta::seconds(60),
    };
    let control = store.issue_control(&control_binding, ceiling, now())?;
    let dispatch_time = now() + TimeDelta::milliseconds(1);
    let effect_binding = PermitBindingV1 {
        actor,
        action_digest: content_digest(&call)?,
        effect_digest: content_digest(&effect)?,
        effect,
        budget,
        policy_version: "candidate-egress-v1".into(),
        parent_permit_id: Some(control.permit_id.clone()),
        parent_operation_id: Some(run_id.clone()),
        issued_at: dispatch_time,
        not_before: dispatch_time,
        expires_at: now() + TimeDelta::seconds(30),
        run_id: run_id.clone(),
        step_id,
        tool: "normal_chat".into(),
        args_digest,
    };

    assert!(store
        .issue_effect(&effect_binding, Vec::new(), now())
        .is_err());
    assert!(store
        .issue_normal_chat(
            &effect_binding,
            &admission,
            &call,
            &recursive_agent_policy::DenyNormalChatAdmission,
            dispatch_time
        )
        .is_err());
    if !unrelated_run {
        let mut changed_action = effect_binding.clone();
        changed_action.action_digest = content_digest(&"unrelated action")?;
        let error = store
            .issue_normal_chat(
                &changed_action,
                &admission,
                &call,
                &AllowCurrentEgress,
                dispatch_time,
            )
            .err()
            .ok_or("action drift accepted")?;
        assert!(
            matches!(error, PolicyError::InvalidLease(ref reason) if reason == "normal-chat dispatch binding mismatch")
        );
        let mut changed_step = effect_binding.clone();
        changed_step.step_id = derive_step_id(&changed_step.run_id, 99, "normal_chat", &call)?;
        assert!(
            matches!(store.issue_normal_chat(&changed_step, &admission, &call, &AllowCurrentEgress, dispatch_time), Err(PolicyError::InvalidLease(ref reason)) if reason == "normal-chat dispatch binding mismatch")
        );
        let mut changed_call = call.clone();
        changed_call.args["request"]["prompt"] = serde_json::json!("substituted");
        assert!(
            matches!(store.issue_normal_chat(&effect_binding, &admission, &changed_call, &AllowCurrentEgress, dispatch_time), Err(PolicyError::InvalidLease(ref reason)) if reason == "normal-chat dispatch binding mismatch")
        );
    }
    let mut wrong_args = effect_binding.clone();
    wrong_args.args_digest = content_digest(&"different arguments")?;
    assert!(store
        .issue_normal_chat(
            &wrong_args,
            &admission,
            &call,
            &AllowCurrentEgress,
            dispatch_time
        )
        .is_err());
    let mut no_parent = effect_binding.clone();
    no_parent.parent_permit_id = None;
    assert!(store
        .issue_normal_chat(
            &no_parent,
            &admission,
            &call,
            &AllowCurrentEgress,
            dispatch_time
        )
        .is_err());
    let mut oversized_budget = effect_binding.clone();
    oversized_budget.budget.max_wall_time_ms += 1;
    assert!(store
        .issue_normal_chat(
            &oversized_budget,
            &admission,
            &call,
            &AllowCurrentEgress,
            dispatch_time
        )
        .is_err());
    assert!(store
        .issue_normal_chat(
            &effect_binding,
            &admission,
            &call,
            &AllowCurrentEgress,
            admission.expires_at()
        )
        .is_err());
    if race {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let path = root.path();
        let outcomes = std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for ordinal in 0..2 {
                let mut binding = effect_binding.clone();
                binding.expires_at -= TimeDelta::seconds(ordinal);
                let admission = &admission;
                let call = &call;
                let barrier = barrier.clone();
                workers.push(scope.spawn(move || {
                    let independent_store = open_store(path)?;
                    barrier.wait();
                    independent_store.issue_normal_chat(
                        &binding,
                        admission,
                        call,
                        &AllowCurrentEgress,
                        dispatch_time,
                    )
                }));
            }
            workers
                .into_iter()
                .map(|worker| worker.join())
                .collect::<Vec<_>>()
        });
        let mut winners = 0;
        for joined in outcomes {
            match joined.map_err(|_| "issuer thread panicked")? {
                Ok(_) => winners += 1,
                Err(PolicyError::InvalidLease(reason)) => {
                    assert_eq!(reason, "normal-chat attempt already has an effect permit")
                }
                Err(error) => return Err(error.into()),
            }
        }
        assert_eq!(winners, 1);
        return Ok(());
    }
    if !unrelated_run {
        let snapshot = || -> Result<std::collections::BTreeMap<String, Vec<u8>>, std::io::Error> {
            let mut records = std::collections::BTreeMap::new();
            for entry in std::fs::read_dir(root.path())? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with("permit-") && name.ends_with(".json") {
                    records.insert(name, std::fs::read(entry.path())?);
                }
            }
            Ok(records)
        };
        let baseline = snapshot()?;
        let poison = root.path().join("permit-corrupt.json");
        std::fs::write(&poison, b"{}")?;
        assert!(store
            .issue_normal_chat(
                &effect_binding,
                &admission,
                &call,
                &AllowCurrentEgress,
                dispatch_time
            )
            .is_err());
        std::fs::remove_file(&poison)?;
        assert_eq!(snapshot()?, baseline);

        let outside = tempfile::NamedTempFile::new()?;
        std::os::unix::fs::symlink(outside.path(), &poison)?;
        assert!(store
            .issue_normal_chat(
                &effect_binding,
                &admission,
                &call,
                &AllowCurrentEgress,
                dispatch_time
            )
            .is_err());
        assert_eq!(std::fs::metadata(outside.path())?.len(), 0);
        std::fs::remove_file(&poison)?;
        assert_eq!(snapshot()?, baseline);

        let oversized = std::fs::File::create(&poison)?;
        oversized.set_len(1024 * 1024 + 1)?;
        drop(oversized);
        assert!(store
            .issue_normal_chat(
                &effect_binding,
                &admission,
                &call,
                &AllowCurrentEgress,
                dispatch_time
            )
            .is_err());
        std::fs::remove_file(&poison)?;
        assert_eq!(snapshot()?, baseline);

        for index in 0..4096 {
            std::fs::write(root.path().join(format!(".scan-test-{index}")), b"")?;
        }
        let error = store
            .issue_normal_chat(
                &effect_binding,
                &admission,
                &call,
                &AllowCurrentEgress,
                dispatch_time,
            )
            .err()
            .ok_or("unbounded scan admitted")?;
        assert!(
            matches!(error, PolicyError::InvalidLease(ref reason) if reason == "normal-chat permit directory scan limit exceeded")
        );
        for index in 0..4096 {
            std::fs::remove_file(root.path().join(format!(".scan-test-{index}")))?;
        }
        assert_eq!(snapshot()?, baseline);
    }
    // Real clocks advance between policy evaluation and durable permit issue.
    // The admission remains valid while its sealed binding remains current.
    let permit = store.issue_normal_chat(
        &effect_binding,
        &admission,
        &call,
        &AllowCurrentEgress,
        dispatch_time,
    )?;
    assert!(store
        .consume(&permit.permit_id, &effect_binding, dispatch_time)
        .is_err());
    assert!(store
        .consume_with_preflight(&permit.permit_id, &effect_binding, dispatch_time)
        .is_err());
    assert!(store
        .consume_with_interruption(&permit.permit_id, &effect_binding, dispatch_time, None)
        .is_err());
    let denied = store.consume_normal_chat(
        &permit.permit_id,
        &admission,
        &call,
        &recursive_agent_policy::DenyNormalChatAdmission,
        || dispatch_time,
    );
    assert!(matches!(denied, Err(PolicyError::NetworkUnavailable)));
    // The clock must be sampled while the OS permit lock is held, not before waiting.
    let independent_lock = std::fs::File::open(root.path().join(".permit.lock"))?;
    let mut sampled = false;
    let expired = store.consume_normal_chat(
        &permit.permit_id,
        &admission,
        &call,
        &AllowCurrentEgress,
        || {
            use rustix::fs::{flock, FlockOperation};
            assert!(flock(&independent_lock, FlockOperation::NonBlockingLockExclusive).is_err());
            sampled = true;
            admission.expires_at()
        },
    );
    assert!(sampled);
    assert!(expired.is_err());
    for final_time in [
        admission.expires_at(),
        effect_binding.expires_at,
        dispatch_time - TimeDelta::nanoseconds(1),
    ] {
        let mut clock_reads = 0;
        let stale = store.consume_normal_chat(
            &permit.permit_id,
            &admission,
            &call,
            &AllowCurrentEgress,
            || {
                clock_reads += 1;
                if clock_reads == 1 {
                    dispatch_time
                } else {
                    final_time
                }
            },
        );
        assert!(
            stale.is_err(),
            "consumed after validity changed during verification"
        );
        assert_eq!(clock_reads, 2);
    }
    // Denied recheck leaves the record issued, so current policy can still consume it.
    let consumed = store.consume_normal_chat(
        &permit.permit_id,
        &admission,
        &call,
        &AllowCurrentEgress,
        || dispatch_time,
    )?;
    assert!(matches!(
        consumed.state,
        PermitEvidenceStateV1::Consumed { .. }
    ));
    assert!(consumed.binding.effect.network_allowed);
    if retry_family {
        let retry_attempt =
            NormalChatAttemptV1::new(operation_for_retry.clone(), 2, content_digest(&request)?)?;
        let retry_args = serde_json::json!({
            "attempt": retry_attempt.clone(),
            "request": request.clone()
        });
        let retry_args_digest = content_digest(&retry_args)?;
        let retry_admission_request = NormalChatAdmissionRequestV1::new(
            "normal_chat",
            retry_attempt.clone(),
            retry_args_digest.clone(),
        )?;
        let retry_admission =
            authorize_normal_chat(&AllowCurrentEgress, &retry_admission_request, now())?;
        let retry_call = ToolCallSpecV1 {
            tool: "normal_chat".into(),
            args: retry_args,
            frozen_clock: None,
        };
        let mut retry_binding = effect_binding.clone();
        retry_binding.action_digest = content_digest(&retry_call)?;
        retry_binding.args_digest = retry_args_digest;
        retry_binding.step_id = derive_step_id(&run_id, 0, "normal_chat", &retry_call)?;
        eprintln!(
            "RETRY_DIAG parent={:?} parent_actions={:?} original_action={} original_args={} retry_action={} retry_args={} original_effect={:?} retry_effect={:?} original_effect_digest={} retry_effect_digest={} original_run={} retry_run={} original_op={} retry_op={} retry_attempt={:?}",
            control.permit_id,
            control.delegation_ceiling.as_ref().map(|ceiling| &ceiling.actions),
            effect_binding.action_digest,
            effect_binding.args_digest,
            retry_binding.action_digest,
            retry_binding.args_digest,
            effect_binding.effect,
            retry_binding.effect,
            effect_binding.effect_digest,
            retry_binding.effect_digest,
            effect_binding.run_id,
            retry_binding.run_id,
            content_digest(&attempt.operation)?,
            content_digest(&retry_attempt.operation)?,
            retry_attempt.attempt_id,
        );
        let retry_permit = match store.issue_normal_chat(
            &retry_binding,
            &retry_admission,
            &retry_call,
            &AllowCurrentEgress,
            dispatch_time,
        ) {
            Ok(permit) => permit,
            Err(error) => {
                println!("retry issue error: {error:?}");
                return Err(error.into());
            }
        };
        assert_ne!(retry_permit.permit_id, permit.permit_id);
        store.consume_normal_chat(
            &retry_permit.permit_id,
            &retry_admission,
            &retry_call,
            &AllowCurrentEgress,
            || dispatch_time,
        )?;
        assert!(
            NormalChatAttemptV1::new(operation_for_retry, 3, content_digest(&request)?,).is_err()
        );
    }
    drop(store);
    let reopened = open_store(root.path())?;
    if reissue {
        let mut second_binding = effect_binding.clone();
        second_binding.expires_at -= TimeDelta::seconds(1);
        let second = reopened.issue_normal_chat(
            &second_binding,
            &admission,
            &call,
            &AllowCurrentEgress,
            dispatch_time,
        )?;
        assert_ne!(second.permit_id, permit.permit_id);
        reopened.consume_normal_chat(
            &second.permit_id,
            &admission,
            &call,
            &AllowCurrentEgress,
            || dispatch_time,
        )?;
    }
    assert!(reopened
        .consume_normal_chat(
            &permit.permit_id,
            &admission,
            &call,
            &AllowCurrentEgress,
            || dispatch_time
        )
        .is_err());
    assert!(reopened
        .consume(&permit.permit_id, &effect_binding, dispatch_time)
        .is_err());
    Ok(())
}
