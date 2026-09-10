use chrono::{DateTime, TimeDelta, Utc};
use recursive_agent_contracts::{
    content_digest, derive_step_id, ContentDigest, NormalChatAttemptV1, NormalChatBudgetV1,
    NormalChatOperationSchemaV1, NormalChatOperationV1, NormalChatReplayV1, ProvenanceRefV1,
    ToolCallSpecV1,
};
use recursive_agent_policy::{
    authorize_normal_chat, ActorPrincipalV1, DelegatedActionV1, DelegationCeilingV1,
    DelegationTransitionV1, DurablePermitStore, EffectScopeV1, NormalChatAdmissionRequestV1,
    NormalChatAdmissionVerifier, NormalChatPolicyValidityV1, PermitBindingV1, PermitBudgetV1,
    PolicyError, ValidatedNormalChatAdmissionV1,
};
use std::sync::atomic::{AtomicUsize, Ordering};

fn now() -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(1_700_000_000)
}

fn open_store(path: &std::path::Path) -> Result<DurablePermitStore, PolicyError> {
    use rustix::fs::{Mode, OFlags};
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    DurablePermitStore::from_dir_fd(&std::fs::File::from(fd))
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

struct TestClock;
impl recursive_agent_runner::Clock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        now() + TimeDelta::milliseconds(2)
    }
}

struct Backend(AtomicUsize);
impl recursive_agent_provider::CompletionBackend for Backend {
    fn complete(
        &self,
        _request: &recursive_agent_provider::CompletionRequestV1,
    ) -> Result<
        recursive_agent_provider::CompletionResponseV1,
        recursive_agent_provider::ProviderError,
    > {
        Err(recursive_agent_provider::ProviderError::Unavailable)
    }

    fn complete_conversation(
        &self,
        _request: &recursive_agent_provider::ConversationRequestV1,
    ) -> Result<
        recursive_agent_provider::CompletionResponseV1,
        recursive_agent_provider::ProviderError,
    > {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(recursive_agent_provider::CompletionResponseV1 {
            model: "fixture-model".into(),
            text: "fixture response".into(),
            raw: serde_json::json!({"fixture": true}),
        })
    }
}

#[test]
fn recorded_response_replays_after_restart_without_backend_reexecution(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let store = open_store(root.path())?;
    let request = recursive_agent_provider::ConversationRequestV1::try_new(
        recursive_agent_provider::ProviderSpecV1::OpenAiCompatible {
            base_url: recursive_agent_provider::ValidatedEndpoint::try_new(
                "https://provider.test/",
            )?,
            model: "fixture-model".into(),
            credential_ref: recursive_agent_provider::CredentialRef::try_new(
                "environment:UNUSED_TEST_KEY",
            )?,
        },
        vec![recursive_agent_provider::ConversationMessageV1::new(
            recursive_agent_provider::ConversationRoleV1::User,
            "hello",
        )],
        Some(8),
    )?;
    let operation = NormalChatOperationV1 {
        schema: NormalChatOperationSchemaV1::V1,
        conversation_ref: "conversation:replay-test".into(),
        parent_run_id: None,
        materialization_ref: "materialization:replay-test".into(),
        materialization_digest: format!("sha256:{}", "a".repeat(64)),
        policy_basis_ref: "policy:replay-test".into(),
        policy_basis_digest: format!("blake3:{}", "b".repeat(64)),
        source_revision: "source:replay-test".into(),
        route_class: "candidate".into(),
        provider_identity: request.provider.egress_provider_identity(),
        model_ref: request.provider.egress_model_ref(),
        request_digest: format!("sha256:{}", "c".repeat(64)),
        budget: NormalChatBudgetV1 {
            max_attempts: 1,
            input_tokens: 4,
            output_reserve: 8,
            max_wall_time_ms: 1_000,
        },
        replay: NormalChatReplayV1::RecordedResponseOnly,
        provenance: vec![ProvenanceRefV1 {
            source: "urn:test:recorded-normal-chat-replay".into(),
            digest: ContentDigest::compute(b"replay-fixture"),
        }],
    };
    let attempt = NormalChatAttemptV1::new(operation, 1, content_digest(&request)?)?;
    let args = serde_json::json!({"attempt": attempt, "request": request});
    let args_digest = content_digest(&args)?;
    let admission_request =
        NormalChatAdmissionRequestV1::new("normal_chat", attempt, args_digest.clone())?;
    let admission = authorize_normal_chat(&AllowCurrentEgress, &admission_request, now())?;
    let call = ToolCallSpecV1 {
        tool: "normal_chat".into(),
        args,
        frozen_clock: None,
    };
    let run_id = admission.attempt().run_id()?;
    let step_id = derive_step_id(&run_id, 0, "normal_chat", &call)?;
    let effect = EffectScopeV1 {
        scope_name: "normal_chat".into(),
        read_roots: Vec::new(),
        write_roots: Vec::new(),
        network_allowed: true,
    };
    let actor = ActorPrincipalV1::try_new("recursive-agent")?;
    let lifecycle = ToolCallSpecV1 {
        tool: "runner.lifecycle".into(),
        args: serde_json::json!({"operation": "normal-chat-replay-test"}),
        frozen_clock: None,
    };
    let lifecycle_effect = EffectScopeV1 {
        scope_name: "runner.lifecycle".into(),
        read_roots: Vec::new(),
        write_roots: Vec::new(),
        network_allowed: false,
    };
    let control_binding = PermitBindingV1 {
        actor: actor.clone(),
        action_digest: content_digest(&lifecycle)?,
        effect_digest: content_digest(&lifecycle_effect)?,
        effect: lifecycle_effect,
        budget: PermitBudgetV1 {
            max_wall_time_ms: 2_000,
            max_output_bytes: 8_192,
            max_artifact_bytes: 8_192,
        },
        policy_version: "replay-test-v1".into(),
        parent_permit_id: None,
        parent_operation_id: Some(run_id.clone()),
        issued_at: now(),
        not_before: now(),
        expires_at: now() + TimeDelta::seconds(60),
        run_id: run_id.clone(),
        step_id: derive_step_id(&run_id, 1, "run-lifecycle", &lifecycle)?,
        tool: "runner.lifecycle".into(),
        args_digest: content_digest(&lifecycle.args)?,
    };
    let ceiling = DelegationCeilingV1 {
        actor: actor.clone(),
        policy_version: "replay-test-v1".into(),
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
            max_wall_time_ms: 2_000,
            max_output_bytes: 8_192,
            max_artifact_bytes: 8_192,
        },
        not_before: now(),
        expires_at: now() + TimeDelta::seconds(60),
    };
    let control = store.issue_control(&control_binding, ceiling, now())?;
    let dispatch = now() + TimeDelta::milliseconds(1);
    let effect_binding = PermitBindingV1 {
        actor,
        action_digest: content_digest(&call)?,
        effect_digest: content_digest(&effect)?,
        effect,
        budget: PermitBudgetV1 {
            max_wall_time_ms: 1_000,
            max_output_bytes: 4_096,
            max_artifact_bytes: 4_096,
        },
        policy_version: "replay-test-v1".into(),
        parent_permit_id: Some(control.permit_id),
        parent_operation_id: Some(run_id.clone()),
        issued_at: dispatch,
        not_before: dispatch,
        expires_at: now() + TimeDelta::seconds(30),
        run_id,
        step_id,
        tool: "normal_chat".into(),
        args_digest,
    };
    let permit = store.issue_normal_chat(
        &effect_binding,
        &admission,
        &call,
        &AllowCurrentEgress,
        dispatch,
    )?;

    let root_fd = std::fs::File::open(root.path())?;
    let artifacts = recursive_agent_ledger::ArtifactStore::from_run_root_fd(&root_fd, true)?;
    let backend = Backend(AtomicUsize::new(0));
    let executor = recursive_agent_runner::NativeNormalChatExecutor::new(
        &store,
        &artifacts,
        &AllowCurrentEgress,
        &TestClock,
        &backend,
    );
    let observed = executor.execute(&permit.permit_id, &admission, &request)?;
    assert_eq!(backend.0.load(Ordering::SeqCst), 1);

    drop(executor);
    drop(store);
    drop(artifacts);

    let reopened_store = open_store(root.path())?;
    let reopened_fd = std::fs::File::open(root.path())?;
    let reopened_artifacts =
        recursive_agent_ledger::ArtifactStore::from_run_root_fd(&reopened_fd, false)?;
    let replayed = recursive_agent_runner::NativeNormalChatObservation::replay_recorded_response(
        &reopened_store,
        &reopened_artifacts,
        &observed.observation_artifact,
        &admission.attempt().attempt_id,
        &permit.permit_id,
    )?;
    assert_eq!(replayed.text, "fixture response");
    assert_eq!(backend.0.load(Ordering::SeqCst), 1);

    let replayed_again =
        recursive_agent_runner::NativeNormalChatObservation::replay_recorded_response(
            &reopened_store,
            &reopened_artifacts,
            &observed.observation_artifact,
            &admission.attempt().attempt_id,
            &permit.permit_id,
        )?;
    assert_eq!(replayed_again, replayed);
    assert_eq!(backend.0.load(Ordering::SeqCst), 1);

    let mut other_operation = admission.attempt().operation.clone();
    other_operation.conversation_ref = "conversation:other".into();
    let other_attempt = NormalChatAttemptV1::new(other_operation, 1, content_digest(&request)?)?;
    assert!(matches!(
        recursive_agent_runner::NativeNormalChatObservation::replay_recorded_response(
            &reopened_store,
            &reopened_artifacts,
            &observed.observation_artifact,
            &other_attempt.attempt_id,
            &permit.permit_id,
        ),
        Err(recursive_agent_runner::NativeNormalChatError::ReplayBindingMismatch)
    ));
    assert_eq!(backend.0.load(Ordering::SeqCst), 1);

    let mut tampered_descriptor = observed.observation_artifact.clone();
    tampered_descriptor.byte_length = tampered_descriptor.byte_length.saturating_add(1);
    assert!(recursive_agent_runner::NativeNormalChatObservation::replay_recorded_response(
        &reopened_store,
        &reopened_artifacts,
        &tampered_descriptor,
        &admission.attempt().attempt_id,
        &permit.permit_id,
    )
    .is_err());
    assert_eq!(backend.0.load(Ordering::SeqCst), 1);

    let original_observation = reopened_artifacts.get(&observed.observation_artifact)?;
    let mut unknown_schema: serde_json::Value = serde_json::from_slice(&original_observation)?;
    unknown_schema["schema"] = serde_json::Value::String(
        "recursive-agent.normal-chat-observation/v999".into(),
    );
    let unknown_artifact = reopened_artifacts.put(
        &serde_json::to_vec(&unknown_schema)?,
        "application/json",
        None,
    )?;
    assert!(matches!(
        recursive_agent_runner::NativeNormalChatObservation::replay_recorded_response(
            &reopened_store,
            &reopened_artifacts,
            &unknown_artifact,
            &admission.attempt().attempt_id,
            &permit.permit_id,
        ),
        Err(recursive_agent_runner::NativeNormalChatError::ReplayObservationMalformed)
    ));
    assert_eq!(backend.0.load(Ordering::SeqCst), 1);

    Ok(())
}
