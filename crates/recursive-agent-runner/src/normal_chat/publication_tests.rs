//! Private-loader witnesses with real disposable permit and artifact owners.
//! No production hook or public replay accessor is added.
use super::*;
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

struct TestClock;
impl crate::Clock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        now() + TimeDelta::milliseconds(1)
    }
}

struct Fixture {
    root: tempfile::TempDir,
    store: DurablePermitStore,
    artifacts: ArtifactStore,
    admission: ValidatedNormalChatAdmissionV1,
    request: ConversationRequestV1,
    permit_id: CurrentPermitId,
}

impl Fixture {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
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
            conversation_ref: format!("conversation:{label}"),
            parent_run_id: None,
            materialization_ref: "materialization:test".into(),
            materialization_digest: format!("sha256:{}", "a".repeat(64)),
            policy_basis_ref: "policy:test".into(),
            policy_basis_digest: format!("blake3:{}", "b".repeat(64)),
            source_revision: "source:test".into(),
            route_class: "candidate".into(),
            provider_identity: request.provider.egress_provider_identity(),
            model_ref: "model:fixture-model".into(),
            request_digest: format!("sha256:{}", "c".repeat(64)),
            budget: NormalChatBudgetV1 {
                max_attempts: 1,
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
        let attempt = NormalChatAttemptV1::new(operation, 1, content_digest(&request)?)?;
        let tool_args = serde_json::json!({"attempt": attempt, "request": request});
        let args_digest = content_digest(&tool_args)?;
        let admission_request =
            NormalChatAdmissionRequestV1::new("normal_chat", attempt, args_digest.clone())?;
        let admission = authorize_normal_chat(&AllowCurrentEgress, &admission_request, now())?;

        let call = ToolCallSpecV1 {
            tool: "normal_chat".into(),
            args: tool_args,
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
            parent_permit_id: Some(control.permit_id),
            parent_operation_id: Some(run_id.clone()),
            issued_at: dispatch_time,
            not_before: dispatch_time,
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
            dispatch_time,
        )?;
        let root_fd = std::fs::File::open(root.path())?;
        let artifacts = recursive_agent_ledger::ArtifactStore::from_run_root_fd(&root_fd, true)?;
        Ok(Self {
            root,
            store,
            artifacts,
            admission,
            request,
            permit_id: permit.permit_id,
        })
    }

    // Publish through real owners but stop before settlement, so the private
    // runner validator is challenged at its actual pre-settlement boundary.
    fn publish(
        &self,
    ) -> Result<
        (
            recursive_agent_policy::NormalChatConsumption,
            ArtifactDescriptorV1,
            ArtifactDescriptorV1,
        ),
        Box<dyn std::error::Error>,
    > {
        let call = ToolCallSpecV1 {
            tool: "normal_chat".into(),
            args: serde_json::json!({"attempt": self.admission.attempt(), "request": self.request}),
            frozen_clock: None,
        };
        let (_, continuation) = self.store.consume_normal_chat_for_execution(
            &self.permit_id,
            &self.admission,
            &call,
            &AllowCurrentEgress,
            || TestClock.now(),
        )?;
        let preflight = self.store.normal_chat_preflight(&self.permit_id)?;
        let response = RecordedNormalChatResponseV1 {
            schema: RecordedNormalChatResponseSchemaV1::V1,
            attempt_id: self.admission.attempt().attempt_id.clone(),
            permit_id: self.permit_id.clone(),
            preflight_receipt_digest: preflight.receipt_digest.clone(),
            response: recursive_agent_provider::CompletionResponseV1 {
                model: "fixture-model".into(),
                text: "fixture response".into(),
                raw: serde_json::json!({}),
            },
        };
        let response = self.artifacts.put(
            &recursive_agent_contracts::jcs_canonical(&response)?,
            "application/json",
            None,
        )?;
        let outcome = self.store.record_reported_outcome(
            &self.permit_id,
            &preflight.receipt_digest,
            ReportedEffectOutcomeV1 {
                state: ReportedEffectStateV1::Succeeded,
                duration_ms: 1,
                error_type: None,
            },
            TestClock.now(),
        )?;
        let observation = RecordedNormalChatObservationV1 {
            schema: RecordedNormalChatObservationSchemaV1::V1,
            attempt: self.admission.attempt().attempt_id.clone(),
            response: response.clone(),
            preflight,
            outcome,
        };
        let observation = self.artifacts.put(
            &recursive_agent_contracts::jcs_canonical(&observation)?,
            "application/json",
            None,
        )?;
        Ok((continuation, response, observation))
    }
}

fn replacement(
    artifacts: &ArtifactStore,
    original: &ArtifactDescriptorV1,
    other: &serde_json::Value,
    field: &str,
) -> Result<ArtifactDescriptorV1, Box<dyn std::error::Error>> {
    let mut body: serde_json::Value = serde_json::from_slice(&artifacts.get(original)?)?;
    assert_ne!(body[field], other[field], "fixture must change {field}");
    body[field] = other[field].clone();
    let bytes = recursive_agent_contracts::jcs_canonical(&body)?;
    let descriptor = artifacts.put(&bytes, "application/json", None)?;
    assert_eq!(
        artifacts.get(&descriptor)?,
        bytes,
        "valid hash in the same store"
    );
    Ok(descriptor)
}

#[test]
fn same_root_valid_hash_substitutions_fail_before_settlement(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new("binding-one")?;
    let other = Fixture::new("binding-two")?;
    let (_, response, observation) = fixture.publish()?;
    let (_, other_response, other_observation) = other.publish()?;
    let other_response: serde_json::Value =
        serde_json::from_slice(&other.artifacts.get(&other_response)?)?;
    let other_observation: serde_json::Value =
        serde_json::from_slice(&other.artifacts.get(&other_observation)?)?;
    validate_publication(
        &fixture.store,
        &fixture.artifacts,
        &fixture.permit_id,
        &response,
        &observation,
    )?;
    for field in ["permit_id", "attempt_id", "preflight_receipt_digest"] {
        let substituted = replacement(&fixture.artifacts, &response, &other_response, field)?;
        // Keep observation->response linkage valid to isolate the response's
        // embedded permit/attempt/preflight binding, rather than its new hash.
        let descriptor_value = serde_json::json!({"response": substituted});
        let joined = replacement(
            &fixture.artifacts,
            &observation,
            &descriptor_value,
            "response",
        )?;
        let _: RecordedNormalChatResponseV1 = decode_record(&fixture.artifacts.get(&substituted)?)?;
        let _: RecordedNormalChatObservationV1 = decode_record(&fixture.artifacts.get(&joined)?)?;
        assert!(
            matches!(
                validate_publication(
                    &fixture.store,
                    &fixture.artifacts,
                    &fixture.permit_id,
                    &substituted,
                    &joined
                ),
                Err(NativeNormalChatError::PublicationInvalid)
            ),
            "response {field}"
        );
    }
    for field in ["attempt", "response", "preflight", "outcome"] {
        let substituted = replacement(&fixture.artifacts, &observation, &other_observation, field)?;
        let _: RecordedNormalChatObservationV1 =
            decode_record(&fixture.artifacts.get(&substituted)?)?;
        assert!(
            matches!(
                validate_publication(
                    &fixture.store,
                    &fixture.artifacts,
                    &fixture.permit_id,
                    &response,
                    &substituted
                ),
                Err(NativeNormalChatError::PublicationInvalid)
            ),
            "observation {field}"
        );
    }
    assert!(fixture
        .store
        .state(&fixture.permit_id)?
        .normal_chat_settlement
        .is_none());
    Ok(())
}

#[test]
fn private_live_readback_rejects_post_settlement_artifact_corruption(
) -> Result<(), Box<dyn std::error::Error>> {
    for corrupt_response in [true, false] {
        let fixture = Fixture::new("settled-corruption")?;
        let (continuation, response, observation) = fixture.publish()?;
        validate_publication(
            &fixture.store,
            &fixture.artifacts,
            &fixture.permit_id,
            &response,
            &observation,
        )?;
        let settled = fixture
            .store
            .settle_normal_chat(&continuation, &response, &observation)?;
        // Reopen both canonical owners; no continuation reconstruction or dispatch.
        let reopened = open_store(fixture.root.path())?;
        let root_fd = std::fs::File::open(fixture.root.path())?;
        let artifacts = ArtifactStore::from_run_root_fd(&root_fd, false)?;
        let valid = load_live_settlement(&reopened, &artifacts, &fixture.permit_id)?;
        assert_eq!(valid.response_artifact, response);
        assert_eq!(valid.observation_artifact, observation);
        let target = if corrupt_response {
            &response
        } else {
            &observation
        };
        let bytes = artifacts.get(target)?;
        let mut corrupted = 0;
        for entry in std::fs::read_dir(fixture.root.path().join("artifacts"))? {
            let entry = entry?;
            if std::fs::read(entry.path())? == bytes {
                std::fs::write(entry.path(), b"{}")?;
                corrupted += 1;
            }
        }
        assert_eq!(
            corrupted, 1,
            "fault must alter exactly the settled artifact"
        );
        assert!(matches!(
            load_live_settlement(&reopened, &artifacts, &fixture.permit_id),
            Err(NativeNormalChatError::Artifact(_))
        ));
        assert_eq!(
            reopened.state(&fixture.permit_id)?.normal_chat_settlement,
            Some(settled)
        );
    }
    Ok(())
}

#[test]
fn private_live_readback_rejects_valid_hash_descriptor_substitution(
) -> Result<(), Box<dyn std::error::Error>> {
    for substitute_response in [true, false] {
        let fixture = Fixture::new("settlement-one")?;
        let other = Fixture::new("settlement-two")?;
        let (continuation, response, observation) = fixture.publish()?;
        let (_, other_response, other_observation) = other.publish()?;
        fixture
            .store
            .settle_normal_chat(&continuation, &response, &observation)?;
        load_live_settlement(&fixture.store, &fixture.artifacts, &fixture.permit_id)?;
        let (target, source, field) = if substitute_response {
            (&response, &other_response, "permit_id")
        } else {
            (&observation, &other_observation, "attempt")
        };
        let other_body: serde_json::Value = serde_json::from_slice(&other.artifacts.get(source)?)?;
        let substituted = replacement(&fixture.artifacts, target, &other_body, field)?;
        // Controlled corruption of a disposable owner record, not a supported
        // mutation API or a guarantee against trusted writers replacing state.
        // The new descriptor remains shape-valid; only embedded linkage is wrong.
        let mut modified = 0;
        for entry in std::fs::read_dir(fixture.root.path())? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("permit-") || !name.ends_with(".json") {
                continue;
            }
            let mut record: recursive_agent_policy::PermitRecordV1 =
                serde_json::from_slice(&std::fs::read(entry.path())?)?;
            if record.permit.permit_id != fixture.permit_id {
                continue;
            }
            let settlement = record
                .normal_chat_settlement
                .as_mut()
                .ok_or("missing settlement")?;
            if substitute_response {
                settlement.response = substituted.clone();
                settlement.observation = replacement(
                    &fixture.artifacts,
                    &observation,
                    &serde_json::json!({"response": substituted}),
                    "response",
                )?;
            } else {
                settlement.observation = substituted.clone();
            }
            std::fs::write(
                entry.path(),
                recursive_agent_contracts::jcs_canonical(&record)?,
            )?;
            modified += 1;
        }
        assert_eq!(modified, 1);
        let reopened = open_store(fixture.root.path())?;
        let settled = reopened
            .state(&fixture.permit_id)?
            .normal_chat_settlement
            .ok_or("missing settlement")?;
        let _: RecordedNormalChatResponseV1 =
            decode_record(&fixture.artifacts.get(&settled.response)?)?;
        let _: RecordedNormalChatObservationV1 =
            decode_record(&fixture.artifacts.get(&settled.observation)?)?;
        assert!(matches!(
            load_live_settlement(&reopened, &fixture.artifacts, &fixture.permit_id),
            Err(NativeNormalChatError::PublicationInvalid)
        ));
    }
    Ok(())
}
