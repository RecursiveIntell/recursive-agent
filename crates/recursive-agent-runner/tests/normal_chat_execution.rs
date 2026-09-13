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
impl recursive_agent_runner::Clock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        now() + TimeDelta::milliseconds(1)
    }
}
struct PublicationFaultClock<'a> {
    backend_calls: &'a std::sync::atomic::AtomicUsize,
    artifact_path: std::path::PathBuf,
    enabled: bool,
    installed: std::sync::atomic::AtomicBool,
}
impl recursive_agent_runner::Clock for PublicationFaultClock<'_> {
    fn now(&self) -> DateTime<Utc> {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::Ordering::SeqCst;
        if self.enabled && self.backend_calls.load(SeqCst) > 0 && !self.installed.load(SeqCst) {
            // The first post-backend clock read is after response retention,
            // immediately before the outcome write in the separate permit root.
            let result = std::fs::set_permissions(
                &self.artifact_path,
                std::fs::Permissions::from_mode(0o500),
            );
            self.installed.store(result.is_ok(), SeqCst);
        }
        now() + TimeDelta::milliseconds(1)
    }
}
struct Backend(std::sync::atomic::AtomicUsize, u8, std::path::PathBuf);
impl recursive_agent_provider::CompletionBackend for Backend {
    fn complete(
        &self,
        _: &recursive_agent_provider::CompletionRequestV1,
    ) -> Result<
        recursive_agent_provider::CompletionResponseV1,
        recursive_agent_provider::ProviderError,
    > {
        Err(recursive_agent_provider::ProviderError::Unavailable)
    }
    fn complete_conversation(
        &self,
        _: &recursive_agent_provider::ConversationRequestV1,
    ) -> Result<
        recursive_agent_provider::CompletionResponseV1,
        recursive_agent_provider::ProviderError,
    > {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if matches!(self.1, 4 | 5) {
            // Fault only after consume and backend entry. Keep the exact
            // consumed record for restoration; block the owner's record path.
            let fault = || -> Result<(), Box<dyn std::error::Error>> {
                for entry in std::fs::read_dir(&self.2)? {
                    let entry = entry?;
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if !name.starts_with("permit-") || !name.ends_with(".json") {
                        continue;
                    }
                    let record: recursive_agent_policy::PermitRecordV1 =
                        serde_json::from_slice(&std::fs::read(entry.path())?)?;
                    if record.preflight_receipt.is_some() {
                        std::fs::rename(entry.path(), entry.path().with_extension("held"))?;
                        std::fs::create_dir(entry.path())?;
                    }
                }
                Ok(())
            };
            fault().map_err(|error| {
                recursive_agent_provider::ProviderError::Malformed(format!(
                    "fault fixture failed: {error}"
                ))
            })?;
        }
        if matches!(self.1, 1 | 5) {
            return Err(recursive_agent_provider::ProviderError::Malformed(
                "PRIVATE_BACKEND_DIAGNOSTIC".into(),
            ));
        }
        Ok(recursive_agent_provider::CompletionResponseV1 {
            model: "fixture-model".into(),
            text: if self.1 == 2 {
                "x".repeat(8192)
            } else {
                "fixture response".into()
            },
            raw: serde_json::json!({"fixture":true}),
        })
    }
}

struct V2Backend {
    calls: std::sync::atomic::AtomicUsize,
    fail: bool,
}

impl recursive_agent_provider::CompletionBackend for V2Backend {
    fn complete(
        &self,
        _: &recursive_agent_provider::CompletionRequestV1,
    ) -> Result<
        recursive_agent_provider::CompletionResponseV1,
        recursive_agent_provider::ProviderError,
    > {
        Err(recursive_agent_provider::ProviderError::Unavailable)
    }

    fn complete_conversation(
        &self,
        _: &recursive_agent_provider::ConversationRequestV1,
    ) -> Result<
        recursive_agent_provider::CompletionResponseV1,
        recursive_agent_provider::ProviderError,
    > {
        Err(recursive_agent_provider::ProviderError::Unavailable)
    }

    fn complete_conversation_v2(
        &self,
        _: &recursive_agent_provider::ConversationRequestV2,
    ) -> Result<
        recursive_agent_provider::CompletionResponseV1,
        recursive_agent_provider::ProviderError,
    > {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.fail {
            return Err(recursive_agent_provider::ProviderError::Malformed(
                "PRIVATE_V2_BACKEND_DIAGNOSTIC".into(),
            ));
        }
        Ok(recursive_agent_provider::CompletionResponseV1 {
            model: "fixture-model".into(),
            text: "fixture v2 response".into(),
            raw: serde_json::json!({"fixture": "v2"}),
        })
    }
}

#[test]
fn native_chat_consumes_records_and_rejects_repeat_backend_execution(
) -> Result<(), Box<dyn std::error::Error>> {
    run_fixture(0)
}

#[test]
fn native_chat_backend_error_is_ambiguous_and_not_retried() -> Result<(), Box<dyn std::error::Error>>
{
    run_fixture(1)
}

#[test]
fn native_chat_oversize_result_is_ambiguous_and_not_retried(
) -> Result<(), Box<dyn std::error::Error>> {
    run_fixture(2)
}

#[test]
fn native_chat_response_storage_failure_retains_ambiguous_outcome(
) -> Result<(), Box<dyn std::error::Error>> {
    run_fixture(3)
}

#[test]
fn native_chat_success_with_unrecordable_outcome_is_explicitly_degraded(
) -> Result<(), Box<dyn std::error::Error>> {
    run_fixture(4)
}

#[test]
fn native_chat_backend_error_with_unrecordable_outcome_is_explicitly_degraded(
) -> Result<(), Box<dyn std::error::Error>> {
    run_fixture(5)
}

#[test]
fn native_chat_combined_artifact_budget_blocks_observation_without_retry(
) -> Result<(), Box<dyn std::error::Error>> {
    run_fixture(6)
}

#[test]
fn native_chat_v2_consumes_exact_structured_request_and_rejects_reuse(
) -> Result<(), Box<dyn std::error::Error>> {
    run_v2_fixture(false)
}

#[test]
fn native_chat_v2_backend_error_is_ambiguous_and_not_retried(
) -> Result<(), Box<dyn std::error::Error>> {
    run_v2_fixture(true)
}

#[test]
fn native_chat_observation_storage_failure_preserves_response_and_outcome(
) -> Result<(), Box<dyn std::error::Error>> {
    run_fixture(7)
}

fn run_fixture(mode: u8) -> Result<(), Box<dyn std::error::Error>> {
    let unrelated_run = false;
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
        conversation_ref: "conversation:permit-test".into(),
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
        max_artifact_bytes: if mode == 6 { 1024 } else { 4_096 },
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
    let backend = Backend(
        std::sync::atomic::AtomicUsize::new(0),
        mode,
        root.path().into(),
    );
    let denied = recursive_agent_runner::NativeNormalChatExecutor::new(
        &store,
        &artifacts,
        &recursive_agent_policy::DenyNormalChatAdmission,
        &TestClock,
        &backend,
    );
    assert!(denied
        .execute(&permit.permit_id, &admission, &request)
        .is_err());
    assert_eq!(backend.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    let publication_clock = PublicationFaultClock {
        backend_calls: &backend.0,
        artifact_path: root.path().join("artifacts"),
        enabled: mode == 7,
        installed: std::sync::atomic::AtomicBool::new(false),
    };
    let executor = recursive_agent_runner::NativeNormalChatExecutor::new(
        &store,
        &artifacts,
        &AllowCurrentEgress,
        &publication_clock,
        &backend,
    );
    let mut changed_request = request.clone();
    changed_request.messages[0].content = "changed after admission".into();
    assert!(executor
        .execute(&permit.permit_id, &admission, &changed_request)
        .is_err());
    assert_eq!(backend.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    let mut changed_limit = request.clone();
    changed_limit.max_tokens = Some(9);
    assert!(executor
        .execute(&permit.permit_id, &admission, &changed_limit)
        .is_err());
    assert_eq!(backend.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    let other_root = tempfile::tempdir()?;
    let other_fd = std::fs::File::open(other_root.path())?;
    let other_artifacts = recursive_agent_ledger::ArtifactStore::from_run_root_fd(&other_fd, true)?;
    let mismatched = recursive_agent_runner::NativeNormalChatExecutor::new(
        &store,
        &other_artifacts,
        &AllowCurrentEgress,
        &TestClock,
        &backend,
    );
    assert!(matches!(
        mismatched.execute(&permit.permit_id, &admission, &request),
        Err(recursive_agent_runner::NativeNormalChatError::StoreMismatch)
    ));
    assert_eq!(backend.0.load(std::sync::atomic::Ordering::SeqCst), 0);

    if mode == 3 {
        // Removing this empty, pinned directory makes its next write fail on
        // Linux even as root, while the permit store remains writable.
        std::fs::remove_dir(root.path().join("artifacts"))?;
    }
    let observed = executor.execute(&permit.permit_id, &admission, &request);
    if mode == 7 {
        use std::os::unix::fs::PermissionsExt;
        // Restore permissions before assertions so fixture cleanup is reliable.
        std::fs::set_permissions(
            root.path().join("artifacts"),
            std::fs::Permissions::from_mode(0o700),
        )?;
        assert!(publication_clock
            .installed
            .load(std::sync::atomic::Ordering::SeqCst));
        match observed {
            Err(recursive_agent_runner::NativeNormalChatError::ObservationPublicationFailed {
                response_artifact, outcome, source,
            }) => {
                assert!(matches!(*source, recursive_agent_ledger::LedgerError::Io(ref error)
                    if error.kind() == std::io::ErrorKind::PermissionDenied));
                let retained: serde_json::Value = serde_json::from_slice(&artifacts.get(&response_artifact)?)?;
                assert_eq!(retained["schema"], "recursive-agent.normal-chat-recorded-response/v1");
                assert_eq!(retained["attempt_id"], serde_json::to_value(&admission.attempt().attempt_id)?);
                assert_eq!(retained["permit_id"], serde_json::to_value(&permit.permit_id)?);
                assert_eq!(retained["preflight_receipt_digest"], serde_json::to_value(store.normal_chat_preflight(&permit.permit_id)?.receipt_digest)?);
                assert_eq!(retained["response"]["text"], "fixture response");
                outcome.validate()?;
                assert_eq!(outcome.permit_id, permit.permit_id);
                assert_eq!(outcome.reported.state, recursive_agent_policy::ReportedEffectStateV1::Succeeded);
            }
            _ => return Err("missing explicit observation publication failure (requires enforced filesystem permissions)".into()),
        }
    } else if matches!(mode, 4 | 5) {
        match observed {
            Err(recursive_agent_runner::NativeNormalChatError::OutcomePersistenceFailed {
                permit_id,
                preflight_receipt_digest,
                ..
            }) => {
                assert_eq!(permit_id, permit.permit_id);
                // Restore the unchanged consumed record after the fault.
                for entry in std::fs::read_dir(root.path())? {
                    let entry = entry?;
                    if entry.path().extension().is_some_and(|ext| ext == "held") {
                        let target = entry.path().with_extension("json");
                        std::fs::remove_dir(&target)?;
                        std::fs::rename(entry.path(), target)?;
                    }
                }
                assert_eq!(
                    preflight_receipt_digest,
                    store
                        .normal_chat_preflight(&permit.permit_id)?
                        .receipt_digest
                );
            }
            _ => return Err("missing explicit post-backend persistence failure".into()),
        }
    } else if mode == 6 {
        match observed {
            Err(recursive_agent_runner::NativeNormalChatError::ObservationBudgetExceeded {
                response_artifact,
                outcome,
                required_bytes,
                maximum_bytes,
            }) => {
                assert_eq!(maximum_bytes, 1024);
                assert!(required_bytes > maximum_bytes);
                assert!(response_artifact.byte_length <= maximum_bytes);
                let retained: serde_json::Value =
                    serde_json::from_slice(&artifacts.get(&response_artifact)?)?;
                assert_eq!(
                    retained["schema"],
                    "recursive-agent.normal-chat-recorded-response/v1"
                );
                assert_eq!(
                    retained["attempt_id"],
                    serde_json::to_value(&admission.attempt().attempt_id)?
                );
                assert_eq!(
                    retained["permit_id"],
                    serde_json::to_value(&permit.permit_id)?
                );
                assert_eq!(
                    retained["preflight_receipt_digest"],
                    serde_json::to_value(
                        store
                            .normal_chat_preflight(&permit.permit_id)?
                            .receipt_digest
                    )?
                );
                assert_eq!(retained["response"]["text"], "fixture response");
                outcome.validate()?;
                assert_eq!(outcome.permit_id, permit.permit_id);
                assert_eq!(
                    outcome.reported.state,
                    recursive_agent_policy::ReportedEffectStateV1::Succeeded
                );
                // Independently reconstruct the declared observation and prove
                // it was not written beyond the admitted byte budget.
                let withheld = serde_json::to_vec(&serde_json::json!({
                    "schema": "recursive-agent.normal-chat-observation/v1",
                    "attempt": admission.attempt().attempt_id,
                    "response": response_artifact,
                    "preflight": store.normal_chat_preflight(&permit.permit_id)?,
                    "outcome": outcome,
                }))?;
                assert_eq!(
                    required_bytes,
                    response_artifact.byte_length + u64::try_from(withheld.len())?
                );
                let withheld_descriptor = recursive_agent_contracts::ArtifactDescriptorV1 {
                    owner_id: recursive_agent_contracts::derive_artifact_id(&withheld)?,
                    digest: ContentDigest::compute(&withheld),
                    byte_length: u64::try_from(withheld.len())?,
                    media_type: "application/json".into(),
                    encoding: None,
                };
                assert!(artifacts.get(&withheld_descriptor).is_err());
            }
            _ => return Err("combined artifact budget was not enforced".into()),
        }
    } else if mode == 3 {
        assert!(matches!(
            observed,
            Err(recursive_agent_runner::NativeNormalChatError::Artifact(_))
        ));
    } else if mode == 0 {
        let result = observed?;
        assert!(
            result.response_artifact.byte_length + result.observation_artifact.byte_length <= 4096
        );
        let retained: serde_json::Value =
            serde_json::from_slice(&artifacts.get(&result.response_artifact)?)?;
        assert_eq!(
            artifacts.get(&result.response_artifact)?,
            recursive_agent_contracts::jcs_canonical(&retained)?
        );
        assert_eq!(
            retained["schema"],
            "recursive-agent.normal-chat-recorded-response/v1"
        );
        assert_eq!(
            retained["attempt_id"],
            serde_json::to_value(&admission.attempt().attempt_id)?
        );
        assert_eq!(
            retained["permit_id"],
            serde_json::to_value(&permit.permit_id)?
        );
        assert_eq!(
            retained["preflight_receipt_digest"],
            serde_json::to_value(
                store
                    .normal_chat_preflight(&permit.permit_id)?
                    .receipt_digest
            )?
        );
        assert_eq!(retained["response"]["text"], "fixture response");
        result.outcome.validate()?;
        assert!(matches!(
            result.outcome.reported.state,
            recursive_agent_policy::ReportedEffectStateV1::Succeeded
        ));
        let joined: serde_json::Value =
            serde_json::from_slice(&artifacts.get(&result.observation_artifact)?)?;
        assert_eq!(
            joined["response"],
            serde_json::to_value(&result.response_artifact)?
        );
        assert_eq!(joined["outcome"], serde_json::to_value(&result.outcome)?);
    } else {
        assert!(matches!(
            observed,
            Err(recursive_agent_runner::NativeNormalChatError::BackendAmbiguous)
        ));
    }
    assert!(executor
        .execute(&permit.permit_id, &admission, &request)
        .is_err());
    assert_eq!(backend.0.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Read the exact native record from disk, rather than trust the executor's return.
    let mut matched = 0;
    for entry in std::fs::read_dir(root.path())? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("permit-") || !name.ends_with(".json") {
            continue;
        }
        let bytes = std::fs::read(entry.path())?;
        assert!(!String::from_utf8_lossy(&bytes).contains("PRIVATE_BACKEND_DIAGNOSTIC"));
        let record: recursive_agent_policy::PermitRecordV1 = serde_json::from_slice(&bytes)?;
        if record.permit.permit_id != permit.permit_id {
            continue;
        }
        matched += 1;
        let preflight = record.preflight_receipt.ok_or("missing native preflight")?;
        preflight.validate()?;
        if matches!(mode, 4 | 5) {
            assert!(record.outcome_receipt.is_none());
            assert!(matches!(
                record.state,
                recursive_agent_policy::PermitStateV1::Consumed { .. }
            ));
            continue;
        }
        let outcome = record.outcome_receipt.ok_or("missing native outcome")?;
        outcome.validate()?;
        assert_eq!(outcome.preflight_receipt_digest, preflight.receipt_digest);
        let expected = if matches!(mode, 0 | 6 | 7) {
            recursive_agent_policy::ReportedEffectStateV1::Succeeded
        } else {
            recursive_agent_policy::ReportedEffectStateV1::OutcomeAmbiguous
        };
        assert_eq!(outcome.reported.state, expected);
        if mode == 3 {
            assert_eq!(
                outcome.reported.error_type.as_deref(),
                Some("conversation_response_storage_failed")
            );
        }
    }
    assert_eq!(matched, 1);
    let reopened = open_store(root.path())?;
    let restarted = recursive_agent_runner::NativeNormalChatExecutor::new(
        &reopened,
        &artifacts,
        &AllowCurrentEgress,
        &TestClock,
        &backend,
    );
    assert!(restarted
        .execute(&permit.permit_id, &admission, &request)
        .is_err());
    assert_eq!(backend.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    Ok(())
}

fn run_v2_fixture(backend_fails: bool) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let store = open_store(root.path())?;
    let request = recursive_agent_provider::ConversationRequestV2::try_new(
        recursive_agent_provider::ProviderSpecV1::OpenAiCompatible {
            base_url: recursive_agent_provider::ValidatedEndpoint::try_new(
                "https://provider.test/",
            )?,
            model: "fixture-model".into(),
            credential_ref: recursive_agent_provider::CredentialRef::try_new(
                "environment:UNUSED_TEST_KEY",
            )?,
        },
        vec![
            recursive_agent_provider::ConversationMessageV2::user("inspect current state"),
            recursive_agent_provider::ConversationMessageV2::assistant_tool_calls(vec![
                recursive_agent_provider::ToolCallV2::try_new(
                    "call-1",
                    "lookup",
                    serde_json::json!({"query": "status"}),
                )?,
            ])?,
            recursive_agent_provider::ConversationMessageV2::tool_result(
                "call-1",
                "state is clean",
            )?,
            recursive_agent_provider::ConversationMessageV2::assistant_text("ready")?,
        ],
        Some(8),
    )?;
    let operation = NormalChatOperationV1 {
        schema: NormalChatOperationSchemaV1::V1,
        conversation_ref: "conversation:permit-v2-test".into(),
        parent_run_id: None,
        materialization_ref: "materialization:v2-test".into(),
        materialization_digest: format!("sha256:{}", "a".repeat(64)),
        policy_basis_ref: "policy:v2-test".into(),
        policy_basis_digest: format!("blake3:{}", "b".repeat(64)),
        source_revision: "source:v2-test".into(),
        route_class: "candidate".into(),
        provider_identity: request.provider.egress_provider_identity(),
        model_ref: "model:fixture-model".into(),
        request_digest: format!("sha256:{}", "c".repeat(64)),
        budget: NormalChatBudgetV1 {
            max_attempts: 1,
            input_tokens: 8,
            output_reserve: 8,
            max_wall_time_ms: 1_000,
        },
        replay: NormalChatReplayV1::RecordedResponseOnly,
        provenance: vec![ProvenanceRefV1 {
            source: "urn:test:normal-chat-v2-permit".into(),
            digest: ContentDigest::compute(b"v2-fixture"),
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
    let lifecycle_call = ToolCallSpecV1 {
        tool: "runner.lifecycle".into(),
        args: serde_json::json!({"operation": "provider-egress-v2"}),
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
            max_wall_time_ms: 2_000,
            max_output_bytes: 8_192,
            max_artifact_bytes: 8_192,
        },
        policy_version: "candidate-egress-v2".into(),
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
        policy_version: "candidate-egress-v2".into(),
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
    let dispatch_time = now() + TimeDelta::milliseconds(1);
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
        policy_version: "candidate-egress-v2".into(),
        parent_permit_id: Some(control.permit_id),
        parent_operation_id: Some(run_id),
        issued_at: dispatch_time,
        not_before: dispatch_time,
        expires_at: now() + TimeDelta::seconds(30),
        run_id: admission.attempt().run_id()?,
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
    let backend = V2Backend {
        calls: std::sync::atomic::AtomicUsize::new(0),
        fail: backend_fails,
    };
    let executor = recursive_agent_runner::NativeNormalChatExecutor::new(
        &store,
        &artifacts,
        &AllowCurrentEgress,
        &TestClock,
        &backend,
    );
    let mut changed_request = request.clone();
    let recursive_agent_provider::ConversationMessageV2::Assistant { tool_calls, .. } =
        &mut changed_request.messages[1]
    else {
        return Err("missing v2 tool-call fixture message".into());
    };
    tool_calls[0].arguments = serde_json::json!({"query": "changed-after-admission"});
    assert!(executor
        .execute_v2(&permit.permit_id, &admission, &changed_request)
        .is_err());
    assert_eq!(backend.calls.load(std::sync::atomic::Ordering::SeqCst), 0);

    let observed = executor.execute_v2(&permit.permit_id, &admission, &request);
    assert_eq!(backend.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    let preflight = store.normal_chat_preflight(&permit.permit_id)?;
    let record = std::fs::read_dir(root.path())?
        .filter_map(Result::ok)
        .find_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("permit-") || !name.ends_with(".json") {
                return None;
            }
            let bytes = std::fs::read(entry.path()).ok()?;
            let record =
                serde_json::from_slice::<recursive_agent_policy::PermitRecordV1>(&bytes).ok()?;
            (record.permit.permit_id == permit.permit_id).then_some(record)
        })
        .ok_or("missing v2 normal-chat permit record")?;
    assert_eq!(
        record
            .preflight_receipt
            .as_ref()
            .ok_or("missing v2 preflight receipt")?
            .receipt_digest,
        preflight.receipt_digest
    );
    if backend_fails {
        assert!(matches!(
            observed,
            Err(recursive_agent_runner::NativeNormalChatError::BackendAmbiguous)
        ));
        let outcome = record
            .outcome_receipt
            .ok_or("missing v2 ambiguous outcome")?;
        outcome.validate()?;
        assert_eq!(
            outcome.reported.state,
            recursive_agent_policy::ReportedEffectStateV1::OutcomeAmbiguous
        );
        assert_eq!(
            outcome.reported.error_type.as_deref(),
            Some("conversation_backend_error")
        );
    } else {
        let result = observed?;
        let retained: serde_json::Value =
            serde_json::from_slice(&artifacts.get(&result.response_artifact)?)?;
        assert_eq!(
            retained["schema"],
            "recursive-agent.normal-chat-recorded-response/v1"
        );
        assert_eq!(retained["response"]["text"], "fixture v2 response");
        assert_eq!(
            result.outcome.reported.state,
            recursive_agent_policy::ReportedEffectStateV1::Succeeded
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &artifacts.get(&result.observation_artifact)?
            )?["response"],
            serde_json::to_value(&result.response_artifact)?
        );
    }
    assert!(executor
        .execute_v2(&permit.permit_id, &admission, &request)
        .is_err());
    let reopened = open_store(root.path())?;
    let restarted = recursive_agent_runner::NativeNormalChatExecutor::new(
        &reopened,
        &artifacts,
        &AllowCurrentEgress,
        &TestClock,
        &backend,
    );
    assert!(restarted
        .execute_v2(&permit.permit_id, &admission, &request)
        .is_err());
    assert_eq!(backend.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    Ok(())
}
