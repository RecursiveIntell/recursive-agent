use chrono::{TimeZone, Utc};
use llm_tool_runtime::{
    Tool, ToolCall, ToolCtx, ToolOriginKind, ToolPlannerStage, ToolRegistry, ToolRetryOwner,
};
use recursive_agent_contracts::{
    ContentDigest, ProviderEgressBindingMaterialV1, ProviderEgressBindingV1,
};
use recursive_agent_policy::{
    DenyProviderEgressAdmission, PolicyError, ProviderEgressAdmissionVerifier,
    ValidatedProviderEgressAdmissionV1,
};
use recursive_agent_provider::{
    CompletionBackend, CompletionRequestV1, CompletionResponseV1, ProviderError, ProviderSpecV1,
    ValidatedEndpoint,
};
use recursive_agent_runner::{tool_runtime_with_sealed_completion, Clock, SealedCompletionTool};
use stack_ids::{AttemptId, TraceCtx, TrialId};
use std::sync::{
    atomic::{AtomicI64, AtomicUsize, Ordering},
    Arc,
};

struct FixtureBackend {
    calls: Arc<AtomicUsize>,
    failure: Option<ProviderError>,
}

impl CompletionBackend for FixtureBackend {
    fn complete(
        &self,
        _request: &CompletionRequestV1,
    ) -> Result<CompletionResponseV1, ProviderError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if let Some(error) = &self.failure {
            return Err(match error {
                ProviderError::Malformed(value) => ProviderError::Malformed(value.clone()),
                _ => ProviderError::Unavailable,
            });
        }
        Ok(CompletionResponseV1 {
            model: "fixture-model".into(),
            text: "verified completion".into(),
            raw: serde_json::json!({"fixture": true}),
        })
    }
}

struct AllowFixtureEgress;

impl ProviderEgressAdmissionVerifier for AllowFixtureEgress {
    fn authorize(&self, admission: &ValidatedProviderEgressAdmissionV1) -> Result<(), PolicyError> {
        if admission.lane() != "sealed_completion" {
            return Err(PolicyError::ToolNotAllowed(admission.lane().into()));
        }
        if admission.binding().graph_obligation_ref != "graph-obligation:node-1"
            || admission.binding().graph_obligation_digest != format!("blake3:{}", "c".repeat(64))
        {
            return Err(PolicyError::InvalidLease(
                "current Graph obligation does not match the sealed request".into(),
            ));
        }
        Ok(())
    }
}

struct MutableClock(AtomicI64);

impl MutableClock {
    fn new(seconds: i64) -> Self {
        Self(AtomicI64::new(seconds))
    }

    fn set_seconds(&self, seconds: i64) {
        self.0.store(seconds, Ordering::Relaxed);
    }
}

impl Clock for MutableClock {
    fn now(&self) -> chrono::DateTime<Utc> {
        Utc.timestamp_opt(self.0.load(Ordering::Relaxed), 0)
            .single()
            .unwrap_or(chrono::DateTime::<Utc>::UNIX_EPOCH)
    }
}

fn tool_ctx() -> ToolCtx {
    ToolCtx {
        trace_ctx: TraceCtx::generate(),
        attempt_id: AttemptId::generate(),
        trial_id: TrialId::generate(),
        deadline: None,
        workload_class: None,
        budget_context: None,
        scope: None,
        dry_run: false,
        approval_grant: None,
        execution_permit: None,
        idempotency_key: None,
        caller: "sealed-completion-test".into(),
        planner_stage: ToolPlannerStage::Execution,
        parent_receipt_id: None,
        family_receipt_id: None,
        replay_parent_receipt_id: None,
        remote_oracle_lease_id: None,
        remote_slice_result_id: None,
        attestation_envelope_id: None,
        cross_runtime_replay_ticket_id: None,
        retry_owner: Some(ToolRetryOwner::External),
    }
}

fn binding_and_request(
) -> Result<(ProviderEgressBindingV1, CompletionRequestV1), Box<dyn std::error::Error>> {
    let provider = ProviderSpecV1::Ollama {
        base_url: ValidatedEndpoint::try_new("http://127.0.0.1:11434")?,
        model: "fixture-model".into(),
    };
    let request = CompletionRequestV1 {
        provider,
        prompt: "exact sealed prompt".into(),
        max_tokens: Some(8),
    };
    let binding = ProviderEgressBindingV1::seal(ProviderEgressBindingMaterialV1 {
        policy_basis_ref: "policy:fixture".into(),
        policy_basis_digest: format!("sha256:{}", "a".repeat(64)),
        context_digest: format!("sha256:{}", "b".repeat(64)),
        source_revision: "source:fixture".into(),
        graph_obligation_ref: "graph-obligation:node-1".into(),
        graph_obligation_digest: format!("blake3:{}", "c".repeat(64)),
        route_class: "candidate".into(),
        provider_identity: "ollama:http://127.0.0.1:11434".into(),
        model_ref: "model:fixture-model".into(),
        input_tokens: 4,
        output_reserve: 8,
        request_digest: ContentDigest::compute_json(&request)?,
        not_after: Utc
            .with_ymd_and_hms(2030, 1, 1, 0, 0, 0)
            .single()
            .ok_or("fixture time")?,
    })?;
    Ok((binding, request))
}

fn call(binding: ProviderEgressBindingV1, request: CompletionRequestV1) -> ToolCall {
    ToolCall {
        descriptor_name: "sealed_completion".into(),
        descriptor_version: "1".into(),
        arguments: serde_json::json!({"binding": binding, "request": request}),
        origin_kind: ToolOriginKind::Local,
        provider_call_id: None,
        tool_run_id: "fixture".into(),
    }
}

#[tokio::test]
async fn sealed_completion_requires_the_validated_policy_gate_before_backend_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let (binding, request) = binding_and_request()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let clock = Arc::new(MutableClock::new(1_788_220_800));
    let tool = SealedCompletionTool::new(
        FixtureBackend {
            calls: calls.clone(),
            failure: None,
        },
        clock,
        Arc::new(AllowFixtureEgress),
    );
    let valid_call = call(binding.clone(), request.clone());
    let result = tool.invoke(&tool_ctx(), &valid_call).await?;
    assert_eq!(result.payload["text"], "verified completion");
    assert!(result.payload.get("raw").is_none());
    assert_eq!(
        result.payload["binding_digest"],
        serde_json::json!(binding.binding_digest)
    );
    assert_eq!(
        result.payload["request_digest"],
        serde_json::json!(binding.request_digest)
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    let mut extra_field = valid_call;
    extra_field.arguments["extra"] = serde_json::json!(true);
    assert!(tool.invoke(&tool_ctx(), &extra_field).await.is_err());
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "extra sealed-completion arguments reached the provider"
    );

    let denied = SealedCompletionTool::new(
        FixtureBackend {
            calls: calls.clone(),
            failure: None,
        },
        Arc::new(MutableClock::new(1_788_220_800)),
        Arc::new(DenyProviderEgressAdmission),
    );
    assert!(denied
        .invoke(&tool_ctx(), &call(binding, request))
        .await
        .is_err());
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "default-denied material reached the provider"
    );
    Ok(())
}

#[tokio::test]
async fn sealed_completion_rejects_binding_metadata_drift_at_the_final_egress_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    let (binding, request) = binding_and_request()?;
    let mismatched = ProviderEgressBindingV1::seal(ProviderEgressBindingMaterialV1 {
        policy_basis_ref: binding.policy_basis_ref.clone(),
        policy_basis_digest: binding.policy_basis_digest.clone(),
        context_digest: binding.context_digest.clone(),
        source_revision: binding.source_revision.clone(),
        graph_obligation_ref: binding.graph_obligation_ref.clone(),
        graph_obligation_digest: binding.graph_obligation_digest.clone(),
        route_class: binding.route_class.clone(),
        provider_identity: binding.provider_identity.clone(),
        model_ref: "model:not-the-request-model".into(),
        input_tokens: binding.input_tokens,
        output_reserve: binding.output_reserve,
        request_digest: binding.request_digest.clone(),
        not_after: binding.not_after,
    })?;
    let calls = Arc::new(AtomicUsize::new(0));
    let tool = SealedCompletionTool::new(
        FixtureBackend {
            calls: calls.clone(),
            failure: None,
        },
        Arc::new(MutableClock::new(1_788_220_800)),
        Arc::new(AllowFixtureEgress),
    );

    assert!(tool
        .invoke(&tool_ctx(), &call(mismatched, request))
        .await
        .is_err());
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    Ok(())
}

#[tokio::test]
async fn sealed_completion_rejects_current_graph_obligation_drift_before_backend_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let (binding, request) = binding_and_request()?;
    let graph_drift = ProviderEgressBindingV1::seal(ProviderEgressBindingMaterialV1 {
        policy_basis_ref: binding.policy_basis_ref.clone(),
        policy_basis_digest: binding.policy_basis_digest.clone(),
        context_digest: binding.context_digest.clone(),
        source_revision: binding.source_revision.clone(),
        graph_obligation_ref: binding.graph_obligation_ref.clone(),
        graph_obligation_digest: format!("blake3:{}", "d".repeat(64)),
        route_class: binding.route_class.clone(),
        provider_identity: binding.provider_identity.clone(),
        model_ref: binding.model_ref.clone(),
        input_tokens: binding.input_tokens,
        output_reserve: binding.output_reserve,
        request_digest: binding.request_digest.clone(),
        not_after: binding.not_after,
    })?;
    let calls = Arc::new(AtomicUsize::new(0));
    let tool = SealedCompletionTool::new(
        FixtureBackend {
            calls: calls.clone(),
            failure: None,
        },
        Arc::new(MutableClock::new(1_788_220_800)),
        Arc::new(AllowFixtureEgress),
    );

    assert!(tool
        .invoke(&tool_ctx(), &call(graph_drift, request))
        .await
        .is_err());
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    Ok(())
}

#[tokio::test]
async fn sealed_completion_rechecks_the_current_clock_and_redacts_backend_failure_details(
) -> Result<(), Box<dyn std::error::Error>> {
    let (binding, request) = binding_and_request()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let clock = Arc::new(MutableClock::new(1_788_220_800));
    let expired = SealedCompletionTool::new(
        FixtureBackend {
            calls: calls.clone(),
            failure: None,
        },
        clock.clone(),
        Arc::new(AllowFixtureEgress),
    );
    clock.set_seconds(1_893_456_000);
    assert!(expired
        .invoke(&tool_ctx(), &call(binding.clone(), request.clone()))
        .await
        .is_err());
    assert_eq!(
        calls.load(Ordering::Relaxed),
        0,
        "expired binding reached the provider"
    );

    let secret = "provider-secret-never-returned";
    let failing = SealedCompletionTool::new(
        FixtureBackend {
            calls: calls.clone(),
            failure: Some(ProviderError::Malformed(secret.into())),
        },
        Arc::new(MutableClock::new(1_788_220_800)),
        Arc::new(AllowFixtureEgress),
    );
    let error = failing
        .invoke(&tool_ctx(), &call(binding, request))
        .await
        .err()
        .ok_or("fixture backend unexpectedly succeeded")?;
    assert!(!error.message.contains(secret));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    Ok(())
}

#[test]
fn sealed_completion_factory_requires_explicit_clock_and_verifier() {
    let runtime = tool_runtime_with_sealed_completion(
        ToolRegistry::new(),
        FixtureBackend {
            calls: Arc::new(AtomicUsize::new(0)),
            failure: None,
        },
        Arc::new(MutableClock::new(1_788_220_800)),
        Arc::new(DenyProviderEgressAdmission),
    );
    assert!(runtime.registry().get("sealed_completion").is_some());
}
