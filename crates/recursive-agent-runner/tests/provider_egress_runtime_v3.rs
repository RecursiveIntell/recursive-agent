use chrono::{TimeZone, Utc};
use llm_tool_runtime::ToolRegistry;
use recursive_agent_contracts::{
    content_digest, derive_provider_egress_operation_id, ActorAuthorityV1, AuthorityOriginV1,
    ContentDigest, DeclaredEffectsV1, OperationBudgetV1, ProvenanceRefV1,
    ProviderEgressBindingMaterialV1, ProviderEgressBindingV1, ProviderEgressOperationEnvelopeV3,
    ProviderEgressOperationSchemaV1, ReceiptKindV1, ReplayClassV1, ReplayIntentV1, ReplaySpecV1,
    RunTerminalStateV1, SealedCompletionArgumentsV3, SealedCompletionCallV3,
};
use recursive_agent_ledger::{
    make_receipt, open, verified_snapshot_with_artifact_store_directory_bound,
    verify_directory_bound, ReceiptDraftV1, RunPaths,
};
use recursive_agent_policy::{
    PolicyError, ProviderEgressAdmissionEvidenceV1, ProviderEgressAdmissionVerifier,
    ValidatedProviderEgressAdmissionV1,
};
use recursive_agent_provider::{
    CompletionBackend, CompletionRequestV1, CompletionResponseV1, ProviderError, ProviderSpecV1,
    ValidatedEndpoint,
};
use recursive_agent_runner::{
    tool_runtime_with_sealed_completion, Clock, RuntimeDependencies, RuntimeLedgerDependencyV1,
    RuntimePolicyDependencyV1, RuntimeProviderDependencyV1, RuntimeSandboxDependencyV1,
    RuntimeService, RuntimeServiceError, RuntimeStoreDependencyV1,
};
use std::sync::{
    atomic::{AtomicI64, AtomicUsize, Ordering},
    mpsc, Arc, Mutex,
};

struct MutableClock(AtomicI64);

impl MutableClock {
    fn new(seconds: i64) -> Self {
        Self(AtomicI64::new(seconds))
    }

    fn set(&self, seconds: i64) {
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

struct AdvancingClock(AtomicI64);

impl AdvancingClock {
    fn new(seconds: i64) -> Self {
        Self(AtomicI64::new(seconds.saturating_mul(1_000)))
    }
}

impl Clock for AdvancingClock {
    fn now(&self) -> chrono::DateTime<Utc> {
        Utc.timestamp_millis_opt(self.0.fetch_add(1, Ordering::Relaxed))
            .single()
            .unwrap_or(chrono::DateTime::<Utc>::UNIX_EPOCH)
    }
}

struct AllowCurrentEgress;

impl ProviderEgressAdmissionVerifier for AllowCurrentEgress {
    fn contract_version(&self) -> &'static str {
        "fixture-egress-policy/v1"
    }

    fn authorize(&self, admission: &ValidatedProviderEgressAdmissionV1) -> Result<(), PolicyError> {
        if admission.lane() != "sealed_completion" {
            return Err(PolicyError::ToolNotAllowed(admission.lane().into()));
        }
        Ok(())
    }
}

struct FixtureBackend(Arc<AtomicUsize>);

impl CompletionBackend for FixtureBackend {
    fn complete(
        &self,
        request: &CompletionRequestV1,
    ) -> Result<CompletionResponseV1, ProviderError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        fixture_response(request)
    }
}

struct BlockingBackend {
    started: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl CompletionBackend for BlockingBackend {
    fn complete(
        &self,
        request: &CompletionRequestV1,
    ) -> Result<CompletionResponseV1, ProviderError> {
        let _ = self.started.send(());
        if let Ok(release) = self.release.lock() {
            let _ = release.recv_timeout(std::time::Duration::from_secs(5));
        }
        fixture_response(request)
    }
}

fn fixture_response(request: &CompletionRequestV1) -> Result<CompletionResponseV1, ProviderError> {
    let model = match &request.provider {
        ProviderSpecV1::Ollama { model, .. } | ProviderSpecV1::OpenAiCompatible { model, .. } => {
            model.clone()
        }
    };
    Ok(CompletionResponseV1 {
        model,
        text: "receipt-bound fixture response".into(),
        raw: serde_json::json!({"must_not_escape": true}),
    })
}

fn provider() -> Result<ProviderSpecV1, ProviderError> {
    Ok(ProviderSpecV1::Ollama {
        base_url: ValidatedEndpoint::try_new("http://127.0.0.1:11434")?,
        model: "fixture-model".into(),
    })
}

fn operation() -> Result<ProviderEgressOperationEnvelopeV3, Box<dyn std::error::Error>> {
    let request = CompletionRequestV1 {
        provider: provider()?,
        prompt: "exact sealed prompt".into(),
        max_tokens: Some(8),
    };
    let request_value = serde_json::to_value(&request)?;
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
        request_digest: content_digest(&request)?,
        not_after: Utc
            .with_ymd_and_hms(2030, 1, 1, 0, 0, 0)
            .single()
            .ok_or("fixture expiry is invalid")?,
    })?;
    let sealed_completion = SealedCompletionCallV3 {
        tool: "sealed_completion".into(),
        arguments: SealedCompletionArgumentsV3 {
            binding,
            request: request_value,
        },
    };
    Ok(ProviderEgressOperationEnvelopeV3 {
        schema: ProviderEgressOperationSchemaV1::V3,
        actor: ActorAuthorityV1 {
            principal: "actor:v3-runtime-fixture".into(),
            origin: AuthorityOriginV1::Direct,
        },
        budget: OperationBudgetV1 {
            max_wall_time_ms: 1_000,
            max_output_bytes: 4_096,
            max_artifact_bytes: 4_096,
            max_steps: 1,
        },
        effects: DeclaredEffectsV1 {
            read_roots: Vec::new(),
            write_roots: Vec::new(),
            network_allowed: true,
            action_digest: content_digest(&sealed_completion)?,
        },
        provenance: vec![ProvenanceRefV1 {
            source: "urn:test:v3-runtime".into(),
            digest: ContentDigest::compute(b"v3-runtime-fixture"),
        }],
        replay: ReplaySpecV1 {
            class: ReplayClassV1::RecordedEffect,
            intent: ReplayIntentV1::ExecuteOnce,
        },
        sealed_completion,
    })
}

fn candidate_service(
    output_root: &std::path::Path,
    calls: Arc<AtomicUsize>,
    clock: Arc<dyn Clock>,
    inject_verifier: bool,
) -> Result<RuntimeService, Box<dyn std::error::Error>> {
    candidate_service_with_backend(output_root, FixtureBackend(calls), clock, inject_verifier)
}

fn candidate_service_with_backend<B: CompletionBackend + Send + Sync + 'static>(
    output_root: &std::path::Path,
    backend: B,
    clock: Arc<dyn Clock>,
    inject_verifier: bool,
) -> Result<RuntimeService, Box<dyn std::error::Error>> {
    let verifier: Arc<dyn ProviderEgressAdmissionVerifier> = Arc::new(AllowCurrentEgress);
    let runtime = tool_runtime_with_sealed_completion(
        ToolRegistry::new(),
        backend,
        clock.clone(),
        verifier.clone(),
    );
    let mut builder = RuntimeDependencies::builder()
        .policy(RuntimePolicyDependencyV1::Native)
        .sandbox(RuntimeSandboxDependencyV1::Native)
        .tool_runtime(Arc::new(runtime))
        .provider(RuntimeProviderDependencyV1::Configured(provider()?))
        .ledger(RuntimeLedgerDependencyV1::Native)
        .clock(clock)
        .store(RuntimeStoreDependencyV1::Native)
        .output_root(output_root);
    if inject_verifier {
        builder = builder.provider_egress_verifier(verifier);
    }
    Ok(RuntimeService::new(builder.build()?))
}

fn replay_only_service(
    output_root: &std::path::Path,
) -> Result<RuntimeService, Box<dyn std::error::Error>> {
    let dependencies = RuntimeDependencies::builder()
        .policy(RuntimePolicyDependencyV1::Native)
        .sandbox(RuntimeSandboxDependencyV1::Native)
        .tool_runtime(Arc::new(llm_tool_runtime::ToolRuntime::new(
            ToolRegistry::new(),
        )))
        .provider(RuntimeProviderDependencyV1::Disabled)
        .ledger(RuntimeLedgerDependencyV1::Native)
        .clock(Arc::new(MutableClock::new(1_925_000_000)))
        .store(RuntimeStoreDependencyV1::Native)
        .output_root(output_root)
        .build()?;
    Ok(RuntimeService::new(dependencies))
}

fn rebuild_without_admission_receipt(
    source: &recursive_agent_ledger::VerifiedReceiptSnapshot,
    source_store: &recursive_agent_ledger::ArtifactStore,
    destination: &std::path::Path,
) -> Result<RunPaths, Box<dyn std::error::Error>> {
    let paths = RunPaths::new(destination);
    let mut chain = open(&paths)?;
    let target_store = chain.artifact_store()?;
    for receipt in source.receipts() {
        if receipt.kind == ReceiptKindV1::ProviderEgressAdmitted {
            continue;
        }
        let mut artifact_refs = Vec::new();
        for descriptor in &receipt.artifact_refs {
            let copied = target_store.put(
                &source_store.get(descriptor)?,
                &descriptor.media_type,
                descriptor.encoding.clone(),
            )?;
            if copied != *descriptor {
                return Err("copied artifact descriptor changed".into());
            }
            artifact_refs.push(copied);
        }
        let rebuilt = make_receipt(
            ReceiptDraftV1 {
                run_id: receipt.run_id.clone(),
                step_id: receipt.step_id.clone(),
                kind: receipt.kind.clone(),
                valid_time: receipt.valid_time,
                lineage: receipt.lineage.clone(),
                spec_digest: receipt.spec_digest.clone(),
                args_digest: receipt.args_digest.clone(),
                artifact_refs,
                outcome: receipt.outcome.clone(),
            },
            chain.head().clone(),
        )?;
        chain.append(rebuilt)?;
    }
    Ok(paths)
}

#[test]
fn active_provider_execution_is_visible_as_in_flight_until_backend_returns(
) -> Result<(), Box<dyn std::error::Error>> {
    let output = tempfile::tempdir()?;
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let clock: Arc<dyn Clock> = Arc::new(MutableClock::new(1_788_220_800));
    let service = Arc::new(candidate_service_with_backend(
        output.path(),
        BlockingBackend {
            started: started_tx,
            release: Mutex::new(release_rx),
        },
        clock,
        true,
    )?);
    let operation = operation()?;
    let operation_id = derive_provider_egress_operation_id(&operation)?.to_string();
    std::thread::scope(|scope| -> Result<(), Box<dyn std::error::Error>> {
        let worker_service = service.clone();
        let worker = scope.spawn(move || worker_service.submit_provider_egress_v3(&operation));
        started_rx.recv_timeout(std::time::Duration::from_secs(2))?;
        let active = service.managed_admission_snapshot()?;
        assert_eq!(active.active, vec![operation_id]);
        assert!(active.draining.is_empty());
        assert_eq!(active.provider_requests_in_flight, 1);
        release_tx.send(())?;
        worker
            .join()
            .map_err(|_| std::io::Error::other("provider worker panicked"))??;
        Ok(())
    })?;
    let completed = service.managed_admission_snapshot()?;
    assert!(completed.active.is_empty());
    assert!(completed.draining.is_empty());
    assert_eq!(completed.provider_requests_in_flight, 0);
    Ok(())
}

#[test]
fn v3_candidate_executes_once_then_replays_verified_artifact_without_backend(
) -> Result<(), Box<dyn std::error::Error>> {
    let output = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let clock = Arc::new(MutableClock::new(1_788_220_800));
    let service = candidate_service(output.path(), calls.clone(), clock.clone(), true)?;
    let operation = operation()?;

    let handle = service.submit_provider_egress_v3(&operation)?;
    let verification = service.verify(handle.run_id())?;
    assert!(verification.current_strict_success);
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    let (snapshot, store) =
        verified_snapshot_with_artifact_store_directory_bound(&RunPaths::new(handle.run_dir()))?;
    let admitted = snapshot
        .receipts()
        .iter()
        .find(|receipt| receipt.kind == ReceiptKindV1::ProviderEgressAdmitted)
        .ok_or("missing provider-egress admission receipt")?;
    let admission_descriptor = admitted
        .artifact_refs
        .first()
        .ok_or("provider-egress admission receipt omitted its evidence")?;
    let admission: ProviderEgressAdmissionEvidenceV1 =
        serde_json::from_slice(&store.get(admission_descriptor)?)?;
    admission.validate()?;
    assert_eq!(admission.binding.request_digest, admission.request_digest);
    assert_eq!(admission.tool_arguments_digest, admitted.args_digest);
    assert_eq!(admission.verified_at, admitted.valid_time);
    assert_eq!(admission.verifier_contract, "fixture-egress-policy/v1");

    let stripped = tempfile::tempdir()?;
    match rebuild_without_admission_receipt(&snapshot, &store, stripped.path()) {
        Err(error) => assert!(error
            .to_string()
            .contains("network effect permit lacks provider-egress admission evidence")),
        Ok(stripped_paths) => assert!(
            verify_directory_bound(&stripped_paths).is_err(),
            "offline verification accepted a network permit without its admission evidence"
        ),
    }

    let completed = snapshot
        .receipts()
        .iter()
        .find(|receipt| receipt.kind == ReceiptKindV1::StepCompleted)
        .ok_or("missing V3 StepCompleted receipt")?;
    let descriptor = completed
        .artifact_refs
        .first()
        .ok_or("V3 StepCompleted omitted its response artifact")?;
    let payload: serde_json::Value = serde_json::from_slice(&store.get(descriptor)?)?;
    assert_eq!(payload["text"], "receipt-bound fixture response");
    assert!(payload.get("raw").is_none());

    clock.set(1_925_000_000);
    let replay_service = replay_only_service(output.path())?;
    let replayed = replay_service.replay_provider_egress_v3(&operation)?;
    assert_eq!(replayed.run_id(), handle.run_id());
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "recorded replay called the backend"
    );
    Ok(())
}

#[test]
fn v3_candidate_executes_with_a_clock_that_advances_between_security_checks(
) -> Result<(), Box<dyn std::error::Error>> {
    let output = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let clock: Arc<dyn Clock> = Arc::new(AdvancingClock::new(1_788_220_800));
    let service = candidate_service(output.path(), calls.clone(), clock, true)?;

    let handle = service.submit_provider_egress_v3(&operation()?)?;
    let verification = service.verify(handle.run_id())?;
    assert_eq!(verification.terminal_state, RunTerminalStateV1::Succeeded);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    Ok(())
}

#[test]
fn v3_recorded_replay_fails_closed_when_no_verified_run_exists(
) -> Result<(), Box<dyn std::error::Error>> {
    let output = tempfile::tempdir()?;
    let service = replay_only_service(output.path())?;
    assert!(matches!(
        service.replay_provider_egress_v3(&operation()?),
        Err(RuntimeServiceError::ProviderEgressReplayUnavailable)
    ));
    assert_eq!(std::fs::read_dir(output.path())?.count(), 0);
    Ok(())
}

#[test]
fn v3_candidate_is_disabled_without_an_injected_runtime_policy_owner(
) -> Result<(), Box<dyn std::error::Error>> {
    let output = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let clock = Arc::new(MutableClock::new(1_788_220_800));
    let service = candidate_service(output.path(), calls.clone(), clock, false)?;
    assert!(matches!(
        service.submit_provider_egress_v3(&operation()?),
        Err(RuntimeServiceError::ProviderEgressDisabled)
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert_eq!(std::fs::read_dir(output.path())?.count(), 0);
    Ok(())
}

#[test]
fn v3_candidate_rejects_binding_metadata_that_misdescribes_the_decoded_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let output = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let clock = Arc::new(MutableClock::new(1_788_220_800));
    let service = candidate_service(output.path(), calls.clone(), clock, true)?;
    let mut mismatched = operation()?;
    let prior = &mismatched.sealed_completion.arguments.binding;
    mismatched.sealed_completion.arguments.binding =
        ProviderEgressBindingV1::seal(ProviderEgressBindingMaterialV1 {
            policy_basis_ref: prior.policy_basis_ref.clone(),
            policy_basis_digest: prior.policy_basis_digest.clone(),
            context_digest: prior.context_digest.clone(),
            source_revision: prior.source_revision.clone(),
            graph_obligation_ref: prior.graph_obligation_ref.clone(),
            graph_obligation_digest: prior.graph_obligation_digest.clone(),
            route_class: prior.route_class.clone(),
            provider_identity: "ollama:http://127.0.0.1:9999".into(),
            model_ref: "model:other".into(),
            input_tokens: prior.input_tokens,
            output_reserve: prior.output_reserve,
            request_digest: prior.request_digest.clone(),
            not_after: prior.not_after,
        })?;
    mismatched.effects.action_digest = content_digest(&mismatched.sealed_completion)?;

    assert!(matches!(
        service.submit_provider_egress_v3(&mismatched),
        Err(RuntimeServiceError::ProviderBindingMismatch)
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert_eq!(std::fs::read_dir(output.path())?.count(), 0);
    Ok(())
}

#[test]
fn v3_candidate_enforces_declared_output_and_artifact_budget_before_success_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let output = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let clock = Arc::new(MutableClock::new(1_788_220_800));
    let service = candidate_service(output.path(), calls.clone(), clock, true)?;
    let mut bounded = operation()?;
    bounded.budget.max_output_bytes = 8;
    bounded.budget.max_artifact_bytes = 8;

    let handle = service.submit_provider_egress_v3(&bounded)?;
    let verification = service.verify(handle.run_id())?;
    assert_eq!(verification.terminal_state, RunTerminalStateV1::Failed);
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    let (snapshot, _) =
        verified_snapshot_with_artifact_store_directory_bound(&RunPaths::new(handle.run_dir()))?;
    assert!(snapshot
        .receipts()
        .iter()
        .any(|receipt| receipt.kind == ReceiptKindV1::StepFailed));
    assert!(!snapshot
        .receipts()
        .iter()
        .any(|receipt| receipt.kind == ReceiptKindV1::StepCompleted));
    Ok(())
}
