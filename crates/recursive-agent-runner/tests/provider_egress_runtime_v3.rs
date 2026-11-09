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
    verify_directory_bound, LedgerError, ReceiptDraftV1, RunPaths,
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
use std::collections::BTreeMap;
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

struct ExpiringBetweenChecksClock(AtomicUsize);

impl Clock for ExpiringBetweenChecksClock {
    fn now(&self) -> chrono::DateTime<Utc> {
        let seconds = if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            1_788_220_800
        } else {
            1_925_000_000
        };
        Utc.timestamp_opt(seconds, 0)
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

struct DenyCurrentEgress;

impl ProviderEgressAdmissionVerifier for DenyCurrentEgress {
    fn authorize(&self, _: &ValidatedProviderEgressAdmissionV1) -> Result<(), PolicyError> {
        Err(PolicyError::NetworkUnavailable)
    }
}

struct CountingCurrentEgress(Arc<AtomicUsize>);

impl ProviderEgressAdmissionVerifier for CountingCurrentEgress {
    fn authorize(&self, _: &ValidatedProviderEgressAdmissionV1) -> Result<(), PolicyError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

struct ReplacingCurrentEgress {
    original: std::path::PathBuf,
    staged: std::path::PathBuf,
    calls: Arc<AtomicUsize>,
}

impl ProviderEgressAdmissionVerifier for ReplacingCurrentEgress {
    fn authorize(&self, _: &ValidatedProviderEgressAdmissionV1) -> Result<(), PolicyError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if std::fs::rename(&self.original, self.original.with_extension("held")).is_err()
            || std::fs::rename(&self.staged, &self.original).is_err()
        {
            return Err(PolicyError::NetworkUnavailable);
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
    replay_only_service_with_policy(output_root, None, 1_925_000_000)
}

fn replay_only_service_with_policy(
    output_root: &std::path::Path,
    verifier: Option<Arc<dyn ProviderEgressAdmissionVerifier>>,
    now: i64,
) -> Result<RuntimeService, Box<dyn std::error::Error>> {
    let mut builder = RuntimeDependencies::builder()
        .policy(RuntimePolicyDependencyV1::Native)
        .sandbox(RuntimeSandboxDependencyV1::Native)
        .tool_runtime(Arc::new(llm_tool_runtime::ToolRuntime::new(
            ToolRegistry::new(),
        )))
        .provider(RuntimeProviderDependencyV1::Disabled)
        .ledger(RuntimeLedgerDependencyV1::Native)
        .clock(Arc::new(MutableClock::new(now)))
        .store(RuntimeStoreDependencyV1::Native)
        .output_root(output_root);
    if let Some(verifier) = verifier {
        builder = builder.provider_egress_verifier(verifier);
    }
    Ok(RuntimeService::new(builder.build()?))
}

fn run_tree_bytes(
    root: &std::path::Path,
) -> std::io::Result<BTreeMap<std::path::PathBuf, Vec<u8>>> {
    fn collect(
        directory: &std::path::Path,
        relative: &std::path::Path,
        files: &mut BTreeMap<std::path::PathBuf, Vec<u8>>,
    ) -> std::io::Result<()> {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let relative_path = relative.join(entry.file_name());
            let kind = entry.file_type()?;
            if kind.is_dir() {
                files.insert(relative_path.clone(), Vec::new());
                collect(&entry.path(), &relative_path, files)?;
            } else if kind.is_file() {
                files.insert(relative_path, std::fs::read(entry.path())?);
            } else {
                return Err(std::io::Error::other("unexpected run-tree entry"));
            }
        }
        Ok(())
    }

    let mut files = BTreeMap::new();
    collect(root, std::path::Path::new(""), &mut files)?;
    Ok(files)
}

fn copy_run_tree(source: &std::path::Path, target: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir(target)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let destination = target.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_run_tree(&entry.path(), &destination)?;
        } else {
            std::fs::copy(entry.path(), destination)?;
        }
    }
    Ok(())
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

// Construct a self-consistent chain under the SAME canonical run path while
// replacing the admission artifact with a valid but wrong sealed context.
fn replace_with_wrong_binding_chain(
    source: &recursive_agent_ledger::VerifiedReceiptSnapshot,
    source_store: &recursive_agent_ledger::ArtifactStore,
    run_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::rename(run_dir, run_dir.with_extension("held"))?;
    let mut chain = open(&RunPaths::new(run_dir))?;
    let target_store = chain.artifact_store()?;
    for receipt in source.receipts() {
        let mut artifacts = Vec::new();
        for descriptor in &receipt.artifact_refs {
            let bytes = if receipt.kind == ReceiptKindV1::ProviderEgressAdmitted {
                let mut evidence: ProviderEgressAdmissionEvidenceV1 =
                    serde_json::from_slice(&source_store.get(descriptor)?)?;
                let binding = &evidence.binding;
                evidence.binding =
                    ProviderEgressBindingV1::seal(ProviderEgressBindingMaterialV1 {
                        policy_basis_ref: binding.policy_basis_ref.clone(),
                        policy_basis_digest: binding.policy_basis_digest.clone(),
                        context_digest: format!("sha256:{}", "f".repeat(64)),
                        source_revision: binding.source_revision.clone(),
                        graph_obligation_ref: binding.graph_obligation_ref.clone(),
                        graph_obligation_digest: binding.graph_obligation_digest.clone(),
                        route_class: binding.route_class.clone(),
                        provider_identity: binding.provider_identity.clone(),
                        model_ref: binding.model_ref.clone(),
                        input_tokens: binding.input_tokens,
                        output_reserve: binding.output_reserve,
                        request_digest: binding.request_digest.clone(),
                        not_after: binding.not_after,
                    })?;
                evidence.validate()?;
                serde_json::to_vec(&evidence)?
            } else {
                source_store.get(descriptor)?
            };
            artifacts.push(target_store.put(
                &bytes,
                &descriptor.media_type,
                descriptor.encoding.clone(),
            )?);
        }
        chain.append(make_receipt(
            ReceiptDraftV1 {
                run_id: receipt.run_id.clone(),
                step_id: receipt.step_id.clone(),
                kind: receipt.kind.clone(),
                valid_time: receipt.valid_time,
                lineage: receipt.lineage.clone(),
                spec_digest: receipt.spec_digest.clone(),
                args_digest: receipt.args_digest.clone(),
                artifact_refs: artifacts,
                outcome: receipt.outcome.clone(),
            },
            chain.head().clone(),
        )?)?;
    }
    Ok(())
}

// Keep the caller/admission/step chain intact while making the recorded
// response invalid at the application boundary. Generic strict verification
// must still pass, otherwise this fixture would not test policy ordering.
fn replace_with_malformed_response_chain(
    source: &recursive_agent_ledger::VerifiedReceiptSnapshot,
    source_store: &recursive_agent_ledger::ArtifactStore,
    run_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::rename(run_dir, run_dir.with_extension("held"))?;
    let mut chain = open(&RunPaths::new(run_dir))?;
    let target_store = chain.artifact_store()?;
    for receipt in source.receipts() {
        let mut artifacts = Vec::new();
        for descriptor in &receipt.artifact_refs {
            let bytes = if matches!(
                receipt.kind,
                ReceiptKindV1::ArtifactStored | ReceiptKindV1::StepCompleted
            ) {
                b"not-json".to_vec()
            } else {
                source_store.get(descriptor)?
            };
            artifacts.push(target_store.put(
                &bytes,
                &descriptor.media_type,
                descriptor.encoding.clone(),
            )?);
        }
        chain.append(make_receipt(
            ReceiptDraftV1 {
                run_id: receipt.run_id.clone(),
                step_id: receipt.step_id.clone(),
                kind: receipt.kind.clone(),
                valid_time: receipt.valid_time,
                lineage: receipt.lineage.clone(),
                spec_digest: receipt.spec_digest.clone(),
                args_digest: receipt.args_digest.clone(),
                artifact_refs: artifacts,
                outcome: receipt.outcome.clone(),
            },
            chain.head().clone(),
        )?)?;
    }
    Ok(())
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

// Rebuild an otherwise valid run with a StepCompleted receipt claiming a
// different sealed step, while retaining the original operation/admission.
fn replace_with_wrong_step_digest_chain(
    source: &recursive_agent_ledger::VerifiedReceiptSnapshot,
    source_store: &recursive_agent_ledger::ArtifactStore,
    run_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::rename(run_dir, run_dir.with_extension("held"))?;
    let mut chain = open(&RunPaths::new(run_dir))?;
    let target_store = chain.artifact_store()?;
    for receipt in source.receipts() {
        let mut artifacts = Vec::new();
        for descriptor in &receipt.artifact_refs {
            let bytes = source_store.get(descriptor)?;
            let copied =
                target_store.put(&bytes, &descriptor.media_type, descriptor.encoding.clone())?;
            if copied != *descriptor {
                return Err("copied artifact descriptor changed".into());
            }
            artifacts.push(copied);
        }
        let spec_digest = if receipt.kind == ReceiptKindV1::StepCompleted {
            ContentDigest::compute(b"different-sealed-step")
        } else {
            receipt.spec_digest.clone()
        };
        chain.append(make_receipt(
            ReceiptDraftV1 {
                run_id: receipt.run_id.clone(),
                step_id: receipt.step_id.clone(),
                kind: receipt.kind.clone(),
                valid_time: receipt.valid_time,
                lineage: receipt.lineage.clone(),
                spec_digest,
                args_digest: receipt.args_digest.clone(),
                artifact_refs: artifacts,
                outcome: receipt.outcome.clone(),
            },
            chain.head().clone(),
        )?)?;
    }
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
    let before = run_tree_bytes(handle.run_dir())?;
    let replay_service = replay_only_service(output.path())?;
    assert!(matches!(
        replay_service.replay_provider_egress_v3(&operation),
        Err(RuntimeServiceError::ProviderEgressDisabled)
    ));
    assert_eq!(run_tree_bytes(handle.run_dir())?, before);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert!(matches!(
        replay_service.submit_provider_egress_v3(&operation),
        Err(RuntimeServiceError::ProviderEgressDisabled)
    ));
    assert_eq!(run_tree_bytes(handle.run_dir())?, before);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let expired_service = replay_only_service_with_policy(
        output.path(),
        Some(Arc::new(AllowCurrentEgress)),
        1_925_000_000,
    )?;
    assert!(matches!(
        expired_service.replay_provider_egress_v3(&operation),
        Err(RuntimeServiceError::Contract(_))
    ));
    assert_eq!(run_tree_bytes(handle.run_dir())?, before);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let denied_service = replay_only_service_with_policy(
        output.path(),
        Some(Arc::new(DenyCurrentEgress)),
        1_788_220_800,
    )?;
    assert!(matches!(
        denied_service.replay_provider_egress_v3(&operation),
        Err(RuntimeServiceError::Run(
            recursive_agent_runner::RunError::Policy(PolicyError::NetworkUnavailable)
        ))
    ));
    assert_eq!(run_tree_bytes(handle.run_dir())?, before);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    // Denial must also precede effects when a backend is actually configured.
    let denied_clock: Arc<dyn Clock> = Arc::new(MutableClock::new(1_788_220_800));
    let replay_calls = Arc::new(AtomicUsize::new(0));
    let verifier: Arc<dyn ProviderEgressAdmissionVerifier> = Arc::new(DenyCurrentEgress);
    let configured_runtime = tool_runtime_with_sealed_completion(
        ToolRegistry::new(),
        FixtureBackend(replay_calls.clone()),
        denied_clock.clone(),
        verifier.clone(),
    );
    let configured_denied = RuntimeService::new(
        RuntimeDependencies::builder()
            .policy(RuntimePolicyDependencyV1::Native)
            .sandbox(RuntimeSandboxDependencyV1::Native)
            .tool_runtime(Arc::new(configured_runtime))
            .provider(RuntimeProviderDependencyV1::Configured(provider()?))
            .ledger(RuntimeLedgerDependencyV1::Native)
            .clock(denied_clock)
            .store(RuntimeStoreDependencyV1::Native)
            .output_root(output.path())
            .provider_egress_verifier(verifier)
            .build()?,
    );
    assert!(matches!(
        configured_denied.replay_provider_egress_v3(&operation),
        Err(RuntimeServiceError::Run(
            recursive_agent_runner::RunError::Policy(PolicyError::NetworkUnavailable)
        ))
    ));
    assert_eq!(replay_calls.load(Ordering::Relaxed), 0);
    assert_eq!(run_tree_bytes(handle.run_dir())?, before);
    let configured_allowed = candidate_service(
        output.path(),
        replay_calls.clone(),
        Arc::new(MutableClock::new(1_788_220_800)),
        true,
    )?;
    assert_eq!(
        configured_allowed
            .replay_provider_egress_v3(&operation)?
            .run_id(),
        handle.run_id()
    );
    assert_eq!(replay_calls.load(Ordering::Relaxed), 0);
    assert_eq!(run_tree_bytes(handle.run_dir())?, before);
    let allowed_service = replay_only_service_with_policy(
        output.path(),
        Some(Arc::new(AllowCurrentEgress)),
        1_788_220_800,
    )?;
    let replayed = allowed_service.replay_provider_egress_v3(&operation)?;
    assert_eq!(replayed.run_id(), handle.run_id());
    assert_eq!(run_tree_bytes(handle.run_dir())?, before);
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "recorded replay called the backend"
    );
    // A tail repair must not be performed by a recorded readback.
    let log = handle.run_dir().join("receipts.ndjson");
    let mut bytes = std::fs::read(&log)?;
    assert_eq!(bytes.pop(), Some(b'\n'));
    std::fs::write(&log, &bytes)?;
    let repairable = run_tree_bytes(handle.run_dir())?;
    assert!(allowed_service
        .replay_provider_egress_v3(&operation)
        .is_err());
    assert_eq!(run_tree_bytes(handle.run_dir())?, repairable);
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    // A stale but well-formed metadata projection must likewise remain
    // untouched, rather than being silently rebuilt during replay.
    bytes.push(b'\n');
    std::fs::write(&log, bytes)?;
    let meta_path = handle.run_dir().join("chain.meta");
    let mut stale: serde_json::Value = serde_json::from_slice(&std::fs::read(&meta_path)?)?;
    stale["length"] = serde_json::json!(0);
    std::fs::write(
        &meta_path,
        recursive_agent_contracts::jcs_canonical(&stale)?,
    )?;
    let stale_before = run_tree_bytes(handle.run_dir())?;
    assert!(allowed_service
        .replay_provider_egress_v3(&operation)
        .is_err());
    assert_eq!(run_tree_bytes(handle.run_dir())?, stale_before);
    assert_eq!(replay_calls.load(Ordering::Relaxed), 0);
    Ok(())
}

#[test]
fn replay_rejects_valid_chain_with_a_different_sealed_binding_before_policy(
) -> Result<(), Box<dyn std::error::Error>> {
    let output = tempfile::tempdir()?;
    let operation = operation()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let writer = candidate_service(
        output.path(),
        calls.clone(),
        Arc::new(MutableClock::new(1_788_220_800)),
        true,
    )?;
    let handle = writer.submit_provider_egress_v3(&operation)?;
    let (snapshot, store) =
        verified_snapshot_with_artifact_store_directory_bound(&RunPaths::new(handle.run_dir()))?;
    replace_with_wrong_binding_chain(&snapshot, &store, handle.run_dir())?;
    // This is NOT simple corruption: the substituted chain passes the
    // generic strict verifier under the same run ID and canonical path.
    assert!(verify_directory_bound(&RunPaths::new(handle.run_dir()))?.current_strict_success);
    let checks = Arc::new(AtomicUsize::new(0));
    let replay = replay_only_service_with_policy(
        output.path(),
        Some(Arc::new(CountingCurrentEgress(checks.clone()))),
        1_788_220_800,
    )?;
    let before = run_tree_bytes(handle.run_dir())?;
    assert!(replay.replay_provider_egress_v3(&operation).is_err());
    assert_eq!(checks.load(Ordering::Relaxed), 0);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(run_tree_bytes(handle.run_dir())?, before);
    Ok(())
}

#[test]
fn replay_rejects_valid_chain_with_a_different_sealed_step_before_policy(
) -> Result<(), Box<dyn std::error::Error>> {
    let output = tempfile::tempdir()?;
    let operation = operation()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let writer = candidate_service(
        output.path(),
        calls.clone(),
        Arc::new(MutableClock::new(1_788_220_800)),
        true,
    )?;
    let handle = writer.submit_provider_egress_v3(&operation)?;
    let (snapshot, store) =
        verified_snapshot_with_artifact_store_directory_bound(&RunPaths::new(handle.run_dir()))?;
    replace_with_wrong_step_digest_chain(&snapshot, &store, handle.run_dir())?;
    assert!(verify_directory_bound(&RunPaths::new(handle.run_dir()))?.current_strict_success);
    let checks = Arc::new(AtomicUsize::new(0));
    let replay = replay_only_service_with_policy(
        output.path(),
        Some(Arc::new(CountingCurrentEgress(checks.clone()))),
        1_788_220_800,
    )?;
    let before = run_tree_bytes(handle.run_dir())?;
    assert!(matches!(
        replay.replay_provider_egress_v3(&operation),
        Err(RuntimeServiceError::Ledger(LedgerError::RunPackInvalid(message)))
            if message == "recorded provider step does not bind admission"
    ));
    assert_eq!(checks.load(Ordering::Relaxed), 0);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(run_tree_bytes(handle.run_dir())?, before);
    Ok(())
}

#[test]
fn recorded_output_consumer_rechecks_sealed_operation_after_handle_return(
) -> Result<(), Box<dyn std::error::Error>> {
    let output = tempfile::tempdir()?;
    let operation = operation()?;
    let backend_calls = Arc::new(AtomicUsize::new(0));
    let writer = candidate_service(
        output.path(),
        backend_calls.clone(),
        Arc::new(MutableClock::new(1_788_220_800)),
        true,
    )?;
    let handle = writer.submit_provider_egress_v3(&operation)?;
    let policy_calls = Arc::new(AtomicUsize::new(0));
    let reader = replay_only_service_with_policy(
        output.path(),
        Some(Arc::new(CountingCurrentEgress(policy_calls.clone()))),
        1_788_220_800,
    )?;
    let replayed = reader.replay_provider_egress_v3(&operation)?;
    assert_eq!(replayed.run_dir(), handle.run_dir());
    let output_record = reader.read_recorded_provider_output_v3(&operation)?;
    assert_eq!(output_record.text, "receipt-bound fixture response");
    assert_eq!(output_record.model, "fixture-model");
    assert_eq!(policy_calls.load(Ordering::Relaxed), 2);

    // A previously returned path handle cannot authorize a later read.
    let (snapshot, store) =
        verified_snapshot_with_artifact_store_directory_bound(&RunPaths::new(handle.run_dir()))?;
    replace_with_wrong_binding_chain(&snapshot, &store, handle.run_dir())?;
    assert!(verify_directory_bound(&RunPaths::new(handle.run_dir()))?.current_strict_success);
    let before = run_tree_bytes(handle.run_dir())?;
    assert!(matches!(
        reader.read_recorded_provider_output_v3(&operation),
        Err(RuntimeServiceError::Ledger(LedgerError::RunPackInvalid(message)))
            if message == "recorded provider admission does not bind caller"
    ));
    assert_eq!(policy_calls.load(Ordering::Relaxed), 2);
    assert_eq!(backend_calls.load(Ordering::Relaxed), 1);
    assert_eq!(run_tree_bytes(handle.run_dir())?, before);
    Ok(())
}

#[test]
fn malformed_recorded_output_is_rejected_before_current_policy(
) -> Result<(), Box<dyn std::error::Error>> {
    let output = tempfile::tempdir()?;
    let operation = operation()?;
    let backend_calls = Arc::new(AtomicUsize::new(0));
    let writer = candidate_service(
        output.path(),
        backend_calls.clone(),
        Arc::new(MutableClock::new(1_788_220_800)),
        true,
    )?;
    let handle = writer.submit_provider_egress_v3(&operation)?;
    let (snapshot, store) =
        verified_snapshot_with_artifact_store_directory_bound(&RunPaths::new(handle.run_dir()))?;
    replace_with_malformed_response_chain(&snapshot, &store, handle.run_dir())?;
    assert!(verify_directory_bound(&RunPaths::new(handle.run_dir()))?.current_strict_success);
    let policy_calls = Arc::new(AtomicUsize::new(0));
    let reader = replay_only_service_with_policy(
        output.path(),
        Some(Arc::new(CountingCurrentEgress(policy_calls.clone()))),
        1_788_220_800,
    )?;
    let before = run_tree_bytes(handle.run_dir())?;
    assert!(matches!(
        reader.read_recorded_provider_output_v3(&operation),
        Err(RuntimeServiceError::RecordedProviderOutputMalformed)
    ));
    assert_eq!(policy_calls.load(Ordering::Relaxed), 0);
    assert_eq!(backend_calls.load(Ordering::Relaxed), 1);
    assert_eq!(run_tree_bytes(handle.run_dir())?, before);
    Ok(())
}

#[test]
fn recorded_output_consumer_rejects_directory_replacement_during_current_policy(
) -> Result<(), Box<dyn std::error::Error>> {
    let output = tempfile::tempdir()?;
    let operation = operation()?;
    let backend_calls = Arc::new(AtomicUsize::new(0));
    let writer = candidate_service(
        output.path(),
        backend_calls.clone(),
        Arc::new(MutableClock::new(1_788_220_800)),
        true,
    )?;
    let handle = writer.submit_provider_egress_v3(&operation)?;
    let staged = output.path().join("staged-consumer-replacement");
    copy_run_tree(handle.run_dir(), &staged)?;
    assert_eq!(run_tree_bytes(handle.run_dir())?, run_tree_bytes(&staged)?);

    let policy_calls = Arc::new(AtomicUsize::new(0));
    let reader = replay_only_service_with_policy(
        output.path(),
        Some(Arc::new(ReplacingCurrentEgress {
            original: handle.run_dir().to_path_buf(),
            staged,
            calls: policy_calls.clone(),
        })),
        1_788_220_800,
    )?;
    assert!(matches!(
        reader.read_recorded_provider_output_v3(&operation),
        Err(RuntimeServiceError::Ledger(LedgerError::RunPackInvalid(message)))
            if message == "recorded replay run directory was replaced"
    ));
    assert_eq!(policy_calls.load(Ordering::Relaxed), 1);
    assert_eq!(backend_calls.load(Ordering::Relaxed), 1);
    assert!(verify_directory_bound(&RunPaths::new(handle.run_dir()))?.current_strict_success);
    Ok(())
}

#[test]
fn recorded_output_consumer_rejects_expiry_between_validation_and_policy(
) -> Result<(), Box<dyn std::error::Error>> {
    let output = tempfile::tempdir()?;
    let operation = operation()?;
    let backend_calls = Arc::new(AtomicUsize::new(0));
    let writer = candidate_service(
        output.path(),
        backend_calls.clone(),
        Arc::new(MutableClock::new(1_788_220_800)),
        true,
    )?;
    let handle = writer.submit_provider_egress_v3(&operation)?;
    let before = run_tree_bytes(handle.run_dir())?;
    let policy_calls = Arc::new(AtomicUsize::new(0));
    let reader = RuntimeService::new(
        RuntimeDependencies::builder()
            .policy(RuntimePolicyDependencyV1::Native)
            .sandbox(RuntimeSandboxDependencyV1::Native)
            .tool_runtime(Arc::new(llm_tool_runtime::ToolRuntime::new(
                ToolRegistry::new(),
            )))
            .provider(RuntimeProviderDependencyV1::Disabled)
            .ledger(RuntimeLedgerDependencyV1::Native)
            .clock(Arc::new(ExpiringBetweenChecksClock(AtomicUsize::new(0))))
            .store(RuntimeStoreDependencyV1::Native)
            .provider_egress_verifier(Arc::new(CountingCurrentEgress(policy_calls.clone())))
            .output_root(output.path())
            .build()?,
    );
    assert!(matches!(
        reader.read_recorded_provider_output_v3(&operation),
        Err(RuntimeServiceError::Run(
            recursive_agent_runner::RunError::Policy(_)
        ))
    ));
    assert_eq!(policy_calls.load(Ordering::Relaxed), 0);
    assert_eq!(backend_calls.load(Ordering::Relaxed), 1);
    assert_eq!(run_tree_bytes(handle.run_dir())?, before);
    Ok(())
}

#[test]
fn replay_rejects_directory_replacement_during_current_policy(
) -> Result<(), Box<dyn std::error::Error>> {
    let output = tempfile::tempdir()?;
    let operation = operation()?;
    let backend_calls = Arc::new(AtomicUsize::new(0));
    let writer = candidate_service(
        output.path(),
        backend_calls.clone(),
        Arc::new(MutableClock::new(1_788_220_800)),
        true,
    )?;
    let handle = writer.submit_provider_egress_v3(&operation)?;
    let staged = output.path().join("staged-replacement");
    copy_run_tree(handle.run_dir(), &staged)?;
    assert_eq!(run_tree_bytes(handle.run_dir())?, run_tree_bytes(&staged)?);

    let calls = Arc::new(AtomicUsize::new(0));
    let replay = replay_only_service_with_policy(
        output.path(),
        Some(Arc::new(ReplacingCurrentEgress {
            original: handle.run_dir().to_path_buf(),
            staged,
            calls: calls.clone(),
        })),
        1_788_220_800,
    )?;
    assert!(matches!(
        replay.replay_provider_egress_v3(&operation),
        Err(RuntimeServiceError::Ledger(LedgerError::RunPackInvalid(message)))
            if message == "recorded replay run directory was replaced"
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(backend_calls.load(Ordering::Relaxed), 1);
    assert!(verify_directory_bound(&RunPaths::new(handle.run_dir()))?.current_strict_success);
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
fn invalid_recorded_evidence_does_not_invoke_current_policy(
) -> Result<(), Box<dyn std::error::Error>> {
    let output = tempfile::tempdir()?;
    let operation = operation()?;
    let checks = Arc::new(AtomicUsize::new(0));
    let replay = replay_only_service_with_policy(
        output.path(),
        Some(Arc::new(CountingCurrentEgress(checks.clone()))),
        1_788_220_800,
    )?;
    assert!(replay.replay_provider_egress_v3(&operation).is_err());
    assert_eq!(checks.load(Ordering::Relaxed), 0);

    let backend_calls = Arc::new(AtomicUsize::new(0));
    let writer = candidate_service(
        output.path(),
        backend_calls.clone(),
        Arc::new(MutableClock::new(1_788_220_800)),
        true,
    )?;
    let handle = writer.submit_provider_egress_v3(&operation)?;
    assert_eq!(backend_calls.load(Ordering::Relaxed), 1);
    let log_path = handle.run_dir().join("receipts.ndjson");
    let log = std::fs::read(&log_path)?;
    std::fs::write(&log_path, &log[..log.len() - 1])?;
    let before = run_tree_bytes(handle.run_dir())?;
    assert!(replay.replay_provider_egress_v3(&operation).is_err());
    assert_eq!(
        checks.load(Ordering::Relaxed),
        0,
        "invalid tail reached policy"
    );
    assert_eq!(run_tree_bytes(handle.run_dir())?, before);

    std::fs::write(&log_path, &log)?;
    let meta_path = handle.run_dir().join("chain.meta");
    let mut stale: serde_json::Value = serde_json::from_slice(&std::fs::read(&meta_path)?)?;
    stale["length"] = serde_json::json!(0);
    std::fs::write(
        &meta_path,
        recursive_agent_contracts::jcs_canonical(&stale)?,
    )?;
    let before = run_tree_bytes(handle.run_dir())?;
    assert!(replay.replay_provider_egress_v3(&operation).is_err());
    assert_eq!(
        checks.load(Ordering::Relaxed),
        0,
        "stale metadata reached policy"
    );
    assert_eq!(run_tree_bytes(handle.run_dir())?, before);
    assert_eq!(backend_calls.load(Ordering::Relaxed), 1);
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
