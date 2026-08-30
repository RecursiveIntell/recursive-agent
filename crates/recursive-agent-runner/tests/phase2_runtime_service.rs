use std::sync::Arc;
use std::sync::{mpsc, Mutex};

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use llm_tool_runtime::{
    McpSurfaceKind, Tool, ToolApprovalKind, ToolBackendKind, ToolCtx, ToolDescriptor, ToolError,
    ToolExposureMode, ToolExposurePolicy, ToolIdempotencyClass, ToolOutputMode,
    ToolReceiptPersistence, ToolRegistry, ToolResult, ToolRuntime, ToolSideEffectClass,
};
use recursive_agent_contracts::{
    content_digest, derive_operation_id, ActorAuthorityV1, AuthorityOriginV1, CausalLinkV1,
    ChildOperationProposalV2, ContentDigest, DeclaredEffectsV1, OperationBudgetV1,
    OperationEnvelopeV1, OperationSchemaV1, ProvenanceRefV1, ReceiptKindV1, ReceiptV1,
    ReplayClassV1, ReplayIntentV1, ReplaySpecV1, RunSpecV1, RunTerminalStateV1, RuntimeEventKindV1,
    StepSpecV1, ToolCallSpecV1,
};
use recursive_agent_ledger::{
    make_receipt, open, put_string, verified_snapshot_directory_bound, ArtifactStore,
    ChildRunLinkV1, ReceiptDraftV1, RunPaths,
};
use recursive_agent_memory::MemoryStore;
use recursive_agent_provider::{
    CompletionBackend, CompletionResponseV1, ProviderSpecV1, ValidatedEndpoint,
};
use recursive_agent_runner::{
    AutonomousBudgetV1, AutonomousCancellation, AutonomousTranscript, Clock, RuntimeCancelResultV1,
    RuntimeDependencies, RuntimeDependencyError, RuntimeLedgerDependencyV1,
    RuntimePolicyDependencyV1, RuntimeProviderDependencyV1, RuntimeSandboxDependencyV1,
    RuntimeService, RuntimeServiceError, RuntimeStatusV1, RuntimeStoreDependencyV1, SystemClock,
};

struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> chrono::DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000, 0)
            .single()
            .unwrap_or_else(Utc::now)
    }

    fn monotonic_now(&self) -> std::time::Duration {
        std::time::Duration::ZERO
    }
}

struct FakeEchoTool {
    descriptor: ToolDescriptor,
}

impl FakeEchoTool {
    fn named(name: &str) -> Self {
        Self {
            descriptor: ToolDescriptor {
                name: name.into(),
                version: "1.0.0".into(),
                description: Some("deterministic Phase 2 echo fixture".into()),
                backend_kind: ToolBackendKind::LocalFunction,
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                    "additionalProperties": false
                }),
                output_mode: ToolOutputMode::StructuredJson,
                read_only: true,
                side_effect_class: ToolSideEffectClass::ReadOnly,
                idempotency_class: ToolIdempotencyClass::Idempotent,
                approval_kind: ToolApprovalKind::None,
                timeout_ms: 1_000,
                concurrency_key: None,
                cache_ttl_ms: None,
                exposure_mode: ToolExposureMode::Auto,
                mcp_surface_kind: McpSurfaceKind::None,
                exposure_policy: ToolExposurePolicy::default(),
                receipt_persistence: ToolReceiptPersistence::Ephemeral,
                output_size_limit_bytes: Some(4_096),
                provider_payload: None,
            },
        }
    }
}

#[async_trait]
impl Tool for FakeEchoTool {
    fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }

    async fn invoke(
        &self,
        _ctx: &ToolCtx,
        call: &llm_tool_runtime::ToolCall,
    ) -> Result<ToolResult, ToolError> {
        Ok(ToolResult::json(serde_json::json!({
            "owner": "admitted-llm-tool-runtime",
            "arguments": call.arguments.clone()
        })))
    }
}

fn fake_tool_runtime(tool_names: &[&str]) -> Arc<ToolRuntime> {
    let mut registry = ToolRegistry::new();
    for name in tool_names {
        registry.register(FakeEchoTool::named(name));
    }
    Arc::new(ToolRuntime::new(registry))
}

/// A test-only gate that makes cancellation land while a real admitted child
/// effect is executing. The runner's second family check must then prevent the
/// child from committing success.
struct BlockingTool {
    descriptor: ToolDescriptor,
    started: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

#[async_trait]
impl Tool for BlockingTool {
    fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }

    async fn invoke(
        &self,
        _ctx: &ToolCtx,
        call: &llm_tool_runtime::ToolCall,
    ) -> Result<ToolResult, ToolError> {
        if call.arguments.get("text") == Some(&serde_json::Value::String("child".into())) {
            let _ = self.started.send(());
            if let Ok(release) = self.release.lock() {
                let _ = release.recv_timeout(std::time::Duration::from_secs(5));
            }
        }
        Ok(ToolResult::json(serde_json::json!({
            "owner": "blocking-child-fixture",
            "arguments": call.arguments.clone()
        })))
    }
}

fn blocking_tool_runtime(
    started: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
) -> Arc<ToolRuntime> {
    let mut registry = ToolRegistry::new();
    registry.register(BlockingTool {
        descriptor: FakeEchoTool::named("echo").descriptor,
        started,
        release: Mutex::new(release),
    });
    Arc::new(ToolRuntime::new(registry))
}

fn sample_operation() -> Result<OperationEnvelopeV1, Box<dyn std::error::Error>> {
    let run_spec = RunSpecV1 {
        name: "runtime-service".into(),
        steps: vec![StepSpecV1 {
            name: "echo".into(),
            call: ToolCallSpecV1 {
                tool: "echo".into(),
                args: serde_json::json!({"text": "hello"}),
                frozen_clock: None,
            },
        }],
        frozen_clock: None,
        policy_version: "m0-2".into(),
    };
    Ok(OperationEnvelopeV1 {
        schema: OperationSchemaV1::V1,
        actor: ActorAuthorityV1 {
            principal: "actor:runtime-service-test".into(),
            origin: AuthorityOriginV1::Direct,
        },
        causality: CausalLinkV1 {
            parent_operation_id: None,
            root_operation_id: None,
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
            network_allowed: false,
            action_digest: content_digest(&run_spec)?,
        },
        provenance: vec![ProvenanceRefV1 {
            source: "urn:test:runtime-service".into(),
            digest: ContentDigest::compute(b"runtime-service-request"),
        }],
        replay: ReplaySpecV1 {
            class: ReplayClassV1::Deterministic,
            intent: ReplayIntentV1::ExecuteOnce,
        },
        run_spec,
    })
}

fn child_proposal(
    parent: &OperationEnvelopeV1,
) -> Result<ChildOperationProposalV2, Box<dyn std::error::Error>> {
    let parent_id = derive_operation_id(parent)?;
    let mut run_spec = parent.run_spec.clone();
    run_spec.name = "runtime-service-child".into();
    run_spec.steps[0].call.args = serde_json::json!({"text": "child"});
    Ok(ChildOperationProposalV2 {
        schema: OperationSchemaV1::V2,
        actor: ActorAuthorityV1 {
            principal: parent.actor.principal.clone(),
            origin: AuthorityOriginV1::Delegated,
        },
        causality: CausalLinkV1 {
            parent_operation_id: Some(parent_id.clone()),
            root_operation_id: Some(parent_id),
        },
        budget: parent.budget.clone(),
        effects: DeclaredEffectsV1 {
            action_digest: content_digest(&run_spec)?,
            ..parent.effects.clone()
        },
        provenance: parent.provenance.clone(),
        replay: parent.replay.clone(),
        run_spec,
    })
}

/// Rebuild a parent chain after replacing only a child-link artifact. This keeps
/// every artifact descriptor and every receipt-chain digest valid, so rejection
/// below proves semantic cross-run verification rather than byte-tamper detection.
fn rebuild_parent_chain(
    run_dir: &std::path::Path,
    mutate: impl FnOnce(&mut Vec<ReceiptV1>, &ArtifactStore) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let paths = RunPaths::new(run_dir);
    let snapshot = verified_snapshot_directory_bound(&paths)?;
    let root = std::fs::File::open(run_dir)?;
    let store = ArtifactStore::from_run_root_fd(&root, false)?;
    let mut receipts = snapshot.receipts().to_vec();
    mutate(&mut receipts, &store)?;

    std::fs::remove_file(paths.receipts_path())?;
    std::fs::remove_file(paths.chain_meta_path())?;
    let mut chain = open(&paths)?;
    for receipt in receipts {
        let replacement = make_receipt(
            ReceiptDraftV1 {
                run_id: receipt.run_id,
                step_id: receipt.step_id,
                kind: receipt.kind,
                valid_time: receipt.valid_time,
                lineage: receipt.lineage,
                spec_digest: receipt.spec_digest,
                args_digest: receipt.args_digest,
                artifact_refs: receipt.artifact_refs,
                outcome: receipt.outcome,
            },
            chain.head().clone(),
        )?;
        chain.append(replacement)?;
    }
    Ok(())
}

fn replace_child_link_artifact(
    receipts: &mut [ReceiptV1],
    store: &ArtifactStore,
    receipt_kind: ReceiptKindV1,
    mutate: impl FnOnce(&mut ChildRunLinkV1),
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = receipts
        .iter_mut()
        .find(|receipt| receipt.kind == receipt_kind)
        .ok_or("missing child-link receipt")?;
    let descriptor = receipt
        .artifact_refs
        .first()
        .ok_or("missing child-link descriptor")?;
    let mut link: ChildRunLinkV1 = serde_json::from_slice(&store.get(descriptor)?)?;
    mutate(&mut link);
    receipt.artifact_refs = vec![put_string(store, &serde_json::to_string(&link)?)?];
    Ok(())
}

fn slow_shell_operation() -> Result<OperationEnvelopeV1, Box<dyn std::error::Error>> {
    let mut operation = sample_operation()?;
    operation.run_spec.name = "runtime-service-concurrent-duplicate".into();
    operation.run_spec.steps[0].call = ToolCallSpecV1 {
        tool: "shell".into(),
        args: serde_json::json!({
            "command": "/usr/bin/sleep",
            "args": ["0.5"],
            "allowed_read_paths": [],
            "allowed_write_paths": [],
            "allow_network": false,
            "timeout_ms": 2_000,
            "max_output_bytes": 4_096
        }),
        frozen_clock: None,
    };
    operation.budget.max_wall_time_ms = 3_000;
    operation.effects.action_digest = content_digest(&operation.run_spec)?;
    operation.replay.class = ReplayClassV1::RecordedEffect;
    Ok(operation)
}

fn service_dependencies(
    output_root: &std::path::Path,
) -> Result<RuntimeDependencies, Box<dyn std::error::Error>> {
    service_dependencies_with_tools(output_root, &["echo"])
}

fn service_dependencies_with_tools(
    output_root: &std::path::Path,
    tool_names: &[&str],
) -> Result<RuntimeDependencies, Box<dyn std::error::Error>> {
    service_dependencies_with_runtime(output_root, fake_tool_runtime(tool_names))
}

fn service_dependencies_with_runtime(
    output_root: &std::path::Path,
    tool_runtime: Arc<ToolRuntime>,
) -> Result<RuntimeDependencies, Box<dyn std::error::Error>> {
    Ok(RuntimeDependencies::builder()
        .policy(RuntimePolicyDependencyV1::Native)
        .sandbox(RuntimeSandboxDependencyV1::Native)
        .tool_runtime(tool_runtime)
        .provider(RuntimeProviderDependencyV1::Configured(
            ProviderSpecV1::Ollama {
                base_url: ValidatedEndpoint::try_new("http://127.0.0.1:1")?,
                model: "deterministic-fake-provider".into(),
            },
        ))
        .ledger(RuntimeLedgerDependencyV1::Native)
        .clock(Arc::new(FixedClock))
        .store(RuntimeStoreDependencyV1::Native)
        .output_root(output_root)
        .build()?)
}

#[test]
fn runtime_dependencies_fail_closed_when_any_owner_is_missing() {
    let result = RuntimeDependencies::builder().build();
    assert!(result.is_err(), "empty runtime dependencies must not build");
    let error = match result {
        Ok(_) => return,
        Err(error) => error,
    };
    assert_eq!(
        error,
        RuntimeDependencyError::Missing {
            names: vec![
                "policy",
                "sandbox",
                "tool_runtime",
                "provider",
                "ledger",
                "clock",
                "store",
                "output_root",
            ]
        }
    );
}

#[test]
fn runtime_dependencies_preserve_every_explicit_owner() -> Result<(), Box<dyn std::error::Error>> {
    let output_root = tempfile::tempdir()?;
    let tool_runtime = Arc::new(ToolRuntime::new(ToolRegistry::new()));
    let dependencies = RuntimeDependencies::builder()
        .policy(RuntimePolicyDependencyV1::Native)
        .sandbox(RuntimeSandboxDependencyV1::Native)
        .tool_runtime(Arc::clone(&tool_runtime))
        .provider(RuntimeProviderDependencyV1::Disabled)
        .ledger(RuntimeLedgerDependencyV1::Native)
        .clock(Arc::new(SystemClock))
        .store(RuntimeStoreDependencyV1::Native)
        .output_root(output_root.path())
        .build()?;

    assert_eq!(dependencies.policy(), RuntimePolicyDependencyV1::Native);
    assert_eq!(dependencies.sandbox(), RuntimeSandboxDependencyV1::Native);
    assert!(std::ptr::eq(
        dependencies.tool_runtime(),
        tool_runtime.as_ref()
    ));
    assert_eq!(
        dependencies.provider(),
        &RuntimeProviderDependencyV1::Disabled
    );
    assert_eq!(dependencies.ledger(), RuntimeLedgerDependencyV1::Native);
    assert_eq!(dependencies.store(), RuntimeStoreDependencyV1::Native);
    assert_eq!(dependencies.output_root(), output_root.path());
    Ok(())
}

#[test]
fn runtime_service_submit_uses_operation_identity_for_the_authoritative_run(
) -> Result<(), Box<dyn std::error::Error>> {
    let output_root = tempfile::tempdir()?;
    let operation = sample_operation()?;
    let expected_operation_id = derive_operation_id(&operation)?;
    let expected_run_directory = output_root
        .path()
        .join(content_digest(&expected_operation_id)?.to_string());
    let service = RuntimeService::new(service_dependencies(output_root.path())?);

    let handle = service.submit(&operation)?;

    assert_eq!(handle.operation_id(), &expected_operation_id);
    assert_eq!(handle.run_id(), handle.operation_id());
    assert_eq!(handle.run_dir(), expected_run_directory);
    assert!(handle.run_dir().is_dir());
    Ok(())
}

#[test]
fn live_parent_v2_binds_child_admission_before_dispatch_and_finalizes_only_after_closure(
) -> Result<(), Box<dyn std::error::Error>> {
    let output_root = tempfile::tempdir()?;
    let parent = sample_operation()?;
    let child = child_proposal(&parent)?;
    let service = RuntimeService::new(service_dependencies(output_root.path())?);

    let mut live_parent = service.begin_parent_v2(&parent)?;
    let child_handle = live_parent.submit_child(&child)?;
    let parent_handle = live_parent.finalize()?;

    assert!(
        service
            .verify(child_handle.run_id())?
            .current_strict_success
    );
    assert!(
        service
            .verify(parent_handle.run_id())?
            .current_strict_success
    );
    let parent_snapshot =
        verified_snapshot_directory_bound(&RunPaths::new(parent_handle.run_dir()))?;
    assert!(
        parent_snapshot
            .receipts()
            .iter()
            .any(|receipt| receipt.kind == ReceiptKindV1::ChildAdmissionPrepared),
        "a durable parent admission receipt must precede every child dispatch"
    );
    assert!(
        parent_snapshot
            .receipts()
            .iter()
            .any(|receipt| receipt.kind == ReceiptKindV1::ChildLinked),
        "the parent must record a content-addressed child link"
    );
    assert!(
        parent_snapshot
            .receipts()
            .iter()
            .any(|receipt| receipt.kind == ReceiptKindV1::ChildClosed),
        "the parent must record verified child terminal closure"
    );
    Ok(())
}

#[test]
fn live_parent_cancellation_revokes_family_before_child_admission_and_closes_parent(
) -> Result<(), Box<dyn std::error::Error>> {
    let output_root = tempfile::tempdir()?;
    let parent = sample_operation()?;
    let child = child_proposal(&parent)?;
    let service = RuntimeService::new(service_dependencies(output_root.path())?);

    let mut live_parent = service.begin_parent_v2(&parent)?;
    assert!(matches!(
        service.cancel(live_parent.run_id())?,
        RuntimeCancelResultV1::CancellationRequested { .. }
    ));
    assert!(matches!(
        live_parent.submit_child(&child),
        Err(RuntimeServiceError::LiveParentNotAdmissible {
            state: RunTerminalStateV1::Cancelled
        })
    ));

    let parent_handle = live_parent.finalize()?;
    let verification = service.verify(parent_handle.run_id())?;
    assert_eq!(verification.terminal_state, RunTerminalStateV1::Cancelled);
    assert!(verification.current_strict_success);
    Ok(())
}

#[test]
fn live_parent_cancellation_during_child_effect_prevents_child_success_and_cancels_parent(
) -> Result<(), Box<dyn std::error::Error>> {
    let output_root = tempfile::tempdir()?;
    let parent = sample_operation()?;
    let child = child_proposal(&parent)?;
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let service = RuntimeService::new(service_dependencies_with_runtime(
        output_root.path(),
        blocking_tool_runtime(started_tx, release_rx),
    )?);
    let mut live_parent = service.begin_parent_v2(&parent)?;
    let parent_run_id = live_parent.run_id().clone();

    let child_handle = std::thread::scope(|scope| -> Result<_, Box<dyn std::error::Error>> {
        let worker = scope.spawn(|| live_parent.submit_child(&child));
        started_rx.recv_timeout(std::time::Duration::from_secs(2))?;
        assert!(matches!(
            service.cancel(&parent_run_id)?,
            RuntimeCancelResultV1::CancellationRequested { .. }
        ));
        release_tx.send(())?;
        Ok(worker
            .join()
            .map_err(|_| std::io::Error::other("child worker panicked"))??)
    })?;

    let child_verification = service.verify(child_handle.run_id())?;
    assert_ne!(
        child_verification.terminal_state,
        RunTerminalStateV1::Succeeded,
        "the post-effect family guard must prevent a revoked child from reporting success"
    );
    let parent_handle = live_parent.finalize()?;
    assert_eq!(
        service.verify(parent_handle.run_id())?.terminal_state,
        RunTerminalStateV1::Cancelled
    );
    Ok(())
}

#[test]
fn live_parent_strict_verification_rejects_tampered_link_and_closure_artifacts(
) -> Result<(), Box<dyn std::error::Error>> {
    for receipt_kind in [ReceiptKindV1::ChildLinked, ReceiptKindV1::ChildClosed] {
        let output_root = tempfile::tempdir()?;
        let parent = sample_operation()?;
        let child = child_proposal(&parent)?;
        let service = RuntimeService::new(service_dependencies(output_root.path())?);
        let mut live_parent = service.begin_parent_v2(&parent)?;
        let _child_handle = live_parent.submit_child(&child)?;
        let parent_handle = live_parent.finalize()?;
        let snapshot = verified_snapshot_directory_bound(&RunPaths::new(parent_handle.run_dir()))?;
        let descriptor = snapshot
            .receipts()
            .iter()
            .find(|receipt| receipt.kind == receipt_kind)
            .and_then(|receipt| receipt.artifact_refs.first())
            .ok_or("missing child link artifact")?;
        std::fs::write(
            parent_handle
                .run_dir()
                .join("artifacts")
                .join(descriptor.digest.hex()),
            b"tampered-child-link",
        )?;
        assert!(
            service.verify(parent_handle.run_id()).is_err(),
            "strict verification must reject tampered {receipt_kind:?} bytes"
        );
    }
    Ok(())
}

#[test]
fn live_parent_strict_verification_rejects_semantic_child_link_matrix_with_valid_descriptors(
) -> Result<(), Box<dyn std::error::Error>> {
    for case in [
        "altered-admission",
        "duplicate-link",
        "duplicate-closure",
        "missing-closure",
        "terminal-state-mismatch",
        "chain-head-mismatch",
    ] {
        let output_root = tempfile::tempdir()?;
        let parent = sample_operation()?;
        let child = child_proposal(&parent)?;
        let service = RuntimeService::new(service_dependencies(output_root.path())?);
        let mut live_parent = service.begin_parent_v2(&parent)?;
        let _child_handle = live_parent.submit_child(&child)?;
        let parent_handle = live_parent.finalize()?;

        let result = rebuild_parent_chain(parent_handle.run_dir(), |receipts, store| {
            match case {
                "altered-admission" => {
                    let unrelated_receipt_id = receipts
                        .iter()
                        .find(|receipt| receipt.kind == ReceiptKindV1::RunStarted)
                        .ok_or("missing RunStarted receipt")?
                        .receipt_id
                        .clone();
                    replace_child_link_artifact(
                        receipts,
                        store,
                        ReceiptKindV1::ChildLinked,
                        |link| link.parent_receipt_id = unrelated_receipt_id,
                    )?;
                }
                "duplicate-link" | "duplicate-closure" => {
                    let kind = if case == "duplicate-link" {
                        ReceiptKindV1::ChildLinked
                    } else {
                        ReceiptKindV1::ChildClosed
                    };
                    let index = receipts
                        .iter()
                        .position(|receipt| receipt.kind == kind)
                        .ok_or("missing child receipt to duplicate")?;
                    receipts.insert(index + 1, receipts[index].clone());
                }
                "missing-closure" => {
                    receipts.retain(|receipt| receipt.kind != ReceiptKindV1::ChildClosed);
                }
                "terminal-state-mismatch" => replace_child_link_artifact(
                    receipts,
                    store,
                    ReceiptKindV1::ChildClosed,
                    |link| link.child_terminal_state = Some(RunTerminalStateV1::Cancelled),
                )?,
                "chain-head-mismatch" => replace_child_link_artifact(
                    receipts,
                    store,
                    ReceiptKindV1::ChildClosed,
                    |link| link.child_chain_head = Some("00".repeat(32)),
                )?,
                _ => return Err(format!("unknown semantic child-link case: {case}").into()),
            }
            Ok(())
        });

        match result {
            Ok(()) => assert!(
                service.verify(parent_handle.run_id()).is_err(),
                "strict verification must reject semantic child-link case {case} even when descriptors and chain are valid"
            ),
            Err(error) => assert!(
                error.to_string().to_lowercase().contains("child"),
                "receipt construction must reject semantic child-link case {case}: {error}"
            ),
        }
    }
    Ok(())
}

#[test]
fn runtime_service_commits_output_from_the_admitted_tool_runtime(
) -> Result<(), Box<dyn std::error::Error>> {
    let output_root = tempfile::tempdir()?;
    let service = RuntimeService::new(service_dependencies(output_root.path())?);
    let handle = service.submit(&sample_operation()?)?;
    let paths = RunPaths::new(handle.run_dir());
    let snapshot = verified_snapshot_directory_bound(&paths)?;
    let completed = snapshot
        .receipts()
        .iter()
        .find(|receipt| receipt.kind == ReceiptKindV1::StepCompleted)
        .ok_or("missing StepCompleted receipt")?;
    let descriptor = completed
        .artifact_refs
        .first()
        .ok_or("StepCompleted receipt has no output artifact")?;
    let run_root = std::fs::File::open(handle.run_dir())?;
    let store = ArtifactStore::from_run_root_fd(&run_root, false)?;
    let output: serde_json::Value = serde_json::from_slice(&store.get(descriptor)?)?;

    assert_eq!(output["owner"], "admitted-llm-tool-runtime");
    assert_eq!(output["arguments"]["text"], "hello");
    Ok(())
}

#[test]
fn admitted_tool_dispatch_preserves_cross_run_event_semantics(
) -> Result<(), Box<dyn std::error::Error>> {
    let first_root = tempfile::tempdir()?;
    let second_root = tempfile::tempdir()?;
    let operation = sample_operation()?;

    let first_service = RuntimeService::new(service_dependencies(first_root.path())?);
    let first_handle = first_service.submit(&operation)?;
    let first_events = first_service.events(first_handle.run_id(), None)?;

    let second_service = RuntimeService::new(service_dependencies(second_root.path())?);
    let second_handle = second_service.submit(&operation)?;
    let second_events = second_service.events(second_handle.run_id(), None)?;

    assert_eq!(first_handle.operation_id(), second_handle.operation_id());
    let first_semantics: Vec<_> = first_events
        .iter()
        .map(|event| (event.sequence, event.kind.clone()))
        .collect();
    let second_semantics: Vec<_> = second_events
        .iter()
        .map(|event| (event.sequence, event.kind.clone()))
        .collect();
    assert_eq!(first_semantics, second_semantics);
    assert!(first_service.verify(first_handle.run_id())?.ok);
    assert!(second_service.verify(second_handle.run_id())?.ok);
    Ok(())
}

#[test]
fn runtime_service_reads_status_events_and_verification_from_committed_evidence(
) -> Result<(), Box<dyn std::error::Error>> {
    let output_root = tempfile::tempdir()?;
    let service = RuntimeService::new(service_dependencies(output_root.path())?);
    let handle = service.submit(&sample_operation()?)?;

    let events = service.events(handle.run_id(), None)?;
    assert!(!events.is_empty());
    assert!(matches!(
        events.last().map(|event| &event.kind),
        Some(RuntimeEventKindV1::Completed { .. })
    ));
    let cursor = events.last().map(|event| event.sequence);
    assert!(service.events(handle.run_id(), cursor)?.is_empty());

    assert_eq!(
        service.status(handle.run_id())?,
        RuntimeStatusV1::Terminal {
            state: RunTerminalStateV1::Succeeded
        }
    );
    let verification = service.verify(handle.run_id())?;
    assert!(verification.ok);
    assert!(verification.current_strict_success);
    assert_eq!(verification.verified_run_id.as_ref(), Some(handle.run_id()));
    assert_eq!(
        service.cancel(handle.run_id())?,
        RuntimeCancelResultV1::AlreadyTerminal {
            state: RunTerminalStateV1::Succeeded
        }
    );
    Ok(())
}

#[test]
fn runtime_service_rejects_unknown_tools_before_creating_output_root(
) -> Result<(), Box<dyn std::error::Error>> {
    let parent = tempfile::tempdir()?;
    let output_root = parent.path().join("must-not-exist");
    let operation = sample_operation()?;
    let service = RuntimeService::new(service_dependencies_with_tools(&output_root, &[])?);

    let result = service.submit(&operation);

    assert!(matches!(
        result,
        Err(RuntimeServiceError::ToolNotRegistered { name }) if name == "echo"
    ));
    assert!(!output_root.exists());
    Ok(())
}

#[test]
fn runtime_service_rejects_concurrent_duplicate_execution() -> Result<(), Box<dyn std::error::Error>>
{
    let output_root = tempfile::tempdir()?;
    let operation = slow_shell_operation()?;
    let operation_id = derive_operation_id(&operation)?;
    let service = Arc::new(RuntimeService::new(service_dependencies_with_tools(
        output_root.path(),
        &["shell"],
    )?));
    let worker_service = Arc::clone(&service);
    let worker_operation = operation.clone();
    let worker = std::thread::spawn(move || {
        worker_service
            .submit(&worker_operation)
            .map_err(|error| error.to_string())
    });

    let mut observed_active = false;
    for _ in 0..200 {
        if matches!(service.status(&operation_id), Ok(RuntimeStatusV1::Active)) {
            observed_active = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(
        observed_active,
        "first submission was never observed active"
    );

    assert!(matches!(
        service.submit(&operation),
        Err(RuntimeServiceError::OperationAlreadyActive { .. })
    ));
    let worker_result = worker
        .join()
        .map_err(|_| std::io::Error::other("runtime-service worker panicked"))?;
    worker_result.map_err(std::io::Error::other)?;
    assert!(matches!(
        service.status(&operation_id)?,
        RuntimeStatusV1::Terminal { .. }
    ));
    Ok(())
}

struct ModelPlanFixture {
    responses: Mutex<Vec<String>>,
    prompts: Mutex<Vec<String>>,
}

impl CompletionBackend for ModelPlanFixture {
    fn complete(
        &self,
        request: &recursive_agent_provider::CompletionRequestV1,
    ) -> Result<CompletionResponseV1, recursive_agent_provider::ProviderError> {
        self.prompts
            .lock()
            .map_err(|_| recursive_agent_provider::ProviderError::Unavailable)?
            .push(request.prompt.clone());
        let response = self
            .responses
            .lock()
            .map_err(|_| recursive_agent_provider::ProviderError::Unavailable)?
            .pop()
            .ok_or(recursive_agent_provider::ProviderError::Unavailable)?;
        Ok(CompletionResponseV1 {
            model: "fixture-model".into(),
            text: response,
            raw: serde_json::json!({"fixture": true}),
        })
    }
}

#[test]
fn runtime_service_model_loop_executes_fixture_plan_through_native_submit(
) -> Result<(), Box<dyn std::error::Error>> {
    let output_root = tempfile::tempdir()?;
    let operation = sample_operation()?;
    let plan = serde_json::json!({
        "complete": false,
        "intents": [{
            "name": "native_operation",
            "payload": {"operation": operation},
            "delegate": false
        }]
    });
    let terminal_plan = serde_json::json!({"complete": true, "intents": []});
    let backend = ModelPlanFixture {
        responses: Mutex::new(vec![terminal_plan.to_string(), plan.to_string()]),
        prompts: Mutex::new(Vec::new()),
    };
    let service = RuntimeService::new(service_dependencies(output_root.path())?);
    let memory = MemoryStore::open(&output_root.path().join("memory.db"))?;
    let cancellation = AutonomousCancellation::new();
    let result = service.run_model_autonomous(
        serde_json::json!({"goal": "execute the admitted fixture operation"}),
        &memory,
        None,
        AutonomousTranscript::open(&output_root.path().join("autonomy.ndjson"))?,
        AutonomousBudgetV1 {
            max_depth: 1,
            max_steps: 2,
            max_children: 1,
            max_wall_time_ms: 10_000,
            max_output_bytes: 16_384,
        },
        &cancellation,
        ProviderSpecV1::Ollama {
            base_url: ValidatedEndpoint::try_new("http://127.0.0.1:11434")?,
            model: "fixture-model".into(),
        },
        &backend,
        Some(256),
    )?;
    assert_eq!(result.output["verified"], true);
    assert!(result.output["run_id"].as_str().is_some());
    let prompts = backend
        .prompts
        .lock()
        .map_err(|_| std::io::Error::other("model fixture prompt lock poisoned"))?;
    assert_eq!(
        prompts.len(),
        2,
        "execution must require explicit completion"
    );
    let second_envelope = prompts[1]
        .split_once("\nCONTEXT:\n")
        .map(|(_, context)| context)
        .ok_or("planner context delimiter missing")?;
    let second_envelope: serde_json::Value = serde_json::from_str(second_envelope)?;
    assert_eq!(
        second_envelope["input"]["verified"], true,
        "the next planner context must contain the preceding observed output"
    );
    drop(prompts);
    let receipt = result
        .receipt
        .as_ref()
        .ok_or("native autonomous result omitted verified terminal receipt")?;
    let native_run_id = result.output["run_id"]
        .as_str()
        .ok_or("native autonomous result omitted run id")?;
    let native_run_id = recursive_agent_contracts::CurrentRunId::try_new(native_run_id)?;
    let native_snapshot = verified_snapshot_directory_bound(&RunPaths::new(
        output_root
            .path()
            .join(content_digest(&native_run_id)?.to_string()),
    ))?;
    assert_eq!(
        native_snapshot
            .receipts()
            .last()
            .ok_or("verified native receipt chain is empty")?
            .receipt_id,
        *receipt,
        "autonomous output must bind the strictly verified native terminal receipt"
    );
    let learned = memory.search("autonomous", "verified", 1)?;
    let learned = learned
        .first()
        .ok_or("successful autonomous operation did not persist learned memory")?;
    assert_eq!(learned.provenance.source_receipt.as_ref(), Some(receipt));
    let transcript = std::fs::read_to_string(output_root.path().join("autonomy.ndjson"))?;
    assert!(transcript.contains("complete"));
    assert!(transcript.contains("succeeded"));
    Ok(())
}

#[test]
fn model_autonomous_rejects_nonterminal_plans_without_complete_receipts(
) -> Result<(), Box<dyn std::error::Error>> {
    for invalid_plan in [
        serde_json::json!({"intents": []}),
        serde_json::json!({"complete": true, "intents": [{"name": "native_operation", "payload": {}, "delegate": false}]}),
        serde_json::json!({"complete": false, "intents": []}),
    ] {
        let output_root = tempfile::tempdir()?;
        let service = RuntimeService::new(service_dependencies(output_root.path())?);
        let memory = MemoryStore::open(&output_root.path().join("memory.db"))?;
        let cancellation = AutonomousCancellation::new();
        let backend = ModelPlanFixture {
            responses: Mutex::new(vec![invalid_plan.to_string()]),
            prompts: Mutex::new(Vec::new()),
        };
        assert!(service
            .run_model_autonomous(
                serde_json::json!({"goal": "must not infer completion"}),
                &memory,
                None,
                AutonomousTranscript::open(&output_root.path().join("autonomy.ndjson"))?,
                AutonomousBudgetV1 {
                    max_depth: 1,
                    max_steps: 2,
                    max_children: 1,
                    max_wall_time_ms: 10_000,
                    max_output_bytes: 16_384,
                },
                &cancellation,
                ProviderSpecV1::Ollama {
                    base_url: ValidatedEndpoint::try_new("http://127.0.0.1:11434")?,
                    model: "fixture-model".into(),
                },
                &backend,
                Some(256),
            )
            .is_err());
        let transcript = std::fs::read_to_string(output_root.path().join("autonomy.ndjson"))?;
        assert!(!transcript.contains("\"action\":\"complete\""));
        assert!(transcript.contains("\"action\":\"rejected\""));
    }
    Ok(())
}

#[test]
fn model_autonomous_budget_rejection_never_emits_complete_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let output_root = tempfile::tempdir()?;
    let operation = sample_operation()?;
    let backend = ModelPlanFixture {
        responses: Mutex::new(vec![serde_json::json!({
            "complete": false,
            "intents": [{"name": "native_operation", "payload": {"operation": operation}, "delegate": false}]
        })
        .to_string()]),
        prompts: Mutex::new(Vec::new()),
    };
    let service = RuntimeService::new(service_dependencies(output_root.path())?);
    let memory = MemoryStore::open(&output_root.path().join("memory.db"))?;
    let cancellation = AutonomousCancellation::new();
    assert!(service
        .run_model_autonomous(
            serde_json::json!({"goal": "must not complete after exhausted budget"}),
            &memory,
            None,
            AutonomousTranscript::open(&output_root.path().join("autonomy.ndjson"))?,
            AutonomousBudgetV1 {
                max_depth: 1,
                max_steps: 1,
                max_children: 1,
                max_wall_time_ms: 10_000,
                max_output_bytes: 16_384,
            },
            &cancellation,
            ProviderSpecV1::Ollama {
                base_url: ValidatedEndpoint::try_new("http://127.0.0.1:11434")?,
                model: "fixture-model".into(),
            },
            &backend,
            Some(256),
        )
        .is_err());
    let transcript = std::fs::read_to_string(output_root.path().join("autonomy.ndjson"))?;
    assert!(!transcript.contains("\"action\":\"complete\""));
    assert!(transcript.contains("\"action\":\"rejected\""));
    Ok(())
}
