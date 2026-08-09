use std::sync::Arc;

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use llm_tool_runtime::{
    McpSurfaceKind, Tool, ToolApprovalKind, ToolBackendKind, ToolCtx, ToolDescriptor, ToolError,
    ToolErrorClass, ToolExposureMode, ToolExposurePolicy, ToolIdempotencyClass, ToolOutputMode,
    ToolReceiptPersistence, ToolRegistry, ToolResult, ToolRuntime, ToolSideEffectClass,
};
use recursive_agent_contracts::{
    content_digest, ActorAuthorityV1, AuthorityOriginV1, CausalLinkV1, ContentDigest,
    DeclaredEffectsV1, OperationBudgetV1, OperationEnvelopeV1, OperationSchemaV1, ProvenanceRefV1,
    ReceiptKindV1, ReceiptOutcomeV1, ReplayClassV1, ReplayIntentV1, ReplaySpecV1, RunSpecV1,
    RunTerminalStateV1, RuntimeEventKindV1, StepSpecV1, ToolCallSpecV1,
};
use recursive_agent_ledger::{verified_snapshot_directory_bound, ArtifactStore, RunPaths};
use recursive_agent_runner::{
    Clock, RuntimeDependencies, RuntimeLedgerDependencyV1, RuntimePolicyDependencyV1,
    RuntimeProviderDependencyV1, RuntimeSandboxDependencyV1, RuntimeService, RuntimeStatusV1,
    RuntimeStoreDependencyV1,
};
use recursive_agent_sandbox::{EnforcementOutcome, SandboxResult};

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

struct ShellDescriptorOwner {
    descriptor: ToolDescriptor,
}

impl ShellDescriptorOwner {
    fn new() -> Self {
        Self {
            descriptor: ToolDescriptor {
                name: "shell".into(),
                version: "1.0.0".into(),
                description: Some("runner-owned bounded sandbox dispatch".into()),
                backend_kind: ToolBackendKind::LocalFunction,
                input_schema: serde_json::json!({"type": "object"}),
                output_mode: ToolOutputMode::StructuredJson,
                read_only: false,
                side_effect_class: ToolSideEffectClass::Write,
                idempotency_class: ToolIdempotencyClass::NonIdempotent,
                approval_kind: ToolApprovalKind::PolicyRequired,
                timeout_ms: 3_000,
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
impl Tool for ShellDescriptorOwner {
    fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }

    async fn invoke(
        &self,
        _ctx: &ToolCtx,
        _call: &llm_tool_runtime::ToolCall,
    ) -> Result<ToolResult, ToolError> {
        Err(ToolError::new(
            ToolErrorClass::Denied,
            "shell effects require runner-owned prepared sandbox dispatch",
        ))
    }
}

fn native_operation() -> Result<OperationEnvelopeV1, Box<dyn std::error::Error>> {
    let call = ToolCallSpecV1 {
        tool: "shell".into(),
        args: serde_json::json!({
            "command": "/usr/bin/printf",
            "args": ["native-vertical-ok"],
            "allowed_read_paths": [],
            "allowed_write_paths": [],
            "allow_network": false,
            "timeout_ms": 2_000,
            "max_output_bytes": 4_096
        }),
        frozen_clock: None,
    };
    let run_spec = RunSpecV1 {
        name: "phase2-native-vertical".into(),
        steps: vec![StepSpecV1 {
            name: "bounded-printf".into(),
            call,
        }],
        frozen_clock: None,
        policy_version: "m0-2".into(),
    };
    Ok(OperationEnvelopeV1 {
        schema: OperationSchemaV1::V1,
        actor: ActorAuthorityV1 {
            principal: "actor:phase2-native-vertical".into(),
            origin: AuthorityOriginV1::Direct,
        },
        causality: CausalLinkV1 {
            parent_operation_id: None,
            root_operation_id: None,
        },
        budget: OperationBudgetV1 {
            max_wall_time_ms: 3_000,
            max_output_bytes: 4_096,
            max_artifact_bytes: 65_536,
            max_steps: 1,
        },
        effects: DeclaredEffectsV1 {
            read_roots: Vec::new(),
            write_roots: Vec::new(),
            network_allowed: false,
            action_digest: content_digest(&run_spec)?,
        },
        provenance: vec![ProvenanceRefV1 {
            source: "urn:recursive-agent:phase2:native-vertical".into(),
            digest: ContentDigest::compute(b"fixed-/usr/bin/printf-native-vertical-ok"),
        }],
        replay: ReplaySpecV1 {
            class: ReplayClassV1::RecordedEffect,
            intent: ReplayIntentV1::ExecuteOnce,
        },
        run_spec,
    })
}

fn native_service(
    output_root: &std::path::Path,
) -> Result<RuntimeService, Box<dyn std::error::Error>> {
    let mut registry = ToolRegistry::new();
    registry.register(ShellDescriptorOwner::new());
    let dependencies = RuntimeDependencies::builder()
        .policy(RuntimePolicyDependencyV1::Native)
        .sandbox(RuntimeSandboxDependencyV1::Native)
        .tool_runtime(Arc::new(ToolRuntime::new(registry)))
        .provider(RuntimeProviderDependencyV1::Disabled)
        .ledger(RuntimeLedgerDependencyV1::Native)
        .clock(Arc::new(FixedClock))
        .store(RuntimeStoreDependencyV1::Native)
        .output_root(output_root)
        .build()?;
    Ok(RuntimeService::new(dependencies))
}

#[test]
fn native_vertical_authenticates_authorizes_sandboxes_executes_streams_persists_and_verifies(
) -> Result<(), Box<dyn std::error::Error>> {
    let output_root = tempfile::tempdir()?;
    let service = native_service(output_root.path())?;
    let operation = native_operation()?;
    let handle = service.submit(&operation)?;

    let status = service.status(handle.run_id())?;
    if status
        != (RuntimeStatusV1::Terminal {
            state: RunTerminalStateV1::Succeeded,
        })
    {
        let paths = RunPaths::new(handle.run_dir());
        let snapshot = verified_snapshot_directory_bound(&paths)?;
        return Err(format!(
            "native vertical did not succeed: status={status:?}, receipts={:#?}",
            snapshot.receipts()
        )
        .into());
    }
    assert!(handle.run_dir().starts_with(output_root.path()));
    assert!(handle.run_dir().is_dir());

    let events = service.events(handle.run_id(), None)?;
    assert!(matches!(
        events.first().ok_or("submitted event missing")?.kind,
        RuntimeEventKindV1::Submitted
    ));
    assert!(events
        .iter()
        .any(|event| matches!(event.kind, RuntimeEventKindV1::Authorized { .. })));
    assert!(events
        .iter()
        .any(|event| matches!(event.kind, RuntimeEventKindV1::OutputCommitted { .. })));
    assert!(matches!(
        events.last().ok_or("terminal event missing")?.kind,
        RuntimeEventKindV1::Completed {
            outcome: ReceiptOutcomeV1::Ok
        }
    ));
    let cursor = events
        .iter()
        .find(|event| matches!(event.kind, RuntimeEventKindV1::Authorized { .. }))
        .ok_or("authorized cursor missing")?
        .sequence;
    let streamed_suffix = service.events(handle.run_id(), Some(cursor))?;
    assert!(streamed_suffix.iter().all(|event| event.sequence > cursor));
    assert!(streamed_suffix
        .iter()
        .any(|event| matches!(event.kind, RuntimeEventKindV1::OutputCommitted { .. })));

    let paths = RunPaths::new(handle.run_dir());
    let snapshot = verified_snapshot_directory_bound(&paths)?;
    let completed = snapshot
        .receipts()
        .iter()
        .find(|receipt| receipt.kind == ReceiptKindV1::StepCompleted)
        .ok_or("step completion receipt missing")?;
    let artifact = completed
        .artifact_refs
        .first()
        .ok_or("sandbox observation artifact missing")?;
    let pinned_root = std::fs::File::open(handle.run_dir())?;
    let store = ArtifactStore::from_run_root_fd(&pinned_root, false)?;
    let artifact_bytes = store.get(artifact)?;
    assert_eq!(ContentDigest::compute(&artifact_bytes), artifact.digest);
    let observation: SandboxResult = serde_json::from_slice(&artifact_bytes)?;
    assert_eq!(observation.exit_code, Some(0));
    assert_eq!(observation.stdout, "native-vertical-ok");
    assert!(observation.stderr.is_empty());
    assert!(!observation.timed_out);
    assert!(!observation.authority_terminated);
    assert_eq!(
        observation.enforcement.outcome,
        EnforcementOutcome::Enforced
    );
    assert!(observation.enforcement.network_isolated);

    let verification = service.verify(handle.run_id())?;
    assert!(verification.ok);
    assert!(verification.current_strict_success);
    assert_eq!(verification.verified_run_id.as_ref(), Some(handle.run_id()));
    assert_eq!(verification.length as usize, events.len());
    println!(
        "native_vertical_evidence run_id={} run_dir={} events={events:#?} artifact={artifact:#?} enforcement={:#?} verification={verification:#?}",
        handle.run_id(),
        handle.run_dir().display(),
        observation.enforcement,
    );
    Ok(())
}
