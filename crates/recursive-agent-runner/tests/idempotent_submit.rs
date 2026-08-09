//! Task 5.4 (submit side) — idempotent submission bound to a canonical digest.
//!
//! With a scheduler projection attached:
//! - an exact duplicate (same idempotency key, same operation) returns a handle
//!   referencing the prior run and does not re-execute;
//! - the same idempotency key with a different operation is a typed conflict;
//! - without a scheduler, idempotent submission is a typed unavailable error.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use async_trait::async_trait;
use llm_tool_runtime::{
    McpSurfaceKind, Tool, ToolApprovalKind, ToolBackendKind, ToolCtx, ToolDescriptor, ToolError,
    ToolExposureMode, ToolExposurePolicy, ToolIdempotencyClass, ToolOutputMode,
    ToolReceiptPersistence, ToolRegistry, ToolResult, ToolRuntime, ToolSideEffectClass,
};
use recursive_agent_contracts::{
    content_digest, ActorAuthorityV1, AuthorityOriginV1, CausalLinkV1, ContentDigest,
    DeclaredEffectsV1, OperationBudgetV1, OperationEnvelopeV1, OperationSchemaV1, ProvenanceRefV1,
    ReplayClassV1, ReplayIntentV1, ReplaySpecV1, RunSpecV1, StepSpecV1, ToolCallSpecV1,
};
use recursive_agent_runner::{
    Clock, RuntimeDependencies, RuntimeLedgerDependencyV1, RuntimePolicyDependencyV1,
    RuntimeProviderDependencyV1, RuntimeSandboxDependencyV1, RuntimeService, RuntimeServiceError,
    RuntimeStoreDependencyV1, SchedulerStore,
};
use std::sync::Arc;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Clone, Copy)]
struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
    fn monotonic_now(&self) -> std::time::Duration {
        std::time::Duration::ZERO
    }
}

struct EchoDescriptorOwner {
    descriptor: ToolDescriptor,
}
impl EchoDescriptorOwner {
    fn new() -> Self {
        Self {
            descriptor: ToolDescriptor {
                name: "echo".into(),
                version: "1.0.0".into(),
                description: Some("deterministic echo".into()),
                backend_kind: ToolBackendKind::LocalFunction,
                input_schema: serde_json::json!({"type": "object"}),
                output_mode: ToolOutputMode::StructuredJson,
                read_only: true,
                side_effect_class: ToolSideEffectClass::ReadOnly,
                idempotency_class: ToolIdempotencyClass::Idempotent,
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
impl Tool for EchoDescriptorOwner {
    fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }
    async fn invoke(
        &self,
        _ctx: &ToolCtx,
        call: &llm_tool_runtime::ToolCall,
    ) -> Result<ToolResult, ToolError> {
        Ok(ToolResult::json(call.arguments.clone()))
    }
}

fn echo_operation(text: &str) -> Result<OperationEnvelopeV1, Box<dyn std::error::Error>> {
    let call = ToolCallSpecV1 {
        tool: "echo".into(),
        args: serde_json::json!({ "text": text }),
        frozen_clock: None,
    };
    let run_spec = RunSpecV1 {
        name: "idempotent".into(),
        steps: vec![StepSpecV1 {
            name: "echo".into(),
            call,
        }],
        frozen_clock: None,
        policy_version: "m0-2".into(),
    };
    Ok(OperationEnvelopeV1 {
        schema: OperationSchemaV1::V1,
        actor: ActorAuthorityV1 {
            principal: "actor:idempotent".into(),
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
            source: "urn:recursive-agent:idempotent".into(),
            digest: ContentDigest::compute(b"idempotent"),
        }],
        replay: ReplaySpecV1 {
            class: ReplayClassV1::Deterministic,
            intent: ReplayIntentV1::ExecuteOnce,
        },
        run_spec,
    })
}

fn service_with_scheduler(
    output_root: &std::path::Path,
    store: SchedulerStore,
) -> Result<RuntimeService, Box<dyn std::error::Error>> {
    let mut registry = ToolRegistry::new();
    registry.register(EchoDescriptorOwner::new());
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
    Ok(RuntimeService::new(dependencies).with_scheduler(store)?)
}

#[test]
fn exact_duplicate_returns_prior_handle_without_reexecution() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = SchedulerStore::open(tmp.path().join("scheduler.json"))?;
    let service = service_with_scheduler(tmp.path(), store)?;
    let op = echo_operation("dup")?;

    let first = service.idempotent_submit(&op, "key-1")?;
    let first_id = first.operation_id().to_string();
    let second = service.idempotent_submit(&op, "key-1")?;
    assert_eq!(
        second.operation_id().to_string(),
        first_id,
        "exact duplicate returns same handle"
    );
    Ok(())
}

#[test]
fn same_key_different_operation_is_a_typed_conflict() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = SchedulerStore::open(tmp.path().join("scheduler.json"))?;
    let service = service_with_scheduler(tmp.path(), store)?;

    service.idempotent_submit(&echo_operation("alpha")?, "key-2")?;
    let conflict = service.idempotent_submit(&echo_operation("beta")?, "key-2");
    assert!(matches!(
        conflict,
        Err(RuntimeServiceError::IdempotencyKeyConflict { .. })
    ));
    Ok(())
}

#[test]
fn without_scheduler_idempotent_submit_is_unavailable() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let mut registry = ToolRegistry::new();
    registry.register(EchoDescriptorOwner::new());
    let dependencies = RuntimeDependencies::builder()
        .policy(RuntimePolicyDependencyV1::Native)
        .sandbox(RuntimeSandboxDependencyV1::Native)
        .tool_runtime(Arc::new(ToolRuntime::new(registry)))
        .provider(RuntimeProviderDependencyV1::Disabled)
        .ledger(RuntimeLedgerDependencyV1::Native)
        .clock(Arc::new(FixedClock))
        .store(RuntimeStoreDependencyV1::Native)
        .output_root(tmp.path())
        .build()?;
    let service = RuntimeService::new(dependencies);
    let err = service.idempotent_submit(&echo_operation("x")?, "key-3");
    assert!(matches!(
        err,
        Err(RuntimeServiceError::IdempotentSubmissionUnavailable)
    ));
    Ok(())
}
