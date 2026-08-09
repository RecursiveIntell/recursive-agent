use std::sync::Arc;

use async_trait::async_trait;
use llm_tool_runtime::{
    McpSurfaceKind, Tool, ToolApprovalKind, ToolBackendKind, ToolCtx, ToolDescriptor, ToolError,
    ToolErrorClass, ToolExposureMode, ToolExposurePolicy, ToolIdempotencyClass, ToolOutputMode,
    ToolReceiptPersistence, ToolRegistry, ToolResult, ToolRuntime, ToolSideEffectClass,
};
use recursive_agent_contracts::{RunSpecV1, RunTerminalStateV1};
use recursive_agent_runner::{
    operation_from_run_spec, Clock, RuntimeDependencies, RuntimeLedgerDependencyV1,
    RuntimePolicyDependencyV1, RuntimeProviderDependencyV1, RuntimeSandboxDependencyV1,
    RuntimeService, RuntimeStoreDependencyV1, SystemClock,
};

#[allow(dead_code)]
#[derive(Debug)]
pub struct TestRunSummary {
    pub run_id: recursive_agent_contracts::CurrentRunId,
    pub run_dir: std::path::PathBuf,
    pub chain_length: u64,
    pub chain_head: String,
    pub terminal_state: RunTerminalStateV1,
}

struct DescriptorOwner {
    descriptor: ToolDescriptor,
}

impl DescriptorOwner {
    fn new(name: &str, read_only: bool) -> Self {
        Self {
            descriptor: ToolDescriptor {
                name: name.into(),
                version: "1.0.0".into(),
                description: Some("test-only admitted runtime descriptor".into()),
                backend_kind: ToolBackendKind::LocalFunction,
                input_schema: serde_json::json!({"type": "object"}),
                output_mode: ToolOutputMode::StructuredJson,
                read_only,
                side_effect_class: if read_only {
                    ToolSideEffectClass::ReadOnly
                } else {
                    ToolSideEffectClass::Write
                },
                idempotency_class: if read_only {
                    ToolIdempotencyClass::Idempotent
                } else {
                    ToolIdempotencyClass::NonIdempotent
                },
                approval_kind: if read_only {
                    ToolApprovalKind::None
                } else {
                    ToolApprovalKind::PolicyRequired
                },
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
impl Tool for DescriptorOwner {
    fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }

    async fn invoke(
        &self,
        _ctx: &ToolCtx,
        call: &llm_tool_runtime::ToolCall,
    ) -> Result<ToolResult, ToolError> {
        match self.descriptor.name.as_str() {
            "echo" => Ok(ToolResult::json(serde_json::json!({
                "text": call.arguments.get("text").cloned().ok_or_else(|| ToolError::new(
                    ToolErrorClass::Denied,
                    "echo requires text",
                ))?
            }))),
            "time_now" => Ok(ToolResult::json(serde_json::json!({
                "timestamp": call.arguments.get("frozen_clock").cloned().ok_or_else(|| ToolError::new(
                    ToolErrorClass::Denied,
                    "time_now requires runner-injected frozen-clock evidence",
                ))?,
                "label": call.arguments.get("label").cloned().ok_or_else(|| ToolError::new(
                    ToolErrorClass::Denied,
                    "time_now requires label",
                ))?
            }))),
            "shell" => Err(ToolError::new(
                ToolErrorClass::Denied,
                "shell effects require runner-owned prepared sandbox dispatch",
            )),
            _ => Err(ToolError::new(
                ToolErrorClass::Denied,
                "unsupported test tool",
            )),
        }
    }
}

fn service(
    output_root: &std::path::Path,
    clock: Arc<dyn Clock>,
) -> Result<RuntimeService, Box<dyn std::error::Error>> {
    let mut registry = ToolRegistry::new();
    registry.register(DescriptorOwner::new("echo", true));
    registry.register(DescriptorOwner::new("time_now", true));
    registry.register(DescriptorOwner::new("shell", false));
    let dependencies = RuntimeDependencies::builder()
        .policy(RuntimePolicyDependencyV1::Native)
        .sandbox(RuntimeSandboxDependencyV1::Native)
        .tool_runtime(Arc::new(ToolRuntime::new(registry)))
        .provider(RuntimeProviderDependencyV1::Disabled)
        .ledger(RuntimeLedgerDependencyV1::Native)
        .clock(clock)
        .store(RuntimeStoreDependencyV1::Native)
        .output_root(output_root)
        .build()?;
    Ok(RuntimeService::new(dependencies))
}

pub fn run_spec(
    spec: &RunSpecV1,
    output_root: &std::path::Path,
) -> Result<TestRunSummary, Box<dyn std::error::Error>> {
    run_spec_with_clock(spec, output_root, SystemClock)
}

pub fn run_spec_with_clock<C: Clock + 'static>(
    spec: &RunSpecV1,
    output_root: &std::path::Path,
    clock: C,
) -> Result<TestRunSummary, Box<dyn std::error::Error>> {
    let service = service(output_root, Arc::new(clock))?;
    let operation = operation_from_run_spec(spec)?;
    let handle = service.submit(&operation)?;
    let verification = service.verify(handle.run_id())?;
    Ok(TestRunSummary {
        run_id: handle.run_id().clone(),
        run_dir: handle.run_dir().to_path_buf(),
        chain_length: verification.length,
        chain_head: verification.final_head,
        terminal_state: verification.terminal_state,
    })
}
