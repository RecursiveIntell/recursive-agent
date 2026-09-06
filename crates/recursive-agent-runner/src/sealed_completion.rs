use std::sync::Arc;

use async_trait::async_trait;
use llm_tool_runtime::{
    ApprovalPolicy, McpSurfaceKind, Tool, ToolApprovalKind, ToolApprovalState, ToolBackendKind,
    ToolCall, ToolDescriptor, ToolError, ToolErrorClass, ToolExposureMode, ToolExposurePolicy,
    ToolIdempotencyClass, ToolOutputMode, ToolReceiptPersistence, ToolRegistry, ToolResult,
    ToolRuntime, ToolSideEffectClass,
};
use recursive_agent_contracts::{content_digest, ProviderEgressBindingV1};
use recursive_agent_policy::{
    authorize_provider_egress, ProviderEgressAdmissionRequestV1, ProviderEgressAdmissionVerifier,
};
use recursive_agent_provider::{CompletionBackend, CompletionRequestV1};

use crate::Clock;

const NATIVE_SEALED_COMPLETION_SCOPE: &str = "recursive-agent:sealed_completion";

struct NativeSealedCompletionApprovalPolicy;

#[async_trait]
impl ApprovalPolicy for NativeSealedCompletionApprovalPolicy {
    async fn evaluate(
        &self,
        descriptor: &ToolDescriptor,
        ctx: &llm_tool_runtime::ToolCtx,
        call: &ToolCall,
    ) -> Result<ToolApprovalState, ToolError> {
        let permit = ctx.execution_permit.as_ref().ok_or_else(|| {
            ToolError::new(
                ToolErrorClass::ApprovalRequired,
                "sealed completion requires a native execution permit",
            )
        })?;
        let binding_target = call
            .arguments
            .get("binding")
            .and_then(|binding| binding.get("binding_digest"))
            .and_then(serde_json::Value::as_str);
        let permit_id_matches =
            ctx.idempotency_key.as_deref() == Some(permit.execution_permit_id().as_str());
        if descriptor.name != "sealed_completion"
            || permit.scope().namespace() != NATIVE_SEALED_COMPLETION_SCOPE
            || binding_target != Some(permit.scope().target_key())
            || !permit_id_matches
        {
            return Err(ToolError::new(
                ToolErrorClass::Denied,
                "native execution permit does not bind sealed completion",
            ));
        }
        Ok(ToolApprovalState::Approved)
    }
}

/// Native-only tool that executes one already-sealed provider request.
pub struct SealedCompletionTool<B> {
    backend: B,
    clock: Arc<dyn Clock>,
    verifier: Arc<dyn ProviderEgressAdmissionVerifier>,
    descriptor: ToolDescriptor,
}

impl<B> SealedCompletionTool<B> {
    /// Construct with an explicit backend, current-time owner, and current
    /// policy verifier. No constructor silently grants provider egress.
    pub fn new(
        backend: B,
        clock: Arc<dyn Clock>,
        verifier: Arc<dyn ProviderEgressAdmissionVerifier>,
    ) -> Self {
        Self {
            backend,
            clock,
            verifier,
            descriptor: ToolDescriptor {
                name: "sealed_completion".into(),
                version: "1".into(),
                description: Some(
                    "Execute one native policy/context-sealed provider request".into(),
                ),
                backend_kind: ToolBackendKind::LocalFunction,
                input_schema: serde_json::json!({"type":"object","required":["binding","request"],"properties":{"binding":{"type":"object"},"request":{"type":"object"}},"additionalProperties":false}),
                output_mode: ToolOutputMode::StructuredJson,
                read_only: false,
                side_effect_class: ToolSideEffectClass::Write,
                idempotency_class: ToolIdempotencyClass::NonIdempotent,
                approval_kind: ToolApprovalKind::PolicyRequired,
                timeout_ms: 300_000,
                concurrency_key: Some("provider:sealed_completion".into()),
                cache_ttl_ms: None,
                exposure_mode: ToolExposureMode::Hidden,
                mcp_surface_kind: McpSurfaceKind::None,
                exposure_policy: ToolExposurePolicy::default(),
                receipt_persistence: ToolReceiptPersistence::Ephemeral,
                output_size_limit_bytes: Some(1024 * 1024),
                provider_payload: None,
            },
        }
    }
}

/// Register the hidden sealed-completion executor before native runtime construction.
/// The caller owns provider configuration and must keep provider-disabled profiles unregistered.
pub fn tool_runtime_with_sealed_completion<B>(
    mut registry: ToolRegistry,
    backend: B,
    clock: Arc<dyn Clock>,
    verifier: Arc<dyn ProviderEgressAdmissionVerifier>,
) -> ToolRuntime
where
    B: CompletionBackend + Send + Sync + 'static,
{
    registry.register(SealedCompletionTool::new(backend, clock, verifier));
    ToolRuntime::new(registry).with_approval_policy(Arc::new(NativeSealedCompletionApprovalPolicy))
}

#[async_trait]
impl<B> Tool for SealedCompletionTool<B>
where
    B: CompletionBackend + Send + Sync + 'static,
{
    fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }

    async fn invoke(
        &self,
        _ctx: &llm_tool_runtime::ToolCtx,
        call: &ToolCall,
    ) -> Result<ToolResult, ToolError> {
        let arguments = call.arguments.as_object().ok_or_else(|| {
            ToolError::new(
                ToolErrorClass::Denied,
                "sealed completion arguments must be an object",
            )
        })?;
        if arguments.len() != 2
            || !arguments.contains_key("binding")
            || !arguments.contains_key("request")
        {
            return Err(ToolError::new(
                ToolErrorClass::Denied,
                "sealed completion accepts only binding and request",
            ));
        }
        let binding: ProviderEgressBindingV1 = serde_json::from_value(
            call.arguments
                .get("binding")
                .cloned()
                .ok_or_else(|| ToolError::new(ToolErrorClass::Denied, "sealed binding missing"))?,
        )
        .map_err(|_| ToolError::new(ToolErrorClass::Denied, "sealed binding malformed"))?;
        let request: CompletionRequestV1 = serde_json::from_value(
            call.arguments
                .get("request")
                .cloned()
                .ok_or_else(|| ToolError::new(ToolErrorClass::Denied, "sealed request missing"))?,
        )
        .map_err(|_| ToolError::new(ToolErrorClass::Denied, "sealed request malformed"))?;
        let request_digest = content_digest(&request).map_err(|_| {
            ToolError::new(ToolErrorClass::Denied, "sealed request digest unavailable")
        })?;
        if request_digest != binding.request_digest
            || !request
                .provider
                .matches_egress_binding(&binding.provider_identity, &binding.model_ref)
        {
            return Err(ToolError::new(
                ToolErrorClass::Denied,
                "sealed request does not match its provider binding",
            ));
        }
        let tool_arguments_digest = content_digest(&call.arguments).map_err(|_| {
            ToolError::new(
                ToolErrorClass::Denied,
                "sealed tool arguments digest unavailable",
            )
        })?;
        let admission = ProviderEgressAdmissionRequestV1::new(
            "sealed_completion",
            binding.clone(),
            request_digest.clone(),
            tool_arguments_digest,
        )
        .map_err(|_| ToolError::new(ToolErrorClass::Denied, "sealed egress admission malformed"))?;
        authorize_provider_egress(self.verifier.as_ref(), &admission, self.clock.now()).map_err(
            |_| ToolError::new(ToolErrorClass::Denied, "sealed egress admission denied"),
        )?;
        let response = self
            .backend
            .complete(&request)
            .map_err(|_| ToolError::new(ToolErrorClass::Execution, "provider completion failed"))?;
        Ok(ToolResult::json(serde_json::json!({
            "model": response.model,
            "text": response.text,
            "binding_digest": binding.binding_digest,
            "request_digest": request_digest,
        })))
    }
}
