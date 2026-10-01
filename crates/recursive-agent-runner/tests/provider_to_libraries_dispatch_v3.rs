//! Disposable joined witness: provider-decoded argument bytes through the
//! Libraries boundary compiler and the REAL llm-tool-runtime dispatcher.
//! This fixture is not the selected daemon route or production authority.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use async_trait::async_trait;
use llm_tool_runtime::{
    McpSurfaceKind, Tool, ToolApprovalKind, ToolBackendKind, ToolCall, ToolCtx, ToolDescriptor,
    ToolError, ToolExposureMode, ToolExposurePolicy, ToolIdempotencyClass, ToolOriginKind,
    ToolOutputMode, ToolPlannerStage, ToolReceiptPersistence, ToolRegistry, ToolResult,
    ToolRetryOwner, ToolRuntime, ToolSideEffectClass,
};
use recursive_agent_provider::{
    ConversationMessageV2, ConversationRequestV2, CredentialRef, CredentialResolveError,
    CredentialResolver, HttpCompletionBackend, ProviderError, ProviderSpecV1, SecretBytes,
    ValidatedEndpoint,
};
use stack_ids::{AttemptId, TraceCtx, TrialId};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type TestServer = (
    String,
    mpsc::Receiver<Result<(), String>>,
    thread::JoinHandle<()>,
);

struct FixtureResolver;
impl CredentialResolver for FixtureResolver {
    fn resolve(&self, _: &CredentialRef) -> Result<SecretBytes, CredentialResolveError> {
        Ok(SecretBytes::new(b"fixture-only".to_vec()))
    }
}

struct CountedReadOnlyTool {
    descriptor: ToolDescriptor,
    invoked: Arc<AtomicUsize>,
}

impl CountedReadOnlyTool {
    fn new(invoked: Arc<AtomicUsize>) -> Self {
        Self {
            descriptor: ToolDescriptor {
                name: "lookup".into(),
                version: "1.0.0".into(),
                description: Some("local fixture only".into()),
                backend_kind: ToolBackendKind::LocalFunction,
                input_schema: serde_json::json!({"type":"object","properties":{"x":{"type":"integer"}},"required":["x"],"additionalProperties":false}),
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
            invoked,
        }
    }
}

#[async_trait]
impl Tool for CountedReadOnlyTool {
    fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }

    async fn invoke(&self, _: &ToolCtx, call: &ToolCall) -> Result<ToolResult, ToolError> {
        self.invoked.fetch_add(1, Ordering::SeqCst);
        Ok(ToolResult::json(call.arguments.clone()))
    }
}

fn context() -> ToolCtx {
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
        caller: "joined-provider-dispatch-fixture".into(),
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

fn response_server(body: &'static str) -> Result<TestServer, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let url = format!("http://{}/", listener.local_addr()?);
    let (tx, rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let outcome = (|| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let (mut stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut request = [0_u8; 4096];
            let n = stream.read(&mut request)?;
            if n == 0 || !request[..n].starts_with(b"POST /v1/chat/completions ") {
                return Err("not a fixture chat request".into());
            }
            let reply = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            stream.write_all(reply.as_bytes())?;
            Ok(())
        })();
        let _ = tx.send(outcome.map_err(|error| error.to_string()));
    });
    Ok((url, rx, server))
}

fn request(url: String) -> Result<ConversationRequestV2, ProviderError> {
    ConversationRequestV2::try_new(
        ProviderSpecV1::OpenAiCompatible {
            base_url: ValidatedEndpoint::try_new(url)?,
            model: "fixture-model".into(),
            credential_ref: CredentialRef::try_new("environment:UNUSED_FIXTURE_KEY")?,
        },
        vec![ConversationMessageV2::user("inspect")],
        Some(64),
    )
}

#[test]
fn later_duplicate_does_not_release_an_earlier_valid_call() -> TestResult {
    let invoked = Arc::new(AtomicUsize::new(0));
    let mut registry = ToolRegistry::new();
    registry.register(CountedReadOnlyTool::new(invoked.clone()));
    let runtime = ToolRuntime::new(registry);
    let backend = HttpCompletionBackend::new(Duration::from_secs(5))?;
    let body = r#"{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"good-1","type":"function","function":{"name":"lookup","arguments":"{\"x\":1}"}},{"id":"bad-2","type":"function","function":{"name":"lookup","arguments":"{\"x\":1,\"\\u0078\":2}"}}]}}]}"#;
    let (url, server_result, server) = response_server(body)?;
    let denied = backend.receive_tool_calls_v3_with_resolver(&request(url)?, &FixtureResolver);
    assert!(matches!(
        denied,
        Err(ProviderError::InvalidConversationToolCall)
    ));
    assert_eq!(invoked.load(Ordering::SeqCst), 0);
    assert!(
        runtime.registry().get("lookup").is_some(),
        "real dispatcher missing"
    );
    server_result
        .recv_timeout(Duration::from_secs(5))?
        .map_err(|e| format!("server: {e}"))?;
    server.join().map_err(|_| "server panic")?;
    Ok(())
}

#[test]
fn provider_decoded_duplicate_denied_before_real_dispatch_and_valid_call_reaches_it() -> TestResult
{
    let invoked = Arc::new(AtomicUsize::new(0));
    let mut registry = ToolRegistry::new();
    registry.register(CountedReadOnlyTool::new(invoked.clone()));
    let runtime = ToolRuntime::new(registry);
    let backend = HttpCompletionBackend::new(Duration::from_secs(5))?;
    let invalid_body = r#"{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"bad-1","type":"function","function":{"name":"lookup","arguments":"{\"x\":1,\"\\u0078\":2}"}}]}}]}"#;
    let (url, server_result, server) = response_server(invalid_body)?;
    let denied = backend.receive_tool_calls_v3_with_resolver(&request(url)?, &FixtureResolver);
    assert!(matches!(
        denied,
        Err(ProviderError::InvalidConversationToolCall)
    ));
    assert_eq!(
        invoked.load(Ordering::SeqCst),
        0,
        "real Libraries tool was invoked after denial"
    );
    server_result
        .recv_timeout(Duration::from_secs(5))?
        .map_err(|e| format!("server: {e}"))?;
    server.join().map_err(|_| "server panic")?;

    let valid_body = r#"{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"good-1","type":"function","function":{"name":"lookup","arguments":"{\"x\":1}"}}]}}]}"#;
    let (url, server_result, server) = response_server(valid_body)?;
    let proposal = backend.receive_tool_calls_v3_with_resolver(&request(url)?, &FixtureResolver)?;
    assert_eq!(proposal.tool_calls.len(), 1);
    let admitted = &proposal.tool_calls[0];
    assert_eq!(admitted.original_arguments, b"{\"x\":1}");
    assert_eq!(admitted.admitted_arguments, serde_json::json!({"x":1}));
    // The digest is of the original decoded string, not of a normalized Value.
    let original_digest = blake3::hash(&admitted.original_arguments)
        .to_hex()
        .to_string();
    let descriptor = runtime
        .registry()
        .get(&admitted.name)
        .ok_or("unregistered tool")?;
    assert!(descriptor.descriptor().read_only);
    assert_eq!(
        descriptor.descriptor().side_effect_class,
        ToolSideEffectClass::ReadOnly
    );
    assert_eq!(
        descriptor.descriptor().approval_kind,
        ToolApprovalKind::None
    );
    let mut call = ToolCall::new(
        descriptor.descriptor().name.clone(),
        descriptor.descriptor().version.clone(),
        admitted.admitted_arguments.clone(),
        ToolOriginKind::OpenAiChat,
    );
    call.provider_call_id = Some(admitted.id.clone());
    let dispatch_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let execution = dispatch_rt.block_on(runtime.execute(&context(), &call, None, None));
    drop(dispatch_rt);
    assert_eq!(execution.result?.payload, serde_json::json!({"x":1}));
    assert_eq!(execution.receipt.tool_run_id, call.tool_run_id);
    assert_eq!(
        execution.receipt.provider_call_id.as_deref(),
        Some("good-1")
    );
    assert_eq!(
        original_digest,
        blake3::hash(b"{\"x\":1}").to_hex().to_string()
    );
    assert_eq!(invoked.load(Ordering::SeqCst), 1);
    server_result
        .recv_timeout(Duration::from_secs(5))?
        .map_err(|e| format!("server: {e}"))?;
    server.join().map_err(|_| "server panic")?;
    Ok(())
}
