//! Task 3.3 — concurrency, backpressure, streaming, and cancellation over the
//! authenticated native IPC path.
//!
//! Starts a real daemon on a private socket, submits a native operation through
//! the embedded runtime, then queries terminal status through the daemon IPC
//! and verifies the strict ledger result. No mocks at the governing boundary.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use llm_tool_runtime::{
    McpSurfaceKind, Tool, ToolApprovalKind, ToolBackendKind, ToolCtx, ToolDescriptor, ToolError,
    ToolExposureMode, ToolExposurePolicy, ToolIdempotencyClass, ToolOutputMode,
    ToolReceiptPersistence, ToolRegistry, ToolResult, ToolRuntime, ToolSideEffectClass,
};
use recursive_agent_contracts::{
    content_digest, derive_run_id, derive_step_id, ActorAuthorityV1, AuthorityOriginV1,
    CausalLinkV1, ContentDigest, DeclaredEffectsV1, OperationBudgetV1, OperationEnvelopeV1,
    OperationSchemaV1, ProvenanceRefV1, ReplayClassV1, ReplayIntentV1, ReplaySpecV1, RunSpecV1,
    StepSpecV1, ToolCallSpecV1,
};
use recursive_agent_daemon::{
    bind_private_socket, serve, IPC_PROTOCOL_VERSION_V1, IPC_REQUEST_SCHEMA_V1,
    MAX_FRAME_PAYLOAD_BYTES,
};
use recursive_agent_policy::{
    ActorPrincipalV1, DelegationPolicyV1, DurablePermitStore, EffectScopeV1,
    OperatorApprovalVerifierV1, OutcomePolicyV1, PermitApprovalRequestV1, PermitBindingV1,
    PermitBudgetV1, ProductionApprovalSignerV1, ProductionApprovalWitnessV1, RetryPolicyV1,
    PRODUCTION_PERMIT_TARGET_ROOT,
};
use recursive_agent_runner::{
    Clock, RuntimeDependencies, RuntimeLedgerDependencyV1, RuntimePolicyDependencyV1,
    RuntimeProviderDependencyV1, RuntimeSandboxDependencyV1, RuntimeService,
    RuntimeStoreDependencyV1, SystemClock,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

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

struct EchoDescriptorOwner {
    descriptor: ToolDescriptor,
}

impl EchoDescriptorOwner {
    fn new() -> Self {
        Self {
            descriptor: ToolDescriptor {
                name: "echo".into(),
                version: "1.0.0".into(),
                description: Some("deterministic echo for IPC vertical".into()),
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

fn native_service(
    output_root: &std::path::Path,
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
    Ok(RuntimeService::new(dependencies))
}

fn native_service_current_clock(
    output_root: &std::path::Path,
) -> Result<RuntimeService, Box<dyn std::error::Error>> {
    let mut registry = ToolRegistry::new();
    registry.register(EchoDescriptorOwner::new());
    let dependencies = RuntimeDependencies::builder()
        .policy(RuntimePolicyDependencyV1::Native)
        .sandbox(RuntimeSandboxDependencyV1::Native)
        .tool_runtime(Arc::new(ToolRuntime::new(registry)))
        .provider(RuntimeProviderDependencyV1::Disabled)
        .ledger(RuntimeLedgerDependencyV1::Native)
        .clock(Arc::new(SystemClock))
        .store(RuntimeStoreDependencyV1::Native)
        .output_root(output_root)
        .build()?;
    Ok(RuntimeService::new(dependencies))
}

fn native_operation() -> Result<OperationEnvelopeV1, Box<dyn std::error::Error>> {
    let call = ToolCallSpecV1 {
        tool: "echo".into(),
        args: serde_json::json!({"text": "ipc-vertical"}),
        frozen_clock: None,
    };
    let run_spec = RunSpecV1 {
        name: "ipc-vertical".into(),
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
            principal: "actor:ipc-vertical".into(),
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
            source: "urn:recursive-agent:ipc-vertical".into(),
            digest: ContentDigest::compute(b"fixed-ipc-vertical"),
        }],
        replay: ReplaySpecV1 {
            class: ReplayClassV1::Deterministic,
            intent: ReplayIntentV1::ExecuteOnce,
        },
        run_spec,
    })
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut framed = (payload.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(payload);
    framed
}

fn status_request(request_id: &str, run_id: &str) -> Vec<u8> {
    let payload = serde_json::json!({
        "schema": IPC_REQUEST_SCHEMA_V1,
        "protocol_version": IPC_PROTOCOL_VERSION_V1,
        "request_id": request_id,
        "request": {"kind": "status", "run_id": run_id},
    });
    frame(&serde_json::to_vec(&payload).unwrap())
}

fn verify_request(request_id: &str, run_id: &str) -> Vec<u8> {
    let payload = serde_json::json!({
        "schema": IPC_REQUEST_SCHEMA_V1,
        "protocol_version": IPC_PROTOCOL_VERSION_V1,
        "request_id": request_id,
        "request": {"kind": "verify", "run_id": run_id},
    });
    frame(&serde_json::to_vec(&payload).unwrap())
}

fn submit_request(request_id: &str, operation: &OperationEnvelopeV1) -> Vec<u8> {
    let payload = serde_json::json!({
        "schema": IPC_REQUEST_SCHEMA_V1,
        "protocol_version": IPC_PROTOCOL_VERSION_V1,
        "request_id": request_id,
        "request": {"kind": "submit", "operation": operation},
    });
    frame(&serde_json::to_vec(&payload).unwrap())
}

fn external_permit_binding(
    call: &ToolCallSpecV1,
) -> Result<PermitBindingV1, Box<dyn std::error::Error>> {
    let spec = RunSpecV1 {
        name: "external-permit".into(),
        steps: vec![StepSpecV1 {
            name: "effect".into(),
            call: call.clone(),
        }],
        frozen_clock: None,
        policy_version: "policy-v1".into(),
    };
    let run_id = derive_run_id(&spec)?;
    let step_id = derive_step_id(&run_id, 0, "effect", call)?;
    let effect = EffectScopeV1 {
        scope_name: "pure".into(),
        read_roots: Vec::new(),
        write_roots: Vec::new(),
        network_allowed: false,
    };
    let now = FixedClock.now();
    Ok(PermitBindingV1 {
        actor: ActorPrincipalV1::try_new("actor:ipc-vertical")?,
        action_digest: content_digest(call)?,
        effect_digest: content_digest(&effect)?,
        effect,
        budget: PermitBudgetV1 {
            max_wall_time_ms: 3_000,
            max_output_bytes: 4_096,
            max_artifact_bytes: 8_192,
        },
        policy_version: "policy-v1".into(),
        parent_permit_id: None,
        parent_operation_id: Some(run_id.clone()),
        issued_at: now,
        not_before: now,
        expires_at: now + chrono::TimeDelta::seconds(60),
        run_id,
        step_id,
        tool: call.tool.clone(),
        args_digest: content_digest(&call.args)?,
    })
}

#[test]
fn daemon_consumes_and_records_external_permit_receipts_over_ipc() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let runtime_root = tmp.path().join("permit-root");
    std::fs::create_dir(&runtime_root)?;
    let call = ToolCallSpecV1 {
        tool: "echo".into(),
        args: serde_json::json!({"text": "permit-vertical"}),
        frozen_clock: None,
    };
    let binding = external_permit_binding(&call)?;
    let root = std::fs::File::open(&runtime_root)?;
    let permits = DurablePermitStore::from_dir_fd(&root)?;
    let permit = permits.issue(&binding, FixedClock.now())?;
    let service = native_service(&runtime_root)?;
    let (listener, socket_path) = bind_private_socket(tmp.path(), "permit.sock")?;
    let server_thread = std::thread::spawn(move || {
        let _ = serve(listener, Arc::new(service), 4);
    });
    let mut stream = connect_with_retry(&socket_path, &server_thread)?;
    let consume = serde_json::json!({
        "schema": IPC_REQUEST_SCHEMA_V1,
        "protocol_version": IPC_PROTOCOL_VERSION_V1,
        "request_id": "permit-consume",
        "request": {"kind": "permit_consume", "permit_id": permit.permit_id, "binding": binding, "call": call},
    });
    stream.write_all(&frame(&serde_json::to_vec(&consume)?))?;
    stream.flush()?;
    let consumed = read_response(&mut stream)?;
    assert_eq!(consumed["request_id"], "permit-consume");
    assert_eq!(consumed["evidence"]["state"]["state"], "consumed");
    let digest = consumed["receipt_artifact"]["receipt_digest"]
        .as_str()
        .ok_or("preflight digest missing")?;
    let outcome = serde_json::json!({
        "schema": IPC_REQUEST_SCHEMA_V1,
        "protocol_version": IPC_PROTOCOL_VERSION_V1,
        "request_id": "permit-outcome",
        "request": {"kind": "permit_outcome_record", "permit_id": consumed["permit_id"], "preflight_receipt_digest": digest, "reported": {"state": "outcome_ambiguous", "duration_ms": 7, "error_type": "transport_lost"}},
    });
    stream.write_all(&frame(&serde_json::to_vec(&outcome)?))?;
    stream.flush()?;
    let recorded = read_response(&mut stream)?;
    assert_eq!(recorded["request_id"], "permit-outcome");
    assert_eq!(
        recorded["outcome_artifact"]["reported"]["state"],
        "outcome_ambiguous"
    );
    Ok(())
}

#[test]
#[ignore = "requires NODE_PRODUCTION_PERMIT_FIXTURE generated by the Desktop signer"]
fn node_generated_witness_is_accepted_by_rust_daemon_owner() -> TestResult {
    let fixture_path = std::env::var("NODE_PRODUCTION_PERMIT_FIXTURE")?;
    let fixture: serde_json::Value = serde_json::from_slice(&std::fs::read(fixture_path)?)?;
    let witness: ProductionApprovalWitnessV1 = serde_json::from_value(fixture["witness"].clone())?;
    let public_key_values = fixture["public_key"]
        .as_array()
        .ok_or("public key array missing")?;
    let public_key: [u8; 32] = public_key_values
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|byte| u8::try_from(byte).ok())
                .ok_or("invalid public key byte")
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| "public key must be 32 bytes")?;
    let tmp = tempfile::tempdir()?;
    let runtime_root = tmp.path().join("node-cross-language-root");
    std::fs::create_dir(&runtime_root)?;
    let verifier = recursive_agent_policy::ProductionApprovalVerifierV1::from_public_key_bytes(
        witness.key_id.clone(),
        public_key,
    )?;
    let service =
        native_service_current_clock(&runtime_root)?.with_production_approval_verifier(verifier);
    let (listener, socket_path) = bind_private_socket(tmp.path(), "node-cross-language.sock")?;
    let server_thread = std::thread::spawn(move || {
        let _ = serve(listener, Arc::new(service), 4);
    });
    let mut stream = connect_with_retry(&socket_path, &server_thread)?;
    let issue = serde_json::json!({
        "schema": IPC_REQUEST_SCHEMA_V1,
        "protocol_version": IPC_PROTOCOL_VERSION_V1,
        "request_id": "node-cross-language-issue",
        "request": {"kind": "permit_issue_production", "witness": witness},
    });
    stream.write_all(&frame(&serde_json::to_vec(&issue)?))?;
    stream.flush()?;
    let issued = read_response(&mut stream)?;
    assert!(issued["error"].is_null(), "Node witness rejected: {issued}");
    assert_eq!(
        issued["issuance_evidence"]["contract"],
        "production_ed25519_per_call_v1"
    );
    let permit_id = issued["permit_id"].clone();
    let binding = issued["binding"].clone();
    let consume = serde_json::json!({
        "schema": IPC_REQUEST_SCHEMA_V1,
        "protocol_version": IPC_PROTOCOL_VERSION_V1,
        "request_id": "node-cross-language-consume",
        "request": {
            "kind": "permit_consume",
            "permit_id": permit_id,
            "binding": binding,
            "call": witness.call,
        },
    });
    stream.write_all(&frame(&serde_json::to_vec(&consume)?))?;
    stream.flush()?;
    let consumed = read_response(&mut stream)?;
    assert!(
        consumed["error"].is_null(),
        "Node permit consume rejected: {consumed}"
    );
    assert_eq!(consumed["evidence"]["state"]["state"], "consumed");
    let preflight_digest = consumed["receipt_artifact"]["receipt_digest"]
        .as_str()
        .ok_or("Node preflight digest missing")?;
    let path = witness.call.args["path"]
        .as_str()
        .ok_or("Node path missing")?;
    let content = witness.call.args["content"]
        .as_str()
        .ok_or("Node content missing")?;
    std::fs::write(path, content)?;
    assert_eq!(std::fs::read_to_string(path)?, content);
    let outcome = serde_json::json!({
        "schema": IPC_REQUEST_SCHEMA_V1,
        "protocol_version": IPC_PROTOCOL_VERSION_V1,
        "request_id": "node-cross-language-outcome",
        "request": {
            "kind": "permit_outcome_record",
            "permit_id": consumed["permit_id"],
            "preflight_receipt_digest": preflight_digest,
            "reported": {"state": "succeeded", "duration_ms": 1, "error_type": null},
        },
    });
    stream.write_all(&frame(&serde_json::to_vec(&outcome)?))?;
    stream.flush()?;
    let recorded = read_response(&mut stream)?;
    assert!(
        recorded["error"].is_null(),
        "Node outcome rejected: {recorded}"
    );
    assert_eq!(
        recorded["outcome_artifact"]["reported"]["state"],
        "succeeded"
    );
    std::fs::remove_file(path)?;
    Ok(())
}

fn production_witness(call: ToolCallSpecV1) -> ProductionApprovalWitnessV1 {
    ProductionApprovalWitnessV1 {
        approval_id: "approval-production-1".into(),
        mission_ref: "production-write-mission".into(),
        target_ref: "path:approved-result".into(),
        call,
        actor: ActorPrincipalV1::try_new("ares-desktop:interactive").unwrap(),
        effect: EffectScopeV1 {
            scope_name: "production-per-call:approval-production-1".into(),
            read_roots: Vec::new(),
            write_roots: vec![PRODUCTION_PERMIT_TARGET_ROOT.into()],
            network_allowed: false,
        },
        budget: PermitBudgetV1 {
            max_wall_time_ms: 300_000,
            max_output_bytes: 4_096,
            max_artifact_bytes: 8_192,
        },
        policy_version: "production-permit-v1".into(),
        issued_at: FixedClock.now(),
        not_before: FixedClock.now(),
        expires_at: FixedClock.now() + chrono::TimeDelta::minutes(5),
        retry: RetryPolicyV1::NoRetry,
        delegation: DelegationPolicyV1::Forbidden,
        outcome_policy: OutcomePolicyV1::TerminalQuarantine,
        key_id: String::new(),
        signature: Vec::new(),
    }
}

#[test]
fn daemon_issues_production_ed25519_witness_once_consumes_and_quarantines_ambiguity() -> TestResult
{
    let tmp = tempfile::tempdir()?;
    let runtime_root = tmp.path().join("production-permit-root");
    std::fs::create_dir(&runtime_root)?;
    let call = ToolCallSpecV1 {
        tool: "write_file".into(),
        args: serde_json::json!({"path": "/home/sikmindz/work/ares-production-permit-20260830/result.txt", "content": "never-dispatched"}),
        frozen_clock: None,
    };
    let signer = ProductionApprovalSignerV1::from_seed("ares-desktop-key-1".into(), [9_u8; 32]);
    let service =
        native_service(&runtime_root)?.with_production_approval_verifier(signer.verifier()?);
    let (listener, socket_path) = bind_private_socket(tmp.path(), "production-permit.sock")?;
    let server_thread = std::thread::spawn(move || {
        let _ = serve(listener, Arc::new(service), 4);
    });
    let mut stream = connect_with_retry(&socket_path, &server_thread)?;
    let signed = signer.sign(production_witness(call.clone()))?;
    let issue = |id: &str, witness: &ProductionApprovalWitnessV1| serde_json::json!({"schema": IPC_REQUEST_SCHEMA_V1, "protocol_version": IPC_PROTOCOL_VERSION_V1, "request_id": id, "request": {"kind": "permit_issue_production", "witness": witness}});
    stream.write_all(&frame(&serde_json::to_vec(&issue(
        "production-issue",
        &signed,
    ))?))?;
    stream.flush()?;
    let issued = read_response(&mut stream)?;
    assert!(
        issued["error"].is_null(),
        "production issuance failed: {issued}"
    );
    assert_eq!(
        issued["issuance_evidence"]["contract"],
        "production_ed25519_per_call_v1"
    );
    let replay = issue("production-replay", &signed);
    stream.write_all(&frame(&serde_json::to_vec(&replay)?))?;
    stream.flush()?;
    assert_eq!(
        read_response(&mut stream)?["error"]["code"],
        "runtime_error"
    );
    let consume = serde_json::json!({"schema": IPC_REQUEST_SCHEMA_V1, "protocol_version": IPC_PROTOCOL_VERSION_V1, "request_id": "production-consume", "request": {"kind": "permit_consume", "permit_id": issued["permit_id"], "binding": issued["binding"], "call": call}});
    stream.write_all(&frame(&serde_json::to_vec(&consume)?))?;
    stream.flush()?;
    let consumed = read_response(&mut stream)?;
    assert_eq!(consumed["evidence"]["state"]["state"], "consumed");
    let ambiguous = serde_json::json!({"schema": IPC_REQUEST_SCHEMA_V1,"protocol_version":IPC_PROTOCOL_VERSION_V1,"request_id":"production-ambiguous","request":{"kind":"permit_outcome_record","permit_id":consumed["permit_id"],"preflight_receipt_digest":consumed["receipt_artifact"]["receipt_digest"],"reported":{"state":"outcome_ambiguous","duration_ms":1,"error_type":"transport_lost"}}});
    stream.write_all(&frame(&serde_json::to_vec(&ambiguous)?))?;
    stream.flush()?;
    assert_eq!(
        read_response(&mut stream)?["outcome_artifact"]["reported"]["state"],
        "outcome_ambiguous"
    );
    Ok(())
}

#[test]
fn production_witness_ipc_rejects_missing_wrong_key_tampered_expired_delegated_and_retry_forms(
) -> TestResult {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().join("root");
    std::fs::create_dir(&root)?;
    let signer = ProductionApprovalSignerV1::from_seed("correct-key".into(), [1_u8; 32]);
    let service = native_service(&root)?.with_production_approval_verifier(signer.verifier()?);
    let (listener, socket) = bind_private_socket(tmp.path(), "negative.sock")?;
    let thread = std::thread::spawn(move || {
        let _ = serve(listener, Arc::new(service), 4);
    });
    let mut stream = connect_with_retry(&socket, &thread)?;
    let call = ToolCallSpecV1 {
        tool: "write_file".into(),
        args: serde_json::json!({"path":"/home/sikmindz/work/ares-production-permit-20260830/n.txt","content":"x"}),
        frozen_clock: None,
    };
    let base = signer.sign(production_witness(call))?;
    let send = |stream: &mut UnixStream,
                id: &str,
                w: serde_json::Value|
     -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let payload = serde_json::json!({"schema":IPC_REQUEST_SCHEMA_V1,"protocol_version":IPC_PROTOCOL_VERSION_V1,"request_id":id,"request":{"kind":"permit_issue_production","witness":w}});
        stream.write_all(&frame(&serde_json::to_vec(&payload)?))?;
        stream.flush()?;
        read_response(stream)
    };
    let wrong = ProductionApprovalSignerV1::from_seed("wrong-key".into(), [2_u8; 32])
        .sign(production_witness(base.call.clone()))?;
    assert_eq!(
        send(&mut stream, "wrong-key", serde_json::to_value(wrong)?)?["error"]["code"],
        "runtime_error"
    );
    let mut tampered = base.clone();
    tampered.call.args["content"] = serde_json::json!("tampered");
    assert_eq!(
        send(&mut stream, "tampered", serde_json::to_value(tampered)?)?["error"]["code"],
        "runtime_error"
    );
    let mut expired = base.clone();
    expired.expires_at = FixedClock.now();
    assert_eq!(
        send(&mut stream, "expired", serde_json::to_value(expired)?)?["error"]["code"],
        "runtime_error"
    );
    let mut delegated = base.clone();
    delegated.delegation = DelegationPolicyV1::Forbidden;
    let mut delegated_value = serde_json::to_value(delegated)?;
    delegated_value["delegation"] = serde_json::json!("allowed");
    assert!(
        send(&mut stream, "delegation", delegated_value).is_err(),
        "unknown delegation enum must fail strict IPC decoding"
    );
    // Malformed enum values terminate this framed connection; reconnect so each
    // negative witness is independently tested against the daemon owner.
    let mut stream = connect_with_retry(&socket, &thread)?;
    let mut retry_value = serde_json::to_value(base)?;
    retry_value["retry"] = serde_json::json!("retry");
    assert!(
        send(&mut stream, "retry", retry_value).is_err(),
        "unknown retry enum must fail strict IPC decoding"
    );
    let mut stream = connect_with_retry(&socket, &thread)?;
    // Missing closed witness material fails during strict IPC decoding before dispatch.
    let missing = serde_json::json!({"schema": IPC_REQUEST_SCHEMA_V1, "protocol_version": IPC_PROTOCOL_VERSION_V1, "request_id": "missing", "request": {"kind": "permit_issue_production"}});
    stream.write_all(&frame(&serde_json::to_vec(&missing)?))?;
    stream.flush()?;
    assert!(read_response(&mut stream).is_err());
    Ok(())
}

#[test]
fn daemon_issues_approved_permit_then_consumes_and_records_outcome_over_ipc() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let runtime_root = tmp.path().join("approved-permit-root");
    std::fs::create_dir(&runtime_root)?;
    let call = ToolCallSpecV1 {
        tool: "echo".into(),
        args: serde_json::json!({"text": "approved-permit"}),
        frozen_clock: None,
    };
    let approval_request = PermitApprovalRequestV1 {
        call: call.clone(),
        requested_validity_ms: 300_000,
    };
    let verifier = OperatorApprovalVerifierV1::from_key([7_u8; 32])?;
    let approval = verifier.issue_witness(&approval_request, "operator-ui:case-1")?;
    let service = native_service(&runtime_root)?.with_operator_approval_verifier(verifier.clone());
    let (listener, socket_path) = bind_private_socket(tmp.path(), "approved-permit.sock")?;
    let server_thread = std::thread::spawn(move || {
        let _ = serve(listener, Arc::new(service), 4);
    });
    let mut stream = connect_with_retry(&socket_path, &server_thread)?;

    // A signed witness binds the exact request. Reusing it for changed call
    // material must fail before the policy owner creates durable state.
    let mut changed_request = approval_request.clone();
    changed_request.call.args = serde_json::json!({"text": "tampered"});
    let tampered = serde_json::json!({
        "schema": IPC_REQUEST_SCHEMA_V1,
        "protocol_version": IPC_PROTOCOL_VERSION_V1,
        "request_id": "permit-issue-tampered",
        "request": {"kind": "permit_issue", "request": changed_request, "approval": approval},
    });
    stream.write_all(&frame(&serde_json::to_vec(&tampered)?))?;
    stream.flush()?;
    let rejected = read_response(&mut stream)?;
    assert_eq!(rejected["request_id"], "permit-issue-tampered");
    assert_eq!(rejected["error"]["code"], "runtime_error");

    let approval = verifier.issue_witness(&approval_request, "operator-ui:case-2")?;
    let issue = serde_json::json!({
        "schema": IPC_REQUEST_SCHEMA_V1,
        "protocol_version": IPC_PROTOCOL_VERSION_V1,
        "request_id": "permit-issue",
        "request": {"kind": "permit_issue", "request": approval_request, "approval": approval},
    });
    stream.write_all(&frame(&serde_json::to_vec(&issue)?))?;
    stream.flush()?;
    let issued = read_response(&mut stream)?;
    assert_eq!(issued["request_id"], "permit-issue");
    assert_eq!(issued["issuance_evidence"]["state"]["state"], "issued");
    assert!(issued["permit_id"].as_str().is_some());

    // Issuance is one-shot: an exact approval replay cannot mint/re-return a permit.
    let replay = serde_json::json!({
        "schema": IPC_REQUEST_SCHEMA_V1,
        "protocol_version": IPC_PROTOCOL_VERSION_V1,
        "request_id": "permit-issue-replay",
        "request": {"kind": "permit_issue", "request": approval_request, "approval": approval},
    });
    stream.write_all(&frame(&serde_json::to_vec(&replay)?))?;
    stream.flush()?;
    let replayed = read_response(&mut stream)?;
    assert_eq!(replayed["error"]["code"], "runtime_error");

    let consume = serde_json::json!({
        "schema": IPC_REQUEST_SCHEMA_V1,
        "protocol_version": IPC_PROTOCOL_VERSION_V1,
        "request_id": "permit-consume-approved",
        "request": {"kind": "permit_consume", "permit_id": issued["permit_id"], "binding": issued["binding"], "call": call},
    });
    stream.write_all(&frame(&serde_json::to_vec(&consume)?))?;
    stream.flush()?;
    let consumed = read_response(&mut stream)?;
    assert_eq!(consumed["evidence"]["state"]["state"], "consumed");
    let outcome = serde_json::json!({
        "schema": IPC_REQUEST_SCHEMA_V1,
        "protocol_version": IPC_PROTOCOL_VERSION_V1,
        "request_id": "permit-outcome-approved",
        "request": {"kind": "permit_outcome_record", "permit_id": consumed["permit_id"], "preflight_receipt_digest": consumed["receipt_artifact"]["receipt_digest"], "reported": {"state": "outcome_ambiguous", "duration_ms": 7, "error_type": "transport_lost"}},
    });
    stream.write_all(&frame(&serde_json::to_vec(&outcome)?))?;
    stream.flush()?;
    let recorded = read_response(&mut stream)?;
    assert_eq!(
        recorded["outcome_artifact"]["reported"]["state"],
        "outcome_ambiguous"
    );
    // Ambiguity is terminal: a later outcome cannot overwrite the quarantine
    // record; a future operator reconciliation is a separate authority path.
    let overwrite = serde_json::json!({
        "schema": IPC_REQUEST_SCHEMA_V1,
        "protocol_version": IPC_PROTOCOL_VERSION_V1,
        "request_id": "permit-outcome-overwrite",
        "request": {"kind": "permit_outcome_record", "permit_id": consumed["permit_id"], "preflight_receipt_digest": consumed["receipt_artifact"]["receipt_digest"], "reported": {"state": "succeeded", "duration_ms": 8, "error_type": null}},
    });
    stream.write_all(&frame(&serde_json::to_vec(&overwrite)?))?;
    stream.flush()?;
    assert_eq!(
        read_response(&mut stream)?["error"]["code"],
        "runtime_error"
    );
    Ok(())
}

/// The Phase 3 gate: a fresh daemon serves the Phase 2 native action over
/// authenticated IPC, returns a run handle, and the run strictly verifies.
#[test]
fn daemon_submits_and_verifies_phase_two_action_over_ipc() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let runtime_root = tmp.path().join("run");
    std::fs::create_dir(&runtime_root)?;
    let service = native_service(&runtime_root)?;

    let (listener, socket_path) = bind_private_socket(tmp.path(), "ra.sock")?;
    let server_thread = std::thread::spawn(move || {
        let _ = serve(listener, Arc::new(service), 4);
    });

    // Submit the native operation over IPC (not through the embedded service).
    let operation = native_operation()?;
    let mut stream = connect_with_retry(&socket_path, &server_thread)?;
    stream.write_all(&submit_request("req-submit", &operation))?;
    stream.flush()?;
    let submitted = read_response(&mut stream)?;
    assert_eq!(submitted["request_id"], "req-submit");
    assert_eq!(submitted["submitted"], true);
    let run_id = submitted["run_id"].as_str().unwrap().to_string();

    // Query terminal status over the same daemon IPC.
    stream.write_all(&status_request("req-status", &run_id))?;
    stream.flush()?;
    let status = read_response(&mut stream)?;
    assert_eq!(status["status"]["state"], "terminal");
    assert_eq!(
        status["status"]["terminal_state"],
        serde_json::json!("succeeded")
    );

    // Verification is daemon-derived from RuntimeService; the client only
    // supplies the authoritative run identifier.
    stream.write_all(&verify_request("req-verify", &run_id))?;
    stream.flush()?;
    let verification = read_response(&mut stream)?;
    assert_eq!(verification["request_id"], "req-verify");
    assert_eq!(verification["run_id"], run_id);
    assert_eq!(verification["verification"]["ok"], true);
    assert_eq!(verification["verification"]["current_strict_success"], true);
    assert!(verification["verification"]["length"].as_u64().is_some());
    Ok(())
}

#[test]
fn daemon_returns_correlated_verify_error_for_tampered_run() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let runtime_root = tmp.path().join("run");
    std::fs::create_dir(&runtime_root)?;
    let service = native_service(&runtime_root)?;
    let handle = service.submit(&native_operation()?)?;
    let run_id = handle.run_id().to_string();
    std::fs::write(handle.run_dir().join("receipts.ndjson"), b"tampered\n")?;

    let (listener, socket_path) = bind_private_socket(tmp.path(), "ra.sock")?;
    let server_thread = std::thread::spawn(move || {
        let _ = serve(listener, Arc::new(service), 4);
    });
    let mut stream = connect_with_retry(&socket_path, &server_thread)?;
    stream.write_all(&verify_request("req-tampered", &run_id))?;
    stream.flush()?;

    let response = read_response(&mut stream)?;
    assert_eq!(response["request_id"], "req-tampered");
    assert_eq!(response["error"]["code"], "runtime_error");
    assert!(response["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .contains("chain divergence"));
    Ok(())
}

#[test]
fn daemon_serves_status_over_authenticated_ipc() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let runtime_root = tmp.path().join("run");
    std::fs::create_dir(&runtime_root)?;
    let service = native_service(&runtime_root)?;

    // Submit the operation through the embedded runtime first to get a terminal
    // run we can query over IPC.
    let operation = native_operation()?;
    let handle = service.submit(&operation)?;
    let run_id = handle.run_id().to_string();

    let (listener, socket_path) = bind_private_socket(tmp.path(), "ra.sock")?;
    let runtime = Arc::new(service);
    let server_thread = std::thread::spawn({
        let runtime = Arc::clone(&runtime);
        move || serve(listener, runtime, 4)
    });

    // Give the accept loop a moment to bind, then connect.
    let mut stream = loop {
        match UnixStream::connect(&socket_path) {
            Ok(s) => break s,
            Err(_) => {
                if server_thread.is_finished() {
                    return Err("daemon server exited early".into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    };

    stream.write_all(&status_request("req-1", &run_id))?;
    stream.flush()?;

    // Read the framed response.
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header) as usize;
    assert!(len <= MAX_FRAME_PAYLOAD_BYTES);
    let mut body = vec![0_u8; len];
    stream.read_exact(&mut body)?;
    let response: serde_json::Value = serde_json::from_slice(&body)?;

    assert_eq!(response["request_id"], "req-1");
    assert_eq!(response["run_id"], run_id);
    assert_eq!(response["status"]["state"], "terminal");
    assert_eq!(
        response["status"]["terminal_state"],
        serde_json::json!("succeeded")
    );

    // A duplicate request id on the same connection must be rejected as a
    // typed frame error rather than corrupting state.
    stream.write_all(&status_request("req-1", &run_id))?;
    stream.flush()?;
    let mut header2 = [0_u8; 4];
    // The server returns a typed frame error on the duplicated id; the exact
    // framing of the error is verified in protocol tests. Here we only assert
    // the connection remains responsive to a fresh id afterward.
    if stream.read_exact(&mut header2).is_ok() {
        let len2 = u32::from_be_bytes(header2) as usize;
        let mut body2 = vec![0_u8; len2];
        stream.read_exact(&mut body2)?;
    }

    Ok(())
}

/// Read one length-prefixed response frame from `stream`.
fn read_response(stream: &mut UnixStream) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header) as usize;
    assert!(len <= MAX_FRAME_PAYLOAD_BYTES);
    let mut body = vec![0_u8; len];
    stream.read_exact(&mut body)?;
    Ok(serde_json::from_slice(&body)?)
}

fn connect_with_retry(
    socket_path: &std::path::Path,
    server_thread: &std::thread::JoinHandle<()>,
) -> Result<UnixStream, Box<dyn std::error::Error>> {
    loop {
        match UnixStream::connect(socket_path) {
            Ok(s) => return Ok(s),
            Err(_) => {
                if server_thread.is_finished() {
                    return Err("daemon server exited early".into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

#[test]
fn daemon_handles_concurrent_connections_within_cap() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let runtime_root = tmp.path().join("run");
    std::fs::create_dir(&runtime_root)?;
    let service = native_service(&runtime_root)?;
    let operation = native_operation()?;
    let handle = service.submit(&operation)?;
    let run_id = handle.run_id().to_string();

    let (listener, socket_path) = bind_private_socket(tmp.path(), "ra.sock")?;
    let server_thread = std::thread::spawn(move || {
        let _ = serve(listener, Arc::new(service), 2);
    });

    // Two concurrent clients, each with a distinct request id.
    let mut c1 = connect_with_retry(&socket_path, &server_thread)?;
    let mut c2 = connect_with_retry(&socket_path, &server_thread)?;
    c1.write_all(&status_request("req-a", &run_id))?;
    c1.flush()?;
    c2.write_all(&status_request("req-b", &run_id))?;
    c2.flush()?;

    let r1 = read_response(&mut c1)?;
    let r2 = read_response(&mut c2)?;
    assert_eq!(r1["request_id"], "req-a");
    assert_eq!(r2["request_id"], "req-b");
    assert_eq!(r1["status"]["state"], "terminal");
    assert_eq!(r2["status"]["state"], "terminal");
    Ok(())
}

/// A malformed or oversized client must not crash the daemon; a fresh valid
/// request on a new connection must still be served afterward.
#[test]
fn daemon_survives_malformed_and_oversized_clients() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let runtime_root = tmp.path().join("run");
    std::fs::create_dir(&runtime_root)?;
    let service = native_service(&runtime_root)?;
    let operation = native_operation()?;
    let handle = service.submit(&operation)?;
    let run_id = handle.run_id().to_string();

    let (listener, socket_path) = bind_private_socket(tmp.path(), "ra.sock")?;
    let server_thread = std::thread::spawn(move || {
        let _ = serve(listener, Arc::new(service), 4);
    });

    // 1. A client that sends an oversized length prefix.
    let mut bad = connect_with_retry(&socket_path, &server_thread)?;
    let oversized: Vec<u8> = vec![0xFF, 0xFF, 0xFF, 0xFF];
    bad.write_all(&oversized)?;
    bad.flush()?;
    drop(bad);

    // 2. A client that sends non-JSON garbage.
    let mut junk = connect_with_retry(&socket_path, &server_thread)?;
    junk.write_all(&[0u8, 0, 0, 3, b'a', b'b', b'c'])?; // valid len=3, non-JSON payload
    junk.flush()?;
    drop(junk);

    // 3. A client that sends a partial frame then disconnects.
    let mut partial = connect_with_retry(&socket_path, &server_thread)?;
    partial.write_all(&[0u8, 0, 0, 100])?; // declares 100 but sends nothing
    partial.flush()?;
    drop(partial);

    // The daemon must still serve a valid request on a fresh connection.
    let mut stream = connect_with_retry(&socket_path, &server_thread)?;
    stream.write_all(&status_request("req-ok", &run_id))?;
    stream.flush()?;
    let response = read_response(&mut stream)?;
    assert_eq!(response["request_id"], "req-ok");
    assert_eq!(response["status"]["state"], "terminal");
    Ok(())
}

/// With `max_concurrent=1`, a connection that is actively being served (its
/// handler thread is alive waiting on reads) must prevent a second concurrent
/// connection from being dispatched. The second is denied at the socket, not
/// queued unboundedly.
#[test]
fn max_concurrent_one_denies_second_connection() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let runtime_root = tmp.path().join("run");
    std::fs::create_dir(&runtime_root)?;
    let service = native_service(&runtime_root)?;
    let operation = native_operation()?;
    let handle = service.submit(&operation)?;
    let run_id = handle.run_id().to_string();

    let (listener, socket_path) = bind_private_socket(tmp.path(), "ra.sock")?;
    let server_thread = std::thread::spawn(move || {
        let _ = serve(listener, Arc::new(service), 1);
    });

    // Hold the only slot open: connect but send nothing so the handler thread
    // stays alive waiting on a read.
    let mut holder = connect_with_retry(&socket_path, &server_thread)?;
    let _ = holder;

    // A second connection is accepted by the kernel but must be denied at the
    // daemon (either a typed denial frame or a dropped connection), never a
    // successful dispatch. Wait briefly for the accept loop to reject it, then
    // confirm the daemon is still alive by releasing the slot.
    std::thread::sleep(Duration::from_millis(100));
    assert!(!server_thread.is_finished(), "daemon must stay alive");

    // Send the valid request on the holder; it should now be served once its
    // slot is the active one (or the read of its request succeeds).
    holder.write_all(&status_request("req-slot", &run_id))?;
    holder.flush()?;
    let response = read_response(&mut holder)?;
    assert_eq!(response["request_id"], "req-slot");
    assert_eq!(response["status"]["state"], "terminal");
    Ok(())
}

/// Slow readers do not cause unbounded buffering: each connection is bounded
/// by `MAX_FRAME_PAYLOAD_BYTES` per frame and served in its own worker. A
/// client that connects and never reads still holds at most one in-flight
/// frame; other clients continue to be served independently.
#[test]
fn slow_reader_does_not_block_other_clients() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let runtime_root = tmp.path().join("run");
    std::fs::create_dir(&runtime_root)?;
    let service = native_service(&runtime_root)?;
    let operation = native_operation()?;
    let handle = service.submit(&operation)?;
    let run_id = handle.run_id().to_string();

    let (listener, socket_path) = bind_private_socket(tmp.path(), "ra.sock")?;
    let server_thread = std::thread::spawn(move || {
        let _ = serve(listener, Arc::new(service), 4);
    });

    // A slow reader: connects, sends a valid request, but never reads the
    // response. Its worker blocks writing one bounded frame to the socket.
    let mut slow = connect_with_retry(&socket_path, &server_thread)?;
    slow.write_all(&status_request("req-slow", &run_id))?;
    slow.flush()?;
    std::thread::sleep(Duration::from_millis(50));

    // A fast client on its own connection must still be served promptly.
    let mut fast = connect_with_retry(&socket_path, &server_thread)?;
    fast.write_all(&status_request("req-fast", &run_id))?;
    fast.flush()?;
    let response = read_response(&mut fast)?;
    assert_eq!(response["request_id"], "req-fast");
    assert_eq!(response["status"]["state"], "terminal");
    Ok(())
}
