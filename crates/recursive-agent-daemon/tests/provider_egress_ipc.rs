#![allow(clippy::unwrap_used, clippy::expect_used)]

use chrono::{TimeZone, Utc};
use llm_tool_runtime::ToolRegistry;
use recursive_agent_contracts::{
    content_digest, ActorAuthorityV1, AuthorityOriginV1, ContentDigest, DeclaredEffectsV1,
    OperationBudgetV1, ProvenanceRefV1, ProviderEgressBindingMaterialV1, ProviderEgressBindingV1,
    ProviderEgressOperationEnvelopeV3, ProviderEgressOperationSchemaV1, ReplayClassV1,
    ReplayIntentV1, ReplaySpecV1, SealedCompletionArgumentsV3, SealedCompletionCallV3,
};
use recursive_agent_daemon::{
    bind_private_socket, serve, IPC_PROTOCOL_VERSION_V1, IPC_REQUEST_SCHEMA_V1,
};
use recursive_agent_policy::{
    PolicyError, ProviderEgressAdmissionVerifier, ValidatedProviderEgressAdmissionV1,
};
use recursive_agent_provider::{
    CompletionBackend, CompletionRequestV1, CompletionResponseV1, ProviderError, ProviderSpecV1,
    ValidatedEndpoint,
};
use recursive_agent_runner::{
    tool_runtime_with_sealed_completion, Clock, RuntimeDependencies, RuntimeLedgerDependencyV1,
    RuntimePolicyDependencyV1, RuntimeProviderDependencyV1, RuntimeSandboxDependencyV1,
    RuntimeService, RuntimeStoreDependencyV1,
};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2029, 1, 1, 0, 0, 0).single().unwrap()
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
        self.0.fetch_add(1, Ordering::SeqCst);
        let model = match &request.provider {
            ProviderSpecV1::Ollama { model, .. }
            | ProviderSpecV1::OpenAiCompatible { model, .. } => model.clone(),
        };
        Ok(CompletionResponseV1 {
            model,
            text: "native-ipc-v3-response".into(),
            raw: serde_json::json!({"fixture": true}),
        })
    }
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
        prompt: "sealed IPC prompt".into(),
        max_tokens: Some(8),
    };
    let request_value = serde_json::to_value(&request)?;
    let binding = ProviderEgressBindingV1::seal(ProviderEgressBindingMaterialV1 {
        policy_basis_ref: "policy:ipc-fixture".into(),
        policy_basis_digest: format!("sha256:{}", "a".repeat(64)),
        context_digest: format!("sha256:{}", "b".repeat(64)),
        source_revision: "source:ipc-fixture".into(),
        graph_obligation_ref: "graph-obligation:ipc-node".into(),
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
            .ok_or("fixture expiry invalid")?,
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
            principal: "actor:v3-ipc-fixture".into(),
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
            source: "urn:test:v3-ipc".into(),
            digest: ContentDigest::compute(b"v3-ipc-fixture"),
        }],
        replay: ReplaySpecV1 {
            class: ReplayClassV1::RecordedEffect,
            intent: ReplayIntentV1::ExecuteOnce,
        },
        sealed_completion,
    })
}

fn service(
    root: &std::path::Path,
    calls: Arc<AtomicUsize>,
) -> Result<RuntimeService, Box<dyn std::error::Error>> {
    let clock: Arc<dyn Clock> = Arc::new(FixedClock);
    let verifier: Arc<dyn ProviderEgressAdmissionVerifier> = Arc::new(AllowCurrentEgress);
    let runtime = tool_runtime_with_sealed_completion(
        ToolRegistry::new(),
        FixtureBackend(calls),
        Arc::clone(&clock),
        Arc::clone(&verifier),
    );
    let dependencies = RuntimeDependencies::builder()
        .policy(RuntimePolicyDependencyV1::Native)
        .sandbox(RuntimeSandboxDependencyV1::Native)
        .tool_runtime(Arc::new(runtime))
        .provider(RuntimeProviderDependencyV1::Configured(provider()?))
        .provider_egress_verifier(verifier)
        .ledger(RuntimeLedgerDependencyV1::Native)
        .clock(clock)
        .store(RuntimeStoreDependencyV1::Native)
        .output_root(root)
        .build()?;
    Ok(RuntimeService::new(dependencies))
}

fn request_frame(request_id: &str, request: serde_json::Value) -> Vec<u8> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "schema": IPC_REQUEST_SCHEMA_V1,
        "protocol_version": IPC_PROTOCOL_VERSION_V1,
        "request_id": request_id,
        "request": request,
    }))
    .unwrap();
    let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&payload);
    frame
}

fn read_response(stream: &mut UnixStream) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    Ok(serde_json::from_slice(&payload)?)
}

fn connect(path: &std::path::Path) -> Result<UnixStream, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match UnixStream::connect(path) {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                if Instant::now() >= deadline {
                    return Err(error.into());
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

#[test]
fn managed_v2_v3_envelope_crosses_real_native_ipc_without_v1_downgrade(
) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().join("runs");
    std::fs::create_dir(&root)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let runtime = Arc::new(service(&root, Arc::clone(&calls))?);
    let (listener, socket_path) = bind_private_socket(tmp.path(), "provider-v3.sock")?;
    let server_runtime = Arc::clone(&runtime);
    std::thread::spawn(move || {
        let _ = serve(listener, server_runtime, 4);
    });

    let operation = operation()?;
    let mut stream = connect(&socket_path)?;
    stream.write_all(&request_frame(
        "submit-v3",
        serde_json::json!({"kind": "submit_provider_egress_v3", "operation": operation}),
    ))?;
    let submitted = read_response(&mut stream)?;
    assert_eq!(submitted["request_id"], "submit-v3");
    assert_eq!(submitted["submitted"], true);
    assert_eq!(submitted["operation_family"], "provider_egress_v3");
    let run_id = submitted["run_id"].as_str().ok_or("run id missing")?;

    stream.write_all(&request_frame(
        "status-v3",
        serde_json::json!({"kind": "status", "run_id": run_id}),
    ))?;
    let status = read_response(&mut stream)?;
    assert_eq!(status["status"]["state"], "terminal");
    assert_eq!(status["status"]["terminal_state"], "succeeded");

    stream.write_all(&request_frame(
        "verify-v3",
        serde_json::json!({"kind": "verify", "run_id": run_id}),
    ))?;
    let verification = read_response(&mut stream)?;
    assert_eq!(verification["verification"]["ok"], true);
    assert_eq!(verification["verification"]["current_strict_success"], true);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}
