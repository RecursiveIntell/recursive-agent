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

    // A later consumer must present the exact sealed operation to the owner,
    // not reopen the path returned by submit or verify.
    stream.write_all(&request_frame(
        "read-recorded-v3",
        serde_json::json!({"kind": "read_recorded_provider_output_v3", "operation": operation}),
    ))?;
    let recorded = read_response(&mut stream)?;
    assert_eq!(recorded["request_id"], "read-recorded-v3");
    assert_eq!(recorded["output"]["model"], "fixture-model");
    assert_eq!(recorded["output"]["text"], "native-ipc-v3-response");
    assert!(recorded.get("run_dir").is_none());
    assert!(recorded["output"].get("raw").is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let mut changed_operation = operation.clone();
    changed_operation.provenance[0].source = "urn:test:different-context".into();
    stream.write_all(&request_frame(
        "read-other-v3",
        serde_json::json!({"kind": "read_recorded_provider_output_v3", "operation": changed_operation}),
    ))?;
    let rejected = read_response(&mut stream)?;
    assert_eq!(rejected["request_id"], "read-other-v3");
    assert_eq!(rejected["error"]["code"], "runtime_error");
    assert!(rejected.get("output").is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn raw_native_ipc_rejects_hostile_bytes_before_runtime_and_preserves_v3_read(
) -> Result<(), Box<dyn std::error::Error>> {
    use base64::Engine as _;
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().join("runs");
    std::fs::create_dir(&root)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let runtime = Arc::new(service(&root, Arc::clone(&calls))?);
    let (listener, socket_path) = bind_private_socket(tmp.path(), "native-raw.sock")?;
    std::thread::spawn(move || {
        let _ = serve(listener, runtime, 4);
    });
    let mut stream = connect(&socket_path)?;
    for (index, raw) in [
        br#"{"schema":"recursive-agent.operation/v3","\u0073chema":"recursive-agent.operation/v1"}"#.as_slice(),
        br#"{"schema":"recursive-agent.operation/v3","nested":{"x":1,"\u0078":2}}"#,
        b"\xff",
        b"{} {}",
        br#"{"schema":"recursive-agent.operation/v9"}"#,
    ].iter().enumerate() {
        stream.write_all(&request_frame(&format!("denied-{index}"), serde_json::json!({
            "kind": "submit_native_raw",
            "operation_json_b64": base64::engine::general_purpose::STANDARD.encode(raw),
        })))?;
        let response = read_response(&mut stream)?;
        assert_eq!(response["error"]["code"], "runtime_error");
        assert!(response.get("run_id").is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(std::fs::read_dir(&root)?.count(), 0);
    }
    let raw = serde_json::to_vec(&operation()?)?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&raw);
    stream.write_all(&request_frame(
        "raw-valid",
        serde_json::json!({
            "kind": "submit_native_raw", "operation_json_b64": encoded,
        }),
    ))?;
    let submitted = read_response(&mut stream)?;
    assert_eq!(submitted["operation_family"], "provider_egress_v3");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    stream.write_all(&request_frame(
        "read-raw-valid",
        serde_json::json!({
            "kind": "read_recorded_provider_output_native_raw", "operation_json_b64": encoded,
        }),
    ))?;
    let recorded = read_response(&mut stream)?;
    assert_eq!(recorded["output"]["text"], "native-ipc-v3-response");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

/// Exercise the actual plugin registration closure over the real Rust native
/// socket. This is an isolated candidate witness, NOT an installed Hermes
/// plugin-loader or selected-session test.
#[test]
fn plugin_registration_to_real_daemon_keeps_raw_rejection_before_runtime(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    let tmp = tempfile::tempdir()?;
    let root = tmp.path().join("runs");
    std::fs::create_dir(&root)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let runtime = Arc::new(service(&root, Arc::clone(&calls))?);
    let (listener, socket_path) = bind_private_socket(tmp.path(), "plugin-join.sock")?;
    std::thread::spawn(move || {
        let _ = serve(listener, runtime, 4);
    });

    // Use the same register(ctx) closure Hermes calls, without installing it.
    // The Python client must carry these bytes through framed native IPC; only
    // the contracts owner inside the daemon is permitted to interpret them.
    let script = r#"
import importlib.util, json, pathlib, sys
plugin_dir = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('hermes_native', plugin_dir / '__init__.py', submodule_search_locations=[str(plugin_dir)])
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)
class Context:
    def __init__(self, socket_path):
        self.socket_path = socket_path
        self.tools = []
    def get_config(self, key, default=None):
        assert key == 'socket_path'
        return self.socket_path
    def register_tool(self, **kwargs):
        self.tools.append(kwargs)
ctx = Context(sys.argv[2])
plugin.register(ctx)
assert len(ctx.tools) == 1
assert ctx.tools[0]['name'] == 'recursive_agent_execute'
assert ctx.tools[0]['check_fn']() is True
print(ctx.tools[0]['handler']({'envelope_path': sys.argv[3]}))
"#;
    let plugin_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../integrations/hermes-native");
    let run_plugin = |input: &std::path::Path| -> Result<String, Box<dyn std::error::Error>> {
        let output = Command::new("python3")
            .arg("-B")
            .arg("-c")
            .arg(script)
            .arg(&plugin_dir)
            .arg(&socket_path)
            .arg(input)
            .output()?;
        assert!(
            output.status.success(),
            "plugin subprocess failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8(output.stdout)?.trim().to_owned())
    };

    for (index, (raw, expected_reason)) in [
        (
            br#"{"schema":"recursive-agent.operation/v3","\u0073chema":"recursive-agent.operation/v1"}"#.as_slice(),
            "native operation contains a duplicate object key",
        ),
        (
            br#"{"schema":"recursive-agent.operation/v3","nested":{"x":1,"\u0078":2}}"#,
            "native operation contains a duplicate object key",
        ),
        (b"\xff", "native operation JSON is malformed"),
        (b"{} {}", "native operation JSON is malformed"),
        (
            br#"{"schema":"recursive-agent.operation/v9"}"#,
            "unsupported native operation schema",
        ),
    ]
    .iter()
    .enumerate()
    {
        let input = tmp.path().join(format!("hostile-{index}.json"));
        std::fs::write(&input, raw)?;
        let result = run_plugin(&input)?;
        assert!(
            result.contains("native operation denied:") && result.contains(expected_reason),
            "hostile input did not reach expected canonical denial: {result}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(std::fs::read_dir(&root)?.count(), 0);
    }

    let valid = tmp.path().join("valid-v3.json");
    std::fs::write(&valid, serde_json::to_vec(&operation()?)?)?;
    let result: serde_json::Value = serde_json::from_str(&run_plugin(&valid)?)?;
    assert_eq!(result["schema"], "recursive-agent.hermes-result/v1");
    assert_eq!(result["verified"], true);
    assert_eq!(result["recorded_output"]["model"], "fixture-model");
    assert_eq!(result["recorded_output"]["text"], "native-ipc-v3-response");
    assert_eq!(
        result["recorded_output"].as_object().map(|map| map.len()),
        Some(2)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(std::fs::read_dir(&root)?.count(), 1);
    Ok(())
}

/// Explicit cross-repository candidate test, not part of the default Rust suite.
/// The Ares source root must be supplied by the controller; the Python fixture
/// refuses to import an installed or unrelated run_agent module.
#[test]
#[ignore = "requires ARES_CANDIDATE_AGENT_ROOT and a separate Ares source worktree"]
fn disposable_full_agent_v3_turn_uses_real_native_ipc_and_fixture_provider(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    let agent_root = std::path::PathBuf::from(std::env::var("ARES_CANDIDATE_AGENT_ROOT")?);
    if !agent_root.join("run_agent.py").is_file() {
        return Err("candidate Ares source has no run_agent.py".into());
    }
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().join("runs");
    std::fs::create_dir(&root)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let runtime = Arc::new(service(&root, Arc::clone(&calls))?);
    let (listener, socket_path) = bind_private_socket(tmp.path(), "full-v3-turn.sock")?;
    let server_runtime = Arc::clone(&runtime);
    std::thread::spawn(move || {
        let _ = serve(listener, server_runtime, 8);
    });
    let valid = tmp.path().join("valid-v3.json");
    std::fs::write(&valid, serde_json::to_vec(&operation()?)?)?;
    let plugin_root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../integrations/hermes-native");
    let fixture = plugin_root.join("tests/disposable_v3_agent_turn.py");
    let output = Command::new("python3")
        .arg("-B")
        .arg(&fixture)
        .arg(&socket_path)
        .arg(&valid)
        .arg(&root)
        .arg(&plugin_root)
        .arg(&agent_root)
        .env("PYTHONPATH", &agent_root)
        .output()?;
    assert!(
        output.status.success(),
        "disposable Ares full V3 turn failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    let summary_line = stdout
        .lines()
        .find_map(|line| line.strip_prefix("AC08_V3_RESULT="))
        .ok_or_else(|| format!("fixture summary missing from stdout: {stdout}"))?;
    let summary: serde_json::Value = serde_json::from_str(summary_line)?;
    assert_eq!(summary["result"], "PASS");
    assert_eq!(summary["legacy_top_level_gate"], false);
    assert_eq!(summary["namespaced_gate"], true);
    assert_eq!(summary["legacy_run_entries"], 0);
    assert_eq!(summary["default_socket_exists"], false);
    assert_eq!(summary["invalid_run_entries"], 0);
    assert_eq!(summary["valid_run_entries"], 1);
    assert_eq!(summary["external_provider"], false);
    assert_eq!(summary["installed_route"], false);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(std::fs::read_dir(&root)?.count(), 1);
    println!("AC08_V3_VERIFIED_SUMMARY={summary}");
    Ok(())
}
