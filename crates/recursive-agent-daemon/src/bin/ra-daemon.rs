//! Executable recursive-agent daemon.
//!
//! Spawns the authenticated native IPC server wired to the canonical
//! `RuntimeService`. Used by the Hermes integration E2E and operators who want
//! a real (not in-process) daemon. This binary only wires admitted runtime
//! dependencies; it owns no execution or authority beyond `RuntimeService`.
//!
//!   ra-daemon serve --root <runs> --socket <path> [--max-concurrent N]

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use llm_tool_runtime::{
    McpSurfaceKind, Tool, ToolApprovalKind, ToolBackendKind, ToolCtx, ToolDescriptor, ToolError,
    ToolErrorClass, ToolExposureMode, ToolExposurePolicy, ToolIdempotencyClass, ToolOutputMode,
    ToolReceiptPersistence, ToolRegistry, ToolResult, ToolRuntime, ToolSideEffectClass,
};
use recursive_agent_contracts::{
    content_digest, ActorAuthorityV1, AuthorityOriginV1, CausalLinkV1, ContentDigest,
    DeclaredEffectsV1, OperationBudgetV1, OperationEnvelopeV1, OperationSchemaV1, ProvenanceRefV1,
    ReplayClassV1, ReplayIntentV1, ReplaySpecV1, RunSpecV1, StepSpecV1, ToolCallSpecV1,
};
use recursive_agent_daemon::repo_audit::AuditLimits;
use recursive_agent_daemon::{bind_private_socket, serve};
use recursive_agent_runner::{
    Clock, RuntimeDependencies, RuntimeLedgerDependencyV1, RuntimePolicyDependencyV1,
    RuntimeProviderDependencyV1, RuntimeSandboxDependencyV1, RuntimeService,
    RuntimeStoreDependencyV1,
};

#[derive(Parser, Debug)]
#[command(name = "ra-daemon", about = "recursive-agent native IPC daemon")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Serve authenticated native IPC on a private socket.
    Serve {
        /// Parent directory for content-addressed run roots.
        #[arg(long)]
        root: PathBuf,
        /// Private socket path (created 0600 under an owned runtime dir).
        #[arg(long, default_value = "/tmp/ra.sock")]
        socket: PathBuf,
        /// Optional canonical source root admitted to the deterministic
        /// `repo_audit` tool. No source path is accepted from an operation.
        #[arg(long)]
        audit_root: Option<PathBuf>,
        /// Max concurrent connections.
        #[arg(long, default_value_t = 4)]
        max_concurrent: usize,
    },
    /// Emit one canonical native operation envelope as JSON (for the Hermes
    /// integration and tests to submit over IPC).
    EmitEnvelope {
        /// Text carried by the bounded echo action.
        #[arg(long, default_value = "recursive-agent-native-ok")]
        text: String,
    },
    /// Emit a canonical envelope for the daemon-configured read-only repo audit.
    EmitRepoAuditEnvelope {
        /// Exact canonical root declared as the operation's only read scope.
        #[arg(long)]
        audit_root: PathBuf,
    },
}

#[derive(Clone, Copy)]
struct SystemClockAdapter;

impl Clock for SystemClockAdapter {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
}

/// A bounded echo tool registered by the daemon so the Hermes vertical slice
/// can submit a deterministic read-only action.
struct EchoDescriptorOwner {
    descriptor: ToolDescriptor,
}

impl EchoDescriptorOwner {
    fn new() -> Self {
        Self {
            descriptor: ToolDescriptor {
                name: "echo".into(),
                version: "1.0.0".into(),
                description: Some("deterministic echo for native IPC".into()),
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

/// A deterministic, read-only source inventory rooted at a daemon-configured
/// canonical directory. Operations supply no filesystem path or shell command.
struct RepoAuditDescriptorOwner {
    descriptor: ToolDescriptor,
    limits: AuditLimits,
}

impl RepoAuditDescriptorOwner {
    fn new(root: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            descriptor: ToolDescriptor {
                name: "repo_audit".into(),
                version: "1.0.0".into(),
                description: Some("bounded, deterministic source inventory".into()),
                backend_kind: ToolBackendKind::LocalFunction,
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {"scope_digest": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"}},
                    "required": ["scope_digest"],
                    "additionalProperties": false
                }),
                output_mode: ToolOutputMode::StructuredJson,
                read_only: true,
                side_effect_class: ToolSideEffectClass::ReadOnly,
                idempotency_class: ToolIdempotencyClass::Idempotent,
                approval_kind: ToolApprovalKind::PolicyRequired,
                timeout_ms: 3_000,
                concurrency_key: Some("repo_audit".into()),
                cache_ttl_ms: None,
                exposure_mode: ToolExposureMode::Auto,
                mcp_surface_kind: McpSurfaceKind::None,
                exposure_policy: ToolExposurePolicy::default(),
                receipt_persistence: ToolReceiptPersistence::Ephemeral,
                output_size_limit_bytes: Some(32_768),
                provider_payload: None,
            },
            limits: AuditLimits::production(root)?,
        })
    }
}

#[async_trait]
impl Tool for RepoAuditDescriptorOwner {
    fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }

    async fn invoke(
        &self,
        _ctx: &ToolCtx,
        call: &llm_tool_runtime::ToolCall,
    ) -> Result<ToolResult, ToolError> {
        let scope_digest = call
            .arguments
            .get("scope_digest")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ToolError::new(ToolErrorClass::Denied, "repo_audit requires scope digest")
            })?;
        let expected_scope = self.limits.configured_scope_digest().map_err(|_| {
            ToolError::new(ToolErrorClass::Denied, "repo_audit has no configured scope")
        })?;
        if scope_digest != expected_scope.hex() {
            return Err(ToolError::new(
                ToolErrorClass::Denied,
                "repo_audit scope does not match daemon configuration",
            ));
        }
        let audit = self.limits.audit().map_err(|_| {
            ToolError::new(
                ToolErrorClass::Denied,
                "repo_audit failed its configured-root safety boundary",
            )
        })?;
        let output = serde_json::to_value(audit).map_err(|_| {
            ToolError::new(
                ToolErrorClass::Denied,
                "repo_audit could not serialize its bounded observation",
            )
        })?;
        Ok(ToolResult::json(output))
    }
}

fn build_runtime(
    root: &std::path::Path,
    audit_root: Option<PathBuf>,
) -> Result<RuntimeService, Box<dyn std::error::Error>> {
    let mut registry = ToolRegistry::new();
    registry.register(EchoDescriptorOwner::new());
    if let Some(audit_root) = audit_root {
        registry.register(RepoAuditDescriptorOwner::new(audit_root)?);
    }
    let dependencies = RuntimeDependencies::builder()
        .policy(RuntimePolicyDependencyV1::Native)
        .sandbox(RuntimeSandboxDependencyV1::Native)
        .tool_runtime(Arc::new(ToolRuntime::new(registry)))
        .provider(RuntimeProviderDependencyV1::Disabled)
        .ledger(RuntimeLedgerDependencyV1::Native)
        .clock(Arc::new(SystemClockAdapter))
        .store(RuntimeStoreDependencyV1::Native)
        .output_root(root)
        .build()?;
    Ok(RuntimeService::new(dependencies))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Serve {
            root,
            socket,
            audit_root,
            max_concurrent,
        } => {
            std::fs::create_dir_all(&root)?;
            let runtime = build_runtime(&root, audit_root)?;
            // The socket parent is the directory containing the socket path.
            let parent = socket
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("."));
            let name = socket
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or("socket path must have a file name")?;
            let (listener, path) = bind_private_socket(&parent, name)?;
            eprintln!("ra-daemon: serving on {path:?}");
            serve(listener, Arc::new(runtime), max_concurrent)?;
            Ok(())
        }
        Cmd::EmitEnvelope { text } => {
            let envelope = canonical_echo_envelope(&text)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&envelope).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        Cmd::EmitRepoAuditEnvelope { audit_root } => {
            let envelope = canonical_repo_audit_envelope(&audit_root)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&envelope).map_err(|e| e.to_string())?
            );
            Ok(())
        }
    }
}

/// Build a canonical echo operation envelope whose `action_digest` matches the
/// run_spec (computed Rust-side via JCS + BLAKE3). The Hermes plugin and E2E
/// tests submit this exact JSON over IPC.
fn canonical_echo_envelope(text: &str) -> Result<OperationEnvelopeV1, Box<dyn std::error::Error>> {
    let call = ToolCallSpecV1 {
        tool: "echo".into(),
        args: serde_json::json!({ "text": text }),
        frozen_clock: None,
    };
    let run_spec = RunSpecV1 {
        name: "hermes-native".into(),
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
            principal: "actor:hermes-native".into(),
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
            source: "urn:recursive-agent:hermes-native".into(),
            digest: ContentDigest::compute(b"fixed-hermes-native-echo"),
        }],
        replay: ReplaySpecV1 {
            class: ReplayClassV1::Deterministic,
            intent: ReplayIntentV1::ExecuteOnce,
        },
        run_spec,
    })
}

fn canonical_repo_audit_envelope(
    audit_root: &std::path::Path,
) -> Result<OperationEnvelopeV1, Box<dyn std::error::Error>> {
    let configured_root = std::fs::canonicalize(audit_root)?;
    let scope_digest = AuditLimits::production(configured_root)?.configured_scope_digest()?;
    let call = ToolCallSpecV1 {
        tool: "repo_audit".into(),
        args: serde_json::json!({"scope_digest": scope_digest.hex()}),
        frozen_clock: None,
    };
    let run_spec = RunSpecV1 {
        name: "recursive-agent-repo-audit".into(),
        steps: vec![StepSpecV1 {
            name: "repo_audit".into(),
            call,
        }],
        frozen_clock: None,
        policy_version: "m0-2".into(),
    };
    Ok(OperationEnvelopeV1 {
        schema: OperationSchemaV1::V1,
        actor: ActorAuthorityV1 {
            principal: "actor:hermes-native".into(),
            origin: AuthorityOriginV1::Direct,
        },
        causality: CausalLinkV1 {
            parent_operation_id: None,
            root_operation_id: None,
        },
        budget: OperationBudgetV1 {
            max_wall_time_ms: 3_000,
            max_output_bytes: 32_768,
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
            source: "urn:recursive-agent:repo-audit".into(),
            digest: ContentDigest::compute(b"recursive-agent-repo-audit-v9"),
        }],
        replay: ReplaySpecV1 {
            class: ReplayClassV1::Deterministic,
            intent: ReplayIntentV1::ExecuteOnce,
        },
        run_spec,
    })
}
