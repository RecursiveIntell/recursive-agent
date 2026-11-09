//! Executable recursive-agent daemon.
//!
//! Spawns the authenticated native IPC server wired to the canonical
//! `RuntimeService`. Used by the Hermes integration E2E and operators who want
//! a real (not in-process) daemon. This binary only wires admitted runtime
//! dependencies; it owns no execution or authority beyond `RuntimeService`.
//!
//!   ra-daemon serve --root <runs> --socket <path> [--max-concurrent N]

use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
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
use recursive_agent_policy::ProductionApprovalVerifierV1;
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
        #[arg(long, default_value = recursive_agent_daemon::DEFAULT_SOCKET_PATH)]
        socket: PathBuf,
        /// Optional canonical source root admitted to the deterministic
        /// `repo_audit` tool. No source path is accepted from an operation.
        #[arg(long)]
        audit_root: Option<PathBuf>,
        /// Max concurrent connections.
        #[arg(long, default_value_t = 4)]
        max_concurrent: usize,
        /// Owned mode-0600 JSON array of one or two exact bounded V1 shell operations.
        /// Use a dedicated socket/root; incompatible with other effect enrollments.
        #[arg(long)]
        closed_commands_file: Option<PathBuf>,
        /// Strictly owned JSON enrollment record containing the Electron public
        /// verifier key. When omitted, production permit issuance stays disabled.
        #[arg(long)]
        production_verifier_file: Option<PathBuf>,
        /// Exact existing root that a production witness may write beneath.
        /// Required whenever a production verifier enrollment is configured.
        #[arg(long)]
        production_write_root: Option<PathBuf>,
        /// Operator-owned scope/controller enrollment. Scope grants cannot be
        /// supplied through IPC. The native authority must be initialized first.
        #[arg(long)]
        context_authority_file: Option<PathBuf>,
    },
    /// Permanently fence a native external namespace and print its enrollment
    /// challenge. Does not enroll a controller or authorize any effect.
    InitializeContextAuthority {
        #[arg(long)]
        root: PathBuf,
    },
    /// Print the canonical public verifier digest used by scope enrollment.
    DescribeProductionVerifier {
        #[arg(long)]
        production_verifier_file: PathBuf,
        #[arg(long)]
        production_write_root: PathBuf,
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

/// Expand a leading `~/` using `$HOME`; any other path is returned unchanged.
pub fn expand_home(path: &std::path::Path) -> PathBuf {
    match path.strip_prefix("~") {
        Ok(rest) => match std::env::var_os("HOME") {
            Some(home) => PathBuf::from(home).join(rest),
            None => path.to_path_buf(),
        },
        Err(_) => path.to_path_buf(),
    }
}

const PRODUCTION_VERIFIER_ENROLLMENT_SCHEMA: &str =
    "recursive-agent.desktop-production-public-key/v1";
const MAX_PRODUCTION_VERIFIER_ENROLLMENT_BYTES: u64 = 8 * 1024;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductionVerifierEnrollmentV1 {
    schema: String,
    key_id: String,
    /// Standard Base64 encoding of the exact 32-byte Ed25519 verifying key.
    public_key: String,
}

/// Load verifier material from an operator-owned, mode-restricted enrollment
/// record. This binary never accepts a verifier key from IPC, environment, or a
/// tool request; startup configuration is the sole live admission boundary.
fn load_production_verifier(
    enrollment_path: &std::path::Path,
    target_root: &std::path::Path,
) -> Result<ProductionApprovalVerifierV1, Box<dyn std::error::Error>> {
    // Audit L2: open without following symlinks, validate the same descriptor
    // with fstat, and read only from that descriptor. Separating a path-based
    // check from a path-based read would let the path be swapped in between.
    // Same owner and mode rule as before (no group/other bits), 8 KiB bound, no link rule.
    let bytes = load_bounded_enrollment(
        enrollment_path,
        EnrollmentPolicy {
            max_bytes: MAX_PRODUCTION_VERIFIER_ENROLLMENT_BYTES,
            exact_0600: false,
            single_link: false,
        },
    )?;
    let record: ProductionVerifierEnrollmentV1 = serde_json::from_slice(&bytes)?;
    if record.schema != PRODUCTION_VERIFIER_ENROLLMENT_SCHEMA {
        return Err("unsupported production verifier enrollment schema".into());
    }
    let decoded = base64::engine::general_purpose::STANDARD.decode(record.public_key)?;
    let public_key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| "production verifier enrollment public key must be exactly 32 bytes")?;
    let target_root = target_root
        .canonicalize()?
        .to_str()
        .ok_or("production verifier target root must be UTF-8")?
        .to_string();
    Ok(
        ProductionApprovalVerifierV1::from_public_key_bytes_for_target_root(
            record.key_id,
            public_key,
            target_root,
        )?,
    )
}

/// Policy for one operator-owned enrollment file. Each consumer keeps its exact rule;
/// the shared loader only centralizes the descriptor-pinned open, validate, and bounded read
/// (audit L2 / Task 6.1), so the path cannot be swapped between a check and a read.
#[derive(Clone, Copy)]
struct EnrollmentPolicy {
    max_bytes: u64,
    /// Accept only exact 0600 (true) or any mode with no group/other bits (false).
    exact_0600: bool,
    /// Require a single hard link (true) or allow any link count (false).
    single_link: bool,
}

/// Open `path` without following symlinks, validate the same descriptor, and read it bounded.
fn load_bounded_enrollment(
    path: &std::path::Path,
    policy: EnrollmentPolicy,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )?;
    let file = fs::File::from(fd);
    let metadata = file.metadata()?;
    let mode_ok = if policy.exact_0600 {
        metadata.mode() & 0o777 == 0o600
    } else {
        metadata.mode() & 0o077 == 0
    };
    let link_ok = !policy.single_link || metadata.nlink() == 1;
    if !metadata.is_file() || metadata.len() > policy.max_bytes {
        return Err("enrollment must be a bounded regular file".into());
    }
    if metadata.uid() != rustix::process::getuid().as_raw() || !mode_ok {
        // Operator-actionable: name the exact mode the policy requires.
        let required = if policy.exact_0600 {
            "owned by the daemon user and mode 0600"
        } else {
            "owned by the daemon user and mode 0600 (no group or other bits)"
        };
        return Err(format!("enrollment must be {required}").into());
    }
    if !link_ok {
        return Err("enrollment must be a single-link file".into());
    }
    let mut bytes = Vec::new();
    file.take(policy.max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > policy.max_bytes {
        return Err("enrollment file exceeds its bound".into());
    }
    Ok(bytes)
}

fn load_context_authority(
    path: &std::path::Path,
) -> Result<recursive_agent_policy::ContextAuthorityConfigurationV1, Box<dyn std::error::Error>> {
    let bytes = load_bounded_enrollment(
        path,
        EnrollmentPolicy { max_bytes: 1024 * 1024, exact_0600: false, single_link: false },
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn load_closed_commands(
    path: &std::path::Path,
) -> Result<Vec<OperationEnvelopeV1>, Box<dyn std::error::Error>> {
    let bytes = load_bounded_enrollment(
        path,
        EnrollmentPolicy { max_bytes: 128 * 1024, exact_0600: true, single_link: true },
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Runner-owned shell surface: effects only through the prepared sandbox
/// dispatch inside RuntimeService, never a direct subprocess here.
struct ShellDescriptorOwner {
    descriptor: ToolDescriptor,
}
impl ShellDescriptorOwner {
    fn new() -> Self {
        Self {
            descriptor: ToolDescriptor {
                name: "shell".into(),
                version: "1.0.0".into(),
                description: Some("bounded shell effect (runner-owned dispatch)".into()),
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

fn build_runtime(
    root: &std::path::Path,
    audit_root: Option<PathBuf>,
    production_verifier: Option<ProductionApprovalVerifierV1>,
    closed_commands: Option<Vec<OperationEnvelopeV1>>,
) -> Result<RuntimeService, Box<dyn std::error::Error>> {
    let mut registry = ToolRegistry::new();
    registry.register(EchoDescriptorOwner::new());
    if closed_commands.is_some() {
        registry.register(ShellDescriptorOwner::new());
    }
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
    let mut runtime = RuntimeService::new(dependencies);
    if let Some(operations) = closed_commands {
        runtime = runtime.with_closed_commands(operations)?;
    }
    Ok(match production_verifier {
        Some(verifier) => runtime.with_production_approval_verifier(verifier),
        None => runtime,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Serve {
            root,
            socket,
            audit_root,
            max_concurrent,
            closed_commands_file,
            production_verifier_file,
            production_write_root,
            context_authority_file,
        } => {
            if closed_commands_file.is_some()
                && (audit_root.is_some()
                    || production_verifier_file.is_some()
                    || production_write_root.is_some()
                    || context_authority_file.is_some()
                    || max_concurrent != 1)
            {
                return Err(
                    "closed commands require one connection and no other effect enrollment".into(),
                );
            }
            let closed_commands = closed_commands_file
                .as_deref()
                .map(load_closed_commands)
                .transpose()?;
            fs::create_dir_all(&root)?;
            let production_verifier = match (production_verifier_file.as_deref(), production_write_root.as_deref()) {
                (None, None) => None,
                (Some(enrollment), Some(target_root)) => {
                    Some(load_production_verifier(enrollment, target_root)?)
                }
                _ => return Err(
                    "production verifier file and production write root must be configured together".into(),
                ),
            };
            let mut runtime =
                build_runtime(&root, audit_root, production_verifier, closed_commands)?;
            if let Some(path) = context_authority_file {
                runtime = runtime.with_context_authority(&load_context_authority(&path)?)?;
            }
            // The socket parent is the directory containing the socket path.
            // Expand the documented `~/` default here; a literal `~` would
            // otherwise become a real directory name.
            let socket = expand_home(&socket);
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
        Cmd::InitializeContextAuthority { root } => {
            fs::create_dir_all(&root)?;
            let store =
                recursive_agent_policy::DurablePermitStore::from_dir_fd(&fs::File::open(root)?)?;
            println!("{}", store.initialize_context_authority()?);
            Ok(())
        }
        Cmd::DescribeProductionVerifier {
            production_verifier_file,
            production_write_root,
        } => {
            let verifier =
                load_production_verifier(&production_verifier_file, &production_write_root)?;
            println!("{}", verifier.context_authority_digest()?);
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
