use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use llm_tool_runtime::{
    McpSurfaceKind, Tool, ToolApprovalKind, ToolBackendKind, ToolCtx, ToolDescriptor, ToolError,
    ToolErrorClass, ToolExposureMode, ToolExposurePolicy, ToolIdempotencyClass, ToolOutputMode,
    ToolReceiptPersistence, ToolRegistry, ToolResult, ToolRuntime, ToolSideEffectClass,
};
use recursive_agent_contracts::parse_run_spec_file;
use recursive_agent_ledger::{
    export_run_pack, verify_directory_bound, verify_run_pack, RunPaths, RunRootIdentity,
};
use recursive_agent_runner::{
    operation_from_run_spec, replay, replay_run_pack, Clock, RunSummary, RuntimeDependencies,
    RuntimeLedgerDependencyV1, RuntimePolicyDependencyV1, RuntimeProviderDependencyV1,
    RuntimeSandboxDependencyV1, RuntimeService, RuntimeStoreDependencyV1,
};

#[derive(Parser, Debug)]
#[command(
    name = "ra",
    version,
    about = "recursive-agent M0 — provenance-native agent CLI"
)]
struct Cli {
    #[arg(long, global = true, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print runtime and capability info. No effects, no provider.
    Doctor,
    /// Run a spec and persist a receipt chain to disk.
    Run {
        /// Path to the run spec JSON file.
        #[arg(long)]
        spec: PathBuf,
        /// Directory to write the run into. Defaults to
        /// $RECURSIVE_AGENT_RUNS or ~/.local/share/recursive-agent/runs.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Execution adapter: embedded (in-process RuntimeService, default) or
        /// ipc (connect to a ra-daemon socket). No silent fallback between modes.
        #[arg(long, value_enum, default_value_t = RuntimeMode::Embedded)]
        runtime: RuntimeMode,
    },
    /// Verify a run directory's receipt chain offline.
    Verify {
        /// Path to the run directory.
        #[arg(long)]
        run: PathBuf,
    },
    /// Replay a run from disk. Reads receipts and artifacts, never
    /// re-executes tools, never calls any provider.
    Replay {
        #[arg(long)]
        run: PathBuf,
    },
    /// Export, verify, or replay a portable Run Pack using ledger/runner owners.
    Pack {
        #[command(subcommand)]
        cmd: PackCmd,
    },
}

#[derive(Subcommand, Debug)]
enum PackCmd {
    /// Export one already-verified terminal run as an immutable Run Pack.
    Export {
        #[arg(long)]
        run: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Strictly verify a portable Run Pack from its own bytes.
    Verify {
        #[arg(long)]
        pack: PathBuf,
    },
    /// Replay only recorded evidence from a strictly verified Run Pack.
    Replay {
        #[arg(long)]
        pack: PathBuf,
    },
}

/// Explicit execution adapter selection (Phase 6, Task 6.1). No silent
/// fallback: each mode is explicit and must translate CLI input to V1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum RuntimeMode {
    Embedded,
    Ipc,
}

fn default_runs_root() -> PathBuf {
    if let Ok(p) = std::env::var("RECURSIVE_AGENT_RUNS") {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("recursive-agent")
        .join("runs")
}

/// Deterministic clock adapter (embedded mode).
#[derive(Clone, Copy)]
struct SystemClockAdapter;
impl Clock for SystemClockAdapter {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
    fn monotonic_now(&self) -> std::time::Duration {
        std::time::Duration::ZERO
    }
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

/// Deterministic echo tool (pure, read-only) required by CLI fixtures.
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

/// Frozen-time tool descriptor. The runner validates and executes it only
/// against the operation's supplied frozen clock; this owner only admits the
/// tool to the embedded runtime registry.
struct TimeNowDescriptorOwner {
    descriptor: ToolDescriptor,
}
impl TimeNowDescriptorOwner {
    fn new() -> Self {
        Self {
            descriptor: ToolDescriptor {
                name: "time_now".into(),
                version: "1.0.0".into(),
                description: Some("frozen-clock time projection".into()),
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
impl Tool for TimeNowDescriptorOwner {
    fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }
    async fn invoke(
        &self,
        _ctx: &ToolCtx,
        call: &llm_tool_runtime::ToolCall,
    ) -> Result<ToolResult, ToolError> {
        let timestamp = call
            .arguments
            .get("frozen_clock")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ToolError::new(
                    ToolErrorClass::Denied,
                    "time_now requires runner-injected frozen-clock evidence",
                )
            })?;
        let label = call
            .arguments
            .get("label")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ToolError::new(ToolErrorClass::Denied, "time_now requires label"))?;
        Ok(ToolResult::json(serde_json::json!({
            "timestamp": timestamp,
            "label": label,
        })))
    }
}

fn embedded_service(output_root: &Path) -> Result<RuntimeService, Box<dyn std::error::Error>> {
    let mut registry = ToolRegistry::new();
    registry.register(ShellDescriptorOwner::new());
    registry.register(EchoDescriptorOwner::new());
    registry.register(TimeNowDescriptorOwner::new());
    let dependencies = RuntimeDependencies::builder()
        .policy(RuntimePolicyDependencyV1::Native)
        .sandbox(RuntimeSandboxDependencyV1::Native)
        .tool_runtime(Arc::new(ToolRuntime::new(registry)))
        .provider(RuntimeProviderDependencyV1::Disabled)
        .ledger(RuntimeLedgerDependencyV1::Native)
        .clock(Arc::new(SystemClockAdapter))
        .store(RuntimeStoreDependencyV1::Native)
        .output_root(output_root)
        .build()?;
    Ok(RuntimeService::new(dependencies))
}

#[allow(deprecated)]
fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Doctor => doctor(),
        Cmd::Run { spec, out, runtime } => {
            let parsed = match parse_run_spec_file(&spec) {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("error: run spec rejected: {error}");
                    std::process::exit(2);
                }
            };
            let out_root = out.unwrap_or_else(default_runs_root);
            match runtime {
                RuntimeMode::Embedded => run_embedded(&parsed, &out_root),
                RuntimeMode::Ipc => {
                    eprintln!("error: --runtime ipc requires a ra-daemon socket and is wired in a later Phase 6 task; use embedded");
                    std::process::exit(2);
                }
            }
        }
        Cmd::Verify { run } => verify_cmd(&run),
        Cmd::Replay { run } => replay_cmd(&run),
        Cmd::Pack { cmd } => match cmd {
            PackCmd::Export { run, out } => pack_export_cmd(&run, &out),
            PackCmd::Verify { pack } => pack_verify_cmd(&pack),
            PackCmd::Replay { pack } => pack_replay_cmd(&pack),
        },
    }
}

/// Execute through the canonical in-process RuntimeService (no private
/// execution surface). Translates the parsed spec to a V1 operation and
/// submits, then renders the runtime status.
#[allow(deprecated)]
fn run_embedded(parsed: &recursive_agent_contracts::RunSpecV1, out_root: &Path) -> ! {
    let service = match embedded_service(out_root) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: embedded runtime construction failed: {e}");
            std::process::exit(2);
        }
    };
    let operation = match operation_from_run_spec(parsed) {
        Ok(op) => op,
        Err(e) => {
            eprintln!("error: run spec to V1 translation failed: {e}");
            std::process::exit(2);
        }
    };
    match service.submit(&operation) {
        Ok(handle) => {
            let run_dir = handle.run_dir();
            let summary = match service.status(handle.run_id()) {
                Ok(status) => {
                    let verification = match service.verify(handle.run_id()) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("error: verification failed: {e}");
                            std::process::exit(1);
                        }
                    };
                    let identity = run_root_identity(run_dir);
                    RunSummary {
                        run_id: handle.run_id().clone(),
                        run_dir: run_dir.to_path_buf(),
                        chain_length: verification.length,
                        chain_head: verification.final_head.clone(),
                        terminal_state: match status {
                            recursive_agent_runner::RuntimeStatusV1::Terminal { state } => state,
                            recursive_agent_runner::RuntimeStatusV1::Active => {
                                eprintln!("error: run did not reach terminal state");
                                std::process::exit(1);
                            }
                        },
                        run_root_identity: identity,
                    }
                }
                Err(e) => {
                    eprintln!("error: run status unavailable: {e}");
                    std::process::exit(1);
                }
            };
            let ok_summary = summary.terminal_state.permits_successful_finalization();
            match serde_json::to_string(&summary) {
                Ok(json) => println!("{json}"),
                Err(error) => {
                    eprintln!("error: run summary serialization failed: {error}");
                    std::process::exit(2);
                }
            }
            std::process::exit(if ok_summary { 0 } else { 1 });
        }
        Err(e) => {
            eprintln!("error: run failed: {e}");
            std::process::exit(1);
        }
    }
}

/// Resolve the pinned run-root identity (device/inode) from a committed run dir.
fn run_root_identity(run_dir: &Path) -> RunRootIdentity {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(run_dir) {
        Ok(meta) => RunRootIdentity {
            device: meta.dev(),
            inode: meta.ino(),
        },
        Err(_) => RunRootIdentity {
            device: 0,
            inode: 0,
        },
    }
}

fn doctor() {
    print!("{}", doctor_report());
}

fn doctor_report() -> &'static str {
    concat!(
        "recursive-agent Phase 1 candidate (admission rejected pending hostile review)\n",
        "mode: provider-free receipt-bearing execution\n",
        "boundary: boundary-compiler 0.1.0 + stack-ids 0.1.3\n",
        "available pure tools: echo, time_now (frozen clock required)\n",
        "available bounded effect: shell (runner-private one-shot dispatch, Bubblewrap + seccomp network EPERM)\n",
        "typed unavailable: llm/provider networking, mcp_call/client spawn, memory runtime, skills, delegate\n",
        "ledger: offline blake3 chain + strict artifact verification + bound replay snapshot\n",
        "policy: m0-2; Phase 1 network is always denied\n",
    )
}

fn verify_cmd(run_dir: &Path) {
    let paths = recursive_agent_ledger::RunPaths::new(run_dir);
    match verify_directory_bound(&paths) {
        Ok(v) => {
            if v.ok {
                println!("verify: ok");
                println!("length: {}", v.length);
                println!("final_head: {}", v.final_head);
                std::process::exit(0);
            } else {
                let Some(d) = v.first_divergence else {
                    eprintln!("verify: internal error: ok=false with no first divergence");
                    std::process::exit(1);
                };
                eprintln!(
                    "verify: FAIL at receipt index {} ({}): expected_head={} observed_head={}",
                    d.index, d.reason, d.expected_head, d.observed_head
                );
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("verify: ERROR: {e}");
            std::process::exit(2);
        }
    }
}

fn replay_cmd(run_dir: &Path) {
    let paths = recursive_agent_ledger::RunPaths::new(run_dir);
    match replay(&paths) {
        Ok(s) => {
            println!("replay: {}", if s.ok { "ok" } else { "FAIL" });
            println!("length: {}", s.length);
            println!("final_head: {}", s.final_head);
            println!("steps: {}", s.step_results.len());
            for st in &s.step_results {
                println!(
                    "  step {} kind={} outcome={} artifacts={}",
                    st.step_id,
                    st.kind,
                    st.outcome,
                    st.artifact_refs.len()
                );
            }
            println!("artifacts: {}", s.artifacts.len());
            for a in &s.artifacts {
                println!("  {a}");
            }
            std::process::exit(if s.ok { 0 } else { 1 });
        }
        Err(e) => {
            eprintln!("replay: ERROR: {e}");
            std::process::exit(2);
        }
    }
}

fn pack_export_cmd(run_dir: &Path, out: &Path) {
    match export_run_pack(&RunPaths::new(run_dir), out) {
        Ok(verification) => print_json_or_exit(
            "pack export",
            &serde_json::json!({
                "schema_version": verification.schema_version,
                "pack_path": out,
                "manifest_digest": verification.manifest_digest,
                "manifest_ref": "PACK_MANIFEST.json",
            }),
        ),
        Err(error) => pack_error_exit("export", error),
    }
}

fn pack_verify_cmd(pack: &Path) {
    match verify_run_pack(pack) {
        Ok(verification) => print_json_or_exit("pack verify", &verification),
        Err(error) => pack_error_exit("verify", error),
    }
}

fn pack_replay_cmd(pack: &Path) {
    match replay_run_pack(pack) {
        Ok(result) => print_json_or_exit("pack replay", &result),
        Err(error) => pack_error_exit("replay", error),
    }
}

fn print_json_or_exit(label: &str, value: &impl serde::Serialize) -> ! {
    match serde_json::to_string(value) {
        Ok(json) => {
            println!("{json}");
            std::process::exit(0);
        }
        Err(error) => {
            eprintln!("{label}: ERROR: serialization failed: {error}");
            std::process::exit(2);
        }
    }
}

fn pack_error_exit(label: &str, error: impl std::fmt::Display) -> ! {
    eprintln!("pack {label}: ERROR: {error}");
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::doctor_report;

    #[test]
    fn doctor_reports_exact_phase_one_candidate_surface() {
        let report = doctor_report();
        assert!(report.contains("Phase 1 candidate"));
        assert!(report.contains("admission rejected"));
        assert!(report.contains("Bubblewrap + seccomp network EPERM"));
        assert!(report.contains("runner-private one-shot dispatch"));
        assert!(!report.contains("sealed permit context"));
        assert!(report.contains("available pure tools: echo, time_now"));
        assert!(report.contains("typed unavailable: llm/provider networking"));
        assert!(!report.contains("Phase 3"));
        assert!(!report.contains("Landlock"));
    }
}
