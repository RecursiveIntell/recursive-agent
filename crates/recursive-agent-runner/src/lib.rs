//! Receipt-bearing, fail-fast runner for recorded-evidence execution.

mod deps;
mod error;
mod runtime;
mod sandbox_engine;
mod scheduler;

pub use deps::{
    RuntimeDependencies, RuntimeDependenciesBuilder, RuntimeLedgerDependencyV1,
    RuntimePolicyDependencyV1, RuntimeProviderDependencyV1, RuntimeSandboxDependencyV1,
    RuntimeStoreDependencyV1,
};
pub use error::RuntimeDependencyError;
pub use runtime::{
    RuntimeCancelResultV1, RuntimeHandleV1, RuntimeService, RuntimeServiceError, RuntimeStatusV1,
};
pub use scheduler::{OperationRow, ProjectedState, SchedulerStore, SchedulerStoreError};

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use chrono::{DateTime, TimeDelta, Utc};
use recursive_agent_contracts::{
    content_digest, derive_permit_id, derive_step_id, ActorAuthorityV1, AuthorityOriginV1,
    CausalLinkV1, ContractError, CurrentPermitId, CurrentRunId, CurrentStepId, DeclaredEffectsV1,
    OperationBudgetV1, OperationEnvelopeV1, OperationSchemaV1, ProvenanceRefV1, ReceiptKindV1,
    ReceiptOutcomeV1, ReplayClassV1, ReplayIntentV1, ReplaySpecV1, RunSpecV1, RunTerminalStateV1,
    StepSpecV1, ToolCallSpecV1, MAX_SHELL_OUTPUT_BYTES, MAX_SHELL_TIMEOUT_MS,
};
use recursive_agent_ledger::{
    make_receipt, open_from_dir_fd, put_string, ArtifactStore, ChainHandle, LedgerError,
    ReceiptDraftV1, RunPaths, RunRootIdentity,
};
use recursive_agent_policy::{
    build_lineage, ActorPrincipalV1, Allowlist, DelegatedActionV1, DelegationCeilingV1,
    DelegationTransitionV1, DurablePermitStore, EffectScopeV1, PermitBindingV1, PermitBudgetV1,
    PermitEvidenceV1, PermitRejectionReasonV1, PermitRevocationReasonV1, PolicyError,
};
use thiserror::Error;

#[cfg(test)]
use recursive_agent_contracts::derive_run_id;

pub(crate) struct RunnerToolOutput {
    pub(crate) body: serde_json::Value,
    pub(crate) source_evidence: Vec<serde_json::Value>,
}

pub(crate) trait RunnerToolExecutor: Sync {
    fn execute(
        &self,
        call: &ToolCallSpecV1,
        evidence: PermitEvidenceV1,
    ) -> Result<RunnerToolOutput, recursive_agent_tools::ToolError>;
}

#[cfg(test)]
struct TestToolExecutor;

#[cfg(test)]
impl RunnerToolExecutor for TestToolExecutor {
    fn execute(
        &self,
        call: &ToolCallSpecV1,
        _evidence: PermitEvidenceV1,
    ) -> Result<RunnerToolOutput, recursive_agent_tools::ToolError> {
        Err(recursive_agent_tools::ToolError::Unavailable(format!(
            "test-only runner executor does not dispatch {}",
            call.tool
        )))
    }
}

macro_rules! append_receipt {
    (
        $chain:expr,
        $run_id:expr,
        $step_id:expr,
        $kind:expr,
        $valid_time:expr,
        $lineage:expr,
        $spec_digest:expr,
        $args_digest:expr,
        $artifact_refs:expr,
        $outcome:expr $(,)?
    ) => {
        append_receipt_draft(
            $chain,
            ReceiptDraftV1 {
                run_id: $run_id,
                step_id: $step_id,
                kind: $kind,
                valid_time: $valid_time,
                lineage: $lineage,
                spec_digest: $spec_digest,
                args_digest: $args_digest,
                artifact_refs: $artifact_refs,
                outcome: $outcome,
            },
        )
    };
}

#[derive(Debug, Error)]
pub enum RunError {
    #[error("policy: {0}")]
    Policy(#[from] PolicyError),
    #[error("ledger: {0}")]
    Ledger(#[from] LedgerError),
    #[error("tool: {0}")]
    Tool(#[from] recursive_agent_tools::ToolError),
    #[error("contract: {0}")]
    Contract(#[from] ContractError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("lifecycle: {0}")]
    Lifecycle(#[from] LifecycleError),
    #[error("run-root locator no longer resolves to the pinned inode")]
    RunRootLocatorMismatch,
    #[error("ledger, artifact, and permit stores do not share one pinned run root")]
    SplitRunRoot,
    #[error("shell executable authority preparation failed: {0}")]
    ExecutablePreparation(String),
    #[error("resume rejected: parent step boundary is not verified ({reason})")]
    ResumeFromUnverifiedBoundary {
        /// Why the parent boundary could not be trusted.
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LifecycleError {
    #[error("terminal transition rejected: current={current:?}, attempted={attempted:?}")]
    AlreadyTerminal {
        current: RunTerminalStateV1,
        attempted: RunTerminalStateV1,
    },
    #[error("run has no terminal state")]
    MissingTerminal,
}

#[derive(Debug, Clone, Default)]
pub struct RunLifecycle {
    terminal: Option<RunTerminalStateV1>,
}

impl RunLifecycle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn transition_terminal(
        &mut self,
        attempted: RunTerminalStateV1,
    ) -> Result<(), LifecycleError> {
        if let Some(current) = self.terminal {
            return Err(LifecycleError::AlreadyTerminal { current, attempted });
        }
        self.terminal = Some(attempted);
        Ok(())
    }

    pub fn terminal(&self) -> Result<RunTerminalStateV1, LifecycleError> {
        self.terminal.ok_or(LifecycleError::MissingTerminal)
    }
}

pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;

    fn monotonic_now(&self) -> std::time::Duration {
        static ORIGIN: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        ORIGIN.get_or_init(std::time::Instant::now).elapsed()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Debug, Clone, Copy)]
enum RunHookPoint {
    PinnedRootOpen,
    ChildConsumeBeforeDispatch,
    DispatchBeforeFinalReadback,
}

trait RunnerHook {
    fn fire(&self, _point: RunHookPoint, _root: &PinnedRunRoot) -> Result<(), RunError> {
        Ok(())
    }
}

struct NoopRunnerHook;

impl RunnerHook for NoopRunnerHook {}

#[derive(Debug)]
struct PinnedRunRoot {
    locator: PathBuf,
    root: File,
    identity: RunRootIdentity,
}

impl PinnedRunRoot {
    fn open(out_root: &Path, child_name: &str) -> Result<Self, RunError> {
        let parent = open_directory_tree(out_root, true)?;
        let root = open_named_directory(&parent, std::ffi::OsStr::new(child_name), true)?;
        let parent_metadata = parent.metadata()?;
        let metadata = root.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != parent_metadata.uid()
            || metadata.mode() & 0o022 != 0
        {
            return Err(RunError::SplitRunRoot);
        }
        Ok(Self {
            locator: out_root.join(child_name),
            identity: RunRootIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            root,
        })
    }

    fn ensure_locator_matches(&self) -> Result<(), RunError> {
        let reopened = open_directory_tree(&self.locator, false)
            .map_err(|_| RunError::RunRootLocatorMismatch)?;
        let metadata = reopened.metadata()?;
        if metadata.dev() != self.identity.device || metadata.ino() != self.identity.inode {
            return Err(RunError::RunRootLocatorMismatch);
        }
        Ok(())
    }
}

fn open_directory_tree(path: &Path, create: bool) -> Result<File, RunError> {
    if path.as_os_str().is_empty() || path == Path::new("/") {
        return Err(RunError::SplitRunRoot);
    }
    let start = if path.is_absolute() { "/" } else { "." };
    let start_fd = rustix::fs::open(
        start,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let mut directory = File::from(start_fd);
    for component in path.components() {
        let name = match component {
            std::path::Component::RootDir | std::path::Component::CurDir => continue,
            std::path::Component::Normal(name) => name,
            std::path::Component::ParentDir | std::path::Component::Prefix(_) => {
                return Err(RunError::SplitRunRoot);
            }
        };
        directory = open_named_directory(&directory, name, create)?;
    }
    Ok(directory)
}

fn open_named_directory(
    parent: &File,
    name: &std::ffi::OsStr,
    create: bool,
) -> Result<File, RunError> {
    let name = name.to_str().ok_or(RunError::SplitRunRoot)?;
    let flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC;
    match secure_open_directory_at(parent, name, flags) {
        Ok(fd) => Ok(File::from(fd)),
        Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
            match rustix::fs::mkdirat(
                parent.as_fd(),
                name,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR,
            ) {
                Ok(()) => {}
                Err(error)
                    if std::io::Error::from(error).kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
            Ok(File::from(secure_open_directory_at(parent, name, flags)?))
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "linux")]
fn secure_open_directory_at(
    parent: &File,
    name: &str,
    flags: rustix::fs::OFlags,
) -> std::io::Result<std::os::fd::OwnedFd> {
    Ok(rustix::fs::openat2(
        parent.as_fd(),
        name,
        flags,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::BENEATH
            | rustix::fs::ResolveFlags::NO_SYMLINKS
            | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )?)
}

#[cfg(not(target_os = "linux"))]
fn secure_open_directory_at(
    parent: &File,
    name: &str,
    flags: rustix::fs::OFlags,
) -> std::io::Result<std::os::fd::OwnedFd> {
    if name.contains('/') || name == "." || name == ".." {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "run-root component is not a single name",
        ));
    }
    Ok(rustix::fs::openat(
        parent.as_fd(),
        name,
        flags | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )?)
}

fn legacy_operation_envelope(spec: &RunSpecV1) -> Result<OperationEnvelopeV1, RunError> {
    let mut read_roots = std::collections::BTreeSet::new();
    let mut write_roots = std::collections::BTreeSet::new();
    let mut network_allowed = false;
    let mut has_shell = false;
    for step in &spec.steps {
        if step.call.tool != "shell" {
            continue;
        }
        has_shell = true;
        read_roots.extend(string_array(&step.call.args, "allowed_read_paths")?);
        write_roots.extend(string_array(&step.call.args, "allowed_write_paths")?);
        network_allowed |= optional_bool(&step.call.args, "allow_network")?.unwrap_or(false);
    }
    let spec_digest = content_digest(spec)?;
    let max_steps = u32::try_from(spec.steps.len()).map_err(|_| {
        ContractError::Malformed("legacy run-spec step count does not fit operation budget".into())
    })?;
    let operation = OperationEnvelopeV1 {
        schema: OperationSchemaV1::V1,
        actor: ActorAuthorityV1 {
            principal: "legacy-run-spec-adapter".into(),
            origin: AuthorityOriginV1::Direct,
        },
        causality: CausalLinkV1 {
            parent_operation_id: None,
            root_operation_id: None,
        },
        budget: OperationBudgetV1 {
            max_wall_time_ms: MAX_SHELL_TIMEOUT_MS,
            max_output_bytes: MAX_SHELL_OUTPUT_BYTES,
            max_artifact_bytes: MAX_SHELL_OUTPUT_BYTES,
            max_steps,
        },
        effects: DeclaredEffectsV1 {
            read_roots: read_roots.into_iter().collect(),
            write_roots: write_roots.into_iter().collect(),
            network_allowed,
            action_digest: spec_digest.clone(),
        },
        provenance: vec![ProvenanceRefV1 {
            source: "urn:recursive-agent:legacy-run-spec-adapter".into(),
            digest: spec_digest,
        }],
        replay: ReplaySpecV1 {
            class: if has_shell {
                ReplayClassV1::RecordedEffect
            } else {
                ReplayClassV1::Deterministic
            },
            intent: ReplayIntentV1::ExecuteOnce,
        },
        run_spec: spec.clone(),
    };
    operation.validate()?;
    Ok(operation)
}

/// Public translation from a legacy `RunSpecV1` to a native V1 operation
/// envelope. Adapters (CLI, MCP, IPC) use this so they execute through the
/// canonical `RuntimeService::submit` rather than a private execution surface.
pub fn operation_from_run_spec(spec: &RunSpecV1) -> Result<OperationEnvelopeV1, RunError> {
    // Preserve the legacy ingress contract: policy rejects forbidden effects
    // before the adapter materializes a native operation envelope.
    Allowlist::default().validate_phase_one_boundary(spec)?;
    let operation = legacy_operation_envelope(spec)?;
    Ok(operation)
}

fn prepare_step_dispatches(
    spec: &RunSpecV1,
) -> Result<Vec<Option<sandbox_engine::PreparedDispatch>>, RunError> {
    spec.steps
        .iter()
        .map(|step| {
            if step.call.tool != "shell" {
                return Ok(None);
            }
            let sandbox: recursive_agent_sandbox::SandboxSpec =
                serde_json::from_value(step.call.args.clone())?;
            sandbox_engine::prepare_authority(&sandbox)
                .map(Some)
                .map_err(|error| RunError::ExecutablePreparation(error.to_string()))
        })
        .collect()
}

#[cfg(test)]
fn run_spec_internal(
    spec: &RunSpecV1,
    out_root: &Path,
    clock: &dyn Clock,
    hook: &dyn RunnerHook,
) -> Result<RunSummary, RunError> {
    let run_id = derive_run_id(spec)?;
    run_spec_internal_with_run_id(spec, out_root, clock, hook, run_id, &TestToolExecutor)
}

fn run_spec_internal_with_run_id(
    spec: &RunSpecV1,
    out_root: &Path,
    clock: &dyn Clock,
    hook: &dyn RunnerHook,
    run_id: CurrentRunId,
    tool_executor: &dyn RunnerToolExecutor,
) -> Result<RunSummary, RunError> {
    let allowlist = Allowlist::default();
    allowlist.validate_phase_one_boundary(spec)?;
    for step in &spec.steps {
        allowlist.authorize(spec, &step.name, &step.call)?;
    }
    let mut prepared_dispatches = prepare_step_dispatches(spec)?;
    let lifecycle_issue_time = clock.now();
    let (delegation_ceiling, lifecycle_binding) = lifecycle_authority(
        spec,
        &run_id,
        &allowlist.policy_version,
        lifecycle_issue_time,
        &prepared_dispatches,
    )?;
    let run_directory_key = content_digest(&run_id)?.to_string();
    let pinned_root = PinnedRunRoot::open(out_root, &run_directory_key)?;
    hook.fire(RunHookPoint::PinnedRootOpen, &pinned_root)?;
    pinned_root.ensure_locator_matches()?;
    let run_dir = pinned_root.locator.clone();
    let paths = RunPaths::new(run_dir.clone());

    let mut chain = open_from_dir_fd(&paths, &pinned_root.root)?;
    if chain.length() != 0 {
        return verified_summary(&pinned_root, run_id, run_dir);
    }

    let store = chain.artifact_store()?;
    let permit_store = DurablePermitStore::from_run_root_fd(&pinned_root.root)?;
    if chain.run_root_identity() != pinned_root.identity
        || store.run_root_identity() != pinned_root.identity
        || permit_store.run_root_identity()
            != (pinned_root.identity.device, pinned_root.identity.inode)
    {
        return Err(RunError::SplitRunRoot);
    }
    let spec_digest = content_digest(spec)?;
    let lifecycle_monotonic_start = clock.monotonic_now();
    let lifecycle_call = ToolCallSpecV1 {
        tool: "runner.lifecycle".into(),
        args: serde_json::json!({"run_spec_digest": spec_digest}),
        frozen_clock: None,
    };
    let lifecycle_step_id =
        derive_step_id(&run_id, spec.steps.len(), "run-lifecycle", &lifecycle_call)?;
    let lifecycle_call_digest = content_digest(&lifecycle_call)?;
    let lifecycle_args_digest = content_digest(&lifecycle_call.args)?;
    let mut lifecycle_binding = lifecycle_binding;
    lifecycle_binding.step_id = lifecycle_step_id.clone();
    lifecycle_binding.action_digest = lifecycle_call_digest.clone();
    lifecycle_binding.args_digest = lifecycle_args_digest.clone();
    let lifecycle_permit =
        permit_store.issue_control(&lifecycle_binding, delegation_ceiling, lifecycle_issue_time)?;
    let lifecycle_validity_ms = (lifecycle_binding.expires_at - lifecycle_binding.not_before)
        .num_milliseconds()
        .try_into()
        .map_err(|_| PolicyError::BudgetOverrun("invalid run authority validity".into()))?;
    let lifecycle_monotonic_deadline = lifecycle_monotonic_start
        .checked_add(std::time::Duration::from_millis(lifecycle_validity_ms))
        .ok_or_else(|| PolicyError::BudgetOverrun("run monotonic deadline overflow".into()))?;
    let lifecycle_lineage = build_lineage(&lifecycle_permit.permit_id, &allowlist.policy_version);
    append_receipt!(
        &mut chain,
        run_id.clone(),
        lifecycle_step_id.clone(),
        ReceiptKindV1::RunStarted,
        clock.now(),
        lifecycle_lineage.clone(),
        spec_digest.clone(),
        spec_digest.clone(),
        vec![],
        ReceiptOutcomeV1::Ok,
    )?;
    append_receipt!(
        &mut chain,
        run_id.clone(),
        lifecycle_step_id.clone(),
        ReceiptKindV1::StepStarted,
        clock.now(),
        lifecycle_lineage.clone(),
        spec_digest.clone(),
        spec_digest.clone(),
        vec![],
        ReceiptOutcomeV1::Ok,
    )?;
    let lifecycle_issue_evidence = put_string(
        &store,
        &serde_json::to_string(&PermitEvidenceV1::from_record(
            &permit_store.state(&lifecycle_permit.permit_id)?,
        )?)?,
    )?;
    append_receipt!(
        &mut chain,
        run_id.clone(),
        lifecycle_step_id.clone(),
        ReceiptKindV1::PermitIssued,
        lifecycle_issue_time,
        lifecycle_lineage.clone(),
        lifecycle_call_digest.clone(),
        lifecycle_args_digest.clone(),
        vec![lifecycle_issue_evidence],
        ReceiptOutcomeV1::Ok,
    )?;

    let mut lifecycle = RunLifecycle::new();
    let mut terminal_reason = "all steps completed".to_string();
    for (index, step) in spec.steps.iter().enumerate() {
        if let Some((state, reason)) = run_step(RunStepContext {
            chain: &mut chain,
            store: &store,
            permit_store: &permit_store,
            spec,
            run_id: &run_id,
            index,
            step,
            allowlist: &allowlist,
            parent_permit_id: &lifecycle_permit.permit_id,
            denial_lineage: &lifecycle_lineage,
            clock,
            parent_monotonic_start: lifecycle_monotonic_start,
            parent_monotonic_deadline: lifecycle_monotonic_deadline,
            parent_expires_at: lifecycle_binding.expires_at,
            prepared_dispatch: prepared_dispatches
                .get_mut(index)
                .ok_or_else(|| ContractError::Malformed("prepared step index missing".into()))?
                .take(),
            tool_executor,
            hook,
            pinned_root: &pinned_root,
        })? {
            lifecycle.transition_terminal(state)?;
            terminal_reason = reason;
            break;
        }
    }
    hook.fire(RunHookPoint::DispatchBeforeFinalReadback, &pinned_root)?;

    if lifecycle.terminal.is_none() {
        lifecycle.transition_terminal(RunTerminalStateV1::Succeeded)?;
    }
    let terminal = lifecycle.terminal()?;
    let revocation_reason = if terminal == RunTerminalStateV1::Succeeded {
        PermitRevocationReasonV1::Operator
    } else {
        PermitRevocationReasonV1::OperationCancelled
    };
    let revoke_time = clock.now();
    let revoked =
        permit_store.revoke(&lifecycle_permit.permit_id, revocation_reason, revoke_time)?;
    let revocation_evidence = put_string(
        &store,
        &serde_json::to_string(&PermitEvidenceV1::from_record(&revoked)?)?,
    )?;
    append_receipt!(
        &mut chain,
        run_id.clone(),
        lifecycle_step_id.clone(),
        ReceiptKindV1::PermitRevoked,
        revoke_time,
        lifecycle_lineage.clone(),
        lifecycle_call_digest,
        lifecycle_args_digest,
        vec![revocation_evidence],
        ReceiptOutcomeV1::Ok,
    )?;
    append_receipt!(
        &mut chain,
        run_id.clone(),
        lifecycle_step_id,
        ReceiptKindV1::RunFinalized,
        clock.now(),
        lifecycle_lineage,
        spec_digest.clone(),
        spec_digest,
        vec![],
        terminal.receipt_outcome(terminal_reason),
    )?;

    let summary = verified_summary(&pinned_root, run_id, run_dir)?;
    if summary.terminal_state != terminal {
        return Err(RunError::SplitRunRoot);
    }
    Ok(summary)
}

fn verified_summary(
    pinned_root: &PinnedRunRoot,
    run_id: CurrentRunId,
    run_dir: PathBuf,
) -> Result<RunSummary, RunError> {
    let snapshot = recursive_agent_ledger::verified_snapshot_expected_run_from_dir_fd(
        &pinned_root.root,
        &run_id,
    )?;
    pinned_root.ensure_locator_matches()?;
    let verification = snapshot.verification();
    Ok(RunSummary {
        run_id,
        run_dir,
        chain_length: verification.length,
        chain_head: verification.final_head.clone(),
        terminal_state: verification.terminal_state,
        run_root_identity: pinned_root.identity,
    })
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunSummary {
    pub run_id: CurrentRunId,
    pub run_dir: std::path::PathBuf,
    pub chain_length: u64,
    pub chain_head: String,
    pub terminal_state: RunTerminalStateV1,
    pub run_root_identity: RunRootIdentity,
}

struct RunStepContext<'a> {
    chain: &'a mut ChainHandle,
    store: &'a ArtifactStore,
    permit_store: &'a DurablePermitStore,
    spec: &'a RunSpecV1,
    run_id: &'a CurrentRunId,
    index: usize,
    step: &'a StepSpecV1,
    allowlist: &'a Allowlist,
    parent_permit_id: &'a CurrentPermitId,
    denial_lineage: &'a [recursive_agent_contracts::AuthorityLineageEntryV1],
    clock: &'a dyn Clock,
    parent_monotonic_start: std::time::Duration,
    parent_monotonic_deadline: std::time::Duration,
    parent_expires_at: DateTime<Utc>,
    prepared_dispatch: Option<sandbox_engine::PreparedDispatch>,
    tool_executor: &'a dyn RunnerToolExecutor,
    hook: &'a dyn RunnerHook,
    pinned_root: &'a PinnedRunRoot,
}

fn run_step(context: RunStepContext<'_>) -> Result<Option<(RunTerminalStateV1, String)>, RunError> {
    let RunStepContext {
        chain,
        store,
        permit_store,
        spec,
        run_id,
        index,
        step,
        allowlist,
        parent_permit_id,
        denial_lineage,
        clock,
        parent_monotonic_start,
        parent_monotonic_deadline,
        parent_expires_at,
        prepared_dispatch,
        tool_executor,
        hook,
        pinned_root,
    } = context;
    let step_id = derive_step_id(run_id, index, &step.name, &step.call)?;
    let call_digest = content_digest(&step.call)?;
    let args_digest = content_digest(&step.call.args)?;
    let parent_monotonic_now = clock.monotonic_now();
    if parent_monotonic_now < parent_monotonic_start
        || parent_monotonic_now >= parent_monotonic_deadline
    {
        let reason = "parent authorization monotonic lease expired or rolled back".to_string();
        let denial_evidence = put_string(
            store,
            &serde_json::to_string(&serde_json::json!({
                "kind": "parent_lease_denied",
                "reason": reason.clone(),
            }))?,
        )?;
        append_receipt!(
            chain,
            run_id.clone(),
            step_id.clone(),
            ReceiptKindV1::StepStarted,
            clock.now(),
            denial_lineage.to_vec(),
            call_digest.clone(),
            args_digest.clone(),
            vec![],
            ReceiptOutcomeV1::Ok,
        )?;
        append_receipt!(
            chain,
            run_id.clone(),
            step_id,
            ReceiptKindV1::StepFailed,
            clock.now(),
            denial_lineage.to_vec(),
            call_digest,
            args_digest,
            vec![denial_evidence],
            ReceiptOutcomeV1::Denied,
        )?;
        return Ok(Some((RunTerminalStateV1::Denied, reason)));
    }
    if let Err(error) = allowlist.authorize(spec, &step.name, &step.call) {
        let reason = error.to_string();
        let denial_evidence = put_string(
            store,
            &serde_json::to_string(&serde_json::json!({
                "kind": "policy_denied",
                "reason": reason,
            }))?,
        )?;
        append_receipt!(
            chain,
            run_id.clone(),
            step_id.clone(),
            ReceiptKindV1::StepStarted,
            clock.now(),
            denial_lineage.to_vec(),
            call_digest.clone(),
            args_digest.clone(),
            vec![],
            ReceiptOutcomeV1::Ok,
        )?;
        append_receipt!(
            chain,
            run_id.clone(),
            step_id,
            ReceiptKindV1::StepFailed,
            clock.now(),
            denial_lineage.to_vec(),
            call_digest,
            args_digest,
            vec![denial_evidence],
            ReceiptOutcomeV1::Denied,
        )?;
        return Ok(Some((RunTerminalStateV1::Denied, reason)));
    }

    let issue_time = clock.now();
    if issue_time >= parent_expires_at {
        let reason = "parent authorization expired before child permit issuance".to_string();
        let denial_evidence = put_string(
            store,
            &serde_json::to_string(&serde_json::json!({
                "kind": "parent_authority_expired",
                "reason": reason,
                "parent_permit_id": parent_permit_id,
                "observed_at": issue_time,
                "parent_expires_at": parent_expires_at,
            }))?,
        )?;
        append_receipt!(
            chain,
            run_id.clone(),
            step_id.clone(),
            ReceiptKindV1::StepStarted,
            issue_time,
            denial_lineage.to_vec(),
            call_digest.clone(),
            args_digest.clone(),
            vec![],
            ReceiptOutcomeV1::Ok,
        )?;
        append_receipt!(
            chain,
            run_id.clone(),
            step_id,
            ReceiptKindV1::StepFailed,
            issue_time,
            denial_lineage.to_vec(),
            call_digest,
            args_digest,
            vec![denial_evidence],
            ReceiptOutcomeV1::Denied,
        )?;
        return Ok(Some((RunTerminalStateV1::Denied, reason)));
    }
    let binding = permit_binding(
        run_id,
        &step_id,
        &step.call,
        &allowlist.policy_version,
        Some(parent_permit_id.clone()),
        issue_time,
        parent_expires_at,
    )?;
    append_receipt!(
        chain,
        run_id.clone(),
        step_id.clone(),
        ReceiptKindV1::StepStarted,
        clock.now(),
        denial_lineage.to_vec(),
        call_digest.clone(),
        args_digest.clone(),
        vec![],
        ReceiptOutcomeV1::Ok,
    )?;
    let executable_authority = prepared_dispatch.as_ref().map_or_else(
        Vec::new,
        sandbox_engine::PreparedDispatch::executable_authority,
    );
    let permit = match permit_store.issue_effect(&binding, executable_authority, issue_time) {
        Ok(permit) => permit,
        Err(error) => {
            let reason = error.to_string();
            let evidence = put_string(
                store,
                &serde_json::to_string(&serde_json::json!({
                    "kind": "permit_issue_denied",
                    "reason": reason.clone(),
                    "binding": binding,
                }))?,
            )?;
            append_receipt!(
                chain,
                run_id.clone(),
                step_id,
                ReceiptKindV1::StepFailed,
                clock.now(),
                denial_lineage.to_vec(),
                call_digest,
                args_digest,
                vec![evidence],
                ReceiptOutcomeV1::Denied,
            )?;
            return Ok(Some((RunTerminalStateV1::Denied, reason)));
        }
    };
    let permit_monotonic_start = clock.monotonic_now();
    let permit_monotonic_deadline = permit_monotonic_start
        .checked_add(std::time::Duration::from_millis(
            binding.budget.max_wall_time_ms,
        ))
        .ok_or_else(|| PolicyError::BudgetOverrun("permit monotonic deadline overflow".into()))?;
    let lineage = build_lineage(&permit.permit_id, &allowlist.policy_version);
    let issued_evidence = put_string(
        store,
        &serde_json::to_string(&PermitEvidenceV1::from_record(
            &permit_store.state(&permit.permit_id)?,
        )?)?,
    )?;
    append_receipt!(
        chain,
        run_id.clone(),
        step_id.clone(),
        ReceiptKindV1::PermitIssued,
        issue_time,
        lineage.clone(),
        call_digest.clone(),
        args_digest.clone(),
        vec![issued_evidence],
        ReceiptOutcomeV1::Ok,
    )?;

    let consume_monotonic = clock.monotonic_now();
    let consume_time = clock.now();
    let authorized_result = if consume_monotonic < permit_monotonic_start {
        Err(PolicyError::PermitRejected {
            permit_id: permit.permit_id.clone(),
            reason: PermitRejectionReasonV1::StateCorrupted,
        })
    } else if consume_monotonic >= permit_monotonic_deadline {
        Err(PolicyError::PermitRejected {
            permit_id: permit.permit_id.clone(),
            reason: PermitRejectionReasonV1::Expired,
        })
    } else {
        permit_store.consume(&permit.permit_id, &binding, consume_time)
    };
    let authorized = match authorized_result {
        Ok(evidence) => evidence,
        Err(error) => {
            let reason = error.to_string();
            let rejection_reason = match &error {
                PolicyError::PermitRejected { reason, .. } => reason.clone(),
                _ => PermitRejectionReasonV1::StateCorrupted,
            };
            let rejection_evidence = put_string(
                store,
                &serde_json::to_string(&PermitEvidenceV1::rejected(
                    &permit,
                    consume_time,
                    rejection_reason,
                )?)?,
            )?;
            append_receipt!(
                chain,
                run_id.clone(),
                step_id,
                ReceiptKindV1::PermitRejected,
                consume_time,
                lineage,
                call_digest,
                args_digest,
                vec![rejection_evidence],
                ReceiptOutcomeV1::Denied,
            )?;
            return Ok(Some((RunTerminalStateV1::Denied, reason)));
        }
    };
    if authorized.permit_id != permit.permit_id {
        return Err(PolicyError::PermitRejected {
            permit_id: permit.permit_id.clone(),
            reason: PermitRejectionReasonV1::StateCorrupted,
        }
        .into());
    }
    let consumed_evidence = put_string(store, &serde_json::to_string(&authorized)?)?;
    append_receipt!(
        chain,
        run_id.clone(),
        step_id.clone(),
        ReceiptKindV1::PermitConsumed,
        consume_time,
        lineage.clone(),
        call_digest.clone(),
        args_digest.clone(),
        vec![consumed_evidence],
        ReceiptOutcomeV1::Ok,
    )?;
    hook.fire(RunHookPoint::ChildConsumeBeforeDispatch, pinned_root)?;
    let dispatch_monotonic = clock.monotonic_now();
    let tool_result = if dispatch_monotonic < consume_monotonic
        || dispatch_monotonic >= permit_monotonic_deadline
        || dispatch_monotonic >= parent_monotonic_deadline
    {
        Err(recursive_agent_tools::ToolError::LeaseExpired(
            "monotonic execution lease expired or rolled back before dispatch".into(),
        ))
    } else {
        permit_store.validate_parent_authority(&permit.permit_id, clock.now())?;
        dispatch_tool(
            tool_executor,
            &step.call,
            authorized,
            permit_store.clone(),
            parent_monotonic_deadline
                .checked_sub(dispatch_monotonic)
                .ok_or_else(|| {
                    PolicyError::BudgetOverrun("parent monotonic budget exhausted".into())
                })?,
            prepared_dispatch,
        )
    };

    let parent_after_dispatch = clock.monotonic_now();
    let post_dispatch_time = clock.now();
    let tool_result = if parent_after_dispatch >= parent_monotonic_deadline
        || permit_store
            .validate_parent_authority(&permit.permit_id, post_dispatch_time)
            .is_err()
    {
        Err(recursive_agent_tools::ToolError::LeaseExpired(
            "parent authority ended during effect execution".into(),
        ))
    } else {
        tool_result
    };

    match tool_result {
        Ok(output) => {
            let descriptor = put_string(store, &serde_json::to_string(&output.body)?)?;
            let mut artifacts = vec![descriptor];
            for source_evidence in output.source_evidence {
                artifacts.push(put_string(
                    store,
                    &serde_json::to_string(&source_evidence)?,
                )?);
            }
            append_receipt!(
                chain,
                run_id.clone(),
                step_id.clone(),
                ReceiptKindV1::ArtifactStored,
                post_dispatch_time,
                lineage.clone(),
                call_digest.clone(),
                args_digest.clone(),
                artifacts.clone(),
                ReceiptOutcomeV1::Ok,
            )?;
            append_receipt!(
                chain,
                run_id.clone(),
                step_id,
                ReceiptKindV1::StepCompleted,
                post_dispatch_time,
                lineage,
                call_digest,
                args_digest,
                artifacts,
                ReceiptOutcomeV1::Ok,
            )?;
            Ok(None)
        }
        Err(error) => {
            let reason = error.to_string();
            let terminal = if error.timed_out() {
                RunTerminalStateV1::TimedOut
            } else if step.call.tool == "shell" && error.failure_observation().is_none() {
                RunTerminalStateV1::SandboxFailed
            } else {
                RunTerminalStateV1::Failed
            };
            let mut evidence = Vec::new();
            if let Some(observation) = error.failure_observation() {
                let descriptor = put_string(store, &serde_json::to_string(observation)?)?;
                append_receipt!(
                    chain,
                    run_id.clone(),
                    step_id.clone(),
                    ReceiptKindV1::ArtifactStored,
                    post_dispatch_time,
                    lineage.clone(),
                    call_digest.clone(),
                    args_digest.clone(),
                    vec![descriptor.clone()],
                    ReceiptOutcomeV1::Ok,
                )?;
                evidence.push(descriptor);
            } else {
                evidence.push(put_string(
                    store,
                    &serde_json::to_string(&serde_json::json!({
                        "kind": "tool_failure",
                        "reason": reason.clone(),
                    }))?,
                )?);
            }
            append_receipt!(
                chain,
                run_id.clone(),
                step_id,
                ReceiptKindV1::StepFailed,
                post_dispatch_time,
                lineage,
                call_digest,
                args_digest,
                evidence,
                terminal.receipt_outcome(reason.clone()),
            )?;
            Ok(Some((terminal, reason)))
        }
    }
}

fn dispatch_tool(
    tool_executor: &dyn RunnerToolExecutor,
    call: &ToolCallSpecV1,
    evidence: PermitEvidenceV1,
    permit_store: DurablePermitStore,
    parent_remaining: std::time::Duration,
    prepared_dispatch: Option<sandbox_engine::PreparedDispatch>,
) -> Result<RunnerToolOutput, recursive_agent_tools::ToolError> {
    if call.tool != "shell" {
        return tool_executor.execute(call, evidence);
    }
    let spec: recursive_agent_sandbox::SandboxSpec = serde_json::from_value(call.args.clone())
        .map_err(|error| recursive_agent_tools::ToolError::Args(format!("shell: {error}")))?;
    let parent_deadline = std::time::Instant::now()
        .checked_add(parent_remaining)
        .ok_or_else(|| {
            recursive_agent_tools::ToolError::LeaseExpired(
                "parent monotonic deadline overflow".into(),
            )
        })?;
    let token =
        sandbox_engine::DispatchToken::from_consumed(evidence, permit_store, parent_deadline)
            .map_err(|error| {
                recursive_agent_tools::ToolError::Runtime(format!("shell: {error}"))
            })?;
    let prepared = prepared_dispatch.ok_or_else(|| {
        recursive_agent_tools::ToolError::Runtime(
            "shell executable authority was not prepared before permit issuance".into(),
        )
    })?;
    let result = sandbox_engine::execute(&spec, call, token, prepared)
        .map_err(|error| recursive_agent_tools::ToolError::Runtime(format!("shell: {error}")))?;
    let success = result.enforcement.outcome
        == recursive_agent_sandbox::EnforcementOutcome::Enforced
        && !result.timed_out
        && !result.authority_terminated
        && result.exit_code == Some(0)
        && !result.stdout_truncated
        && !result.stderr_truncated
        && result.stdout_dropped_bytes == 0
        && result.stderr_dropped_bytes == 0;
    let observation = serde_json::to_value(result)
        .map_err(|error| recursive_agent_tools::ToolError::Args(format!("shell: {error}")))?;
    if success {
        return Ok(RunnerToolOutput {
            body: observation,
            source_evidence: Vec::new(),
        });
    }
    let reason = if observation
        .get("timed_out")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        "sandbox command timed out"
    } else if observation
        .get("stdout_dropped_bytes")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
        > 0
        || observation
            .get("stderr_dropped_bytes")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            > 0
    {
        "sandbox command exceeded an output bound"
    } else {
        "sandbox command did not exit successfully"
    };
    Err(recursive_agent_tools::ToolError::ShellNonSuccess {
        reason: reason.into(),
        observation: Box::new(observation),
    })
}

fn lifecycle_authority(
    spec: &RunSpecV1,
    run_id: &CurrentRunId,
    policy_version: &str,
    trusted_now: DateTime<Utc>,
    prepared: &[Option<sandbox_engine::PreparedDispatch>],
) -> Result<(DelegationCeilingV1, PermitBindingV1), RunError> {
    let actor = ActorPrincipalV1::try_new("recursive-agent")?;
    let mut actions = BTreeMap::new();
    let mut total = PermitBudgetV1 {
        max_wall_time_ms: 0,
        max_output_bytes: 0,
        max_artifact_bytes: 0,
    };
    for (index, step) in spec.steps.iter().enumerate() {
        let read_roots = string_array(&step.call.args, "allowed_read_paths")?;
        let write_roots = string_array(&step.call.args, "allowed_write_paths")?;
        let effect = EffectScopeV1 {
            scope_name: step.call.tool.clone(),
            read_roots,
            write_roots,
            network_allowed: optional_bool(&step.call.args, "allow_network")?.unwrap_or(false),
        };
        let default_timeout = if step.call.tool == "shell" {
            120_000
        } else {
            1_000
        };
        let wall = optional_u64(&step.call.args, "timeout_ms")?
            .unwrap_or(default_timeout)
            .max(1);
        let budget = PermitBudgetV1 {
            max_wall_time_ms: wall,
            max_output_bytes: 128 * 1024,
            max_artifact_bytes: recursive_agent_ledger::MAX_ARTIFACT_SIZE,
        };
        total.max_wall_time_ms = total
            .max_wall_time_ms
            .checked_add(budget.max_wall_time_ms)
            .ok_or_else(|| PolicyError::BudgetOverrun("control wall budget overflow".into()))?;
        total.max_output_bytes = total
            .max_output_bytes
            .checked_add(budget.max_output_bytes)
            .ok_or_else(|| PolicyError::BudgetOverrun("control output budget overflow".into()))?;
        total.max_artifact_bytes = total
            .max_artifact_bytes
            .checked_add(budget.max_artifact_bytes)
            .ok_or_else(|| PolicyError::BudgetOverrun("control artifact budget overflow".into()))?;
        let executable_authority = prepared.get(index).and_then(Option::as_ref).map_or_else(
            Vec::new,
            sandbox_engine::PreparedDispatch::executable_authority,
        );
        let action = DelegatedActionV1 {
            tool: step.call.tool.clone(),
            action_digest: content_digest(&step.call)?,
            args_digest: content_digest(&step.call.args)?,
            effect_digest: content_digest(&effect)?,
            effect,
            executable_authority,
        };
        let action_id = content_digest(&action)?.hex().to_owned();
        actions.entry(action_id).or_insert(action);
    }
    if actions.is_empty() {
        return Err(PolicyError::InvalidLease("run spec must contain a step".into()).into());
    }
    let audiences = actions
        .values()
        .map(|action| action.tool.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let actions = actions.into_values().collect::<Vec<_>>();
    let validity_ms = total
        .max_wall_time_ms
        .checked_add(5_000)
        .ok_or_else(|| PolicyError::BudgetOverrun("control validity overflow".into()))?;
    if validity_ms > 300_000 {
        return Err(PolicyError::BudgetOverrun(
            "aggregate child wall authority exceeds the Phase 1 control ceiling".into(),
        )
        .into());
    }
    let validity = i64::try_from(validity_ms)
        .map_err(|_| PolicyError::BudgetOverrun("control validity exceeds i64".into()))?;
    let expires_at = trusted_now
        .checked_add_signed(TimeDelta::milliseconds(validity))
        .ok_or_else(|| PolicyError::BudgetOverrun("control expiry overflow".into()))?;
    let spec_digest = content_digest(spec)?;
    let lifecycle_call = ToolCallSpecV1 {
        tool: "runner.lifecycle".into(),
        args: serde_json::json!({"run_spec_digest": spec_digest}),
        frozen_clock: None,
    };
    let lifecycle_step_id =
        derive_step_id(run_id, spec.steps.len(), "run-lifecycle", &lifecycle_call)?;
    let ceiling = DelegationCeilingV1 {
        actor: actor.clone(),
        policy_version: policy_version.into(),
        run_id: run_id.clone(),
        transition: DelegationTransitionV1::ControlToEffect,
        audiences,
        actions,
        budget: total.clone(),
        not_before: trusted_now,
        expires_at,
    };
    ceiling.validate()?;
    let control_effect = EffectScopeV1 {
        scope_name: "runner.lifecycle".into(),
        read_roots: Vec::new(),
        write_roots: Vec::new(),
        network_allowed: false,
    };
    let binding = PermitBindingV1 {
        actor,
        action_digest: content_digest(&lifecycle_call)?,
        effect_digest: content_digest(&control_effect)?,
        effect: control_effect,
        budget: total,
        policy_version: policy_version.into(),
        parent_permit_id: None,
        parent_operation_id: Some(run_id.clone()),
        issued_at: trusted_now,
        not_before: trusted_now,
        expires_at,
        run_id: run_id.clone(),
        step_id: lifecycle_step_id,
        tool: "runner.lifecycle".into(),
        args_digest: content_digest(&lifecycle_call.args)?,
    };
    Ok((ceiling, binding))
}

fn permit_binding(
    run_id: &CurrentRunId,
    step_id: &CurrentStepId,
    call: &ToolCallSpecV1,
    policy_version: &str,
    parent_permit_id: Option<CurrentPermitId>,
    trusted_now: DateTime<Utc>,
    parent_expires_at: DateTime<Utc>,
) -> Result<PermitBindingV1, RunError> {
    let read_roots = string_array(&call.args, "allowed_read_paths")?;
    let write_roots = string_array(&call.args, "allowed_write_paths")?;
    let effect = EffectScopeV1 {
        scope_name: call.tool.clone(),
        read_roots,
        write_roots,
        network_allowed: optional_bool(&call.args, "allow_network")?.unwrap_or(false),
    };
    let default_timeout = if call.tool == "shell" { 120_000 } else { 1_000 };
    let timeout = optional_u64(&call.args, "timeout_ms")?
        .unwrap_or(default_timeout)
        .max(1);
    let expiry_delta = i64::try_from(timeout.saturating_add(1_000))
        .map_err(|_| ContractError::Malformed("permit timeout exceeds i64".into()))?;
    let requested_expires_at = trusted_now
        .checked_add_signed(TimeDelta::milliseconds(expiry_delta))
        .ok_or_else(|| ContractError::Malformed("permit expiry overflow".into()))?;
    let expires_at = requested_expires_at.min(parent_expires_at);
    let binding = PermitBindingV1 {
        actor: ActorPrincipalV1::try_new("recursive-agent")?,
        action_digest: content_digest(call)?,
        effect_digest: content_digest(&effect)?,
        effect,
        budget: PermitBudgetV1 {
            max_wall_time_ms: timeout,
            max_output_bytes: 128 * 1024,
            max_artifact_bytes: recursive_agent_ledger::MAX_ARTIFACT_SIZE,
        },
        policy_version: policy_version.into(),
        parent_permit_id,
        parent_operation_id: Some(run_id.clone()),
        issued_at: trusted_now,
        not_before: trusted_now,
        expires_at,
        run_id: run_id.clone(),
        step_id: step_id.clone(),
        tool: call.tool.clone(),
        args_digest: content_digest(&call.args)?,
    };
    binding.validate()?;
    let _ = derive_permit_id(&binding.identity_material()?)?;
    Ok(binding)
}

fn optional_bool(value: &serde_json::Value, key: &str) -> Result<Option<bool>, ContractError> {
    let Some(raw) = value.get(key) else {
        return Ok(None);
    };
    raw.as_bool()
        .map(Some)
        .ok_or_else(|| ContractError::Malformed(format!("{key} must be a bool when provided")))
}

fn optional_u64(value: &serde_json::Value, key: &str) -> Result<Option<u64>, ContractError> {
    let Some(raw) = value.get(key) else {
        return Ok(None);
    };
    raw.as_u64().map(Some).ok_or_else(|| {
        ContractError::Malformed(format!("{key} must be an unsigned integer when provided"))
    })
}

fn string_array(value: &serde_json::Value, key: &str) -> Result<Vec<String>, ContractError> {
    let Some(raw) = value.get(key) else {
        return Ok(Vec::new());
    };
    let values = raw
        .as_array()
        .ok_or_else(|| ContractError::Malformed(format!("{key} must be an array")))?;
    values
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| ContractError::Malformed(format!("{key} entry must be a string")))
        })
        .collect()
}

fn append_receipt_draft(chain: &mut ChainHandle, draft: ReceiptDraftV1) -> Result<(), RunError> {
    let receipt = make_receipt(draft, chain.head().clone())?;
    recursive_agent_policy::assert_lineage_for_receipt(&receipt)?;
    chain.append(receipt)?;
    Ok(())
}

/// Recorded-evidence replay: strict verification precedes every projection.
/// Tools and providers are never invoked.
pub fn replay(paths: &RunPaths) -> Result<ReplaySummary, RunError> {
    let snapshot = recursive_agent_ledger::verified_snapshot_directory_bound(paths)?;
    let verification = snapshot.verification();
    let mut artifacts = Vec::new();
    let mut step_results = Vec::new();
    for receipt in snapshot.receipts() {
        let refs = receipt
            .artifact_refs
            .iter()
            .map(|descriptor| descriptor.owner_id.to_string())
            .collect::<Vec<_>>();
        for artifact in &refs {
            if !artifacts.contains(artifact) {
                artifacts.push(artifact.clone());
            }
        }
        step_results.push(ReplayStep {
            step_id: receipt.step_id.to_string(),
            kind: format!("{:?}", receipt.kind),
            outcome: format!("{:?}", receipt.outcome),
            artifact_refs: refs,
        });
    }
    Ok(ReplaySummary {
        ok: verification.ok,
        length: verification.length,
        final_head: verification.final_head.clone(),
        step_results,
        artifacts,
        replay_capability: if verification.ok {
            // Recorded-evidence replay: the chain strictly verifies and every
            // artifact is re-emitted from stored bytes. No external state is
            // touched. Determinism is only claimed when the run declared it;
            // recorded-evidence is the truthful default for verified runs.
            ReplayCapability::RecordedEvidence
        } else {
            ReplayCapability::Unavailable
        },
    })
}

#[derive(Debug, Clone)]
pub struct ReplaySummary {
    pub ok: bool,
    pub length: u64,
    pub final_head: String,
    pub step_results: Vec<ReplayStep>,
    pub artifacts: Vec<String>,
    /// Explicit replay-capability classification (Task 5.4). Never overstates:
    /// a verified run replays recorded evidence; unverified/legacy runs are
    /// Unavailable rather than silently re-fetching external state.
    pub replay_capability: ReplayCapability,
}

/// Explicit, honest classification of what a replay can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayCapability {
    /// The run is deterministic and replayable from committed evidence.
    Deterministic,
    /// Recorded-evidence replay: verified receipts/artifacts are re-emitted;
    /// no tool, provider, or network call is made.
    RecordedEvidence,
    /// Replay is not available (verification failed, legacy/ambiguous
    /// evidence, or missing recorded output).
    Unavailable,
}

#[derive(Debug, Clone)]
pub struct ReplayStep {
    pub step_id: String,
    pub kind: String,
    pub outcome: String,
    pub artifact_refs: Vec<String>,
}

/// A verified, terminal step boundary from which a continuation may resume.
#[derive(Debug, Clone)]
pub struct VerifiedBoundary {
    /// Canonical id of the verified parent run.
    pub parent_run_id: String,
    /// The parent chain verified successfully.
    pub verified: bool,
}

/// Task 5.3 — resume only from a strictly-verified step boundary.
///
/// Strictly verifies a parent run directory and, on success, returns a
/// causally-linked continuation plan (parent_operation_id set) so a new
/// continuation run never mutates the prior evidence. An unverified or
/// mismatched parent boundary is a typed error, never a silent resume.
pub fn resume_from_verified_boundary(
    parent_paths: &recursive_agent_ledger::RunPaths,
) -> Result<VerifiedBoundary, RunError> {
    let verification = recursive_agent_ledger::verify_directory_bound(parent_paths)?;
    if !verification.ok {
        return Err(RunError::ResumeFromUnverifiedBoundary {
            reason: "parent chain verification failed".into(),
        });
    }
    let parent_run_id = verification
        .verified_run_id
        .as_ref()
        .ok_or(RunError::ResumeFromUnverifiedBoundary {
            reason: "parent run id is absent".into(),
        })?
        .to_string();
    Ok(VerifiedBoundary {
        parent_run_id,
        verified: true,
    })
}

/// Build a causally-linked continuation envelope for the given step set,
/// bound to a previously verified parent boundary. No in-place mutation of the
/// parent run occurs; the continuation is a fresh run carrying parent lineage.
pub fn continuation_envelope(
    boundary: &VerifiedBoundary,
    name: &str,
    steps: Vec<StepSpecV1>,
    policy_version: &str,
) -> Result<OperationEnvelopeV1, RunError> {
    let parent_run_id = CurrentRunId::try_new(&boundary.parent_run_id).map_err(|_| {
        ContractError::Malformed("parent boundary run id is not a canonical run id".into())
    })?;
    let run_spec = RunSpecV1 {
        name: name.into(),
        steps,
        frozen_clock: None,
        policy_version: policy_version.into(),
    };
    let mut operation = legacy_operation_envelope(&run_spec)?;
    // A continuation is inherently a child: it must carry parent/root lineage,
    // which the contract only permits for Delegated authority.
    operation.actor = ActorAuthorityV1 {
        principal: "continuation".into(),
        origin: AuthorityOriginV1::Delegated,
    };
    operation.causality.parent_operation_id = Some(parent_run_id.clone());
    operation.causality.root_operation_id = Some(parent_run_id);
    operation.validate()?;
    Ok(operation)
}

#[cfg(test)]
mod pinned_root_tests {
    use super::*;
    use recursive_agent_contracts::{StepSpecV1, ToolCallSpecV1};
    use std::io;
    use std::sync::Mutex;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[derive(Clone, Copy)]
    enum Replacement {
        Directory,
        Symlink,
    }

    struct ReplacementHook {
        at: RunHookPoint,
        replacement: Replacement,
        parked: Mutex<Option<PathBuf>>,
        retained_root: Mutex<Option<File>>,
    }

    impl ReplacementHook {
        fn new(at: RunHookPoint, replacement: Replacement) -> Self {
            Self {
                at,
                replacement,
                parked: Mutex::new(None),
                retained_root: Mutex::new(None),
            }
        }

        fn parked(&self) -> Result<PathBuf, io::Error> {
            self.parked
                .lock()
                .map_err(|_| io::Error::other("parked-path lock poisoned"))?
                .clone()
                .ok_or_else(|| io::Error::other("replacement hook did not fire"))
        }

        fn retained_root(&self) -> Result<File, io::Error> {
            self.retained_root
                .lock()
                .map_err(|_| io::Error::other("retained-root lock poisoned"))?
                .take()
                .ok_or_else(|| io::Error::other("replacement hook did not retain the root"))
        }
    }

    impl RunnerHook for ReplacementHook {
        fn fire(&self, point: RunHookPoint, root: &PinnedRunRoot) -> Result<(), RunError> {
            if std::mem::discriminant(&point) != std::mem::discriminant(&self.at) {
                return Ok(());
            }
            let parked = root.locator.with_extension("pinned-original");
            std::fs::rename(&root.locator, &parked)?;
            match self.replacement {
                Replacement::Directory => {
                    std::fs::create_dir(&root.locator)?;
                    std::fs::write(root.locator.join("receipts.ndjson"), b"plausible\n")?;
                    std::fs::write(root.locator.join("chain.meta"), b"{}\n")?;
                }
                Replacement::Symlink => {
                    let attacker = root.locator.with_extension("attacker");
                    std::fs::create_dir(&attacker)?;
                    std::os::unix::fs::symlink(&attacker, &root.locator)?;
                }
            }
            let duplicate =
                File::from(rustix::io::dup(root.root.as_fd()).map_err(std::io::Error::from)?);
            *self
                .parked
                .lock()
                .map_err(|_| io::Error::other("parked-path lock poisoned"))? = Some(parked);
            *self
                .retained_root
                .lock()
                .map_err(|_| io::Error::other("retained-root lock poisoned"))? = Some(duplicate);
            Ok(())
        }
    }

    fn shell_spec(marker: &Path) -> Result<RunSpecV1, serde_json::Error> {
        let sandbox = recursive_agent_sandbox::SandboxSpec {
            command: "/usr/bin/bash".into(),
            args: vec!["-c".into(), format!("printf x >> {}", marker.display())],
            allowed_read_paths: vec![],
            allowed_write_paths: vec![marker
                .parent()
                .map_or_else(String::new, |path| path.display().to_string())],
            allow_network: false,
            timeout_ms: 2_000,
            max_output_bytes: 1_024,
        };
        Ok(RunSpecV1 {
            name: "pinned-root-race".into(),
            steps: vec![StepSpecV1 {
                name: "shell".into(),
                call: ToolCallSpecV1 {
                    tool: "shell".into(),
                    args: serde_json::to_value(sandbox)?,
                    frozen_clock: None,
                },
            }],
            frozen_clock: None,
            policy_version: "m0-2".into(),
        })
    }

    #[test]
    fn directory_replacement_before_authorization_dispatches_nothing() -> TestResult {
        let output = tempfile::tempdir()?;
        let marker_root = tempfile::tempdir()?;
        let marker = marker_root.path().join("effect-marker");
        let spec = shell_spec(&marker)?;
        let hook = ReplacementHook::new(RunHookPoint::PinnedRootOpen, Replacement::Directory);
        let result = run_spec_internal(&spec, output.path(), &SystemClock, &hook);
        assert!(matches!(result, Err(RunError::RunRootLocatorMismatch)));
        assert!(!marker.exists());
        let parked = hook.parked()?;
        assert!(!parked.join("receipts.ndjson").exists());
        assert!(!parked.join("artifacts").exists());
        assert!(!parked.join("permits").exists());
        Ok(())
    }

    #[test]
    fn symlink_replacement_before_authorization_dispatches_nothing() -> TestResult {
        let output = tempfile::tempdir()?;
        let marker_root = tempfile::tempdir()?;
        let marker = marker_root.path().join("effect-marker");
        let spec = shell_spec(&marker)?;
        let hook = ReplacementHook::new(RunHookPoint::PinnedRootOpen, Replacement::Symlink);
        let result = run_spec_internal(&spec, output.path(), &SystemClock, &hook);
        assert!(matches!(result, Err(RunError::RunRootLocatorMismatch)));
        assert!(!marker.exists());
        Ok(())
    }

    #[test]
    fn replacement_after_dispatch_preserves_one_inode_but_cannot_report_success() -> TestResult {
        let output = tempfile::tempdir()?;
        let marker_root = tempfile::tempdir()?;
        let marker = marker_root.path().join("effect-marker");
        let spec = shell_spec(&marker)?;
        let run_id = derive_run_id(&spec)?;
        let hook = ReplacementHook::new(
            RunHookPoint::DispatchBeforeFinalReadback,
            Replacement::Directory,
        );
        let result = run_spec_internal(&spec, output.path(), &SystemClock, &hook);
        assert!(matches!(result, Err(RunError::RunRootLocatorMismatch)));
        assert_eq!(std::fs::read(&marker)?, b"x");

        let retained_root = hook.retained_root()?;
        let snapshot = recursive_agent_ledger::verified_snapshot_expected_run_from_dir_fd(
            &retained_root,
            &run_id,
        )?;
        assert_eq!(
            snapshot.verification().terminal_state,
            RunTerminalStateV1::Succeeded
        );
        let parked = hook.parked()?;
        let paths = RunPaths::new(parked);
        let chain = open_from_dir_fd(&paths, &retained_root)?;
        let artifacts = chain.artifact_store()?;
        let permits = DurablePermitStore::from_run_root_fd(&retained_root)?;
        assert_eq!(chain.run_root_identity(), artifacts.run_root_identity());
        assert_eq!(
            (
                chain.run_root_identity().device,
                chain.run_root_identity().inode
            ),
            permits.run_root_identity()
        );
        Ok(())
    }
}
