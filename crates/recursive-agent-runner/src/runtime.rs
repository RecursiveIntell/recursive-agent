use std::collections::BTreeMap;
use std::sync::Mutex;

use llm_tool_runtime::{
    ToolBudgetContext, ToolCall, ToolCtx, ToolExecutionPermit, ToolOriginKind, ToolPlannerStage,
    ToolRetryOwner, ToolRuntime,
};
use recursive_agent_contracts::{
    content_digest, derive_child_operation_id, derive_child_operation_proposal_digest,
    derive_operation_id, derive_provider_egress_operation_id, derive_step_id,
    parse_operation_envelope_bytes, ChildOperationEnvelopeV2, ChildOperationProposalV2,
    ChildRunAuthorityV1, ContractError, CurrentPermitId, CurrentRunId, OperationEnvelopeV1,
    ProviderEgressOperationEnvelopeV3, ReceiptKindV1, RunTerminalStateV1, RuntimeEventV1,
    ToolCallSpecV1,
};
use recursive_agent_ledger::{
    committed_events_directory_bound, verified_snapshot_directory_bound,
    verified_snapshot_with_artifact_store_directory_bound, verify_child_links_in_runtime_root,
    verify_directory_bound, ChainVerification, ChildRunLinkV1, LedgerError, RunPaths,
};
use recursive_agent_policy::{
    authorize_provider_egress, ActorPrincipalV1, ChildRunCeilingV1, DurablePermitStore,
    FamilyAuthorityStore, FamilyChildRequestV1, FamilyRootGrantV1, OperatorApprovalVerifierV1,
    OperatorApprovalWitnessV1, PermitApprovalRequestV1, PermitBudgetV1, PermitEvidenceV1,
    PermitOutcomeReceiptV1, PermitPreflightReceiptV1, PolicyError, ProductionApprovalVerifierV1,
    ProductionApprovalWitnessV1, ProviderEgressAdmissionRequestV1, ReportedEffectOutcomeV1,
};
use recursive_agent_provider::{CompletionBackend, CompletionRequestV1, ProviderSpecV1};
use stack_ids::{AttemptId, TraceCtx, TrialId};
use thiserror::Error;

use crate::{
    run_child_spec_with_run_id, run_live_parent_spec_with_run_id,
    run_provider_egress_operation_v3_with_run_id, run_spec_internal_with_run_id,
    AutonomousBudgetV1, AutonomousCancellation, AutonomousError, AutonomousExecutor,
    AutonomousIntentV1, AutonomousPlanner, AutonomousResultV1, AutonomousTranscript,
    JsonAutonomousPlanner, LiveParentRun, ManagedAdmissionDomain, ManagedAdmissionError,
    ManagedAdmissionRequestV1, ManagedBudgetV1, ManagedReservation, ModelAutonomousPlanner,
    NoopRunnerHook, ProviderEgressAuthorizer, RunError, RunnerToolExecutor, RunnerToolOutput,
    RuntimeDependencies,
};

/// Stable handle returned only after the authoritative run has reached a terminal receipt.
///
/// Adapters may inspect a handle but cannot construct one:
///
/// ```compile_fail
/// use std::path::PathBuf;
/// use recursive_agent_contracts::CurrentRunId;
/// use recursive_agent_runner::RuntimeHandleV1;
///
/// fn forge(operation_id: CurrentRunId, run_dir: PathBuf) -> RuntimeHandleV1 {
///     RuntimeHandleV1 {
///         operation_id: operation_id.clone(),
///         run_id: operation_id,
///         run_dir,
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeHandleV1 {
    /// Canonical identity derived from the complete operation envelope.
    operation_id: CurrentRunId,
    /// Authoritative run identity; equal to `operation_id` for native V1 operations.
    run_id: CurrentRunId,
    /// Content-addressed directory containing the committed evidence chain.
    run_dir: std::path::PathBuf,
}

impl RuntimeHandleV1 {
    /// Borrow the canonical complete-operation identity.
    pub fn operation_id(&self) -> &CurrentRunId {
        &self.operation_id
    }

    /// Borrow the authoritative run identity.
    pub fn run_id(&self) -> &CurrentRunId {
        &self.run_id
    }

    /// Borrow the content-addressed authoritative run directory.
    pub fn run_dir(&self) -> &std::path::Path {
        &self.run_dir
    }
}

/// Runtime-owned V2 parent lifecycle. It retains the pinned appendable parent
/// chain and family authority; callers can submit only pre-admission child
/// proposals and must explicitly finalize the parent.
pub struct RuntimeLiveParentV2<'a> {
    service: &'a RuntimeService,
    parent: LiveParentRun,
    finalized: bool,
}

/// Ledger-derived runtime state. No adapter-supplied terminal state is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeStatusV1 {
    /// The operation is currently owned by this service instance.
    Active,
    /// Strict verification found authoritative terminal evidence.
    Terminal {
        /// Exact terminal state from the verified receipt chain.
        state: RunTerminalStateV1,
    },
}

/// Truthful result of requesting cancellation through the runtime owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeCancelResultV1 {
    /// The run already has terminal evidence and cannot be cancelled retroactively.
    AlreadyTerminal {
        /// Existing authoritative terminal state.
        state: RunTerminalStateV1,
    },
    /// The cancellation request was durably recorded; the runtime will
    /// propagate it to the active process/descendants (Phase 5 scheduler).
    CancellationRequested {
        /// Canonical run identifier the cancellation was recorded for.
        run_id: String,
    },
}

/// Typed failures at the canonical runtime-service boundary.
#[derive(Debug, Error)]
pub enum RuntimeServiceError {
    /// Native permit root could not be opened.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Policy-owned permit admission, consumption, or outcome recording failed.
    #[error("policy: {0}")]
    Policy(#[from] PolicyError),
    #[error("test-only permit issuance is disabled without a verifier")]
    PermitIssuanceDisabled,
    /// Native operation validation or identity derivation failed before effects.
    #[error("operation contract: {0}")]
    Contract(#[from] ContractError),
    /// Strict ledger readback or event projection failed.
    #[error("ledger: {0}")]
    Ledger(#[from] LedgerError),
    /// Verified evidence did not bind to the caller-requested run identity.
    #[error("verified run identity mismatch: expected={expected}, observed={observed}")]
    RunIdentityMismatch {
        /// Caller-requested run identity.
        expected: String,
        /// Identity observed in verified evidence.
        observed: String,
    },
    /// A referenced tool is absent from the admitted owner registry.
    #[error("tool is not registered in the admitted runtime: {name}")]
    ToolNotRegistered {
        /// Missing canonical tool name.
        name: String,
    },
    /// Candidate V3 egress has no injected current policy owner.
    #[error("candidate provider egress is disabled in this runtime composition")]
    ProviderEgressDisabled,
    /// Opaque V3 request did not decode as the provider owner's closed request.
    #[error("candidate provider request is malformed")]
    ProviderRequestMalformed,
    /// V3 request provider differs from the explicitly configured dependency.
    #[error("candidate provider request does not match runtime configuration")]
    ProviderConfigurationMismatch,
    /// Policy-facing provider/model metadata does not describe the decoded request.
    #[error("candidate provider binding does not match the decoded request route")]
    ProviderBindingMismatch,
    /// Recorded replay was requested before a verified V3 run exists.
    #[error("recorded provider-egress replay is unavailable")]
    ProviderEgressReplayUnavailable,
    /// The same operation is already executing through this service instance.
    #[error("operation is already active: {operation_id}")]
    OperationAlreadyActive {
        /// Canonical operation identity.
        operation_id: String,
    },
    /// The owner-controlled active-leaf capacity is currently exhausted.
    #[error("active-leaf capacity exhausted: configured ceiling={configured}")]
    ActiveLeafCapacityExceeded { configured: usize },
    /// Managed native admission failed before physical dispatch.
    #[error("managed admission: {0}")]
    ManagedAdmission(ManagedAdmissionError),
    /// Internal concurrent state was poisoned; the service fails closed.
    #[error("runtime service state is poisoned")]
    StatePoisoned,
    /// Active cancellation is intentionally unavailable until the durable scheduler owns it.
    #[error("active cancellation requires the Phase-5 durable scheduler")]
    ActiveCancellationUnavailable,
    /// The authoritative runner rejected or failed the operation.
    #[error("run: {0}")]
    Run(#[from] RunError),
    /// The autonomous planner/executor boundary failed before a native result
    /// could be returned. The autonomous transcript remains the durable owner
    /// of its internal state transitions.
    #[error("autonomous: {0}")]
    Autonomous(#[from] AutonomousError),
    /// Idempotency key was reused with a different canonical request digest.
    #[error(
        "idempotency key conflict: key={key} previously bound to digest={prior} now {incoming}"
    )]
    IdempotencyKeyConflict {
        /// The caller-supplied idempotency key.
        key: String,
        /// Digest the key was originally bound to.
        prior: String,
        /// Digest of the incoming (conflicting) request.
        incoming: String,
    },
    /// No scheduler projection is attached, so idempotent submission is unavailable.
    #[error("idempotent submission requires the Phase-5 durable scheduler")]
    IdempotentSubmissionUnavailable,
    /// A live parent has already reached a non-success terminal condition in
    /// its own declared steps, so it cannot admit children.
    #[error("live parent cannot admit children after terminal state {state:?}")]
    LiveParentNotAdmissible { state: RunTerminalStateV1 },
    /// The proposal does not bind exactly to the runtime-owned parent family.
    #[error("child proposal causal lineage does not bind the live parent")]
    ChildParentMismatch,
    /// The live parent is already finalized and cannot receive another call.
    #[error("live parent lifecycle has already been finalized")]
    LiveParentFinalized,
}

struct AdmittedToolExecutor<'a> {
    runtime: &'a ToolRuntime,
}

/// Executor that turns an autonomous intent containing an `operation` object
/// into one canonical native V1 submission. It is deliberately explicit: an
/// intent without a complete operation envelope cannot select a tool by name
/// or acquire provider access implicitly.
pub struct NativeOperationExecutor<'a> {
    service: &'a RuntimeService,
}

impl<'a> NativeOperationExecutor<'a> {
    pub fn new(service: &'a RuntimeService) -> Self {
        Self { service }
    }
}

impl AutonomousExecutor for NativeOperationExecutor<'_> {
    fn execute(
        &self,
        _context: &crate::AutonomousContextV1,
        intent: &AutonomousIntentV1,
    ) -> Result<AutonomousResultV1, AutonomousError> {
        let operation = intent.payload.get("operation").ok_or_else(|| {
            AutonomousError::InvalidPlan("intent lacks operation envelope".into())
        })?;
        let bytes = serde_json::to_vec(operation)?;
        let operation = parse_operation_envelope_bytes(&bytes)
            .map_err(|error| AutonomousError::InvalidPlan(error.to_string()))?;
        let handle = self
            .service
            .submit(&operation)
            .map_err(|error| AutonomousError::InvalidPlan(error.to_string()))?;
        let verification = self
            .service
            .verify(handle.run_id())
            .map_err(|error| AutonomousError::InvalidPlan(error.to_string()))?;
        if !verification.current_strict_success
            || verification.terminal_state != RunTerminalStateV1::Succeeded
        {
            return Err(AutonomousError::InvalidPlan(
                "native operation lacks strictly verified successful terminal evidence".into(),
            ));
        }
        let snapshot = verified_snapshot_directory_bound(&RunPaths::new(handle.run_dir()))
            .map_err(|error| AutonomousError::InvalidPlan(error.to_string()))?;
        let terminal_receipt = snapshot.receipts().last().ok_or_else(|| {
            AutonomousError::InvalidPlan("verified native operation transcript is empty".into())
        })?;
        if terminal_receipt.kind != ReceiptKindV1::RunFinalized {
            return Err(AutonomousError::InvalidPlan(
                "verified native operation lacks a terminal receipt".into(),
            ));
        }
        Ok(AutonomousResultV1 {
            output: serde_json::json!({
                "run_id": handle.run_id().to_string(),
                "operation_id": handle.operation_id().to_string(),
                "run_dir": handle.run_dir().display().to_string(),
                "verified": true,
            }),
            receipt: Some(terminal_receipt.receipt_id.clone()),
        })
    }
}

impl RunnerToolExecutor for AdmittedToolExecutor<'_> {
    fn execute(
        &self,
        call: &recursive_agent_contracts::ToolCallSpecV1,
        evidence: PermitEvidenceV1,
    ) -> Result<RunnerToolOutput, recursive_agent_tools::ToolError> {
        let owner = self
            .runtime
            .registry()
            .get(&call.tool)
            .ok_or_else(|| recursive_agent_tools::ToolError::Unknown(call.tool.clone()))?;
        let identity_material = evidence.binding_digest.to_string();
        let id_error = |error: stack_ids::IdError| {
            recursive_agent_tools::ToolError::Runtime(format!(
                "tool context identity derivation failed: {error}"
            ))
        };
        let trace_material = blake3::hash(identity_material.as_bytes())
            .to_hex()
            .to_string();
        let context = ToolCtx {
            trace_ctx: TraceCtx::from_trace_id(&trace_material[..32]),
            attempt_id: AttemptId::deterministic("recursive-agent-attempt", &identity_material)
                .map_err(id_error)?,
            trial_id: TrialId::deterministic("recursive-agent-trial", &identity_material)
                .map_err(id_error)?,
            deadline: Some(evidence.binding.expires_at.to_rfc3339()),
            workload_class: Some("recursive-agent-operation-v1".into()),
            budget_context: Some(ToolBudgetContext {
                budget_kind: Some("recursive-agent-consumed-permit".into()),
                max_steps: Some(1),
                time_budget_ms: Some(evidence.binding.budget.max_wall_time_ms),
                cost_budget_units: None,
            }),
            scope: None,
            dry_run: false,
            approval_grant: None,
            execution_permit: None,
            idempotency_key: Some(evidence.permit_id.to_string()),
            caller: evidence.binding.actor.as_str().into(),
            planner_stage: ToolPlannerStage::Execution,
            parent_receipt_id: None,
            family_receipt_id: Some(evidence.binding.run_id.to_string()),
            replay_parent_receipt_id: None,
            remote_oracle_lease_id: None,
            remote_slice_result_id: None,
            attestation_envelope_id: None,
            cross_runtime_replay_ticket_id: None,
            retry_owner: Some(ToolRetryOwner::External),
        };
        let owner_call = ToolCall {
            descriptor_name: call.tool.clone(),
            descriptor_version: owner.descriptor().version.clone(),
            arguments: admitted_tool_arguments(call)?,
            origin_kind: ToolOriginKind::Local,
            provider_call_id: None,
            tool_run_id: format!(
                "{}:{}:{}",
                evidence.binding.run_id, evidence.binding.step_id, evidence.permit_id
            ),
        };
        let tool_execution_permit = if call.tool == "sealed_completion" {
            let target_key = call
                .args
                .get("binding")
                .and_then(|binding| binding.get("binding_digest"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    recursive_agent_tools::ToolError::Args(
                        "sealed_completion binding digest is missing".into(),
                    )
                })?;
            let execution_permit_id =
                stack_ids::ExecutionPermitId::try_new(evidence.permit_id.to_string())
                    .map_err(id_error)?;
            let decision_id = stack_ids::PolicyDecisionId::deterministic(
                "recursive-agent/provider-egress-policy",
                evidence.binding_digest.hex(),
            )
            .map_err(id_error)?;
            Some(ToolExecutionPermit::new(
                execution_permit_id,
                decision_id,
                None,
                "recursive-agent:sealed_completion",
                target_key,
            ))
        } else {
            None
        };
        let joined = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_time()
                        .build()
                        .map_err(|error| {
                            recursive_agent_tools::ToolError::Runtime(format!(
                                "admitted tool runtime initialization failed: {error}"
                            ))
                        })?;
                    Ok::<llm_tool_runtime::ToolExecution, recursive_agent_tools::ToolError>(
                        runtime.block_on(self.runtime.execute(
                            &context,
                            &owner_call,
                            tool_execution_permit.as_ref(),
                            None,
                        )),
                    )
                })
                .join()
        });
        let execution = joined.map_err(|_| {
            recursive_agent_tools::ToolError::Runtime(
                "admitted tool runtime worker panicked".into(),
            )
        })??;
        match execution.result {
            Ok(result) => Ok(RunnerToolOutput {
                body: result.payload,
                source_evidence: Vec::new(),
            }),
            Err(error) => {
                let reason = format!("{:?}: {}", error.class, error.message);
                Err(recursive_agent_tools::ToolError::OwnerRuntime {
                    reason: reason.clone(),
                    observation: Box::new(serde_json::json!({
                        "kind": "admitted_tool_runtime_failure",
                        "reason": reason,
                        "retryable": error.retryable,
                        "details": error.details
                    })),
                })
            }
        }
    }
}

/// Construct the admitted descriptor input from a typed operation call.
/// `time_now` receives the frozen timestamp explicitly because descriptor
/// execution is intentionally isolated from the runner clock and must never
/// read wall-clock time.
fn admitted_tool_arguments(
    call: &recursive_agent_contracts::ToolCallSpecV1,
) -> Result<serde_json::Value, recursive_agent_tools::ToolError> {
    if call.tool != "time_now" {
        return Ok(call.args.clone());
    }
    let frozen_clock = call
        .frozen_clock
        .ok_or_else(|| recursive_agent_tools::ToolError::FrozenClockRequired("time_now".into()))?;
    let mut arguments = call.args.clone();
    let object = arguments.as_object_mut().ok_or_else(|| {
        recursive_agent_tools::ToolError::Args("time_now arguments must be an object".into())
    })?;
    object.insert(
        "frozen_clock".into(),
        serde_json::Value::String(frozen_clock.to_rfc3339()),
    );
    Ok(arguments)
}

/// Canonical native owner of operation admission and terminal execution evidence.
pub struct RuntimeService {
    dependencies: RuntimeDependencies,
    admission: ManagedAdmissionDomain,
    /// Live-parent cancellation reaches the family authority directly; this is
    /// authority state, not a scheduler projection.
    live_families: Mutex<BTreeMap<String, FamilyAuthorityStore>>,
    /// Optional durable scheduler control projection (Phase 5). When present,
    /// cancellation and admission are persisted across restarts.
    scheduler: std::sync::Mutex<Option<crate::SchedulerStore>>,
    operator_approval_verifier: Option<OperatorApprovalVerifierV1>,
    production_approval_verifier: Option<ProductionApprovalVerifierV1>,
    context_authority: Option<recursive_agent_policy::ContextAuthorityAccess>,
}

impl RuntimeService {
    /// Construct a service from a complete, previously admitted dependency set.
    pub fn new(dependencies: RuntimeDependencies) -> Self {
        let admission = ManagedAdmissionDomain::from_global(
            dependencies.active_leaf_config().max_active_leaves,
        );
        Self::new_with_managed_admission(dependencies, admission)
    }

    /// Construct a managed facade over an explicitly shared physical-admission
    /// owner. Multi-facade daemon/Graph/specialist compositions must use this
    /// constructor rather than manufacturing independent capacity pools.
    pub fn new_with_managed_admission(
        dependencies: RuntimeDependencies,
        admission: ManagedAdmissionDomain,
    ) -> Self {
        Self {
            dependencies,
            admission,
            live_families: Mutex::new(BTreeMap::new()),
            scheduler: std::sync::Mutex::new(None),
            operator_approval_verifier: None,
            production_approval_verifier: None,
            context_authority: None,
        }
    }

    pub fn with_operator_approval_verifier(mut self, verifier: OperatorApprovalVerifierV1) -> Self {
        self.operator_approval_verifier = Some(verifier);
        self
    }

    /// Explicitly inject the daemon-owned production public verifier key.
    pub fn with_production_approval_verifier(
        mut self,
        verifier: ProductionApprovalVerifierV1,
    ) -> Self {
        self.production_approval_verifier = Some(verifier);
        self
    }

    /// Install an operator-owned startup enrollment through the native permit
    /// owner. Ares cannot enroll keys or scope labels over IPC.
    pub fn with_context_authority(
        mut self,
        configuration: &recursive_agent_policy::ContextAuthorityConfigurationV1,
    ) -> Result<Self, RuntimeServiceError> {
        let verifier = self
            .production_approval_verifier
            .as_ref()
            .ok_or(RuntimeServiceError::PermitIssuanceDisabled)?;
        if verifier.context_authority_digest()? != configuration.approval_verifier {
            return Err(RuntimeServiceError::Policy(PolicyError::InvalidLease(
                "context authority approval verifier enrollment mismatch".into(),
            )));
        }
        let root = std::fs::File::open(self.dependencies.output_root())?;
        let permits = DurablePermitStore::from_dir_fd(&root)?;
        self.context_authority = Some(permits.enroll_context_authority(configuration)?);
        Ok(self)
    }

    pub fn issue_scoped_external_permit(
        &self,
        witness: &ProductionApprovalWitnessV1,
        context: &recursive_agent_policy::ContextCallBindingV1,
    ) -> Result<recursive_agent_policy::ScopedExecutionPermitV1, RuntimeServiceError> {
        let verifier = self
            .production_approval_verifier
            .as_ref()
            .ok_or(RuntimeServiceError::PermitIssuanceDisabled)?;
        let access = self
            .context_authority
            .as_ref()
            .ok_or(RuntimeServiceError::PermitIssuanceDisabled)?;
        let root = std::fs::File::open(self.dependencies.output_root())?;
        Ok(
            DurablePermitStore::from_dir_fd(&root)?.issue_scoped_external_permit(
                access,
                verifier,
                witness,
                context,
                || self.dependencies.clock().now(),
            )?,
        )
    }

    pub fn consume_scoped_external_permit(
        &self,
        permit: &recursive_agent_policy::ScopedExecutionPermitV1,
        call: &ToolCallSpecV1,
    ) -> Result<recursive_agent_policy::ScopedPermitPreflightV1, RuntimeServiceError> {
        let verifier = self
            .production_approval_verifier
            .as_ref()
            .ok_or(RuntimeServiceError::PermitIssuanceDisabled)?;
        let access = self
            .context_authority
            .as_ref()
            .ok_or(RuntimeServiceError::PermitIssuanceDisabled)?;
        let root = std::fs::File::open(self.dependencies.output_root())?;
        Ok(
            DurablePermitStore::from_dir_fd(&root)?.consume_scoped_external_permit(
                access,
                verifier,
                permit,
                call,
                || self.dependencies.clock().now(),
            )?,
        )
    }

    pub fn transition_context_authority(
        &self,
        request: &recursive_agent_policy::ContextTransitionRequestV1,
    ) -> Result<recursive_agent_policy::ContextTransitionReceiptV1, RuntimeServiceError> {
        let access = self
            .context_authority
            .as_ref()
            .ok_or(RuntimeServiceError::PermitIssuanceDisabled)?;
        let root = std::fs::File::open(self.dependencies.output_root())?;
        Ok(
            DurablePermitStore::from_dir_fd(&root)?.transition_context_authority(
                access,
                request,
                || self.dependencies.clock().now(),
                None,
            )?,
        )
    }

    pub fn read_scoped_external_permit(
        &self,
        permit: &recursive_agent_policy::ScopedExecutionPermitV1,
    ) -> Result<recursive_agent_policy::ScopedPermitRecordV1, RuntimeServiceError> {
        let root = std::fs::File::open(self.dependencies.output_root())?;
        Ok(DurablePermitStore::from_dir_fd(&root)?.read_scoped_external_permit(permit)?)
    }

    pub fn read_context_authority(
        &self,
        incarnation: &recursive_agent_contracts::ContentDigest,
        scope: &recursive_agent_policy::ContextScopeV1,
    ) -> Result<recursive_agent_policy::ContextAuthoritySnapshotV1, RuntimeServiceError> {
        let root = std::fs::File::open(self.dependencies.output_root())?;
        Ok(DurablePermitStore::from_dir_fd(&root)?.read_context_authority(incarnation, scope)?)
    }

    pub fn read_context_transition(
        &self,
        request: &recursive_agent_policy::ContextTransitionRequestV1,
    ) -> Result<Option<recursive_agent_policy::ContextTransitionReceiptV1>, RuntimeServiceError>
    {
        let root = std::fs::File::open(self.dependencies.output_root())?;
        Ok(DurablePermitStore::from_dir_fd(&root)?.read_context_transition(request)?)
    }

    pub fn settle_scoped_external_permit(
        &self,
        permit: &recursive_agent_policy::ScopedExecutionPermitV1,
        preflight_digest: &recursive_agent_contracts::ContentDigest,
        reported: ReportedEffectOutcomeV1,
    ) -> Result<PermitOutcomeReceiptV1, RuntimeServiceError> {
        let root = std::fs::File::open(self.dependencies.output_root())?;
        Ok(
            DurablePermitStore::from_dir_fd(&root)?.settle_scoped_external_permit(
                permit,
                preflight_digest,
                reported,
                || self.dependencies.clock().now(),
            )?,
        )
    }

    pub fn issue_production_permit(
        &self,
        witness: &ProductionApprovalWitnessV1,
    ) -> Result<recursive_agent_policy::ExecutionPermitV1, RuntimeServiceError> {
        let verifier = self
            .production_approval_verifier
            .as_ref()
            .ok_or(RuntimeServiceError::PermitIssuanceDisabled)?;
        let now = self.dependencies.clock().now();
        let binding = verifier.verify_and_build_binding(witness, now)?;
        let root = std::fs::File::open(self.dependencies.output_root())?;
        let permits = DurablePermitStore::from_dir_fd(&root)?;
        let candidate =
            recursive_agent_policy::ExecutionPermitV1::effect(binding.clone(), Vec::new())?;
        if permits.state(&candidate.permit_id).is_ok() {
            return Err(RuntimeServiceError::Policy(
                PolicyError::PermitStateConflict,
            ));
        }
        Ok(permits.issue(&binding, now)?)
    }

    /// Narrow test-only issuance; policy reconstructs every binding field.
    pub fn issue_approved_echo_permit(
        &self,
        request: &PermitApprovalRequestV1,
        approval: &OperatorApprovalWitnessV1,
    ) -> Result<recursive_agent_policy::ExecutionPermitV1, RuntimeServiceError> {
        let verifier = self
            .operator_approval_verifier
            .as_ref()
            .ok_or(RuntimeServiceError::PermitIssuanceDisabled)?;
        let now = self.dependencies.clock().now();
        let binding = verifier.verify_and_build_echo_binding(request, approval, now)?;
        let root = std::fs::File::open(self.dependencies.output_root())?;
        let permits = DurablePermitStore::from_dir_fd(&root)?;
        let candidate =
            recursive_agent_policy::ExecutionPermitV1::effect(binding.clone(), Vec::new())?;
        if permits.state(&candidate.permit_id).is_ok() {
            return Err(RuntimeServiceError::Policy(
                PolicyError::PermitStateConflict,
            ));
        }
        Ok(permits.issue(&binding, now)?)
    }

    /// Return a cloneable handle to this service's one physical-admission owner.
    /// The handle shares state; it is not a copied scheduler or capacity pool.
    pub fn managed_admission_domain(&self) -> ManagedAdmissionDomain {
        self.admission.clone()
    }

    /// Record one accepted IPC connection independently of physical workers.
    pub fn managed_ipc_connection_opened(&self) -> Result<(), RuntimeServiceError> {
        self.admission
            .connection_opened()
            .map_err(map_admission_error)
    }

    /// Release one accepted IPC connection independently of physical workers.
    pub fn managed_ipc_connection_closed(&self) -> Result<(), RuntimeServiceError> {
        self.admission
            .connection_closed()
            .map_err(map_admission_error)
    }

    /// Attach a durable scheduler control projection (non-breaking; callers
    /// that do not need durability can keep using [`Self::new`]).
    pub fn with_scheduler(self, store: crate::SchedulerStore) -> Result<Self, RuntimeServiceError> {
        let mut guard = self
            .scheduler
            .lock()
            .map_err(|_| RuntimeServiceError::StatePoisoned)?;
        *guard = Some(store);
        drop(guard);
        Ok(self)
    }

    /// Atomically consume one pre-issued permit and persist daemon-owned
    /// preflight evidence. The exact action and argument digests are rebuilt
    /// from `call`; caller-provided digest fields cannot authorize a different
    /// effect.
    pub fn consume_external_permit(
        &self,
        permit_id: &CurrentPermitId,
        binding: &recursive_agent_policy::PermitBindingV1,
        call: &ToolCallSpecV1,
    ) -> Result<PermitPreflightReceiptV1, RuntimeServiceError> {
        let mut dispatch = binding.clone();
        dispatch.tool = call.tool.clone();
        dispatch.action_digest = content_digest(call)?;
        dispatch.args_digest = content_digest(&call.args)?;
        let root = std::fs::File::open(self.dependencies.output_root())?;
        let permits = DurablePermitStore::from_dir_fd(&root)?;
        Ok(permits
            .consume_with_preflight(permit_id, &dispatch, || self.dependencies.clock().now())?)
    }

    /// Read persisted external permit receipts without granting dispatch or retry.
    pub fn read_external_permit(
        &self,
        permit_id: &CurrentPermitId,
        binding: &recursive_agent_policy::PermitBindingV1,
        preflight_receipt_digest: Option<&recursive_agent_contracts::ContentDigest>,
    ) -> Result<recursive_agent_policy::ExternalPermitReadbackV1, RuntimeServiceError> {
        let root = std::fs::File::open(self.dependencies.output_root())?;
        let permits = DurablePermitStore::from_dir_fd(&root)?;
        Ok(permits.read_external_permit(permit_id, binding, preflight_receipt_digest)?)
    }

    /// Persist a bounded executor-reported outcome bound to a consumed
    /// preflight receipt. A reported success is not external confirmation.
    pub fn record_external_permit_outcome(
        &self,
        permit_id: &CurrentPermitId,
        preflight_receipt_digest: &recursive_agent_contracts::ContentDigest,
        reported: ReportedEffectOutcomeV1,
    ) -> Result<PermitOutcomeReceiptV1, RuntimeServiceError> {
        let root = std::fs::File::open(self.dependencies.output_root())?;
        let permits = DurablePermitStore::from_dir_fd(&root)?;
        Ok(permits.record_reported_outcome(
            permit_id,
            preflight_receipt_digest,
            reported,
            self.dependencies.clock().now(),
        )?)
    }

    /// Return the configured active-leaf ceiling owned by this service.
    pub fn active_leaf_config(&self) -> crate::ActiveLeafConfigV1 {
        self.dependencies.active_leaf_config()
    }

    /// Read the service-owned global queue/lane/draining projection. This is
    /// operational state, not execution receipt truth.
    pub fn managed_admission_snapshot(
        &self,
    ) -> Result<crate::ManagedAdmissionSnapshotV1, RuntimeServiceError> {
        self.admission.snapshot().map_err(map_admission_error)
    }

    /// Apply an explicitly versioned managed admission configuration. Existing
    /// reservations retain their original budgets and drain under the new cap.
    pub fn reconfigure_managed_admission(
        &self,
        config: crate::ManagedAdmissionConfigV1,
    ) -> Result<(), RuntimeServiceError> {
        self.admission
            .reconfigure(config)
            .map_err(map_admission_error)
    }

    /// Execute a direct V1 root operation's own declared steps, then retain
    /// its lifecycle permit and parent chain as an appendable, runtime-owned
    /// V2 child-admission session. `submit` deliberately does not use this
    /// path and keeps its terminal-only V1 contract.
    pub fn begin_parent_v2(
        &self,
        operation: &OperationEnvelopeV1,
    ) -> Result<RuntimeLiveParentV2<'_>, RuntimeServiceError> {
        operation.validate()?;
        self.require_registered_tools(&operation.run_spec.steps)?;
        let operation_id = derive_operation_id(operation)?;
        let active = self.acquire_active_operation(operation_id.to_string(), &operation.budget)?;
        let executor = AdmittedToolExecutor {
            runtime: self.dependencies.tool_runtime(),
        };
        let mut parent = run_live_parent_spec_with_run_id(
            operation,
            self.dependencies.output_root(),
            self.dependencies.clock(),
            operation_id.clone(),
            &executor,
        )?;
        let (not_before, expires_at) = parent.parent_control_window()?;
        let budget = permit_budget(&operation.budget);
        parent.configure_family(
            self.dependencies.output_root(),
            FamilyRootGrantV1 {
                root_operation_id: operation_id.clone(),
                parent_control_permit_id: parent.lifecycle_permit_id().clone(),
                actor: ActorPrincipalV1::try_new(operation.actor.principal.clone())
                    .map_err(RunError::Policy)?,
                policy_version: operation.run_spec.policy_version.clone(),
                effect_budget: budget.clone(),
                child_run_ceiling: ChildRunCeilingV1 {
                    max_depth: 1,
                    max_children: operation.budget.max_steps,
                    family_budget: budget,
                    not_before,
                    expires_at,
                },
            },
        )?;
        let family = parent.family_store()?;
        self.register_live_family(&operation_id, family)?;
        // The parent has finished its physical work and now represents only a
        // durable control/lifecycle boundary. It must not retain scarce leaf
        // capacity while descendants wait or execute.
        active.release().map_err(map_admission_error)?;
        Ok(RuntimeLiveParentV2 {
            service: self,
            parent,
            finalized: false,
        })
    }

    /// Validate and synchronously execute one native V1 operation.
    ///
    /// The returned handle exists only after the runner has committed and strictly
    /// verified terminal evidence. Adapters cannot supply or mint terminal state.
    pub fn submit(
        &self,
        operation: &OperationEnvelopeV1,
    ) -> Result<RuntimeHandleV1, RuntimeServiceError> {
        operation.validate()?;
        for step in &operation.run_spec.steps {
            if self
                .dependencies
                .tool_runtime()
                .registry()
                .get(&step.call.tool)
                .is_none()
            {
                return Err(RuntimeServiceError::ToolNotRegistered {
                    name: step.call.tool.clone(),
                });
            }
        }

        let operation_id = derive_operation_id(operation)?;
        let _guard = self.acquire_active_operation(operation_id.to_string(), &operation.budget)?;

        let tool_executor = AdmittedToolExecutor {
            runtime: self.dependencies.tool_runtime(),
        };
        let summary = run_spec_internal_with_run_id(
            &operation.run_spec,
            self.dependencies.output_root(),
            self.dependencies.clock(),
            &NoopRunnerHook,
            operation_id.clone(),
            &tool_executor,
        )?;

        Ok(RuntimeHandleV1 {
            operation_id,
            run_id: summary.run_id,
            run_dir: summary.run_dir,
        })
    }

    /// Execute one closed V3 provider-egress operation through the native
    /// permit, artifact, and terminal-receipt chain. This entry point exists
    /// only on an explicitly configured candidate runtime; V1/V2/default
    /// submission remains provider-disabled.
    pub fn submit_provider_egress_v3(
        &self,
        operation: &ProviderEgressOperationEnvelopeV3,
    ) -> Result<RuntimeHandleV1, RuntimeServiceError> {
        operation.validate_structure()?;
        let operation_id = derive_provider_egress_operation_id(operation)?;
        let run_dir = self
            .dependencies
            .output_root()
            .join(content_digest(&operation_id)?.to_string());
        if run_dir.is_dir() {
            return self.replay_provider_egress_v3(operation);
        }
        if self
            .dependencies
            .tool_runtime()
            .registry()
            .get("sealed_completion")
            .is_none()
        {
            return Err(RuntimeServiceError::ToolNotRegistered {
                name: "sealed_completion".into(),
            });
        }
        let verifier = self
            .dependencies
            .provider_egress_verifier()
            .ok_or(RuntimeServiceError::ProviderEgressDisabled)?;
        let request: CompletionRequestV1 =
            serde_json::from_value(operation.sealed_completion.arguments.request.clone())
                .map_err(|_| RuntimeServiceError::ProviderRequestMalformed)?;
        if content_digest(&request)? != operation.sealed_completion.arguments.binding.request_digest
        {
            return Err(RuntimeServiceError::ProviderRequestMalformed);
        }
        let binding = &operation.sealed_completion.arguments.binding;
        if !request
            .provider
            .matches_egress_binding(&binding.provider_identity, &binding.model_ref)
        {
            return Err(RuntimeServiceError::ProviderBindingMismatch);
        }
        match self.dependencies.provider() {
            crate::RuntimeProviderDependencyV1::Configured(configured)
                if configured == &request.provider => {}
            crate::RuntimeProviderDependencyV1::Disabled => {
                return Err(RuntimeServiceError::ProviderEgressDisabled);
            }
            crate::RuntimeProviderDependencyV1::Configured(_) => {
                return Err(RuntimeServiceError::ProviderConfigurationMismatch);
            }
        }
        let trusted_now = self.dependencies.clock().now();
        operation.validate_at(trusted_now)?;
        let tool_arguments = serde_json::to_value(&operation.sealed_completion.arguments)
            .map_err(|_| RuntimeServiceError::ProviderRequestMalformed)?;
        let admission_request = ProviderEgressAdmissionRequestV1::new(
            "sealed_completion",
            operation.sealed_completion.arguments.binding.clone(),
            content_digest(&request)?,
            content_digest(&tool_arguments)?,
        )
        .map_err(RunError::Policy)?;
        let admission = authorize_provider_egress(verifier, &admission_request, trusted_now)
            .map_err(RunError::Policy)?;
        let context_bytes =
            u64::from(operation.sealed_completion.arguments.binding.input_tokens).saturating_mul(4);
        let guard = self.acquire_provider_operation(
            operation_id.to_string(),
            &operation.sealed_completion.arguments.binding.model_ref,
            &operation.budget,
            context_bytes,
            u64::from(operation.sealed_completion.arguments.binding.input_tokens).saturating_add(
                u64::from(operation.sealed_completion.arguments.binding.output_reserve),
            ),
        )?;
        guard
            .mark_provider_in_flight()
            .map_err(map_admission_error)?;
        let tool_executor = AdmittedToolExecutor {
            runtime: self.dependencies.tool_runtime(),
        };
        let execution = run_provider_egress_operation_v3_with_run_id(
            operation,
            self.dependencies.output_root(),
            self.dependencies.clock(),
            operation_id.clone(),
            &tool_executor,
            &admission,
        );
        guard
            .mark_provider_complete()
            .map_err(map_admission_error)?;
        let summary = execution?;
        Ok(RuntimeHandleV1 {
            operation_id,
            run_id: summary.run_id,
            run_dir: summary.run_dir,
        })
    }

    /// Read a previously verified V3 result without provider, tool, credential,
    /// current-policy, or current-route access. This is recorded replay only:
    /// absence or corruption fails closed, and no new receipt is appended.
    pub fn replay_provider_egress_v3(
        &self,
        operation: &ProviderEgressOperationEnvelopeV3,
    ) -> Result<RuntimeHandleV1, RuntimeServiceError> {
        operation.validate_structure()?;
        let operation_id = derive_provider_egress_operation_id(operation)?;
        let run_dir = self
            .dependencies
            .output_root()
            .join(content_digest(&operation_id)?.to_string());
        if !run_dir.is_dir() {
            return Err(RuntimeServiceError::ProviderEgressReplayUnavailable);
        }
        self.verify(&operation_id)?;
        Ok(RuntimeHandleV1 {
            operation_id: operation_id.clone(),
            run_id: operation_id,
            run_dir,
        })
    }

    /// Run the bounded autonomous loop inside the canonical runtime owner.
    /// The transcript, memory store, and optional skill registry are explicit
    /// inputs; no provider, tool, or child operation is inferred by this
    /// facade.
    // The explicit dependency list is intentional: memory, skills, transcript,
    // budget, cancellation, planner, and executor remain caller-owned and are
    // not hidden behind a second mutable runtime configuration object.
    #[allow(clippy::too_many_arguments)]
    pub fn run_autonomous<P, E>(
        &self,
        input: serde_json::Value,
        memory: &recursive_agent_memory::MemoryStore,
        skills: Option<&recursive_agent_skills::SkillRegistry>,
        transcript: AutonomousTranscript,
        budget: AutonomousBudgetV1,
        cancellation: &AutonomousCancellation,
        planner: &P,
        executor: &E,
    ) -> Result<AutonomousResultV1, RuntimeServiceError>
    where
        P: AutonomousPlanner,
        E: AutonomousExecutor,
    {
        let mut runner =
            crate::AutonomousRunner::new(memory, skills, transcript, budget, cancellation)?;
        Ok(runner.run(input, planner, executor)?)
    }

    /// Convenience entry point for a closed JSON plan whose intents contain
    /// complete native V1 operation envelopes. Each executed intent still
    /// passes through `RuntimeService::submit` and its strict verification.
    pub fn run_json_autonomous(
        &self,
        input: serde_json::Value,
        memory: &recursive_agent_memory::MemoryStore,
        skills: Option<&recursive_agent_skills::SkillRegistry>,
        transcript: AutonomousTranscript,
        budget: AutonomousBudgetV1,
        cancellation: &AutonomousCancellation,
    ) -> Result<AutonomousResultV1, RuntimeServiceError> {
        let planner = JsonAutonomousPlanner;
        let executor = NativeOperationExecutor::new(self);
        self.run_autonomous(
            input,
            memory,
            skills,
            transcript,
            budget,
            cancellation,
            &planner,
            &executor,
        )
    }

    /// Run a model-backed autonomous loop through the canonical runtime owner.
    /// The provider backend is explicit and injected, allowing deterministic
    /// tests to use a fake completion source while production callers choose
    /// `HttpCompletionBackend` deliberately.
    #[allow(clippy::too_many_arguments)]
    pub fn run_model_autonomous<B: CompletionBackend>(
        &self,
        input: serde_json::Value,
        memory: &recursive_agent_memory::MemoryStore,
        skills: Option<&recursive_agent_skills::SkillRegistry>,
        transcript: AutonomousTranscript,
        budget: AutonomousBudgetV1,
        cancellation: &AutonomousCancellation,
        provider: ProviderSpecV1,
        backend: &B,
        max_tokens: Option<u32>,
    ) -> Result<AutonomousResultV1, RuntimeServiceError> {
        let _ = (
            input,
            memory,
            skills,
            transcript,
            budget,
            cancellation,
            provider,
            backend,
            max_tokens,
        );
        Err(RuntimeServiceError::Autonomous(
            AutonomousError::ProviderEgressPolicyRequired,
        ))
    }

    /// Run a model-backed autonomous loop only after the caller supplies the
    /// current policy/access decision for the exact provider route and context.
    #[allow(clippy::too_many_arguments)]
    pub fn run_model_autonomous_with_egress_authorizer<B: CompletionBackend>(
        &self,
        input: serde_json::Value,
        memory: &recursive_agent_memory::MemoryStore,
        skills: Option<&recursive_agent_skills::SkillRegistry>,
        transcript: AutonomousTranscript,
        budget: AutonomousBudgetV1,
        cancellation: &AutonomousCancellation,
        provider: ProviderSpecV1,
        backend: &B,
        authorizer: &dyn ProviderEgressAuthorizer,
        max_tokens: Option<u32>,
    ) -> Result<AutonomousResultV1, RuntimeServiceError> {
        let planner = ModelAutonomousPlanner::new_with_egress_authorizer(
            backend, provider, authorizer, max_tokens,
        );
        let executor = NativeOperationExecutor::new(self);
        self.run_autonomous(
            input,
            memory,
            skills,
            transcript,
            budget,
            cancellation,
            &planner,
            &executor,
        )
    }

    /// Idempotently submit one native V1 operation (Task 5.4, submit side).
    ///
    /// Binds the canonical request digest to a caller-supplied idempotency key
    /// in the durable scheduler projection:
    ///   - an exact duplicate (same key, same digest) returns the original handle;
    ///   - the same key with a different digest is a typed conflict;
    ///   - a fresh key admits and executes once.
    ///
    /// Requires a scheduler projection (see [`Self::with_scheduler`]).
    pub fn idempotent_submit(
        &self,
        operation: &OperationEnvelopeV1,
        idempotency_key: &str,
    ) -> Result<RuntimeHandleV1, RuntimeServiceError> {
        operation.validate()?;
        for step in &operation.run_spec.steps {
            if self
                .dependencies
                .tool_runtime()
                .registry()
                .get(&step.call.tool)
                .is_none()
            {
                return Err(RuntimeServiceError::ToolNotRegistered {
                    name: step.call.tool.clone(),
                });
            }
        }

        let mut guard = self
            .scheduler
            .lock()
            .map_err(|_| RuntimeServiceError::StatePoisoned)?;
        let store = guard
            .as_mut()
            .ok_or(RuntimeServiceError::IdempotentSubmissionUnavailable)?;

        // Canonical request digest bound to the idempotency-key digest.
        let incoming = derive_operation_id(operation)?.to_string();
        let key_digest = content_digest(&idempotency_key)?.to_string();

        // Existing rows keyed by operation id carry the digest the key was
        // originally bound to. Find a prior binding by its native digest.
        if let Some(prior) = store
            .live_rows()
            .into_iter()
            .find(|row| row.idempotency_key_digest.as_deref() == Some(key_digest.as_str()))
        {
            if prior.operation_id != incoming {
                return Err(RuntimeServiceError::IdempotencyKeyConflict {
                    key: idempotency_key.into(),
                    prior: prior.operation_id,
                    incoming,
                });
            }
            // Exact duplicate: return a handle referencing the prior run.
            let run_id = CurrentRunId::try_new(&prior.operation_id)
                .map_err(|_| RuntimeServiceError::StatePoisoned)?;
            let run_dir = self.run_paths(&run_id)?.root;
            self.verify(&run_id)?;
            return Ok(RuntimeHandleV1 {
                operation_id: run_id.clone(),
                run_id,
                run_dir,
            });
        }

        // Fresh key: admit durably, then execute.
        store
            .admit(&incoming, key_digest)
            .map_err(|_| RuntimeServiceError::StatePoisoned)?;
        drop(guard);
        self.submit(operation)
    }

    /// Stream only ledger-committed events after an optional sequence cursor.
    pub fn events(
        &self,
        run_id: &CurrentRunId,
        after: Option<u64>,
    ) -> Result<Vec<RuntimeEventV1>, RuntimeServiceError> {
        let events = committed_events_directory_bound(&self.run_paths(run_id)?, after)?;
        if let Some(mismatched) = events.iter().find(|event| &event.run_id != run_id) {
            return Err(RuntimeServiceError::RunIdentityMismatch {
                expected: run_id.to_string(),
                observed: mismatched.run_id.to_string(),
            });
        }
        Ok(events)
    }

    /// Return active state or strict ledger-derived terminal state.
    pub fn status(&self, run_id: &CurrentRunId) -> Result<RuntimeStatusV1, RuntimeServiceError> {
        if self.is_active(run_id)? {
            return Ok(RuntimeStatusV1::Active);
        }
        let verification = self.verify(run_id)?;
        Ok(RuntimeStatusV1::Terminal {
            state: verification.terminal_state,
        })
    }

    /// Request cancellation without fabricating a cancellation receipt.
    ///
    /// Active cancellation is durably recorded in the scheduler projection
    /// (when one is attached) and the runtime reports it as requested. When no
    /// scheduler is attached, active cancellation is unavailable and existing
    /// terminal evidence is reported instead.
    pub fn cancel(
        &self,
        run_id: &CurrentRunId,
    ) -> Result<RuntimeCancelResultV1, RuntimeServiceError> {
        match self.status(run_id)? {
            RuntimeStatusV1::Terminal { state } => {
                Ok(RuntimeCancelResultV1::AlreadyTerminal { state })
            }
            RuntimeStatusV1::Active => {
                if let Some(family) = self
                    .live_families
                    .lock()
                    .map_err(|_| RuntimeServiceError::StatePoisoned)?
                    .get(&run_id.to_string())
                    .cloned()
                {
                    family
                        .revoke_parent(self.dependencies.clock().now())
                        .map_err(RunError::Policy)?;
                    self.admission
                        .mark_descendants_draining(&run_id.to_string())
                        .map_err(map_admission_error)?;
                    return Ok(RuntimeCancelResultV1::CancellationRequested {
                        run_id: run_id.to_string(),
                    });
                }
                // Persist a durable cancellation request if a scheduler store
                // is attached; otherwise active cancellation is unavailable.
                let mut guard = self
                    .scheduler
                    .lock()
                    .map_err(|_| RuntimeServiceError::StatePoisoned)?;
                if let Some(store) = guard.as_mut() {
                    store
                        .request_cancel(&run_id.to_string())
                        .map_err(|_| RuntimeServiceError::StatePoisoned)?;
                    self.admission
                        .mark_active_draining(&run_id.to_string())
                        .map_err(map_admission_error)?;
                    Ok(RuntimeCancelResultV1::CancellationRequested {
                        run_id: run_id.to_string(),
                    })
                } else {
                    Err(RuntimeServiceError::ActiveCancellationUnavailable)
                }
            }
        }
    }

    /// Strictly verify the authoritative receipt chain, artifacts, permits, and run binding.
    pub fn verify(&self, run_id: &CurrentRunId) -> Result<ChainVerification, RuntimeServiceError> {
        let paths = self.run_paths(run_id)?;
        let verification = verify_directory_bound(&paths)?;
        if verification.verified_run_id.as_ref() != Some(run_id) {
            return Err(RuntimeServiceError::RunIdentityMismatch {
                expected: run_id.to_string(),
                observed: verification
                    .verified_run_id
                    .as_ref()
                    .map_or_else(|| "none".into(), ToString::to_string),
            });
        }
        let (snapshot, store) = verified_snapshot_with_artifact_store_directory_bound(&paths)?;
        verify_child_links_in_runtime_root(
            &snapshot,
            &store,
            self.dependencies.output_root(),
            true,
        )?;
        Ok(verification)
    }

    fn run_paths(&self, run_id: &CurrentRunId) -> Result<RunPaths, ContractError> {
        Ok(RunPaths::new(
            self.dependencies
                .output_root()
                .join(content_digest(run_id)?.to_string()),
        ))
    }

    fn is_active(&self, run_id: &CurrentRunId) -> Result<bool, RuntimeServiceError> {
        if self
            .admission
            .contains_active(&run_id.to_string())
            .map_err(map_admission_error)?
        {
            return Ok(true);
        }
        // A V2 parent can remain logically active while it is idle between
        // physical leaves. Its family store is the lifecycle owner; it must
        // remain cancellable/status-visible without consuming leaf capacity.
        let families = self
            .live_families
            .lock()
            .map_err(|_| RuntimeServiceError::StatePoisoned)?;
        Ok(families.contains_key(&run_id.to_string()))
    }

    /// Reserve one physical tool leaf under the sole native runtime owner.
    /// Legacy/direct calls retain fail-fast capacity behavior.
    fn acquire_active_operation(
        &self,
        active_key: String,
        budget: &recursive_agent_contracts::OperationBudgetV1,
    ) -> Result<ManagedReservation, RuntimeServiceError> {
        self.acquire_tool_operation(active_key, None, budget)
    }

    fn acquire_child_operation(
        &self,
        active_key: String,
        parent_operation_id: String,
        budget: &recursive_agent_contracts::OperationBudgetV1,
    ) -> Result<ManagedReservation, RuntimeServiceError> {
        self.acquire_tool_operation(active_key, Some(parent_operation_id), budget)
    }

    fn acquire_tool_operation(
        &self,
        active_key: String,
        parent_operation_id: Option<String>,
        budget: &recursive_agent_contracts::OperationBudgetV1,
    ) -> Result<ManagedReservation, RuntimeServiceError> {
        let managed_budget = if parent_operation_id.is_some() {
            // FamilyAuthorityStore owns the actual child-count and effect
            // ceiling. Admission tracks the same family scope without minting a
            // second competing budget authority.
            ManagedBudgetV1 {
                max_attempts: u64::MAX,
                max_wall_time_ms: u64::MAX,
                max_tokens: u64::MAX,
                max_cost_microunits: u64::MAX,
                max_artifact_bytes: u64::MAX,
                max_context_bytes: u64::MAX,
            }
        } else {
            ManagedBudgetV1 {
                max_attempts: 1,
                max_wall_time_ms: budget.max_wall_time_ms,
                max_tokens: u64::MAX,
                max_cost_microunits: u64::MAX,
                max_artifact_bytes: budget.max_artifact_bytes,
                max_context_bytes: 1,
            }
        };
        let mut request =
            ManagedAdmissionRequestV1::tool(active_key, "native-tool-runtime", managed_budget);
        request.parent_operation_id = parent_operation_id.clone();
        request.budget_scope_id = parent_operation_id.map(|parent| format!("family:{parent}"));
        request.estimated_artifact_bytes = budget.max_artifact_bytes;
        let reservation = self
            .admission
            .reserve(request)
            .map_err(map_admission_error)?;
        reservation
            .charge_attempt(0, 0, 0, 0, 0)
            .map_err(map_admission_error)?;
        Ok(reservation)
    }

    /// Queue one provider-backed managed leaf under the same global/lane owner.
    fn acquire_provider_operation(
        &self,
        active_key: String,
        model_ref: &str,
        budget: &recursive_agent_contracts::OperationBudgetV1,
        context_bytes: u64,
        token_reserve: u64,
    ) -> Result<ManagedReservation, RuntimeServiceError> {
        let mut request = ManagedAdmissionRequestV1::provider(
            active_key,
            model_ref,
            ManagedBudgetV1 {
                max_attempts: 1,
                max_wall_time_ms: budget.max_wall_time_ms,
                max_tokens: token_reserve.max(1),
                max_cost_microunits: u64::MAX,
                max_artifact_bytes: budget.max_artifact_bytes,
                max_context_bytes: context_bytes.max(1),
            },
        );
        request.context_bytes = context_bytes;
        request.estimated_artifact_bytes = budget.max_artifact_bytes;
        request.queue_timeout_ms = budget.max_wall_time_ms.min(300_000);
        let reservation = self
            .admission
            .reserve(request)
            .map_err(map_admission_error)?;
        reservation
            .charge_attempt(0, token_reserve, 0, 0, context_bytes)
            .map_err(map_admission_error)?;
        Ok(reservation)
    }

    fn require_registered_tools(
        &self,
        steps: &[recursive_agent_contracts::StepSpecV1],
    ) -> Result<(), RuntimeServiceError> {
        for step in steps {
            if self
                .dependencies
                .tool_runtime()
                .registry()
                .get(&step.call.tool)
                .is_none()
            {
                return Err(RuntimeServiceError::ToolNotRegistered {
                    name: step.call.tool.clone(),
                });
            }
        }
        Ok(())
    }

    fn register_live_family(
        &self,
        parent_id: &CurrentRunId,
        family: FamilyAuthorityStore,
    ) -> Result<(), RuntimeServiceError> {
        let mut families = self
            .live_families
            .lock()
            .map_err(|_| RuntimeServiceError::StatePoisoned)?;
        if families.insert(parent_id.to_string(), family).is_some() {
            return Err(RuntimeServiceError::OperationAlreadyActive {
                operation_id: parent_id.to_string(),
            });
        }
        Ok(())
    }

    fn unregister_live_family(&self, parent_id: &CurrentRunId) -> Result<(), RuntimeServiceError> {
        let mut families = self
            .live_families
            .lock()
            .map_err(|_| RuntimeServiceError::StatePoisoned)?;
        families.remove(&parent_id.to_string());
        Ok(())
    }
}

impl RuntimeLiveParentV2<'_> {
    /// Return the runtime-owned parent run identity for status and cancellation.
    pub fn run_id(&self) -> &CurrentRunId {
        self.parent.run_id()
    }

    /// Durably admit, reserve, link, execute, strictly verify, and close one
    /// V2 child. The proposal has no parent receipt ID, preventing the
    /// self-referential receipt/artifact identity cycle.
    pub fn submit_child(
        &mut self,
        proposal: &ChildOperationProposalV2,
    ) -> Result<RuntimeHandleV1, RuntimeServiceError> {
        if self.finalized {
            return Err(RuntimeServiceError::LiveParentFinalized);
        }
        proposal.validate()?;
        if self.parent.terminal_state() != RunTerminalStateV1::Succeeded {
            return Err(RuntimeServiceError::LiveParentNotAdmissible {
                state: self.parent.terminal_state(),
            });
        }
        let parent_id = self.parent.run_id().clone();
        if proposal.actor.principal != self.parent.parent_actor
            || proposal.causality.parent_operation_id.as_ref() != Some(&parent_id)
            || proposal.causality.root_operation_id.as_ref() != Some(&parent_id)
        {
            return Err(RuntimeServiceError::ChildParentMismatch);
        }
        if self
            .parent
            .family_store()?
            .parent_is_revoked()
            .map_err(RunError::Policy)?
        {
            return Err(RuntimeServiceError::LiveParentNotAdmissible {
                state: RunTerminalStateV1::Cancelled,
            });
        }
        self.service
            .require_registered_tools(&proposal.run_spec.steps)?;
        self.parent.appendable_snapshot()?;

        let proposal_digest = derive_child_operation_proposal_digest(proposal)?;
        let proposal_spec_digest = content_digest(proposal)?;
        let admission_step = child_receipt_step_id(&parent_id, &proposal_digest, "admission")?;
        let admission = self.parent.append_child_receipt(
            ReceiptKindV1::ChildAdmissionPrepared,
            admission_step,
            proposal_spec_digest,
            proposal_digest.clone(),
            Vec::new(),
            self.service.dependencies.clock().now(),
        )?;

        let reread = self.parent.appendable_snapshot()?;
        if !reread.receipts().iter().any(|receipt| {
            receipt.receipt_id == admission.receipt_id
                && receipt.kind == ReceiptKindV1::ChildAdmissionPrepared
                && receipt.args_digest == proposal_digest
        }) {
            return Err(RuntimeServiceError::Ledger(LedgerError::ChildLinkInvalid(
                "parent admission receipt did not survive strict readback".into(),
            )));
        }

        let child_authority = ChildRunAuthorityV1 {
            parent_operation_id: parent_id.clone(),
            root_operation_id: parent_id.clone(),
            parent_control_permit_id: self.parent.lifecycle_permit_id().clone(),
            parent_admission_receipt_id: admission.receipt_id.clone(),
            requested_budget: proposal.budget.clone(),
            child_operation_digest: proposal_digest.clone(),
        };
        let child = ChildOperationEnvelopeV2 {
            schema: proposal.schema,
            actor: proposal.actor.clone(),
            causality: proposal.causality.clone(),
            child_authority,
            budget: proposal.budget.clone(),
            effects: proposal.effects.clone(),
            provenance: proposal.provenance.clone(),
            replay: proposal.replay.clone(),
            run_spec: proposal.run_spec.clone(),
        };
        child.validate()?;
        let child_run_id = derive_child_operation_id(&child)?;
        let _active = self.service.acquire_child_operation(
            child_run_id.to_string(),
            parent_id.to_string(),
            &proposal.budget,
        )?;
        let request = FamilyChildRequestV1 {
            child_run_id: child_run_id.clone(),
            parent_operation_id: parent_id.clone(),
            root_operation_id: parent_id.clone(),
            parent_control_permit_id: self.parent.lifecycle_permit_id().clone(),
            parent_admission_receipt_id: admission.receipt_id.clone(),
            requested_budget: permit_budget(&proposal.budget),
            child_operation_digest: proposal_digest.clone(),
            depth: 1,
        };
        let child_control_permit_id = self
            .parent
            .reserve_child(&request, self.service.dependencies.clock().now())?;
        let child_envelope_digest = content_digest(&child)?;
        let link = ChildRunLinkV1 {
            parent_run_id: parent_id.clone(),
            parent_receipt_id: admission.receipt_id,
            parent_control_permit_id: self.parent.lifecycle_permit_id().clone(),
            child_run_id: child_run_id.clone(),
            child_control_permit_id: child_control_permit_id.clone(),
            root_operation_id: parent_id,
            reserved_budget: proposal.budget.clone(),
            child_envelope_digest,
            child_terminal_receipt_id: None,
            child_terminal_state: None,
            child_chain_head: None,
            cancelled: false,
        };
        let link_descriptor = recursive_agent_ledger::put_string(
            self.parent.store(),
            &serde_json::to_string(&link).map_err(RunError::Json)?,
        )?;
        self.parent.append_child_receipt(
            ReceiptKindV1::ChildLinked,
            child_receipt_step_id(&link.parent_run_id, &proposal_digest, "link")?,
            link.child_envelope_digest.clone(),
            proposal_digest.clone(),
            vec![link_descriptor],
            self.service.dependencies.clock().now(),
        )?;
        self.parent.appendable_snapshot()?;

        let executor = AdmittedToolExecutor {
            runtime: self.service.dependencies.tool_runtime(),
        };
        let summary = run_child_spec_with_run_id(
            &child.run_spec,
            self.service.dependencies.output_root(),
            self.service.dependencies.clock(),
            child_run_id.clone(),
            &executor,
            self.parent.family_store()?,
            child_control_permit_id,
        )?;
        let verification = self.service.verify(&child_run_id)?;
        let child_snapshot =
            verified_snapshot_directory_bound(&self.service.run_paths(&child_run_id)?)?;
        let child_terminal = child_snapshot.receipts().last().ok_or_else(|| {
            RuntimeServiceError::Ledger(LedgerError::ChildLinkInvalid(
                "strictly verified child transcript is empty".into(),
            ))
        })?;
        if child_terminal.kind != ReceiptKindV1::RunFinalized {
            return Err(RuntimeServiceError::Ledger(LedgerError::ChildLinkInvalid(
                "strictly verified child lacks terminal receipt".into(),
            )));
        }
        let closure = ChildRunLinkV1 {
            child_terminal_receipt_id: Some(child_terminal.receipt_id.clone()),
            child_terminal_state: Some(verification.terminal_state),
            child_chain_head: Some(verification.final_head.clone()),
            ..link
        };
        let closure_descriptor = recursive_agent_ledger::put_string(
            self.parent.store(),
            &serde_json::to_string(&closure).map_err(RunError::Json)?,
        )?;
        self.parent.append_child_receipt(
            ReceiptKindV1::ChildClosed,
            child_receipt_step_id(&closure.parent_run_id, &proposal_digest, "closure")?,
            closure.child_envelope_digest.clone(),
            proposal_digest,
            vec![closure_descriptor],
            self.service.dependencies.clock().now(),
        )?;
        self.parent
            .verify_child_links(self.service.dependencies.output_root(), true)?;
        Ok(RuntimeHandleV1 {
            operation_id: child_run_id,
            run_id: summary.run_id,
            run_dir: summary.run_dir,
        })
    }

    /// Reject incomplete, duplicated, or unverified child closure evidence
    /// before revoking the parent lifecycle permit and appending `RunFinalized`.
    pub fn finalize(&mut self) -> Result<RuntimeHandleV1, RuntimeServiceError> {
        if self.finalized {
            return Err(RuntimeServiceError::LiveParentFinalized);
        }
        self.parent
            .verify_child_links(self.service.dependencies.output_root(), true)?;
        let family = self.parent.family_store()?;
        if family.parent_is_revoked().map_err(RunError::Policy)? {
            self.parent
                .mark_cancelled(self.service.dependencies.clock())?;
        } else {
            family
                .revoke_parent(self.service.dependencies.clock().now())
                .map_err(RunError::Policy)?;
        }
        let summary = self
            .parent
            .finish_chain(self.service.dependencies.clock())?;
        self.service.verify(&summary.run_id)?;
        self.service.unregister_live_family(&summary.run_id)?;
        self.finalized = true;
        Ok(RuntimeHandleV1 {
            operation_id: summary.run_id.clone(),
            run_id: summary.run_id,
            run_dir: summary.run_dir,
        })
    }
}

impl Drop for RuntimeLiveParentV2<'_> {
    fn drop(&mut self) {
        if !self.finalized {
            if let Ok(family) = self.parent.family_store() {
                let _ = family.revoke_parent(self.service.dependencies.clock().now());
            }
        }
        let _ = self.service.unregister_live_family(self.parent.run_id());
    }
}

fn permit_budget(budget: &recursive_agent_contracts::OperationBudgetV1) -> PermitBudgetV1 {
    PermitBudgetV1 {
        max_wall_time_ms: budget.max_wall_time_ms,
        max_output_bytes: budget.max_output_bytes,
        max_artifact_bytes: budget.max_artifact_bytes,
    }
}

fn child_receipt_step_id(
    parent_run_id: &CurrentRunId,
    proposal_digest: &recursive_agent_contracts::ContentDigest,
    phase: &str,
) -> Result<recursive_agent_contracts::CurrentStepId, ContractError> {
    let call = ToolCallSpecV1 {
        tool: format!("runner.child.{phase}"),
        args: serde_json::json!({"proposal_digest": proposal_digest}),
        frozen_clock: None,
    };
    derive_step_id(parent_run_id, usize::MAX, &format!("child-{phase}"), &call)
}

fn map_admission_error(error: ManagedAdmissionError) -> RuntimeServiceError {
    match error {
        ManagedAdmissionError::DuplicateOperation(operation_id) => {
            RuntimeServiceError::OperationAlreadyActive { operation_id }
        }
        ManagedAdmissionError::Capacity { configured }
        | ManagedAdmissionError::SimultaneousCapacity { configured, .. } => {
            RuntimeServiceError::ActiveLeafCapacityExceeded { configured }
        }
        ManagedAdmissionError::StatePoisoned => RuntimeServiceError::StatePoisoned,
        other => RuntimeServiceError::ManagedAdmission(other),
    }
}
