use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use llm_tool_runtime::{
    ToolBudgetContext, ToolCall, ToolCtx, ToolOriginKind, ToolPlannerStage, ToolRetryOwner,
    ToolRuntime,
};
use recursive_agent_contracts::{
    content_digest, derive_child_operation_id, derive_child_operation_proposal_digest,
    derive_operation_id, derive_step_id, ChildOperationEnvelopeV2, ChildOperationProposalV2,
    ChildRunAuthorityV1, ContractError, CurrentRunId, OperationEnvelopeV1, ReceiptKindV1,
    RunTerminalStateV1, RuntimeEventV1, ToolCallSpecV1,
};
use recursive_agent_ledger::{
    committed_events_directory_bound, verified_snapshot_directory_bound,
    verified_snapshot_with_artifact_store_directory_bound, verify_child_links_in_runtime_root,
    verify_directory_bound, ChainVerification, ChildRunLinkV1, LedgerError, RunPaths,
};
use recursive_agent_policy::{
    ActorPrincipalV1, ChildRunCeilingV1, FamilyAuthorityStore, FamilyChildRequestV1,
    FamilyRootGrantV1, PermitBudgetV1, PermitEvidenceV1,
};
use stack_ids::{AttemptId, TraceCtx, TrialId};
use thiserror::Error;

use crate::{
    run_child_spec_with_run_id, run_live_parent_spec_with_run_id, run_spec_internal_with_run_id,
    LiveParentRun, NoopRunnerHook, RunError, RunnerToolExecutor, RunnerToolOutput,
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
    _active: ActiveOperationGuard<'a>,
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
    /// The same operation is already executing through this service instance.
    #[error("operation is already active: {operation_id}")]
    OperationAlreadyActive {
        /// Canonical operation identity.
        operation_id: String,
    },
    /// Internal concurrent state was poisoned; the service fails closed.
    #[error("runtime service state is poisoned")]
    StatePoisoned,
    /// Active cancellation is intentionally unavailable until the durable scheduler owns it.
    #[error("active cancellation requires the Phase-5 durable scheduler")]
    ActiveCancellationUnavailable,
    /// The authoritative runner rejected or failed the operation.
    #[error("run: {0}")]
    Run(#[from] RunError),
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
                        runtime.block_on(self.runtime.execute(&context, &owner_call, None, None)),
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
    active_operations: Mutex<BTreeSet<String>>,
    /// Live-parent cancellation reaches the family authority directly; this is
    /// authority state, not a scheduler projection.
    live_families: Mutex<BTreeMap<String, FamilyAuthorityStore>>,
    /// Optional durable scheduler control projection (Phase 5). When present,
    /// cancellation and admission are persisted across restarts.
    scheduler: std::sync::Mutex<Option<crate::SchedulerStore>>,
}

impl RuntimeService {
    /// Construct a service from a complete, previously admitted dependency set.
    pub fn new(dependencies: RuntimeDependencies) -> Self {
        Self {
            dependencies,
            active_operations: Mutex::new(BTreeSet::new()),
            live_families: Mutex::new(BTreeMap::new()),
            scheduler: std::sync::Mutex::new(None),
        }
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
        let active_key = operation_id.to_string();
        {
            let mut active = self
                .active_operations
                .lock()
                .map_err(|_| RuntimeServiceError::StatePoisoned)?;
            if !active.insert(active_key.clone()) {
                return Err(RuntimeServiceError::OperationAlreadyActive {
                    operation_id: active_key,
                });
            }
        }
        let active = ActiveOperationGuard {
            active_operations: &self.active_operations,
            active_key,
            released: false,
        };
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
        Ok(RuntimeLiveParentV2 {
            service: self,
            parent,
            finalized: false,
            _active: active,
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
        let active_key = operation_id.to_string();
        {
            let mut active = self
                .active_operations
                .lock()
                .map_err(|_| RuntimeServiceError::StatePoisoned)?;
            if !active.insert(active_key.clone()) {
                return Err(RuntimeServiceError::OperationAlreadyActive {
                    operation_id: active_key,
                });
            }
        }
        let _guard = ActiveOperationGuard {
            active_operations: &self.active_operations,
            active_key,
            released: false,
        };

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

        // Canonical request digest bound to the idempotency key.
        let incoming = derive_operation_id(operation)?.to_string();

        // Existing rows keyed by operation id carry the digest the key was
        // originally bound to. Find a prior binding by idempotency key.
        if let Some(prior) = store
            .live_rows()
            .into_iter()
            .find(|row| row.idempotency_key_digest.as_deref() == Some(idempotency_key))
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
            return Ok(RuntimeHandleV1 {
                operation_id: run_id.clone(),
                run_id,
                run_dir: prior.operation_id.into(),
            });
        }

        // Fresh key: admit durably, then execute.
        store
            .admit(&incoming, idempotency_key.to_string())
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
        let active = self
            .active_operations
            .lock()
            .map_err(|_| RuntimeServiceError::StatePoisoned)?;
        Ok(active.contains(&run_id.to_string()))
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
            return Err(RuntimeServiceError::LiveParentNotAdmissible {
                state: RunTerminalStateV1::Cancelled,
            });
        }
        family
            .revoke_parent(self.service.dependencies.clock().now())
            .map_err(RunError::Policy)?;
        let summary = self
            .parent
            .finish_chain(self.service.dependencies.clock())?;
        self.service.verify(&summary.run_id)?;
        self.service.unregister_live_family(&summary.run_id)?;
        self.finalized = true;
        self._active.release();
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

struct ActiveOperationGuard<'a> {
    active_operations: &'a Mutex<BTreeSet<String>>,
    active_key: String,
    released: bool,
}

impl ActiveOperationGuard<'_> {
    fn release(&mut self) {
        if !self.released {
            if let Ok(mut active) = self.active_operations.lock() {
                active.remove(&self.active_key);
            }
            self.released = true;
        }
    }
}

impl Drop for ActiveOperationGuard<'_> {
    fn drop(&mut self) {
        self.release();
    }
}
