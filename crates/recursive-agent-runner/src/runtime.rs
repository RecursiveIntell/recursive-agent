use std::collections::BTreeSet;
use std::sync::Mutex;

use llm_tool_runtime::{
    ToolBudgetContext, ToolCall, ToolCtx, ToolOriginKind, ToolPlannerStage, ToolRetryOwner,
    ToolRuntime,
};
use recursive_agent_contracts::{
    content_digest, derive_operation_id, derive_run_id, ContractError, CurrentRunId,
    OperationEnvelopeV1, RunTerminalStateV1, RuntimeEventV1,
};
use recursive_agent_ledger::{
    committed_events_directory_bound, verify_directory_bound, ChainVerification, LedgerError,
    RunPaths,
};
use recursive_agent_policy::PermitEvidenceV1;
use stack_ids::{AttemptId, TraceCtx, TrialId};
use thiserror::Error;

use crate::{
    run_spec_internal_with_run_id, Clock, LegacyToolExecutor, NoopRunnerHook, RunError, RunSummary,
    RunnerToolExecutor, RunnerToolOutput, RuntimeDependencies,
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

    /// Compatibility-only V1 admission for deprecated `RunSpecV1` entrypoints.
    ///
    /// This is crate-private so adapters cannot choose the legacy executor or
    /// bypass the complete dependency set required by [`Self::submit`]. Phase 6
    /// removes this path with the deprecated wrappers.
    pub(crate) fn submit_legacy_run_spec(
        operation: &OperationEnvelopeV1,
        output_root: &std::path::Path,
        clock: &dyn Clock,
    ) -> Result<RunSummary, RunError> {
        operation.validate()?;
        let run_id = derive_run_id(&operation.run_spec)?;
        run_spec_internal_with_run_id(
            &operation.run_spec,
            output_root,
            clock,
            &NoopRunnerHook,
            run_id,
            &LegacyToolExecutor,
        )
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
        let verification = verify_directory_bound(&self.run_paths(run_id)?)?;
        if verification.verified_run_id.as_ref() != Some(run_id) {
            return Err(RuntimeServiceError::RunIdentityMismatch {
                expected: run_id.to_string(),
                observed: verification
                    .verified_run_id
                    .as_ref()
                    .map_or_else(|| "none".into(), ToString::to_string),
            });
        }
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
}

struct ActiveOperationGuard<'a> {
    active_operations: &'a Mutex<BTreeSet<String>>,
    active_key: String,
}

impl Drop for ActiveOperationGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active_operations.lock() {
            active.remove(&self.active_key);
        }
    }
}
