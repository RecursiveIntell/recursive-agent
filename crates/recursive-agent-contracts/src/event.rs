use crate::{
    validate_receipt_sequence, ArtifactDescriptorV1, ContractError, CurrentReceiptId, CurrentRunId,
    CurrentStepId, LifecycleValidationMode, ReceiptKindV1, ReceiptOutcomeV1, ReceiptV1,
};
use serde::{Deserialize, Serialize};

/// Exact version tag for committed runtime-event projections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeEventSchemaV1 {
    /// The only admitted runtime-event schema in Phase 2.
    #[serde(rename = "recursive-agent.runtime-event/v1")]
    V1,
}

/// Closed runtime-event projection of one authoritative ledger receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeEventKindV1 {
    /// The run was durably admitted to its receipt chain.
    Submitted,
    /// A step entered execution lifecycle.
    Started {
        /// Step whose lifecycle started.
        step_id: CurrentStepId,
    },
    /// A capability permit was durably issued.
    AuthorizationIssued {
        /// Step governed by the permit.
        step_id: CurrentStepId,
    },
    /// An issued permit was durably consumed before effects.
    Authorized {
        /// Step authorized for dispatch.
        step_id: CurrentStepId,
    },
    /// An issued permit was rejected.
    AuthorizationRejected {
        /// Step whose authorization failed.
        step_id: CurrentStepId,
    },
    /// A permit was durably revoked or closed.
    AuthorizationRevoked {
        /// Step whose permit was revoked.
        step_id: CurrentStepId,
    },
    /// Artifact bytes were committed before being exposed to clients.
    OutputCommitted {
        /// Step that produced the artifacts.
        step_id: CurrentStepId,
        /// Ledger-verified artifact descriptors.
        artifacts: Vec<ArtifactDescriptorV1>,
    },
    /// A step completed with committed artifact evidence.
    StepCompleted {
        /// Completed step.
        step_id: CurrentStepId,
        /// Artifacts cited by the completion receipt.
        artifacts: Vec<ArtifactDescriptorV1>,
    },
    /// A step reached a terminal non-success outcome.
    Failed {
        /// Failed step.
        step_id: CurrentStepId,
        /// Exact terminal receipt outcome.
        outcome: ReceiptOutcomeV1,
    },
    /// The run reached its authoritative terminal state.
    Completed {
        /// Exact terminal receipt outcome, including non-success states.
        outcome: ReceiptOutcomeV1,
    },
}

/// Monotonic client-facing projection of one committed ledger transition.
///
/// `evidence_receipt` is both the event's durable identity and its backing
/// evidence reference. `causal_parent` is the preceding committed receipt ID,
/// avoiding a second material-ID family or authoritative event store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEventV1 {
    /// Exact closed event schema version.
    pub schema: RuntimeEventSchemaV1,
    /// Authoritative run identity from the backing receipt.
    pub run_id: CurrentRunId,
    /// Zero-based contiguous position in the committed receipt transcript.
    pub sequence: u64,
    /// Prior committed event/receipt identity, absent only for sequence zero.
    pub causal_parent: Option<CurrentReceiptId>,
    /// Typed lifecycle projection.
    pub kind: RuntimeEventKindV1,
    /// Authoritative receipt that proves this event.
    pub evidence_receipt: CurrentReceiptId,
}

/// Project validated authoritative receipts into committed runtime events.
pub fn project_runtime_events(
    receipts: &[ReceiptV1],
) -> Result<Vec<RuntimeEventV1>, ContractError> {
    validate_receipt_sequence(receipts, LifecycleValidationMode::AppendInProgress)?;
    receipts
        .iter()
        .enumerate()
        .map(|(index, receipt)| {
            let sequence = u64::try_from(index).map_err(|_| {
                ContractError::Malformed("runtime event sequence exceeds u64".into())
            })?;
            Ok(RuntimeEventV1 {
                schema: RuntimeEventSchemaV1::V1,
                run_id: receipt.run_id.clone(),
                sequence,
                causal_parent: index
                    .checked_sub(1)
                    .map(|previous| receipts[previous].receipt_id.clone()),
                kind: event_kind(receipt),
                evidence_receipt: receipt.receipt_id.clone(),
            })
        })
        .collect()
}

/// Validate that events are exactly the projection of the supplied committed
/// receipts. Missing, duplicate, reordered, wrong-parent, post-terminal, and
/// receipt-less events all fail closed.
pub fn validate_runtime_event_sequence(
    events: &[RuntimeEventV1],
    committed_receipts: &[ReceiptV1],
) -> Result<(), ContractError> {
    let expected = project_runtime_events(committed_receipts)?;
    if events != expected {
        return Err(ContractError::Malformed(
            "runtime events do not exactly match committed receipt evidence".into(),
        ));
    }
    Ok(())
}

fn event_kind(receipt: &ReceiptV1) -> RuntimeEventKindV1 {
    match receipt.kind {
        ReceiptKindV1::RunStarted => RuntimeEventKindV1::Submitted,
        ReceiptKindV1::StepStarted => RuntimeEventKindV1::Started {
            step_id: receipt.step_id.clone(),
        },
        ReceiptKindV1::PermitIssued => RuntimeEventKindV1::AuthorizationIssued {
            step_id: receipt.step_id.clone(),
        },
        ReceiptKindV1::PermitConsumed => RuntimeEventKindV1::Authorized {
            step_id: receipt.step_id.clone(),
        },
        ReceiptKindV1::PermitRejected => RuntimeEventKindV1::AuthorizationRejected {
            step_id: receipt.step_id.clone(),
        },
        ReceiptKindV1::PermitRevoked => RuntimeEventKindV1::AuthorizationRevoked {
            step_id: receipt.step_id.clone(),
        },
        ReceiptKindV1::ArtifactStored => RuntimeEventKindV1::OutputCommitted {
            step_id: receipt.step_id.clone(),
            artifacts: receipt.artifact_refs.clone(),
        },
        ReceiptKindV1::StepCompleted => RuntimeEventKindV1::StepCompleted {
            step_id: receipt.step_id.clone(),
            artifacts: receipt.artifact_refs.clone(),
        },
        ReceiptKindV1::StepFailed => RuntimeEventKindV1::Failed {
            step_id: receipt.step_id.clone(),
            outcome: receipt.outcome.clone(),
        },
        ReceiptKindV1::RunFinalized => RuntimeEventKindV1::Completed {
            outcome: receipt.outcome.clone(),
        },
    }
}
