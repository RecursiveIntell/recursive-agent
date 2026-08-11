use crate::{
    ContentDigest, ContractError, CurrentRunId, KernelRunId, RunSpecV1, MAX_RUN_NAME_BYTES,
    MAX_RUN_SPEC_INPUT_BYTES, MAX_RUN_SPEC_MATERIAL_BYTES, MAX_RUN_SPEC_STEPS,
    MAX_SHELL_OUTPUT_BYTES, MAX_SHELL_PATH_BYTES, MAX_SHELL_ROOTS_PER_MODE, MAX_SHELL_TIMEOUT_MS,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Typed failures from hostile operation-envelope byte ingress.
#[derive(Debug, Error)]
pub enum OperationIngressError {
    /// Raw attacker input exceeded the admitted byte ceiling.
    #[error("operation envelope input exceeds the byte limit of {maximum_bytes}")]
    InputTooLarge { maximum_bytes: u64 },
    /// An object repeated a key before typed decoding.
    #[error("operation envelope contains a duplicate object key")]
    DuplicateKey,
    /// JSON shape, schema, current IDs, or closed fields were invalid.
    #[error("operation envelope is malformed or contains an unknown field")]
    Malformed,
    /// Canonical boundary processing failed or exceeded its material ceiling.
    #[error("operation envelope canonical boundary validation failed")]
    CanonicalBoundary,
    /// Typed field relationships or semantic ceilings were invalid.
    #[error("operation envelope semantic validation failed")]
    Semantic(#[source] ContractError),
}

/// Exact closed tags for native operation envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationSchemaV1 {
    /// Direct root-operation envelope. It cannot carry delegated lineage.
    #[serde(rename = "recursive-agent.operation/v1")]
    V1,
    /// Child-operation envelope with explicit, closed delegation proof.
    #[serde(rename = "recursive-agent.operation/v2")]
    V2,
}

/// Origin class for the authority asserted by an operation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityOriginV1 {
    /// Authority originates directly from the authenticated principal.
    Direct,
    /// Authority is attenuated from an admitted parent operation.
    Delegated,
    /// Authority arrived through a remote admission boundary.
    Remote,
}

/// Actor identity and authority origin carried by an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorAuthorityV1 {
    /// Authenticated principal identifier.
    pub principal: String,
    /// Origin class that determines later admission checks.
    pub origin: AuthorityOriginV1,
}

/// Optional causal linkage to parent and root operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalLinkV1 {
    /// Immediate parent operation when this is a child.
    pub parent_operation_id: Option<CurrentRunId>,
    /// Root operation for a delegated causal family.
    pub root_operation_id: Option<CurrentRunId>,
}

/// Explicit ceilings that bound one operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationBudgetV1 {
    /// Maximum authorized wall-clock duration.
    pub max_wall_time_ms: u64,
    /// Maximum captured stdout and stderr bytes.
    pub max_output_bytes: u64,
    /// Maximum aggregate artifact bytes.
    pub max_artifact_bytes: u64,
    /// Maximum number of admitted steps.
    pub max_steps: u32,
}

/// Immutable admission proof required by every V2 child operation.
///
/// This type deliberately has no defaults and is not embedded as an optional
/// field in the direct V1 envelope. A V1 caller cannot silently acquire
/// child-run semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildRunAuthorityV1 {
    /// Immediate parent operation that admitted this child proposal.
    pub parent_operation_id: CurrentRunId,
    /// Stable root operation for the complete causal family.
    pub root_operation_id: CurrentRunId,
    /// Parent control permit authorized to allocate this child.
    pub parent_control_permit_id: crate::CurrentPermitId,
    /// Committed parent admission receipt authorizing the proposal.
    pub parent_admission_receipt_id: crate::CurrentReceiptId,
    /// Exact budget reserved for this child before dispatch.
    pub requested_budget: OperationBudgetV1,
    /// Digest of the child operation material excluding this proof.
    pub child_operation_digest: ContentDigest,
}

/// Complete declared effect surface for operation admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredEffectsV1 {
    /// Descriptor-safe roots the operation may read.
    pub read_roots: Vec<String>,
    /// Descriptor-safe roots the operation may write.
    pub write_roots: Vec<String>,
    /// Whether network access is requested.
    pub network_allowed: bool,
    /// Digest of the action material authorized for execution.
    pub action_digest: ContentDigest,
}

/// Durable source reference contributing to an operation request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceRefV1 {
    /// Stable source locator or owner-qualified reference.
    pub source: String,
    /// Content digest of the referenced source material.
    pub digest: ContentDigest,
}

/// Behavioral replay class of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayClassV1 {
    /// Re-execution is deterministic under the declared inputs.
    Deterministic,
    /// The operation has effects and replay must use retained evidence.
    RecordedEffect,
    /// The operation cannot be safely replayed.
    NonReplayable,
}

/// Caller intent for execution or retained replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayIntentV1 {
    /// Execute the operation at most once under a fresh permit.
    ExecuteOnce,
    /// Read and verify an already committed transcript without effects.
    ReadRecorded,
}

/// Replay classification and requested behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaySpecV1 {
    /// Replay safety class.
    pub class: ReplayClassV1,
    /// Requested execution or replay behavior.
    pub intent: ReplayIntentV1,
}

/// Canonical native request accepted by the runtime owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationEnvelopeV1 {
    /// Exact closed operation schema version.
    pub schema: OperationSchemaV1,
    /// Authenticated actor and authority origin.
    pub actor: ActorAuthorityV1,
    /// Optional parent/root causal linkage.
    pub causality: CausalLinkV1,
    /// Explicit operation-wide resource ceilings.
    pub budget: OperationBudgetV1,
    /// Declared effect surface and action binding.
    pub effects: DeclaredEffectsV1,
    /// Durable provenance inputs.
    pub provenance: Vec<ProvenanceRefV1>,
    /// Replay classification and intent.
    pub replay: ReplaySpecV1,
    /// Existing bounded run graph carried as payload, not a second model.
    pub run_spec: RunSpecV1,
}

/// Caller-supplied V2 child-operation material before it has a parent admission
/// receipt. This deliberately omits `ChildRunAuthorityV1` so an admission
/// receipt can bind this material without requiring its own ID in the preimage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildOperationProposalV2 {
    /// Must be `recursive-agent.operation/v2`.
    pub schema: OperationSchemaV1,
    /// Delegated actor authority.
    pub actor: ActorAuthorityV1,
    /// Immediate parent and root causal linkage.
    pub causality: CausalLinkV1,
    /// Explicit operation-wide resource ceilings.
    pub budget: OperationBudgetV1,
    /// Declared effect surface and action binding.
    pub effects: DeclaredEffectsV1,
    /// Durable provenance inputs.
    pub provenance: Vec<ProvenanceRefV1>,
    /// Replay classification and intent.
    pub replay: ReplaySpecV1,
    /// Existing bounded run graph carried as payload, not a second model.
    pub run_spec: RunSpecV1,
}

/// Canonical V2 child-operation request accepted only after live-parent
/// admission has created and bound `child_authority`.
///
/// V2 repeats direct operation material rather than placing optional child
/// authority into `OperationEnvelopeV1`: V1 remains a closed root-only
/// contract and V2 cannot be decoded as a V1 request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildOperationEnvelopeV2 {
    /// Must be `recursive-agent.operation/v2`.
    pub schema: OperationSchemaV1,
    /// Delegated actor authority.
    pub actor: ActorAuthorityV1,
    /// Immediate parent and root causal linkage.
    pub causality: CausalLinkV1,
    /// Required, closed child admission proof.
    pub child_authority: ChildRunAuthorityV1,
    /// Explicit operation-wide resource ceilings.
    pub budget: OperationBudgetV1,
    /// Declared effect surface and action binding.
    pub effects: DeclaredEffectsV1,
    /// Durable provenance inputs.
    pub provenance: Vec<ProvenanceRefV1>,
    /// Replay classification and intent.
    pub replay: ReplaySpecV1,
    /// Existing bounded run graph carried as payload, not a second model.
    pub run_spec: RunSpecV1,
}

/// Derive the authoritative run identity from the complete operation material.
///
/// This deliberately reuses the current run-ID owner and domain. The operation
/// envelope replaces the narrower legacy run-spec preimage; it does not create
/// a parallel operation-ID family.
pub fn derive_operation_id(envelope: &OperationEnvelopeV1) -> Result<CurrentRunId, ContractError> {
    derive_operation_identity(envelope)
}

/// Derive the authoritative child-run identity from all V2 material,
/// including its immutable parent-admission proof.
pub fn derive_child_operation_id(
    envelope: &ChildOperationEnvelopeV2,
) -> Result<CurrentRunId, ContractError> {
    derive_operation_identity(envelope)
}

/// Derive the digest that a V2 proposal binds before a parent-admission receipt
/// exists. It is exactly the material later copied into a closed envelope.
pub fn derive_child_operation_proposal_digest(
    proposal: &ChildOperationProposalV2,
) -> Result<ContentDigest, ContractError> {
    crate::content_digest(proposal)
}

/// Derive the digest that a V2 child envelope must carry as its immutable
/// proposal material. The child-authority proof itself is deliberately
/// excluded so the proof can bind this exact proposed operation without a
/// circular identity dependency.
pub fn derive_child_operation_material_digest(
    envelope: &ChildOperationEnvelopeV2,
) -> Result<ContentDigest, ContractError> {
    derive_child_operation_proposal_digest(&ChildOperationProposalV2 {
        schema: envelope.schema,
        actor: envelope.actor.clone(),
        causality: envelope.causality.clone(),
        budget: envelope.budget.clone(),
        effects: envelope.effects.clone(),
        provenance: envelope.provenance.clone(),
        replay: envelope.replay.clone(),
        run_spec: envelope.run_spec.clone(),
    })
}

fn derive_operation_identity<T: Serialize>(envelope: &T) -> Result<CurrentRunId, ContractError> {
    let digest = crate::content_digest(envelope)?;
    let owner = KernelRunId::deterministic(crate::RUN_ID_DOMAIN, digest.hex())
        .map_err(crate::owner_id_error)?;
    CurrentRunId::from_owner(owner)
}

/// Decode hostile bytes into one validated, canonical native operation.
pub fn parse_operation_envelope_bytes(
    input: &[u8],
) -> Result<OperationEnvelopeV1, OperationIngressError> {
    if input.len() as u64 > MAX_RUN_SPEC_INPUT_BYTES {
        return Err(OperationIngressError::InputTooLarge {
            maximum_bytes: MAX_RUN_SPEC_INPUT_BYTES,
        });
    }
    let parsed = serde_json::from_slice::<crate::DuplicateSafeValue>(input).map_err(|error| {
        if error.to_string().contains("duplicate object key") {
            OperationIngressError::DuplicateKey
        } else {
            OperationIngressError::Malformed
        }
    })?;
    let canonical =
        crate::jcs_canonical(&parsed.0).map_err(|_| OperationIngressError::CanonicalBoundary)?;
    if canonical.len() > MAX_RUN_SPEC_MATERIAL_BYTES {
        return Err(OperationIngressError::CanonicalBoundary);
    }
    let envelope = serde_json::from_value::<OperationEnvelopeV1>(parsed.0)
        .map_err(|_| OperationIngressError::Malformed)?;
    envelope
        .validate()
        .map_err(OperationIngressError::Semantic)?;
    Ok(envelope)
}

/// Decode hostile bytes into one validated, closed V2 child operation.
pub fn parse_child_operation_proposal_v2_bytes(
    input: &[u8],
) -> Result<ChildOperationProposalV2, OperationIngressError> {
    if input.len() as u64 > MAX_RUN_SPEC_INPUT_BYTES {
        return Err(OperationIngressError::InputTooLarge {
            maximum_bytes: MAX_RUN_SPEC_INPUT_BYTES,
        });
    }
    let parsed = serde_json::from_slice::<crate::DuplicateSafeValue>(input).map_err(|error| {
        if error.to_string().contains("duplicate object key") {
            OperationIngressError::DuplicateKey
        } else {
            OperationIngressError::Malformed
        }
    })?;
    let canonical =
        crate::jcs_canonical(&parsed.0).map_err(|_| OperationIngressError::CanonicalBoundary)?;
    if canonical.len() > MAX_RUN_SPEC_MATERIAL_BYTES {
        return Err(OperationIngressError::CanonicalBoundary);
    }
    let proposal = serde_json::from_value::<ChildOperationProposalV2>(parsed.0)
        .map_err(|_| OperationIngressError::Malformed)?;
    proposal
        .validate()
        .map_err(OperationIngressError::Semantic)?;
    Ok(proposal)
}

/// Decode hostile bytes into one validated, closed V2 child operation.
pub fn parse_child_operation_envelope_v2_bytes(
    input: &[u8],
) -> Result<ChildOperationEnvelopeV2, OperationIngressError> {
    if input.len() as u64 > MAX_RUN_SPEC_INPUT_BYTES {
        return Err(OperationIngressError::InputTooLarge {
            maximum_bytes: MAX_RUN_SPEC_INPUT_BYTES,
        });
    }
    let parsed = serde_json::from_slice::<crate::DuplicateSafeValue>(input).map_err(|error| {
        if error.to_string().contains("duplicate object key") {
            OperationIngressError::DuplicateKey
        } else {
            OperationIngressError::Malformed
        }
    })?;
    let canonical =
        crate::jcs_canonical(&parsed.0).map_err(|_| OperationIngressError::CanonicalBoundary)?;
    if canonical.len() > MAX_RUN_SPEC_MATERIAL_BYTES {
        return Err(OperationIngressError::CanonicalBoundary);
    }
    let envelope = serde_json::from_value::<ChildOperationEnvelopeV2>(parsed.0)
        .map_err(|_| OperationIngressError::Malformed)?;
    envelope
        .validate()
        .map_err(OperationIngressError::Semantic)?;
    Ok(envelope)
}

impl OperationEnvelopeV1 {
    /// Validate operation-wide ceilings before policy, persistence, or effects.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema != OperationSchemaV1::V1 {
            return Err(ContractError::Malformed(
                "V1 operation ingress requires the exact V1 schema tag".into(),
            ));
        }
        if self.actor.origin != AuthorityOriginV1::Direct
            || self.causality.parent_operation_id.is_some()
            || self.causality.root_operation_id.is_some()
        {
            return Err(ContractError::Malformed(
                "V1 operation ingress admits only direct root authority".into(),
            ));
        }
        validate_operation_identifier(
            &self.actor.principal,
            "actor.principal",
            MAX_RUN_NAME_BYTES,
        )?;
        validate_operation_provenance(&self.provenance)?;
        validate_declared_effects(&self.run_spec, &self.effects, &self.replay)?;
        validate_operation_budget(&self.budget, &self.run_spec)
    }
}

impl ChildOperationProposalV2 {
    /// Validate delegated child material before a live parent creates its
    /// admission receipt and closed child authority.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema != OperationSchemaV1::V2 {
            return Err(ContractError::Malformed(
                "child operation requires the exact V2 schema tag".into(),
            ));
        }
        if self.actor.origin != AuthorityOriginV1::Delegated {
            return Err(ContractError::Malformed(
                "child operation requires delegated authority origin".into(),
            ));
        }
        validate_operation_identifier(
            &self.actor.principal,
            "actor.principal",
            MAX_RUN_NAME_BYTES,
        )?;
        if self.causality.parent_operation_id.is_none()
            || self.causality.root_operation_id.is_none()
        {
            return Err(ContractError::Malformed(
                "child operation requires parent and root lineage".into(),
            ));
        }
        validate_operation_provenance(&self.provenance)?;
        validate_declared_effects(&self.run_spec, &self.effects, &self.replay)?;
        validate_operation_budget(&self.budget, &self.run_spec)
    }
}

impl ChildOperationEnvelopeV2 {
    /// Validate a closed delegated child-operation proposal before policy or
    /// runtime admission. This proves envelope shape only; the family store
    /// and runner still own permit reservation and parent-receipt verification.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema != OperationSchemaV1::V2 {
            return Err(ContractError::Malformed(
                "child operation requires the exact V2 schema tag".into(),
            ));
        }
        if self.actor.origin != AuthorityOriginV1::Delegated {
            return Err(ContractError::Malformed(
                "child operation requires delegated authority origin".into(),
            ));
        }
        validate_operation_identifier(
            &self.actor.principal,
            "actor.principal",
            MAX_RUN_NAME_BYTES,
        )?;
        let parent = self.causality.parent_operation_id.as_ref().ok_or_else(|| {
            ContractError::Malformed("child operation requires parent lineage".into())
        })?;
        let root = self.causality.root_operation_id.as_ref().ok_or_else(|| {
            ContractError::Malformed("child operation requires root lineage".into())
        })?;
        if parent != &self.child_authority.parent_operation_id
            || root != &self.child_authority.root_operation_id
        {
            return Err(ContractError::Malformed(
                "child authority does not bind causal parent and root lineage".into(),
            ));
        }
        if self.budget != self.child_authority.requested_budget {
            return Err(ContractError::Malformed(
                "child authority budget does not exactly bind the child operation budget".into(),
            ));
        }
        if self.child_authority.child_operation_digest
            != derive_child_operation_material_digest(self)?
        {
            return Err(ContractError::Malformed(
                "child authority digest does not bind the child operation material".into(),
            ));
        }
        validate_operation_provenance(&self.provenance)?;
        validate_declared_effects(&self.run_spec, &self.effects, &self.replay)?;
        validate_operation_budget(&self.budget, &self.run_spec)
    }
}

fn validate_operation_provenance(provenance: &[ProvenanceRefV1]) -> Result<(), ContractError> {
    if provenance.is_empty() || provenance.len() > MAX_SHELL_ROOTS_PER_MODE {
        return Err(ContractError::Malformed(
            "operation provenance is empty or exceeds its item ceiling".into(),
        ));
    }
    let mut provenance_sources = std::collections::BTreeSet::new();
    for item in provenance {
        validate_operation_identifier(&item.source, "provenance[].source", MAX_SHELL_PATH_BYTES)?;
        if !provenance_sources.insert(item.source.as_str()) {
            return Err(ContractError::Malformed(
                "operation provenance contains a duplicate source".into(),
            ));
        }
    }
    Ok(())
}

fn validate_operation_budget(
    budget: &OperationBudgetV1,
    run_spec: &RunSpecV1,
) -> Result<(), ContractError> {
    if budget.max_wall_time_ms == 0 || budget.max_wall_time_ms > MAX_SHELL_TIMEOUT_MS {
        return Err(ContractError::Malformed(
            "operation wall-time budget is zero or exceeds the admitted ceiling".into(),
        ));
    }
    if budget.max_output_bytes == 0 || budget.max_output_bytes > MAX_SHELL_OUTPUT_BYTES {
        return Err(ContractError::Malformed(
            "operation output budget is zero or exceeds the admitted ceiling".into(),
        ));
    }
    if budget.max_artifact_bytes == 0 || budget.max_artifact_bytes > MAX_SHELL_OUTPUT_BYTES {
        return Err(ContractError::Malformed(
            "operation artifact budget is zero or exceeds the admitted ceiling".into(),
        ));
    }
    let declared_steps = usize::try_from(budget.max_steps)
        .map_err(|_| ContractError::Malformed("operation step budget does not fit usize".into()))?;
    if declared_steps == 0
        || declared_steps > MAX_RUN_SPEC_STEPS
        || run_spec.steps.len() > declared_steps
    {
        return Err(ContractError::Malformed(
            "operation step budget is zero, over limit, or below the payload step count".into(),
        ));
    }
    Ok(())
}

fn validate_operation_identifier(
    value: &str,
    field: &'static str,
    maximum_bytes: usize,
) -> Result<(), ContractError> {
    crate::validate_identifier(value, field, maximum_bytes).map_err(|_| {
        ContractError::Malformed(format!("operation field {field} has invalid semantics"))
    })
}

fn validate_declared_effects(
    run_spec: &RunSpecV1,
    effects: &DeclaredEffectsV1,
    replay: &ReplaySpecV1,
) -> Result<(), ContractError> {
    crate::validate_ingress_spec(run_spec).map_err(|_| {
        ContractError::Malformed("operation payload failed run-spec semantic validation".into())
    })?;
    let expected_digest = crate::content_digest(run_spec)?;
    if effects.action_digest != expected_digest {
        return Err(ContractError::Malformed(
            "declared action digest does not bind the operation payload".into(),
        ));
    }

    let mut required_reads = std::collections::BTreeSet::new();
    let mut required_writes = std::collections::BTreeSet::new();
    let mut required_network = false;
    let mut has_shell = false;
    for step in &run_spec.steps {
        if step.call.tool == "shell" {
            has_shell = true;
            let args = serde_json::from_value::<crate::ShellArgsIngressV1>(step.call.args.clone())
                .map_err(|_| {
                    ContractError::Malformed("shell effect declaration could not be decoded".into())
                })?;
            required_reads.extend(args.allowed_read_paths);
            required_writes.extend(args.allowed_write_paths);
            required_network |= args.allow_network;
        }
    }

    let declared_reads = effects
        .read_roots
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let declared_writes = effects
        .write_roots
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if declared_reads.len() != effects.read_roots.len()
        || declared_writes.len() != effects.write_roots.len()
    {
        return Err(ContractError::Malformed(
            "declared effect roots contain duplicates".into(),
        ));
    }
    if declared_reads != required_reads
        || declared_writes != required_writes
        || effects.network_allowed != required_network
    {
        return Err(ContractError::Malformed(
            "declared effects do not exactly match the operation payload".into(),
        ));
    }
    match (has_shell, replay.class) {
        (false, ReplayClassV1::Deterministic)
        | (true, ReplayClassV1::RecordedEffect | ReplayClassV1::NonReplayable) => {}
        (false, ReplayClassV1::RecordedEffect | ReplayClassV1::NonReplayable)
        | (true, ReplayClassV1::Deterministic) => {
            return Err(ContractError::Malformed(
                "operation replay class does not match its effect surface".into(),
            ));
        }
    }
    if replay.class == ReplayClassV1::NonReplayable && replay.intent == ReplayIntentV1::ReadRecorded
    {
        return Err(ContractError::Malformed(
            "non-replayable operation cannot request recorded replay".into(),
        ));
    }
    Ok(())
}
