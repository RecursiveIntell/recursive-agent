//! Closed V3 operation contract for one future sealed provider egress.
//!
//! This module deliberately accepts opaque provider-request JSON. Decoding that
//! JSON into a provider-owned request type is a later runner boundary; contracts
//! own only strict ingress and exact request-to-binding digest equality.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    content_digest, parse_strict_json_value, ActorAuthorityV1, AuthorityOriginV1, ContractError,
    CurrentRunId, DeclaredEffectsV1, KernelRunId, OperationBudgetV1, ProvenanceRefV1,
    ProviderEgressBindingV1, ReplayClassV1, ReplayIntentV1, ReplaySpecV1, MAX_RUN_NAME_BYTES,
    MAX_RUN_SPEC_INPUT_BYTES, MAX_RUN_SPEC_MATERIAL_BYTES, MAX_SHELL_OUTPUT_BYTES,
    MAX_SHELL_ROOTS_PER_MODE, MAX_SHELL_TIMEOUT_MS,
};

const SEALED_COMPLETION_TOOL: &str = "sealed_completion";

/// Exact tag for the provider-egress operation family. It is deliberately
/// distinct from V1/V2 so existing parsers cannot widen silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderEgressOperationSchemaV1 {
    #[serde(rename = "recursive-agent.operation/v3")]
    V3,
}

/// Closed arguments for the only supported V3 effect call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedCompletionArgumentsV3 {
    pub binding: ProviderEgressBindingV1,
    pub request: serde_json::Value,
}

/// Exactly one sealed completion call. There is no generic tool map or list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedCompletionCallV3 {
    pub tool: String,
    pub arguments: SealedCompletionArgumentsV3,
}

/// Direct-root candidate operation carrying exactly one sealed provider request.
/// A serialized envelope is correlation material, not a current policy proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEgressOperationEnvelopeV3 {
    pub schema: ProviderEgressOperationSchemaV1,
    pub actor: ActorAuthorityV1,
    pub budget: OperationBudgetV1,
    pub effects: DeclaredEffectsV1,
    pub provenance: Vec<ProvenanceRefV1>,
    pub replay: ReplaySpecV1,
    pub sealed_completion: SealedCompletionCallV3,
}

/// Derive the canonical run identity from every closed V3 operation field.
pub fn derive_provider_egress_operation_id(
    envelope: &ProviderEgressOperationEnvelopeV3,
) -> Result<CurrentRunId, ContractError> {
    let digest = content_digest(envelope)?;
    let owner = KernelRunId::deterministic(crate::RUN_ID_DOMAIN, digest.hex())
        .map_err(crate::owner_id_error)?;
    CurrentRunId::from_owner(owner)
}

/// V3 byte-ingress failures. No variant implies policy authorization or backend availability.
#[derive(Debug, Error)]
pub enum ProviderEgressOperationIngressError {
    #[error("provider-egress operation input exceeds the byte limit of {maximum_bytes}")]
    InputTooLarge { maximum_bytes: u64 },
    #[error("provider-egress operation contains a duplicate object key")]
    DuplicateKey,
    #[error("provider-egress operation is malformed or contains an unknown field")]
    Malformed,
    #[error("provider-egress operation canonical boundary validation failed")]
    CanonicalBoundary,
    #[error("provider-egress operation semantic validation failed")]
    Semantic(#[source] ContractError),
}

impl ProviderEgressOperationEnvelopeV3 {
    /// Validate V3 shape and exact opaque request binding without reading wall-clock time.
    /// Dispatch must call [`Self::validate_at`] with its trusted current clock.
    pub fn validate_structure(&self) -> Result<(), ContractError> {
        if self.schema != ProviderEgressOperationSchemaV1::V3 {
            return Err(ContractError::Malformed(
                "unsupported provider-egress operation schema".into(),
            ));
        }
        if self.actor.origin != AuthorityOriginV1::Direct {
            return Err(ContractError::Malformed(
                "V3 provider egress requires direct authority".into(),
            ));
        }
        validate_identifier(&self.actor.principal, "actor.principal", MAX_RUN_NAME_BYTES)?;
        validate_budget(&self.budget)?;
        validate_provenance(&self.provenance)?;
        if self.replay.class != ReplayClassV1::RecordedEffect
            || self.replay.intent != ReplayIntentV1::ExecuteOnce
        {
            return Err(ContractError::Malformed(
                "V3 provider egress requires recorded-effect execute-once replay".into(),
            ));
        }
        if self.sealed_completion.tool != SEALED_COMPLETION_TOOL {
            return Err(ContractError::Malformed(
                "V3 admits only sealed_completion".into(),
            ));
        }
        if !self.sealed_completion.arguments.request.is_object() {
            return Err(ContractError::Malformed(
                "sealed provider request must be an object".into(),
            ));
        }
        let request_digest = content_digest(&self.sealed_completion.arguments.request)?;
        if request_digest != self.sealed_completion.arguments.binding.request_digest {
            return Err(ContractError::Malformed(
                "sealed provider request does not match the binding digest".into(),
            ));
        }
        self.sealed_completion
            .arguments
            .binding
            .validate_structure()?;
        if !self.effects.network_allowed
            || !self.effects.read_roots.is_empty()
            || !self.effects.write_roots.is_empty()
            || self.effects.action_digest != content_digest(&self.sealed_completion)?
        {
            return Err(ContractError::Malformed(
                "V3 declared effects do not exactly bind its sealed provider call".into(),
            ));
        }
        Ok(())
    }

    /// Revalidate a structurally valid V3 envelope at dispatch time using the
    /// runtime/policy owner's trusted current clock.
    pub fn validate_at(&self, now: chrono::DateTime<chrono::Utc>) -> Result<(), ContractError> {
        self.validate_structure()?;
        self.sealed_completion.arguments.binding.validate_at(now)
    }
}

/// Decode one strict V3 candidate operation from hostile bytes. Successful
/// decoding remains non-executable until the runner repeats validation and
/// obtains a current policy decision.
pub fn parse_provider_egress_operation_v3_bytes(
    input: &[u8],
) -> Result<ProviderEgressOperationEnvelopeV3, ProviderEgressOperationIngressError> {
    if input.len() as u64 > MAX_RUN_SPEC_INPUT_BYTES {
        return Err(ProviderEgressOperationIngressError::InputTooLarge {
            maximum_bytes: MAX_RUN_SPEC_INPUT_BYTES,
        });
    }
    let parsed = parse_strict_json_value(input).map_err(|error| match error {
        crate::StrictJsonError::DuplicateKey => ProviderEgressOperationIngressError::DuplicateKey,
        crate::StrictJsonError::Malformed => ProviderEgressOperationIngressError::Malformed,
    })?;
    parse_provider_egress_operation_v3_value(parsed)
}

pub(crate) fn parse_provider_egress_operation_v3_value(
    parsed: serde_json::Value,
) -> Result<ProviderEgressOperationEnvelopeV3, ProviderEgressOperationIngressError> {
    let canonical = crate::jcs_canonical(&parsed)
        .map_err(|_| ProviderEgressOperationIngressError::CanonicalBoundary)?;
    if canonical.len() > MAX_RUN_SPEC_MATERIAL_BYTES {
        return Err(ProviderEgressOperationIngressError::CanonicalBoundary);
    }
    let envelope = serde_json::from_value::<ProviderEgressOperationEnvelopeV3>(parsed)
        .map_err(|_| ProviderEgressOperationIngressError::Malformed)?;
    envelope
        .validate_structure()
        .map_err(ProviderEgressOperationIngressError::Semantic)?;
    Ok(envelope)
}

fn validate_identifier(
    value: &str,
    field: &str,
    maximum_bytes: usize,
) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > maximum_bytes
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.:@/".contains(character))
    {
        return Err(ContractError::Malformed(format!(
            "V3 field {field} has invalid semantics"
        )));
    }
    Ok(())
}

fn validate_budget(budget: &OperationBudgetV1) -> Result<(), ContractError> {
    if budget.max_wall_time_ms == 0
        || budget.max_wall_time_ms > MAX_SHELL_TIMEOUT_MS
        || budget.max_output_bytes == 0
        || budget.max_output_bytes > MAX_SHELL_OUTPUT_BYTES
        || budget.max_artifact_bytes == 0
        || budget.max_artifact_bytes > MAX_SHELL_OUTPUT_BYTES
        || budget.max_steps != 1
    {
        return Err(ContractError::Malformed(
            "invalid V3 provider-egress budget".into(),
        ));
    }
    Ok(())
}

fn validate_provenance(provenance: &[ProvenanceRefV1]) -> Result<(), ContractError> {
    if provenance.is_empty() || provenance.len() > MAX_SHELL_ROOTS_PER_MODE {
        return Err(ContractError::Malformed(
            "invalid V3 provider-egress provenance".into(),
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for reference in provenance {
        validate_identifier(
            &reference.source,
            "provenance.source",
            MAX_RUN_SPEC_MATERIAL_BYTES,
        )?;
        if !seen.insert(reference.source.as_str()) {
            return Err(ContractError::Malformed(
                "duplicate V3 provenance source".into(),
            ));
        }
    }
    Ok(())
}
