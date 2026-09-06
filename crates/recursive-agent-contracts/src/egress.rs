//! Canonical native provider-egress binding contract.
//!
//! A caller may carry foreign policy/context digests as opaque references, but
//! the native runtime owns the BLAKE3 binding of the exact provider request.

use crate::{
    content_digest, parse_strict_json_value, ContentDigest, ContractError,
    MAX_RUN_SPEC_INPUT_BYTES, MAX_RUN_SPEC_MATERIAL_BYTES,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const SCHEMA: &str = "recursive-agent.egress-binding/v1";
const MAX_REFERENCE_BYTES: usize = 4096;

/// Byte-ingress failures for a sealed provider request binding.
#[derive(Debug, Error)]
pub enum ProviderEgressBindingIngressError {
    /// Raw input exceeded the owner-controlled ceiling.
    #[error("egress binding input exceeds the byte limit of {maximum_bytes}")]
    InputTooLarge { maximum_bytes: u64 },
    /// Attacker input repeated a JSON object key.
    #[error("egress binding contains a duplicate JSON key")]
    DuplicateKey,
    /// The closed binding shape could not be decoded.
    #[error("egress binding is malformed or contains an unknown field")]
    Malformed,
    /// Canonicalization failed or produced an oversized material value.
    #[error("egress binding canonical boundary validation failed")]
    CanonicalBoundary,
    /// A typed semantic invariant failed.
    #[error("egress binding semantic validation failed")]
    Semantic(#[source] ContractError),
}

/// Material supplied before the native owner seals an exact request binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEgressBindingMaterialV1 {
    /// Opaque reference to the policy owner projection.
    pub policy_basis_ref: String,
    /// Algorithm-qualified digest emitted by the policy owner; it remains external evidence.
    pub policy_basis_digest: String,
    /// SHA-256 digest emitted by the context owner.
    pub context_digest: String,
    /// Exact source generation selected during materialization.
    pub source_revision: String,
    /// Exact Agent Graph obligation slice reference. The native owner carries
    /// this opaquely and does not interpret Graph semantics.
    pub graph_obligation_ref: String,
    /// Algorithm-qualified digest emitted by the Agent Graph obligation owner.
    pub graph_obligation_digest: String,
    /// Policy-authorized provider route class.
    pub route_class: String,
    /// Provider identity excluding credentials.
    pub provider_identity: String,
    /// Selected provider model reference.
    pub model_ref: String,
    /// Counted rendered input tokens.
    pub input_tokens: u32,
    /// Reserved output tokens.
    pub output_reserve: u32,
    /// Native BLAKE3 digest of the exact serialized provider request.
    pub request_digest: ContentDigest,
    /// Binding expiry checked immediately before dispatch.
    pub not_after: DateTime<Utc>,
}

/// Closed, native-owned binding for one exact provider request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEgressBindingV1 {
    /// Exact schema discriminator.
    pub schema: String,
    /// Opaque reference to the policy owner projection.
    pub policy_basis_ref: String,
    /// Algorithm-qualified digest emitted by the policy owner.
    pub policy_basis_digest: String,
    /// SHA-256 digest emitted by the context owner.
    pub context_digest: String,
    /// Exact source generation selected during materialization.
    pub source_revision: String,
    /// Exact Agent Graph obligation slice reference. The native owner carries
    /// this opaquely and does not interpret Graph semantics.
    pub graph_obligation_ref: String,
    /// Algorithm-qualified digest emitted by the Agent Graph obligation owner.
    pub graph_obligation_digest: String,
    /// Policy-authorized provider route class.
    pub route_class: String,
    /// Provider identity excluding credentials.
    pub provider_identity: String,
    /// Selected provider model reference.
    pub model_ref: String,
    /// Counted rendered input tokens.
    pub input_tokens: u32,
    /// Reserved output tokens.
    pub output_reserve: u32,
    /// Native BLAKE3 digest of the exact serialized provider request.
    pub request_digest: ContentDigest,
    /// Binding expiry checked immediately before dispatch.
    pub not_after: DateTime<Utc>,
    /// Native BLAKE3 digest over every field above.
    pub binding_digest: ContentDigest,
}

impl ProviderEgressBindingV1 {
    /// Seal caller material after structural validation, without minting authority.
    pub fn seal(material: ProviderEgressBindingMaterialV1) -> Result<Self, ContractError> {
        validate_material(&material)?;
        let mut binding = Self {
            schema: SCHEMA.into(),
            policy_basis_ref: material.policy_basis_ref,
            policy_basis_digest: material.policy_basis_digest,
            context_digest: material.context_digest,
            source_revision: material.source_revision,
            graph_obligation_ref: material.graph_obligation_ref,
            graph_obligation_digest: material.graph_obligation_digest,
            route_class: material.route_class,
            provider_identity: material.provider_identity,
            model_ref: material.model_ref,
            input_tokens: material.input_tokens,
            output_reserve: material.output_reserve,
            request_digest: material.request_digest,
            not_after: material.not_after,
            binding_digest: ContentDigest::compute(b"recursive-agent-egress-unsealed"),
        };
        binding.binding_digest = binding.expected_digest()?;
        Ok(binding)
    }

    /// Validate immutable binding shape and digest without reading wall-clock
    /// time. This supports deterministic offline structure validation; effect
    /// dispatch must call [`Self::validate_at`] with its trusted current clock.
    pub fn validate_structure(&self) -> Result<(), ContractError> {
        if self.schema != SCHEMA {
            return Err(ContractError::Malformed(
                "unsupported egress binding schema".into(),
            ));
        }
        validate_material(&ProviderEgressBindingMaterialV1 {
            policy_basis_ref: self.policy_basis_ref.clone(),
            policy_basis_digest: self.policy_basis_digest.clone(),
            context_digest: self.context_digest.clone(),
            source_revision: self.source_revision.clone(),
            graph_obligation_ref: self.graph_obligation_ref.clone(),
            graph_obligation_digest: self.graph_obligation_digest.clone(),
            route_class: self.route_class.clone(),
            provider_identity: self.provider_identity.clone(),
            model_ref: self.model_ref.clone(),
            input_tokens: self.input_tokens,
            output_reserve: self.output_reserve,
            request_digest: self.request_digest.clone(),
            not_after: self.not_after,
        })?;
        if self.binding_digest != self.expected_digest()? {
            return Err(ContractError::Malformed(
                "egress binding digest mismatch".into(),
            ));
        }
        Ok(())
    }

    /// Validate immutable shape, digest, and expiry at the native egress point.
    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), ContractError> {
        self.validate_structure()?;
        if self.not_after <= now {
            return Err(ContractError::Malformed("egress binding expired".into()));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, ContractError> {
        let mut value = serde_json::to_value(self)
            .map_err(|error| ContractError::Malformed(format!("egress binding encode: {error}")))?;
        value
            .as_object_mut()
            .ok_or_else(|| {
                ContractError::Malformed("egress binding must encode as an object".into())
            })?
            .remove("binding_digest");
        content_digest(&value)
    }
}

/// Decode one strict native egress binding from hostile JSON bytes.
pub fn parse_provider_egress_binding_v1_bytes(
    input: &[u8],
) -> Result<ProviderEgressBindingV1, ProviderEgressBindingIngressError> {
    if input.len() as u64 > MAX_RUN_SPEC_INPUT_BYTES {
        return Err(ProviderEgressBindingIngressError::InputTooLarge {
            maximum_bytes: MAX_RUN_SPEC_INPUT_BYTES,
        });
    }
    let parsed = parse_strict_json_value(input).map_err(|error| match error {
        crate::StrictJsonError::DuplicateKey => ProviderEgressBindingIngressError::DuplicateKey,
        crate::StrictJsonError::Malformed => ProviderEgressBindingIngressError::Malformed,
    })?;
    let canonical = crate::jcs_canonical(&parsed)
        .map_err(|_| ProviderEgressBindingIngressError::CanonicalBoundary)?;
    if canonical.len() > MAX_RUN_SPEC_MATERIAL_BYTES {
        return Err(ProviderEgressBindingIngressError::CanonicalBoundary);
    }
    let binding = serde_json::from_value::<ProviderEgressBindingV1>(parsed)
        .map_err(|_| ProviderEgressBindingIngressError::Malformed)?;
    binding
        .validate_at(Utc::now())
        .map_err(ProviderEgressBindingIngressError::Semantic)?;
    Ok(binding)
}

fn validate_material(material: &ProviderEgressBindingMaterialV1) -> Result<(), ContractError> {
    for (name, value) in [
        ("policy_basis_ref", &material.policy_basis_ref),
        ("source_revision", &material.source_revision),
        ("graph_obligation_ref", &material.graph_obligation_ref),
        ("route_class", &material.route_class),
        ("provider_identity", &material.provider_identity),
        ("model_ref", &material.model_ref),
    ] {
        if value.is_empty() || value.len() > MAX_REFERENCE_BYTES {
            return Err(ContractError::Malformed(format!("invalid egress {name}")));
        }
    }
    validate_external_digest(
        "policy_basis_digest",
        &material.policy_basis_digest,
        &["sha256", "blake3"],
    )?;
    validate_external_digest("context_digest", &material.context_digest, &["sha256"])?;
    validate_external_digest(
        "graph_obligation_digest",
        &material.graph_obligation_digest,
        &["sha256", "blake3"],
    )?;
    if material.input_tokens == 0 || material.output_reserve == 0 {
        return Err(ContractError::Malformed(
            "egress token counts must be nonzero".into(),
        ));
    }
    Ok(())
}

fn validate_external_digest(
    name: &str,
    value: &str,
    allowed_algorithms: &[&str],
) -> Result<(), ContractError> {
    let Some((algorithm, hexadecimal)) = value.split_once(':') else {
        return Err(ContractError::Malformed(format!("invalid external {name}")));
    };
    if !allowed_algorithms.contains(&algorithm)
        || hexadecimal.len() != 64
        || !hexadecimal
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(ContractError::Malformed(format!("invalid external {name}")));
    }
    Ok(())
}
