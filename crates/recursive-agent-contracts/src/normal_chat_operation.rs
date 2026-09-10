//! Closed normal-chat request identity contract.
//!
//! This is intentionally not a provider-egress operation.  It carries only
//! secret-free, owner-issued references and bounded accounting material that a
//! later runtime admission/attempt owner may consume.  It cannot grant a
//! permit, select a route, resolve a credential, send a request, or claim a
//! terminal outcome.

use crate::{
    content_digest, parse_strict_json_value, ContractError, CurrentRunId, ProvenanceRefV1,
    MAX_RUN_SPEC_INPUT_BYTES, MAX_RUN_SPEC_MATERIAL_BYTES,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const ATTEMPT_ID_DOMAIN: &str = "recursive-agent/normal-chat-attempt/v1";
const MAX_REFERENCE_BYTES: usize = 4096;

/// Strict ingress errors for a normal-chat identity projection.
#[derive(Debug, Error)]
pub enum NormalChatOperationIngressError {
    #[error("normal-chat input exceeds the byte limit of {maximum_bytes}")]
    InputTooLarge { maximum_bytes: u64 },
    #[error("normal-chat input contains a duplicate object key")]
    DuplicateKey,
    #[error("normal-chat input is malformed or contains an unknown field")]
    Malformed,
    #[error("normal-chat input canonical boundary validation failed")]
    CanonicalBoundary,
    #[error("normal-chat input semantic validation failed")]
    Semantic(#[source] ContractError),
}

/// Exact schema tag; this remains distinct from provider-egress V3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatOperationSchemaV1 {
    #[serde(rename = "recursive-agent.normal-chat/v1")]
    V1,
}

/// Normal-chat may only be replayed from a retained observed response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatReplayV1 {
    #[serde(rename = "recorded_response_only")]
    RecordedResponseOnly,
}

/// Bounded request accounting carried as an external policy projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatBudgetV1 {
    pub max_attempts: u32,
    pub input_tokens: u32,
    pub output_reserve: u32,
    pub max_wall_time_ms: u64,
}

/// Secret-free, nonauthorizing normal-chat identity material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatOperationV1 {
    pub schema: NormalChatOperationSchemaV1,
    pub conversation_ref: String,
    pub parent_run_id: Option<CurrentRunId>,
    pub materialization_ref: String,
    pub materialization_digest: String,
    pub policy_basis_ref: String,
    pub policy_basis_digest: String,
    pub source_revision: String,
    pub route_class: String,
    pub provider_identity: String,
    pub model_ref: String,
    pub request_digest: String,
    pub budget: NormalChatBudgetV1,
    pub replay: NormalChatReplayV1,
    pub provenance: Vec<ProvenanceRefV1>,
}

/// Concrete execution identity backed by the canonical TrialId owner.
/// The candidate wire name/domain is retained; this is not a retry-family AttemptId.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct NormalChatAttemptId(stack_ids::TrialId);

impl NormalChatAttemptId {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn from_owner(value: stack_ids::TrialId) -> Result<Self, ContractError> {
        crate::validate_current_id(value.as_str(), ATTEMPT_ID_DOMAIN)?;
        Ok(Self(value))
    }
}

impl<'de> Deserialize<'de> for NormalChatAttemptId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        crate::validate_current_id(&value, ATTEMPT_ID_DOMAIN).map_err(serde::de::Error::custom)?;
        let owner = stack_ids::TrialId::try_new(value).map_err(serde::de::Error::custom)?;
        Self::from_owner(owner).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Display for NormalChatAttemptId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Serialize)]
struct AttemptIdentityMaterial<'a> {
    operation: &'a NormalChatOperationV1,
    attempt_number: u32,
    provider_request_digest: &'a crate::ContentDigest,
}

/// Derive an idempotent attempt identity from both the external serialized-body
/// digest in the operation and the native digest of the provider request. This
/// does not reserve or authorize the attempt; a runtime permit/receipt owner
/// must perform those operations.
pub fn derive_normal_chat_attempt_id(
    operation: &NormalChatOperationV1,
    attempt_number: u32,
    provider_request_digest: &crate::ContentDigest,
) -> Result<NormalChatAttemptId, ContractError> {
    operation.validate()?;
    if attempt_number == 0 {
        return Err(ContractError::Malformed(
            "normal-chat attempt number must be at least one".into(),
        ));
    }
    if attempt_number > operation.budget.max_attempts {
        return Err(ContractError::Malformed(
            "normal-chat attempt exceeds declared attempt ceiling".into(),
        ));
    }
    let digest = content_digest(&AttemptIdentityMaterial {
        operation,
        attempt_number,
        provider_request_digest,
    })?;
    let owner = stack_ids::TrialId::deterministic(ATTEMPT_ID_DOMAIN, digest.hex())
        .map_err(crate::owner_id_error)?;
    NormalChatAttemptId::from_owner(owner)
}

/// Strict ingress errors for a single native normal-chat attempt.
#[derive(Debug, Error)]
pub enum NormalChatAttemptIngressError {
    #[error("normal-chat attempt input exceeds the byte limit of {maximum_bytes}")]
    InputTooLarge { maximum_bytes: u64 },
    #[error("normal-chat attempt input contains a duplicate object key")]
    DuplicateKey,
    #[error("normal-chat attempt input is malformed or contains an unknown field")]
    Malformed,
    #[error("normal-chat attempt canonical boundary validation failed")]
    CanonicalBoundary,
    #[error("normal-chat attempt semantic validation failed")]
    Semantic(#[source] ContractError),
}

/// Closed schema tag for the normal-chat attempt family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatAttemptSchemaV1 {
    #[serde(rename = "recursive-agent.normal-chat-attempt/v1")]
    V1,
}

/// One request digest-bound, nonauthorizing normal-chat attempt candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatAttemptV1 {
    pub schema: NormalChatAttemptSchemaV1,
    pub operation: NormalChatOperationV1,
    pub attempt_number: u32,
    pub provider_request_digest: crate::ContentDigest,
    pub attempt_id: NormalChatAttemptId,
}

impl NormalChatAttemptV1 {
    /// Native run identity is derived from the validated logical operation, not
    /// from one physical retry attempt. Distinct attempts therefore share one
    /// run/family identity while retaining distinct attempt IDs.
    pub fn run_id(&self) -> Result<CurrentRunId, ContractError> {
        self.validate()?;
        let digest = content_digest(&self.operation)?;
        let owner = crate::KernelRunId::deterministic(crate::RUN_ID_DOMAIN, digest.hex())
            .map_err(crate::owner_id_error)?;
        CurrentRunId::from_owner(owner)
    }

    /// Construct a closed attempt identity without granting permission to send.
    pub fn new(
        operation: NormalChatOperationV1,
        attempt_number: u32,
        provider_request_digest: crate::ContentDigest,
    ) -> Result<Self, ContractError> {
        let attempt_id =
            derive_normal_chat_attempt_id(&operation, attempt_number, &provider_request_digest)?;
        Ok(Self {
            schema: NormalChatAttemptSchemaV1::V1,
            operation,
            attempt_number,
            provider_request_digest,
            attempt_id,
        })
    }

    /// Validate closure and cross-field identity binding before policy or I/O.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema != NormalChatAttemptSchemaV1::V1 {
            return Err(ContractError::Malformed(
                "normal-chat attempt requires the exact V1 schema tag".into(),
            ));
        }
        let expected = derive_normal_chat_attempt_id(
            &self.operation,
            self.attempt_number,
            &self.provider_request_digest,
        )?;
        if self.attempt_id != expected {
            return Err(ContractError::Malformed(
                "normal-chat attempt identity does not bind its request".into(),
            ));
        }
        Ok(())
    }
}

/// Decode one strict normal-chat attempt from hostile bytes.
pub fn parse_normal_chat_attempt_v1_bytes(
    input: &[u8],
) -> Result<NormalChatAttemptV1, NormalChatAttemptIngressError> {
    if input.len() as u64 > MAX_RUN_SPEC_INPUT_BYTES {
        return Err(NormalChatAttemptIngressError::InputTooLarge {
            maximum_bytes: MAX_RUN_SPEC_INPUT_BYTES,
        });
    }
    let parsed = parse_strict_json_value(input).map_err(|error| match error {
        crate::StrictJsonError::DuplicateKey => NormalChatAttemptIngressError::DuplicateKey,
        crate::StrictJsonError::Malformed => NormalChatAttemptIngressError::Malformed,
    })?;
    let canonical = crate::jcs_canonical(&parsed)
        .map_err(|_| NormalChatAttemptIngressError::CanonicalBoundary)?;
    if canonical.len() > MAX_RUN_SPEC_MATERIAL_BYTES {
        return Err(NormalChatAttemptIngressError::CanonicalBoundary);
    }
    let attempt = serde_json::from_value::<NormalChatAttemptV1>(parsed)
        .map_err(|_| NormalChatAttemptIngressError::Malformed)?;
    attempt
        .validate()
        .map_err(NormalChatAttemptIngressError::Semantic)?;
    Ok(attempt)
}

impl NormalChatOperationV1 {
    /// Validate identity material before any policy, permit, or provider work.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema != NormalChatOperationSchemaV1::V1 {
            return Err(ContractError::Malformed(
                "normal-chat ingress requires the exact V1 schema tag".into(),
            ));
        }
        for (name, value) in [
            ("conversation_ref", &self.conversation_ref),
            ("materialization_ref", &self.materialization_ref),
            ("policy_basis_ref", &self.policy_basis_ref),
            ("source_revision", &self.source_revision),
            ("route_class", &self.route_class),
            ("provider_identity", &self.provider_identity),
            ("model_ref", &self.model_ref),
        ] {
            validate_reference(name, value)?;
        }
        validate_external_digest(
            "materialization_digest",
            &self.materialization_digest,
            &["sha256"],
        )?;
        validate_external_digest(
            "policy_basis_digest",
            &self.policy_basis_digest,
            &["sha256", "blake3"],
        )?;
        validate_external_digest("request_digest", &self.request_digest, &["sha256"])?;
        if self.budget.max_attempts == 0
            || self.budget.input_tokens == 0
            || self.budget.output_reserve == 0
            || self.budget.max_wall_time_ms == 0
        {
            return Err(ContractError::Malformed(
                "normal-chat budget values must be nonzero".into(),
            ));
        }
        if self.replay != NormalChatReplayV1::RecordedResponseOnly {
            return Err(ContractError::Malformed(
                "normal-chat replay must be recorded-response-only".into(),
            ));
        }
        if self.provenance.is_empty() {
            return Err(ContractError::Malformed(
                "normal-chat provenance must be nonempty".into(),
            ));
        }
        for provenance in &self.provenance {
            validate_reference("provenance.source", &provenance.source)?;
        }
        Ok(())
    }
}

/// Decode one strict normal-chat identity projection from hostile bytes.
pub fn parse_normal_chat_operation_v1_bytes(
    input: &[u8],
) -> Result<NormalChatOperationV1, NormalChatOperationIngressError> {
    if input.len() as u64 > MAX_RUN_SPEC_INPUT_BYTES {
        return Err(NormalChatOperationIngressError::InputTooLarge {
            maximum_bytes: MAX_RUN_SPEC_INPUT_BYTES,
        });
    }
    let parsed = parse_strict_json_value(input).map_err(|error| match error {
        crate::StrictJsonError::DuplicateKey => NormalChatOperationIngressError::DuplicateKey,
        crate::StrictJsonError::Malformed => NormalChatOperationIngressError::Malformed,
    })?;
    let canonical = crate::jcs_canonical(&parsed)
        .map_err(|_| NormalChatOperationIngressError::CanonicalBoundary)?;
    if canonical.len() > MAX_RUN_SPEC_MATERIAL_BYTES {
        return Err(NormalChatOperationIngressError::CanonicalBoundary);
    }
    let operation = serde_json::from_value::<NormalChatOperationV1>(parsed)
        .map_err(|_| NormalChatOperationIngressError::Malformed)?;
    operation
        .validate()
        .map_err(NormalChatOperationIngressError::Semantic)?;
    Ok(operation)
}

fn validate_reference(name: &str, value: &str) -> Result<(), ContractError> {
    if value.is_empty() || value.len() > MAX_REFERENCE_BYTES || value.chars().any(char::is_control)
    {
        return Err(ContractError::Malformed(format!(
            "invalid normal-chat {name}"
        )));
    }
    Ok(())
}

fn validate_external_digest(
    name: &str,
    value: &str,
    algorithms: &[&str],
) -> Result<(), ContractError> {
    let (algorithm, hex) = value
        .split_once(':')
        .ok_or_else(|| ContractError::Malformed(format!("invalid normal-chat {name}")))?;
    if !algorithms.contains(&algorithm)
        || hex.len() != 64
        || !hex
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        return Err(ContractError::Malformed(format!(
            "invalid normal-chat {name}"
        )));
    }
    Ok(())
}
