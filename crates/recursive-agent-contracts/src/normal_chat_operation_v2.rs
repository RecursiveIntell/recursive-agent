//! Closed V2 identity and bounded-budget contract for governed normal-chat dispatch.
//!
//! These values are correlation/accounting material, not permits. Only the
//! policy/runtime owners may derive attempt ids, reserve budgets, or authorize
//! provider dispatch.

use crate::normal_chat_operation::{validate_external_digest, validate_reference};
use crate::{
    content_digest, parse_strict_json_value, ContentDigest, ContractError, CurrentRunId,
    KernelRunId, ProvenanceRefV1, StrictJsonError, MAX_RUN_SPEC_INPUT_BYTES,
    MAX_RUN_SPEC_MATERIAL_BYTES, RUN_ID_DOMAIN,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum serialized provider request size admitted by this contract.
pub const MAX_NORMAL_CHAT_REQUEST_BYTES_V2: u64 = MAX_RUN_SPEC_INPUT_BYTES;

/// Strict ingress failures for the closed V2 normal-chat operation.
#[derive(Debug, Error)]
pub enum NormalChatOperationV2IngressError {
    #[error("normal-chat V2 input exceeds the byte limit of {maximum_bytes}")]
    InputTooLarge { maximum_bytes: u64 },
    #[error("normal-chat V2 input contains a duplicate object key")]
    DuplicateKey,
    #[error("normal-chat V2 input is malformed or contains an unknown field")]
    Malformed,
    #[error("normal-chat V2 canonical boundary validation failed")]
    CanonicalBoundary,
    #[error("normal-chat V2 semantic validation failed")]
    Semantic(#[source] ContractError),
}

/// Exact V2 schema tag; it is deliberately distinct from the V1 contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatOperationSchemaV2 {
    #[serde(rename = "recursive-agent.normal-chat/v2")]
    V2,
}

/// V2 replay is intentionally unavailable because the contract retains digests,
/// not the response artifact required by the V1 recorded-response replay law.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatReplayV2 {
    #[serde(rename = "unavailable")]
    Unavailable,
}

/// The only supported request-projection algorithm for this V2 schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatRequestProjectionSchemaV2 {
    #[serde(rename = "ares-json-sorted-v1")]
    AresJsonSortedV1,
}

/// Per-physical-attempt bounds. The session grant owner separately enforces
/// cumulative attempt and output-reservation ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatBudgetV2 {
    /// Output tokens reserved for this physical network attempt.
    pub output_reserve: u32,
    /// Maximum local transport timeout for this physical attempt.
    pub max_wall_time_ms: u64,
    /// Maximum serialized request-body bytes for this physical attempt.
    pub max_request_bytes: u64,
}

/// Secret-free, closed identity material for one logical normal-chat dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatOperationV2 {
    pub schema: NormalChatOperationSchemaV2,
    pub conversation_ref: String,
    /// Owner-issued session parent run. Never fabricated by the client.
    pub parent_run_id: CurrentRunId,
    pub materialization_ref: String,
    pub materialization_digest: String,
    pub policy_basis_ref: String,
    pub policy_basis_digest: String,
    pub source_revision: String,
    pub route_class: String,
    pub provider_identity: String,
    pub model_ref: String,
    /// Resolved provider API mode; required for exact grant-route matching.
    pub api_mode: String,
    /// Digest of the named logical-call projection, not a physical send body.
    pub request_digest: String,
    pub request_projection_schema: NormalChatRequestProjectionSchemaV2,
    pub budget: NormalChatBudgetV2,
    pub replay: NormalChatReplayV2,
    pub provenance: Vec<ProvenanceRefV1>,
}

impl NormalChatOperationV2 {
    /// Validate the closed schema and every field before policy or I/O.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema != NormalChatOperationSchemaV2::V2 {
            return Err(ContractError::Malformed(
                "normal-chat operation requires the exact V2 schema tag".into(),
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
            ("api_mode", &self.api_mode),
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
        if self.budget.output_reserve == 0
            || self.budget.max_wall_time_ms == 0
            || self.budget.max_request_bytes == 0
            || self.budget.max_request_bytes > MAX_NORMAL_CHAT_REQUEST_BYTES_V2
        {
            return Err(ContractError::Malformed(
                "normal-chat V2 per-attempt budget is zero or exceeds its request-byte ceiling"
                    .into(),
            ));
        }
        if self.replay != NormalChatReplayV2::Unavailable {
            return Err(ContractError::Malformed(
                "normal-chat V2 replay must be unavailable".into(),
            ));
        }
        if self.provenance.is_empty() {
            return Err(ContractError::Malformed(
                "normal-chat V2 provenance must be nonempty".into(),
            ));
        }
        for provenance in &self.provenance {
            validate_reference("provenance.source", &provenance.source)?;
        }
        Ok(())
    }
}

/// Decode one strict V2 operation from hostile bytes. V1 is never a fallback.
pub fn parse_normal_chat_operation_v2_bytes(
    input: &[u8],
) -> Result<NormalChatOperationV2, NormalChatOperationV2IngressError> {
    if input.len() as u64 > MAX_RUN_SPEC_INPUT_BYTES {
        return Err(NormalChatOperationV2IngressError::InputTooLarge {
            maximum_bytes: MAX_RUN_SPEC_INPUT_BYTES,
        });
    }
    let parsed = parse_strict_json_value(input).map_err(|error| match error {
        StrictJsonError::DuplicateKey => NormalChatOperationV2IngressError::DuplicateKey,
        StrictJsonError::Malformed => NormalChatOperationV2IngressError::Malformed,
    })?;
    let canonical = crate::jcs_canonical(&parsed)
        .map_err(|_| NormalChatOperationV2IngressError::CanonicalBoundary)?;
    if canonical.len() > MAX_RUN_SPEC_MATERIAL_BYTES {
        return Err(NormalChatOperationV2IngressError::CanonicalBoundary);
    }
    let operation = serde_json::from_value::<NormalChatOperationV2>(parsed)
        .map_err(|_| NormalChatOperationV2IngressError::Malformed)?;
    operation
        .validate()
        .map_err(NormalChatOperationV2IngressError::Semantic)?;
    Ok(operation)
}

const ATTEMPT_ID_DOMAIN_V2: &str = "recursive-agent/normal-chat-attempt/v2";

/// Strict ingress failures for a V2 physical-send attempt.
#[derive(Debug, Error)]
pub enum NormalChatAttemptV2IngressError {
    #[error("normal-chat attempt V2 input exceeds the byte limit of {maximum_bytes}")]
    InputTooLarge { maximum_bytes: u64 },
    #[error("normal-chat attempt V2 input contains a duplicate object key")]
    DuplicateKey,
    #[error("normal-chat attempt V2 input is malformed or contains an unknown field")]
    Malformed,
    #[error("normal-chat attempt V2 canonical boundary validation failed")]
    CanonicalBoundary,
    #[error("normal-chat attempt V2 semantic validation failed")]
    Semantic(#[source] ContractError),
}

/// Closed V2 schema tag for one physical provider send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatAttemptSchemaV2 {
    #[serde(rename = "recursive-agent.normal-chat-attempt/v2")]
    V2,
}

/// Owner-derived attempt identity; parsing validates its family-qualified ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct NormalChatAttemptIdV2(stack_ids::TrialId);

impl NormalChatAttemptIdV2 {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn from_owner(value: stack_ids::TrialId) -> Result<Self, ContractError> {
        crate::validate_current_id(value.as_str(), ATTEMPT_ID_DOMAIN_V2)?;
        Ok(Self(value))
    }
}

impl<'de> Deserialize<'de> for NormalChatAttemptIdV2 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        crate::validate_current_id(&value, ATTEMPT_ID_DOMAIN_V2)
            .map_err(serde::de::Error::custom)?;
        let owner = stack_ids::TrialId::try_new(value).map_err(serde::de::Error::custom)?;
        Self::from_owner(owner).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Display for NormalChatAttemptIdV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Serialize)]
struct AttemptIdentityMaterialV2<'a> {
    operation: &'a NormalChatOperationV2,
    attempt_number: u32,
    provider_request_digest: &'a ContentDigest,
    provider_request_bytes: u64,
}

/// Derive the V2 physical-attempt ID from the exact versioned identity
/// preimage. This is identity derivation only; it does not reserve or permit.
pub fn derive_normal_chat_attempt_id_v2(
    operation: &NormalChatOperationV2,
    attempt_number: u32,
    provider_request_digest: &ContentDigest,
    provider_request_bytes: u64,
) -> Result<NormalChatAttemptIdV2, ContractError> {
    operation.validate()?;
    if attempt_number == 0 {
        return Err(ContractError::Malformed(
            "normal-chat V2 attempt number must be at least one".into(),
        ));
    }
    if provider_request_bytes == 0 || provider_request_bytes > MAX_NORMAL_CHAT_REQUEST_BYTES_V2 {
        return Err(ContractError::Malformed(
            "normal-chat V2 physical request length is zero or exceeds the hard byte limit".into(),
        ));
    }
    let digest = content_digest(&AttemptIdentityMaterialV2 {
        operation,
        attempt_number,
        provider_request_digest,
        provider_request_bytes,
    })?;
    let owner = stack_ids::TrialId::deterministic(ATTEMPT_ID_DOMAIN_V2, digest.hex())
        .map_err(crate::owner_id_error)?;
    NormalChatAttemptIdV2::from_owner(owner)
}

/// One owner-derived physical provider attempt. Construction is not authority;
/// the policy owner must durably reserve it and issue/consume the effect permit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatAttemptV2 {
    pub schema: NormalChatAttemptSchemaV2,
    pub operation: NormalChatOperationV2,
    pub attempt_number: u32,
    pub provider_request_digest: ContentDigest,
    /// Length of the exact body buffer hashed at the Ares send boundary.
    /// This is executor-reported until transport-owner conformance is proved.
    pub provider_request_bytes: u64,
    pub dispatch_intent_ref: String,
    pub session_run_id: CurrentRunId,
    pub attempt_id: NormalChatAttemptIdV2,
}

impl NormalChatAttemptV2 {
    /// Construct deterministic identity material without granting permission.
    pub fn new(
        operation: NormalChatOperationV2,
        attempt_number: u32,
        provider_request_digest: ContentDigest,
        provider_request_bytes: u64,
        dispatch_intent_ref: String,
        session_run_id: CurrentRunId,
    ) -> Result<Self, ContractError> {
        let attempt_id = derive_normal_chat_attempt_id_v2(
            &operation,
            attempt_number,
            &provider_request_digest,
            provider_request_bytes,
        )?;
        let attempt = Self {
            schema: NormalChatAttemptSchemaV2::V2,
            operation,
            attempt_number,
            provider_request_digest,
            provider_request_bytes,
            dispatch_intent_ref,
            session_run_id,
            attempt_id,
        };
        attempt.validate()?;
        Ok(attempt)
    }

    /// Validate owner identity, session parent, and dispatch-intent binding.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema != NormalChatAttemptSchemaV2::V2 {
            return Err(ContractError::Malformed(
                "normal-chat attempt requires the exact V2 schema tag".into(),
            ));
        }
        self.operation.validate()?;
        validate_reference("dispatch_intent_ref", &self.dispatch_intent_ref)?;
        if self.session_run_id != self.operation.parent_run_id {
            return Err(ContractError::Malformed(
                "normal-chat V2 attempt session run does not match its operation parent".into(),
            ));
        }
        let expected = derive_normal_chat_attempt_id_v2(
            &self.operation,
            self.attempt_number,
            &self.provider_request_digest,
            self.provider_request_bytes,
        )?;
        if self.attempt_id != expected {
            return Err(ContractError::Malformed(
                "normal-chat V2 attempt ID does not bind operation, ordinal, request digest, and length"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Each physical send has a separate deterministic run/receipt root.
    pub fn run_id(&self) -> Result<CurrentRunId, ContractError> {
        self.validate()?;
        let digest = content_digest(self)?;
        let owner = KernelRunId::deterministic(RUN_ID_DOMAIN, digest.hex())
            .map_err(crate::owner_id_error)?;
        CurrentRunId::from_owner(owner)
    }
}

/// Decode one strict V2 physical attempt from hostile bytes.
pub fn parse_normal_chat_attempt_v2_bytes(
    input: &[u8],
) -> Result<NormalChatAttemptV2, NormalChatAttemptV2IngressError> {
    if input.len() as u64 > MAX_RUN_SPEC_INPUT_BYTES {
        return Err(NormalChatAttemptV2IngressError::InputTooLarge {
            maximum_bytes: MAX_RUN_SPEC_INPUT_BYTES,
        });
    }
    let parsed = parse_strict_json_value(input).map_err(|error| match error {
        StrictJsonError::DuplicateKey => NormalChatAttemptV2IngressError::DuplicateKey,
        StrictJsonError::Malformed => NormalChatAttemptV2IngressError::Malformed,
    })?;
    let canonical = crate::jcs_canonical(&parsed)
        .map_err(|_| NormalChatAttemptV2IngressError::CanonicalBoundary)?;
    if canonical.len() > MAX_RUN_SPEC_MATERIAL_BYTES {
        return Err(NormalChatAttemptV2IngressError::CanonicalBoundary);
    }
    let attempt = serde_json::from_value::<NormalChatAttemptV2>(parsed)
        .map_err(|_| NormalChatAttemptV2IngressError::Malformed)?;
    attempt
        .validate()
        .map_err(NormalChatAttemptV2IngressError::Semantic)?;
    Ok(attempt)
}
