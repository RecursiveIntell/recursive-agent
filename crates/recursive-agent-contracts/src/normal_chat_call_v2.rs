//! Receipt-independent preparation material for a governed physical call.
//! No caller-authored allocation, ordinal, receipt or permit is accepted here.
use crate::normal_chat_operation::validate_reference;
use crate::{
    content_digest, jcs_canonical, parse_strict_json_value, ContentDigest, ContractError,
    NormalChatOperationV2, NormalChatOperationV2IngressError, StrictJsonError,
    MAX_RUN_SPEC_INPUT_BYTES, MAX_RUN_SPEC_MATERIAL_BYTES,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatCallRequestSchemaV2 {
    #[serde(rename = "recursive-agent.normal-chat-call-request/v2")]
    V2,
}
/// Nonauthorizing request; the embedded parent id must already be owner-issued.
/// Policy allocates all child identities only after durable parent preparation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatCallRequestV2 {
    pub schema: NormalChatCallRequestSchemaV2,
    pub operation: NormalChatOperationV2,
    pub provider_request_digest: ContentDigest,
    pub provider_request_bytes: u64,
    pub dispatch_intent_ref: String,
}
impl NormalChatCallRequestV2 {
    /// Lossless, nonauthorizing projection of a validated owner-derived attempt.
    /// Allocated ordinal/id fields are deliberately not preparation material.
    pub fn from_attempt(attempt: &crate::NormalChatAttemptV2) -> Result<Self, ContractError> {
        attempt.validate()?;
        let call = Self {
            schema: NormalChatCallRequestSchemaV2::V2,
            operation: attempt.operation.clone(),
            provider_request_digest: attempt.provider_request_digest.clone(),
            provider_request_bytes: attempt.provider_request_bytes,
            dispatch_intent_ref: attempt.dispatch_intent_ref.clone(),
        };
        call.validate()?;
        Ok(call)
    }
    /// Same owner validation for status/recovery ingress without a new call.
    pub fn validate_dispatch_intent_ref(intent: &str) -> Result<(), ContractError> {
        validate_reference("dispatch_intent_ref", intent)
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        self.operation.validate()?;
        Self::validate_dispatch_intent_ref(&self.dispatch_intent_ref)?;
        if self.provider_request_bytes == 0
            || self.provider_request_bytes > self.operation.budget.max_request_bytes
            || jcs_canonical(self)?.len() > MAX_RUN_SPEC_MATERIAL_BYTES
        {
            return Err(ContractError::Malformed(
                "call request exceeds its closed bounds".into(),
            ));
        }
        Ok(())
    }
    /// Canonical exact preparation preimage, excluding allocation-dependent ids.
    pub fn preparation_digest(&self) -> Result<ContentDigest, ContractError> {
        self.validate()?;
        content_digest(self)
    }
}
/// Strict bounded wire ingress. No aliases, authority fields or repair fallback.
pub fn parse_normal_chat_call_request_v2_bytes(
    input: &[u8],
) -> Result<NormalChatCallRequestV2, NormalChatOperationV2IngressError> {
    use NormalChatOperationV2IngressError as Error;
    if input.len() as u64 > MAX_RUN_SPEC_INPUT_BYTES {
        return Err(Error::InputTooLarge {
            maximum_bytes: MAX_RUN_SPEC_INPUT_BYTES,
        });
    }
    let value = parse_strict_json_value(input).map_err(|error| match error {
        StrictJsonError::DuplicateKey => Error::DuplicateKey,
        StrictJsonError::Malformed => Error::Malformed,
    })?;
    let canonical = jcs_canonical(&value).map_err(|_| Error::CanonicalBoundary)?;
    if canonical.len() > MAX_RUN_SPEC_MATERIAL_BYTES {
        return Err(Error::CanonicalBoundary);
    }
    let request: NormalChatCallRequestV2 =
        serde_json::from_value(value).map_err(|_| Error::Malformed)?;
    if jcs_canonical(&request).map_err(|_| Error::CanonicalBoundary)? != canonical {
        return Err(Error::Malformed);
    }
    request.validate().map_err(Error::Semantic)?;
    Ok(request)
}
