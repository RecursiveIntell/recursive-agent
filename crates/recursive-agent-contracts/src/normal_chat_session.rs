//! Closed identity for a grant-bound normal-chat session root.
//!
//! This is correlation material only: parsing or deriving a run ID cannot
//! authorize a session, delegate a child, or permit provider egress. The policy
//! owner constructs production values from its startup-loaded operator grant.

use crate::normal_chat_operation::{validate_external_digest, validate_reference};
use crate::{
    content_digest, jcs_canonical, parse_strict_json_value, ContractError, CurrentRunId,
    KernelRunId, StrictJsonError, MAX_RUN_SPEC_INPUT_BYTES, MAX_RUN_SPEC_MATERIAL_BYTES,
    RUN_ID_DOMAIN,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatSessionSchemaV1 {
    #[serde(rename = "recursive-agent.normal-chat-session/v1")]
    V1,
}

/// Stable session-generation and operator-policy identity, never a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatSessionV1 {
    pub schema: NormalChatSessionSchemaV1,
    pub conversation_ref: String,
    /// Lineage only. The runtime must independently admit the referenced parent.
    pub parent_session_run_id: Option<CurrentRunId>,
    pub ares_home_digest: String,
    pub grant_revision: u64,
    pub policy_basis_digest: String,
}

impl NormalChatSessionV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_reference("conversation_ref", &self.conversation_ref)?;
        validate_external_digest("ares_home_digest", &self.ares_home_digest, &["sha256"])?;
        validate_external_digest(
            "policy_basis_digest",
            &self.policy_basis_digest,
            &["sha256"],
        )?;
        if self.grant_revision == 0 || self.grant_revision > i64::MAX as u64 {
            return Err(ContractError::Malformed(
                "invalid normal-chat session grant revision".into(),
            ));
        }
        Ok(())
    }

    /// Identity derivation through the existing material-ID owner, not authority.
    pub fn run_id(&self) -> Result<CurrentRunId, ContractError> {
        self.validate()?;
        let digest = content_digest(self)?;
        let owner = KernelRunId::deterministic(RUN_ID_DOMAIN, digest.hex())
            .map_err(crate::owner_id_error)?;
        CurrentRunId::from_owner(owner)
    }
}

#[derive(Debug, Error)]
pub enum NormalChatSessionIngressErrorV1 {
    #[error("normal-chat session exceeds byte limit {maximum_bytes}")]
    InputTooLarge { maximum_bytes: u64 },
    #[error("normal-chat session contains a duplicate key")]
    DuplicateKey,
    #[error("normal-chat session is malformed or has an unknown field")]
    Malformed,
    #[error("normal-chat session failed canonical boundary validation")]
    CanonicalBoundary,
    #[error("normal-chat session failed semantic validation")]
    Semantic(#[source] ContractError),
}

pub fn parse_normal_chat_session_v1_bytes(
    input: &[u8],
) -> Result<NormalChatSessionV1, NormalChatSessionIngressErrorV1> {
    if input.len() as u64 > MAX_RUN_SPEC_INPUT_BYTES {
        return Err(NormalChatSessionIngressErrorV1::InputTooLarge {
            maximum_bytes: MAX_RUN_SPEC_INPUT_BYTES,
        });
    }
    let value = parse_strict_json_value(input).map_err(|error| match error {
        StrictJsonError::DuplicateKey => NormalChatSessionIngressErrorV1::DuplicateKey,
        StrictJsonError::Malformed => NormalChatSessionIngressErrorV1::Malformed,
    })?;
    let bytes =
        jcs_canonical(&value).map_err(|_| NormalChatSessionIngressErrorV1::CanonicalBoundary)?;
    if bytes.len() > MAX_RUN_SPEC_MATERIAL_BYTES {
        return Err(NormalChatSessionIngressErrorV1::CanonicalBoundary);
    }
    let session: NormalChatSessionV1 =
        serde_json::from_value(value).map_err(|_| NormalChatSessionIngressErrorV1::Malformed)?;
    session
        .validate()
        .map_err(NormalChatSessionIngressErrorV1::Semantic)?;
    Ok(session)
}
