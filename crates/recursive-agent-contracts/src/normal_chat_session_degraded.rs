//! Reference-only degraded session cause. Parsing cannot establish native truth.
use crate::{
    jcs_canonical, parse_strict_json_value, ArtifactDescriptorV1, ContentDigest, ContractError,
    CurrentPermitId, CurrentReceiptId, CurrentRunId, CurrentStepId, ReceiptKindV1,
    ReceiptOutcomeV1, ReceiptV1, StrictJsonError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;
pub const MAX_NORMAL_CHAT_SESSION_DEGRADATION_BYTES_V1: usize = 1024 * 1024;
pub const NORMAL_CHAT_CHILD_OUTCOME_UNKNOWN_REASON_V1: &str =
    "normal_chat_degraded:CHILD_OUTCOME_UNKNOWN";
pub const NORMAL_CHAT_CHILD_ADMISSION_INTERRUPTED_REASON_V1: &str =
    "normal_chat_interrupted:CHILD_ADMISSION_NOT_RELEASED";
pub const NORMAL_CHAT_SESSION_CANCELLED_REASON_V1: &str = "normal_chat_session_cancelled";
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatSessionDegradationSchemaV1 {
    #[serde(rename = "recursive-agent.normal-chat-session-degradation/v1")]
    V1,
    #[serde(rename = "recursive-agent.normal-chat-session-known-interrupted/v1")]
    KnownInterruptedV1,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum NormalChatUnknownSourceRefV1 {
    ReportedUnknownV2 { evidence: Vec<ArtifactDescriptorV1> },
    MissingExecutorOutcomeV1 { evidence: ArtifactDescriptorV1 },
    UnconsumedAdmissionInterruptedV1 { evidence: ArtifactDescriptorV1 },
    PreparedAdmissionInterruptedV1 { evidence: ArtifactDescriptorV1 },
    ConsumedAdmissionInterruptedV2 { evidence: ArtifactDescriptorV1 },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatDegradedChildRefV1 {
    pub prepared_receipt_id: CurrentReceiptId,
    pub linked_receipt_id: CurrentReceiptId,
    pub closed_receipt_id: CurrentReceiptId,
    pub child_run_id: CurrentRunId,
    pub child_terminal_receipt_id: CurrentReceiptId,
    pub child_chain_head: ContentDigest,
    pub child_closed_artifact: ArtifactDescriptorV1,
    pub unknown_source: Option<NormalChatUnknownSourceRefV1>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatSessionDegradationV1 {
    pub schema: NormalChatSessionDegradationSchemaV1,
    pub parent_run_id: CurrentRunId,
    pub root_step_id: CurrentStepId,
    pub root_permit_id: CurrentPermitId,
    pub root_revocation_receipt_id: CurrentReceiptId,
    pub root_revocation_evidence: ArtifactDescriptorV1,
    pub family_closed_at: DateTime<Utc>,
    pub family_parent_revoked_at: Option<DateTime<Utc>>,
    pub finalized_at: DateTime<Utc>,
    pub children: Vec<NormalChatDegradedChildRefV1>,
}
fn malformed(reason: &str) -> ContractError {
    ContractError::Malformed(reason.into())
}
fn metadata(d: &ArtifactDescriptorV1) -> Result<(), ContractError> {
    d.validate()?;
    if d.media_type != "application/json"
        || d.encoding.is_some()
        || d.byte_length == 0
        || d.byte_length > MAX_NORMAL_CHAT_SESSION_DEGRADATION_BYTES_V1 as u64
    {
        return Err(malformed(
            "degraded session references require bounded JSON metadata",
        ));
    }
    Ok(())
}
impl NormalChatSessionDegradationV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        metadata(&self.root_revocation_evidence)?;
        if self.children.is_empty()
            || self.children.len() > 1024
            || self.finalized_at < self.family_closed_at
            || self
                .family_parent_revoked_at
                .is_some_and(|at| self.finalized_at < at)
        {
            return Err(malformed("degraded session bounds/time/child set invalid"));
        }
        let mut children = BTreeSet::new();
        let mut receipts = BTreeSet::new();
        receipts.insert(self.root_revocation_receipt_id.clone());
        let mut unknown = false;
        let mut interrupted = false;
        for c in &self.children {
            if c.child_run_id == self.parent_run_id || !children.insert(c.child_run_id.clone()) {
                return Err(malformed("duplicate or self child"));
            }
            for id in [
                &c.prepared_receipt_id,
                &c.linked_receipt_id,
                &c.closed_receipt_id,
                &c.child_terminal_receipt_id,
            ] {
                if !receipts.insert(id.clone()) {
                    return Err(malformed("duplicate child or root receipt reference"));
                }
            }
            metadata(&c.child_closed_artifact)?;
            if let Some(source) = &c.unknown_source {
                match source {
                    NormalChatUnknownSourceRefV1::UnconsumedAdmissionInterruptedV1 { evidence }
                    | NormalChatUnknownSourceRefV1::PreparedAdmissionInterruptedV1 { evidence }
                    | NormalChatUnknownSourceRefV1::ConsumedAdmissionInterruptedV2 { evidence } => {
                        interrupted = true;
                        metadata(evidence)?;
                    }
                    NormalChatUnknownSourceRefV1::MissingExecutorOutcomeV1 { evidence } => {
                        unknown = true;
                        metadata(evidence)?
                    }
                    NormalChatUnknownSourceRefV1::ReportedUnknownV2 { evidence } => {
                        unknown = true;
                        if evidence.len() != 2 || evidence[0].digest == evidence[1].digest {
                            return Err(malformed("reported unknown requires distinct settlement and degradation references"));
                        }
                        for d in evidence {
                            metadata(d)?;
                        }
                    }
                }
            }
        }
        if (!unknown && !interrupted)
            || (self.schema == NormalChatSessionDegradationSchemaV1::KnownInterruptedV1) != !unknown
            || jcs_canonical(self)?.len() > MAX_NORMAL_CHAT_SESSION_DEGRADATION_BYTES_V1
        {
            return Err(malformed(
                "missing unknown source or oversized degradation marker",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Error)]
pub enum NormalChatSessionDegradationIngressErrorV1 {
    #[error("degraded session metadata exceeds bound")]
    InputTooLarge,
    #[error("duplicate metadata key")]
    DuplicateKey,
    #[error("malformed metadata or unknown member")]
    Malformed,
    #[error("metadata is not exact typed canonical JSON")]
    NonCanonical,
    #[error("invalid metadata: {0}")]
    Semantic(#[source] ContractError),
}
pub fn parse_normal_chat_session_degradation_v1_bytes(
    input: &[u8],
) -> Result<NormalChatSessionDegradationV1, NormalChatSessionDegradationIngressErrorV1> {
    use NormalChatSessionDegradationIngressErrorV1 as E;
    if input.len() > MAX_NORMAL_CHAT_SESSION_DEGRADATION_BYTES_V1 {
        return Err(E::InputTooLarge);
    }
    let value = parse_strict_json_value(input).map_err(|e| match e {
        StrictJsonError::DuplicateKey => E::DuplicateKey,
        StrictJsonError::Malformed => E::Malformed,
    })?;
    if jcs_canonical(&value).map_err(|_| E::NonCanonical)? != input {
        return Err(E::NonCanonical);
    }
    let marker: NormalChatSessionDegradationV1 =
        serde_json::from_value(value).map_err(|_| E::Malformed)?;
    if jcs_canonical(&marker).map_err(|_| E::NonCanonical)? != input {
        return Err(E::NonCanonical);
    }
    marker.validate().map_err(E::Semantic)?;
    Ok(marker)
}
/// Receipt-only shape. Native provenance and referenced bytes belong to ledger.
pub(crate) fn validate_session_degraded_marker(
    receipts: &[ReceiptV1],
    index: usize,
) -> Result<(), ContractError> {
    let marker = &receipts[index];
    if index < 7
        || (index - 4) % 3 != 0
        || marker.artifact_refs.len() != 1
        || !matches!(&marker.outcome,
        ReceiptOutcomeV1::Failed{reason} if reason==NORMAL_CHAT_CHILD_OUTCOME_UNKNOWN_REASON_V1 || reason==NORMAL_CHAT_CHILD_ADMISSION_INTERRUPTED_REASON_V1)
            && !matches!(&marker.outcome,ReceiptOutcomeV1::Cancelled{reason} if reason==NORMAL_CHAT_SESSION_CANCELLED_REASON_V1)
            && marker.outcome != ReceiptOutcomeV1::Denied
    {
        return Err(malformed("invalid degraded parent marker shape/outcome"));
    }
    metadata(&marker.artifact_refs[0])?;
    let boot = &receipts[..3];
    let close = &receipts[index - 1];
    if boot[0].kind != ReceiptKindV1::RunStarted
        || boot[1].kind != ReceiptKindV1::StepStarted
        || boot[2].kind != ReceiptKindV1::PermitIssued
        || close.kind != ReceiptKindV1::PermitRevoked
        || close.outcome != ReceiptOutcomeV1::Ok
        || close.artifact_refs.len() != 1
    {
        return Err(malformed("degraded parent requires completed root control"));
    }
    for r in boot.iter().chain(std::iter::once(close)) {
        if r.run_id != marker.run_id
            || r.step_id != marker.step_id
            || r.lineage != marker.lineage
            || r.spec_digest != marker.spec_digest
            || r.args_digest != marker.args_digest
            || r.outcome != ReceiptOutcomeV1::Ok
            || r.valid_time > marker.valid_time
        {
            return Err(malformed("degraded parent root binding/time differs"));
        }
    }
    for g in receipts[3..index - 1].chunks_exact(3) {
        for (r, kind, phase) in [
            (&g[0], ReceiptKindV1::ChildAdmissionPrepared, "admission"),
            (&g[1], ReceiptKindV1::ChildLinked, "link"),
            (&g[2], ReceiptKindV1::ChildClosed, "closure"),
        ] {
            if r.kind != kind
                || r.outcome != ReceiptOutcomeV1::Ok
                || r.args_digest != g[0].args_digest
                || r.step_id
                    != crate::derive_child_receipt_step_id(
                        &marker.run_id,
                        &g[0].args_digest,
                        phase,
                    )?
                || r.lineage != marker.lineage
                || r.valid_time > marker.valid_time
            {
                return Err(malformed(
                    "degraded parent requires complete exact ordered child groups",
                ));
            }
        }
        if !g[0].artifact_refs.is_empty()
            || g[0].spec_digest != g[0].args_digest
            || g[1].artifact_refs.len() != 1
            || g[2].artifact_refs.len() != 1
            || g[1].spec_digest != g[2].spec_digest
        {
            return Err(malformed("degraded parent child group shape differs"));
        }
    }
    Ok(())
}
