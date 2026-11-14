//! Historical V2 settlement metadata projections. These bind reports to a
//! consumed admission; they do not confirm provider work or grant authority.
use super::*;
use recursive_agent_contracts::ReceiptOutcomeV1;
use serde::{Deserialize, Serialize};

pub const MAX_NORMAL_CHAT_SETTLEMENT_METADATA_BYTES_V2: usize = 32_768;

impl NormalChatSettlementV2 {
    pub fn validate_for_admission_v2(
        &self,
        proof: &NormalChatLedgerAdmissionEvidenceV2,
    ) -> Result<(), PolicyError> {
        proof.validate()?;
        self.validate_for_attempt(&proof.admission.reservation.attempt)?;
        if self.outcome.permit_id != proof.preflight.permit_id
            || self.outcome.preflight_receipt_digest != proof.preflight.receipt_digest
            || self.outcome.recorded_at < proof.preflight.recorded_at
        {
            return Err(PolicyError::PermitStateConflict);
        }
        if jcs_canonical(self)?.len() > MAX_NORMAL_CHAT_SETTLEMENT_METADATA_BYTES_V2 {
            return Err(NormalChatEgressDenialV1::Malformed.into());
        }
        Ok(())
    }
    /// Outcome of recording the exact executor report, not provider confirmation.
    /// OutcomeUnknown is represented as a failed generic run plus degradation.
    pub fn ledger_outcome_v2(
        &self,
        proof: &NormalChatLedgerAdmissionEvidenceV2,
    ) -> Result<ReceiptOutcomeV1, PolicyError> {
        self.validate_for_admission_v2(proof)?;
        Ok(match self.outcome.reported.state {
            ReportedEffectStateV1::Succeeded => ReceiptOutcomeV1::Ok,
            ReportedEffectStateV1::OutcomeAmbiguous => ReceiptOutcomeV1::Failed {
                reason: "normal_chat_degraded:OUTCOME_UNKNOWN".into(),
            },
            ReportedEffectStateV1::Failed => ReceiptOutcomeV1::Failed {
                reason: self
                    .outcome
                    .reported
                    .error_type
                    .clone()
                    .ok_or(PolicyError::PermitStateConflict)?,
            },
        })
    }
    pub fn degradation_record_v1(
        &self,
        proof: &NormalChatLedgerAdmissionEvidenceV2,
    ) -> Result<Option<NormalChatDegradationRecordV1>, PolicyError> {
        self.validate_for_admission_v2(proof)?;
        if self.report.state != NormalChatReportedStateV2::OutcomeUnknown {
            return Ok(None);
        }
        Ok(Some(NormalChatDegradationRecordV1 {
            schema: NormalChatDegradationSchemaV1::V1,
            attempt_id: self.attempt_id.clone(),
            permit_id: self.outcome.permit_id.clone(),
            reason_code: NormalChatDegradationReasonV1::OutcomeUnknown,
            provider_send_state: NormalChatProviderSendStateV1::MayHaveBeenSent,
            preflight_receipt_digest: self.outcome.preflight_receipt_digest.clone(),
            recorded_at: self.outcome.recorded_at,
        }))
    }
}

/// Strict canonical artifact ingress. Whitespace/aliases/unknown/duplicate fields
/// reject rather than being normalized, and no historical object restores send.
pub fn parse_normal_chat_settlement_metadata_v2_bytes(
    bytes: &[u8],
    proof: &NormalChatLedgerAdmissionEvidenceV2,
) -> Result<NormalChatSettlementV2, PolicyError> {
    if bytes.len() > MAX_NORMAL_CHAT_SETTLEMENT_METADATA_BYTES_V2 {
        return Err(NormalChatEgressDenialV1::Malformed.into());
    }
    let value = recursive_agent_contracts::parse_strict_json_value(bytes)
        .map_err(|_| NormalChatEgressDenialV1::Malformed)?;
    if jcs_canonical(&value)? != bytes {
        return Err(NormalChatEgressDenialV1::Malformed.into());
    }
    let settlement: NormalChatSettlementV2 = serde_json::from_value(value)?;
    if jcs_canonical(&settlement)? != bytes {
        return Err(NormalChatEgressDenialV1::Malformed.into());
    }
    settlement.validate_for_admission_v2(proof)?;
    Ok(settlement)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatDegradationSchemaV1 {
    #[serde(rename = "recursive-agent.normal-chat-degradation/v1")]
    V1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatDegradationReasonV1 {
    #[serde(rename = "OUTCOME_UNKNOWN")]
    OutcomeUnknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatProviderSendStateV1 {
    #[serde(rename = "may_have_been_sent")]
    MayHaveBeenSent,
}
/// Nonauthorizing metadata derived only from the exact consumed report. Ledger
/// readers must require exact canonical equality to the settlement's projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatDegradationRecordV1 {
    pub schema: NormalChatDegradationSchemaV1,
    pub attempt_id: recursive_agent_contracts::NormalChatAttemptIdV2,
    pub permit_id: CurrentPermitId,
    pub reason_code: NormalChatDegradationReasonV1,
    pub provider_send_state: NormalChatProviderSendStateV1,
    pub preflight_receipt_digest: ContentDigest,
    pub recorded_at: DateTime<Utc>,
}
