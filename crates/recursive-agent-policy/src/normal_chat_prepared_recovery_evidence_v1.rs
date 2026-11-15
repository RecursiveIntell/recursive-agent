//! Closed evidence for recovery of a prepared local control, without an effect.
use super::*;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatPreparedRecoveryEvidenceV1 {
    pub admission: NormalChatRetainedAdmissionV2,
    pub recovery: NormalChatPreparedRecoveryRecordV1,
}
impl NormalChatPreparedRecoveryEvidenceV1 {
    pub fn validate(&self) -> Result<(), PolicyError> {
        self.recovery.validate(&self.admission)
    }
    pub fn control(&self) -> Result<PermitEvidenceV1, PolicyError> {
        self.validate()?;
        let (control, effect) = normal_chat_attempt_v2::build_attempt_permits(&self.admission)?;
        let mut allocations = BTreeMap::new();
        allocations.insert(effect.permit_id, effect.binding.budget);
        PermitEvidenceV1::from_record(&PermitRecordV1 {
            permit: control,
            state: PermitStateV1::Issued,
            child_allocations: allocations,
            preflight_receipt: None,
            outcome_receipt: None,
            retained_normal_chat_admission: None,
            normal_chat_settlement: None,
            normal_chat_attempt_v2: None,
        })
    }
    pub fn closed_control(&self) -> Result<PermitEvidenceV1, PolicyError> {
        let mut control = self.control()?;
        let PermitStateV1::Revoked { revoked_at, reason } = self.recovery.closed_state() else {
            return Err(PolicyError::PermitStateConflict);
        };
        control.state = PermitEvidenceStateV1::Revoked {
            at: revoked_at,
            reason,
        };
        Ok(control)
    }
}
