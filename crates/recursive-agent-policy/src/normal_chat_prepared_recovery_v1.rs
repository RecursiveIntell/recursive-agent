//! Narrow-only disposition for a native local control with no consumed effect.
use super::*;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatPreparedRecoverySchemaV1 {
    #[serde(rename = "recursive-agent.normal-chat-prepared-recovery/v1")]
    V1,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatPreparedRecoveryRecordV1 {
    pub schema: NormalChatPreparedRecoverySchemaV1,
    pub admission_digest: ContentDigest,
    pub original_control_state: PermitStateV1,
    pub observed_at: DateTime<Utc>,
    pub recovery_digest: ContentDigest,
}
impl NormalChatPreparedRecoveryRecordV1 {
    pub fn computed_digest(&self) -> Result<ContentDigest, PolicyError> {
        Ok(content_digest(&(
            self.schema,
            &self.admission_digest,
            &self.original_control_state,
            self.observed_at,
        ))?)
    }
    pub fn validate(&self, admission: &NormalChatRetainedAdmissionV2) -> Result<(), PolicyError> {
        let (control, _) = normal_chat_attempt_v2::build_attempt_permits(admission)?;
        if self.admission_digest != content_digest(admission)?
            || self.recovery_digest != self.computed_digest()?
            || self.observed_at < control.binding.issued_at
            || matches!(self.original_control_state, PermitStateV1::Consumed { .. })
            || matches!(self.original_control_state, PermitStateV1::Revoked { revoked_at, .. } if revoked_at > self.observed_at)
        {
            return Err(PolicyError::PermitStateConflict);
        }
        Ok(())
    }
    pub fn closed_state(&self) -> PermitStateV1 {
        match &self.original_control_state {
            PermitStateV1::Issued => PermitStateV1::Revoked {
                revoked_at: self.observed_at,
                reason: PermitRevocationReasonV1::Operator,
            },
            other => other.clone(),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalChatPreparedRecoveryInterruptionV1 {
    Family(PermitTransitionStage),
    Control(PermitTransitionStage),
}
impl DurablePermitStore {
    pub fn read_normal_chat_prepared_recovery_v1(
        &self,
        family: &FamilyAuthorityStore,
        intent: &str,
    ) -> Result<Option<NormalChatPreparedRecoveryRecordV1>, PolicyError> {
        if [
            self.run_root_identity(),
            (self.permit_root_device, self.permit_root_inode),
        ]
        .contains(&family.root_identity())
        {
            return Err(PolicyError::PermitStateConflict);
        }
        let reservation = family
            .read_normal_chat_reservation(intent)?
            .ok_or(PolicyError::PermitStateConflict)?;
        self.with_lock(|| {
            let view = self.read_normal_chat_attempt_snapshot_v2(&reservation)?;
            if view.state != NormalChatAttemptPolicyStateV2::RecoveredPrepared {
                return Ok(None);
            }
            let control = view.local_control.ok_or(PolicyError::PermitStateConflict)?;
            let record = self.read_record_or_reject(&control.permit_id)?;
            let Some(NormalChatAttemptRecordV2::PreparedRecovered { recovery, .. }) =
                record.normal_chat_attempt_v2
            else {
                return Err(PolicyError::PermitStateConflict);
            };
            family.confirm_normal_chat_report_closed_v2()?;
            self.root.sync_all()?;
            self.validate_v2_child_locator()?;
            Ok(Some(*recovery))
        })
    }
    /// Runtime has verified an existing empty child ledger. No effect record is
    /// created: the original control retains its allocation, identity and lease.
    pub fn recover_prepared_normal_chat_attempt_v1(
        &self,
        family: &FamilyAuthorityStore,
        intent: &str,
        mut clock: impl FnMut() -> DateTime<Utc>,
        fault: Option<NormalChatPreparedRecoveryInterruptionV1>,
    ) -> Result<NormalChatPreparedRecoveryRecordV1, PolicyError> {
        if [
            self.run_root_identity(),
            (self.permit_root_device, self.permit_root_inode),
        ]
        .contains(&family.root_identity())
        {
            return Err(PolicyError::PermitStateConflict);
        }
        let reservation = family
            .read_normal_chat_reservation(intent)?
            .ok_or(PolicyError::PermitStateConflict)?;
        self.with_lock(|| {
            self.validate_v2_child_locator()?;
            let before = self.read_normal_chat_attempt_snapshot_v2(&reservation)?;
            let control = before
                .local_control
                .as_ref()
                .ok_or(PolicyError::PermitStateConflict)?;
            let mut record = self.read_record_or_reject(&control.permit_id)?;
            if before.state == NormalChatAttemptPolicyStateV2::RecoveredPrepared {
                let Some(NormalChatAttemptRecordV2::PreparedRecovered { recovery, .. }) =
                    record.normal_chat_attempt_v2
                else {
                    return Err(PolicyError::PermitStateConflict);
                };
                family.confirm_normal_chat_report_closed_v2()?;
                self.root.sync_all()?;
                return Ok(*recovery);
            }
            if before.state != NormalChatAttemptPolicyStateV2::Prepared
                || before.preflight.is_some()
                || before.effect.is_some()
                || before.outcome.is_some()
                || before.settlement.is_some()
            {
                return Err(PolicyError::PermitStateConflict);
            }
            let Some(NormalChatAttemptRecordV2::Control { admission }) =
                &record.normal_chat_attempt_v2
            else {
                return Err(PolicyError::PermitStateConflict);
            };
            let admission = admission.clone();
            let at = clock();
            let mut recovery = NormalChatPreparedRecoveryRecordV1 {
                schema: NormalChatPreparedRecoverySchemaV1::V1,
                admission_digest: content_digest(&admission)?,
                original_control_state: record.state.clone(),
                observed_at: at,
                recovery_digest: ContentDigest::compute(b"uncommitted"),
            };
            recovery.recovery_digest = recovery.computed_digest()?;
            recovery.validate(&admission)?;
            family.close_normal_chat_session_for_report_v2(
                at,
                &mut clock,
                match fault {
                    Some(NormalChatPreparedRecoveryInterruptionV1::Family(stage)) => Some(stage),
                    _ => None,
                },
            )?;
            if self.read_normal_chat_attempt_snapshot_v2(&reservation)? != before {
                return Err(PolicyError::PermitStateConflict);
            }
            record.state = recovery.closed_state();
            record.normal_chat_attempt_v2 = Some(NormalChatAttemptRecordV2::PreparedRecovered {
                admission,
                recovery: Box::new(recovery.clone()),
            });
            self.validate_record_bindings(&record)?;
            self.replace_record(
                &record,
                match fault {
                    Some(NormalChatPreparedRecoveryInterruptionV1::Control(stage)) => Some(stage),
                    _ => None,
                },
            )?;
            if self
                .read_normal_chat_attempt_snapshot_v2(&reservation)?
                .state
                != NormalChatAttemptPolicyStateV2::RecoveredPrepared
            {
                return Err(PolicyError::PermitStateConflict);
            }
            family.confirm_normal_chat_report_closed_v2()?;
            self.validate_v2_child_locator()?;
            Ok(recovery)
        })
    }
}
