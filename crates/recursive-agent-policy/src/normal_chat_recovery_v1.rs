//! Native expired-attempt disposition, distinct from an executor report.
//! No duration/usage/provider result, send continuation or ledger certificate is
//! inferred. Runtime/ledger integration and restart routing are separate gates.
use super::*;
use serde::{Deserialize, Serialize};

pub const MAX_NORMAL_CHAT_RECOVERY_BYTES_V1: usize = 16_384;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatRecoverySchemaV1 {
    #[serde(rename = "recursive-agent.normal-chat-recovery/v1")]
    V1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatRecoveryReasonV1 {
    #[serde(rename = "executor_outcome_missing_after_expiry")]
    ExecutorOutcomeMissingAfterExpiry,
}
/// Owner observation of an empty native executor-outcome slot after expiry.
/// It does not say whether SDK/network/provider work occurred or stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatRecoveryRecordV1 {
    pub schema: NormalChatRecoverySchemaV1,
    pub attempt_id: recursive_agent_contracts::NormalChatAttemptIdV2,
    pub permit_id: CurrentPermitId,
    pub preflight_receipt_digest: ContentDigest,
    pub reason: NormalChatRecoveryReasonV1,
    pub provider_send_state: NormalChatProviderSendStateV1,
    pub observed_at: DateTime<Utc>,
    pub recovery_digest: ContentDigest,
}
impl NormalChatRecoveryRecordV1 {
    pub fn computed_digest(&self) -> Result<ContentDigest, PolicyError> {
        Ok(content_digest(&(
            self.schema,
            &self.attempt_id,
            &self.permit_id,
            &self.preflight_receipt_digest,
            self.reason,
            self.provider_send_state,
            self.observed_at,
        ))?)
    }
    fn from_observation(
        proof: &NormalChatLedgerAdmissionEvidenceV2,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, PolicyError> {
        let schema = NormalChatRecoverySchemaV1::V1;
        let attempt_id = proof.admission.reservation.attempt.attempt_id.clone();
        let permit_id = proof.preflight.permit_id.clone();
        let preflight_receipt_digest = proof.preflight.receipt_digest.clone();
        let reason = NormalChatRecoveryReasonV1::ExecutorOutcomeMissingAfterExpiry;
        let provider_send_state = NormalChatProviderSendStateV1::MayHaveBeenSent;
        let recovery_digest = content_digest(&(
            schema,
            &attempt_id,
            &permit_id,
            &preflight_receipt_digest,
            reason,
            provider_send_state,
            observed_at,
        ))?;
        let value = Self {
            schema,
            attempt_id,
            permit_id,
            preflight_receipt_digest,
            reason,
            provider_send_state,
            observed_at,
            recovery_digest,
        };
        value.validate_for_admission_v1(proof)?;
        Ok(value)
    }
    /// Pure failed-run projection for missing executor evidence, not a
    /// provider failure report or a live permit. The record itself is the
    /// distinct recovery/degradation evidence; no SDK sidecar is fabricated.
    pub fn ledger_outcome_v1(
        &self,
        proof: &NormalChatLedgerAdmissionEvidenceV2,
    ) -> Result<recursive_agent_contracts::ReceiptOutcomeV1, PolicyError> {
        self.validate_for_admission_v1(proof)?;
        Ok(recursive_agent_contracts::ReceiptOutcomeV1::Failed {
            reason: recursive_agent_contracts::NORMAL_CHAT_MISSING_EXECUTOR_OUTCOME_REASON_V1
                .into(),
        })
    }
    /// Pure historical binding check, never proof of current authority or SDK
    /// absence. Digests do not authenticate against an arbitrary same-UID writer.
    pub fn validate_for_admission_v1(
        &self,
        proof: &NormalChatLedgerAdmissionEvidenceV2,
    ) -> Result<(), PolicyError> {
        proof.validate()?;
        if self.attempt_id != proof.admission.reservation.attempt.attempt_id
            || self.permit_id != proof.preflight.permit_id
            || self.preflight_receipt_digest != proof.preflight.receipt_digest
            || self.observed_at < proof.preflight.recorded_at
            || self.observed_at < proof.preflight.evidence.binding.expires_at
            || self.recovery_digest != self.computed_digest()?
            || jcs_canonical(self)?.len() > MAX_NORMAL_CHAT_RECOVERY_BYTES_V1
        {
            return Err(PolicyError::PermitStateConflict);
        }
        Ok(())
    }
}
/// Exact canonical artifact ingress only. This does not write a native record
/// or authorize a caller-supplied observation timestamp.
pub fn parse_normal_chat_recovery_record_v1_bytes(
    bytes: &[u8],
    proof: &NormalChatLedgerAdmissionEvidenceV2,
) -> Result<NormalChatRecoveryRecordV1, PolicyError> {
    if bytes.len() > MAX_NORMAL_CHAT_RECOVERY_BYTES_V1 {
        return Err(NormalChatEgressDenialV1::Malformed.into());
    }
    let value = recursive_agent_contracts::parse_strict_json_value(bytes)
        .map_err(|_| NormalChatEgressDenialV1::Malformed)?;
    if jcs_canonical(&value)? != bytes {
        return Err(NormalChatEgressDenialV1::Malformed.into());
    }
    let record: NormalChatRecoveryRecordV1 = serde_json::from_value(value)?;
    if jcs_canonical(&record)? != bytes {
        return Err(NormalChatEgressDenialV1::Malformed.into());
    }
    record.validate_for_admission_v1(proof)?;
    Ok(record)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalChatRecoveryInterruptionV1 {
    FamilyClose(PermitTransitionStage),
    ChildRecovery(PermitTransitionStage),
}
impl DurablePermitStore {
    /// Narrow an existing expired attempt whose executor outcome is still absent.
    /// The clock callback must be supplied by the trusted native owner, never
    /// exposed as caller-authored wire time. Parent locator/ledger verification
    /// belongs to RuntimeService; this result proves neither terminality nor send.
    pub fn recover_expired_normal_chat_attempt_v1(
        &self,
        family: &FamilyAuthorityStore,
        intent: &str,
        preflight: &ContentDigest,
        trusted_clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<NormalChatRecoveryRecordV1, PolicyError> {
        self.recover_expired_normal_chat_attempt_v1_with_interruption(
            family,
            intent,
            preflight,
            trusted_clock,
            None,
        )
    }
    #[doc(hidden)]
    pub fn recover_expired_normal_chat_attempt_v1_with_interruption(
        &self,
        family: &FamilyAuthorityStore,
        intent: &str,
        preflight: &ContentDigest,
        mut trusted_clock: impl FnMut() -> DateTime<Utc>,
        fault: Option<NormalChatRecoveryInterruptionV1>,
    ) -> Result<NormalChatRecoveryRecordV1, PolicyError> {
        if [
            self.run_root_identity(),
            (self.permit_root_device, self.permit_root_inode),
        ]
        .contains(&family.root_identity())
        {
            return Err(PolicyError::UnsafePermitRoot(
                "recovery requires distinct pinned child/family roots".into(),
            ));
        }
        let reservation = family
            .read_normal_chat_reservation(intent)?
            .ok_or(NormalChatEgressDenialV1::Malformed)?;
        // Same child -> family order as report publication. The canonical child
        // lock arbitrates reports versus recovery; no compare in an adapter.
        self.with_lock(|| {
            self.validate_v2_child_locator()?;
            let view = self.read_normal_chat_attempt_snapshot_v2(&reservation)?;
            let retained = view
                .preflight
                .as_ref()
                .ok_or(PolicyError::PermitStateConflict)?;
            if retained.receipt_digest != *preflight {
                return Err(PolicyError::PermitStateConflict);
            }
            if view.state == NormalChatAttemptPolicyStateV2::RecoveredUnknown {
                return self.confirm_recovered_snapshot_v1(family, &reservation, &view, fault);
            }
            if view.state != NormalChatAttemptPolicyStateV2::Consumed
                || view.outcome.is_some()
                || view.settlement.is_some()
            {
                return Err(PolicyError::PermitStateConflict);
            }
            let mut record = self.read_record_or_reject(&retained.permit_id)?;
            let original = record.clone();
            let proof = self.recovery_admission_v1(&view)?;
            let observed_at = trusted_clock();
            if view.local_control.as_ref().is_some_and(|control|
                matches!(control.state, PermitEvidenceStateV1::Revoked { at, .. } if observed_at < at))
            {
                return Err(NormalChatEgressDenialV1::Malformed.into());
            }
            let recovery = NormalChatRecoveryRecordV1::from_observation(&proof, observed_at)?;
            self.require_recovery_source_unchanged_v1(&reservation, &view, &original)?;
            record.normal_chat_attempt_v2 = Some(NormalChatAttemptRecordV2::Recovered {
                recovery: Box::new(recovery.clone()),
            });
            self.validate_record_bindings(&record)?;
            family.close_normal_chat_session_for_report_v2(
                observed_at,
                &mut trusted_clock,
                match fault {
                    Some(NormalChatRecoveryInterruptionV1::FamilyClose(stage)) => Some(stage),
                    _ => None,
                },
            )?;
            // A late time callback may remove/replace records. Never republish
            // cached authority or overwrite a report after that final sample.
            self.require_recovery_source_unchanged_v1(&reservation, &view, &original)?;
            self.replace_record(
                &record,
                match fault {
                    Some(NormalChatRecoveryInterruptionV1::ChildRecovery(stage)) => Some(stage),
                    _ => None,
                },
            )?;
            let after = self.read_normal_chat_attempt_snapshot_v2(&reservation)?;
            if after.state != NormalChatAttemptPolicyStateV2::RecoveredUnknown
                || self.recovery_from_snapshot_v1(&after)?.as_ref() != Some(&recovery)
            {
                return Err(PolicyError::PermitStateConflict);
            }
            family.confirm_normal_chat_report_closed_v2()?;
            self.validate_v2_child_locator()?;
            Ok(recovery)
        })
    }
    /// Confirm ONLY an existing recovered record under the child lock. Unlike
    /// recover_expired_normal_chat_attempt_v1 this has no creation branch or
    /// clock callback; missing/downgraded state or fence rejects without repair.
    pub fn confirm_normal_chat_recovery_v1(
        &self,
        family: &FamilyAuthorityStore,
        intent: &str,
        preflight: &ContentDigest,
    ) -> Result<NormalChatRecoveryRecordV1, PolicyError> {
        if [
            self.run_root_identity(),
            (self.permit_root_device, self.permit_root_inode),
        ]
        .contains(&family.root_identity())
        {
            return Err(PolicyError::UnsafePermitRoot(
                "recovery requires distinct pinned child/family roots".into(),
            ));
        }
        let reservation = family
            .read_normal_chat_reservation(intent)?
            .ok_or(NormalChatEgressDenialV1::Malformed)?;
        self.with_lock(|| {
            self.validate_v2_child_locator()?;
            let view = self.read_normal_chat_attempt_snapshot_v2(&reservation)?;
            if view.preflight.as_ref().map(|p| &p.receipt_digest) != Some(preflight) {
                return Err(PolicyError::PermitStateConflict);
            }
            self.confirm_recovered_snapshot_v1(family, &reservation, &view, None)
        })
    }
    // Caller holds the canonical child lock. Shared by exact recovery retry and
    // confirmation so neither path can omit an existing-fence/durability check.
    fn confirm_recovered_snapshot_v1(
        &self,
        family: &FamilyAuthorityStore,
        reservation: &NormalChatFamilyReservationV2,
        view: &NormalChatAttemptReadbackV2,
        fault: Option<NormalChatRecoveryInterruptionV1>,
    ) -> Result<NormalChatRecoveryRecordV1, PolicyError> {
        if view.state != NormalChatAttemptPolicyStateV2::RecoveredUnknown {
            return Err(PolicyError::PermitStateConflict);
        }
        let existing = self
            .recovery_from_snapshot_v1(view)?
            .ok_or(PolicyError::PermitStateConflict)?;
        family.confirm_normal_chat_report_closed_v2()?;
        if fault
            == Some(NormalChatRecoveryInterruptionV1::FamilyClose(
                PermitTransitionStage::DirectoryFsync,
            ))
        {
            return Err(PolicyError::InjectedInterruption(
                PermitTransitionStage::DirectoryFsync,
            ));
        }
        self.root.sync_all()?;
        if fault
            == Some(NormalChatRecoveryInterruptionV1::ChildRecovery(
                PermitTransitionStage::DirectoryFsync,
            ))
        {
            return Err(PolicyError::InjectedInterruption(
                PermitTransitionStage::DirectoryFsync,
            ));
        }
        if self.read_normal_chat_attempt_snapshot_v2(reservation)? != *view {
            return Err(PolicyError::PermitStateConflict);
        }
        self.validate_v2_child_locator()?;
        Ok(existing)
    }
    /// Nonauthorizing historical record read, including uncertain rename status.
    /// Missing closure is NOT repaired or treated as current send authority.
    pub fn read_normal_chat_recovery_v1(
        &self,
        family: &FamilyAuthorityStore,
        intent: &str,
    ) -> Result<Option<NormalChatRecoveryRecordV1>, PolicyError> {
        let reservation = family
            .read_normal_chat_reservation(intent)?
            .ok_or(NormalChatEgressDenialV1::Malformed)?;
        self.with_lock(|| {
            let view = self.read_normal_chat_attempt_snapshot_v2(&reservation)?;
            let value = self.recovery_from_snapshot_v1(&view)?;
            self.validate_v2_child_locator()?;
            Ok(value)
        })
    }
    fn recovery_from_snapshot_v1(
        &self,
        view: &NormalChatAttemptReadbackV2,
    ) -> Result<Option<NormalChatRecoveryRecordV1>, PolicyError> {
        if view.state != NormalChatAttemptPolicyStateV2::RecoveredUnknown {
            return Ok(None);
        }
        let id = &view
            .effect
            .as_ref()
            .ok_or(PolicyError::PermitStateConflict)?
            .permit_id;
        let record = self.read_record_or_reject(id)?;
        let Some(NormalChatAttemptRecordV2::Recovered { recovery }) = record.normal_chat_attempt_v2
        else {
            return Err(PolicyError::PermitStateConflict);
        };
        Ok(Some(*recovery))
    }
    fn recovery_admission_v1(
        &self,
        view: &NormalChatAttemptReadbackV2,
    ) -> Result<NormalChatLedgerAdmissionEvidenceV2, PolicyError> {
        let control = view
            .local_control
            .as_ref()
            .ok_or(PolicyError::PermitStateConflict)?;
        let record = self.read_record_or_reject(&control.permit_id)?;
        let Some(NormalChatAttemptRecordV2::Control { admission }) = record.normal_chat_attempt_v2
        else {
            return Err(PolicyError::PermitStateConflict);
        };
        let proof = NormalChatLedgerAdmissionEvidenceV2 {
            schema: NormalChatLedgerAdmissionSchemaV2::V2,
            admission: *admission,
            preflight: view
                .preflight
                .clone()
                .ok_or(PolicyError::PermitStateConflict)?,
        };
        proof.validate()?;
        Ok(proof)
    }
    fn require_recovery_source_unchanged_v1(
        &self,
        reservation: &NormalChatFamilyReservationV2,
        view: &NormalChatAttemptReadbackV2,
        original: &PermitRecordV1,
    ) -> Result<(), PolicyError> {
        self.validate_v2_child_locator()?;
        if self.read_normal_chat_attempt_snapshot_v2(reservation)? != *view
            || self.read_record_or_reject(&original.permit.permit_id)? != *original
        {
            return Err(PolicyError::PermitStateConflict);
        }
        self.validate_v2_child_locator()
    }
}
