//! Native interrupted-admission disposition. Not an executor report or send capability.
use super::*;

/// Pure validation of the normative pre-release transcript. A complete seven-row
/// prefix is deliberately ineligible: a lost successful response is UNKNOWN.
/// Runtime/ledger must additionally verify chain bytes, inventory and pinned roots.
pub fn validate_interrupted_preflight_v2(
    proof: &NormalChatLedgerAdmissionEvidenceV2,
    rows: &[recursive_agent_contracts::ReceiptV1],
) -> Result<(), PolicyError> {
    use recursive_agent_contracts::{ReceiptKindV1 as K, ReceiptOutcomeV1};
    proof.validate()?;
    if rows.len() >= 7 {
        return Err(PolicyError::PermitStateConflict);
    }
    recursive_agent_contracts::validate_receipt_sequence(
        rows,
        recursive_agent_contracts::LifecycleValidationMode::AppendInProgress,
    )?;
    let control = proof.control_evidence()?;
    let issued = proof.issued_effect_evidence()?;
    let consumed = &proof.preflight.evidence;
    let payloads = [
        jcs_canonical(&control)?,
        jcs_canonical(proof)?,
        jcs_canonical(&issued)?,
        jcs_canonical(consumed)?,
    ];
    let descriptors = payloads
        .iter()
        .map(|b| {
            Ok(recursive_agent_contracts::ArtifactDescriptorV1 {
                owner_id: recursive_agent_contracts::derive_artifact_id(b)?,
                digest: ContentDigest::compute(b),
                byte_length: b.len() as u64,
                media_type: "application/json".into(),
                encoding: None,
            })
        })
        .collect::<Result<Vec<_>, PolicyError>>()?;
    for (row, (e, kind, at, refs)) in rows.iter().zip([
        (&control, K::RunStarted, control.binding.issued_at, vec![]),
        (&control, K::StepStarted, control.binding.issued_at, vec![]),
        (
            &control,
            K::PermitIssued,
            control.binding.issued_at,
            vec![descriptors[0].clone()],
        ),
        (&issued, K::StepStarted, issued.binding.issued_at, vec![]),
        (
            consumed,
            K::NormalChatAttemptAdmittedV2,
            proof.preflight.recorded_at,
            vec![descriptors[1].clone()],
        ),
        (
            &issued,
            K::PermitIssued,
            issued.binding.issued_at,
            vec![descriptors[2].clone()],
        ),
    ]) {
        if row.kind != kind
            || row.run_id != e.binding.run_id
            || row.step_id != e.binding.step_id
            || row.valid_time != at
            || row.lineage != build_lineage(&e.permit_id, &e.binding.policy_version)
            || row.spec_digest != e.binding.action_digest
            || row.args_digest != e.binding.args_digest
            || row.artifact_refs != refs
            || row.outcome != ReceiptOutcomeV1::Ok
        {
            return Err(PolicyError::PermitStateConflict);
        }
    }
    Ok(())
}
use serde::{Deserialize, Serialize};

pub const MAX_NORMAL_CHAT_INTERRUPTED_RECOVERY_BYTES_V2: usize = 65_536;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatInterruptedRecoverySchemaV2 {
    #[serde(rename = "recursive-agent.normal-chat-interrupted-recovery/v2")]
    V2,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatInterruptedRecoveryReasonV2 {
    #[serde(rename = "admission_response_not_released")]
    AdmissionResponseNotReleased,
}
/// Owner observation of an exact incomplete admission transcript under the
/// normative release invariant. Not an SDK report, usage or duration claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatInterruptedRecoveryRecordV2 {
    pub schema: NormalChatInterruptedRecoverySchemaV2,
    pub attempt_id: recursive_agent_contracts::NormalChatAttemptIdV2,
    pub permit_id: CurrentPermitId,
    pub preflight_receipt_digest: ContentDigest,
    pub reason: NormalChatInterruptedRecoveryReasonV2,
    pub prefix_receipts: Vec<recursive_agent_contracts::ReceiptV1>,
    pub observed_at: DateTime<Utc>,
    pub recovery_digest: ContentDigest,
}
impl NormalChatInterruptedRecoveryRecordV2 {
    pub fn computed_digest(&self) -> Result<ContentDigest, PolicyError> {
        Ok(content_digest(&(
            self.schema,
            &self.attempt_id,
            &self.permit_id,
            &self.preflight_receipt_digest,
            self.reason,
            &self.prefix_receipts,
            self.observed_at,
        ))?)
    }
    fn from_observation(
        proof: &NormalChatLedgerAdmissionEvidenceV2,
        observed_at: DateTime<Utc>,
        prefix_receipts: Vec<recursive_agent_contracts::ReceiptV1>,
    ) -> Result<Self, PolicyError> {
        let schema = NormalChatInterruptedRecoverySchemaV2::V2;
        let attempt_id = proof.admission.reservation.attempt.attempt_id.clone();
        let permit_id = proof.preflight.permit_id.clone();
        let preflight_receipt_digest = proof.preflight.receipt_digest.clone();
        let reason = NormalChatInterruptedRecoveryReasonV2::AdmissionResponseNotReleased;
        validate_interrupted_preflight_v2(proof, &prefix_receipts)?;
        let recovery_digest = content_digest(&(
            schema,
            &attempt_id,
            &permit_id,
            &preflight_receipt_digest,
            reason,
            &prefix_receipts,
            observed_at,
        ))?;
        let value = Self {
            schema,
            attempt_id,
            permit_id,
            preflight_receipt_digest,
            reason,
            prefix_receipts,
            observed_at,
            recovery_digest,
        };
        value.validate_for_admission_v2(proof)?;
        Ok(value)
    }
    /// Pure failed-run projection for missing executor evidence, not a
    /// provider failure report or a live permit. The record itself is the
    /// distinct recovery/degradation evidence; no SDK sidecar is fabricated.
    pub fn ledger_outcome_v2(
        &self,
        proof: &NormalChatLedgerAdmissionEvidenceV2,
    ) -> Result<recursive_agent_contracts::ReceiptOutcomeV1, PolicyError> {
        self.validate_for_admission_v2(proof)?;
        Ok(recursive_agent_contracts::ReceiptOutcomeV1::Failed {
            reason: recursive_agent_contracts::NORMAL_CHAT_INTERRUPTED_ADMISSION_REASON_V2.into(),
        })
    }
    /// Pure historical binding check, never proof of current authority or SDK
    /// absence. Digests do not authenticate against an arbitrary same-UID writer.
    pub fn validate_for_admission_v2(
        &self,
        proof: &NormalChatLedgerAdmissionEvidenceV2,
    ) -> Result<(), PolicyError> {
        proof.validate()?;
        validate_interrupted_preflight_v2(proof, &self.prefix_receipts)?;
        if self.attempt_id != proof.admission.reservation.attempt.attempt_id
            || self.permit_id != proof.preflight.permit_id
            || self.preflight_receipt_digest != proof.preflight.receipt_digest
            || self.observed_at < proof.preflight.recorded_at
            || self.recovery_digest != self.computed_digest()?
            || jcs_canonical(self)?.len() > MAX_NORMAL_CHAT_INTERRUPTED_RECOVERY_BYTES_V2
        {
            return Err(PolicyError::PermitStateConflict);
        }
        Ok(())
    }
}
/// Exact canonical artifact ingress only. This does not write a native record
/// or authorize a caller-supplied observation timestamp.
pub fn parse_normal_chat_interrupted_recovery_record_v2_bytes(
    bytes: &[u8],
    proof: &NormalChatLedgerAdmissionEvidenceV2,
) -> Result<NormalChatInterruptedRecoveryRecordV2, PolicyError> {
    if bytes.len() > MAX_NORMAL_CHAT_INTERRUPTED_RECOVERY_BYTES_V2 {
        return Err(NormalChatEgressDenialV1::Malformed.into());
    }
    let value = recursive_agent_contracts::parse_strict_json_value(bytes)
        .map_err(|_| NormalChatEgressDenialV1::Malformed)?;
    if jcs_canonical(&value)? != bytes {
        return Err(NormalChatEgressDenialV1::Malformed.into());
    }
    let record: NormalChatInterruptedRecoveryRecordV2 = serde_json::from_value(value)?;
    if jcs_canonical(&record)? != bytes {
        return Err(NormalChatEgressDenialV1::Malformed.into());
    }
    record.validate_for_admission_v2(proof)?;
    Ok(record)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalChatInterruptedRecoveryInterruptionV2 {
    FamilyClose(PermitTransitionStage),
    ChildRecovery(PermitTransitionStage),
}
impl DurablePermitStore {
    /// Narrow an existing consumed attempt with an exact incomplete preflight.
    /// The clock callback must be supplied by the trusted native owner, never
    /// exposed as caller-authored wire time. Parent locator/ledger verification
    /// belongs to RuntimeService; this result proves neither terminality nor send.
    pub fn recover_interrupted_normal_chat_attempt_v2(
        &self,
        family: &FamilyAuthorityStore,
        intent: &str,
        preflight: &ContentDigest,
        prefix: &[recursive_agent_contracts::ReceiptV1],
        trusted_clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<NormalChatInterruptedRecoveryRecordV2, PolicyError> {
        self.recover_interrupted_normal_chat_attempt_v2_with_interruption(
            family,
            intent,
            preflight,
            prefix,
            trusted_clock,
            None,
        )
    }
    #[doc(hidden)]
    pub fn recover_interrupted_normal_chat_attempt_v2_with_interruption(
        &self,
        family: &FamilyAuthorityStore,
        intent: &str,
        preflight: &ContentDigest,
        prefix: &[recursive_agent_contracts::ReceiptV1],
        mut trusted_clock: impl FnMut() -> DateTime<Utc>,
        fault: Option<NormalChatInterruptedRecoveryInterruptionV2>,
    ) -> Result<NormalChatInterruptedRecoveryRecordV2, PolicyError> {
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
            if view.state == NormalChatAttemptPolicyStateV2::RecoveredBeforeRelease {
                return self.confirm_interrupted_snapshot_v2(family, &reservation, &view, fault);
            }
            if view.state != NormalChatAttemptPolicyStateV2::Consumed
                || view.outcome.is_some()
                || view.settlement.is_some()
            {
                return Err(PolicyError::PermitStateConflict);
            }
            let mut record = self.read_record_or_reject(&retained.permit_id)?;
            let original = record.clone();
            let proof = self.interrupted_admission_v2(&view)?;
            let observed_at = trusted_clock();
            if view.local_control.as_ref().is_some_and(|control|
                matches!(control.state, PermitEvidenceStateV1::Revoked { at, .. } if observed_at < at))
            {
                return Err(NormalChatEgressDenialV1::Malformed.into());
            }
            let recovery = NormalChatInterruptedRecoveryRecordV2::from_observation(&proof, observed_at, prefix.to_vec())?;
            self.require_interrupted_source_unchanged_v2(&reservation, &view, &original)?;
            record.normal_chat_attempt_v2 = Some(NormalChatAttemptRecordV2::Interrupted {
                recovery: Box::new(recovery.clone()),
            });
            self.validate_record_bindings(&record)?;
            family.close_normal_chat_session_for_report_v2(
                observed_at,
                &mut trusted_clock,
                match fault {
                    Some(NormalChatInterruptedRecoveryInterruptionV2::FamilyClose(stage)) => Some(stage),
                    _ => None,
                },
            )?;
            // A late time callback may remove/replace records. Never republish
            // cached authority or overwrite a report after that final sample.
            self.require_interrupted_source_unchanged_v2(&reservation, &view, &original)?;
            self.replace_record(
                &record,
                match fault {
                    Some(NormalChatInterruptedRecoveryInterruptionV2::ChildRecovery(stage)) => Some(stage),
                    _ => None,
                },
            )?;
            let after = self.read_normal_chat_attempt_snapshot_v2(&reservation)?;
            if after.state != NormalChatAttemptPolicyStateV2::RecoveredBeforeRelease
                || self.interrupted_from_snapshot_v2(&after)?.as_ref() != Some(&recovery)
            {
                return Err(PolicyError::PermitStateConflict);
            }
            family.confirm_normal_chat_report_closed_v2()?;
            self.validate_v2_child_locator()?;
            Ok(recovery)
        })
    }
    /// Confirm ONLY an existing recovered record under the child lock. Unlike
    /// recover_interrupted_normal_chat_attempt_v2 this has no creation branch or
    /// clock callback; missing/downgraded state or fence rejects without repair.
    pub fn confirm_normal_chat_interrupted_recovery_v2(
        &self,
        family: &FamilyAuthorityStore,
        intent: &str,
        preflight: &ContentDigest,
    ) -> Result<NormalChatInterruptedRecoveryRecordV2, PolicyError> {
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
            self.confirm_interrupted_snapshot_v2(family, &reservation, &view, None)
        })
    }
    // Caller holds the canonical child lock. Shared by exact recovery retry and
    // confirmation so neither path can omit an existing-fence/durability check.
    fn confirm_interrupted_snapshot_v2(
        &self,
        family: &FamilyAuthorityStore,
        reservation: &NormalChatFamilyReservationV2,
        view: &NormalChatAttemptReadbackV2,
        fault: Option<NormalChatInterruptedRecoveryInterruptionV2>,
    ) -> Result<NormalChatInterruptedRecoveryRecordV2, PolicyError> {
        if view.state != NormalChatAttemptPolicyStateV2::RecoveredBeforeRelease {
            return Err(PolicyError::PermitStateConflict);
        }
        let existing = self
            .interrupted_from_snapshot_v2(view)?
            .ok_or(PolicyError::PermitStateConflict)?;
        family.confirm_normal_chat_report_closed_v2()?;
        if fault
            == Some(NormalChatInterruptedRecoveryInterruptionV2::FamilyClose(
                PermitTransitionStage::DirectoryFsync,
            ))
        {
            return Err(PolicyError::InjectedInterruption(
                PermitTransitionStage::DirectoryFsync,
            ));
        }
        self.root.sync_all()?;
        if fault
            == Some(NormalChatInterruptedRecoveryInterruptionV2::ChildRecovery(
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
    pub fn read_normal_chat_interrupted_recovery_v2(
        &self,
        family: &FamilyAuthorityStore,
        intent: &str,
    ) -> Result<Option<NormalChatInterruptedRecoveryRecordV2>, PolicyError> {
        let reservation = family
            .read_normal_chat_reservation(intent)?
            .ok_or(NormalChatEgressDenialV1::Malformed)?;
        self.with_lock(|| {
            let view = self.read_normal_chat_attempt_snapshot_v2(&reservation)?;
            let value = self.interrupted_from_snapshot_v2(&view)?;
            self.validate_v2_child_locator()?;
            Ok(value)
        })
    }
    fn interrupted_from_snapshot_v2(
        &self,
        view: &NormalChatAttemptReadbackV2,
    ) -> Result<Option<NormalChatInterruptedRecoveryRecordV2>, PolicyError> {
        if view.state != NormalChatAttemptPolicyStateV2::RecoveredBeforeRelease {
            return Ok(None);
        }
        let id = &view
            .effect
            .as_ref()
            .ok_or(PolicyError::PermitStateConflict)?
            .permit_id;
        let record = self.read_record_or_reject(id)?;
        let Some(NormalChatAttemptRecordV2::Interrupted { recovery }) =
            record.normal_chat_attempt_v2
        else {
            return Err(PolicyError::PermitStateConflict);
        };
        Ok(Some(*recovery))
    }
    fn interrupted_admission_v2(
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
    fn require_interrupted_source_unchanged_v2(
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
