//! Historical, non-authorizing V2 normal-chat admission metadata. Native policy
//! and canonical readback share these expected projections; no bytes restore a
//! live continuation. Cumulative parent budget/link verification is runtime work.
use super::*;
#[cfg(test)]
mod tests;
use recursive_agent_contracts::NormalChatSessionV1;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatGrantContextV2 {
    pub grant: NormalChatEgressGrantV1,
    pub session: NormalChatSessionV1,
    pub root_control: ExecutionPermitV1,
}
impl NormalChatGrantContextV2 {
    /// Pure historical projection, never a native control or family capability.
    pub fn session_root_issued_record_v2(&self) -> Result<PermitRecordV1, PolicyError> {
        let (expected, _) = normal_chat_session_control::expected_session_control(
            &self.grant,
            &self.session,
            self.root_control.binding.issued_at,
            self.root_control.binding.actor.clone(),
        )?;
        if expected != self.root_control {
            return Err(PolicyError::PermitStateConflict);
        }
        Ok(evidence_record(expected, PermitStateV1::Issued))
    }
    /// Immutable family material for require-existing readback only.
    pub fn session_family_grant_v2(&self) -> Result<FamilyRootGrantV1, PolicyError> {
        self.session_root_issued_record_v2()?;
        let (_, family) = normal_chat_session_control::expected_session_control(
            &self.grant,
            &self.session,
            self.root_control.binding.issued_at,
            self.root_control.binding.actor.clone(),
        )?;
        Ok(family)
    }

    pub(super) fn validate_reservation(
        &self,
        reservation: &NormalChatFamilyReservationV2,
    ) -> Result<(), PolicyError> {
        let attempt = &reservation.attempt;
        let root = &self.root_control;
        let (expected, family) = normal_chat_session_control::expected_session_control(
            &self.grant,
            &self.session,
            root.binding.issued_at,
            root.binding.actor.clone(),
        )?;
        if expected != *root
            || self.session.run_id()? != attempt.session_run_id
            || self.session.conversation_ref != attempt.operation.conversation_ref
        {
            return Err(PolicyError::PermitStateConflict);
        }
        normal_chat_egress::check_normal_chat_grant_attempt(
            &self.grant,
            attempt,
            reservation.reserved_at,
        )?;
        // Reuse the owner shape/attenuation rules for this one historical child.
        // This temporary input is NOT persisted family state or cumulative proof.
        let shape = FamilyAuthorityStateV1 {
            grant: family.clone(),
            parent_revoked_at: None,
            children: BTreeMap::new(),
            normal_chat_session: None,
        };
        let child = &reservation.child_control;
        validate_family_request(&shape, &child.request, reservation.reserved_at)?;
        if child.child_control_permit_id != derive_family_child_permit_id(&child.request, &family)?
            || child.request.parent_operation_id != attempt.session_run_id
            || child.request.child_run_id != attempt.run_id()?
            || child.request.child_operation_digest != content_digest(attempt)?
            || !matches!(child.state, FamilyChildPermitStateV1::Issued)
            || child.request.requested_budget != normal_chat_metadata_budget_v2(&attempt.operation)?
        {
            return Err(PolicyError::PermitStateConflict);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatLedgerAdmissionSchemaV2 {
    #[serde(rename = "recursive-agent.normal-chat-ledger-admission/v2")]
    V2,
}
/// Closed correlation evidence for one actually consumed policy attempt. Its
/// hashes and retained grant are not authentication against a same-UID writer.
/// Full parent admission/links and current authority are separate runtime gates.
///
/// ```compile_fail
/// use recursive_agent_policy::NormalChatAttemptConsumptionV2;
/// let _: NormalChatAttemptConsumptionV2 = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatLedgerAdmissionEvidenceV2 {
    pub schema: NormalChatLedgerAdmissionSchemaV2,
    pub admission: NormalChatRetainedAdmissionV2,
    pub preflight: PermitPreflightReceiptV1,
}
impl NormalChatLedgerAdmissionEvidenceV2 {
    pub fn validate(&self) -> Result<(), PolicyError> {
        let (_, effect) = normal_chat_attempt_v2::build_attempt_permits(&self.admission)?;
        self.preflight.validate()?;
        let PermitEvidenceStateV1::Consumed { at } = self.preflight.evidence.state else {
            return Err(PolicyError::PermitStateConflict);
        };
        let expected = effect_evidence(&effect, PermitStateV1::Consumed { consumed_at: at })?;
        if self.preflight.recorded_at != at
            || self.preflight.permit_id != effect.permit_id
            || self.preflight.evidence != expected
            || at < effect.binding.issued_at
            || at < effect.binding.not_before
            || at >= effect.binding.expires_at
        {
            return Err(PolicyError::PermitStateConflict);
        }
        normal_chat_egress::check_normal_chat_grant_attempt(
            &self.admission.context.grant,
            &self.admission.reservation.attempt,
            at,
        )?;
        Ok(())
    }
    /// Original local-control issuance snapshot, even after later revocation.
    pub fn control_evidence(&self) -> Result<PermitEvidenceV1, PolicyError> {
        self.validate()?;
        let (control, effect) = normal_chat_attempt_v2::build_attempt_permits(&self.admission)?;
        let mut record = evidence_record(control, PermitStateV1::Issued);
        record
            .child_allocations
            .insert(effect.permit_id, effect.binding.budget);
        PermitEvidenceV1::from_record(&record)
    }
    /// Policy-owned historical issue projection of an atomic issue+consume.
    /// No Issued effect was externally published and this cannot authorize retry.
    pub fn issued_effect_evidence(&self) -> Result<PermitEvidenceV1, PolicyError> {
        self.validate()?;
        let (_, effect) = normal_chat_attempt_v2::build_attempt_permits(&self.admission)?;
        effect_evidence(&effect, PermitStateV1::Issued)
    }
}
fn evidence_record(permit: ExecutionPermitV1, state: PermitStateV1) -> PermitRecordV1 {
    PermitRecordV1 {
        permit,
        state,
        child_allocations: BTreeMap::new(),
        preflight_receipt: None,
        outcome_receipt: None,
        retained_normal_chat_admission: None,
        normal_chat_settlement: None,
        normal_chat_attempt_v2: None,
    }
}
fn effect_evidence(
    permit: &ExecutionPermitV1,
    state: PermitStateV1,
) -> Result<PermitEvidenceV1, PolicyError> {
    PermitEvidenceV1::from_record(&evidence_record(permit.clone(), state))
}

/// Canonical-byte metadata ingress: bounded strict JSON, no duplicate/unknown
/// keys, no V1/V3 fallback, no tolerant normalization or reserialized substitute.
pub fn parse_normal_chat_ledger_admission_v2_bytes(
    input: &[u8],
) -> Result<NormalChatLedgerAdmissionEvidenceV2, PolicyError> {
    if input.len() as u64 > MAX_PERMIT_RECORD_BYTES {
        return Err(NormalChatEgressDenialV1::Malformed.into());
    }
    let value = recursive_agent_contracts::parse_strict_json_value(input)
        .map_err(|_| NormalChatEgressDenialV1::Malformed)?;
    if jcs_canonical(&value)? != input {
        return Err(NormalChatEgressDenialV1::Malformed.into());
    }
    let evidence: NormalChatLedgerAdmissionEvidenceV2 = serde_json::from_value(value)?;
    if jcs_canonical(&evidence)? != input {
        return Err(NormalChatEgressDenialV1::Malformed.into());
    }
    evidence.validate()?;
    Ok(evidence)
}
/// Owned V2/session records must retain every original wire member. Comparing
/// typed canonical bytes rejects lossy unit aliases/default insertion, not just
/// non-JCS text. Other legacy V1 record formats are not normalized or migrated.
pub(super) fn validate_governed_record_wire(
    bytes: &[u8],
    record: &PermitRecordV1,
) -> Result<(), PolicyError> {
    if (record.normal_chat_attempt_v2.is_some()
        || normal_chat_attempt_v2::is_v2_attempt_tool(&record.permit.binding.tool)
        || record.permit.binding.tool == normal_chat_session_control::SESSION_CONTROL_TOOL)
        && jcs_canonical(record)? != bytes
    {
        return Err(rejected(
            &record.permit.permit_id,
            PermitRejectionReasonV1::StateCorrupted,
        ));
    }
    Ok(())
}

impl DurablePermitStore {
    /// Historical repair projection from canonical family identity and validated
    /// child records. Prepared/unbegun state has no consumed admission evidence.
    pub fn read_normal_chat_ledger_admission_v2(
        &self,
        family: &FamilyAuthorityStore,
        intent: &str,
    ) -> Result<Option<NormalChatLedgerAdmissionEvidenceV2>, PolicyError> {
        let reservation = family
            .read_normal_chat_reservation(intent)?
            .ok_or(NormalChatEgressDenialV1::Malformed)?;
        self.with_lock(|| {
            let view = self.read_normal_chat_attempt_snapshot_v2(&reservation)?;
            let Some(preflight) = view.preflight else {
                return Ok(None);
            };
            let control = view.local_control.ok_or(PolicyError::PermitStateConflict)?;
            let record = self.read_record_or_reject(&control.permit_id)?;
            let Some(NormalChatAttemptRecordV2::Control { admission }) =
                record.normal_chat_attempt_v2
            else {
                return Err(PolicyError::PermitStateConflict);
            };
            let evidence = NormalChatLedgerAdmissionEvidenceV2 {
                schema: NormalChatLedgerAdmissionSchemaV2::V2,
                admission: *admission,
                preflight,
            };
            evidence.validate()?;
            self.validate_v2_child_locator()?;
            Ok(Some(evidence))
        })
    }
}
