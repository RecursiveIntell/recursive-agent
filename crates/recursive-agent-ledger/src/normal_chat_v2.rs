//! Closed V2 normal-chat receipt admission, separate from V3 sealed completion.
//! All inputs are historical artifacts, not live authority or send continuations.
use super::*;
use recursive_agent_policy::{
    build_lineage, parse_normal_chat_ledger_admission_v2_bytes,
    NormalChatLedgerAdmissionEvidenceV2, PermitEvidenceV1, NORMAL_CHAT_EFFECT_TOOL_V2,
};

pub(super) type Admissions = BTreeMap<CurrentStepId, (usize, NormalChatLedgerAdmissionEvidenceV2)>;

fn canonical_evidence(bytes: &[u8], index: usize) -> Result<PermitEvidenceV1, LedgerError> {
    let value = recursive_agent_contracts::parse_strict_json_value(bytes)
        .map_err(|_| permit_divergence(index, "V2 permit evidence is not strict JSON"))?;
    if recursive_agent_contracts::jcs_canonical(&value)? != bytes {
        return Err(permit_divergence(
            index,
            "V2 permit evidence is not canonical",
        ));
    }
    let evidence: PermitEvidenceV1 = serde_json::from_value(value).map_err(|_| {
        permit_divergence(index, "V2 permit evidence has unknown or malformed fields")
    })?;
    if recursive_agent_contracts::jcs_canonical(&evidence)? != bytes {
        return Err(permit_divergence(
            index,
            "V2 evidence lost original wire members",
        ));
    }
    evidence
        .validate()
        .map_err(|error| permit_divergence(index, &error.to_string()))?;
    Ok(evidence)
}

fn require_declared_step(
    receipts: &[ReceiptV1],
    evidence: &PermitEvidenceV1,
    index: usize,
) -> Result<(), LedgerError> {
    let declared = receipts
        .iter()
        .find(|row| {
            row.kind == ReceiptKindV1::StepStarted && row.step_id == evidence.binding.step_id
        })
        .ok_or_else(|| permit_divergence(index, "V2 step declaration absent"))?;
    if declared.run_id != evidence.binding.run_id
        || declared.spec_digest != evidence.binding.action_digest
        || declared.args_digest != evidence.binding.args_digest
        || declared.lineage != build_lineage(&evidence.permit_id, &evidence.binding.policy_version)
    {
        return Err(permit_divergence(
            index,
            "V2 step declaration differs from admitted action/lineage",
        ));
    }
    Ok(())
}

pub(super) fn read_admissions(
    receipts: &[ReceiptV1],
    store: &ArtifactStore,
) -> Result<Admissions, LedgerError> {
    let mut admitted = Admissions::new();
    for (index, receipt) in receipts.iter().enumerate() {
        if receipt.kind != ReceiptKindV1::NormalChatAttemptAdmittedV2 {
            continue;
        }
        if receipt.artifact_refs.len() != 1 || receipt.outcome != ReceiptOutcomeV1::Ok {
            return Err(permit_divergence(
                index,
                "V2 admission requires one successful metadata artifact",
            ));
        }
        let descriptor = &receipt.artifact_refs[0];
        if descriptor.media_type != "application/json" || descriptor.encoding.is_some() {
            return Err(permit_divergence(
                index,
                "V2 admission artifact encoding is not canonical JSON",
            ));
        }
        let proof = parse_normal_chat_ledger_admission_v2_bytes(&store.get(descriptor)?).map_err(
            |error| permit_divergence(index, &format!("invalid V2 admission evidence: {error}")),
        )?;
        let effect = &proof.preflight.evidence;
        require_declared_step(&receipts[..index], effect, index)?;
        if receipt.run_id != effect.binding.run_id
            || receipt.step_id != effect.binding.step_id
            || receipt.valid_time != proof.preflight.recorded_at
            || receipt.spec_digest != effect.binding.action_digest
            || receipt.args_digest != effect.binding.args_digest
            || receipt.lineage != build_lineage(&effect.permit_id, &effect.binding.policy_version)
            || receipts.iter().any(|row| {
                row.step_id == receipt.step_id && row.kind == ReceiptKindV1::ProviderEgressAdmitted
            })
        {
            return Err(permit_divergence(
                index,
                "V2 admission does not bind exact receipt/lane/lineage",
            ));
        }
        let control = proof
            .control_evidence()
            .map_err(|error| permit_divergence(index, &error.to_string()))?;
        require_declared_step(&receipts[..index], &control, index)?;
        let issued_control = receipts[..index]
            .iter()
            .find(|row| {
                row.kind == ReceiptKindV1::PermitIssued && row.step_id == control.binding.step_id
            })
            .ok_or_else(|| {
                permit_divergence(
                    index,
                    "V2 admission has no preceding local-control issuance",
                )
            })?;
        if issued_control.artifact_refs.len() != 1
            || issued_control.lineage
                != build_lineage(&control.permit_id, &control.binding.policy_version)
            || canonical_evidence(&store.get(&issued_control.artifact_refs[0])?, index)? != control
        {
            return Err(permit_divergence(
                index,
                "V2 admission local-control evidence differs",
            ));
        }
        if admitted
            .insert(receipt.step_id.clone(), (index, proof))
            .is_some()
        {
            return Err(permit_divergence(index, "duplicate V2 admission"));
        }
    }
    Ok(admitted)
}

pub(super) fn validate_settlements(
    receipts: &[ReceiptV1],
    store: &ArtifactStore,
    admissions: &Admissions,
) -> Result<(), LedgerError> {
    use recursive_agent_policy::parse_normal_chat_settlement_metadata_v2_bytes;
    let mut settled_steps = BTreeSet::new();
    for (index, row) in receipts.iter().enumerate() {
        if row.kind != ReceiptKindV1::NormalChatAttemptSettledV2 {
            continue;
        }
        let (admitted_at, proof) = admissions
            .get(&row.step_id)
            .ok_or_else(|| permit_divergence(index, "V2 settlement lacks consumed admission"))?;
        let effect = &proof.preflight.evidence;
        if *admitted_at >= index
            || !settled_steps.insert(row.step_id.clone())
            || !receipts[..index].iter().any(|prior| {
                prior.kind == ReceiptKindV1::PermitConsumed && prior.step_id == row.step_id
            })
            || !(1..=2).contains(&row.artifact_refs.len())
        {
            return Err(permit_divergence(
                index,
                "V2 settlement ordering/cardinality differs",
            ));
        }
        for descriptor in &row.artifact_refs {
            if descriptor.media_type != "application/json" || descriptor.encoding.is_some() {
                return Err(permit_divergence(
                    index,
                    "V2 settlement descriptor is not canonical metadata",
                ));
            }
        }
        let settlement = parse_normal_chat_settlement_metadata_v2_bytes(
            &store.get(&row.artifact_refs[0])?,
            proof,
        )
        .map_err(|error| {
            permit_divergence(index, &format!("invalid V2 settlement metadata: {error}"))
        })?;
        if row.run_id != effect.binding.run_id
            || row.step_id != effect.binding.step_id
            || row.spec_digest != effect.binding.action_digest
            || row.args_digest != effect.binding.args_digest
            || row.lineage != build_lineage(&effect.permit_id, &effect.binding.policy_version)
            || row.valid_time != settlement.outcome.recorded_at
            || row.outcome
                != settlement
                    .ledger_outcome_v2(proof)
                    .map_err(|error| permit_divergence(index, &error.to_string()))?
        {
            return Err(permit_divergence(
                index,
                "V2 settlement differs from exact reported outcome/binding/time",
            ));
        }
        let degradation = settlement
            .degradation_record_v1(proof)
            .map_err(|error| permit_divergence(index, &error.to_string()))?;
        match degradation {
            Some(expected) => {
                if row.artifact_refs.len() != 2
                    || store.get(&row.artifact_refs[1])?
                        != recursive_agent_contracts::jcs_canonical(&expected)?
                {
                    return Err(permit_divergence(
                        index,
                        "V2 degradation artifact missing or misbound",
                    ));
                }
            }
            None if row.artifact_refs.len() == 1 => {}
            None => {
                return Err(permit_divergence(
                    index,
                    "V2 success/failure has unexpected degradation artifact",
                ))
            }
        }
    }
    Ok(())
}

/// Check by closed lane identity as well as its metadata slot. Stripping the
/// network bit or relabeling a proved step cannot bypass the V2 contract.
pub(super) fn validate_transition(
    receipt: &ReceiptV1,
    evidence: &PermitEvidenceV1,
    bytes: &[u8],
    index: usize,
    admissions: &Admissions,
) -> Result<(), LedgerError> {
    let entry = admissions.get(&receipt.step_id);
    if evidence.binding.tool != NORMAL_CHAT_EFFECT_TOOL_V2 && entry.is_none() {
        return Ok(());
    }
    let (admission_index, proof) =
        entry.ok_or_else(|| permit_divergence(index, "V2 effect lacks admission evidence"))?;
    if evidence.binding.tool != NORMAL_CHAT_EFFECT_TOOL_V2
        || *admission_index >= index
        || receipt.lineage != build_lineage(&evidence.permit_id, &evidence.binding.policy_version)
        || canonical_evidence(bytes, index)? != *evidence
    {
        return Err(permit_divergence(
            index,
            "V2 transition does not bind its exact lane/admission/lineage",
        ));
    }
    match receipt.kind {
        ReceiptKindV1::PermitIssued => {
            let expected = proof
                .issued_effect_evidence()
                .map_err(|error| permit_divergence(index, &error.to_string()))?;
            if *evidence != expected {
                return Err(permit_divergence(
                    index,
                    "V2 issuance is not the policy-owned historical projection",
                ));
            }
        }
        ReceiptKindV1::PermitConsumed => {
            if *evidence != proof.preflight.evidence
                || receipt.valid_time != proof.preflight.recorded_at
            {
                return Err(permit_divergence(
                    index,
                    "V2 consumption differs from exact preflight evidence/time",
                ));
            }
        }
        _ => {
            return Err(permit_divergence(
                index,
                "V2 consumed admission contradicts rejection or revocation",
            ))
        }
    }
    Ok(())
}
