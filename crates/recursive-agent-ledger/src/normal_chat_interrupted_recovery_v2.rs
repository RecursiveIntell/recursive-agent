//! Offline evidence for an owner-observed missing executor outcome. This is
//! distinct from SDK settlement, current authority and provider/no-send proof.
use super::*;
use recursive_agent_policy::{
    build_lineage, parse_normal_chat_interrupted_recovery_record_v2_bytes,
    MAX_NORMAL_CHAT_INTERRUPTED_RECOVERY_BYTES_V2,
};

pub(super) fn validate_recoveries(
    receipts: &[ReceiptV1],
    store: &ArtifactStore,
    admissions: &normal_chat_v2::Admissions,
) -> Result<(), LedgerError> {
    let mut recovered = BTreeSet::new();
    for (index, row) in receipts.iter().enumerate() {
        if row.kind != ReceiptKindV1::NormalChatAttemptInterruptedV2 {
            continue;
        }
        let (admitted_at, proof) = admissions
            .get(&row.step_id)
            .ok_or_else(|| permit_divergence(index, "recovery lacks consumed V2 admission"))?;
        if *admitted_at >= index
            || !recovered.insert(row.step_id.clone())
            || row.artifact_refs.len() != 1
            || !receipts[..index].iter().any(|prior| {
                prior.kind == ReceiptKindV1::PermitConsumed && prior.step_id == row.step_id
            })
            || receipts.iter().any(|other| {
                other.kind == ReceiptKindV1::NormalChatAttemptSettledV2
                    && other.step_id == row.step_id
            })
        {
            return Err(permit_divergence(
                index,
                "recovery ordering/cardinality conflicts with the exclusive V2 terminal slot",
            ));
        }
        let descriptor = &row.artifact_refs[0];
        if descriptor.media_type != "application/json"
            || descriptor.encoding.is_some()
            || descriptor.byte_length > MAX_NORMAL_CHAT_INTERRUPTED_RECOVERY_BYTES_V2 as u64
        {
            return Err(permit_divergence(
                index,
                "recovery descriptor is not canonical JSON metadata",
            ));
        }
        let recovery =
            parse_normal_chat_interrupted_recovery_record_v2_bytes(&store.get(descriptor)?, proof)
                .map_err(|error| {
                    permit_divergence(index, &format!("invalid native recovery metadata: {error}"))
                })?;
        if receipts.get(..recovery.prefix_receipts.len())
            != Some(recovery.prefix_receipts.as_slice())
        {
            return Err(permit_divergence(
                index,
                "interrupted recovery retained prefix changed",
            ));
        }
        let effect = &proof.preflight.evidence;
        let outcome = recovery
            .ledger_outcome_v2(proof)
            .map_err(|error| permit_divergence(index, &error.to_string()))?;
        if row.run_id != effect.binding.run_id
            || row.step_id != effect.binding.step_id
            || row.spec_digest != effect.binding.action_digest
            || row.args_digest != effect.binding.args_digest
            || row.lineage != build_lineage(&effect.permit_id, &effect.binding.policy_version)
            || row.valid_time != recovery.observed_at
            || row.outcome != outcome
        {
            return Err(permit_divergence(
                index,
                "recovery differs from exact attempt/binding/observation/outcome",
            ));
        }
        // The generic lifecycle remains authoritative for closure and terminal
        // ordering. Additionally preserve the recovery's exact meaning at the
        // final run boundary: no arbitrary Failed reason or unrelated step.
        let control = proof
            .control_evidence()
            .map_err(|error| permit_divergence(index, &error.to_string()))?;
        for (terminal_index, terminal) in receipts.iter().enumerate().skip(index + 1) {
            if terminal.kind != ReceiptKindV1::RunFinalized {
                continue;
            }
            let latest_close = receipts[..terminal_index]
                .iter()
                .filter(|prior| {
                    prior.kind == ReceiptKindV1::PermitRevoked
                        && prior.step_id == control.binding.step_id
                })
                .map(|prior| prior.valid_time)
                .max();
            if terminal.run_id != row.run_id
                || terminal.step_id != row.step_id
                || terminal.spec_digest != row.spec_digest
                || terminal.args_digest != row.args_digest
                || terminal.lineage != row.lineage
                || terminal.outcome != outcome
                || !terminal.artifact_refs.is_empty()
                || terminal.valid_time < recovery.observed_at
                || latest_close.map_or(true, |at| terminal.valid_time < at)
            {
                return Err(permit_divergence(
                    terminal_index,
                    "finalization changes recovered attempt binding/outcome/time or lacks control closure",
                ));
            }
        }
    }
    Ok(())
}
