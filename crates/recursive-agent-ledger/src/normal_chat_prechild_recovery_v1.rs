//! Closed parent-only terminal receipt for a pre-child admission prefix.
//! It is not a fabricated child RunFinalized or SDK NotSent observation.
use super::*;
use recursive_agent_contracts::jcs_canonical;
use recursive_agent_policy::{
    build_lineage, NormalChatPrechildRecoveryRecordV1, PermitEvidenceStateV1, PermitEvidenceV1,
};
fn invalid(reason: &str) -> LedgerError {
    LedgerError::ChildLinkInvalid(format!("pre-child recovery: {reason}"))
}
fn describe(bytes: &[u8]) -> Result<ArtifactDescriptorV1, LedgerError> {
    Ok(ArtifactDescriptorV1 {
        owner_id: derive_artifact_id(bytes)?,
        digest: ContentDigest::compute(bytes),
        byte_length: bytes.len() as u64,
        media_type: "application/json".into(),
        encoding: None,
    })
}
pub fn normal_chat_prechild_recovery_plan_v1(
    record: &NormalChatPrechildRecoveryRecordV1,
    closed: &PermitEvidenceV1,
) -> Result<(Vec<ReceiptDraftV1>, Vec<Vec<u8>>), LedgerError> {
    record.validate().map_err(|e| invalid(&e.to_string()))?;
    let original = record
        .context
        .session_root_issued_record_v2()
        .map_err(|e| invalid(&e.to_string()))?;
    let mut expected =
        PermitEvidenceV1::from_record(&original).map_err(|e| invalid(&e.to_string()))?;
    expected.state = closed.state.clone();
    let at = match closed.state {
        PermitEvidenceStateV1::Revoked { at, .. } => at,
        _ => return Err(invalid("native root not closed")),
    };
    if expected != *closed || at < original.permit.binding.issued_at {
        return Err(invalid("closed root differs from original"));
    }
    let payloads = vec![jcs_canonical(record)?, jcs_canonical(closed)?];
    let recovery = describe(&payloads[0])?;
    let control = describe(&payloads[1])?;
    let b = &closed.binding;
    let prep = record.request.preparation_digest()?;
    let failed = ReceiptOutcomeV1::Failed {
        reason: recursive_agent_contracts::NORMAL_CHAT_INTERRUPTED_ADMISSION_REASON_V2.into(),
    };
    let marker_at = std::cmp::max(at, record.observed_at);
    let drafts = [
        (
            ReceiptKindV1::PermitRevoked,
            at,
            b.action_digest.clone(),
            b.args_digest.clone(),
            vec![control],
            ReceiptOutcomeV1::Ok,
        ),
        (
            ReceiptKindV1::NormalChatPrechildAdmissionRecoveredV1,
            marker_at,
            prep.clone(),
            prep.clone(),
            vec![recovery],
            failed.clone(),
        ),
        (
            ReceiptKindV1::RunFinalized,
            marker_at,
            prep.clone(),
            prep,
            vec![],
            failed,
        ),
    ]
    .into_iter()
    .map(
        |(kind, valid_time, spec_digest, args_digest, artifact_refs, outcome)| ReceiptDraftV1 {
            run_id: b.run_id.clone(),
            step_id: b.step_id.clone(),
            kind,
            valid_time,
            lineage: build_lineage(&closed.permit_id, &b.policy_version),
            spec_digest,
            args_digest,
            artifact_refs,
            outcome,
        },
    )
    .collect();
    Ok((drafts, payloads))
}
pub(super) fn validate_prechild_recoveries(
    receipts: &[ReceiptV1],
    store: &ArtifactStore,
) -> Result<(), LedgerError> {
    for row in receipts
        .iter()
        .filter(|r| r.kind == ReceiptKindV1::NormalChatPrechildAdmissionRecoveredV1)
    {
        let descriptor = row
            .artifact_refs
            .first()
            .ok_or_else(|| invalid("recovery artifact absent"))?;
        let bytes = store.get(descriptor)?;
        if bytes.len() > 131072 || descriptor != &describe(&bytes)? {
            return Err(invalid("recovery descriptor differs"));
        }
        let value = recursive_agent_contracts::parse_strict_json_value(&bytes)
            .map_err(|_| invalid("invalid recovery JSON"))?;
        let record: NormalChatPrechildRecoveryRecordV1 = serde_json::from_value(value)?;
        if jcs_canonical(&record)? != bytes {
            return Err(invalid("lossy recovery record"));
        }
        record.validate().map_err(|e| invalid(&e.to_string()))?;
        let base = record.parent_prefix.len();
        if receipts.get(..base) != Some(record.parent_prefix.as_slice())
            || !(base + 2..=base + 3).contains(&receipts.len())
        {
            return Err(invalid("original prefix changed or suffix differs"));
        }
        let close = &receipts[base];
        if close.kind != ReceiptKindV1::PermitRevoked || close.artifact_refs.len() != 1 {
            return Err(invalid("root closure absent"));
        }
        let closed_bytes = store.get(&close.artifact_refs[0])?;
        let value = recursive_agent_contracts::parse_strict_json_value(&closed_bytes)
            .map_err(|_| invalid("invalid closed root JSON"))?;
        let closed: PermitEvidenceV1 = serde_json::from_value(value)?;
        if jcs_canonical(&closed)? != closed_bytes {
            return Err(invalid("lossy closed root"));
        }
        let (drafts, _) = normal_chat_prechild_recovery_plan_v1(&record, &closed)?;
        for (draft, actual) in drafts.into_iter().zip(&receipts[base..]) {
            let mut expected = make_receipt(draft, actual.prev_chain_digest.clone())?;
            expected.recorded_time = actual.recorded_time;
            if expected != *actual {
                return Err(invalid("recovery suffix differs from native plan"));
            }
        }
        for descriptor in &record.retained_artifacts {
            store.verify_descriptor(descriptor)?;
        }
    }
    Ok(())
}
