//! Three-row terminal transcript with no issued or consumed local permit.
use super::*;
use recursive_agent_contracts::jcs_canonical;
use recursive_agent_policy::{
    build_lineage, DurablePermitStore, FamilyAuthorityStore, NormalChatAttemptPolicyStateV2,
    NormalChatFamilyReservationV2, NormalChatGrantContextV2, NormalChatUnconsumedRecoveryRecordV1,
};
fn invalid(s: &str) -> LedgerError {
    LedgerError::ChildLinkInvalid(format!("unconsumed recovery: {s}"))
}
fn native<T>(r: Result<T, recursive_agent_policy::PolicyError>) -> Result<T, LedgerError> {
    r.map_err(|e| invalid(&e.to_string()))
}
fn describe(b: &[u8]) -> Result<ArtifactDescriptorV1, LedgerError> {
    Ok(ArtifactDescriptorV1 {
        owner_id: derive_artifact_id(b)?,
        digest: ContentDigest::compute(b),
        byte_length: b.len() as u64,
        media_type: "application/json".into(),
        encoding: None,
    })
}
fn plan(
    record: &NormalChatUnconsumedRecoveryRecordV1,
) -> Result<(Vec<ReceiptDraftV1>, Vec<u8>, ArtifactDescriptorV1), LedgerError> {
    native(record.validate())?;
    let bytes = jcs_canonical(record)?;
    let descriptor = describe(&bytes)?;
    let attempt = &record.reservation.attempt;
    let run_id = attempt.run_id()?;
    let digest = content_digest(attempt)?;
    let step = recursive_agent_contracts::derive_child_receipt_step_id(
        &attempt.run_id()?,
        &digest,
        "interruption",
    )?;
    let failed = ReceiptOutcomeV1::Failed {
        reason: recursive_agent_contracts::NORMAL_CHAT_INTERRUPTED_ADMISSION_REASON_V2.into(),
    };
    let rows = [
        (
            ReceiptKindV1::RunStarted,
            record.checkpoint.at,
            vec![],
            ReceiptOutcomeV1::Ok,
        ),
        (
            ReceiptKindV1::NormalChatUnconsumedAttemptRecoveredV1,
            record.observed_at,
            vec![descriptor.clone()],
            failed.clone(),
        ),
        (
            ReceiptKindV1::RunFinalized,
            record.observed_at,
            vec![],
            failed,
        ),
    ]
    .into_iter()
    .map(
        |(kind, valid_time, artifact_refs, outcome)| ReceiptDraftV1 {
            run_id: run_id.clone(),
            step_id: step.clone(),
            kind,
            valid_time,
            lineage: build_lineage(
                &record.reservation.child_control.child_control_permit_id,
                &record.context.root_control.binding.policy_version,
            ),
            spec_digest: digest.clone(),
            args_digest: digest.clone(),
            artifact_refs,
            outcome,
        },
    )
    .collect();
    Ok((rows, bytes, descriptor))
}
fn compare(draft: ReceiptDraftV1, row: &ReceiptV1) -> Result<(), LedgerError> {
    let mut expected = make_receipt(draft, row.prev_chain_digest.clone())?;
    expected.recorded_time = row.recorded_time;
    if expected != *row {
        return Err(invalid("row differs from native source"));
    }
    Ok(())
}
fn source(
    root: &File,
    family: &FamilyAuthorityStore,
    context: &NormalChatGrantContextV2,
    reservation: &NormalChatFamilyReservationV2,
) -> Result<NormalChatUnconsumedRecoveryRecordV1, LedgerError> {
    let record = native(family.read_normal_chat_unconsumed_recovery_v1())?
        .ok_or_else(|| invalid("native source absent"))?;
    if record.context != *context
        || record.reservation != *reservation
        || native(family.read_normal_chat_reservation(&reservation.attempt.dispatch_intent_ref))?
            .as_ref()
            != Some(reservation)
    {
        return Err(invalid("native source binding differs"));
    }
    native(record.checkpoint.check(root))?;
    let policy = native(DurablePermitStore::require_existing_from_run_root_fd(root))?;
    let view = native(
        policy.read_normal_chat_attempt_v2(family, &reservation.attempt.dispatch_intent_ref),
    )?;
    if view.state != NormalChatAttemptPolicyStateV2::Unbegun
        || view.local_control.is_some()
        || view.effect.is_some()
        || view.preflight.is_some()
        || view.outcome.is_some()
        || view.settlement.is_some()
    {
        return Err(invalid("native permit/report exists"));
    }
    if native(family.read_normal_chat_session_snapshot_v2())?
        .admission
        .closed_at
        .is_none()
    {
        return Err(invalid("family not closed"));
    }
    Ok(record)
}
pub struct VerifiedNormalChatUnconsumedChildV1 {
    snapshot: VerifiedReceiptSnapshot,
    inventory: Vec<ArtifactDescriptorV1>,
}
impl VerifiedNormalChatUnconsumedChildV1 {
    pub fn chain_head(&self) -> &str {
        &self.snapshot.verification().final_head
    }
    pub fn terminal_receipt(&self) -> &ReceiptV1 {
        &self.snapshot.receipts()[2]
    }
    pub fn artifact_inventory(&self) -> &[ArtifactDescriptorV1] {
        &self.inventory
    }
}
pub fn verify_closed_unconsumed_normal_chat_child_from_dir_fd(
    root: &File,
    family: &FamilyAuthorityStore,
    context: &NormalChatGrantContextV2,
    reservation: &NormalChatFamilyReservationV2,
) -> Result<VerifiedNormalChatUnconsumedChildV1, LedgerError> {
    let record = source(root, family, context, reservation)?;
    let (drafts, _, descriptor) = plan(&record)?;
    let snapshot = read_only_appendable_snapshot_expected_run_from_dir_fd(
        root,
        &reservation.attempt.run_id()?,
    )?;
    if snapshot.receipts().len() != 3
        || snapshot.verification().terminal_state != RunTerminalStateV1::Failed
    {
        return Err(invalid("not exact unconsumed terminal"));
    }
    for (draft, row) in drafts.into_iter().zip(snapshot.receipts()) {
        compare(draft, row)?;
    }
    let store = ArtifactStore::from_run_root_fd(root, false)?;
    store.require_exact_inventory(std::slice::from_ref(&descriptor))?;
    store.require_locator_matches(root)?;
    if source(root, family, context, reservation)? != record {
        return Err(invalid("native source changed"));
    }
    Ok(VerifiedNormalChatUnconsumedChildV1 {
        snapshot,
        inventory: vec![descriptor],
    })
}
pub fn publish_unconsumed_normal_chat_child_recovery_from_dir_fd(
    root: &File,
    paths: &RunPaths,
    family: &FamilyAuthorityStore,
    context: &NormalChatGrantContextV2,
    reservation: &NormalChatFamilyReservationV2,
    fault: Option<(usize, AppendStage)>,
) -> Result<VerifiedNormalChatUnconsumedChildV1, LedgerError> {
    let record = source(root, family, context, reservation)?;
    let (drafts, bytes, descriptor) = plan(&record)?;
    let snapshot = recoverable_normal_chat_preflight_snapshot_from_dir_fd(
        root,
        &reservation.attempt.run_id()?,
    )?;
    if snapshot.receipts().len() > 3 {
        return Err(invalid("unexpected suffix"));
    }
    for (draft, row) in drafts.iter().cloned().zip(snapshot.receipts()) {
        compare(draft, row)?;
    }
    let store = ArtifactStore::from_run_root_fd(root, false)?;
    store.require_inventory_subset(&[descriptor])?;
    store.put(&bytes, "application/json", None)?;
    let mut chain = open_existing_from_dir_fd(paths, root)?;
    for (ordinal, draft) in drafts
        .into_iter()
        .enumerate()
        .skip(snapshot.receipts().len())
    {
        let receipt = make_receipt(draft, chain.head().clone())?;
        chain.append_with_interruption(
            receipt,
            fault.filter(|(i, _)| *i == ordinal).map(|(_, s)| s),
        )?;
    }
    chain.sync_all()?;
    verify_closed_unconsumed_normal_chat_child_from_dir_fd(root, family, context, reservation)
}
pub(super) fn validate_unconsumed_recoveries(
    receipts: &[ReceiptV1],
    store: &ArtifactStore,
) -> Result<(), LedgerError> {
    for row in receipts
        .iter()
        .filter(|r| r.kind == ReceiptKindV1::NormalChatUnconsumedAttemptRecoveredV1)
    {
        let descriptor = row
            .artifact_refs
            .first()
            .ok_or_else(|| invalid("metadata absent"))?;
        let bytes = store.get(descriptor)?;
        if bytes.len() > 131072 || *descriptor != describe(&bytes)? {
            return Err(invalid("metadata bound/descriptor differs"));
        }
        let value = recursive_agent_contracts::parse_strict_json_value(&bytes)
            .map_err(|_| invalid("invalid JSON"))?;
        let record: NormalChatUnconsumedRecoveryRecordV1 = serde_json::from_value(value)?;
        if jcs_canonical(&record)? != bytes || !(2..=3).contains(&receipts.len()) {
            return Err(invalid("lossy record/transcript"));
        }
        let (drafts, _, _) = plan(&record)?;
        for (draft, row) in drafts.into_iter().zip(receipts) {
            compare(draft, row)?;
        }
    }
    Ok(())
}
