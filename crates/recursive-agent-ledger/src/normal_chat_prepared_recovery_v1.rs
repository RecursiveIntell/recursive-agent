//! Five-row local-control-only terminal recovery. Never invents effect consumption.
use super::*;
use recursive_agent_contracts::jcs_canonical;
use recursive_agent_policy::{
    build_lineage, DurablePermitStore, FamilyAuthorityStore, NormalChatAttemptPolicyStateV2,
    NormalChatFamilyReservationV2, NormalChatGrantContextV2, NormalChatPreparedRecoveryEvidenceV1,
};
fn invalid(message: &str) -> LedgerError {
    LedgerError::ChildLinkInvalid(format!("prepared recovery: {message}"))
}
fn native<T>(result: Result<T, recursive_agent_policy::PolicyError>) -> Result<T, LedgerError> {
    result.map_err(|e| invalid(&e.to_string()))
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
struct Plan {
    drafts: Vec<ReceiptDraftV1>,
    payloads: Vec<Vec<u8>>,
    descriptors: Vec<ArtifactDescriptorV1>,
}
fn plan(evidence: &NormalChatPreparedRecoveryEvidenceV1) -> Result<Plan, LedgerError> {
    native(evidence.validate())?;
    let control = native(evidence.control())?;
    native(evidence.closed_control())?;
    let payloads = vec![jcs_canonical(&control)?, jcs_canonical(evidence)?];
    let descriptors = payloads
        .iter()
        .map(|b| describe(b))
        .collect::<Result<Vec<_>, _>>()?;
    let failed = ReceiptOutcomeV1::Failed {
        reason: recursive_agent_contracts::NORMAL_CHAT_INTERRUPTED_ADMISSION_REASON_V2.into(),
    };
    let drafts = [
        (
            ReceiptKindV1::RunStarted,
            control.binding.issued_at,
            vec![],
            ReceiptOutcomeV1::Ok,
        ),
        (
            ReceiptKindV1::StepStarted,
            control.binding.issued_at,
            vec![],
            ReceiptOutcomeV1::Ok,
        ),
        (
            ReceiptKindV1::PermitIssued,
            control.binding.issued_at,
            vec![descriptors[0].clone()],
            ReceiptOutcomeV1::Ok,
        ),
        (
            ReceiptKindV1::NormalChatPreparedAttemptRecoveredV1,
            evidence.recovery.observed_at,
            vec![descriptors[1].clone()],
            failed.clone(),
        ),
        (
            ReceiptKindV1::RunFinalized,
            evidence.recovery.observed_at,
            vec![],
            failed,
        ),
    ]
    .into_iter()
    .map(
        |(kind, valid_time, artifact_refs, outcome)| ReceiptDraftV1 {
            run_id: control.binding.run_id.clone(),
            step_id: control.binding.step_id.clone(),
            kind,
            valid_time,
            lineage: build_lineage(&control.permit_id, &control.binding.policy_version),
            spec_digest: control.binding.action_digest.clone(),
            args_digest: control.binding.args_digest.clone(),
            artifact_refs,
            outcome,
        },
    )
    .collect();
    Ok(Plan {
        drafts,
        payloads,
        descriptors,
    })
}
fn compare(draft: ReceiptDraftV1, row: &ReceiptV1) -> Result<(), LedgerError> {
    let mut expected = make_receipt(draft, row.prev_chain_digest.clone())?;
    expected.recorded_time = row.recorded_time;
    if expected != *row {
        return Err(invalid("retained row differs from native plan"));
    }
    Ok(())
}
fn source(
    root: &File,
    family: &FamilyAuthorityStore,
    context: &NormalChatGrantContextV2,
    reservation: &NormalChatFamilyReservationV2,
) -> Result<NormalChatPreparedRecoveryEvidenceV1, LedgerError> {
    let policy = native(DurablePermitStore::require_existing_from_run_root_fd(root))?;
    let intent = &reservation.attempt.dispatch_intent_ref;
    let view = native(policy.read_normal_chat_attempt_v2(family, intent))?;
    if view.state != NormalChatAttemptPolicyStateV2::RecoveredPrepared
        || view.effect.is_some()
        || view.preflight.is_some()
        || view.outcome.is_some()
        || view.settlement.is_some()
    {
        return Err(invalid("not native prepared-only terminal"));
    }
    let admission = native(policy.read_retained_normal_chat_admission_v2())?
        .ok_or_else(|| invalid("retained context absent"))?;
    let recovery = native(policy.read_normal_chat_prepared_recovery_v1(family, intent))?
        .ok_or_else(|| invalid("native disposition absent"))?;
    if admission.context != *context || admission.reservation != *reservation {
        return Err(invalid("context/reservation differs"));
    }
    let evidence = NormalChatPreparedRecoveryEvidenceV1 {
        admission,
        recovery,
    };
    if view.local_control.as_ref() != Some(&native(evidence.closed_control())?) {
        return Err(invalid("closed control differs"));
    }
    Ok(evidence)
}
pub struct VerifiedNormalChatPreparedChildV1 {
    snapshot: VerifiedReceiptSnapshot,
    inventory: Vec<ArtifactDescriptorV1>,
}
impl VerifiedNormalChatPreparedChildV1 {
    pub fn terminal_receipt(&self) -> &ReceiptV1 {
        &self.snapshot.receipts()[4]
    }
    pub fn chain_head(&self) -> &str {
        &self.snapshot.verification().final_head
    }
    pub fn artifact_inventory(&self) -> &[ArtifactDescriptorV1] {
        &self.inventory
    }
}
pub fn verify_closed_prepared_normal_chat_child_from_dir_fd(
    root: &File,
    family: &FamilyAuthorityStore,
    context: &NormalChatGrantContextV2,
    reservation: &NormalChatFamilyReservationV2,
) -> Result<VerifiedNormalChatPreparedChildV1, LedgerError> {
    let evidence = source(root, family, context, reservation)?;
    let plan = plan(&evidence)?;
    let snapshot = read_only_appendable_snapshot_expected_run_from_dir_fd(
        root,
        &reservation.attempt.run_id()?,
    )?;
    if snapshot.receipts().len() != 5
        || snapshot.verification().terminal_state != RunTerminalStateV1::Failed
    {
        return Err(invalid("not five-row failed child"));
    }
    for (draft, row) in plan.drafts.into_iter().zip(snapshot.receipts()) {
        compare(draft, row)?;
    }
    let store = ArtifactStore::from_run_root_fd(root, false)?;
    store.require_exact_inventory(&plan.descriptors)?;
    store.require_locator_matches(root)?;
    if source(root, family, context, reservation)? != evidence {
        return Err(invalid("native source changed"));
    }
    Ok(VerifiedNormalChatPreparedChildV1 {
        snapshot,
        inventory: plan.descriptors,
    })
}
pub fn publish_prepared_normal_chat_child_recovery_from_dir_fd(
    root: &File,
    paths: &RunPaths,
    family: &FamilyAuthorityStore,
    context: &NormalChatGrantContextV2,
    reservation: &NormalChatFamilyReservationV2,
    fault: Option<(usize, AppendStage)>,
) -> Result<VerifiedNormalChatPreparedChildV1, LedgerError> {
    let evidence = source(root, family, context, reservation)?;
    let plan = plan(&evidence)?;
    let snapshot = recoverable_normal_chat_preflight_snapshot_from_dir_fd(
        root,
        &reservation.attempt.run_id()?,
    )?;
    if snapshot.receipts().len() > 5 {
        return Err(invalid("unexpected child suffix"));
    }
    for (draft, row) in plan.drafts.iter().cloned().zip(snapshot.receipts()) {
        compare(draft, row)?;
    }
    let store = ArtifactStore::from_run_root_fd(root, false)?;
    store.require_inventory_subset(&plan.descriptors)?;
    for (bytes, descriptor) in plan.payloads.iter().zip(&plan.descriptors) {
        if store.put(bytes, "application/json", None)? != *descriptor {
            return Err(invalid("descriptor changed"));
        }
    }
    let mut chain = open_existing_from_dir_fd(paths, root)?;
    for (ordinal, draft) in plan
        .drafts
        .into_iter()
        .enumerate()
        .skip(snapshot.receipts().len())
    {
        let receipt = make_receipt(draft, chain.head().clone())?;
        chain.append_with_interruption(
            receipt,
            fault.filter(|(i, _)| *i == ordinal).map(|(_, stage)| stage),
        )?;
    }
    chain.sync_all()?;
    verify_closed_prepared_normal_chat_child_from_dir_fd(root, family, context, reservation)
}
pub(super) fn validate_prepared_recoveries(
    receipts: &[ReceiptV1],
    store: &ArtifactStore,
) -> Result<(), LedgerError> {
    for row in receipts
        .iter()
        .filter(|r| r.kind == ReceiptKindV1::NormalChatPreparedAttemptRecoveredV1)
    {
        let descriptor = row
            .artifact_refs
            .first()
            .ok_or_else(|| invalid("recovery artifact absent"))?;
        let bytes = store.get(descriptor)?;
        if bytes.len() > 65536 || descriptor != &describe(&bytes)? {
            return Err(invalid("recovery metadata descriptor differs"));
        }
        let value = recursive_agent_contracts::parse_strict_json_value(&bytes)
            .map_err(|_| invalid("invalid recovery JSON"))?;
        let evidence: NormalChatPreparedRecoveryEvidenceV1 = serde_json::from_value(value)?;
        if jcs_canonical(&evidence)? != bytes {
            return Err(invalid("lossy recovery metadata"));
        }
        let plan = plan(&evidence)?;
        if receipts.len() < 4 || receipts.len() > 5 {
            return Err(invalid("unexpected prepared transcript length"));
        }
        for (draft, row) in plan.drafts.into_iter().zip(receipts) {
            compare(draft, row)?;
        }
    }
    Ok(())
}
