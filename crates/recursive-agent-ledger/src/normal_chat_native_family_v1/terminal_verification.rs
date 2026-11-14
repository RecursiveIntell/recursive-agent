//! Private terminal candidate and native-joined strict proof. No publication.
use super::degradation_preparation::{
    prepare_verified_family, NormalChatSessionDegradationPreparationErrorV1 as E,
    PreparedNormalChatSessionDegradationV1,
};
use super::*;
use crate::NormalChatSessionGateV1;
use recursive_agent_contracts::{
    parse_normal_chat_session_degradation_v1_bytes, NormalChatSessionDegradationV1,
};
/// Internal local shape, NEVER exposed as full verified terminal evidence.
pub(super) struct TerminalCandidateV1 {
    rows: Vec<ReceiptV1>,
    metadata: Vec<u8>,
    log_bytes: Vec<u8>,
    prefix: VerifiedReceiptSnapshot,
    head: ContentDigest,
}
impl TerminalCandidateV1 {
    pub(super) fn read(root: &File, id: &CurrentRunId) -> Result<Self, LedgerError> {
        with_exclusive_lock(root, |root| Self::read_locked(root, id))
    }
    fn read_locked(root: &File, id: &CurrentRunId) -> Result<Self, LedgerError> {
        let log_bytes = read_bounded_regular_at(root, "receipts.ndjson", MAX_RECEIPT_LOG_BYTES)?;
        let scan = scan_complete_bytes(&log_bytes)?;
        let metadata = read_chain_metadata_read_only(root, &scan)?;
        let lifecycle =
            validate_receipt_sequence(&scan.receipts, LifecycleValidationMode::StrictCurrent)?;
        if lifecycle.run_id.as_ref() != Some(id) || scan.receipts.len() < 9 {
            return Err(invalid("terminal parent run/cardinality differs"));
        }
        let end = scan.receipts.len() - 3;
        if (end - 3) % 3 != 0
            || scan.receipts[end].kind != ReceiptKindV1::PermitRevoked
            || scan.receipts[end + 1].kind != ReceiptKindV1::NormalChatSessionDegradedV1
            || scan.receipts[end + 2].kind != ReceiptKindV1::RunFinalized
        {
            return Err(invalid(
                "terminal candidate requires exact three-row suffix",
            ));
        }
        let prefix_rows = &scan.receipts[..end];
        let (prefix_lifecycle, verified_artifacts) = validate_authoritative_sequence(
            root,
            prefix_rows,
            LifecycleValidationMode::AppendInProgress,
        )?;
        let prefix = VerifiedReceiptSnapshot {
            verification: ChainVerification {
                ok: true,
                current_strict_success: false,
                length: end as u64,
                final_head: scan.receipts[end].prev_chain_digest.to_string(),
                verified_artifacts,
                terminal_state: prefix_lifecycle
                    .terminal_state
                    .unwrap_or(RunTerminalStateV1::LegacyUnknown),
                verified_run_id: prefix_lifecycle.run_id,
                first_divergence: None,
            },
            receipts: Arc::from(prefix_rows.to_vec()),
        };
        Ok(Self {
            rows: scan.receipts,
            metadata,
            log_bytes,
            prefix,
            head: scan.head,
        })
    }
    fn end(&self) -> usize {
        self.rows.len() - 3
    }
    pub(super) fn prefix_snapshot(
        &self,
        root: &File,
        id: &CurrentRunId,
    ) -> Result<VerifiedReceiptSnapshot, LedgerError> {
        self.require_unchanged(root, id)?;
        Ok(self.prefix.clone())
    }
    fn require_unchanged(&self, root: &File, id: &CurrentRunId) -> Result<(), LedgerError> {
        with_exclusive_lock(root, |root| self.require_unchanged_locked(root, id))
    }
    fn require_unchanged_locked(&self, root: &File, id: &CurrentRunId) -> Result<(), LedgerError> {
        let now = Self::read_locked(root, id)?;
        if now.log_bytes != self.log_bytes
            || now.rows != self.rows
            || now.metadata != self.metadata
            || now.head != self.head
            || now.prefix.receipts() != self.prefix.receipts()
        {
            return Err(invalid("terminal parent bytes changed"));
        }
        Ok(())
    }
    pub(super) fn inventory(&self, base: &[ArtifactDescriptorV1]) -> Vec<ArtifactDescriptorV1> {
        let mut all = base.to_vec();
        all.extend(self.rows[self.end()].artifact_refs.clone());
        all.extend(self.rows[self.end() + 1].artifact_refs.clone());
        all
    }
}
/// Strict native/ledger terminal consistency under an explicitly held gate.
/// This proves neither provider success nor send authority or publication origin.
///
/// ```compile_fail
/// use recursive_agent_ledger::VerifiedNormalChatDegradedSessionV1;
/// fn forge<'a>()->VerifiedNormalChatDegradedSessionV1<'a>{VerifiedNormalChatDegradedSessionV1{}}
/// ```
/// ```compile_fail
/// use recursive_agent_ledger::VerifiedNormalChatDegradedSessionV1;
/// fn duplicate(p:VerifiedNormalChatDegradedSessionV1<'_>){let _=p.clone();}
/// ```
/// ```compile_fail
/// use std::fs::File;
/// use recursive_agent_contracts::CurrentRunId;
/// use recursive_agent_ledger::{NormalChatSessionGateV1,verify_degraded_normal_chat_session_from_runtime_root_fd};
/// fn release_early(out:&File,id:&CurrentRunId,gate:NormalChatSessionGateV1)->Result<(),Box<dyn std::error::Error>> {
/// let proof=verify_degraded_normal_chat_session_from_runtime_root_fd(out,id,&gate)?;
/// gate.unlock()?;let _=proof.chain_head();Ok(())
/// }
/// ```
pub struct VerifiedNormalChatDegradedSessionV1<'gate> {
    plan: PreparedNormalChatSessionDegradationV1<'gate>,
    verification: ChainVerification,
}
impl VerifiedNormalChatDegradedSessionV1<'_> {
    pub fn verification(&self) -> &ChainVerification {
        &self.verification
    }
    pub fn terminal_state(&self) -> RunTerminalStateV1 {
        self.verification.terminal_state
    }
    pub fn chain_head(&self) -> &str {
        &self.verification.final_head
    }
    pub fn marker(&self) -> &NormalChatSessionDegradationV1 {
        self.plan.marker()
    }
    pub fn children(&self) -> &[super::VerifiedNormalChatFamilyChildV1] {
        self.plan.family.children()
    }
    pub fn child_count(&self) -> usize {
        self.plan.family.child_count()
    }
    pub fn unknown_child_count(&self) -> usize {
        self.plan.family.unknown_child_count()
    }
    pub fn recheck(&self) -> Result<(), E> {
        self.plan.recheck()
    }
}
fn candidate<'a>(
    plan: &'a PreparedNormalChatSessionDegradationV1<'_>,
) -> Result<&'a TerminalCandidateV1, E> {
    match &plan.family.parent_read {
        ParentReadV1::Terminal(c) => Ok(c),
        ParentReadV1::Pristine | ParentReadV1::Recovery(_) => {
            Err(E::Invalid("missing internal terminal candidate"))
        }
    }
}
pub(super) fn compare(draft: ReceiptDraftV1, row: &ReceiptV1) -> Result<(), E> {
    if row.run_id != draft.run_id
        || row.step_id != draft.step_id
        || row.kind != draft.kind
        || row.valid_time != draft.valid_time
        || row.lineage != draft.lineage
        || row.spec_digest != draft.spec_digest
        || row.args_digest != draft.args_digest
        || row.artifact_refs != draft.artifact_refs
        || row.outcome != draft.outcome
    {
        return Err(E::Invalid("terminal suffix differs from native projection"));
    }
    Ok(())
}
fn exact_suffix(plan: &PreparedNormalChatSessionDegradationV1<'_>) -> Result<(), E> {
    let c = candidate(plan)?;
    let rows = &c.rows[c.end()..];
    let store = &plan.family.parent_store;
    compare(plan.root_revocation_draft(), &rows[0])?;
    if rows[0].receipt_id != plan.marker().root_revocation_receipt_id
        || store.get(plan.root_revocation_descriptor())? != plan.root_revocation_bytes()
    {
        return Err(E::Invalid("root close identity/payload differs"));
    }
    let mut marker = plan.root_revocation_draft();
    marker.kind = ReceiptKindV1::NormalChatSessionDegradedV1;
    marker.valid_time = plan.marker().finalized_at;
    marker.outcome = plan.outcome().clone();
    marker.artifact_refs = vec![plan.marker_descriptor().clone()];
    compare(marker, &rows[1])?;
    let bytes = store.get(plan.marker_descriptor())?;
    if bytes != plan.marker_bytes()
        || parse_normal_chat_session_degradation_v1_bytes(&bytes)
            .map_err(|_| E::Invalid("invalid terminal marker metadata"))?
            != *plan.marker()
    {
        return Err(E::Invalid("marker differs from complete native source"));
    }
    let mut final_row = plan.root_revocation_draft();
    final_row.kind = ReceiptKindV1::RunFinalized;
    final_row.valid_time = plan.marker().finalized_at;
    final_row.outcome = plan.outcome().clone();
    final_row.artifact_refs.clear();
    compare(final_row, &rows[2])?;
    Ok(())
}
pub fn verify_degraded_normal_chat_session_from_runtime_root_fd<'g>(
    output: &File,
    id: &CurrentRunId,
    gate: &'g NormalChatSessionGateV1,
) -> Result<VerifiedNormalChatDegradedSessionV1<'g>, E> {
    verify_degraded_normal_chat_session_from_runtime_root_fd_with_observer(output, id, gate, || {})
}
#[doc(hidden)]
pub fn verify_degraded_normal_chat_session_from_runtime_root_fd_with_observer<'g>(
    output: &File,
    id: &CurrentRunId,
    gate: &'g NormalChatSessionGateV1,
    before_return: impl FnOnce(),
) -> Result<VerifiedNormalChatDegradedSessionV1<'g>, E> {
    let output = output.try_clone()?;
    let identity = run_root_identity(&output)?;
    let parent = RunPin::open(&output, id)?;
    gate.check(&parent.root)?;
    let terminal_input = TerminalCandidateV1::read(&parent.root, id)?;
    let family = verify_family_from_pins(
        output,
        identity,
        parent,
        id,
        ParentReadV1::Terminal(Box::new(terminal_input)),
        |root| {
            gate.check(root)
                .map_err(|e| invalid(&format!("terminal gate changed: {e}")))
        },
        || {},
    )?;
    let plan = prepare_verified_family(family, gate)?;
    exact_suffix(&plan)?;
    // This private local entry is reached only AFTER full native/source/suffix
    // equality; generic APIs keep their unconditional scope-required wrapper.
    let verification = with_exclusive_lock(&plan.family.parent.root, |root| {
        let c = candidate(&plan).map_err(|_| invalid("terminal candidate missing"))?;
        c.require_unchanged_locked(root, id)?;
        let (lifecycle, verified_artifacts) = validate_local_authoritative_sequence(
            root,
            &c.rows,
            LifecycleValidationMode::StrictCurrent,
        )?;
        Ok(ChainVerification {
            ok: true,
            current_strict_success: true,
            length: c.rows.len() as u64,
            final_head: c.head.to_string(),
            verified_artifacts,
            terminal_state: lifecycle
                .terminal_state
                .ok_or_else(|| invalid("terminal state missing"))?,
            verified_run_id: lifecycle.run_id,
            first_divergence: None,
        })
    })?;
    before_return();
    plan.recheck()?;
    Ok(VerifiedNormalChatDegradedSessionV1 { plan, verification })
}
