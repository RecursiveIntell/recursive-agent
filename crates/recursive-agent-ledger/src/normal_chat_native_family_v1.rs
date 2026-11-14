//! Descriptor-scoped verification of complete native normal-chat families.
//! This is historical metadata proof, not an egress grant, finalization cause,
//! new permit or serialized capability. Appendable readers may repair metadata.
use super::*;
mod degradation_preparation;
mod publication_recovery;
use publication_recovery::RecoveryCandidateV1;
pub use publication_recovery::{
    recover_normal_chat_session_degradation_from_runtime_root_fd,
    recover_normal_chat_session_degradation_from_runtime_root_fd_with_observer,
    recover_normal_chat_session_degradation_from_runtime_root_fd_with_observers,
};
mod terminal_verification;
use terminal_verification::TerminalCandidateV1;
pub use terminal_verification::{
    verify_degraded_normal_chat_session_from_runtime_root_fd,
    verify_degraded_normal_chat_session_from_runtime_root_fd_with_observer,
    VerifiedNormalChatDegradedSessionV1,
};
// Candidate state is private, not a public validation skip or terminal proof.
enum ParentReadV1 {
    Pristine,
    Terminal(Box<TerminalCandidateV1>),
    Recovery(Box<RecoveryCandidateV1>),
}
pub use degradation_preparation::{
    prepare_normal_chat_session_degradation_from_runtime_root_fd,
    prepare_normal_chat_session_degradation_from_runtime_root_fd_with_observer,
    NormalChatSessionDegradationPreparationErrorV1, NormalChatSessionPublicationInterruptionV1,
    PreparedNormalChatSessionDegradationV1,
};
use recursive_agent_contracts::{jcs_canonical, NormalChatCallRequestV2};
use recursive_agent_policy::{
    build_lineage, DurablePermitStore, FamilyAuthorityStore, NormalChatAttemptPolicyStateV2,
    NormalChatAttemptReadbackV2, NormalChatFamilyReservationV2, NormalChatGrantContextV2,
    NormalChatLedgerAdmissionEvidenceV2, NormalChatRecoveryRecordV1, NormalChatReportedStateV2,
    NormalChatSessionSnapshotV2, NormalChatSettlementV2, PermitEvidenceStateV1, PermitEvidenceV1,
    PermitRecordV1,
};
fn invalid(reason: &str) -> LedgerError {
    LedgerError::ChildLinkInvalid(format!("native normal-chat family: {reason}"))
}
// Closed child sources are read-only: a missing/stale metadata sidecar is not
// permission for a family reader to reconstruct child history.
fn strict_native_child_snapshot(
    root: &File,
    id: &CurrentRunId,
) -> Result<VerifiedReceiptSnapshot, LedgerError> {
    with_exclusive_lock(root, |root| {
        let scan = scan_existing_read_only(root)?;
        read_chain_metadata_read_only(root, &scan)?;
        let verification = verify_scan_locked(root, &scan, VerificationMode::StrictCurrent)?;
        if verification.verified_run_id.as_ref() != Some(id) {
            return Err(invalid("strict child run differs"));
        }
        Ok(VerifiedReceiptSnapshot {
            verification,
            receipts: Arc::from(scan.receipts),
        })
    })
}
fn native<T>(r: Result<T, recursive_agent_policy::PolicyError>) -> Result<T, LedgerError> {
    r.map_err(|e| invalid(&e.to_string()))
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
fn descriptors(bytes: &[Vec<u8>]) -> Result<Vec<ArtifactDescriptorV1>, LedgerError> {
    bytes.iter().map(|b| describe(b)).collect()
}
fn row(
    actual: &ReceiptV1,
    evidence: &PermitEvidenceV1,
    kind: ReceiptKindV1,
    time: DateTime<Utc>,
    refs: Vec<ArtifactDescriptorV1>,
    outcome: ReceiptOutcomeV1,
) -> Result<(), LedgerError> {
    if actual.kind != kind
        || actual.run_id != evidence.binding.run_id
        || actual.step_id != evidence.binding.step_id
        || actual.valid_time != time
        || actual.spec_digest != evidence.binding.action_digest
        || actual.args_digest != evidence.binding.args_digest
        || actual.lineage != build_lineage(&evidence.permit_id, &evidence.binding.policy_version)
        || actual.artifact_refs != refs
        || actual.outcome != outcome
    {
        return Err(invalid(
            "receipt differs from canonical native binding/metadata",
        ));
    }
    Ok(())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedNormalChatDispositionV1 {
    Reported(NormalChatReportedStateV2),
    MissingExecutorOutcome,
    AdmissionInterruptedBeforeRelease,
    PreparedAdmissionInterrupted,
    UnconsumedAdmissionInterrupted,
}
impl VerifiedNormalChatDispositionV1 {
    pub fn is_unknown(self) -> bool {
        matches!(
            self,
            Self::Reported(NormalChatReportedStateV2::OutcomeUnknown)
                | Self::MissingExecutorOutcome
        )
    }
}
#[derive(Clone, PartialEq)]
enum Terminal {
    Reported(Box<NormalChatSettlementV2>),
    Recovered(NormalChatRecoveryRecordV1),
    Interrupted(recursive_agent_policy::NormalChatInterruptedRecoveryRecordV2),
}
impl Terminal {
    fn outcome(
        &self,
        p: &NormalChatLedgerAdmissionEvidenceV2,
    ) -> Result<ReceiptOutcomeV1, LedgerError> {
        match self {
            Self::Reported(s) => native(s.ledger_outcome_v2(p)),
            Self::Recovered(r) => native(r.ledger_outcome_v1(p)),
            Self::Interrupted(r) => native(r.ledger_outcome_v2(p)),
        }
    }
    fn time(&self) -> DateTime<Utc> {
        match self {
            Self::Reported(s) => s.outcome.recorded_at,
            Self::Recovered(r) => r.observed_at,
            Self::Interrupted(r) => r.observed_at,
        }
    }
    fn disposition(&self) -> VerifiedNormalChatDispositionV1 {
        match self {
            Self::Reported(s) => VerifiedNormalChatDispositionV1::Reported(s.report.state),
            Self::Recovered(_) => VerifiedNormalChatDispositionV1::MissingExecutorOutcome,
            Self::Interrupted(_) => {
                VerifiedNormalChatDispositionV1::AdmissionInterruptedBeforeRelease
            }
        }
    }
}
/// Verified source/chain metadata only. Native stores and file capabilities are
/// retained privately; no mutation handle or send continuation is exposed.
pub struct VerifiedNormalChatClosedChildV1 {
    root: File,
    identity: RunRootIdentity,
    store: ArtifactStore,
    policy: DurablePermitStore,
    proof: NormalChatLedgerAdmissionEvidenceV2,
    view: NormalChatAttemptReadbackV2,
    source: Terminal,
    snapshot: VerifiedReceiptSnapshot,
    metadata: Vec<u8>,
    inventory: Vec<ArtifactDescriptorV1>,
}
impl VerifiedNormalChatClosedChildV1 {
    pub fn run_id(&self) -> &CurrentRunId {
        &self.proof.preflight.evidence.binding.run_id
    }
    pub fn chain_head(&self) -> &str {
        &self.snapshot.verification().final_head
    }
    pub fn terminal_receipt(&self) -> &ReceiptV1 {
        &self.snapshot.receipts()[9]
    }
    pub fn disposition(&self) -> VerifiedNormalChatDispositionV1 {
        self.source.disposition()
    }
    pub fn source_artifacts(&self) -> &[ArtifactDescriptorV1] {
        &self.snapshot.receipts()[7].artifact_refs
    }
    pub fn admission(&self) -> &NormalChatLedgerAdmissionEvidenceV2 {
        &self.proof
    }
    pub fn artifact_inventory(&self) -> &[ArtifactDescriptorV1] {
        &self.inventory
    }
    pub fn native_readback(&self) -> &NormalChatAttemptReadbackV2 {
        &self.view
    }
    fn recheck(&self, family: &FamilyAuthorityStore) -> Result<(), LedgerError> {
        if run_root_identity(&self.root)? != self.identity {
            return Err(invalid("child root identity changed"));
        }
        let (view, proof, source) = read_native(
            &self.policy,
            family,
            &self.proof.admission.context,
            &self.proof.admission.reservation,
        )?;
        if view != self.view || proof != self.proof || source != self.source {
            return Err(invalid("child native source changed"));
        }
        let current = strict_native_child_snapshot(&self.root, self.run_id())?;
        if read_bounded_regular_at(&self.root, "chain.meta", MAX_CHAIN_META_BYTES)? != self.metadata
        {
            return Err(invalid("child metadata bytes changed"));
        }
        if current.receipts() != self.snapshot.receipts()
            || current.verification().final_head != self.chain_head()
        {
            return Err(invalid("child transcript changed"));
        }
        self.store.require_exact_inventory(&self.inventory)?;
        self.store.require_locator_matches(&self.root)?;
        Ok(())
    }
}
fn read_native(
    policy: &DurablePermitStore,
    family: &FamilyAuthorityStore,
    context: &NormalChatGrantContextV2,
    reservation: &NormalChatFamilyReservationV2,
) -> Result<
    (
        NormalChatAttemptReadbackV2,
        NormalChatLedgerAdmissionEvidenceV2,
        Terminal,
    ),
    LedgerError,
> {
    let intent = &reservation.attempt.dispatch_intent_ref;
    if native(family.read_normal_chat_reservation(intent))?.as_ref() != Some(reservation) {
        return Err(invalid("child reservation differs from canonical family"));
    }
    let view = native(policy.read_normal_chat_attempt_v2(family, intent))?;
    let proof = native(policy.read_normal_chat_ledger_admission_v2(family, intent))?
        .ok_or_else(|| invalid("child consumed proof absent"))?;
    if proof.admission.context != *context || proof.admission.reservation != *reservation {
        return Err(invalid("child context/reservation differs"));
    }
    let control = view
        .local_control
        .as_ref()
        .ok_or_else(|| invalid("child control absent"))?;
    if !matches!(control.state, PermitEvidenceStateV1::Revoked { .. }) {
        return Err(invalid("child native control still open"));
    }
    let source = match view.state {
        NormalChatAttemptPolicyStateV2::Settled => {
            let settled = view
                .settlement
                .as_ref()
                .ok_or_else(|| invalid("SDK settlement absent"))?;
            let exact = native(policy.confirm_normal_chat_settlement_v2(
                family,
                intent,
                &proof.preflight.receipt_digest,
                &settled.report,
            ))?;
            if exact != *settled {
                return Err(invalid("SDK source changed"));
            }
            Terminal::Reported(Box::new(exact))
        }
        NormalChatAttemptPolicyStateV2::RecoveredUnknown => {
            if view.outcome.is_some() || view.settlement.is_some() {
                return Err(invalid("recovery has SDK sidecar"));
            }
            Terminal::Recovered(native(policy.confirm_normal_chat_recovery_v1(
                family,
                intent,
                &proof.preflight.receipt_digest,
            ))?)
        }
        NormalChatAttemptPolicyStateV2::RecoveredBeforeRelease => {
            if view.outcome.is_some() || view.settlement.is_some() {
                return Err(invalid("interrupted recovery has SDK sidecar"));
            }
            Terminal::Interrupted(native(policy.confirm_normal_chat_interrupted_recovery_v2(
                family,
                intent,
                &proof.preflight.receipt_digest,
            ))?)
        }
        _ => return Err(invalid("child has no closed native terminal source")),
    };
    if native(policy.read_normal_chat_attempt_v2(family, intent))? != view {
        return Err(invalid("child native view changed during read"));
    }
    Ok((view, proof, source))
}
/// Verify the canonical runtime normal-chat ten-row child against BOTH strict
/// ledger evidence and current native policy source. No active grant/clock.
pub fn verify_closed_normal_chat_child_from_dir_fd(
    root: &File,
    family: &FamilyAuthorityStore,
    context: &NormalChatGrantContextV2,
    reservation: &NormalChatFamilyReservationV2,
) -> Result<VerifiedNormalChatClosedChildV1, LedgerError> {
    let root = root.try_clone()?;
    let identity = run_root_identity(&root)?;
    let store = ArtifactStore::from_run_root_fd(&root, false)?;
    let policy = native(DurablePermitStore::require_existing_from_run_root_fd(&root))?;
    let (view, proof, source) = read_native(&policy, family, context, reservation)?;
    let snapshot = strict_native_child_snapshot(&root, &reservation.attempt.run_id()?)?;
    let rows = snapshot.receipts();
    if rows.len() != 10 {
        return Err(invalid("child is not canonical ten-row terminal"));
    }
    let control = native(proof.control_evidence())?;
    let issued = native(proof.issued_effect_evidence())?;
    let consumed = &proof.preflight.evidence;
    let mut closed = control.clone();
    let actual = view
        .local_control
        .as_ref()
        .ok_or_else(|| invalid("child control absent"))?;
    closed.state = actual.state.clone();
    if closed != *actual {
        return Err(invalid(
            "closed child control differs from admitted control",
        ));
    }
    let closed_at = match closed.state {
        PermitEvidenceStateV1::Revoked { at, .. } => at,
        _ => return Err(invalid("control is not revoked")),
    };
    if closed_at < proof.preflight.recorded_at {
        return Err(invalid("control closure precedes consumption"));
    }
    let mut payloads = vec![
        jcs_canonical(&control)?,
        jcs_canonical(&proof)?,
        jcs_canonical(&issued)?,
        jcs_canonical(consumed)?,
    ];
    let base = descriptors(&payloads)?;
    for (index, (e, kind, time, refs)) in [
        (
            &control,
            ReceiptKindV1::RunStarted,
            control.binding.issued_at,
            vec![],
        ),
        (
            &control,
            ReceiptKindV1::StepStarted,
            control.binding.issued_at,
            vec![],
        ),
        (
            &control,
            ReceiptKindV1::PermitIssued,
            control.binding.issued_at,
            vec![base[0].clone()],
        ),
        (
            &issued,
            ReceiptKindV1::StepStarted,
            issued.binding.issued_at,
            vec![],
        ),
        (
            consumed,
            ReceiptKindV1::NormalChatAttemptAdmittedV2,
            proof.preflight.recorded_at,
            vec![base[1].clone()],
        ),
        (
            &issued,
            ReceiptKindV1::PermitIssued,
            issued.binding.issued_at,
            vec![base[2].clone()],
        ),
        (
            consumed,
            ReceiptKindV1::PermitConsumed,
            proof.preflight.recorded_at,
            vec![base[3].clone()],
        ),
    ]
    .into_iter()
    .enumerate()
    {
        row(&rows[index], e, kind, time, refs, ReceiptOutcomeV1::Ok)?;
    }
    let mut terminal = match &source {
        Terminal::Recovered(r) => vec![jcs_canonical(r)?],
        Terminal::Interrupted(r) => vec![jcs_canonical(r)?],
        Terminal::Reported(s) => {
            let mut out = vec![jcs_canonical(s.as_ref())?];
            if let Some(d) = native(s.degradation_record_v1(&proof))? {
                out.push(jcs_canonical(&d)?);
            }
            out
        }
    };
    let refs = descriptors(&terminal)?;
    terminal.push(jcs_canonical(&closed)?);
    let closed_descriptor = describe(
        terminal
            .last()
            .ok_or_else(|| invalid("closed control payload absent"))?,
    )?;
    let kind = match source {
        Terminal::Reported(_) => ReceiptKindV1::NormalChatAttemptSettledV2,
        Terminal::Recovered(_) => ReceiptKindV1::NormalChatAttemptRecoveredV1,
        Terminal::Interrupted(_) => ReceiptKindV1::NormalChatAttemptInterruptedV2,
    };
    row(
        &rows[7],
        consumed,
        kind,
        source.time(),
        refs,
        source.outcome(&proof)?,
    )?;
    row(
        &rows[8],
        &closed,
        ReceiptKindV1::PermitRevoked,
        closed_at,
        vec![closed_descriptor],
        ReceiptOutcomeV1::Ok,
    )?;
    row(
        &rows[9],
        consumed,
        ReceiptKindV1::RunFinalized,
        std::cmp::max(closed_at, source.time()),
        vec![],
        source.outcome(&proof)?,
    )?;
    payloads.extend(terminal);
    let inventory = descriptors(&payloads)?;
    let mut unique = BTreeMap::new();
    for d in &inventory {
        unique.insert(d.digest.clone(), d.byte_length);
    }
    let bytes = unique
        .values()
        .try_fold(0u64, |n, v| n.checked_add(*v))
        .ok_or_else(|| invalid("child metadata size overflow"))?;
    if bytes
        > reservation
            .child_control
            .request
            .requested_budget
            .max_artifact_bytes
    {
        return Err(invalid("child metadata exceeds native budget"));
    }
    store.require_exact_inventory(&inventory)?;
    store.require_locator_matches(&root)?;
    let result = VerifiedNormalChatClosedChildV1 {
        metadata: read_bounded_regular_at(&root, "chain.meta", MAX_CHAIN_META_BYTES)?,
        root,
        identity,
        store,
        policy,
        proof,
        view,
        source,
        snapshot,
        inventory,
    };
    result.recheck(family)?;
    Ok(result)
}

/// Closed family child, retaining the concrete native owner rather than
/// coercing a prepared-only control into a consumed admission.
pub struct VerifiedNormalChatFamilyChildV1 {
    inner: FamilyChildSourceV1,
}
enum FamilyChildSourceV1 {
    Consumed(Box<VerifiedNormalChatClosedChildV1>),
    Prepared {
        unconsumed: bool,
        root: File,
        context: Box<NormalChatGrantContextV2>,
        reservation: Box<NormalChatFamilyReservationV2>,
        view: Box<NormalChatAttemptReadbackV2>,
        snapshot: Box<VerifiedReceiptSnapshot>,
        inventory: Vec<ArtifactDescriptorV1>,
        metadata: Vec<u8>,
    },
}
impl VerifiedNormalChatFamilyChildV1 {
    pub fn run_id(&self) -> &CurrentRunId {
        &self.snapshot().receipts()[0].run_id
    }
    pub fn native_readback(&self) -> &NormalChatAttemptReadbackV2 {
        match &self.inner {
            FamilyChildSourceV1::Consumed(c) => c.native_readback(),
            FamilyChildSourceV1::Prepared { view, .. } => view,
        }
    }
    pub fn context(&self) -> &NormalChatGrantContextV2 {
        match &self.inner {
            FamilyChildSourceV1::Consumed(c) => &c.proof.admission.context,
            FamilyChildSourceV1::Prepared { context, .. } => context,
        }
    }
    pub fn chain_head(&self) -> &str {
        &self.snapshot().verification().final_head
    }
    fn snapshot(&self) -> &VerifiedReceiptSnapshot {
        match &self.inner {
            FamilyChildSourceV1::Consumed(c) => &c.snapshot,
            FamilyChildSourceV1::Prepared { snapshot, .. } => snapshot,
        }
    }
    pub fn terminal_receipt(&self) -> &ReceiptV1 {
        let rows = self.snapshot().receipts();
        &rows[rows.len() - 1]
    }
    pub fn disposition(&self) -> VerifiedNormalChatDispositionV1 {
        match &self.inner {
            FamilyChildSourceV1::Consumed(c) => c.disposition(),
            FamilyChildSourceV1::Prepared { unconsumed, .. } => {
                if *unconsumed {
                    VerifiedNormalChatDispositionV1::UnconsumedAdmissionInterrupted
                } else {
                    VerifiedNormalChatDispositionV1::PreparedAdmissionInterrupted
                }
            }
        }
    }
    pub fn source_artifacts(&self) -> &[ArtifactDescriptorV1] {
        match &self.inner {
            FamilyChildSourceV1::Consumed(c) => c.source_artifacts(),
            FamilyChildSourceV1::Prepared {
                snapshot,
                unconsumed,
                ..
            } => &snapshot.receipts()[if *unconsumed { 1 } else { 3 }].artifact_refs,
        }
    }
    pub fn artifact_inventory(&self) -> &[ArtifactDescriptorV1] {
        match &self.inner {
            FamilyChildSourceV1::Consumed(c) => c.artifact_inventory(),
            FamilyChildSourceV1::Prepared { inventory, .. } => inventory,
        }
    }
    fn admission_time(&self) -> DateTime<Utc> {
        match &self.inner {
            FamilyChildSourceV1::Consumed(c) => c.proof.preflight.recorded_at,
            FamilyChildSourceV1::Prepared { snapshot, .. } => snapshot.receipts()[0].valid_time,
        }
    }
    fn recheck(&self, family: &FamilyAuthorityStore) -> Result<(), LedgerError> {
        match &self.inner {
            FamilyChildSourceV1::Consumed(c) => c.recheck(family),
            FamilyChildSourceV1::Prepared {
                root,
                context,
                reservation,
                view,
                snapshot,
                inventory,
                metadata,
                unconsumed,
            } => {
                let (head, actual_inventory) = if *unconsumed {
                    let p=super::normal_chat_unconsumed_recovery_v1::verify_closed_unconsumed_normal_chat_child_from_dir_fd(root,family,context,reservation)?;
                    (p.chain_head().to_owned(), p.artifact_inventory().to_vec())
                } else {
                    let p=super::normal_chat_prepared_recovery_v1::verify_closed_prepared_normal_chat_child_from_dir_fd(root, family, context, reservation)?;
                    (p.chain_head().to_owned(), p.artifact_inventory().to_vec())
                };
                let current = strict_native_child_snapshot(root, &reservation.attempt.run_id()?)?;
                let policy = native(DurablePermitStore::require_existing_from_run_root_fd(root))?;
                if native(
                    policy.read_normal_chat_attempt_v2(
                        family,
                        &reservation.attempt.dispatch_intent_ref,
                    ),
                )? != **view
                    || current.receipts() != snapshot.receipts()
                    || head != self.chain_head()
                    || actual_inventory != *inventory
                    || read_bounded_regular_at(root, "chain.meta", MAX_CHAIN_META_BYTES)?
                        != *metadata
                {
                    return Err(invalid("prepared child source changed"));
                }
                Ok(())
            }
        }
    }
}
fn verify_family_child(
    root: &File,
    family: &FamilyAuthorityStore,
    context: &NormalChatGrantContextV2,
    reservation: &NormalChatFamilyReservationV2,
) -> Result<VerifiedNormalChatFamilyChildV1, LedgerError> {
    let policy = native(DurablePermitStore::require_existing_from_run_root_fd(root))?;
    let view = native(
        policy.read_normal_chat_attempt_v2(family, &reservation.attempt.dispatch_intent_ref),
    )?;
    let unconsumed = native(family.read_normal_chat_unconsumed_recovery_v1())?
        .is_some_and(|r| r.reservation == *reservation);
    if !unconsumed && view.state != NormalChatAttemptPolicyStateV2::RecoveredPrepared {
        return Ok(VerifiedNormalChatFamilyChildV1 {
            inner: FamilyChildSourceV1::Consumed(Box::new(
                verify_closed_normal_chat_child_from_dir_fd(root, family, context, reservation)?,
            )),
        });
    }
    let inventory = if unconsumed {
        super::normal_chat_unconsumed_recovery_v1::verify_closed_unconsumed_normal_chat_child_from_dir_fd(root,family,context,reservation)?.artifact_inventory().to_vec()
    } else {
        super::normal_chat_prepared_recovery_v1::verify_closed_prepared_normal_chat_child_from_dir_fd(root,family,context,reservation)?.artifact_inventory().to_vec()
    };
    let child = VerifiedNormalChatFamilyChildV1 {
        inner: FamilyChildSourceV1::Prepared {
            unconsumed,
            root: root.try_clone()?,
            context: Box::new(context.clone()),
            reservation: Box::new(reservation.clone()),
            view: Box::new(view),
            snapshot: Box::new(strict_native_child_snapshot(
                root,
                &reservation.attempt.run_id()?,
            )?),
            inventory,
            metadata: read_bounded_regular_at(root, "chain.meta", MAX_CHAIN_META_BYTES)?,
        },
    };
    child.recheck(family)?;
    Ok(child)
}

struct RunPin {
    root: File,
    name: String,
    identity: RunRootIdentity,
}
impl RunPin {
    fn open(output: &File, id: &CurrentRunId) -> Result<Self, LedgerError> {
        let name = content_digest(id)?.to_string();
        let root = open_child_directory(output, &name, false)?;
        let identity = run_root_identity(&root)?;
        Ok(Self {
            root,
            name,
            identity,
        })
    }
    fn check(&self, output: &File) -> Result<(), LedgerError> {
        if run_root_identity(&open_child_directory(output, &self.name, false)?)? != self.identity {
            return Err(invalid("run locator was replaced"));
        }
        Ok(())
    }
}
/// Complete pre-finalization family proof. It retains source capabilities
/// privately, exposes metadata only and never returns native mutation handles.
///
/// ```compile_fail
/// use recursive_agent_ledger::VerifiedNormalChatClosedFamilyV1;
/// fn copy(proof:VerifiedNormalChatClosedFamilyV1) { let _ = proof.clone(); }
/// ```
/// ```compile_fail
/// use recursive_agent_ledger::VerifiedNormalChatClosedFamilyV1;
/// fn mutate(proof:VerifiedNormalChatClosedFamilyV1) { proof.family().revoke_parent(); }
/// ```
pub struct VerifiedNormalChatClosedFamilyV1 {
    output: File,
    output_identity: RunRootIdentity,
    parent: RunPin,
    parent_snapshot: VerifiedReceiptSnapshot,
    parent_read: ParentReadV1,
    parent_store: ArtifactStore,
    parent_policy: DurablePermitStore,
    context: NormalChatGrantContextV2,
    root_record: PermitRecordV1,
    family: FamilyAuthorityStore,
    native_snapshot: NormalChatSessionSnapshotV2,
    children: Vec<VerifiedNormalChatFamilyChildV1>,
    pins: Vec<RunPin>,
    inventory: Vec<ArtifactDescriptorV1>,
}
impl VerifiedNormalChatClosedFamilyV1 {
    pub fn parent_run_id(&self) -> &CurrentRunId {
        &self.context.root_control.binding.run_id
    }
    pub fn parent_chain_head(&self) -> &str {
        &self.parent_snapshot.verification().final_head
    }
    pub fn child_count(&self) -> usize {
        self.children.len()
    }
    pub fn unknown_child_count(&self) -> usize {
        self.children
            .iter()
            .filter(|c| c.disposition().is_unknown())
            .count()
    }
    pub fn interrupted_child_count(&self) -> usize {
        self.children
            .iter()
            .filter(|c| {
                matches!(
                    c.disposition(),
                    VerifiedNormalChatDispositionV1::AdmissionInterruptedBeforeRelease
                        | VerifiedNormalChatDispositionV1::PreparedAdmissionInterrupted
                        | VerifiedNormalChatDispositionV1::UnconsumedAdmissionInterrupted
                )
            })
            .count()
    }
    pub fn children(&self) -> &[VerifiedNormalChatFamilyChildV1] {
        &self.children
    }
    pub fn context(&self) -> &NormalChatGrantContextV2 {
        &self.context
    }
    pub fn native_snapshot(&self) -> &NormalChatSessionSnapshotV2 {
        &self.native_snapshot
    }
    pub fn native_root_record(&self) -> &PermitRecordV1 {
        &self.root_record
    }
    pub fn recheck(&self) -> Result<(), LedgerError> {
        if run_root_identity(&self.output)? != self.output_identity {
            return Err(invalid("output capability identity changed"));
        }
        self.parent.check(&self.output)?;
        if native(self.parent_policy.read_normal_chat_session_control_record())?.as_ref()
            != Some(&self.root_record)
            || native(self.family.read_normal_chat_session_snapshot_v2())? != self.native_snapshot
        {
            return Err(invalid("parent native source changed"));
        }
        let now = match &self.parent_read {
            ParentReadV1::Pristine => appendable_snapshot_expected_run_from_dir_fd(
                &self.parent.root,
                self.parent_run_id(),
            )?,
            ParentReadV1::Terminal(candidate) => {
                candidate.prefix_snapshot(&self.parent.root, self.parent_run_id())?
            }
            ParentReadV1::Recovery(candidate) => candidate.prefix_snapshot(&self.parent.root)?,
        };
        if now.receipts() != self.parent_snapshot.receipts()
            || now.verification().final_head != self.parent_chain_head()
        {
            return Err(invalid("parent chain changed"));
        }
        for (pin, child) in self.pins.iter().zip(&self.children) {
            pin.check(&self.output)?;
            child.recheck(&self.family)?;
        }
        let inventory = match &self.parent_read {
            ParentReadV1::Pristine => self.inventory.clone(),
            ParentReadV1::Terminal(candidate) => candidate.inventory(&self.inventory),
            ParentReadV1::Recovery(candidate) => candidate.inventory(),
        };
        self.parent_store.require_exact_inventory(&inventory)?;
        self.parent_store
            .require_locator_matches(&self.parent.root)?;
        self.parent.check(&self.output)?;
        Ok(())
    }
}
fn canonical_link(
    store: &ArtifactStore,
    receipt: &ReceiptV1,
) -> Result<ChildRunLinkV1, LedgerError> {
    let link = child_link_from_receipt(store, receipt)?;
    let bytes = store.get(&receipt.artifact_refs[0])?;
    if jcs_canonical(&link)? != bytes || receipt.artifact_refs[0] != describe(&bytes)? {
        return Err(invalid("parent link is not exact canonical typed JSON"));
    }
    Ok(link)
}
fn expected_link(
    parent: &CurrentRunId,
    res: &NormalChatFamilyReservationV2,
) -> Result<ChildRunLinkV1, LedgerError> {
    let c = &res.child_control;
    Ok(ChildRunLinkV1 {
        parent_run_id: parent.clone(),
        parent_receipt_id: c.request.parent_admission_receipt_id.clone(),
        parent_control_permit_id: c.request.parent_control_permit_id.clone(),
        child_run_id: res.attempt.run_id()?,
        child_control_permit_id: c.child_control_permit_id.clone(),
        root_operation_id: c.request.root_operation_id.clone(),
        reserved_budget: native(res.link_budget_v2())?,
        child_envelope_digest: content_digest(&res.attempt)?,
        child_terminal_receipt_id: None,
        child_terminal_state: None,
        child_chain_head: None,
        cancelled: false,
    })
}
/// Verify a complete normal-chat pre-finalization family from one caller-pinned
/// output-directory capability. No paths, active grant, clock or claimed flags.
/// Already-finalized/suffixed parents, partial groups and empty families reject.
pub fn verify_closed_normal_chat_family_from_runtime_root_fd(
    output: &File,
    parent: &CurrentRunId,
) -> Result<VerifiedNormalChatClosedFamilyV1, LedgerError> {
    verify_closed_normal_chat_family_from_runtime_root_fd_with_observer(output, parent, || {})
}
#[doc(hidden)]
pub fn verify_closed_normal_chat_family_from_runtime_root_fd_with_observer(
    output: &File,
    parent_id: &CurrentRunId,
    observer: impl FnOnce(),
) -> Result<VerifiedNormalChatClosedFamilyV1, LedgerError> {
    let output = output.try_clone()?;
    let output_identity = run_root_identity(&output)?;
    let parent = RunPin::open(&output, parent_id)?;
    verify_family_from_pins(
        output,
        output_identity,
        parent,
        parent_id,
        ParentReadV1::Pristine,
        |_| Ok(()),
        observer,
    )
}
// Same retained parent capability throughout. The private scope callback is a
// coordination fence, never a public semantic-validation bypass.
fn verify_family_from_pins(
    output: File,
    output_identity: RunRootIdentity,
    parent: RunPin,
    parent_id: &CurrentRunId,
    parent_read: ParentReadV1,
    scope: impl Fn(&File) -> Result<(), LedgerError>,
    observer: impl FnOnce(),
) -> Result<VerifiedNormalChatClosedFamilyV1, LedgerError> {
    scope(&parent.root)?;
    parent.check(&output)?;
    let parent_store = ArtifactStore::from_run_root_fd(&parent.root, false)?;
    let parent_snapshot = match &parent_read {
        ParentReadV1::Pristine => {
            appendable_snapshot_expected_run_from_dir_fd(&parent.root, parent_id)?
        }
        ParentReadV1::Terminal(candidate) => candidate.prefix_snapshot(&parent.root, parent_id)?,
        ParentReadV1::Recovery(candidate) => candidate.prefix_snapshot(&parent.root)?,
    };
    let rows = parent_snapshot.receipts();
    if rows.len() < 6 || (rows.len() - 3) % 3 != 0 {
        return Err(invalid("parent is not complete pre-finalization groups"));
    }
    let identity_descriptor = rows[0]
        .artifact_refs
        .first()
        .ok_or_else(|| invalid("session identity absent"))?;
    let identity_bytes = parent_store.get(identity_descriptor)?;
    let value = recursive_agent_contracts::parse_strict_json_value(&identity_bytes)
        .map_err(|_| invalid("invalid session identity"))?;
    let session: recursive_agent_contracts::NormalChatSessionV1 = serde_json::from_value(value)?;
    if jcs_canonical(&session)? != identity_bytes {
        return Err(invalid("lossy session identity"));
    }
    let (_, context) = native(
        FamilyAuthorityStore::require_existing_normal_chat_history_context_v1(
            &parent.root,
            &session,
        ),
    )?;
    if context.session.run_id()? != *parent_id {
        return Err(invalid("parent session context differs"));
    }
    let parent_policy = native(DurablePermitStore::require_existing_from_run_root_fd(
        &parent.root,
    ))?;
    let root_record = native(parent_policy.read_normal_chat_session_control_record())?
        .ok_or_else(|| invalid("native root absent"))?;
    let original = native(context.session_root_issued_record_v2())?;
    let mut current = original.clone();
    current.state = root_record.state.clone();
    if current != root_record
        || !matches!(
            root_record.state,
            recursive_agent_policy::PermitStateV1::Issued
                | recursive_agent_policy::PermitStateV1::Revoked { .. }
        )
    {
        return Err(invalid("native root differs from original context"));
    }
    native(PermitEvidenceV1::from_record(&root_record))?;
    let control = native(PermitEvidenceV1::from_record(&original))?;
    let identity = describe(&jcs_canonical(&context.session)?)?;
    let control_descriptor = describe(&jcs_canonical(&control)?)?;
    if parent_store.get(&identity)? != jcs_canonical(&context.session)?
        || parent_store.get(&control_descriptor)? != jcs_canonical(&control)?
    {
        return Err(invalid("bootstrap artifacts differ"));
    }
    row(
        &rows[0],
        &control,
        ReceiptKindV1::RunStarted,
        control.binding.issued_at,
        vec![identity.clone()],
        ReceiptOutcomeV1::Ok,
    )?;
    row(
        &rows[1],
        &control,
        ReceiptKindV1::StepStarted,
        control.binding.issued_at,
        vec![],
        ReceiptOutcomeV1::Ok,
    )?;
    row(
        &rows[2],
        &control,
        ReceiptKindV1::PermitIssued,
        control.binding.issued_at,
        vec![control_descriptor.clone()],
        ReceiptOutcomeV1::Ok,
    )?;
    let family = native(FamilyAuthorityStore::require_existing_from_dir_fd(
        &parent.root,
        native(context.session_family_grant_v2())?,
    ))?;
    let native_snapshot = native(family.read_normal_chat_session_snapshot_v2())?;
    if native_snapshot.admission.run_id != *parent_id
        || native_snapshot.admission.control_permit_id != control.permit_id
    {
        return Err(invalid("family root differs"));
    }
    let mut remaining = BTreeMap::new();
    for res in &native_snapshot.reservations {
        if remaining
            .insert(
                res.child_control
                    .request
                    .parent_admission_receipt_id
                    .clone(),
                res,
            )
            .is_some()
        {
            return Err(invalid("duplicate native parent preparation"));
        }
    }
    let mut children = Vec::new();
    let mut pins = Vec::new();
    let mut inventory = vec![identity, control_descriptor];
    let mut ordinals = BTreeMap::<String, u32>::new();
    let mut floor = control.binding.issued_at;
    let mut prepared = BTreeMap::new();
    for group in rows[3..].chunks_exact(3) {
        let prep = &group[0];
        let linked = &group[1];
        let closed = &group[2];
        if prep.kind != ReceiptKindV1::ChildAdmissionPrepared
            || linked.kind != ReceiptKindV1::ChildLinked
            || closed.kind != ReceiptKindV1::ChildClosed
        {
            return Err(invalid("parent group is not prep/link/closure"));
        }
        let res = remaining
            .remove(&prep.receipt_id)
            .ok_or_else(|| invalid("parent preparation absent from native family"))?;
        let request = NormalChatCallRequestV2::from_attempt(&res.attempt)?;
        let digest = request.preparation_digest()?;
        let ordinal = ordinals
            .get(&request.operation.materialization_ref)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| invalid("ordinal overflow"))?;
        if ordinal != res.attempt.attempt_number
            || prep.valid_time < floor
            || prep.valid_time > res.reserved_at
        {
            return Err(invalid("native chronology/ordinal differs"));
        }
        ordinals.insert(request.operation.materialization_ref.clone(), ordinal);
        if prep.run_id != *parent_id
            || prep.step_id
                != recursive_agent_contracts::derive_child_receipt_step_id(
                    parent_id,
                    &digest,
                    "admission",
                )?
            || prep.spec_digest != digest
            || prep.args_digest != digest
            || prep.outcome != ReceiptOutcomeV1::Ok
            || !prep.artifact_refs.is_empty()
            || prep.lineage != build_lineage(&control.permit_id, &control.binding.policy_version)
        {
            return Err(invalid("preparation binding differs"));
        }
        let request_bytes = jcs_canonical(&request)?;
        let request_descriptor = describe(&request_bytes)?;
        if parent_store.get(&request_descriptor)? != request_bytes {
            return Err(invalid("canonical preparation bytes differ"));
        }
        inventory.push(request_descriptor);
        prepared.insert(digest.to_string(), prep.receipt_id.clone());
        let link = canonical_link(&parent_store, linked)?;
        let closure = canonical_link(&parent_store, closed)?;
        validate_admission_link(parent_id, linked, &prepared, &link, false)?;
        validate_admission_link(parent_id, closed, &prepared, &closure, true)?;
        if link != expected_link(parent_id, res)?
            || !same_child_link_admission(&link, &closure)
            || linked.valid_time < res.reserved_at
        {
            return Err(invalid("immutable link differs from native allocation"));
        }
        for (r, phase) in [(linked, "link"), (closed, "closure")] {
            if r.step_id
                != recursive_agent_contracts::derive_child_receipt_step_id(
                    parent_id, &digest, phase,
                )?
                || r.outcome != ReceiptOutcomeV1::Ok
                || r.lineage != build_lineage(&control.permit_id, &control.binding.policy_version)
                || r.spec_digest != link.child_envelope_digest
                || r.args_digest != digest
            {
                return Err(invalid("parent link receipt binding differs"));
            }
        }
        let pin = RunPin::open(&output, &link.child_run_id)?;
        let child = verify_family_child(&pin.root, &family, &context, res)?;
        if linked.valid_time > child.admission_time()
            || closed.valid_time != child.terminal_receipt().valid_time
            || closure.child_terminal_receipt_id.as_ref()
                != Some(&child.terminal_receipt().receipt_id)
            || closure.child_terminal_state != Some(child.snapshot().verification().terminal_state)
            || closure.child_chain_head.as_deref() != Some(child.chain_head())
        {
            return Err(invalid("closure differs from verified native child"));
        }
        floor = std::cmp::max(floor, closed.valid_time);
        inventory.extend(linked.artifact_refs.clone());
        inventory.extend(closed.artifact_refs.clone());
        children.push(child);
        pins.push(pin);
    }
    if !remaining.is_empty() || children.len() != native_snapshot.reservations.len() {
        return Err(invalid("parent/native child sets differ"));
    }
    let complete_inventory = match &parent_read {
        ParentReadV1::Pristine => inventory.clone(),
        ParentReadV1::Terminal(candidate) => candidate.inventory(&inventory),
        ParentReadV1::Recovery(candidate) => candidate.inventory(),
    };
    parent_store.require_exact_inventory(&complete_inventory)?;
    parent_store.require_locator_matches(&parent.root)?;
    let result = VerifiedNormalChatClosedFamilyV1 {
        output,
        output_identity,
        parent,
        parent_snapshot,
        parent_read,
        parent_store,
        parent_policy,
        context,
        root_record,
        family,
        native_snapshot,
        children,
        pins,
        inventory,
    };
    observer();
    scope(&result.parent.root)?;
    result.recheck()?;
    scope(&result.parent.root)?;
    Ok(result)
}
