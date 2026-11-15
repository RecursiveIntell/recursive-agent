//! Serial normal-chat family reconciliation: a projection of canonical owners,
//! not another authority or an automatic recovery dispatcher. Ledger-owned
//! appendable readers may recover torn tails/metadata; this is not forensic
//! byte-immutability or protection from arbitrary same-UID writers.
use super::normal_chat_attempt::{all_artifacts, expected_link, request_descriptor};
use super::normal_chat_terminal::{closure_link, describe};
use super::RuntimeServiceError;
use crate::PinnedRunRoot;
use chrono::{DateTime, Utc};
use recursive_agent_contracts::{
    jcs_canonical, ArtifactDescriptorV1, ContentDigest, CurrentReceiptId, NormalChatCallRequestV2,
    ReceiptKindV1, ReceiptOutcomeV1, ReceiptV1,
};
use recursive_agent_ledger::{
    appendable_snapshot_expected_run_from_dir_fd, make_receipt,
    verified_snapshot_expected_run_from_dir_fd, verify_child_links_in_runtime_root, ArtifactStore,
    ChainHandle, ChildRunLinkV1, ReceiptDraftV1,
};
use recursive_agent_policy::{
    build_lineage, DurablePermitStore, FamilyAuthorityStore, NormalChatAttemptReadbackV2,
    NormalChatFamilyReservationV2, NormalChatGrantContextV2, NormalChatSessionSnapshotV2,
    PermitEvidenceStateV1,
};
use std::collections::BTreeMap;
use std::fs::File;

fn recovery(reason: &'static str) -> RuntimeServiceError {
    RuntimeServiceError::NormalChatSessionRecoveryRequired { reason }
}
#[derive(Clone, Copy)]
pub(super) struct FamilyHistoryInputs<'a> {
    pub family: &'a FamilyAuthorityStore,
    pub context: &'a NormalChatGrantContextV2,
}
pub(super) struct FamilyGroupV2 {
    pub reservation: NormalChatFamilyReservationV2,
    pub request: NormalChatCallRequestV2,
    pub prepared_index: usize,
    pub linked_index: usize,
    pub closed_index: Option<usize>,
    pub child_policy: NormalChatAttemptReadbackV2,
}
struct ChildFenceV2 {
    pinned: PinnedRunRoot,
    artifacts: ArtifactStore,
    policy: DurablePermitStore,
    view: NormalChatAttemptReadbackV2,
    head: String,
    length: usize,
    inventory: Vec<ArtifactDescriptorV1>,
    intent: String,
}
impl ChildFenceV2 {
    fn recheck(&self, family: &FamilyAuthorityStore) -> Result<(), RuntimeServiceError> {
        self.pinned.ensure_locator_matches()?;
        self.artifacts.require_locator_matches(&self.pinned.root)?;
        if self
            .policy
            .read_normal_chat_attempt_v2(family, &self.intent)?
            != self.view
        {
            return Err(recovery("closed sibling policy changed"));
        }
        let snapshot = verified_snapshot_expected_run_from_dir_fd(
            &self.pinned.root,
            &self.view.attempt.run_id()?,
        )?;
        if snapshot.verification().final_head != self.head
            || snapshot.receipts().len() != self.length
        {
            return Err(recovery("closed sibling head changed"));
        }
        self.artifacts.require_exact_inventory(&self.inventory)?;
        self.artifacts.require_locator_matches(&self.pinned.root)?;
        self.pinned.ensure_locator_matches()?;
        Ok(())
    }
}
pub(super) struct ReconciledFamilyV2 {
    pub snapshot: NormalChatSessionSnapshotV2,
    pub rows: Vec<ReceiptV1>,
    pub groups: Vec<FamilyGroupV2>,
    pub parent_head: ContentDigest,
    pub group_end: usize,
    pub floor: DateTime<Utc>,
    pub degraded: bool,
    fences: Vec<ChildFenceV2>,
}
impl ReconciledFamilyV2 {
    pub fn group(&self, intent: &str) -> Option<&FamilyGroupV2> {
        self.groups
            .iter()
            .find(|g| g.request.dispatch_intent_ref == intent)
    }
    pub fn require_terminalizable(&self) -> Result<(), RuntimeServiceError> {
        if self.groups.iter().any(|g| g.closed_index.is_none()) {
            return Err(recovery("family has an unclosed child"));
        }
        if self.degraded {
            return Err(recovery("degraded family requires explicit recovery"));
        }
        Ok(())
    }
    pub fn require_ready(&self) -> Result<(), RuntimeServiceError> {
        self.require_terminalizable()?;
        if self.snapshot.admission.closed_at.is_some()
            || self.snapshot.admission.parent_revoked_at.is_some()
        {
            return Err(recovery("family admission closed"));
        }
        Ok(())
    }
    pub fn recheck_closed(&self, family: &FamilyAuthorityStore) -> Result<(), RuntimeServiceError> {
        for fence in &self.fences {
            fence.recheck(family)?;
        }
        Ok(())
    }
}
impl super::RuntimeService {
    /// Reopen only existing, fully closed, nondegraded ACTIVE session history.
    /// This is not bootstrap fallback, authority creation, or lease renewal.
    pub fn resume_normal_chat_session(
        &self,
        conversation_ref: &str,
    ) -> Result<super::RuntimeNormalChatSessionV1, RuntimeServiceError> {
        use super::normal_chat_attempt::{require_parent_history, MonotonicClock};
        use super::normal_chat_session::SessionGate;
        let authority = self
            .normal_chat_grant
            .as_ref()
            .ok_or(RuntimeServiceError::NormalChatGovernanceDisabled)?;
        let identity = authority.normal_chat_session(conversation_ref, None)?;
        let run_id = identity.run_id()?;
        let pinned = PinnedRunRoot::open_existing(
            self.dependencies.output_root(),
            &recursive_agent_contracts::content_digest(&run_id)?.to_string(),
        )?;
        let store = ArtifactStore::from_run_root_fd(&pinned.root, false)?;
        let chain = recursive_agent_ledger::open_existing_from_dir_fd(
            &recursive_agent_ledger::RunPaths::new(&pinned.locator),
            &pinned.root,
        )?;
        let gate = SessionGate::acquire_existing(&pinned.root)?;
        let clock = MonotonicClock::new(self.dependencies.clock());
        let mut handle = super::RuntimeNormalChatSessionV1 {
            verified_head: chain.head().clone(),
            pinned,
            session: identity,
            run_id,
        };
        let result = (|| -> Result<ContentDigest, RuntimeServiceError> {
            let root = &handle.pinned.root;
            let (permits, family, record) =
                require_parent_history(authority, &handle, &chain, &store)?;
            let context = NormalChatGrantContextV2 {
                grant: authority.grant().clone(),
                session: handle.session.clone(),
                root_control: record.permit.clone(),
            };
            let inputs = FamilyHistoryInputs {
                family: &family,
                context: &context,
            };
            let history = reconcile_family(&chain, root, &store, inputs, None)?;
            history.require_ready()?;
            if clock.sample() < history.floor {
                return Err(recovery("resume clock precedes semantic history"));
            }
            clock.check()?;
            let control = permits.require_existing_normal_chat_session_control(
                authority,
                conversation_ref,
                None,
                &record,
                || clock.sample(),
            )?;
            let guarded = FamilyAuthorityStore::require_existing_normal_chat_session_family(
                root,
                authority,
                &control,
                || clock.sample(),
            )?;
            if guarded.read_normal_chat_session_snapshot_v2()? != history.snapshot {
                return Err(recovery("family changed during resume"));
            }
            history.recheck_closed(&family)?;
            let final_history = reconcile_family(&chain, root, &store, inputs, None)?;
            if final_history.snapshot != history.snapshot
                || final_history.parent_head != history.parent_head
            {
                return Err(recovery("resumed family history changed"));
            }
            permits.require_existing_normal_chat_session_control(
                authority,
                conversation_ref,
                None,
                &record,
                || clock.sample(),
            )?;
            clock.check()?;
            history.recheck_closed(&family)?;
            final_history.recheck_closed(&family)?;
            store.require_locator_matches(root)?;
            gate.check(root)?;
            handle.pinned.ensure_locator_matches()?;
            Ok(history.parent_head)
        })();
        let unlock = gate.unlock();
        handle.verified_head = match (result, unlock) {
            (Ok(head), Ok(())) => head,
            (Err(error), _) | (Ok(_), Err(error)) => return Err(error),
        };
        handle.pinned.ensure_locator_matches()?;
        Ok(handle)
    }
}

fn semantic_floor(view: &NormalChatAttemptReadbackV2, mut floor: DateTime<Utc>) -> DateTime<Utc> {
    if let Some(value) = &view.preflight {
        floor = std::cmp::max(floor, value.recorded_at);
    }
    if let Some(value) = &view.settlement {
        floor = std::cmp::max(floor, value.outcome.recorded_at);
    }
    if let Some(value) = &view.local_control {
        floor = std::cmp::max(floor, value.binding.issued_at);
        if let PermitEvidenceStateV1::Revoked { at, .. } = &value.state {
            floor = std::cmp::max(floor, *at);
        }
    }
    floor
}
fn parent_row(
    actual: &ReceiptV1,
    context: &NormalChatGrantContextV2,
    phase: &str,
    kind: ReceiptKindV1,
    spec: ContentDigest,
    args: ContentDigest,
    artifacts: Vec<ArtifactDescriptorV1>,
) -> Result<(), RuntimeServiceError> {
    let binding = &context.root_control.binding;
    let mut expected = make_receipt(
        ReceiptDraftV1 {
            run_id: binding.run_id.clone(),
            step_id: super::child_receipt_step_id(&binding.run_id, &args, phase)?,
            kind,
            valid_time: actual.valid_time,
            lineage: build_lineage(&context.root_control.permit_id, &binding.policy_version),
            spec_digest: spec,
            args_digest: args,
            artifact_refs: artifacts,
            outcome: ReceiptOutcomeV1::Ok,
        },
        actual.prev_chain_digest.clone(),
    )?;
    expected.recorded_time = actual.recorded_time;
    if expected.canonical_bytes()? != actual.canonical_bytes()? {
        return Err(recovery(
            "parent group receipt differs from exact native binding",
        ));
    }
    Ok(())
}
fn open_child(
    output: &std::path::Path,
    reservation: &NormalChatFamilyReservationV2,
    inputs: FamilyHistoryInputs<'_>,
) -> Result<
    (
        PinnedRunRoot,
        ArtifactStore,
        DurablePermitStore,
        NormalChatAttemptReadbackV2,
    ),
    RuntimeServiceError,
> {
    let id = reservation.attempt.run_id()?;
    let pinned = PinnedRunRoot::open_existing(
        output,
        &recursive_agent_contracts::content_digest(&id)?.to_string(),
    )?;
    let artifacts = ArtifactStore::from_run_root_fd(&pinned.root, false)?;
    let policy = DurablePermitStore::require_existing_from_run_root_fd(&pinned.root)?;
    let view = policy
        .read_normal_chat_attempt_v2(inputs.family, &reservation.attempt.dispatch_intent_ref)?;
    if view.attempt != reservation.attempt {
        return Err(recovery("child policy attempt differs"));
    }
    if let Some(proof) = policy.read_normal_chat_ledger_admission_v2(
        inputs.family,
        &reservation.attempt.dispatch_intent_ref,
    )? {
        if proof.admission.context != *inputs.context || proof.admission.reservation != *reservation
        {
            return Err(recovery(
                "child context differs from current family history",
            ));
        }
    }
    pinned.ensure_locator_matches()?;
    artifacts.require_locator_matches(&pinned.root)?;
    Ok((pinned, artifacts, policy, view))
}
fn verify_terminal(
    pinned: &PinnedRunRoot,
    artifacts: &ArtifactStore,
    policy: &DurablePermitStore,
    view: &NormalChatAttemptReadbackV2,
    inputs: FamilyHistoryInputs<'_>,
    reservation: &NormalChatFamilyReservationV2,
) -> Result<(String, ChildRunLinkV1, Vec<ArtifactDescriptorV1>, bool), RuntimeServiceError> {
    if inputs
        .family
        .read_normal_chat_unconsumed_recovery_v1()?
        .is_some_and(|r| r.reservation == *reservation)
    {
        let proof = recursive_agent_ledger::verify_closed_unconsumed_normal_chat_child_from_dir_fd(
            &pinned.root,
            inputs.family,
            inputs.context,
            reservation,
        )?;
        artifacts.require_exact_inventory(proof.artifact_inventory())?;
        pinned.ensure_locator_matches()?;
        return Ok((
            proof.chain_head().to_owned(),
            closure_link(reservation, proof.terminal_receipt(), proof.chain_head())?,
            proof.artifact_inventory().to_vec(),
            true,
        ));
    }
    if view.state == recursive_agent_policy::NormalChatAttemptPolicyStateV2::RecoveredPrepared {
        let proof = recursive_agent_ledger::verify_closed_prepared_normal_chat_child_from_dir_fd(
            &pinned.root,
            inputs.family,
            inputs.context,
            reservation,
        )?;
        artifacts.require_exact_inventory(proof.artifact_inventory())?;
        artifacts.require_locator_matches(&pinned.root)?;
        pinned.ensure_locator_matches()?;
        return Ok((
            proof.chain_head().to_owned(),
            closure_link(reservation, proof.terminal_receipt(), proof.chain_head())?,
            proof.artifact_inventory().to_vec(),
            true,
        ));
    }
    let proof = recursive_agent_ledger::verify_closed_normal_chat_child_from_dir_fd(
        &pinned.root,
        inputs.family,
        inputs.context,
        reservation,
    )?;
    if proof.native_readback() != view
        || policy
            .read_normal_chat_attempt_v2(inputs.family, &reservation.attempt.dispatch_intent_ref)?
            != *view
    {
        return Err(recovery(
            "closed child native source changed during owner verification",
        ));
    }
    artifacts.require_exact_inventory(proof.artifact_inventory())?;
    artifacts.require_locator_matches(&pinned.root)?;
    pinned.ensure_locator_matches()?;
    let link = closure_link(reservation, proof.terminal_receipt(), proof.chain_head())?;
    Ok((
        proof.chain_head().to_owned(),
        link,
        proof.artifact_inventory().to_vec(),
        proof.disposition().is_unknown() || proof.disposition() == recursive_agent_ledger::VerifiedNormalChatDispositionV1::AdmissionInterruptedBeforeRelease,
    ))
}
fn check_group_chronology(
    ordinals: &mut BTreeMap<String, u32>,
    materialization: &str,
    ordinal: u32,
    prepared_at: DateTime<Utc>,
    prior_floor: DateTime<Utc>,
) -> Result<(), RuntimeServiceError> {
    if prepared_at < prior_floor {
        return Err(recovery("parent group predates prior semantic history"));
    }
    let next = ordinals
        .get(materialization)
        .copied()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| recovery("materialization ordinal overflow"))?;
    if ordinal != next {
        return Err(recovery(
            "parent order differs from native materialization ordinals",
        ));
    }
    ordinals.insert(materialization.into(), next);
    Ok(())
}

/// Bootstrap identity/control must first pass require_parent_history's pure
/// comparison. All remaining rows and reservations are validated here together.
pub(super) fn reconcile_family(
    chain: &ChainHandle,
    root: &File,
    store: &ArtifactStore,
    inputs: FamilyHistoryInputs<'_>,
    pending: Option<&ArtifactDescriptorV1>,
) -> Result<ReconciledFamilyV2, RuntimeServiceError> {
    reconcile_family_inner(chain, root, store, inputs, pending, None)
}
pub(super) fn reconcile_prechild_family(
    chain: &ChainHandle,
    root: &File,
    store: &ArtifactStore,
    inputs: FamilyHistoryInputs<'_>,
    request: &NormalChatCallRequestV2,
) -> Result<ReconciledFamilyV2, RuntimeServiceError> {
    reconcile_family_inner(chain, root, store, inputs, None, Some(request))
}
fn reconcile_family_inner(
    chain: &ChainHandle,
    root: &File,
    store: &ArtifactStore,
    inputs: FamilyHistoryInputs<'_>,
    pending: Option<&ArtifactDescriptorV1>,
    prechild: Option<&NormalChatCallRequestV2>,
) -> Result<ReconciledFamilyV2, RuntimeServiceError> {
    let context = inputs.context;
    context.session_root_issued_record_v2()?;
    let run = context.session.run_id()?;
    let snapshot = inputs.family.read_normal_chat_session_snapshot_v2()?;
    if snapshot.admission.run_id != run
        || snapshot.admission.control_permit_id != context.root_control.permit_id
    {
        return Err(recovery("family root binding differs"));
    }
    let transcript = appendable_snapshot_expected_run_from_dir_fd(root, &run)?;
    if transcript.receipts().len() < 3
        || transcript.verification().final_head != chain.head().to_string()
    {
        return Err(recovery("parent family head differs"));
    }
    let retained = inputs.family.read_normal_chat_prechild_recovery_v1()?;
    let rows = if prechild.is_some() {
        retained
            .as_ref()
            .map(|r| r.parent_prefix.as_slice())
            .unwrap_or(transcript.receipts())
    } else {
        transcript.receipts()
    };
    let mut remaining = BTreeMap::<CurrentReceiptId, NormalChatFamilyReservationV2>::new();
    for reservation in &snapshot.reservations {
        if remaining
            .insert(
                reservation
                    .child_control
                    .request
                    .parent_admission_receipt_id
                    .clone(),
                reservation.clone(),
            )
            .is_some()
        {
            return Err(recovery("duplicate canonical parent admission binding"));
        }
    }
    let output = chain
        .paths()
        .root
        .parent()
        .ok_or_else(|| recovery("runtime output locator absent"))?;
    let mut cursor = 3;
    let mut ordinals = BTreeMap::new();
    let mut groups = Vec::new();
    let mut fences = Vec::new();
    let mut inventory = all_artifacts(transcript.receipts());
    let mut floor = context.root_control.binding.issued_at;
    let mut degraded = false;
    let mut pending_expected = None;
    while cursor < rows.len() {
        let prep = &rows[cursor];
        if let Some(request) = prechild {
            if prep.kind == ReceiptKindV1::ChildAdmissionPrepared
                && prep.args_digest == request.preparation_digest()?
            {
                if prep.valid_time < floor {
                    return Err(recovery(
                        "pending preparation precedes verified sibling floor",
                    ));
                }
                break;
            }
        }
        if prep.kind != ReceiptKindV1::ChildAdmissionPrepared {
            break; // Only the exact native-derived terminal suffix may follow.
        }
        let reservation = remaining
            .remove(&prep.receipt_id)
            .ok_or_else(|| recovery("preparation has no exact canonical reservation"))?;
        let request = NormalChatCallRequestV2::from_attempt(&reservation.attempt)?;
        let preparation = request.preparation_digest()?;
        check_group_chronology(
            &mut ordinals,
            &request.operation.materialization_ref,
            reservation.attempt.attempt_number,
            prep.valid_time,
            floor,
        )?;
        if prep.valid_time < context.root_control.binding.issued_at
            || prep.valid_time > reservation.reserved_at
        {
            return Err(recovery("preparation time differs from reservation order"));
        }
        let request_artifact = request_descriptor(&request)?;
        if store.get(&request_artifact)? != jcs_canonical(&request)? {
            return Err(recovery("preparation request artifact differs"));
        }
        inventory.push(request_artifact);
        parent_row(
            prep,
            context,
            "admission",
            ReceiptKindV1::ChildAdmissionPrepared,
            preparation.clone(),
            preparation.clone(),
            vec![],
        )?;
        let linked = rows
            .get(cursor + 1)
            .ok_or_else(|| recovery("prepared child lacks immutable link"))?;
        let link = expected_link(&reservation)?;
        let link_bytes = jcs_canonical(&link)?;
        if linked.valid_time < reservation.reserved_at {
            return Err(recovery("child link precedes canonical reservation"));
        }
        let descriptor = describe(&link_bytes)?;
        if store.get(&descriptor)? != link_bytes {
            return Err(recovery("immutable child link artifact differs"));
        }
        parent_row(
            linked,
            context,
            "link",
            ReceiptKindV1::ChildLinked,
            link.child_envelope_digest.clone(),
            preparation.clone(),
            vec![descriptor],
        )?;
        let (pinned, artifacts, policy, view) = open_child(output, &reservation, inputs)?;
        if view
            .preflight
            .as_ref()
            .is_some_and(|proof| proof.recorded_at < linked.valid_time)
        {
            return Err(recovery("consumption precedes immutable parent link"));
        }
        floor = std::cmp::max(
            floor,
            std::cmp::max(
                prep.valid_time,
                std::cmp::max(linked.valid_time, reservation.reserved_at),
            ),
        );
        floor = semantic_floor(&view, floor);
        let mut closed_index = None;
        if let Some(closed) = rows
            .get(cursor + 2)
            .filter(|row| row.kind == ReceiptKindV1::ChildClosed)
        {
            let (head, closure, child_inventory, is_degraded) =
                verify_terminal(&pinned, &artifacts, &policy, &view, inputs, &reservation)?;
            let closure_bytes = jcs_canonical(&closure)?;
            let closure_descriptor = describe(&closure_bytes)?;
            if store.get(&closure_descriptor)? != closure_bytes {
                return Err(recovery(
                    "parent closure artifact differs from strict native child",
                ));
            }
            let strict = verified_snapshot_expected_run_from_dir_fd(
                &pinned.root,
                &reservation.attempt.run_id()?,
            )?;
            let terminal = strict
                .receipts()
                .last()
                .ok_or_else(|| recovery("child terminal absent"))?;
            if closed.valid_time != terminal.valid_time {
                return Err(recovery("parent closure time differs from native terminal"));
            }
            parent_row(
                closed,
                context,
                "closure",
                ReceiptKindV1::ChildClosed,
                link.child_envelope_digest.clone(),
                preparation,
                vec![closure_descriptor],
            )?;
            floor = std::cmp::max(floor, closed.valid_time);
            degraded |= is_degraded;
            closed_index = Some(cursor + 2);
            fences.push(ChildFenceV2 {
                pinned,
                artifacts,
                policy,
                view: view.clone(),
                head,
                length: strict.receipts().len(),
                inventory: child_inventory,
                intent: request.dispatch_intent_ref.clone(),
            });
        } else {
            if cursor + 2 != rows.len() {
                return Err(recovery(
                    "pending child is not latest complete parent group",
                ));
            }
            // A complete native terminal may have published its exact closure
            // artifact before losing the parent append ACK. This allowance is
            // derived from the LATEST group, independently of the retry target.
            // No closure is inferred/appended; Fresh/resume still reject it.
            let unconsumed = inputs
                .family
                .read_normal_chat_unconsumed_recovery_v1()?
                .is_some_and(|r| r.reservation == reservation);
            if (unconsumed || (view.settlement.is_some()
                || view.state
                    == recursive_agent_policy::NormalChatAttemptPolicyStateV2::RecoveredUnknown
                || view.state == recursive_agent_policy::NormalChatAttemptPolicyStateV2::RecoveredBeforeRelease
                || view.state == recursive_agent_policy::NormalChatAttemptPolicyStateV2::RecoveredPrepared)
                && view.local_control.as_ref().is_some_and(|control| {
                    matches!(control.state, PermitEvidenceStateV1::Revoked { .. })
                }))
                && recursive_agent_ledger::recoverable_normal_chat_preflight_snapshot_from_dir_fd(
                    &pinned.root,
                    &reservation.attempt.run_id()?,
                )?
                .receipts()
                .len()
                    == if unconsumed {3} else if view.state == recursive_agent_policy::NormalChatAttemptPolicyStateV2::RecoveredPrepared { 5 } else { 10 }
            {
                let (_, closure, _, _) =
                    verify_terminal(&pinned, &artifacts, &policy, &view, inputs, &reservation)?;
                pending_expected = Some(describe(&jcs_canonical(&closure)?)?);
            }
        }
        let step = if closed_index.is_some() { 3 } else { 2 };
        groups.push(FamilyGroupV2 {
            reservation,
            request,
            prepared_index: cursor,
            linked_index: cursor + 1,
            closed_index,
            child_policy: view,
        });
        cursor += step;
    }
    let pending_count = if let Some(request) = prechild {
        if groups.iter().any(|g| g.closed_index.is_none()) || rows.len() - cursor > 2 {
            return Err(recovery("prechild requires complete prior siblings"));
        }
        let reservation = remaining
            .values()
            .find(|r| r.attempt.dispatch_intent_ref == request.dispatch_intent_ref)
            .cloned();
        if let Some(reservation) = &reservation {
            remaining.remove(
                &reservation
                    .child_control
                    .request
                    .parent_admission_receipt_id,
            );
            if NormalChatCallRequestV2::from_attempt(&reservation.attempt)? != *request {
                return Err(recovery("pending request/reservation conflict"));
            }
            inventory.push(describe(&jcs_canonical(&expected_link(reservation)?)?)?);
        }
        inventory.push(request_descriptor(request)?);
        usize::from(reservation.is_some())
    } else {
        0
    };
    if !remaining.is_empty() || groups.len() + pending_count != snapshot.reservations.len() {
        return Err(recovery("reservation and parent group sets differ"));
    }
    let root_record = DurablePermitStore::require_existing_from_run_root_fd(root)?
        .read_normal_chat_session_control_record()?
        .ok_or_else(|| recovery("parent close root control absent"))?;
    if let (Some(request), Some(record)) = (prechild, retained.as_ref()) {
        if record.request != *request || record.context != *context {
            return Err(recovery("retained prechild source differs"));
        }
        if matches!(
            root_record.state,
            recursive_agent_policy::PermitStateV1::Revoked { .. }
        ) {
            let closed = recursive_agent_policy::PermitEvidenceV1::from_record(&root_record)?;
            let (_, payloads) =
                recursive_agent_ledger::normal_chat_prechild_recovery_plan_v1(record, &closed)?;
            // Exact native-derived recovery artifacts may precede their receipt
            // ACK. No unrelated inventory or caller allowance is admitted.
            for payload in payloads {
                inventory.push(describe(&payload)?);
            }
        }
    }
    let parent_terminal = if prechild.is_some() {
        None
    } else {
        super::normal_chat_parent_close::parent_terminal_projection(
            context,
            &root_record,
            &snapshot,
            floor,
            groups.iter().all(|g| g.closed_index.is_some()) && !degraded,
        )?
    };
    if let Some(terminal) = &parent_terminal {
        terminal.compare_tail(&rows[cursor..])?;
    } else if prechild.is_none() && cursor != rows.len() {
        return Err(recovery("parent suffix lacks exact closed native pair"));
    }
    if let Some(pending) = pending {
        if !inventory.contains(pending) && pending_expected.as_ref() != Some(pending) {
            return Err(recovery(
                "pending artifact is not exact native terminal closure",
            ));
        }
    }
    let optional_parent = parent_terminal.as_ref().map(|t| t.descriptor.clone());
    let optional_any = pending_expected.is_some() || optional_parent.is_some();
    if let Some(optional_closure) = pending_expected.or(optional_parent) {
        inventory.push(optional_closure);
    }
    if optional_any || prechild.is_some() {
        // All mandatory members above have already been read and compared;
        // only the exact child closure OR native closed-root projection is
        // optional before its receipt append; no arbitrary orphan is admitted.
        store.require_inventory_subset(&inventory)?;
    } else {
        store.require_exact_inventory(&inventory)?;
    }
    if prechild.is_none() {
        verify_child_links_in_runtime_root(&transcript, store, output, false)?;
    }
    store.require_locator_matches(root)?;
    let history = ReconciledFamilyV2 {
        snapshot,
        rows: rows.to_vec(),
        groups,
        parent_head: chain.head().clone(),
        group_end: cursor,
        floor,
        degraded,
        fences,
    };
    history.recheck_closed(inputs.family)?;
    Ok(history)
}

#[cfg(test)]
mod chronology_tests {
    use super::*;
    #[test]
    fn parent_order_keeps_equal_times_and_interleaved_materializations(
    ) -> Result<(), RuntimeServiceError> {
        let at = DateTime::<Utc>::UNIX_EPOCH;
        let mut seen = BTreeMap::new();
        check_group_chronology(&mut seen, "z", 1, at, at)?;
        check_group_chronology(&mut seen, "a", 1, at, at)?;
        check_group_chronology(&mut seen, "z", 2, at, at)?;
        let before = seen.clone();
        assert!(check_group_chronology(&mut seen, "z", 2, at, at).is_err());
        assert!(check_group_chronology(&mut seen, "z", 4, at, at).is_err());
        assert!(check_group_chronology(&mut seen, "new", 2, at, at).is_err());
        assert!(check_group_chronology(
            &mut seen,
            "new",
            1,
            at,
            at + chrono::TimeDelta::milliseconds(1)
        )
        .is_err());
        assert_eq!(seen, before);
        Ok(())
    }
}
