//! Explicit startup-opted-in, narrow-only recovery of complete expired attempts.
//! Historical context is correlation; this creates no grant/permit/continuation.
//! Native narrowing precedes deterministic terminal publication, never rollback.
use super::normal_chat_attempt::{
    require_parent_history_context, MonotonicClock, METADATA_TERMINAL_HEADROOM,
};
use super::normal_chat_family_history::{reconcile_family, FamilyHistoryInputs};
use super::normal_chat_recovery_inspection::discover;
use super::normal_chat_session::SessionGate;
use super::normal_chat_terminal::{
    closure_link, compare_existing, describe, describe_all, ensure_suffix, preflight_payloads,
    require_terminal_capacity, verify_preflight, NormalChatTerminalInterruptionV2,
};
use super::{RuntimeService, RuntimeServiceError};
use crate::PinnedRunRoot;
use chrono::{DateTime, Utc};
use recursive_agent_contracts::{
    content_digest, jcs_canonical, ArtifactDescriptorV1, ContentDigest, CurrentReceiptId,
    CurrentRunId, NormalChatAttemptV2, NormalChatCallRequestV2, ReceiptKindV1, ReceiptOutcomeV1,
    RunTerminalStateV1,
};
use recursive_agent_ledger::{
    appendable_snapshot_expected_run_from_dir_fd, open_existing_from_dir_fd,
    verified_snapshot_expected_run_from_dir_fd, verify_child_links_in_runtime_root, AppendStage,
    ArtifactStore, ReceiptDraftV1, RunPaths,
};
use recursive_agent_policy::{
    build_lineage, NormalChatAttemptPolicyStateV2, NormalChatLedgerAdmissionEvidenceV2,
    NormalChatRecoveryInterruptionV1, NormalChatRecoveryRecordV1, PermitEvidenceStateV1,
    PermitEvidenceV1, PermitRevocationReasonV1, PermitStateV1, PermitTransitionStage,
};
use std::path::{Path, PathBuf};
fn required(reason: &'static str) -> RuntimeServiceError {
    RuntimeServiceError::NormalChatSessionRecoveryRequired { reason }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalChatRuntimeRecoveryInterruptionV1 {
    Native(NormalChatRecoveryInterruptionV1),
    AfterNative,
    ControlClose(PermitTransitionStage),
    AfterControlClose,
    MetadataCapacity,
    Artifact { ordinal: usize },
    ChildReceipt { ordinal: usize, stage: AppendStage },
    ParentArtifact,
    ParentReceipt(AppendStage),
    BeforeReturn,
}
fn stop(
    fault: Option<NormalChatRuntimeRecoveryInterruptionV1>,
    at: NormalChatRuntimeRecoveryInterruptionV1,
) -> Result<(), RuntimeServiceError> {
    if fault == Some(at) {
        return Err(required("runtime recovery publication interrupted"));
    }
    Ok(())
}
fn ledger_fault(
    fault: Option<NormalChatRuntimeRecoveryInterruptionV1>,
) -> Option<NormalChatTerminalInterruptionV2> {
    // Test-only append-stage mapping; no authority/outcome/semantic adapter.
    match fault {
        Some(NormalChatRuntimeRecoveryInterruptionV1::ChildReceipt { ordinal, stage }) => {
            Some(NormalChatTerminalInterruptionV2::ChildReceipt { ordinal, stage })
        }
        Some(NormalChatRuntimeRecoveryInterruptionV1::ParentReceipt(stage)) => {
            Some(NormalChatTerminalInterruptionV2::ParentReceipt(stage))
        }
        _ => None,
    }
}
/// Historical failed/unknown child terminal and exact parent-link closure.
/// The session parent is NOT finalized and no send permission is returned.
///
/// ```compile_fail
/// use recursive_agent_runner::RuntimeNormalChatRecoveredV1;
/// fn copy(v:RuntimeNormalChatRecoveredV1) {let _ = v.clone();}
/// ```
/// ```compile_fail
/// use recursive_agent_runner::RuntimeNormalChatRecoveredV1;
/// fn send(v:RuntimeNormalChatRecoveredV1) {v.submit_child();}
/// ```
pub struct RuntimeNormalChatRecoveredV1 {
    attempt: NormalChatAttemptV2,
    recovery: NormalChatRecoveryRecordV1,
    child_dir: PathBuf,
    terminal_receipt: CurrentReceiptId,
    child_head: ContentDigest,
    parent_head: ContentDigest,
}
impl RuntimeNormalChatRecoveredV1 {
    pub fn attempt(&self) -> &NormalChatAttemptV2 {
        &self.attempt
    }
    pub fn recovery(&self) -> &NormalChatRecoveryRecordV1 {
        &self.recovery
    }
    pub fn child_run_dir(&self) -> &Path {
        &self.child_dir
    }
    pub fn terminal_receipt_id(&self) -> &CurrentReceiptId {
        &self.terminal_receipt
    }
    pub fn terminal_state(&self) -> RunTerminalStateV1 {
        RunTerminalStateV1::Failed
    }
    pub fn child_chain_head(&self) -> &ContentDigest {
        &self.child_head
    }
    pub fn parent_chain_head(&self) -> &ContentDigest {
        &self.parent_head
    }
}
fn closed_time(
    proof: &NormalChatLedgerAdmissionEvidenceV2,
    closed: &PermitEvidenceV1,
) -> Result<DateTime<Utc>, RuntimeServiceError> {
    let at = match &closed.state {
        PermitEvidenceStateV1::Revoked { at, .. } => *at,
        _ => return Err(required("recovery control is not revoked")),
    };
    let mut expected = proof.control_evidence()?;
    expected.state = closed.state.clone();
    if expected != *closed || at < proof.preflight.recorded_at {
        return Err(required("recovery control differs from consumed admission"));
    }
    Ok(at)
}
pub(super) fn recovery_payloads(
    proof: &NormalChatLedgerAdmissionEvidenceV2,
    record: &NormalChatRecoveryRecordV1,
    closed: &PermitEvidenceV1,
) -> Result<Vec<Vec<u8>>, RuntimeServiceError> {
    record.validate_for_admission_v1(proof)?;
    closed_time(proof, closed)?;
    Ok(vec![jcs_canonical(record)?, jcs_canonical(closed)?])
}
pub(super) fn recovery_drafts(
    proof: &NormalChatLedgerAdmissionEvidenceV2,
    record: &NormalChatRecoveryRecordV1,
    closed: &PermitEvidenceV1,
    descriptors: &[ArtifactDescriptorV1],
) -> Result<Vec<ReceiptDraftV1>, RuntimeServiceError> {
    let at = closed_time(proof, closed)?;
    if describe_all(&recovery_payloads(proof, record, closed)?)? != descriptors {
        return Err(required("recovery terminal artifact plan differs"));
    }
    let effect = &proof.preflight.evidence;
    let outcome = record.ledger_outcome_v1(proof)?;
    let mut rows = Vec::new();
    for (evidence, kind, time, refs, result) in [
        (
            effect,
            ReceiptKindV1::NormalChatAttemptRecoveredV1,
            record.observed_at,
            vec![descriptors[0].clone()],
            outcome.clone(),
        ),
        (
            closed,
            ReceiptKindV1::PermitRevoked,
            at,
            vec![descriptors[1].clone()],
            ReceiptOutcomeV1::Ok,
        ),
        (
            effect,
            ReceiptKindV1::RunFinalized,
            std::cmp::max(at, record.observed_at),
            vec![],
            outcome,
        ),
    ] {
        rows.push(ReceiptDraftV1 {
            run_id: evidence.binding.run_id.clone(),
            step_id: evidence.binding.step_id.clone(),
            kind,
            valid_time: time,
            lineage: build_lineage(&evidence.permit_id, &evidence.binding.policy_version),
            spec_digest: evidence.binding.action_digest.clone(),
            args_digest: evidence.binding.args_digest.clone(),
            artifact_refs: refs,
            outcome: result,
        });
    }
    Ok(rows)
}

impl RuntimeService {
    /// Trusted startup opt-in for NARROW-ONLY expired existing-attempt recovery
    /// within the configured output root. Not grant enrollment or an IPC field.
    /// Default constructors and installing an egress grant do not enable it.
    pub fn with_expired_normal_chat_recovery(mut self) -> Self {
        self.normal_chat_expired_recovery_enabled = true;
        self
    }
    pub fn recover_expired_normal_chat_attempt(
        &self,
        session: &CurrentRunId,
        intent: &str,
    ) -> Result<RuntimeNormalChatRecoveredV1, RuntimeServiceError> {
        self.recover_expired_normal_chat_attempt_with_interruption(session, intent, None)
    }
    #[doc(hidden)]
    pub fn recover_expired_normal_chat_attempt_with_interruption(
        &self,
        session: &CurrentRunId,
        intent: &str,
        fault: Option<NormalChatRuntimeRecoveryInterruptionV1>,
    ) -> Result<RuntimeNormalChatRecoveredV1, RuntimeServiceError> {
        self.recover_expired_normal_chat_attempt_with_observer(session, intent, fault, || {})
    }
    #[doc(hidden)]
    pub fn recover_expired_normal_chat_attempt_with_observer(
        &self,
        session: &CurrentRunId,
        intent: &str,
        fault: Option<NormalChatRuntimeRecoveryInterruptionV1>,
        observer: impl FnOnce(),
    ) -> Result<RuntimeNormalChatRecoveredV1, RuntimeServiceError> {
        use NormalChatRuntimeRecoveryInterruptionV1 as Stop;
        if !self.normal_chat_expired_recovery_enabled {
            return Err(RuntimeServiceError::NormalChatRecoveryDisabled);
        }
        NormalChatCallRequestV2::validate_dispatch_intent_ref(intent)?;
        if matches!(
            fault,
            Some(
                Stop::Artifact { ordinal: 2.. }
                    | Stop::ChildReceipt { ordinal: 3.., .. }
                    | Stop::ChildReceipt {
                        stage: AppendStage::ArtifactWrite,
                        ..
                    }
                    | Stop::ParentReceipt(AppendStage::ArtifactWrite)
            )
        ) {
            return Err(required("invalid runtime recovery interruption selection"));
        }
        let parent = PinnedRunRoot::open_existing(
            self.dependencies.output_root(),
            &content_digest(session)?.to_string(),
        )?;
        let root = &parent.root;
        let gate = SessionGate::acquire_existing(root)?;
        let clock = MonotonicClock::new_lazy(self.dependencies.clock());
        let result = (|| -> Result<RuntimeNormalChatRecoveredV1, RuntimeServiceError> {
            let store = ArtifactStore::from_run_root_fd(root, false)?;
            let mut chain = open_existing_from_dir_fd(&RunPaths::new(&parent.locator), root)?;
            let mut child = discover(
                root,
                &store,
                self.dependencies.output_root(),
                session,
                intent,
            )?;
            let proof = child.proof.clone();
            let context = &proof.admission.context;
            let reservation = &proof.admission.reservation;
            let request = NormalChatCallRequestV2::from_attempt(&reservation.attempt)?;
            let (root_policy, family, root_record) =
                require_parent_history_context(context, root, session, &chain, &store)?;
            let inputs = FamilyHistoryInputs {
                family: &family,
                context,
            };
            let history = reconcile_family(&chain, root, &store, inputs, None)?;
            let target = history
                .group(intent)
                .ok_or_else(|| required("recovery target absent from complete family"))?;
            if history
                .groups
                .last()
                .map(|g| g.request.dispatch_intent_ref.as_str())
                != Some(intent)
                || target.request != request
                || target.reservation != *reservation
            {
                return Err(required(
                    "recovery target is not exact latest canonical group",
                ));
            }
            let closed_index = target.closed_index;
            let linked_index = target.linked_index;
            let expected_parent_len = history.rows.len() + usize::from(closed_index.is_none());
            let before = child.policy.read_normal_chat_attempt_v2(&family, intent)?;
            if !matches!(
                before.state,
                NormalChatAttemptPolicyStateV2::Consumed
                    | NormalChatAttemptPolicyStateV2::RecoveredUnknown
            ) || before.outcome.is_some()
                || before.settlement.is_some()
                || child
                    .policy
                    .read_normal_chat_ledger_admission_v2(&family, intent)?
                    .as_ref()
                    != Some(&proof)
            {
                return Err(required(
                    "recovery requires exact consumed proof and no SDK outcome",
                ));
            }
            let old_recovery = child.policy.read_normal_chat_recovery_v1(&family, intent)?;
            let base_payloads = preflight_payloads(&proof)?;
            let base = describe_all(&base_payloads)?;
            verify_preflight(&child.pinned.root, &proof, &base)?;
            // Reuse the pre-admission headroom law; exact unique terminal bytes
            // are checked after native timestamps exist, before publication.
            require_terminal_capacity(
                &base_payloads,
                reservation
                    .child_control
                    .request
                    .requested_budget
                    .max_artifact_bytes
                    .saturating_sub(METADATA_TERMINAL_HEADROOM),
            )?;
            let prefix = appendable_snapshot_expected_run_from_dir_fd(
                &child.pinned.root,
                &reservation.attempt.run_id()?,
            )?;
            let mut allowed = base.clone();
            if let Some(old) = &old_recovery {
                old.validate_for_admission_v1(&proof)?;
                let control = before
                    .local_control
                    .as_ref()
                    .ok_or_else(|| required("recovery child control absent"))?;
                if matches!(control.state, PermitEvidenceStateV1::Revoked { .. }) {
                    let payloads = recovery_payloads(&proof, old, control)?;
                    let ds = describe_all(&payloads)?;
                    let drafts = recovery_drafts(&proof, old, control, &ds)?;
                    for (draft, row) in drafts.into_iter().zip(prefix.receipts().iter().skip(7)) {
                        compare_existing(draft, row)?;
                    }
                    allowed.extend(ds);
                } else if prefix.receipts().len() != 7 {
                    return Err(required("recovery suffix without closed native control"));
                }
            } else if before.state != NormalChatAttemptPolicyStateV2::Consumed
                || prefix.receipts().len() != 7
            {
                return Err(required(
                    "recovery terminal prefix without native recovery record",
                ));
            }
            child.artifacts.require_inventory_subset(&allowed)?;
            store.require_locator_matches(root)?;
            parent.ensure_locator_matches()?;
            gate.check(root)?;
            if old_recovery.is_none() {
                if clock.sample() < history.floor {
                    return Err(required(
                        "recovery observation clock precedes retained history",
                    ));
                }
                clock.check()?;
                require_parent_history_context(context, root, session, &chain, &store)?;
            }
            let recovered = child
                .policy
                .recover_expired_normal_chat_attempt_v1_with_interruption(
                    &family,
                    intent,
                    &proof.preflight.receipt_digest,
                    || clock.sample(),
                    match fault {
                        Some(Stop::Native(point)) => Some(point),
                        _ => None,
                    },
                )?;
            clock.check()?;
            recovered.validate_for_admission_v1(&proof)?;
            stop(fault, Stop::AfterNative)?;
            require_parent_history_context(context, root, session, &chain, &store)?;
            store.require_locator_matches(root)?;
            parent.ensure_locator_matches()?;
            gate.check(root)?;
            let after_native = family.read_normal_chat_session_snapshot_v2()?;
            let mut expected = history.snapshot.clone();
            expected.admission.closed_at = after_native.admission.closed_at;
            if expected != after_native || after_native.admission.closed_at.is_none() {
                return Err(required(
                    "recovery changed more than the permitted family close",
                ));
            }
            let control_id = proof.control_evidence()?.permit_id;
            let mut control = child.policy.state(&control_id)?;
            if matches!(control.state, PermitStateV1::Issued) {
                let at = clock.sample();
                clock.check()?;
                if at < std::cmp::max(history.floor, recovered.observed_at) {
                    return Err(required(
                        "recovery control clock precedes observation/history",
                    ));
                }
                require_parent_history_context(context, root, session, &chain, &store)?;
                control = child.policy.revoke_with_interruption(
                    &control_id,
                    PermitRevocationReasonV1::Operator,
                    at,
                    match fault {
                        Some(Stop::ControlClose(stage)) => Some(stage),
                        _ => None,
                    },
                )?;
            }
            let closed = PermitEvidenceV1::from_record(&control)?;
            closed_time(&proof, &closed)?;
            stop(fault, Stop::AfterControlClose)?;
            let payloads = recovery_payloads(&proof, &recovered, &closed)?;
            let descriptors = describe_all(&payloads)?;
            let mut all_payloads = base_payloads;
            all_payloads.extend(payloads.clone());
            let mut all_descriptors = base;
            all_descriptors.extend(descriptors.clone());
            require_terminal_capacity(
                &all_payloads,
                if fault == Some(Stop::MetadataCapacity) {
                    0
                } else {
                    reservation
                        .child_control
                        .request
                        .requested_budget
                        .max_artifact_bytes
                },
            )?;
            child
                .artifacts
                .require_locator_matches(&child.pinned.root)?;
            child.pinned.ensure_locator_matches()?;
            child.artifacts.require_inventory_subset(&all_descriptors)?;
            for (ordinal, bytes) in payloads.iter().enumerate() {
                if child.artifacts.put(bytes, "application/json", None)? != descriptors[ordinal] {
                    return Err(required("recovery descriptor changed"));
                }
                stop(fault, Stop::Artifact { ordinal })?;
            }
            ensure_suffix(
                &mut child.chain,
                &child.pinned.root,
                7,
                recovery_drafts(&proof, &recovered, &closed, &descriptors)?,
                ledger_fault(fault),
                false,
            )?;
            child.chain.sync_all()?;
            child.artifacts.require_exact_inventory(&all_descriptors)?;
            let strict = verified_snapshot_expected_run_from_dir_fd(
                &child.pinned.root,
                &reservation.attempt.run_id()?,
            )?;
            if strict.receipts().len() != 10
                || strict.verification().final_head != child.chain.head().to_string()
                || strict.verification().terminal_state != RunTerminalStateV1::Failed
            {
                return Err(required("recovered child terminal differs"));
            }
            let terminal = strict
                .receipts()
                .last()
                .ok_or_else(|| required("recovered child terminal absent"))?;
            let closure = closure_link(reservation, terminal, &strict.verification().final_head)?;
            let closure_bytes = jcs_canonical(&closure)?;
            let closure_descriptor = describe(&closure_bytes)?;
            let current =
                reconcile_family(&chain, root, &store, inputs, Some(&closure_descriptor))?;
            if current.snapshot != after_native {
                return Err(required(
                    "recovered family changed before closure publication",
                ));
            }
            if store.put(&closure_bytes, "application/json", None)? != closure_descriptor {
                return Err(required("recovery parent closure descriptor differs"));
            }
            stop(fault, Stop::ParentArtifact)?;
            let preparation = request.preparation_digest()?;
            let binding = &root_record.permit.binding;
            let draft = ReceiptDraftV1 {
                run_id: session.clone(),
                step_id: super::child_receipt_step_id(session, &preparation, "closure")?,
                kind: ReceiptKindV1::ChildClosed,
                valid_time: terminal.valid_time,
                lineage: build_lineage(&root_record.permit.permit_id, &binding.policy_version),
                spec_digest: content_digest(&reservation.attempt)?,
                args_digest: preparation,
                artifact_refs: vec![closure_descriptor],
                outcome: ReceiptOutcomeV1::Ok,
            };
            if let Some(index) = closed_index {
                compare_existing(draft, &history.rows[index])?;
            } else {
                if linked_index + 1 != history.rows.len() {
                    return Err(required("only latest pending recovery may acquire closure"));
                }
                ensure_suffix(
                    &mut chain,
                    root,
                    history.rows.len(),
                    vec![draft],
                    ledger_fault(fault),
                    true,
                )?;
            }
            chain.sync_all()?;
            crate::open_directory_tree(self.dependencies.output_root(), false)?.sync_all()?;
            stop(fault, Stop::BeforeReturn)?;
            let final_history = reconcile_family(&chain, root, &store, inputs, None)?;
            observer();
            history.recheck_closed(&family)?;
            current.recheck_closed(&family)?;
            final_history.recheck_closed(&family)?;
            let (_, _, final_root) =
                require_parent_history_context(context, root, session, &chain, &store)?;
            if final_root != root_record
                || root_policy
                    .read_normal_chat_session_control_record()?
                    .as_ref()
                    != Some(&root_record)
                || family.read_normal_chat_session_snapshot_v2()? != after_native
            {
                return Err(required("recovery native root/family changed at return"));
            }
            let final_child = verified_snapshot_expected_run_from_dir_fd(
                &child.pinned.root,
                &reservation.attempt.run_id()?,
            )?;
            let final_parent = appendable_snapshot_expected_run_from_dir_fd(root, session)?;
            if final_child.verification().final_head != child.chain.head().to_string()
                || final_parent.verification().final_head != chain.head().to_string()
                || final_parent.receipts().len() != expected_parent_len
            {
                return Err(required("recovery terminal heads changed at return"));
            }
            verify_child_links_in_runtime_root(
                &final_parent,
                &store,
                self.dependencies.output_root(),
                true,
            )?;
            let late = reconcile_family(&chain, root, &store, inputs, None)?;
            if late.snapshot != after_native || late.parent_head != *chain.head() {
                return Err(required("recovery closure history changed"));
            }
            let last = child.policy.read_normal_chat_attempt_v2(&family, intent)?;
            if last.local_control.as_ref() != Some(&closed)
                || last.outcome.is_some()
                || last.settlement.is_some()
                || last.state != NormalChatAttemptPolicyStateV2::RecoveredUnknown
            {
                return Err(required("recovery native terminal changed"));
            }
            if child.policy.confirm_normal_chat_recovery_v1(
                &family,
                intent,
                &proof.preflight.receipt_digest,
            )? != recovered
            {
                return Err(required(
                    "recovery disposition/fence changed at final confirmation",
                ));
            }
            require_parent_history_context(context, root, session, &chain, &store)?;
            history.recheck_closed(&family)?;
            current.recheck_closed(&family)?;
            final_history.recheck_closed(&family)?;
            late.recheck_closed(&family)?;
            child.artifacts.require_exact_inventory(&all_descriptors)?;
            child
                .artifacts
                .require_locator_matches(&child.pinned.root)?;
            child.pinned.ensure_locator_matches()?;
            store.require_locator_matches(root)?;
            gate.check(root)?;
            parent.ensure_locator_matches()?;
            clock.check()?;
            Ok(RuntimeNormalChatRecoveredV1 {
                attempt: reservation.attempt.clone(),
                recovery: recovered,
                child_dir: child.pinned.locator.clone(),
                terminal_receipt: terminal.receipt_id.clone(),
                child_head: child.chain.head().clone(),
                parent_head: chain.head().clone(),
            })
        })();
        let unlock = gate.unlock();
        match (result, unlock) {
            (Ok(value), Ok(())) => {
                parent.ensure_locator_matches()?;
                clock.check()?;
                Ok(value)
            }
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }
}
