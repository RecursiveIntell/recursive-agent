//! Runtime-owned reported terminal composition for one admitted V2 child.
//! No send continuation is reconstructed here, even on exact lost-ACK retry.
use super::normal_chat_attempt::{
    expected_link, preflight_rows, require_parent_history, require_parent_history_context,
    verify_parent_attempt_with_pending_closure, MonotonicClock,
};
use super::normal_chat_family_history::{reconcile_family, FamilyHistoryInputs};
use super::normal_chat_session::SessionGate;
use super::{RuntimeNormalChatSessionV1, RuntimeService, RuntimeServiceError};
use crate::PinnedRunRoot;
use chrono::{DateTime, Utc};
use recursive_agent_contracts::{
    content_digest, derive_artifact_id, jcs_canonical, ArtifactDescriptorV1, ContentDigest,
    CurrentReceiptId, NormalChatAttemptV2, NormalChatCallRequestV2, ReceiptKindV1,
    ReceiptOutcomeV1, ReceiptV1, RunTerminalStateV1,
};
use recursive_agent_ledger::{
    appendable_snapshot_expected_run_from_dir_fd, make_receipt, open_existing_from_dir_fd,
    verified_snapshot_expected_run_from_dir_fd, verify_child_links_in_runtime_root, AppendStage,
    ArtifactStore, ChainHandle, ChildRunLinkV1, ReceiptDraftV1, RunPaths,
};
use recursive_agent_policy::{
    build_lineage, DurablePermitStore, NormalChatExecutorReportV2,
    NormalChatLedgerAdmissionEvidenceV2, NormalChatReportedStateV2,
    NormalChatSettlementInterruptionV2, NormalChatSettlementV2, PermitEvidenceStateV1,
    PermitEvidenceV1, PermitRevocationReasonV1, PermitStateV1, PermitTransitionStage,
};
use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};

fn recovery(reason: &'static str) -> RuntimeServiceError {
    RuntimeServiceError::NormalChatSessionRecoveryRequired { reason }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalChatTerminalInterruptionV2 {
    Policy(NormalChatSettlementInterruptionV2),
    AfterPolicy,
    ControlClose(PermitTransitionStage),
    AfterControlClose,
    Artifact { ordinal: usize },
    ChildReceipt { ordinal: usize, stage: AppendStage },
    ParentArtifact,
    ParentReceipt(AppendStage),
    BeforeReturn,
}
fn stop(
    selected: Option<NormalChatTerminalInterruptionV2>,
    point: NormalChatTerminalInterruptionV2,
) -> Result<(), RuntimeServiceError> {
    if selected == Some(point) {
        return Err(recovery("normal-chat terminal composition interrupted"));
    }
    Ok(())
}
/// Returned only after strict child terminal and exact parent closure readback.
/// This is a local reported-outcome receipt, never provider confirmation or send.
pub struct RuntimeNormalChatSettlementV2 {
    attempt: NormalChatAttemptV2,
    settlement: NormalChatSettlementV2,
    child_dir: PathBuf,
    terminal_state: RunTerminalStateV1,
    terminal_receipt: CurrentReceiptId,
    child_head: ContentDigest,
    parent_head: ContentDigest,
}
impl RuntimeNormalChatSettlementV2 {
    pub fn attempt(&self) -> &NormalChatAttemptV2 {
        &self.attempt
    }
    pub fn settlement(&self) -> &NormalChatSettlementV2 {
        &self.settlement
    }
    pub fn child_run_dir(&self) -> &Path {
        &self.child_dir
    }
    pub fn terminal_state(&self) -> RunTerminalStateV1 {
        self.terminal_state
    }
    pub fn terminal_receipt_id(&self) -> &CurrentReceiptId {
        &self.terminal_receipt
    }
    pub fn child_chain_head(&self) -> &ContentDigest {
        &self.child_head
    }
    pub fn parent_chain_head(&self) -> &ContentDigest {
        &self.parent_head
    }
}
struct TerminalInput<'a> {
    session: &'a RuntimeNormalChatSessionV1,
    request: &'a NormalChatCallRequestV2,
    preflight: &'a ContentDigest,
    report: &'a NormalChatExecutorReportV2,
    historical_context: Option<&'a recursive_agent_policy::NormalChatGrantContextV2>,
}

impl RuntimeService {
    /// Repair only a durably reported child with an already-closed accounting
    /// control. No report, grant, clock, path or continuation is accepted. This
    /// does not recover the parent session or enable daemon TTL scheduling.
    pub fn repair_retained_normal_chat_settlement(
        &self,
        run_id: &recursive_agent_contracts::CurrentRunId,
        intent: &str,
    ) -> Result<RuntimeNormalChatSettlementV2, RuntimeServiceError> {
        if !self.normal_chat_interrupted_recovery_enabled {
            return Err(RuntimeServiceError::NormalChatRecoveryDisabled);
        }
        NormalChatCallRequestV2::validate_dispatch_intent_ref(intent)?;
        let pinned = PinnedRunRoot::open_existing(
            self.dependencies.output_root(),
            &content_digest(run_id)?.to_string(),
        )?;
        let gate = SessionGate::acquire_existing(&pinned.root)?;
        let result = (|| {
            let store = ArtifactStore::from_run_root_fd(&pinned.root, false)?;
            let child = super::normal_chat_recovery_inspection::discover(
                &pinned.root,
                &store,
                self.dependencies.output_root(),
                run_id,
                intent,
            )?;
            let context = child.proof.admission.context.clone();
            let parent = open_existing_from_dir_fd(&RunPaths::new(&pinned.locator), &pinned.root)?;
            let (_, family, _) =
                require_parent_history_context(&context, &pinned.root, run_id, &parent, &store)?;
            let view = child.policy.read_normal_chat_attempt_v2(&family, intent)?;
            if view.state != recursive_agent_policy::NormalChatAttemptPolicyStateV2::Settled
                || !matches!(
                    view.local_control.as_ref().map(|v| &v.state),
                    Some(PermitEvidenceStateV1::Revoked { .. })
                )
            {
                return Err(recovery("historical repair requires durable settlement and already-closed child control"));
            }
            let settled = view
                .settlement
                .as_ref()
                .ok_or_else(|| recovery("historical repair settlement absent"))?;
            settled.validate_for_admission_v2(&child.proof)?;
            if child.policy.confirm_normal_chat_settlement_v2(
                &family,
                intent,
                &child.proof.preflight.receipt_digest,
                &settled.report,
            )? != *settled
            {
                return Err(recovery("historical repair native confirmation differs"));
            }
            let request = NormalChatCallRequestV2::from_attempt(&view.attempt)?;
            let session = RuntimeNormalChatSessionV1 {
                pinned: PinnedRunRoot {
                    locator: pinned.locator.clone(),
                    root: pinned.root.try_clone()?,
                    identity: pinned.identity,
                },
                session: context.session.clone(),
                run_id: run_id.clone(),
                verified_head: parent.head().clone(),
            };
            let input = TerminalInput {
                session: &session,
                request: &request,
                preflight: &child.proof.preflight.receipt_digest,
                report: &settled.report,
                historical_context: Some(&context),
            };
            let clock = MonotonicClock::new_lazy(self.dependencies.clock());
            self.settle_normal_chat_locked(&input, &gate, &clock, None, || {})
        })();
        let unlock = gate.unlock();
        match (result, unlock) {
            (Ok(value), Ok(())) => {
                pinned.ensure_locator_matches()?;
                Ok(value)
            }
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }

    pub fn settle_normal_chat_attempt(
        &self,
        session: &RuntimeNormalChatSessionV1,
        request: &NormalChatCallRequestV2,
        preflight: &ContentDigest,
        report: &NormalChatExecutorReportV2,
    ) -> Result<RuntimeNormalChatSettlementV2, RuntimeServiceError> {
        self.settle_normal_chat_attempt_with_interruption(session, request, preflight, report, None)
    }
    #[doc(hidden)]
    pub fn settle_normal_chat_attempt_with_interruption(
        &self,
        session: &RuntimeNormalChatSessionV1,
        request: &NormalChatCallRequestV2,
        preflight: &ContentDigest,
        report: &NormalChatExecutorReportV2,
        fault: Option<NormalChatTerminalInterruptionV2>,
    ) -> Result<RuntimeNormalChatSettlementV2, RuntimeServiceError> {
        self.settle_normal_chat_attempt_with_observer(
            session,
            request,
            preflight,
            report,
            fault,
            || {},
        )
    }
    /// Negative-test seam; it cannot skip the final canonical readback/locators.
    #[doc(hidden)]
    pub fn settle_normal_chat_attempt_with_observer(
        &self,
        session: &RuntimeNormalChatSessionV1,
        request: &NormalChatCallRequestV2,
        preflight: &ContentDigest,
        report: &NormalChatExecutorReportV2,
        fault: Option<NormalChatTerminalInterruptionV2>,
        before_return: impl FnOnce(),
    ) -> Result<RuntimeNormalChatSettlementV2, RuntimeServiceError> {
        request.validate()?;
        report.validate()?;
        if request.operation.parent_run_id != *session.run_id()
            || request.operation.conversation_ref != session.session().conversation_ref
            || self.run_paths(session.run_id())?.root != session.run_dir()
        {
            return Err(recovery(
                "settlement does not bind this runtime session/root",
            ));
        }
        let payload_count = if report.state == NormalChatReportedStateV2::OutcomeUnknown {
            3
        } else {
            2
        };
        if matches!(fault, Some(NormalChatTerminalInterruptionV2::Artifact { ordinal }) if ordinal >= payload_count)
            || matches!(
                fault,
                Some(
                    NormalChatTerminalInterruptionV2::ChildReceipt { ordinal: 3.., .. }
                        | NormalChatTerminalInterruptionV2::ChildReceipt {
                            stage: AppendStage::ArtifactWrite,
                            ..
                        }
                        | NormalChatTerminalInterruptionV2::ParentReceipt(
                            AppendStage::ArtifactWrite
                        )
                )
            )
        {
            return Err(recovery("invalid terminal interruption selection"));
        }
        session.pinned.ensure_locator_matches()?;
        let gate = SessionGate::acquire(&session.pinned.root)?;
        let clock = MonotonicClock::new(self.dependencies.clock());
        let input = TerminalInput {
            session,
            request,
            preflight,
            report,
            historical_context: None,
        };
        let result = self.settle_normal_chat_locked(&input, &gate, &clock, fault, before_return);
        let unlock = gate.unlock();
        match (result, unlock) {
            (Ok(value), Ok(())) => {
                clock.check()?;
                session.pinned.ensure_locator_matches()?;
                Ok(value)
            }
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }

    fn settle_normal_chat_locked(
        &self,
        input: &TerminalInput<'_>,
        gate: &SessionGate,
        clock: &MonotonicClock<'_>,
        fault: Option<NormalChatTerminalInterruptionV2>,
        before_return: impl FnOnce(),
    ) -> Result<RuntimeNormalChatSettlementV2, RuntimeServiceError> {
        // Preserve the ordinary entry's original deny-before-storage ordering.
        // Only the private source-derived repair input may use historical context.
        if input.historical_context.is_none() && self.normal_chat_grant.is_none() {
            return Err(RuntimeServiceError::NormalChatGovernanceDisabled);
        }
        let session = input.session;
        let root = &session.pinned.root;
        let parent_store = ArtifactStore::from_run_root_fd(root, false)?;
        let mut parent = open_existing_from_dir_fd(&RunPaths::new(session.run_dir()), root)?;
        let (family, parent_record, context) = if let Some(context) = input.historical_context {
            let (_, family, record) = require_parent_history_context(
                context,
                root,
                session.run_id(),
                &parent,
                &parent_store,
            )?;
            (family, record, context.clone())
        } else {
            let authority = self
                .normal_chat_grant
                .as_ref()
                .ok_or(RuntimeServiceError::NormalChatGovernanceDisabled)?;
            let (_, family, record) =
                require_parent_history(authority, session, &parent, &parent_store)?;
            let context = recursive_agent_policy::NormalChatGrantContextV2 {
                grant: authority.grant().clone(),
                session: session.session().clone(),
                root_control: record.permit.clone(),
            };
            (family, record, context)
        };
        let family_view = family.read_normal_chat_session_snapshot_v2()?;
        let reservation = family_view
            .reservations
            .iter()
            .find(|value| value.attempt.dispatch_intent_ref == input.request.dispatch_intent_ref)
            .ok_or_else(|| recovery("terminal intent absent from canonical family"))?;
        let inputs = FamilyHistoryInputs {
            family: &family,
            context: &context,
        };
        let attempt = &reservation.attempt;
        if NormalChatFamilyRequest::from_prepared_call(
            input.request,
            reservation
                .child_control
                .request
                .parent_admission_receipt_id
                .clone(),
        )? != reservation_request(reservation)
        {
            return Err(recovery(
                "terminal request conflicts with canonical reservation",
            ));
        }
        let child_id = attempt.run_id()?;
        let child = PinnedRunRoot::open_existing(
            self.dependencies.output_root(),
            &content_digest(&child_id)?.to_string(),
        )?;
        let child_artifacts = ArtifactStore::from_run_root_fd(&child.root, false)?;
        let child_policy = DurablePermitStore::require_existing_from_run_root_fd(&child.root)?;
        let mut child_chain =
            open_existing_from_dir_fd(&RunPaths::new(&child.locator), &child.root)?;
        let view = child_policy
            .read_normal_chat_attempt_v2(&family, &input.request.dispatch_intent_ref)?;
        let proof = child_policy
            .read_normal_chat_ledger_admission_v2(&family, &input.request.dispatch_intent_ref)?
            .ok_or_else(|| recovery("settlement requires consumed admission"))?;
        if proof.admission.reservation != *reservation
            || &proof.preflight.receipt_digest != input.preflight
        {
            return Err(recovery("settlement preflight/reservation mismatch"));
        }
        if view
            .settlement
            .as_ref()
            .is_some_and(|old| old.report != *input.report)
        {
            return Err(recovery("conflicting terminal report"));
        }
        let base_payloads = preflight_payloads(&proof)?;
        let base_descriptors = describe_all(&base_payloads)?;
        verify_preflight(&child.root, &proof, &base_descriptors)?;
        let rows = appendable_snapshot_expected_run_from_dir_fd(&child.root, &child_id)?;
        if rows.receipts().len() > 7 && view.settlement.is_none() {
            return Err(recovery(
                "terminal ledger prefix lacks canonical policy settlement",
            ));
        }
        let current_control = view
            .local_control
            .as_ref()
            .ok_or_else(|| recovery("child control absent"))?;
        if input.historical_context.is_some()
            && (view.settlement.is_none()
                || !matches!(current_control.state, PermitEvidenceStateV1::Revoked { .. }))
        {
            return Err(recovery(
                "historical repair cannot perform a narrowing policy transition",
            ));
        }
        // Known complete artifacts left ahead of their receipts are permissible
        // only when their full bytes derive from already durable policy state.
        let mut allowed = base_descriptors.clone();
        if let Some(old) = &view.settlement {
            old.validate_for_admission_v2(&proof)?;
            let old_payloads = terminal_payloads(old, &proof, revoked_evidence(current_control))?;
            allowed.extend(describe_all(&old_payloads)?);
        }
        child_artifacts.require_inventory_subset(&allowed)?;
        let pending_before =
            pending_closure(&child.root, &proof, reservation, view.settlement.as_ref())?;
        let pending_descriptor = pending_before
            .as_ref()
            .map(jcs_canonical)
            .transpose()?
            .as_ref()
            .map(|bytes| describe(bytes))
            .transpose()?;
        let history = reconcile_family(
            &parent,
            root,
            &parent_store,
            inputs,
            pending_descriptor.as_ref(),
        )?;
        let target = history
            .group(&input.request.dispatch_intent_ref)
            .ok_or_else(|| recovery("terminal target absent from reconciled history"))?;
        if target.request != *input.request
            || target.reservation != *reservation
            || target.linked_index != target.prepared_index + 1
        {
            return Err(recovery(
                "terminal target differs from exact reconciled group",
            ));
        }
        let closed_index = target.closed_index;
        let expected_parent_length = if closed_index.is_some() {
            history.rows.len()
        } else {
            history.rows.len() + 1
        };
        // New native transitions must follow every retained semantic time.
        // Exact fully-closed history remains comparable after expiry or clock
        // regression because it writes no new policy timestamp.
        if view.settlement.is_none()
            || matches!(current_control.state, PermitEvidenceStateV1::Issued)
        {
            if clock.sample() < history.floor {
                return Err(recovery(
                    "terminal mutation clock precedes retained history",
                ));
            }
            clock.check()?;
        }
        let policy_fault = match fault {
            Some(NormalChatTerminalInterruptionV2::Policy(point)) => Some(point),
            _ => None,
        };
        let settled = if input.historical_context.is_some() || closed_index.is_some() {
            // Runtime has already verified the exact native terminal and parent
            // closure. Confirm existing durability, never replay a timed setter.
            child_policy.confirm_normal_chat_settlement_v2(
                &family,
                &input.request.dispatch_intent_ref,
                input.preflight,
                input.report,
            )?
        } else {
            child_policy.settle_normal_chat_attempt_v2_with_interruption(
                &family,
                &input.request.dispatch_intent_ref,
                input.preflight,
                input.report,
                || clock.sample(),
                policy_fault,
            )?
        };
        stop(fault, NormalChatTerminalInterruptionV2::AfterPolicy)?;
        settled.validate_for_admission_v2(&proof)?;
        let outcome = settled.ledger_outcome_v2(&proof)?;
        let control_id = proof.control_evidence()?.permit_id;
        let mut control = child_policy.state(&control_id)?;
        if matches!(control.state, PermitStateV1::Issued) {
            let point = match fault {
                Some(NormalChatTerminalInterruptionV2::ControlClose(stage)) => Some(stage),
                _ => None,
            };
            let now = clock.sample();
            if now < std::cmp::max(history.floor, settled.outcome.recorded_at) {
                return Err(recovery(
                    "control closure clock precedes retained settlement",
                ));
            }
            clock.check()?;
            control = child_policy.revoke_with_interruption(
                &control_id,
                PermitRevocationReasonV1::Operator,
                now,
                point,
            )?;
        }
        let closed = PermitEvidenceV1::from_record(&control)?;
        let (closed_at, reason) = match &closed.state {
            PermitEvidenceStateV1::Revoked { at, reason } => (*at, reason.clone()),
            _ => return Err(recovery("child accounting control is not closed")),
        };
        if outcome == ReceiptOutcomeV1::Ok && reason != PermitRevocationReasonV1::Operator {
            return Err(recovery(
                "non-Operator revocation cannot become successful orderly closure",
            ));
        }
        stop(fault, NormalChatTerminalInterruptionV2::AfterControlClose)?;
        let payloads = terminal_payloads(&settled, &proof, Some(&closed))?;
        let mut all_payloads = base_payloads;
        all_payloads.extend(payloads.clone());
        require_terminal_capacity(
            &all_payloads,
            reservation
                .child_control
                .request
                .requested_budget
                .max_artifact_bytes,
        )?;
        let descriptors = describe_all(&payloads)?;
        let mut all_descriptors = base_descriptors.clone();
        all_descriptors.extend(descriptors.clone());
        child_artifacts.require_inventory_subset(&all_descriptors)?;
        for (ordinal, bytes) in payloads.iter().enumerate() {
            let stored = child_artifacts.put(bytes, "application/json", None)?;
            if stored != descriptors[ordinal] {
                return Err(recovery("terminal artifact descriptor differs"));
            }
            stop(
                fault,
                NormalChatTerminalInterruptionV2::Artifact { ordinal },
            )?;
        }
        let drafts = terminal_drafts(&proof, &settled, &closed, closed_at, &descriptors)?;
        ensure_suffix(&mut child_chain, &child.root, 7, drafts, fault, false)?;
        child_chain.sync_all()?;
        child_artifacts.require_exact_inventory(&all_descriptors)?;
        let child_terminal = verified_snapshot_expected_run_from_dir_fd(&child.root, &child_id)?;
        if child_terminal.receipts().len() != 10
            || child_terminal.verification().final_head != child_chain.head().to_string()
        {
            return Err(recovery(
                "child terminal transcript differs from exact expected suffix",
            ));
        }
        let terminal = child_terminal
            .receipts()
            .last()
            .ok_or_else(|| recovery("child terminal absent"))?;
        let closure = closure_link(
            reservation,
            terminal,
            &child_terminal.verification().final_head,
        )?;
        let closure_bytes = jcs_canonical(&closure)?;
        let closure_descriptor = describe(&closure_bytes)?;
        verify_parent_attempt_with_pending_closure(
            &parent,
            root,
            &parent_store,
            input.request,
            reservation,
            Some(&closure_descriptor),
            inputs,
        )?;
        if parent_store.put(&closure_bytes, "application/json", None)? != closure_descriptor {
            return Err(recovery("parent closure artifact differs"));
        }
        stop(fault, NormalChatTerminalInterruptionV2::ParentArtifact)?;
        let preparation = input.request.preparation_digest()?;
        let binding = &parent_record.permit.binding;
        let parent_draft = ReceiptDraftV1 {
            run_id: session.run_id().clone(),
            step_id: super::child_receipt_step_id(session.run_id(), &preparation, "closure")?,
            kind: ReceiptKindV1::ChildClosed,
            valid_time: terminal.valid_time,
            lineage: build_lineage(&parent_record.permit.permit_id, &binding.policy_version),
            spec_digest: content_digest(attempt)?,
            args_digest: preparation,
            artifact_refs: vec![closure_descriptor.clone()],
            outcome: ReceiptOutcomeV1::Ok,
        };
        if let Some(index) = closed_index {
            compare_existing(parent_draft, &history.rows[index])?;
        } else {
            if target.linked_index + 1 != history.rows.len() {
                return Err(recovery(
                    "only the latest pending group may acquire closure",
                ));
            }
            ensure_suffix(
                &mut parent,
                root,
                history.rows.len(),
                vec![parent_draft],
                fault,
                true,
            )?;
        }
        parent.sync_all()?;
        crate::open_directory_tree(self.dependencies.output_root(), false)?.sync_all()?;
        stop(fault, NormalChatTerminalInterruptionV2::BeforeReturn)?;
        let final_history = reconcile_family(&parent, root, &parent_store, inputs, None)?;
        before_return();
        history.recheck_closed(&family)?;
        final_history.recheck_closed(&family)?;
        if input.historical_context.is_none() {
            clock.sample();
        }
        clock.check()?;
        child.ensure_locator_matches()?;
        session.pinned.ensure_locator_matches()?;
        gate.check(root)?;
        parent_store.require_locator_matches(root)?;
        child_artifacts.require_locator_matches(&child.root)?;
        let child_final = verified_snapshot_expected_run_from_dir_fd(&child.root, &child_id)?;
        let parent_final = appendable_snapshot_expected_run_from_dir_fd(root, session.run_id())?;
        if child_final.verification().final_head != child_chain.head().to_string()
            || parent_final.verification().final_head != parent.head().to_string()
            || parent_final.receipts().len() != expected_parent_length
        {
            return Err(recovery("terminal heads changed at return"));
        }
        verify_parent_attempt_with_pending_closure(
            &parent,
            root,
            &parent_store,
            input.request,
            reservation,
            None,
            inputs,
        )?;
        verify_child_links_in_runtime_root(
            &parent_final,
            &parent_store,
            self.dependencies.output_root(),
            final_history
                .groups
                .iter()
                .all(|value| value.closed_index.is_some()),
        )?;
        child_artifacts.require_exact_inventory(&all_descriptors)?;
        let final_policy = child_policy
            .read_normal_chat_attempt_v2(&family, &input.request.dispatch_intent_ref)?;
        if final_policy.settlement.as_ref() != Some(&settled)
            || final_policy.local_control.as_ref() != Some(&closed)
            || family.read_normal_chat_session_snapshot_v2()?.reservations
                != family_view.reservations
        {
            return Err(recovery("canonical terminal policy/reservation changed"));
        }
        // Reconfirm native outcome and any required family fence after the last
        // clock/observer. Historical confirmation never repairs missing closure
        // or fabricates a new report/timestamp, including explicit unknowns.
        if child_policy.confirm_normal_chat_settlement_v2(
            &family,
            &input.request.dispatch_intent_ref,
            input.preflight,
            input.report,
        )? != settled
        {
            return Err(recovery("terminal native outcome/fence changed at return"));
        }
        // Parent revocation/expiry is irrelevant to historical reporting, but
        // missing/rebound root authority must still never be silently recreated.
        require_parent_history_context(&context, root, session.run_id(), &parent, &parent_store)?;
        history.recheck_closed(&family)?;
        final_history.recheck_closed(&family)?;
        parent_store.require_locator_matches(root)?;
        child_artifacts.require_locator_matches(&child.root)?;
        gate.check(root)?;
        child.ensure_locator_matches()?;
        session.pinned.ensure_locator_matches()?;
        Ok(RuntimeNormalChatSettlementV2 {
            attempt: attempt.clone(),
            settlement: settled,
            child_dir: child.locator,
            terminal_state: child_final.verification().terminal_state,
            terminal_receipt: terminal.receipt_id.clone(),
            child_head: child_chain.head().clone(),
            parent_head: parent.head().clone(),
        })
    }
}

type NormalChatFamilyRequest = recursive_agent_policy::NormalChatFamilyReservationRequestV2;
fn reservation_request(
    value: &recursive_agent_policy::NormalChatFamilyReservationV2,
) -> NormalChatFamilyRequest {
    NormalChatFamilyRequest {
        operation: value.attempt.operation.clone(),
        provider_request_digest: value.attempt.provider_request_digest.clone(),
        provider_request_bytes: value.attempt.provider_request_bytes,
        dispatch_intent_ref: value.attempt.dispatch_intent_ref.clone(),
        parent_admission_receipt_id: value
            .child_control
            .request
            .parent_admission_receipt_id
            .clone(),
        requested_budget: value.child_control.request.requested_budget.clone(),
    }
}
pub(super) fn describe(bytes: &[u8]) -> Result<ArtifactDescriptorV1, RuntimeServiceError> {
    Ok(ArtifactDescriptorV1 {
        owner_id: derive_artifact_id(bytes)?,
        digest: ContentDigest::compute(bytes),
        byte_length: bytes.len() as u64,
        media_type: "application/json".into(),
        encoding: None,
    })
}
pub(super) fn describe_all(
    bytes: &[Vec<u8>],
) -> Result<Vec<ArtifactDescriptorV1>, RuntimeServiceError> {
    bytes.iter().map(|value| describe(value)).collect()
}
pub(super) fn preflight_payloads(
    proof: &NormalChatLedgerAdmissionEvidenceV2,
) -> Result<Vec<Vec<u8>>, RuntimeServiceError> {
    Ok(vec![
        jcs_canonical(&proof.control_evidence()?)?,
        jcs_canonical(proof)?,
        jcs_canonical(&proof.issued_effect_evidence()?)?,
        jcs_canonical(&proof.preflight.evidence)?,
    ])
}
fn revoked_evidence(value: &PermitEvidenceV1) -> Option<&PermitEvidenceV1> {
    if matches!(value.state, PermitEvidenceStateV1::Revoked { .. }) {
        Some(value)
    } else {
        None
    }
}
pub(super) fn terminal_payloads(
    settled: &NormalChatSettlementV2,
    proof: &NormalChatLedgerAdmissionEvidenceV2,
    closed: Option<&PermitEvidenceV1>,
) -> Result<Vec<Vec<u8>>, RuntimeServiceError> {
    let mut values = vec![jcs_canonical(settled)?];
    if let Some(degraded) = settled.degradation_record_v1(proof)? {
        values.push(jcs_canonical(&degraded)?);
    }
    if let Some(closed) = closed {
        values.push(jcs_canonical(closed)?);
    }
    Ok(values)
}
pub(super) fn require_terminal_capacity(
    payloads: &[Vec<u8>],
    maximum: u64,
) -> Result<(), RuntimeServiceError> {
    let mut unique = BTreeMap::new();
    for bytes in payloads {
        unique.insert(ContentDigest::compute(bytes), bytes.len() as u64);
    }
    let total = unique
        .values()
        .try_fold(0_u64, |sum, size| sum.checked_add(*size))
        .ok_or_else(|| recovery("terminal artifact aggregate overflow"))?;
    if total > maximum {
        return Err(recovery(
            "terminal artifacts exceed canonical child ceiling",
        ));
    }
    Ok(())
}
pub(super) fn compare_existing(
    draft: ReceiptDraftV1,
    actual: &ReceiptV1,
) -> Result<(), RuntimeServiceError> {
    let mut expected = make_receipt(draft, actual.prev_chain_digest.clone())?;
    expected.recorded_time = actual.recorded_time;
    if expected.canonical_bytes()? != actual.canonical_bytes()? {
        return Err(recovery(
            "retained receipt conflicts with exact canonical projection",
        ));
    }
    Ok(())
}
pub(super) fn verify_preflight(
    root: &File,
    proof: &NormalChatLedgerAdmissionEvidenceV2,
    descriptors: &[ArtifactDescriptorV1],
) -> Result<(), RuntimeServiceError> {
    let snapshot = appendable_snapshot_expected_run_from_dir_fd(
        root,
        &proof.preflight.evidence.binding.run_id,
    )?;
    if !(7..=10).contains(&snapshot.receipts().len()) {
        return Err(recovery(
            "incomplete or excessive preflight/terminal prefix",
        ));
    }
    let drafts = preflight_rows(
        &proof.control_evidence()?,
        &proof.issued_effect_evidence()?,
        &proof.preflight.evidence,
        proof.preflight.recorded_at,
        descriptors,
    );
    for (draft, actual) in drafts.into_iter().zip(snapshot.receipts()) {
        compare_existing(draft, actual)?;
    }
    Ok(())
}
pub(super) fn terminal_drafts(
    proof: &NormalChatLedgerAdmissionEvidenceV2,
    settled: &NormalChatSettlementV2,
    closed: &PermitEvidenceV1,
    closed_at: DateTime<Utc>,
    descriptors: &[ArtifactDescriptorV1],
) -> Result<Vec<ReceiptDraftV1>, RuntimeServiceError> {
    let effect = &proof.preflight.evidence;
    let outcome = settled.ledger_outcome_v2(proof)?;
    let end = std::cmp::max(settled.outcome.recorded_at, closed_at);
    let count = if settled.report.state == NormalChatReportedStateV2::OutcomeUnknown {
        2
    } else {
        1
    };
    if descriptors.len() != count + 1 {
        return Err(recovery("terminal artifact plan differs"));
    }
    let mut rows = Vec::new();
    for (evidence, kind, time, artifacts, result) in [
        (
            effect,
            ReceiptKindV1::NormalChatAttemptSettledV2,
            settled.outcome.recorded_at,
            descriptors[..count].to_vec(),
            outcome.clone(),
        ),
        (
            closed,
            ReceiptKindV1::PermitRevoked,
            closed_at,
            vec![descriptors[count].clone()],
            ReceiptOutcomeV1::Ok,
        ),
        (effect, ReceiptKindV1::RunFinalized, end, vec![], outcome),
    ] {
        rows.push(ReceiptDraftV1 {
            run_id: evidence.binding.run_id.clone(),
            step_id: evidence.binding.step_id.clone(),
            kind,
            valid_time: time,
            lineage: build_lineage(&evidence.permit_id, &evidence.binding.policy_version),
            spec_digest: evidence.binding.action_digest.clone(),
            args_digest: evidence.binding.args_digest.clone(),
            artifact_refs: artifacts,
            outcome: result,
        });
    }
    Ok(rows)
}
pub(super) fn ensure_suffix(
    chain: &mut ChainHandle,
    root: &File,
    base: usize,
    drafts: Vec<ReceiptDraftV1>,
    fault: Option<NormalChatTerminalInterruptionV2>,
    parent: bool,
) -> Result<(), RuntimeServiceError> {
    let run_id = drafts
        .first()
        .ok_or_else(|| recovery("empty terminal suffix plan"))?
        .run_id
        .clone();
    let prior = if base == 0 && drafts.len() == 7 && drafts[0].kind == ReceiptKindV1::RunStarted {
        recursive_agent_ledger::recoverable_normal_chat_preflight_snapshot_from_dir_fd(
            root, &run_id,
        )?
    } else {
        appendable_snapshot_expected_run_from_dir_fd(root, &run_id)?
    };
    if prior.receipts().len() < base || prior.receipts().len() > base + drafts.len() {
        return Err(recovery("unexpected terminal suffix length"));
    }
    for (ordinal, draft) in drafts.into_iter().enumerate() {
        if let Some(actual) = prior.receipts().get(base + ordinal) {
            compare_existing(draft, actual)?;
        } else {
            let receipt = make_receipt(draft, chain.head().clone())?;
            // Existing complete rows retain their actual recorded_time. Missing
            // rows are newly recorded now by the ledger owner; valid_time is the
            // immutable policy report/closure time, not a fabricated send time.
            let point = match fault {
                Some(NormalChatTerminalInterruptionV2::ParentReceipt(stage)) if parent => {
                    Some(stage)
                }
                Some(NormalChatTerminalInterruptionV2::ChildReceipt {
                    ordinal: selected,
                    stage,
                }) if !parent && selected == ordinal => Some(stage),
                _ => None,
            };
            chain.append_with_interruption(receipt, point)?;
        }
    }
    Ok(())
}
pub(super) fn closure_link(
    reservation: &recursive_agent_policy::NormalChatFamilyReservationV2,
    terminal: &ReceiptV1,
    head: &str,
) -> Result<ChildRunLinkV1, RuntimeServiceError> {
    if terminal.kind != ReceiptKindV1::RunFinalized {
        return Err(recovery("child closure lacks terminal receipt"));
    }
    Ok(ChildRunLinkV1 {
        child_terminal_receipt_id: Some(terminal.receipt_id.clone()),
        child_terminal_state: Some(
            terminal
                .outcome
                .terminal_state()
                .ok_or_else(|| recovery("child terminal outcome absent"))?,
        ),
        child_chain_head: Some(head.into()),
        ..expected_link(reservation)?
    })
}
fn pending_closure(
    root: &File,
    proof: &NormalChatLedgerAdmissionEvidenceV2,
    reservation: &recursive_agent_policy::NormalChatFamilyReservationV2,
    settled: Option<&NormalChatSettlementV2>,
) -> Result<Option<ChildRunLinkV1>, RuntimeServiceError> {
    let snapshot = appendable_snapshot_expected_run_from_dir_fd(
        root,
        &proof.preflight.evidence.binding.run_id,
    )?;
    if snapshot.receipts().len() != 10 {
        return Ok(None);
    }
    let settled = settled.ok_or_else(|| recovery("terminal child without canonical settlement"))?;
    let strict =
        verified_snapshot_expected_run_from_dir_fd(root, &proof.preflight.evidence.binding.run_id)?;
    if strict.verification().terminal_state
        != settled
            .ledger_outcome_v2(proof)?
            .terminal_state()
            .ok_or_else(|| recovery("report terminal absent"))?
    {
        return Err(recovery("child terminal contradicts canonical report"));
    }
    Ok(Some(closure_link(
        reservation,
        strict
            .receipts()
            .last()
            .ok_or_else(|| recovery("terminal absent"))?,
        &strict.verification().final_head,
    )?))
}
