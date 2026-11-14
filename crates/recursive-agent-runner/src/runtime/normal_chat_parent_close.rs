//! Runtime parent terminal composition. Native closure is a prerequisite, not
//! a terminal certificate. No status/recovery path reconstructs send authority.
use super::normal_chat_attempt::{require_parent_history, MonotonicClock};
use super::normal_chat_family_history::{reconcile_family, ReconciledFamilyV2};
use super::normal_chat_session::SessionGate;
use super::normal_chat_terminal::{compare_existing, describe};
use super::{RuntimeNormalChatSessionV1, RuntimeService, RuntimeServiceError};
use chrono::{DateTime, Utc};
use recursive_agent_contracts::{
    jcs_canonical, ArtifactDescriptorV1, ContentDigest, ReceiptKindV1, ReceiptOutcomeV1, ReceiptV1,
    RunTerminalStateV1,
};
use recursive_agent_ledger::{
    appendable_snapshot_expected_run_from_dir_fd, make_receipt, open_existing_from_dir_fd,
    verified_snapshot_expected_run_from_dir_fd, verify_child_links_in_runtime_root, AppendStage,
    ArtifactStore, ReceiptDraftV1, RunPaths,
};
use recursive_agent_policy::{
    build_lineage, NormalChatGrantContextV2, NormalChatSessionCloseInterruptionV2,
    NormalChatSessionSnapshotV2, PermitEvidenceV1, PermitRecordV1, PermitRevocationReasonV1,
    PermitStateV1,
};
use std::collections::BTreeMap;

fn recovery(reason: &'static str) -> RuntimeServiceError {
    RuntimeServiceError::NormalChatSessionRecoveryRequired { reason }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalChatParentCloseInterruptionV2 {
    Native(NormalChatSessionCloseInterruptionV2),
    AfterNative,
    MetadataCapacity,
    AfterArtifact,
    Receipt { ordinal: usize, stage: AppendStage },
    BeforeReturn,
}
/// Lifecycle closure, NOT evidence that all model attempts succeeded.
///
/// ```compile_fail
/// use recursive_agent_runner::RuntimeNormalChatClosedSessionV2;
/// fn forge() -> RuntimeNormalChatClosedSessionV2 { RuntimeNormalChatClosedSessionV2 {} }
/// ```
pub struct RuntimeNormalChatClosedSessionV2 {
    head: ContentDigest,
    state: RunTerminalStateV1,
    attempts: usize,
    all_success: bool,
}
impl RuntimeNormalChatClosedSessionV2 {
    pub fn chain_head(&self) -> &ContentDigest {
        &self.head
    }
    pub fn terminal_state(&self) -> RunTerminalStateV1 {
        self.state
    }
    pub fn attempt_count(&self) -> usize {
        self.attempts
    }
    pub fn all_attempts_reported_success(&self) -> bool {
        self.all_success
    }
}
/// Pure projection of existing native state, not another close/state database.
pub(super) struct ParentTerminalV2 {
    pub descriptor: ArtifactDescriptorV1,
    pub bytes: Vec<u8>,
    record: PermitRecordV1,
    snapshot: NormalChatSessionSnapshotV2,
    floor: DateTime<Utc>,
}
impl ParentTerminalV2 {
    pub fn outcome(&self) -> RunTerminalStateV1 {
        let reason = match &self.record.state {
            PermitStateV1::Revoked { reason, .. } => reason,
            _ => return RunTerminalStateV1::Denied,
        };
        if self.snapshot.admission.parent_revoked_at.is_some()
            || matches!(
                reason,
                PermitRevocationReasonV1::ParentRevoked
                    | PermitRevocationReasonV1::OperationCancelled
            )
        {
            RunTerminalStateV1::Cancelled
        } else if *reason != PermitRevocationReasonV1::Operator {
            RunTerminalStateV1::Denied
        } else {
            RunTerminalStateV1::Succeeded
        }
    }
    pub fn drafts(&self) -> Result<Vec<ReceiptDraftV1>, RuntimeServiceError> {
        let at = match self.record.state {
            PermitStateV1::Revoked { revoked_at, .. } => revoked_at,
            _ => return Err(recovery("parent terminal lacks root revocation")),
        };
        let binding = &self.record.permit.binding;
        let final_at = std::cmp::max(
            self.floor,
            std::cmp::max(
                at,
                self.snapshot
                    .admission
                    .closed_at
                    .ok_or_else(|| recovery("family not closed"))?,
            ),
        );
        let state = self.outcome();
        let make = |kind, valid_time, artifact_refs, outcome| ReceiptDraftV1 {
            run_id: binding.run_id.clone(),
            step_id: binding.step_id.clone(),
            kind,
            valid_time,
            lineage: build_lineage(&self.record.permit.permit_id, &binding.policy_version),
            spec_digest: binding.action_digest.clone(),
            args_digest: binding.args_digest.clone(),
            artifact_refs,
            outcome,
        };
        let mut drafts = Vec::new();
        if state == RunTerminalStateV1::Cancelled {
            let cause_at = self.snapshot.admission.parent_revoked_at.unwrap_or(at);
            if cause_at < binding.issued_at {
                return Err(recovery("parent cancellation precedes root issuance"));
            }
            drafts.push(make(
                ReceiptKindV1::ParentCancelled,
                cause_at,
                vec![],
                ReceiptOutcomeV1::Cancelled {
                    reason: "normal_chat_session_cancelled".into(),
                },
            ));
        }
        drafts.push(make(
            ReceiptKindV1::PermitRevoked,
            at,
            vec![self.descriptor.clone()],
            if state == RunTerminalStateV1::Denied {
                ReceiptOutcomeV1::Denied
            } else {
                ReceiptOutcomeV1::Ok
            },
        ));
        drafts.push(make(
            ReceiptKindV1::RunFinalized,
            std::cmp::max(
                final_at,
                self.snapshot
                    .admission
                    .parent_revoked_at
                    .unwrap_or(final_at),
            ),
            vec![],
            match state {
                RunTerminalStateV1::Succeeded => ReceiptOutcomeV1::Ok,
                RunTerminalStateV1::Cancelled => ReceiptOutcomeV1::Cancelled {
                    reason: "normal_chat_session_cancelled".into(),
                },
                _ => ReceiptOutcomeV1::Denied,
            },
        ));
        Ok(drafts)
    }
    pub fn compare_tail(&self, rows: &[ReceiptV1]) -> Result<(), RuntimeServiceError> {
        let drafts = self.drafts()?;
        if rows.len() > drafts.len() {
            return Err(recovery("parent terminal has extra rows"));
        }
        for (draft, row) in drafts.into_iter().zip(rows) {
            compare_existing(draft, row)?;
        }
        Ok(())
    }
    fn require_capacity(
        &self,
        history: &ReconciledFamilyV2,
        maximum: u64,
    ) -> Result<(), RuntimeServiceError> {
        let mut sizes = BTreeMap::new();
        for row in &history.rows {
            for d in &row.artifact_refs {
                sizes.insert(d.digest.clone(), d.byte_length);
            }
        }
        for group in &history.groups {
            let d = super::normal_chat_attempt::request_descriptor(&group.request)?;
            sizes.insert(d.digest, d.byte_length);
        }
        sizes.insert(self.descriptor.digest.clone(), self.descriptor.byte_length);
        let total = sizes
            .values()
            .try_fold(0u64, |n, v| n.checked_add(*v))
            .ok_or_else(|| recovery("parent artifact aggregate overflow"))?;
        if total > maximum {
            return Err(recovery(
                "parent metadata exceeds original artifact ceiling",
            ));
        }
        Ok(())
    }
}
pub(super) fn parent_terminal_projection(
    context: &NormalChatGrantContextV2,
    record: &PermitRecordV1,
    snapshot: &NormalChatSessionSnapshotV2,
    floor: DateTime<Utc>,
    children_complete: bool,
) -> Result<Option<ParentTerminalV2>, RuntimeServiceError> {
    let mut original = context.session_root_issued_record_v2()?;
    original.state = record.state.clone();
    if original != *record
        || snapshot
            .admission
            .parent_revoked_at
            .is_some_and(|at| at < record.permit.binding.issued_at)
    {
        return Err(recovery("parent close native record/time differs"));
    }
    let PermitStateV1::Revoked { revoked_at, .. } = record.state else {
        return Ok(None);
    };
    if revoked_at < record.permit.binding.issued_at {
        return Err(recovery("root revocation precedes issue"));
    }
    if !children_complete || snapshot.admission.closed_at.is_none() {
        return Ok(None);
    }
    let bytes = jcs_canonical(&PermitEvidenceV1::from_record(record)?)?;
    Ok(Some(ParentTerminalV2 {
        descriptor: describe(&bytes)?,
        bytes,
        record: record.clone(),
        snapshot: snapshot.clone(),
        floor,
    }))
}
fn stop(
    selected: Option<NormalChatParentCloseInterruptionV2>,
    point: NormalChatParentCloseInterruptionV2,
) -> Result<(), RuntimeServiceError> {
    if selected == Some(point) {
        return Err(recovery("parent close interrupted"));
    }
    Ok(())
}
impl RuntimeService {
    pub fn close_normal_chat_session(
        &self,
        session: &RuntimeNormalChatSessionV1,
    ) -> Result<RuntimeNormalChatClosedSessionV2, RuntimeServiceError> {
        self.close_normal_chat_session_with_interruption(session, None)
    }
    #[doc(hidden)]
    pub fn close_normal_chat_session_with_interruption(
        &self,
        session: &RuntimeNormalChatSessionV1,
        fault: Option<NormalChatParentCloseInterruptionV2>,
    ) -> Result<RuntimeNormalChatClosedSessionV2, RuntimeServiceError> {
        self.close_normal_chat_session_with_observer(session, fault, || {})
    }
    #[doc(hidden)]
    pub fn close_normal_chat_session_with_observer(
        &self,
        session: &RuntimeNormalChatSessionV1,
        fault: Option<NormalChatParentCloseInterruptionV2>,
        observer: impl FnOnce(),
    ) -> Result<RuntimeNormalChatClosedSessionV2, RuntimeServiceError> {
        if self.run_paths(session.run_id())?.root != session.run_dir() {
            return Err(recovery("parent close root differs"));
        }
        if matches!(
            fault,
            Some(
                NormalChatParentCloseInterruptionV2::Receipt { ordinal: 3.., .. }
                    | NormalChatParentCloseInterruptionV2::Receipt {
                        stage: AppendStage::ArtifactWrite,
                        ..
                    }
            )
        ) {
            return Err(recovery("invalid parent close interruption"));
        }
        let authority = self
            .normal_chat_grant
            .as_ref()
            .ok_or(RuntimeServiceError::NormalChatGovernanceDisabled)?;
        session.pinned.ensure_locator_matches()?;
        let root = &session.pinned.root;
        let gate = SessionGate::acquire_existing(root)?;
        let clock = MonotonicClock::new(self.dependencies.clock());
        let result = (|| -> Result<RuntimeNormalChatClosedSessionV2, RuntimeServiceError> {
            let mut chain = open_existing_from_dir_fd(&RunPaths::new(session.run_dir()), root)?;
            let store = ArtifactStore::from_run_root_fd(root, false)?;
            let (permits, family, record) =
                require_parent_history(authority, session, &chain, &store)?;
            let context = NormalChatGrantContextV2 {
                grant: authority.grant().clone(),
                session: session.session().clone(),
                root_control: record.permit,
            };
            let inputs = super::normal_chat_family_history::FamilyHistoryInputs {
                family: &family,
                context: &context,
            };
            let history = reconcile_family(&chain, root, &store, inputs, None)?;
            history.require_terminalizable()?;
            let floor = std::cmp::max(history.floor, clock.sample());
            clock.check()?;
            let native = permits.close_normal_chat_session_v2_with_interruption(
                &family,
                &context,
                &history.snapshot,
                floor,
                || clock.sample(),
                match fault {
                    Some(NormalChatParentCloseInterruptionV2::Native(point)) => Some(point),
                    _ => None,
                },
            )?;
            clock.check()?;
            stop(fault, NormalChatParentCloseInterruptionV2::AfterNative)?;
            let projection = parent_terminal_projection(
                &context,
                &native.root_control,
                &native.snapshot,
                history.floor,
                true,
            )?
            .ok_or_else(|| recovery("native close did not close pair"))?;
            let current = reconcile_family(&chain, root, &store, inputs, None)?;
            current.require_terminalizable()?;
            if current.snapshot != native.snapshot {
                return Err(recovery("closed family changed before publication"));
            }
            projection.require_capacity(
                &current,
                if fault == Some(NormalChatParentCloseInterruptionV2::MetadataCapacity) {
                    0
                } else {
                    native.root_control.permit.binding.budget.max_artifact_bytes
                },
            )?;
            let drafts = projection.drafts()?;
            if matches!(fault,Some(NormalChatParentCloseInterruptionV2::Receipt{ordinal,..}) if ordinal>=drafts.len())
            {
                return Err(recovery("unused parent receipt interruption"));
            }
            projection.compare_tail(&current.rows[current.group_end..])?;
            if store.put(&projection.bytes, "application/json", None)? != projection.descriptor {
                return Err(recovery("parent close descriptor differs"));
            }
            stop(fault, NormalChatParentCloseInterruptionV2::AfterArtifact)?;
            for (ordinal, draft) in drafts.into_iter().enumerate() {
                let index = current.group_end + ordinal;
                if let Some(row) = current.rows.get(index) {
                    compare_existing(draft, row)?;
                } else {
                    if chain.length() as usize != index {
                        return Err(recovery("parent terminal append length differs"));
                    }
                    let row = make_receipt(draft, chain.head().clone())?;
                    let stage = match fault {
                        Some(NormalChatParentCloseInterruptionV2::Receipt {
                            ordinal: chosen,
                            stage,
                        }) if chosen == ordinal => Some(stage),
                        _ => None,
                    };
                    chain.append_with_interruption(row, stage)?;
                }
            }
            chain.sync_all()?;
            crate::open_directory_tree(self.dependencies.output_root(), false)?.sync_all()?;
            stop(fault, NormalChatParentCloseInterruptionV2::BeforeReturn)?;
            let final_history = reconcile_family(&chain, root, &store, inputs, None)?;
            final_history.require_terminalizable()?;
            observer();
            history.recheck_closed(&family)?;
            current.recheck_closed(&family)?;
            final_history.recheck_closed(&family)?;
            let strict = verified_snapshot_expected_run_from_dir_fd(root, session.run_id())?;
            verify_child_links_in_runtime_root(
                &strict,
                &store,
                self.dependencies.output_root(),
                true,
            )?;
            let late = reconcile_family(&chain, root, &store, inputs, None)?;
            if late.snapshot != native.snapshot
                || late.parent_head != *chain.head()
                || late.rows.len() != current.group_end + projection.drafts()?.len()
            {
                return Err(recovery("parent terminal changed at return"));
            }
            let confirmed =
                permits.confirm_closed_normal_chat_session_v2(&family, &context, &native)?;
            if confirmed != native {
                return Err(recovery("native close changed at return"));
            }
            clock.sample();
            clock.check()?;
            history.recheck_closed(&family)?;
            final_history.recheck_closed(&family)?;
            late.recheck_closed(&family)?;
            // No clock callback may invalidate authority after its last read.
            // Both owners are already closed: this is noncreating, clock-free
            // durability confirmation, not a retry of a timed close transition.
            if permits.confirm_closed_normal_chat_session_v2(&family, &context, &native)? != native
            {
                return Err(recovery("native close changed after final time sample"));
            }
            store.require_locator_matches(root)?;
            gate.check(root)?;
            session.pinned.ensure_locator_matches()?;
            let end = appendable_snapshot_expected_run_from_dir_fd(root, session.run_id())?;
            if end.verification().final_head != chain.head().to_string() {
                return Err(recovery("parent head changed at final fence"));
            }
            let all_success = !late.groups.is_empty()
                && late.groups.iter().all(|g| {
                    g.child_policy.settlement.as_ref().is_some_and(|s| {
                        s.report.state
                            == recursive_agent_policy::NormalChatReportedStateV2::Succeeded
                            && s.violations.is_empty()
                    })
                });
            Ok(RuntimeNormalChatClosedSessionV2 {
                head: chain.head().clone(),
                state: projection.outcome(),
                attempts: late.groups.len(),
                all_success: all_success && projection.outcome() == RunTerminalStateV1::Succeeded,
            })
        })();
        let unlock = gate.unlock();
        match (result, unlock) {
            (Ok(value), Ok(())) => {
                session.pinned.ensure_locator_matches()?;
                Ok(value)
            }
            (Err(e), _) | (Ok(_), Err(e)) => Err(e),
        }
    }
}
