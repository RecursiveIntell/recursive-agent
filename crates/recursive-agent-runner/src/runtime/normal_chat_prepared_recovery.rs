//! Explicit terminal recovery of a retained native Prepared local control.
use super::normal_chat_attempt::{expected_link, require_parent_history_context, MonotonicClock};
use super::normal_chat_family_history::{reconcile_family, FamilyHistoryInputs};
use super::normal_chat_session::SessionGate;
use super::normal_chat_terminal::{
    closure_link, compare_existing, describe, ensure_suffix, NormalChatTerminalInterruptionV2,
};
use super::{RuntimeService, RuntimeServiceError};
use crate::PinnedRunRoot;
use recursive_agent_contracts::{
    content_digest, jcs_canonical, parse_strict_json_value, ContentDigest, CurrentReceiptId,
    CurrentRunId, ReceiptKindV1, ReceiptOutcomeV1, RunTerminalStateV1,
};
use recursive_agent_ledger::{
    open_existing_from_dir_fd, publish_prepared_normal_chat_child_recovery_from_dir_fd,
    recoverable_normal_chat_preflight_snapshot_from_dir_fd,
    verify_closed_prepared_normal_chat_child_from_dir_fd, AppendStage, ArtifactStore,
    ChildRunLinkV1, ReceiptDraftV1, RunPaths,
};
use recursive_agent_policy::{
    build_lineage, DurablePermitStore, NormalChatAttemptPolicyStateV2,
    NormalChatPreparedRecoveryInterruptionV1, NormalChatPreparedRecoveryRecordV1,
};
use std::path::{Path, PathBuf};
fn required(reason: &'static str) -> RuntimeServiceError {
    RuntimeServiceError::NormalChatSessionRecoveryRequired { reason }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalChatPreparedRuntimeRecoveryInterruptionV1 {
    Native(NormalChatPreparedRecoveryInterruptionV1),
    AfterNative,
    ChildReceipt { ordinal: usize, stage: AppendStage },
    ParentArtifact,
    ParentReceipt(AppendStage),
    BeforeReturn,
}
/// Historical evidence only; cannot be cloned, deserialized or sent.
/// ```compile_fail
/// use recursive_agent_runner::RuntimeNormalChatPreparedRecoveredV1;
/// fn send(v: RuntimeNormalChatPreparedRecoveredV1) { v.submit_child(); }
/// ```
/// ```compile_fail
/// use recursive_agent_runner::RuntimeNormalChatPreparedRecoveredV1;
/// fn restore() -> Result<(), serde_json::Error> { let _: RuntimeNormalChatPreparedRecoveredV1 = serde_json::from_str("{}")?; Ok(()) }
/// ```
pub struct RuntimeNormalChatPreparedRecoveredV1 {
    child_dir: PathBuf,
    child_head: ContentDigest,
    parent_head: ContentDigest,
    terminal_receipt: CurrentReceiptId,
    recovery: NormalChatPreparedRecoveryRecordV1,
}
impl RuntimeNormalChatPreparedRecoveredV1 {
    pub fn child_run_dir(&self) -> &Path {
        &self.child_dir
    }
    pub fn child_chain_head(&self) -> &ContentDigest {
        &self.child_head
    }
    pub fn parent_chain_head(&self) -> &ContentDigest {
        &self.parent_head
    }
    pub fn terminal_receipt_id(&self) -> &CurrentReceiptId {
        &self.terminal_receipt
    }
    pub fn recovery(&self) -> &NormalChatPreparedRecoveryRecordV1 {
        &self.recovery
    }
    pub fn terminal_state(&self) -> RunTerminalStateV1 {
        RunTerminalStateV1::Failed
    }
}
impl RuntimeService {
    pub fn recover_prepared_normal_chat_attempt(
        &self,
        session: &CurrentRunId,
        intent: &str,
    ) -> Result<RuntimeNormalChatPreparedRecoveredV1, RuntimeServiceError> {
        self.recover_prepared_normal_chat_attempt_with_observer(session, intent, None, || {})
    }
    #[doc(hidden)]
    pub fn recover_prepared_normal_chat_attempt_with_observer(
        &self,
        session: &CurrentRunId,
        intent: &str,
        fault: Option<NormalChatPreparedRuntimeRecoveryInterruptionV1>,
        observer: impl FnOnce(),
    ) -> Result<RuntimeNormalChatPreparedRecoveredV1, RuntimeServiceError> {
        use NormalChatPreparedRuntimeRecoveryInterruptionV1 as Stop;
        if !self.normal_chat_interrupted_recovery_enabled {
            return Err(RuntimeServiceError::NormalChatRecoveryDisabled);
        }
        recursive_agent_contracts::NormalChatCallRequestV2::validate_dispatch_intent_ref(intent)?;
        if matches!(
            fault,
            Some(
                Stop::ChildReceipt { ordinal: 5.., .. }
                    | Stop::ChildReceipt {
                        stage: AppendStage::ArtifactWrite,
                        ..
                    }
                    | Stop::ParentReceipt(AppendStage::ArtifactWrite)
            )
        ) {
            return Err(required("invalid prepared recovery interruption"));
        }
        let parent = PinnedRunRoot::open_existing(
            self.dependencies.output_root(),
            &content_digest(session)?.to_string(),
        )?;
        let gate = SessionGate::acquire_existing(&parent.root)?;
        let clock = MonotonicClock::new_lazy(self.dependencies.clock());
        let result = (|| {
            let rows =
                recoverable_normal_chat_preflight_snapshot_from_dir_fd(&parent.root, session)?;
            let store = ArtifactStore::from_run_root_fd(&parent.root, false)?;
            let mut selected = None;
            for row in rows
                .receipts()
                .iter()
                .filter(|r| r.kind == ReceiptKindV1::ChildLinked)
            {
                if row.artifact_refs.len() != 1 {
                    return Err(required("prepared recovery child link malformed"));
                }
                let bytes = store.get(&row.artifact_refs[0])?;
                let value = parse_strict_json_value(&bytes)
                    .map_err(|_| required("invalid child link JSON"))?;
                let link: ChildRunLinkV1 =
                    serde_json::from_value(value).map_err(|_| required("invalid child link"))?;
                if jcs_canonical(&link)? != bytes {
                    return Err(required("lossy child link"));
                }
                let child = PinnedRunRoot::open_existing(
                    self.dependencies.output_root(),
                    &content_digest(&link.child_run_id)?.to_string(),
                )?;
                let child_policy =
                    DurablePermitStore::require_existing_from_run_root_fd(&child.root)?;
                let admission = child_policy
                    .read_retained_normal_chat_admission_v2()?
                    .ok_or_else(|| required("prepared recovery retained context absent"))?;
                if admission.reservation.attempt.dispatch_intent_ref == intent {
                    if selected.is_some()
                        || admission.context.session.run_id()? != *session
                        || expected_link(&admission.reservation)? != link
                    {
                        return Err(required("prepared recovery ambiguous context/link"));
                    }
                    selected = Some((child, child_policy, admission));
                }
            }
            let (child, child_policy, admission) =
                selected.ok_or_else(|| required("prepared recovery target absent"))?;
            let reservation = &admission.reservation;
            let context = &admission.context;
            let mut chain =
                open_existing_from_dir_fd(&RunPaths::new(&parent.locator), &parent.root)?;
            let (_, family, root_record) =
                require_parent_history_context(context, &parent.root, session, &chain, &store)?;
            let inputs = FamilyHistoryInputs {
                family: &family,
                context,
            };
            let history = reconcile_family(&chain, &parent.root, &store, inputs, None)?;
            let target = history
                .group(intent)
                .ok_or_else(|| required("prepared recovery canonical group absent"))?;
            if history
                .groups
                .last()
                .map(|g| g.request.dispatch_intent_ref.as_str())
                != Some(intent)
                || target.reservation != *reservation
            {
                return Err(required(
                    "prepared recovery target not latest canonical group",
                ));
            }
            let old = child_policy.read_normal_chat_prepared_recovery_v1(&family, intent)?;
            let view = child_policy.read_normal_chat_attempt_v2(&family, intent)?;
            if !matches!(
                view.state,
                NormalChatAttemptPolicyStateV2::Prepared
                    | NormalChatAttemptPolicyStateV2::RecoveredPrepared
            ) {
                return Err(required(
                    "prepared recovery requires actual Prepared native state",
                ));
            }
            let prefix = recoverable_normal_chat_preflight_snapshot_from_dir_fd(
                &child.root,
                &reservation.attempt.run_id()?,
            )?;
            let artifacts = ArtifactStore::from_run_root_fd(&child.root, false)?;
            if old.is_none() {
                if !prefix.receipts().is_empty() {
                    return Err(required(
                        "unrecovered Prepared control has child ledger history",
                    ));
                }
                artifacts.require_exact_inventory(&[])?;
                if clock.sample()
                    < super::normal_chat_attempt::retained_root_floor(&root_record, history.floor)
                {
                    return Err(required("prepared recovery clock precedes history"));
                }
                clock.check()?;
            }
            gate.check(&parent.root)?;
            parent.ensure_locator_matches()?;
            child.ensure_locator_matches()?;
            let recovery = child_policy.recover_prepared_normal_chat_attempt_v1(
                &family,
                intent,
                || clock.sample(),
                match fault {
                    Some(Stop::Native(point)) => Some(point),
                    _ => None,
                },
            )?;
            clock.check()?;
            if fault == Some(Stop::AfterNative) {
                return Err(required("prepared recovery interrupted after native"));
            }
            let proof = publish_prepared_normal_chat_child_recovery_from_dir_fd(
                &child.root,
                &RunPaths::new(&child.locator),
                &family,
                context,
                reservation,
                match fault {
                    Some(Stop::ChildReceipt { ordinal, stage }) => Some((ordinal, stage)),
                    _ => None,
                },
            )?;
            let closure = closure_link(reservation, proof.terminal_receipt(), proof.chain_head())?;
            let bytes = jcs_canonical(&closure)?;
            let descriptor = describe(&bytes)?;
            reconcile_family(&chain, &parent.root, &store, inputs, Some(&descriptor))?;
            if store.put(&bytes, "application/json", None)? != descriptor {
                return Err(required("prepared closure descriptor changed"));
            }
            if fault == Some(Stop::ParentArtifact) {
                return Err(required("prepared recovery interrupted at parent artifact"));
            }
            let preparation = target.request.preparation_digest()?;
            let draft = ReceiptDraftV1 {
                run_id: session.clone(),
                step_id: super::child_receipt_step_id(session, &preparation, "closure")?,
                kind: ReceiptKindV1::ChildClosed,
                valid_time: proof.terminal_receipt().valid_time,
                lineage: build_lineage(
                    &root_record.permit.permit_id,
                    &root_record.permit.binding.policy_version,
                ),
                spec_digest: content_digest(&reservation.attempt)?,
                args_digest: preparation,
                artifact_refs: vec![descriptor],
                outcome: ReceiptOutcomeV1::Ok,
            };
            if let Some(index) = target.closed_index {
                compare_existing(draft, &history.rows[index])?;
            } else {
                ensure_suffix(
                    &mut chain,
                    &parent.root,
                    history.rows.len(),
                    vec![draft],
                    match fault {
                        Some(Stop::ParentReceipt(stage)) => {
                            Some(NormalChatTerminalInterruptionV2::ParentReceipt(stage))
                        }
                        _ => None,
                    },
                    true,
                )?;
            }
            chain.sync_all()?;
            crate::open_directory_tree(self.dependencies.output_root(), false)?.sync_all()?;
            if fault == Some(Stop::BeforeReturn) {
                return Err(required("prepared recovery interrupted before return"));
            }
            observer();
            let final_history = reconcile_family(&chain, &parent.root, &store, inputs, None)?;
            history.recheck_closed(&family)?;
            final_history.recheck_closed(&family)?;
            let final_proof = verify_closed_prepared_normal_chat_child_from_dir_fd(
                &child.root,
                &family,
                context,
                reservation,
            )?;
            require_parent_history_context(context, &parent.root, session, &chain, &store)?;
            if final_proof.chain_head() != proof.chain_head()
                || child_policy
                    .read_normal_chat_prepared_recovery_v1(&family, intent)?
                    .as_ref()
                    != Some(&recovery)
            {
                return Err(required("prepared recovery changed at return"));
            }
            artifacts.require_locator_matches(&child.root)?;
            child.ensure_locator_matches()?;
            store.require_locator_matches(&parent.root)?;
            gate.check(&parent.root)?;
            parent.ensure_locator_matches()?;
            clock.check()?;
            Ok(RuntimeNormalChatPreparedRecoveredV1 {
                child_dir: child.locator.clone(),
                child_head: ContentDigest::from_hex(proof.chain_head().to_string())
                    .map_err(|_| required("verified child head malformed"))?,
                parent_head: chain.head().clone(),
                terminal_receipt: proof.terminal_receipt().receipt_id.clone(),
                recovery,
            })
        })();
        let unlock = gate.unlock();
        match (result, unlock) {
            (Ok(value), Ok(())) => {
                parent.ensure_locator_matches()?;
                Ok(value)
            }
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }
}
