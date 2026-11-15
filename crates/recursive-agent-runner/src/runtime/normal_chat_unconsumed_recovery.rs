//! Source-proven nonconsumed bootstrap interruption. No authority creation.
use super::normal_chat_attempt::{require_parent_history_context, MonotonicClock};
use super::normal_chat_family_history::{reconcile_family, FamilyHistoryInputs};
use super::normal_chat_session::SessionGate;
use super::normal_chat_terminal::{
    closure_link, describe, ensure_suffix, NormalChatTerminalInterruptionV2,
};
use super::{RuntimeService, RuntimeServiceError};
use crate::PinnedRunRoot;
use recursive_agent_contracts::{
    content_digest, jcs_canonical, parse_strict_json_value, ContentDigest, CurrentRunId,
    NormalChatCallRequestV2, NormalChatSessionV1, ReceiptKindV1, ReceiptOutcomeV1,
};
use recursive_agent_ledger::{
    open_existing_from_dir_fd, publish_unconsumed_normal_chat_child_recovery_from_dir_fd,
    recoverable_normal_chat_preflight_snapshot_from_dir_fd,
    verify_closed_unconsumed_normal_chat_child_from_dir_fd, AppendStage, ArtifactStore,
    ReceiptDraftV1, RunPaths,
};
use recursive_agent_policy::{
    build_lineage, DurablePermitStore, FamilyAuthorityStore, NormalChatUnconsumedRecoveryRecordV1,
    PermitTransitionStage,
};
use std::path::{Path, PathBuf};
fn required(reason: &'static str) -> RuntimeServiceError {
    RuntimeServiceError::NormalChatSessionRecoveryRequired { reason }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalChatUnconsumedRuntimeRecoveryInterruptionV1 {
    Native(PermitTransitionStage),
    AfterNative,
    ChildReceipt { ordinal: usize, stage: AppendStage },
    ParentArtifact,
    ParentReceipt(AppendStage),
    BeforeReturn,
}
/// Historical terminal evidence, not a Fresh/send capability.
pub struct RuntimeNormalChatUnconsumedRecoveredV1 {
    child_dir: PathBuf,
    child_head: ContentDigest,
    parent_head: ContentDigest,
    recovery: NormalChatUnconsumedRecoveryRecordV1,
}
impl RuntimeNormalChatUnconsumedRecoveredV1 {
    pub fn child_run_dir(&self) -> &Path {
        &self.child_dir
    }
    pub fn child_chain_head(&self) -> &ContentDigest {
        &self.child_head
    }
    pub fn parent_chain_head(&self) -> &ContentDigest {
        &self.parent_head
    }
    pub fn recovery(&self) -> &NormalChatUnconsumedRecoveryRecordV1 {
        &self.recovery
    }
}
impl RuntimeService {
    pub fn recover_unconsumed_normal_chat_attempt(
        &self,
        session: &CurrentRunId,
        intent: &str,
    ) -> Result<RuntimeNormalChatUnconsumedRecoveredV1, RuntimeServiceError> {
        self.recover_unconsumed_normal_chat_attempt_with_observer(session, intent, None, || {})
    }
    #[doc(hidden)]
    pub fn recover_unconsumed_normal_chat_attempt_with_observer(
        &self,
        session: &CurrentRunId,
        intent: &str,
        fault: Option<NormalChatUnconsumedRuntimeRecoveryInterruptionV1>,
        observer: impl FnOnce(),
    ) -> Result<RuntimeNormalChatUnconsumedRecoveredV1, RuntimeServiceError> {
        use NormalChatUnconsumedRuntimeRecoveryInterruptionV1 as Stop;
        if !self.normal_chat_interrupted_recovery_enabled {
            return Err(RuntimeServiceError::NormalChatRecoveryDisabled);
        }
        NormalChatCallRequestV2::validate_dispatch_intent_ref(intent)?;
        if matches!(
            fault,
            Some(
                Stop::ChildReceipt { ordinal: 3.., .. }
                    | Stop::ChildReceipt {
                        stage: AppendStage::ArtifactWrite,
                        ..
                    }
                    | Stop::ParentReceipt(AppendStage::ArtifactWrite)
            )
        ) {
            return Err(required("invalid unconsumed recovery fault"));
        }
        let parent = PinnedRunRoot::open_existing(
            self.dependencies.output_root(),
            &content_digest(session)?.to_string(),
        )?;
        let gate = SessionGate::acquire_existing(&parent.root)?;
        let clock = MonotonicClock::new_lazy(self.dependencies.clock());
        let result = (|| {
            let snapshot =
                recoverable_normal_chat_preflight_snapshot_from_dir_fd(&parent.root, session)?;
            let store = ArtifactStore::from_run_root_fd(&parent.root, false)?;
            let descriptor = snapshot
                .receipts()
                .first()
                .and_then(|r| r.artifact_refs.first())
                .ok_or_else(|| required("bootstrap identity absent"))?;
            let bytes = store.get(descriptor)?;
            let identity: NormalChatSessionV1 = serde_json::from_value(
                parse_strict_json_value(&bytes).map_err(|_| required("invalid session JSON"))?,
            )
            .map_err(|_| required("invalid session identity"))?;
            if jcs_canonical(&identity)? != bytes || identity.run_id()? != *session {
                return Err(required("session identity differs"));
            }
            let (_, context) =
                FamilyAuthorityStore::require_existing_normal_chat_history_context_v1(
                    &parent.root,
                    &identity,
                )?;
            let mut chain =
                open_existing_from_dir_fd(&RunPaths::new(&parent.locator), &parent.root)?;
            let (_, family, root_record) =
                require_parent_history_context(&context, &parent.root, session, &chain, &store)?;
            let reservation = family
                .read_normal_chat_reservation(intent)?
                .ok_or_else(|| required("reservation absent"))?;
            let child_id = reservation.attempt.run_id()?;
            let child = PinnedRunRoot::open_existing(
                self.dependencies.output_root(),
                &content_digest(&child_id)?.to_string(),
            )?;
            let policy = DurablePermitStore::require_existing_from_run_root_fd(&child.root)?;
            let checkpoint = family.require_normal_chat_child_checkpoint_v1(intent, &child.root)?;
            let history = reconcile_family(
                &chain,
                &parent.root,
                &store,
                FamilyHistoryInputs {
                    family: &family,
                    context: &context,
                },
                None,
            )?;
            let group = history
                .group(intent)
                .ok_or_else(|| required("canonical child group absent"))?;
            if history
                .groups
                .iter()
                .any(|g| g.request.dispatch_intent_ref != intent && g.closed_index.is_none())
                || history
                    .groups
                    .last()
                    .map(|g| g.request.dispatch_intent_ref.as_str())
                    != Some(intent)
            {
                return Err(required("unconsumed child is not latest serial group"));
            }
            let view = policy.read_normal_chat_attempt_v2(&family, intent)?;
            if view.local_control.is_some()
                || view.effect.is_some()
                || view.preflight.is_some()
                || view.outcome.is_some()
                || view.settlement.is_some()
            {
                return Err(required("local control or consumption exists"));
            }
            let artifacts = ArtifactStore::from_run_root_fd(&child.root, false)?;
            let old = family.read_normal_chat_unconsumed_recovery_v1()?;
            if old.is_none() {
                let child_rows =
                    recoverable_normal_chat_preflight_snapshot_from_dir_fd(&child.root, &child_id)?;
                if !child_rows.receipts().is_empty() {
                    return Err(required(
                        "unconsumed source is not preflight-free empty prefix",
                    ));
                }
                artifacts.require_exact_inventory(&[])?;
                let floor = super::normal_chat_attempt::retained_root_floor(
                    &root_record,
                    std::cmp::max(history.floor, checkpoint.at),
                );
                if clock.sample() < floor {
                    return Err(required("unconsumed clock precedes complete history"));
                }
                clock.check()?;
            }
            checkpoint.check(&child.root)?;
            history.recheck_closed(&family)?;
            gate.check(&parent.root)?;
            parent.ensure_locator_matches()?;
            child.ensure_locator_matches()?;
            let record = policy.recover_unconsumed_normal_chat_attempt_v1(
                &family,
                &context,
                intent,
                || clock.sample(),
                match fault {
                    Some(Stop::Native(s)) => Some(s),
                    _ => None,
                },
            )?;
            clock.check()?;
            if fault == Some(Stop::AfterNative) {
                return Err(required("unconsumed interrupted after native"));
            }
            let proof = publish_unconsumed_normal_chat_child_recovery_from_dir_fd(
                &child.root,
                &RunPaths::new(&child.locator),
                &family,
                &context,
                &reservation,
                match fault {
                    Some(Stop::ChildReceipt { ordinal, stage }) => Some((ordinal, stage)),
                    _ => None,
                },
            )?;
            let closure = closure_link(&reservation, proof.terminal_receipt(), proof.chain_head())?;
            let bytes = jcs_canonical(&closure)?;
            let descriptor = describe(&bytes)?;
            store.put(&bytes, "application/json", None)?;
            if fault == Some(Stop::ParentArtifact) {
                return Err(required("unconsumed interrupted parent artifact"));
            }
            let digest = NormalChatCallRequestV2::from_attempt(&reservation.attempt)?
                .preparation_digest()?;
            ensure_suffix(
                &mut chain,
                &parent.root,
                group.linked_index + 1,
                vec![ReceiptDraftV1 {
                    run_id: session.clone(),
                    step_id: super::child_receipt_step_id(session, &digest, "closure")?,
                    kind: ReceiptKindV1::ChildClosed,
                    valid_time: proof.terminal_receipt().valid_time,
                    lineage: build_lineage(
                        &context.root_control.permit_id,
                        &context.root_control.binding.policy_version,
                    ),
                    spec_digest: content_digest(&reservation.attempt)?,
                    args_digest: digest,
                    artifact_refs: vec![descriptor],
                    outcome: ReceiptOutcomeV1::Ok,
                }],
                match fault {
                    Some(Stop::ParentReceipt(s)) => {
                        Some(NormalChatTerminalInterruptionV2::ParentReceipt(s))
                    }
                    _ => None,
                },
                true,
            )?;
            chain.sync_all()?;
            if fault == Some(Stop::BeforeReturn) {
                return Err(required("unconsumed interrupted before return"));
            }
            observer();
            let strict = verify_closed_unconsumed_normal_chat_child_from_dir_fd(
                &child.root,
                &family,
                &context,
                &reservation,
            )?;
            if strict.chain_head() != proof.chain_head()
                || family.read_normal_chat_unconsumed_recovery_v1()?.as_ref() != Some(&record)
            {
                return Err(required("unconsumed source changed"));
            }
            let final_history = reconcile_family(
                &chain,
                &parent.root,
                &store,
                FamilyHistoryInputs {
                    family: &family,
                    context: &context,
                },
                None,
            )?;
            if final_history.snapshot.reservations != history.snapshot.reservations
                || final_history
                    .group(intent)
                    .and_then(|g| g.closed_index)
                    .is_none()
            {
                return Err(required("unconsumed family changed"));
            }
            history.recheck_closed(&family)?;
            final_history.recheck_closed(&family)?;
            checkpoint.check(&child.root)?;
            artifacts.require_locator_matches(&child.root)?;
            store.require_locator_matches(&parent.root)?;
            gate.check(&parent.root)?;
            parent.ensure_locator_matches()?;
            child.ensure_locator_matches()?;
            clock.check()?;
            Ok(RuntimeNormalChatUnconsumedRecoveredV1 {
                child_dir: child.locator.clone(),
                child_head: ContentDigest::from_hex(strict.chain_head())
                    .map_err(|_| required("invalid child head"))?,
                parent_head: chain.head().clone(),
                recovery: record,
            })
        })();
        let unlock = gate.unlock();
        match (result, unlock) {
            (Ok(v), Ok(())) => {
                parent.ensure_locator_matches()?;
                Ok(v)
            }
            (Err(e), _) | (Ok(_), Err(e)) => Err(e),
        }
    }
}
