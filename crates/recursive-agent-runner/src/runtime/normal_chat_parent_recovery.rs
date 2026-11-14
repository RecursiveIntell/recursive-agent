//! Startup-only narrowing adapter. The ledger owns source proof, marker derivation,
//! interrupted suffix recovery and final inventory verification; policy owns close.
use super::normal_chat_attempt::MonotonicClock;
use super::normal_chat_session::SessionGate;
use super::{RuntimeService, RuntimeServiceError};
use crate::PinnedRunRoot;
use recursive_agent_contracts::{content_digest, ContentDigest, CurrentRunId, RunTerminalStateV1};
use recursive_agent_ledger::{
    prepare_normal_chat_session_degradation_from_runtime_root_fd,
    recover_normal_chat_session_degradation_from_runtime_root_fd,
    verify_closed_normal_chat_family_from_runtime_root_fd,
    NormalChatSessionPublicationInterruptionV1,
};
use recursive_agent_policy::{
    DurablePermitStore, FamilyAuthorityStore, NormalChatSessionCloseInterruptionV2, PermitStateV1,
};
use std::os::unix::fs::MetadataExt;

fn required(reason: &'static str) -> RuntimeServiceError {
    RuntimeServiceError::NormalChatSessionRecoveryRequired { reason }
}
/// Negative-test interruption seams only; no caller-supplied source/state flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalChatParentRecoveryInterruptionV1 {
    Native(NormalChatSessionCloseInterruptionV2),
    AfterNative,
    Publication(NormalChatSessionPublicationInterruptionV1),
    BeforeReturn,
}
/// Immutable historical evidence, not Fresh authority or an all-calls-success claim.
///
/// ```compile_fail
/// use recursive_agent_runner::RuntimeNormalChatRecoveredSessionV1;
/// fn forge() -> RuntimeNormalChatRecoveredSessionV1 { RuntimeNormalChatRecoveredSessionV1 {} }
/// ```
/// ```compile_fail
/// use recursive_agent_runner::RuntimeNormalChatRecoveredSessionV1;
/// fn send(v: RuntimeNormalChatRecoveredSessionV1) { v.submit_child(); }
/// ```
pub struct RuntimeNormalChatRecoveredSessionV1 {
    run_id: CurrentRunId,
    head: ContentDigest,
    state: RunTerminalStateV1,
    attempts: usize,
    unknown: usize,
}
impl RuntimeNormalChatRecoveredSessionV1 {
    pub fn run_id(&self) -> &CurrentRunId {
        &self.run_id
    }
    pub fn chain_head(&self) -> &ContentDigest {
        &self.head
    }
    pub fn terminal_state(&self) -> RunTerminalStateV1 {
        self.state
    }
    pub fn attempt_count(&self) -> usize {
        self.attempts
    }
    pub fn unknown_attempt_count(&self) -> usize {
        self.unknown
    }
}
impl RuntimeService {
    /// Trusted startup setting, separate from grant enrollment and expired-child recovery.
    pub fn with_normal_chat_parent_recovery(mut self, enabled: bool) -> Self {
        self.normal_chat_parent_recovery_enabled = enabled;
        self
    }
    pub fn recover_normal_chat_session_parent(
        &self,
        run_id: &CurrentRunId,
    ) -> Result<RuntimeNormalChatRecoveredSessionV1, RuntimeServiceError> {
        self.recover_normal_chat_session_parent_with_observer(run_id, None, || {})
    }
    #[doc(hidden)]
    pub fn recover_normal_chat_session_parent_with_interruption(
        &self,
        run_id: &CurrentRunId,
        fault: Option<NormalChatParentRecoveryInterruptionV1>,
    ) -> Result<RuntimeNormalChatRecoveredSessionV1, RuntimeServiceError> {
        self.recover_normal_chat_session_parent_with_observer(run_id, fault, || {})
    }
    #[doc(hidden)]
    pub fn recover_normal_chat_session_parent_with_observer(
        &self,
        run_id: &CurrentRunId,
        fault: Option<NormalChatParentRecoveryInterruptionV1>,
        observer: impl FnOnce(),
    ) -> Result<RuntimeNormalChatRecoveredSessionV1, RuntimeServiceError> {
        use NormalChatParentRecoveryInterruptionV1 as Stop;
        if !self.normal_chat_parent_recovery_enabled {
            return Err(RuntimeServiceError::NormalChatParentRecoveryDisabled);
        }
        let output = crate::open_directory_tree(self.dependencies.output_root(), false)?;
        let output_meta = output.metadata()?;
        let check_output = || -> Result<(), RuntimeServiceError> {
            let now =
                crate::open_directory_tree(self.dependencies.output_root(), false)?.metadata()?;
            if (now.dev(), now.ino()) != (output_meta.dev(), output_meta.ino()) {
                return Err(required("parent recovery output locator changed"));
            }
            Ok(())
        };
        let parent = PinnedRunRoot::open_existing(
            self.dependencies.output_root(),
            &content_digest(run_id)?.to_string(),
        )?;
        let root = &parent.root;
        let gate = SessionGate::acquire_existing(root)?;
        let clock = MonotonicClock::new_lazy(self.dependencies.clock());
        let result = (|| {
            parent.ensure_locator_matches()?;
            check_output()?;
            gate.check(root)?;
            let policy = DurablePermitStore::require_existing_from_run_root_fd(root)?;
            let record = policy
                .read_normal_chat_session_control_record()?
                .ok_or_else(|| required("parent recovery native root absent"))?;
            if record.permit.binding.run_id != *run_id {
                return Err(required("parent recovery native run differs"));
            }
            let new_close = matches!(record.state, PermitStateV1::Issued);
            let mut closed_pair = None;
            let mut child_heads = None;
            if new_close {
                // Pristine family proof refuses a suffix contradicting an Issued root.
                // Historical context is retained evidence, never today's grant.
                let proof = verify_closed_normal_chat_family_from_runtime_root_fd(&output, run_id)?;
                if proof.native_root_record() != &record
                    || (proof.unknown_child_count() == 0 && proof.interrupted_child_count() == 0)
                {
                    return Err(required(
                        "parent recovery requires genuine closed unknown family",
                    ));
                }
                let context = proof.context();
                let family = FamilyAuthorityStore::require_existing_from_dir_fd(
                    root,
                    context.session_family_grant_v2()?,
                )?;
                // Every child's terminal valid time bounds its source/preflight/native
                // terminal times. Native close additionally checks reservations, prior
                // cancellation, issuance/not-before, opened_at and closed_at itself.
                let floor = proof
                    .children()
                    .iter()
                    .fold(record.permit.binding.issued_at, |at, child| {
                        std::cmp::max(at, child.terminal_receipt().valid_time)
                    });
                let at = clock.sample();
                clock.check()?;
                if at < floor {
                    return Err(required("parent recovery clock precedes complete history"));
                }
                // A trusted clock is a callback too: recheck before changing authority.
                proof.recheck()?;
                check_output()?;
                parent.ensure_locator_matches()?;
                gate.check(root)?;
                let native = policy.close_normal_chat_session_v2_with_interruption(
                    &family,
                    context,
                    proof.native_snapshot(),
                    floor,
                    || clock.sample(),
                    match fault {
                        Some(Stop::Native(point)) => Some(point),
                        _ => None,
                    },
                )?;
                clock.check()?;
                child_heads = Some(
                    proof
                        .children()
                        .iter()
                        .map(|c| (c.run_id().clone(), c.chain_head().to_owned()))
                        .collect::<Vec<_>>(),
                );
                closed_pair = Some((family, context.clone(), native));
            } else if !matches!(record.state, PermitStateV1::Revoked { .. }) {
                return Err(required(
                    "parent recovery native root is not issued/revoked",
                ));
            }
            if fault == Some(Stop::AfterNative) {
                return Err(required("parent recovery interrupted after native close"));
            }
            check_output()?;
            parent.ensure_locator_matches()?;
            gate.check(root)?;
            if let Some((family, context, native)) = &closed_pair {
                policy.confirm_closed_normal_chat_session_v2(family, context, native)?;
            }
            if let Some(Stop::Publication(point)) = fault {
                // Exercise the publication owner's actual crash boundaries. Production
                // always uses explicit recovery, including for pristine closed pairs.
                prepare_normal_chat_session_degradation_from_runtime_root_fd(
                    &output,
                    run_id,
                    gate.ledger_guard(),
                )
                .map_err(|_| required("parent recovery preparation refused"))?
                .publish_with_interruption(Some(point))
                .map_err(|_| required("parent recovery publication interrupted"))?;
            }
            // No generic append/open reader before this scoped ingress for an
            // already-revoked root: marker/torn suffix belong exclusively here.
            let proof = recover_normal_chat_session_degradation_from_runtime_root_fd(
                &output,
                run_id,
                gate.ledger_guard(),
            )
            .map_err(|_| required("parent recovery source/publication requires quarantine"))?;
            if fault == Some(Stop::BeforeReturn) {
                return Err(required("parent recovery interrupted before return"));
            }
            observer();
            if new_close {
                clock.sample();
                clock.check()?;
            }
            // NONCREATING checks only after observer/final clock. Never re-close a
            // downgraded native pair in order to make it match a published suffix.
            proof
                .recheck()
                .map_err(|_| required("parent recovery final source proof changed"))?;
            if let Some((family, context, native)) = &closed_pair {
                policy.confirm_closed_normal_chat_session_v2(family, context, native)?;
            }
            if let Some(expected) = child_heads {
                let actual = proof
                    .marker()
                    .children
                    .iter()
                    .map(|c| (c.child_run_id.clone(), c.child_chain_head.to_string()))
                    .collect::<Vec<_>>();
                if actual != expected {
                    return Err(required("parent recovery original child heads changed"));
                }
            }
            check_output()?;
            gate.check(root)?;
            parent.ensure_locator_matches()?;
            Ok(RuntimeNormalChatRecoveredSessionV1 {
                run_id: run_id.clone(),
                head: ContentDigest::from_hex(proof.chain_head())
                    .map_err(|_| required("parent recovery invalid verified head"))?,
                state: proof.terminal_state(),
                attempts: proof.child_count(),
                unknown: proof.unknown_child_count(),
            })
        })();
        let unlock = gate.unlock();
        match (result, unlock) {
            (Ok(value), Ok(())) => {
                check_output()?;
                parent.ensure_locator_matches()?;
                Ok(value)
            }
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }
}
