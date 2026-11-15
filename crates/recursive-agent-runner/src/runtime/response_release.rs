//! The final local response boundary consumes fresh ownership. It is not a
//! status-to-authority conversion and performs no provider request.
use super::super::normal_chat_terminal::{describe_all, preflight_payloads, verify_preflight};
use super::*;
use recursive_agent_contracts::CurrentPermitId;
use recursive_agent_policy::PolicyError;
use std::time::Instant;

/// Immutable metadata borrowed only during synchronous fenced publication.
/// It cannot be constructed, cloned or decoded into a fresh transition.
pub struct RuntimeNormalChatDispatchV2 {
    attempt: NormalChatAttemptV2,
    permit_id: CurrentPermitId,
    preflight: ContentDigest,
    expires_at: DateTime<Utc>,
    admitted_at: DateTime<Utc>,
    deadline: Instant,
    parent_head: ContentDigest,
    child_head: ContentDigest,
}
impl RuntimeNormalChatDispatchV2 {
    pub fn attempt(&self) -> &NormalChatAttemptV2 {
        &self.attempt
    }
    pub fn permit_id(&self) -> &CurrentPermitId {
        &self.permit_id
    }
    pub fn preflight_digest(&self) -> &ContentDigest {
        &self.preflight
    }
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    pub fn admitted_at(&self) -> DateTime<Utc> {
        self.admitted_at
    }
    /// Absolute monotonic deadline; validation/serialization/write share it.
    pub fn publication_deadline(&self) -> Instant {
        self.deadline
    }
    pub fn parent_chain_head(&self) -> &ContentDigest {
        &self.parent_head
    }
    pub fn child_chain_head(&self) -> &ContentDigest {
        &self.child_head
    }
}

impl RuntimeService {
    /// The trusted sink MUST finish bounded synchronous publication here. It
    /// must not enqueue work, return a future, or re-enter policy/ledger owners.
    /// Delivery failure never returns fresh ownership, refunds, or permits retry.
    pub fn release_normal_chat_attempt(
        &self,
        fresh: RuntimeNormalChatFreshV2,
        deliver: impl FnOnce(&RuntimeNormalChatDispatchV2) -> std::io::Result<()>,
    ) -> Result<(), RuntimeServiceError> {
        self.release_normal_chat_attempt_with_observer(fresh, || {}, deliver)
    }

    #[doc(hidden)]
    pub fn release_normal_chat_attempt_with_observer(
        &self,
        fresh: RuntimeNormalChatFreshV2,
        observer: impl FnOnce(),
        deliver: impl FnOnce(&RuntimeNormalChatDispatchV2) -> std::io::Result<()>,
    ) -> Result<(), RuntimeServiceError> {
        let authority = self
            .normal_chat_grant
            .as_ref()
            .ok_or(RuntimeServiceError::NormalChatGovernanceDisabled)?;
        // Anchor BEFORE the clock sample: never restart remaining lease after
        // expensive verification or serialization and never trust a stale delta.
        let anchor = Instant::now();
        let clock = MonotonicClock::new(self.dependencies.clock());
        let sampled = clock
            .last
            .get()
            .ok_or_else(|| recovery("response release clock absent"))?;
        if sampled < fresh.release_floor {
            return Err(recovery("response clock precedes original Begin floor"));
        }
        let remaining = (fresh.expires_at() - sampled)
            .to_std()
            .map_err(|_| recovery("response release original lease expired"))?;
        let deadline = anchor
            .checked_add(remaining)
            .ok_or_else(|| recovery("response release deadline overflow"))?;
        let pinned_root = fresh._parent.root.try_clone()?;
        let root = &pinned_root;
        let gate = SessionGate::acquire_existing(root)?;
        let result = (|| {
            let proof = fresh.consumption.ledger_evidence()?;
            let request = NormalChatCallRequestV2::from_attempt(fresh.attempt())?;
            recursive_agent_ledger::read_only_appendable_snapshot_expected_run_from_dir_fd(
                root,
                &proof.admission.context.session.run_id()?,
            )?;
            recursive_agent_ledger::read_only_appendable_snapshot_expected_run_from_dir_fd(
                &fresh.child.root,
                &fresh.attempt().run_id()?,
            )?;
            let chain = recursive_agent_ledger::open_existing_from_dir_fd(
                &RunPaths::new(&fresh._parent.locator),
                root,
            )?;
            let store = chain.artifact_store()?;
            let child_store = ArtifactStore::from_run_root_fd(&fresh.child.root, false)?;
            let family = FamilyAuthorityStore::require_existing_from_dir_fd(
                root,
                proof.admission.context.session_family_grant_v2()?,
            )?;
            let inputs = FamilyHistoryInputs {
                family: &family,
                context: &proof.admission.context,
            };
            let descriptors = describe_all(&preflight_payloads(&proof)?)?;
            let validate = || -> Result<(), RuntimeServiceError> {
                gate.check(root)?;
                recursive_agent_ledger::read_only_appendable_snapshot_expected_run_from_dir_fd(
                    root,
                    &proof.admission.context.session.run_id()?,
                )?;
                recursive_agent_ledger::read_only_appendable_snapshot_expected_run_from_dir_fd(
                    &fresh.child.root,
                    &fresh.attempt().run_id()?,
                )?;
                fresh._parent.ensure_locator_matches()?;
                fresh.child.ensure_locator_matches()?;
                store.require_locator_matches(root)?;
                child_store.require_locator_matches(&fresh.child.root)?;
                if verify_parent_attempt(
                    &chain,
                    root,
                    &store,
                    &request,
                    &proof.admission.reservation,
                    inputs,
                )? != fresh.parent_head
                {
                    return Err(recovery("response release parent evidence changed"));
                }
                let child = appendable_snapshot_expected_run_from_dir_fd(
                    &fresh.child.root,
                    &fresh.attempt().run_id()?,
                )?;
                if child.receipts().len() != 7
                    || child.verification().final_head != fresh.child_head.to_string()
                {
                    return Err(recovery("response release child head changed"));
                }
                verify_preflight(&fresh.child.root, &proof, &descriptors)?;
                child_store.require_exact_inventory(&descriptors)?;
                fresh._history.recheck_closed(&family)?;
                if family.read_normal_chat_session_snapshot_v2()? != fresh._history.snapshot {
                    return Err(recovery("response release family snapshot changed"));
                }
                Ok(())
            };
            validate()?;
            observer();
            validate()?;
            clock.sample();
            clock.check()?;
            if Instant::now() >= deadline {
                return Err(recovery(
                    "response publication deadline consumed before fence",
                ));
            }
            let dispatch = RuntimeNormalChatDispatchV2 {
                attempt: fresh.attempt().clone(),
                permit_id: fresh.consumption.effect_permit().permit_id.clone(),
                preflight: fresh.preflight_digest().clone(),
                expires_at: fresh.expires_at(),
                admitted_at: sampled,
                deadline,
                parent_head: fresh.parent_head.clone(),
                child_head: fresh.child_head.clone(),
            };
            fresh.consumption.publish_runtime_response_v2(
                authority,
                &fresh._family,
                clock
                    .last
                    .get()
                    .ok_or_else(|| recovery("response release final clock floor absent"))?,
                &fresh._history.snapshot,
                || clock.sample(),
                |now| {
                    if Instant::now() >= deadline {
                        return Err(PolicyError::Io(std::io::ErrorKind::TimedOut.into()));
                    }
                    let dispatch = RuntimeNormalChatDispatchV2 {
                        admitted_at: now,
                        ..dispatch
                    };
                    // No native/ledger readers inside the native lock graph.
                    deliver(&dispatch).map_err(PolicyError::Io)?;
                    if Instant::now() >= deadline {
                        return Err(PolicyError::Io(std::io::ErrorKind::TimedOut.into()));
                    }
                    Ok(())
                },
            )?;
            clock.check()?;
            Ok(())
        })();
        let unlock = gate.unlock();
        match (result, unlock) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), _) | (Ok(()), Err(error)) => Err(error),
        }
    }
}
