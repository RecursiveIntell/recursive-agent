//! Serial-attempt cross-store barrier. Every prior child must be reconciled
//! before a new intent can consume authority. Existing/partial state is never
//! upgraded into a fresh continuation. This module performs no provider call;
//! daemon response release is a separate gate.
#[path = "response_release.rs"]
mod response_release;
use super::normal_chat_family_history::{
    reconcile_family, FamilyHistoryInputs, ReconciledFamilyV2,
};
use super::normal_chat_session::{verify_bootstrap_prefix, SessionGate};
use super::{RuntimeNormalChatSessionV1, RuntimeService, RuntimeServiceError};
use crate::PinnedRunRoot;
use chrono::{DateTime, Utc};
use recursive_agent_contracts::{
    content_digest, jcs_canonical, ArtifactDescriptorV1, ContentDigest, NormalChatAttemptV2,
    NormalChatCallRequestV2, ReceiptKindV1, ReceiptOutcomeV1, ReceiptV1,
};
use recursive_agent_ledger::{
    appendable_snapshot_expected_run_from_dir_fd, make_receipt, open_from_dir_fd, AppendStage,
    ArtifactStore, ChainHandle, ChildRunLinkV1, ReceiptDraftV1, RunPaths,
};
use recursive_agent_policy::{
    build_lineage, DurablePermitStore, FamilyAuthorityStore, NormalChatAttemptBeginV2,
    NormalChatAttemptConsumptionV2, NormalChatAttemptReadbackV2, NormalChatControlledFamilyV1,
    NormalChatFamilyReservationRequestV2, NormalChatFamilyReservationV2, NormalChatGrantContextV2,
    PermitEvidenceV1,
};
pub use response_release::RuntimeNormalChatDispatchV2;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::Path;

fn recovery(reason: &'static str) -> RuntimeServiceError {
    RuntimeServiceError::NormalChatSessionRecoveryRequired { reason }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalChatAttemptInterruptionV2 {
    AfterRequestArtifact,
    AfterPreparation,
    AfterReservation,
    AfterLinkArtifact,
    AfterLink,
    AfterPolicyConsume,
    PreflightArtifact {
        ordinal: usize,
    },
    Policy(recursive_agent_policy::NormalChatBeginInterruptionV2),
    /// Test-only attenuation of the metadata ceiling; can only force rejection.
    MetadataCapacity,
    ChildReceipt {
        ordinal: usize,
        stage: AppendStage,
    },
    BeforeRelease,
}
fn stop(
    selected: Option<NormalChatAttemptInterruptionV2>,
    point: NormalChatAttemptInterruptionV2,
) -> Result<(), RuntimeServiceError> {
    if selected == Some(point) {
        return Err(recovery("normal-chat attempt interrupted"));
    }
    Ok(())
}
/// Historical correlation only. Even Consumed does NOT authorize a send.
pub struct RuntimeNormalChatExistingV2 {
    pub reservation: NormalChatFamilyReservationV2,
    pub child_policy: Option<NormalChatAttemptReadbackV2>,
}
pub enum RuntimeNormalChatBeginV2 {
    Fresh(Box<RuntimeNormalChatFreshV2>),
    Existing(Box<RuntimeNormalChatExistingV2>),
}
/// Owns the unique fresh native transition; no constructor from evidence/status.
/// This is not an IPC response, terminal run, or permission to bypass transport
/// conformance. Daemon response release must later CONSUME this handle.
///
/// ```compile_fail
/// use recursive_agent_runner::RuntimeNormalChatFreshV2;
/// fn duplicate(cap: RuntimeNormalChatFreshV2) { let _ = cap.clone(); }
/// ```
/// ```compile_fail
/// use recursive_agent_runner::RuntimeNormalChatFreshV2;
/// let _: RuntimeNormalChatFreshV2 = serde_json::from_str("{}").unwrap();
/// ```
pub struct RuntimeNormalChatFreshV2 {
    consumption: NormalChatAttemptConsumptionV2,
    child: PinnedRunRoot,
    _parent: PinnedRunRoot,
    _family: NormalChatControlledFamilyV1,
    _history: ReconciledFamilyV2,
    parent_head: ContentDigest,
    child_head: ContentDigest,
    release_floor: DateTime<Utc>,
}
impl RuntimeNormalChatFreshV2 {
    pub fn attempt(&self) -> &NormalChatAttemptV2 {
        self.consumption.attempt()
    }
    pub fn child_run_dir(&self) -> &Path {
        &self.child.locator
    }
    pub fn parent_chain_head(&self) -> &ContentDigest {
        &self.parent_head
    }
    pub fn child_chain_head(&self) -> &ContentDigest {
        &self.child_head
    }
    pub fn preflight_digest(&self) -> &ContentDigest {
        &self.consumption.preflight().receipt_digest
    }
    /// Original reservation lease, never a fresh timeout at response time.
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.consumption.effect_permit().binding.expires_at
    }
}
/// A retained native root cause is semantic history, even if its ledger
/// projection has not yet been appended. New observations cannot precede it.
pub(super) fn retained_root_floor(
    record: &recursive_agent_policy::PermitRecordV1,
    floor: DateTime<Utc>,
) -> DateTime<Utc> {
    match record.state {
        recursive_agent_policy::PermitStateV1::Revoked { revoked_at, .. } => {
            std::cmp::max(floor, revoked_at)
        }
        _ => floor,
    }
}
pub(super) struct MonotonicClock<'a> {
    clock: &'a dyn crate::Clock,
    last: Cell<Option<DateTime<Utc>>>,
    regressed: Cell<bool>,
}
impl<'a> MonotonicClock<'a> {
    pub(super) fn new(clock: &'a dyn crate::Clock) -> Self {
        Self {
            clock,
            last: Cell::new(Some(clock.now())),
            regressed: Cell::new(false),
        }
    }
    /// Historical paths must not read a clock until a new native transition.
    /// Existing callers retain the eager constructor's original behavior.
    pub(super) fn new_lazy(clock: &'a dyn crate::Clock) -> Self {
        Self {
            clock,
            last: Cell::new(None),
            regressed: Cell::new(false),
        }
    }
    pub(super) fn sample(&self) -> DateTime<Utc> {
        let now = self.clock.now();
        if self.last.get().is_some_and(|last| now < last) {
            self.regressed.set(true);
        }
        self.last.set(Some(now));
        now
    }
    pub(super) fn check(&self) -> Result<(), RuntimeServiceError> {
        if self.regressed.get() {
            return Err(recovery("trusted runtime clock regressed"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod clock_contract {
    use super::*;
    struct Count(std::sync::atomic::AtomicI64);
    impl crate::Clock for Count {
        fn now(&self) -> DateTime<Utc> {
            DateTime::<Utc>::UNIX_EPOCH
                + chrono::TimeDelta::milliseconds(
                    self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                )
        }
    }
    #[test]
    fn lazy_clock_does_not_change_eager_sampling_or_regression_detection(
    ) -> Result<(), RuntimeServiceError> {
        let eager = Count(std::sync::atomic::AtomicI64::new(0));
        let old = MonotonicClock::new(&eager);
        assert_eq!(eager.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(old.last.get(), Some(DateTime::<Utc>::UNIX_EPOCH));
        let lazy = Count(std::sync::atomic::AtomicI64::new(0));
        let historical = MonotonicClock::new_lazy(&lazy);
        assert_eq!(lazy.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(historical.last.get(), None);
        historical.check()?;
        historical.sample();
        assert_eq!(lazy.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        lazy.0.store(-1, std::sync::atomic::Ordering::SeqCst);
        historical.sample();
        assert!(historical.check().is_err());
        Ok(())
    }
}

impl RuntimeService {
    pub fn begin_normal_chat_attempt(
        &self,
        session: &RuntimeNormalChatSessionV1,
        request: &NormalChatCallRequestV2,
    ) -> Result<RuntimeNormalChatBeginV2, RuntimeServiceError> {
        self.begin_normal_chat_attempt_with_interruption(session, request, None)
    }
    #[doc(hidden)]
    pub fn begin_normal_chat_attempt_with_interruption(
        &self,
        session: &RuntimeNormalChatSessionV1,
        request: &NormalChatCallRequestV2,
        interruption: Option<NormalChatAttemptInterruptionV2>,
    ) -> Result<RuntimeNormalChatBeginV2, RuntimeServiceError> {
        self.begin_normal_chat_attempt_with_observer(session, request, interruption, || {})
    }

    /// Deterministic negative-test seam immediately before the final policy
    /// fence. It cannot grant authority or skip any release validation.
    #[doc(hidden)]
    pub fn begin_normal_chat_attempt_with_observer(
        &self,
        session: &RuntimeNormalChatSessionV1,
        request: &NormalChatCallRequestV2,
        interruption: Option<NormalChatAttemptInterruptionV2>,
        before_release: impl FnOnce(),
    ) -> Result<RuntimeNormalChatBeginV2, RuntimeServiceError> {
        request.validate()?;
        if request.operation.parent_run_id != session.run_id
            || request.operation.conversation_ref != session.session.conversation_ref
            || self.run_paths(&session.run_id)?.root != session.pinned.locator
        {
            return Err(recovery("call request does not bind runtime session/root"));
        }
        if matches!(
            interruption,
            Some(
                NormalChatAttemptInterruptionV2::ChildReceipt { ordinal: 7.., .. }
                    | NormalChatAttemptInterruptionV2::PreflightArtifact { ordinal: 4.. }
                    | NormalChatAttemptInterruptionV2::ChildReceipt {
                        stage: AppendStage::ArtifactWrite,
                        ..
                    }
            )
        ) {
            return Err(recovery("invalid child interruption selection"));
        }
        let clock = MonotonicClock::new(self.dependencies.clock());
        session.pinned.ensure_locator_matches()?;
        let gate = SessionGate::acquire(&session.pinned.root)?;
        let result = self.begin_normal_chat_attempt_locked(
            session,
            request,
            &gate,
            &clock,
            (interruption, before_release),
        );
        let unlock = gate.unlock();
        let value = match (result, unlock) {
            (Ok(value), Ok(())) => value,
            (Err(error), _) | (Ok(_), Err(error)) => return Err(error),
        };
        clock.check()?;
        session.pinned.ensure_locator_matches()?;
        Ok(value)
    }

    fn begin_normal_chat_attempt_locked(
        &self,
        session: &RuntimeNormalChatSessionV1,
        request: &NormalChatCallRequestV2,
        gate: &SessionGate,
        clock: &MonotonicClock<'_>,
        fault: (Option<NormalChatAttemptInterruptionV2>, impl FnOnce()),
    ) -> Result<RuntimeNormalChatBeginV2, RuntimeServiceError> {
        let (interruption, before_release) = fault;
        let authority = self
            .normal_chat_grant
            .as_ref()
            .ok_or(RuntimeServiceError::NormalChatGovernanceDisabled)?;
        let root = &session.pinned.root;
        let mut parent = open_from_dir_fd(&RunPaths::new(&session.pinned.locator), root)?;
        let parent_store = parent.artifact_store()?;
        let (permits, historical_family, record) =
            require_parent_history(authority, session, &parent, &parent_store)?;
        let context = NormalChatGrantContextV2 {
            grant: authority.grant().clone(),
            session: session.session.clone(),
            root_control: record.permit.clone(),
        };
        let inputs = FamilyHistoryInputs {
            family: &historical_family,
            context: &context,
        };
        let history = reconcile_family(&parent, root, &parent_store, inputs, None)?;
        let family_snapshot = &history.snapshot;
        if let Some(existing) = history.group(&request.dispatch_intent_ref) {
            if existing.request != *request {
                return Err(recovery(
                    "existing intent conflicts with exact canonical request",
                ));
            }
            history.recheck_closed(&historical_family)?;
            gate.check(root)?;
            session.pinned.ensure_locator_matches()?;
            return Ok(RuntimeNormalChatBeginV2::Existing(Box::new(
                RuntimeNormalChatExistingV2 {
                    reservation: existing.reservation.clone(),
                    child_policy: Some(existing.child_policy.clone()),
                },
            )));
        }
        history.require_ready()?;
        if clock.sample() < history.floor {
            return Err(recovery(
                "new call clock precedes reconciled semantic history",
            ));
        }
        clock.check()?;
        let control = permits.require_existing_normal_chat_session_control(
            authority,
            &session.session.conversation_ref,
            None,
            &record,
            || clock.sample(),
        )?;
        let family = FamilyAuthorityStore::require_existing_normal_chat_session_family(
            root,
            authority,
            &control,
            || clock.sample(),
        )?;
        if family_snapshot.admission.closed_at.is_some()
            || family_snapshot.admission.parent_revoked_at.is_some()
        {
            return Err(recovery("family admission is closed"));
        }
        // Same native accounting evaluator as the real atomic reservation;
        // this read check allocates nothing and returns no preview authority.
        family.check_new_normal_chat_call(authority, request, || clock.sample())?;
        clock.check()?;
        let preparation = request.preparation_digest()?;
        let request_artifact =
            parent_store.put(&jcs_canonical(request)?, "application/json", None)?;
        stop(
            interruption,
            NormalChatAttemptInterruptionV2::AfterRequestArtifact,
        )?;
        clock.check()?;
        let admission = append_parent(
            &mut parent,
            &record,
            ReceiptKindV1::ChildAdmissionPrepared,
            &preparation,
            &preparation,
            vec![],
            clock.sample(),
        )?;
        let reread = appendable_snapshot_expected_run_from_dir_fd(root, &session.run_id)?;
        if parent_store.get(&request_artifact)? != jcs_canonical(request)?
            || reread.receipts().last() != Some(&admission)
        {
            return Err(recovery("preparation did not survive exact readback"));
        }
        stop(
            interruption,
            NormalChatAttemptInterruptionV2::AfterPreparation,
        )?;
        let reservation_request = NormalChatFamilyReservationRequestV2::from_prepared_call(
            request,
            admission.receipt_id,
        )?;
        let reservation =
            family
                .reserve_normal_chat_attempt(authority, &reservation_request, || clock.sample())?;
        stop(
            interruption,
            NormalChatAttemptInterruptionV2::AfterReservation,
        )?;
        let link = expected_link(&reservation)?;
        let link_artifact = parent_store.put(&jcs_canonical(&link)?, "application/json", None)?;
        stop(
            interruption,
            NormalChatAttemptInterruptionV2::AfterLinkArtifact,
        )?;
        append_parent(
            &mut parent,
            &record,
            ReceiptKindV1::ChildLinked,
            &link.child_envelope_digest,
            &preparation,
            vec![link_artifact],
            clock.sample(),
        )?;
        stop(interruption, NormalChatAttemptInterruptionV2::AfterLink)?;
        family.mark_normal_chat_child_root_started_v1(
            authority,
            &request.dispatch_intent_ref,
            || clock.sample(),
        )?;
        clock.check()?;
        let child_id = reservation.attempt.run_id()?;
        let child = PinnedRunRoot::open(
            self.dependencies.output_root(),
            &content_digest(&child_id)?.to_string(),
        )?;
        child.ensure_locator_matches()?;
        let mut child_chain = open_from_dir_fd(&RunPaths::new(&child.locator), &child.root)?;
        let artifacts = child_chain.artifact_store()?;
        if child_chain.length() != 0 {
            return Err(recovery("fresh child already has ledger history"));
        }
        artifacts.require_exact_inventory(&[])?;
        child_chain.initialize_empty_receipt_log()?;
        let child_permits = DurablePermitStore::from_run_root_fd(&child.root)?;
        family.checkpoint_normal_chat_child_storage_v1(
            &request.dispatch_intent_ref,
            &child.root,
            clock.sample(),
        )?;
        clock.check()?;
        verify_parent_attempt(&parent, root, &parent_store, request, &reservation, inputs)?;
        let consumption = match child_permits.begin_normal_chat_attempt_v2_with_interruption(
            authority,
            &family,
            &request.dispatch_intent_ref,
            || clock.sample(),
            match interruption {
                Some(NormalChatAttemptInterruptionV2::Policy(stage)) => Some(stage),
                _ => None,
            },
        )? {
            NormalChatAttemptBeginV2::Consumed(value) => *value,
            NormalChatAttemptBeginV2::Existing(_) => {
                return Err(recovery(
                    "fresh child has retained policy; status cannot resume send",
                ))
            }
        };
        stop(
            interruption,
            NormalChatAttemptInterruptionV2::AfterPolicyConsume,
        )?;
        let proof = consumption.ledger_evidence()?;
        let control_evidence = proof.control_evidence()?;
        let effect_issued = proof.issued_effect_evidence()?;
        let payloads = [
            jcs_canonical(&control_evidence)?,
            jcs_canonical(&proof)?,
            jcs_canonical(&effect_issued)?,
            jcs_canonical(&proof.preflight.evidence)?,
        ];
        let ceiling = if interruption == Some(NormalChatAttemptInterruptionV2::MetadataCapacity) {
            METADATA_TERMINAL_HEADROOM
        } else {
            reservation
                .child_control
                .request
                .requested_budget
                .max_artifact_bytes
        };
        require_metadata_capacity(&payloads, ceiling)?;
        let mut descriptors = Vec::new();
        for (ordinal, payload) in payloads.iter().enumerate() {
            descriptors.push(artifacts.put(payload, "application/json", None)?);
            stop(
                interruption,
                NormalChatAttemptInterruptionV2::PreflightArtifact { ordinal },
            )?;
        }
        let rows = preflight_rows(
            &control_evidence,
            &effect_issued,
            &proof.preflight.evidence,
            proof.preflight.recorded_at,
            &descriptors,
        );
        for (ordinal, draft) in rows.into_iter().enumerate() {
            let receipt = make_receipt(draft, child_chain.head().clone())?;
            let stage = match interruption {
                Some(NormalChatAttemptInterruptionV2::ChildReceipt {
                    ordinal: selected,
                    stage,
                }) if selected == ordinal => Some(stage),
                _ => None,
            };
            child_chain.append_with_interruption(receipt, stage)?;
        }
        child_chain.sync_all()?;
        parent.sync_all()?;
        crate::open_directory_tree(self.dependencies.output_root(), false)?.sync_all()?;
        let parent_head =
            verify_parent_attempt(&parent, root, &parent_store, request, &reservation, inputs)?;
        let snapshot = appendable_snapshot_expected_run_from_dir_fd(&child.root, &child_id)?;
        if snapshot.receipts().len() != 7
            || snapshot.verification().final_head != child_chain.head().to_string()
        {
            return Err(recovery(
                "child preflight differs from exact seven-receipt prefix",
            ));
        }
        for (expected, actual) in preflight_rows(
            &control_evidence,
            &effect_issued,
            &proof.preflight.evidence,
            proof.preflight.recorded_at,
            &descriptors,
        )
        .into_iter()
        .zip(snapshot.receipts())
        {
            let mut expected = make_receipt(expected, actual.prev_chain_digest.clone())?;
            expected.recorded_time = actual.recorded_time;
            if expected.canonical_bytes()? != actual.canonical_bytes()? {
                return Err(recovery("child preflight draft mismatch"));
            }
        }
        artifacts.require_exact_inventory(&descriptors)?;
        let final_history = reconcile_family(&parent, root, &parent_store, inputs, None)?;
        let final_family = &final_history.snapshot;
        let mut expected = history.snapshot.reservations.clone();
        expected.push(reservation.clone());
        // Canonical policy snapshot is keyed by intent; this sorts SET equality
        // only. Parent receipt order above remains the sole call chronology.
        expected.sort_by(|a, b| {
            a.attempt
                .dispatch_intent_ref
                .cmp(&b.attempt.dispatch_intent_ref)
        });
        if final_family.reservations != expected {
            return Err(recovery("complete family reservation set changed"));
        }
        stop(interruption, NormalChatAttemptInterruptionV2::BeforeRelease)?;
        before_release();
        history.recheck_closed(&historical_family)?;
        final_history.recheck_closed(&historical_family)?;
        // Canonical normal-chat runtime writers MUST share this session gate.
        // Ledger locks are short-lived per operation, not retained by a handle.
        // These checks reject locator substitution; they do not prevent arbitrary
        // same-UID store rewriting or other code bypassing the owner/gate.
        parent_store.require_locator_matches(root)?;
        artifacts.require_locator_matches(&child.root)?;
        if verify_parent_attempt(&parent, root, &parent_store, request, &reservation, inputs)?
            != parent_head
        {
            return Err(recovery("parent changed at release"));
        }
        let late_child = appendable_snapshot_expected_run_from_dir_fd(&child.root, &child_id)?;
        if late_child.receipts().len() != 7
            || late_child.verification().final_head != child_chain.head().to_string()
        {
            return Err(recovery("child changed at release"));
        }
        artifacts.require_exact_inventory(&descriptors)?;
        clock.sample();
        clock.check()?;
        gate.check(root)?;
        child.ensure_locator_matches()?;
        session.pinned.ensure_locator_matches()?;
        let floor = clock
            .last
            .get()
            .ok_or_else(|| recovery("fresh release has no trusted clock sample"))?;
        let consumption = consumption.check_runtime_release_v2(
            authority,
            &family,
            floor,
            final_family,
            || clock.sample(),
        )?;
        clock.check()?;
        history.recheck_closed(&historical_family)?;
        final_history.recheck_closed(&historical_family)?;
        gate.check(root)?;
        child.ensure_locator_matches()?;
        session.pinned.ensure_locator_matches()?;
        parent_store.require_locator_matches(root)?;
        artifacts.require_locator_matches(&child.root)?;
        Ok(RuntimeNormalChatBeginV2::Fresh(Box::new(
            RuntimeNormalChatFreshV2 {
                consumption,
                child,
                _parent: PinnedRunRoot {
                    locator: session.pinned.locator.clone(),
                    root: root.try_clone()?,
                    identity: session.pinned.identity,
                },
                _family: family,
                _history: final_history,
                parent_head,
                child_head: child_chain.head().clone(),
                release_floor: clock
                    .last
                    .get()
                    .ok_or_else(|| recovery("fresh response floor absent"))?,
            },
        )))
    }
}

/// Validate current-grant caller history without issuing or renewing authority.
pub(super) fn require_parent_history(
    authority: &recursive_agent_policy::NormalChatGrantAuthorityV1,
    session: &RuntimeNormalChatSessionV1,
    parent: &ChainHandle,
    store: &ArtifactStore,
) -> Result<
    (
        DurablePermitStore,
        FamilyAuthorityStore,
        recursive_agent_policy::PermitRecordV1,
    ),
    RuntimeServiceError,
> {
    let root = &session.pinned.root;
    let record = DurablePermitStore::require_existing_from_run_root_fd(root)?
        .read_normal_chat_session_control_record()?
        .ok_or_else(|| recovery("session control absent"))?;
    let context = NormalChatGrantContextV2 {
        grant: authority.grant().clone(),
        session: session.session.clone(),
        root_control: record.permit,
    };
    require_parent_history_context(&context, root, &session.run_id, parent, store)
}

/// Historical context is identity/correlation, never current grant authority.
/// Only require-existing owners and original bootstrap evidence are admitted.
pub(super) fn require_parent_history_context(
    context: &NormalChatGrantContextV2,
    root: &std::fs::File,
    run_id: &recursive_agent_contracts::CurrentRunId,
    parent: &ChainHandle,
    store: &ArtifactStore,
) -> Result<
    (
        DurablePermitStore,
        FamilyAuthorityStore,
        recursive_agent_policy::PermitRecordV1,
    ),
    RuntimeServiceError,
> {
    if context.session.run_id()? != *run_id {
        return Err(recovery(
            "historical context has a different session identity",
        ));
    }
    let snapshot = appendable_snapshot_expected_run_from_dir_fd(root, run_id)?;
    if snapshot.receipts().len() < 3
        || snapshot.verification().final_head != parent.head().to_string()
    {
        return Err(recovery(
            "session bootstrap prefix/head is incomplete or changed",
        ));
    }
    let permits = DurablePermitStore::require_existing_from_run_root_fd(root)?;
    let record = permits
        .read_normal_chat_session_control_record()?
        .ok_or_else(|| recovery("session control absent"))?;
    let original = context.session_root_issued_record_v2()?;
    let mut retained = original.clone();
    retained.state = record.state.clone();
    if retained != record {
        return Err(recovery(
            "historical context differs from the exact native root record",
        ));
    }
    let identity = snapshot.receipts()[0]
        .artifact_refs
        .first()
        .ok_or_else(|| recovery("session identity artifact absent"))?;
    let issued = snapshot.receipts()[2]
        .artifact_refs
        .first()
        .ok_or_else(|| recovery("session control artifact absent"))?;
    if store.get(identity)? != jcs_canonical(&context.session)?
        || store.get(issued)? != jcs_canonical(&PermitEvidenceV1::from_record(&original)?)?
    {
        return Err(recovery("session original identity/evidence differs"));
    }
    verify_bootstrap_prefix(snapshot.receipts(), &original, identity, issued)?;
    let family = FamilyAuthorityStore::require_existing_from_dir_fd(
        root,
        context.session_family_grant_v2()?,
    )?;
    Ok((permits, family, record))
}

/// Prepared args/spec bind the canonical content bytes. The existing generic
/// ChildAdmissionPrepared contract forbids artifact_refs; derive the exact
/// content-addressed descriptor through the contracts owner instead of widening
/// that receipt. The additional inventory member is mandatory at this barrier.
pub(super) fn request_descriptor(
    request: &NormalChatCallRequestV2,
) -> Result<ArtifactDescriptorV1, RuntimeServiceError> {
    let bytes = jcs_canonical(request)?;
    Ok(ArtifactDescriptorV1 {
        owner_id: recursive_agent_contracts::derive_artifact_id(&bytes)?,
        digest: ContentDigest::compute(&bytes),
        byte_length: bytes.len() as u64,
        media_type: "application/json".into(),
        encoding: None,
    })
}

pub(super) const METADATA_TERMINAL_HEADROOM: u64 = 65_536;

/// Charge unique canonical payload bytes, not references. Descriptor sidecars
/// are bounded store overhead; no provider response text is captured here.
fn require_metadata_capacity(
    payloads: &[Vec<u8>],
    maximum: u64,
) -> Result<(), RuntimeServiceError> {
    let mut unique = BTreeMap::new();
    for payload in payloads {
        unique.insert(ContentDigest::compute(payload), payload.len() as u64);
    }
    let aggregate = unique
        .values()
        .try_fold(0_u64, |sum, size| sum.checked_add(*size))
        .and_then(|sum| sum.checked_add(METADATA_TERMINAL_HEADROOM))
        .ok_or_else(|| recovery("metadata aggregate overflow"))?;
    if aggregate > maximum {
        return Err(recovery(
            "child metadata exceeds aggregate ceiling/headroom",
        ));
    }
    Ok(())
}

pub(super) fn all_artifacts(rows: &[ReceiptV1]) -> Vec<ArtifactDescriptorV1> {
    rows.iter()
        .flat_map(|row| row.artifact_refs.clone())
        .collect()
}
pub(super) fn expected_link(
    reservation: &NormalChatFamilyReservationV2,
) -> Result<ChildRunLinkV1, RuntimeServiceError> {
    let child = &reservation.child_control;
    Ok(ChildRunLinkV1 {
        parent_run_id: reservation.attempt.session_run_id.clone(),
        parent_receipt_id: child.request.parent_admission_receipt_id.clone(),
        parent_control_permit_id: child.request.parent_control_permit_id.clone(),
        child_run_id: reservation.attempt.run_id()?,
        child_control_permit_id: child.child_control_permit_id.clone(),
        root_operation_id: child.request.root_operation_id.clone(),
        reserved_budget: reservation.link_budget_v2()?,
        child_envelope_digest: content_digest(&reservation.attempt)?,
        child_terminal_receipt_id: None,
        child_terminal_state: None,
        child_chain_head: None,
        cancelled: false,
    })
}
pub(super) fn verify_parent_attempt(
    chain: &ChainHandle,
    root: &std::fs::File,
    store: &ArtifactStore,
    request: &NormalChatCallRequestV2,
    reservation: &NormalChatFamilyReservationV2,
    inputs: FamilyHistoryInputs<'_>,
) -> Result<ContentDigest, RuntimeServiceError> {
    verify_parent_attempt_with_pending_closure(
        chain,
        root,
        store,
        request,
        reservation,
        None,
        inputs,
    )
}
pub(super) fn verify_parent_attempt_with_pending_closure(
    chain: &ChainHandle,
    root: &std::fs::File,
    store: &ArtifactStore,
    request: &NormalChatCallRequestV2,
    reservation: &NormalChatFamilyReservationV2,
    pending: Option<&ArtifactDescriptorV1>,
    inputs: FamilyHistoryInputs<'_>,
) -> Result<ContentDigest, RuntimeServiceError> {
    let history = reconcile_family(chain, root, store, inputs, pending)?;
    let group = history
        .group(&request.dispatch_intent_ref)
        .ok_or_else(|| recovery("target intent absent from complete family history"))?;
    if group.request != *request || group.reservation != *reservation {
        return Err(recovery(
            "target request/reservation differs from full family history",
        ));
    }
    Ok(history.parent_head)
}
fn append_parent(
    chain: &mut ChainHandle,
    record: &recursive_agent_policy::PermitRecordV1,
    kind: ReceiptKindV1,
    spec: &ContentDigest,
    args: &ContentDigest,
    artifacts: Vec<ArtifactDescriptorV1>,
    time: DateTime<Utc>,
) -> Result<ReceiptV1, RuntimeServiceError> {
    let phase = if kind == ReceiptKindV1::ChildAdmissionPrepared {
        "admission"
    } else {
        "link"
    };
    let row = make_receipt(
        ReceiptDraftV1 {
            run_id: record.permit.binding.run_id.clone(),
            step_id: super::child_receipt_step_id(&record.permit.binding.run_id, args, phase)?,
            kind,
            valid_time: time,
            lineage: build_lineage(
                &record.permit.permit_id,
                &record.permit.binding.policy_version,
            ),
            spec_digest: spec.clone(),
            args_digest: args.clone(),
            artifact_refs: artifacts,
            outcome: ReceiptOutcomeV1::Ok,
        },
        chain.head().clone(),
    )?;
    chain.append(row.clone())?;
    Ok(row)
}
pub(super) fn preflight_rows(
    control: &PermitEvidenceV1,
    issued: &PermitEvidenceV1,
    consumed: &PermitEvidenceV1,
    at: DateTime<Utc>,
    artifacts: &[ArtifactDescriptorV1],
) -> Vec<ReceiptDraftV1> {
    [
        (
            control,
            ReceiptKindV1::RunStarted,
            vec![],
            control.binding.issued_at,
        ),
        (
            control,
            ReceiptKindV1::StepStarted,
            vec![],
            control.binding.issued_at,
        ),
        (
            control,
            ReceiptKindV1::PermitIssued,
            vec![artifacts[0].clone()],
            control.binding.issued_at,
        ),
        (
            issued,
            ReceiptKindV1::StepStarted,
            vec![],
            issued.binding.issued_at,
        ),
        (
            consumed,
            ReceiptKindV1::NormalChatAttemptAdmittedV2,
            vec![artifacts[1].clone()],
            at,
        ),
        (
            issued,
            ReceiptKindV1::PermitIssued,
            vec![artifacts[2].clone()],
            issued.binding.issued_at,
        ),
        (
            consumed,
            ReceiptKindV1::PermitConsumed,
            vec![artifacts[3].clone()],
            at,
        ),
    ]
    .into_iter()
    .map(
        |(evidence, kind, artifact_refs, valid_time)| ReceiptDraftV1 {
            run_id: evidence.binding.run_id.clone(),
            step_id: evidence.binding.step_id.clone(),
            kind,
            valid_time,
            lineage: build_lineage(&evidence.permit_id, &evidence.binding.policy_version),
            spec_digest: evidence.binding.action_digest.clone(),
            args_digest: evidence.binding.args_digest.clone(),
            artifact_refs,
            outcome: ReceiptOutcomeV1::Ok,
        },
    )
    .collect()
}

#[cfg(test)]
mod capacity_tests {
    use super::*;
    #[test]
    fn exact_metadata_boundary_and_digest_deduplication() {
        // Valid canonical JSON payloads; this tests the calculation directly,
        // not an oversized/invalid operation that cannot reach this boundary.
        let payloads = vec![b"{}".to_vec(), b"[]".to_vec(), b"{}".to_vec()];
        let exact = METADATA_TERMINAL_HEADROOM + 4;
        assert!(require_metadata_capacity(&payloads, exact).is_ok());
        assert!(require_metadata_capacity(&payloads, exact - 1).is_err());
        assert!(require_metadata_capacity(&payloads, METADATA_TERMINAL_HEADROOM).is_err());
        assert!(require_metadata_capacity(&[], METADATA_TERMINAL_HEADROOM).is_ok());
    }
}
