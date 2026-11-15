//! Grant-bound session accounting in the existing family authority owner.
//!
//! These reservations allocate child control only. They do not issue or consume
//! an effect permit, pass the ledger release barrier, or authorize a send. The
//! runtime must verify the root control authority and compose those later gates.

use super::*;
#[path = "normal_chat_prechild_recovery_v1.rs"]
mod prechild_recovery;
#[path = "normal_chat_unconsumed_recovery_v1.rs"]
mod unconsumed_recovery;
pub use prechild_recovery::*;
pub use unconsumed_recovery::*;
#[path = "normal_chat_session_close.rs"]
mod session_close;
use recursive_agent_contracts::{CurrentReceiptId, NormalChatAttemptV2, NormalChatOperationV2};
use serde::{Deserialize, Serialize};
pub use session_close::*;

const SESSION_SCHEMA: &str = "recursive-agent.normal-chat-session-budget/v1";

/// Fixed local ceilings, never a token conversion or provider payload allowance.
pub fn normal_chat_metadata_budget_v2(
    operation: &NormalChatOperationV2,
) -> Result<PermitBudgetV1, PolicyError> {
    operation.validate()?;
    Ok(PermitBudgetV1 {
        max_wall_time_ms: operation.budget.max_wall_time_ms,
        max_output_bytes: NORMAL_CHAT_SESSION_METADATA_BYTES_PER_ATTEMPT,
        max_artifact_bytes: NORMAL_CHAT_SESSION_METADATA_BYTES_PER_ATTEMPT,
    })
}

impl NormalChatFamilyReservationRequestV2 {
    /// Policy owns receipt stamping and local ceilings. Runtime must first prove
    /// the exact committed preparation; its receipt id is correlation, not a grant.
    pub fn from_prepared_call(
        call: &recursive_agent_contracts::NormalChatCallRequestV2,
        receipt: CurrentReceiptId,
    ) -> Result<Self, PolicyError> {
        call.validate()?;
        Ok(Self {
            operation: call.operation.clone(),
            provider_request_digest: call.provider_request_digest.clone(),
            provider_request_bytes: call.provider_request_bytes,
            dispatch_intent_ref: call.dispatch_intent_ref.clone(),
            parent_admission_receipt_id: receipt,
            requested_budget: normal_chat_metadata_budget_v2(&call.operation)?,
        })
    }
}

impl NormalChatFamilyReservationV2 {
    /// Generic V1 units are preserved: BOTH control and effect are admitted
    /// steps. stdout/stderr ceiling is unused (captured bytes = zero), not a new
    /// metadata category; aggregate artifacts retain the fixed byte ceiling.
    pub fn link_budget_v2(
        &self,
    ) -> Result<recursive_agent_contracts::OperationBudgetV1, PolicyError> {
        let budget = normal_chat_metadata_budget_v2(&self.attempt.operation)?;
        if self.child_control.request.requested_budget != budget {
            return Err(PolicyError::PermitStateConflict);
        }
        Ok(recursive_agent_contracts::OperationBudgetV1 {
            max_wall_time_ms: budget.max_wall_time_ms,
            max_output_bytes: budget.max_output_bytes,
            max_artifact_bytes: budget.max_artifact_bytes,
            max_steps: 2,
        })
    }
}

/// Native policy/runner composition input, not a daemon IPC or authority grant.
/// The family owner allocates the ordinal and derives all child identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatFamilyReservationRequestV2 {
    pub operation: NormalChatOperationV2,
    pub provider_request_digest: ContentDigest,
    pub provider_request_bytes: u64,
    pub dispatch_intent_ref: String,
    pub parent_admission_receipt_id: CurrentReceiptId,
    pub requested_budget: PermitBudgetV1,
}

/// Readback projection of one durable reservation, not a send-capable permit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatFamilyReservationV2 {
    pub attempt: NormalChatAttemptV2,
    pub child_control: FamilyChildControlPermitV1,
    pub reserved_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredReservationV1 {
    attempt: NormalChatAttemptV2,
    request_digest: ContentDigest,
    reserved_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bootstrap: Option<NormalChatChildBootstrapV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum NormalChatChildBootstrapV1 {
    ParentReserved {
        schema: NormalChatChildBootstrapSchemaV1,
    },
    ChildStorageReady {
        schema: NormalChatChildBootstrapSchemaV1,
        started_at: DateTime<Utc>,
        checkpoint: NormalChatChildStorageCheckpointV1,
    },
    ChildRootStarted {
        schema: NormalChatChildBootstrapSchemaV1,
        at: DateTime<Utc>,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum NormalChatChildBootstrapSchemaV1 {
    #[serde(rename = "recursive-agent.normal-chat-child-bootstrap/v1")]
    V1,
}

/// A closed extension of family-authority state; persisted in the same atomic
/// file as child controls. Counters are recomputed from these reservations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NormalChatSessionBudgetV1 {
    schema: String,
    grant: NormalChatEgressGrantV1,
    conversation_ref: String,
    opened_at: DateTime<Utc>,
    closed_at: Option<DateTime<Utc>>,
    reservations: BTreeMap<String, StoredReservationV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prechild_recovery: Option<Box<NormalChatPrechildRecoveryRecordV1>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unconsumed_recovery: Option<Box<NormalChatUnconsumedRecoveryRecordV1>>,
}

impl NormalChatSessionBudgetV1 {
    pub(super) fn matches_context(
        &self,
        authority: &NormalChatGrantAuthorityV1,
        conversation: &str,
    ) -> bool {
        self.grant == *authority.grant() && self.conversation_ref == conversation
    }
    pub(super) fn allows_dispatch_at(&self, trusted_now: DateTime<Utc>) -> bool {
        self.closed_at.is_none()
            && trusted_now >= self.opened_at
            && trusted_now < self.grant.expires_at
            && self
                .reservations
                .values()
                .all(|stored| trusted_now >= stored.reserved_at)
    }

    fn validate_binding(&self, family: &FamilyRootGrantV1) -> Result<(), PolicyError> {
        self.grant.validate_structure()?;
        let ceiling = &family.child_run_ceiling;
        if self.schema != SESSION_SCHEMA
            || self.conversation_ref.is_empty()
            || self.conversation_ref.len() > 4096
            || self.conversation_ref.chars().any(char::is_control)
            || family.policy_version
                != format!("normal-chat-grant:revision-{}", self.grant.revision)
            || ceiling.max_depth != 1
            || ceiling.max_children > self.grant.caps.max_attempts
            || ceiling.expires_at > self.grant.expires_at
            || self.opened_at < ceiling.not_before
            || self.opened_at >= ceiling.expires_at
            || self.closed_at.is_some_and(|closed| closed < self.opened_at)
        {
            return Err(PolicyError::PermitStateConflict);
        }
        Ok(())
    }

    pub(super) fn validate(&self, state: &FamilyAuthorityStateV1) -> Result<(), PolicyError> {
        self.validate_binding(&state.grant)?;
        if let Some(recovery) = &self.unconsumed_recovery {
            recovery.validate()?;
            let stored = self
                .reservations
                .get(&recovery.reservation.attempt.dispatch_intent_ref)
                .ok_or(PolicyError::PermitStateConflict)?;
            if self.prechild_recovery.is_some()
                || self.closed_at.is_none()
                || recovery.context.session_family_grant_v2()? != state.grant
                || reservation_readback(state, stored)? != recovery.reservation
                || !matches!(&stored.bootstrap,Some(NormalChatChildBootstrapV1::ChildStorageReady{checkpoint,started_at,..}) if checkpoint==&recovery.checkpoint && started_at==&recovery.started_at)
            {
                return Err(PolicyError::PermitStateConflict);
            }
        }
        if let Some(recovery) = &self.prechild_recovery {
            recovery.validate()?;
            if self.grant != recovery.context.grant
                || self.conversation_ref != recovery.context.session.conversation_ref
                || recovery.context.session_family_grant_v2()? != state.grant
                || self.closed_at.is_none()
            {
                return Err(PolicyError::PermitStateConflict);
            }
            for expected in &recovery.prior_reservations {
                let stored = self
                    .reservations
                    .get(&expected.attempt.dispatch_intent_ref)
                    .ok_or(PolicyError::PermitStateConflict)?;
                if reservation_readback(state, stored)? != *expected {
                    return Err(PolicyError::PermitStateConflict);
                }
            }
            match &recovery.reservation {
                Some(expected) => {
                    let stored = self
                        .reservations
                        .get(&recovery.request.dispatch_intent_ref)
                        .ok_or(PolicyError::PermitStateConflict)?;
                    if self.reservations.len() != recovery.prior_reservations.len() + 1
                        || reservation_readback(state, stored)? != *expected
                        || matches!(
                            stored.bootstrap,
                            Some(
                                NormalChatChildBootstrapV1::ChildRootStarted { .. }
                                    | NormalChatChildBootstrapV1::ChildStorageReady { .. }
                            )
                        )
                        || (recovery.parent_prefix.len()
                            == 5 + 3 * recovery.prior_reservations.len()
                            && !matches!(
                                stored.bootstrap,
                                Some(NormalChatChildBootstrapV1::ParentReserved { .. })
                            ))
                    {
                        return Err(PolicyError::PermitStateConflict);
                    }
                }
                None if self.reservations.len() == recovery.prior_reservations.len() => {}
                None => return Err(PolicyError::PermitStateConflict),
            }
        }
        if self.reservations.len() != state.children.len()
            || self.reservations.len() > self.grant.caps.max_attempts as usize
            || self.reservations.len() > state.grant.child_run_ceiling.max_children as usize
        {
            return Err(PolicyError::PermitStateConflict);
        }
        let mut output_total = 0_u32;
        let mut budget_total = PermitBudgetV1::zero();
        let mut ordinals = BTreeMap::<&str, BTreeSet<u32>>::new();
        let mut child_ids = BTreeSet::new();
        for (intent, stored) in &self.reservations {
            let attempt = &stored.attempt;
            if let Some(NormalChatChildBootstrapV1::ChildRootStarted { at, .. }) = stored.bootstrap
            {
                if at < stored.reserved_at {
                    return Err(PolicyError::PermitStateConflict);
                }
            }
            super::normal_chat_egress::check_normal_chat_grant_attempt(
                &self.grant,
                attempt,
                stored.reserved_at,
            )?;
            let child_id = attempt.run_id()?;
            let child = state
                .children
                .get(&child_id)
                .ok_or(PolicyError::PermitStateConflict)?;
            if intent != &attempt.dispatch_intent_ref
                || attempt.operation.conversation_ref != self.conversation_ref
                || attempt.session_run_id != state.grant.root_operation_id
                || stored.reserved_at < self.opened_at
                || stored.reserved_at >= state.grant.child_run_ceiling.expires_at
                || self
                    .closed_at
                    .is_some_and(|closed| stored.reserved_at > closed)
                || child.request.child_run_id != child_id
                || child.request.parent_operation_id != state.grant.root_operation_id
                || child.request.root_operation_id != state.grant.root_operation_id
                || child.request.parent_control_permit_id != state.grant.parent_control_permit_id
                || child.request.depth != 1
                || child.request.child_operation_digest != content_digest(attempt)?
                || child.child_control_permit_id
                    != derive_family_child_permit_id(&child.request, &state.grant)?
                || child.request.requested_budget
                    != normal_chat_metadata_budget_v2(&attempt.operation)?
                || !child_ids.insert(child_id)
            {
                return Err(PolicyError::PermitStateConflict);
            }
            let request = NormalChatFamilyReservationRequestV2 {
                operation: attempt.operation.clone(),
                provider_request_digest: attempt.provider_request_digest.clone(),
                provider_request_bytes: attempt.provider_request_bytes,
                dispatch_intent_ref: intent.clone(),
                parent_admission_receipt_id: child.request.parent_admission_receipt_id.clone(),
                requested_budget: child.request.requested_budget.clone(),
            };
            if content_digest(&request)? != stored.request_digest {
                return Err(PolicyError::PermitStateConflict);
            }
            if !ordinals
                .entry(&attempt.operation.materialization_ref)
                .or_default()
                .insert(attempt.attempt_number)
            {
                return Err(PolicyError::PermitStateConflict);
            }
            output_total = output_total
                .checked_add(attempt.operation.budget.output_reserve)
                .ok_or(PolicyError::PermitStateConflict)?;
            budget_total = budget_total.checked_add(&child.request.requested_budget)?;
        }
        if output_total > self.grant.caps.max_output_tokens
            || !budget_total.is_within(&state.grant.child_run_ceiling.family_budget)
            || ordinals
                .values()
                .any(|numbers| numbers.iter().copied().ne(1..=numbers.len() as u32))
        {
            return Err(PolicyError::PermitStateConflict);
        }
        Ok(())
    }
}

/// Native read-only projection from canonical family state. It is neither an
/// input grant nor a replacement status store; callers cannot submit it back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalChatSessionAdmissionReadbackV1 {
    pub run_id: CurrentRunId,
    pub control_permit_id: CurrentPermitId,
    pub closed_at: Option<DateTime<Utc>>,
    pub parent_revoked_at: Option<DateTime<Utc>>,
    pub reservation_count: usize,
}

/// Complete bounded projection from one validated canonical family state.
/// Historical evidence only; unlike counts or separate lookups this establishes
/// the full reservation set for cross-store reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalChatSessionSnapshotV2 {
    pub admission: NormalChatSessionAdmissionReadbackV1,
    pub reservations: Vec<NormalChatFamilyReservationV2>,
}

impl FamilyAuthorityStore {
    /// Read-only admission precheck. It allocates nothing and gives no ordinal,
    /// child control, or guarantee against a subsequent concurrent mutation.
    /// Real reservation repeats the same owner checks under its write lock.
    pub fn check_new_normal_chat_call(
        &self,
        authority: &NormalChatGrantAuthorityV1,
        call: &recursive_agent_contracts::NormalChatCallRequestV2,
        mut clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<(), PolicyError> {
        self.with_lock(|| {
            let state = self.read_state()?;
            plan_new_call(&state, authority, call, clock())?;
            Ok(())
        })
    }
    pub fn read_normal_chat_session_snapshot_v2(
        &self,
    ) -> Result<NormalChatSessionSnapshotV2, PolicyError> {
        self.with_lock(|| snapshot_from_state_v2(&self.read_state()?))
    }

    pub fn read_normal_chat_session_admission(
        &self,
    ) -> Result<NormalChatSessionAdmissionReadbackV1, PolicyError> {
        self.with_lock(|| {
            let state = self.read_state()?;
            let session = state
                .normal_chat_session
                .as_ref()
                .ok_or(NormalChatEgressDenialV1::GrantMissing)?;
            Ok(NormalChatSessionAdmissionReadbackV1 {
                run_id: state.grant.root_operation_id,
                control_permit_id: state.grant.parent_control_permit_id,
                closed_at: session.closed_at,
                parent_revoked_at: state.parent_revoked_at,
                reservation_count: session.reservations.len(),
            })
        })
    }

    /// Bind a native-verified family root to a startup-loaded operator grant.
    /// Root control admission/ledger verification remains the runtime's duty;
    /// this method alone cannot mint an effect permit or authorize egress.
    pub fn open_normal_chat_session_from_grant(
        root: &File,
        family: FamilyRootGrantV1,
        authority: &NormalChatGrantAuthorityV1,
        conversation_ref: &str,
        trusted_now: DateTime<Utc>,
    ) -> Result<Self, PolicyError> {
        if trusted_now < authority.loaded_at() {
            return Err(NormalChatEgressDenialV1::Malformed.into());
        }
        authority
            .grant()
            .validate_at(&authority.grant().ares_home_digest, trusted_now)?;
        let candidate = NormalChatSessionBudgetV1 {
            schema: SESSION_SCHEMA.into(),
            grant: authority.grant().clone(),
            conversation_ref: conversation_ref.into(),
            opened_at: trusted_now,
            closed_at: None,
            reservations: BTreeMap::new(),
            prechild_recovery: None,
            unconsumed_recovery: None,
        };
        candidate.validate_binding(&family)?;
        let store = Self::from_dir_fd(root, family)?;
        store.with_lock(|| {
            let mut state = store.read_state()?;
            if let Some(existing) = &state.normal_chat_session {
                if existing.grant != candidate.grant
                    || existing.conversation_ref != candidate.conversation_ref
                {
                    return Err(PolicyError::PermitStateConflict);
                }
                store.root.sync_all()?;
            } else {
                if !state.children.is_empty() || state.parent_revoked_at.is_some() {
                    return Err(PolicyError::PermitStateConflict);
                }
                state.normal_chat_session = Some(candidate);
                store.write_state(&state)?;
            }
            Ok(())
        })?;
        Ok(store)
    }

    /// Atomically reserve one attempt plus its child control. No effect permit
    /// is issued. Exact-intent retry is readback only and never a new send grant.
    /// An I/O error can follow rename: it is an uncertain commit, NOT proof of
    /// absence. Read back the exact intent before retrying; never refund it.
    pub fn reserve_normal_chat_attempt(
        &self,
        authority: &NormalChatGrantAuthorityV1,
        request: &NormalChatFamilyReservationRequestV2,
        trusted_now: DateTime<Utc>,
    ) -> Result<NormalChatFamilyReservationV2, PolicyError> {
        self.reserve_normal_chat_attempt_with_interruption(authority, request, trusted_now, None)
    }

    /// Deterministic failpoint seam for native durability tests. This may only
    /// interrupt a transition; it cannot relax admission or create authority.
    #[doc(hidden)]
    pub fn reserve_normal_chat_attempt_with_interruption(
        &self,
        authority: &NormalChatGrantAuthorityV1,
        request: &NormalChatFamilyReservationRequestV2,
        trusted_now: DateTime<Utc>,
        interrupt_after: Option<PermitTransitionStage>,
    ) -> Result<NormalChatFamilyReservationV2, PolicyError> {
        use NormalChatEgressDenialV1 as Denial;
        self.with_lock(|| {
            let mut state = self.read_state()?;
            let session =
                validate_call_context(&state, authority, &request.operation, trusted_now)?;
            let request_digest = content_digest(request)?;
            if let Some(existing) = session.reservations.get(&request.dispatch_intent_ref) {
                if existing.request_digest != request_digest {
                    return Err(Denial::IntentConflict.into());
                }
                // Complete a possibly uncertain previous rename before this
                // exact retry is described as a durable reservation.
                self.root.sync_all()?;
                return reservation_readback(&state, existing);
            }
            let call = recursive_agent_contracts::NormalChatCallRequestV2 {
                schema: recursive_agent_contracts::NormalChatCallRequestSchemaV2::V2,
                operation: request.operation.clone(),
                provider_request_digest: request.provider_request_digest.clone(),
                provider_request_bytes: request.provider_request_bytes,
                dispatch_intent_ref: request.dispatch_intent_ref.clone(),
            };
            let attempt = plan_new_call(&state, authority, &call, trusted_now)?;
            if request.requested_budget != normal_chat_metadata_budget_v2(&attempt.operation)? {
                return Err(Denial::Malformed.into());
            }
            let child_request = FamilyChildRequestV1 {
                child_run_id: attempt.run_id()?,
                parent_operation_id: state.grant.root_operation_id.clone(),
                root_operation_id: state.grant.root_operation_id.clone(),
                parent_control_permit_id: state.grant.parent_control_permit_id.clone(),
                parent_admission_receipt_id: request.parent_admission_receipt_id.clone(),
                requested_budget: request.requested_budget.clone(),
                child_operation_digest: content_digest(&attempt)?,
                depth: 1,
            };
            let child_control = reserve_family_child(&mut state, &child_request, trusted_now)?;
            state
                .normal_chat_session
                .as_mut()
                .ok_or(Denial::GrantMissing)?
                .reservations
                .insert(
                    request.dispatch_intent_ref.clone(),
                    StoredReservationV1 {
                        attempt: attempt.clone(),
                        request_digest,
                        reserved_at: trusted_now,
                        bootstrap: Some(NormalChatChildBootstrapV1::ParentReserved {
                            schema: NormalChatChildBootstrapSchemaV1::V1,
                        }),
                    },
                );
            state
                .normal_chat_session
                .as_ref()
                .ok_or(Denial::GrantMissing)?
                .validate(&state)?;
            self.write_state_with_interruption(&state, interrupt_after)?;
            Ok(NormalChatFamilyReservationV2 {
                attempt,
                child_control,
                reserved_at: trusted_now,
            })
        })
    }

    /// Read authoritative allocation state even after close/expiry. This never
    /// renews a reservation or releases a send-capable permit.
    pub fn read_normal_chat_reservation(
        &self,
        dispatch_intent_ref: &str,
    ) -> Result<Option<NormalChatFamilyReservationV2>, PolicyError> {
        self.with_lock(|| {
            let state = self.read_state()?;
            let session = state
                .normal_chat_session
                .as_ref()
                .ok_or(NormalChatEgressDenialV1::GrantMissing)?;
            session
                .reservations
                .get(dispatch_intent_ref)
                .map(|stored| reservation_readback(&state, stored))
                .transpose()
        })
    }

    /// Stop new reservations durably without refunding earlier allocations.
    /// This closes accounting only; runtime child reconciliation and the final
    /// parent ledger receipt are separate mandatory gates.
    pub fn close_normal_chat_session(&self, trusted_now: DateTime<Utc>) -> Result<(), PolicyError> {
        self.close_normal_chat_session_for_report_v2(trusted_now, &mut || trusted_now, None)
    }

    /// Historical durability confirmation only. Missing closure is never
    /// created here and no current time is assigned to already closed history.
    pub(super) fn confirm_normal_chat_report_closed_v2(&self) -> Result<(), PolicyError> {
        self.with_lock(|| {
            let state = self.read_state()?;
            let session = state
                .normal_chat_session
                .as_ref()
                .ok_or(NormalChatEgressDenialV1::GrantMissing)?;
            if session.closed_at.is_none() {
                return Err(PolicyError::PermitStateConflict);
            }
            self.root.sync_all()?;
            if self.read_state()? != state {
                return Err(PolicyError::PermitStateConflict);
            }
            Ok(())
        })
    }

    /// Narrow admission before a fenced report or owner expiry disposition.
    /// The clock is sampled under the family lock, not before waiting for a
    /// concurrent reservation. A close is accounting authority, not a terminal
    /// ledger outcome, cancellation of in-flight work, or a refund.
    pub(super) fn close_normal_chat_session_for_report_v2(
        &self,
        report_recorded_at: DateTime<Utc>,
        trusted_clock: &mut dyn FnMut() -> DateTime<Utc>,
        interrupt_after: Option<PermitTransitionStage>,
    ) -> Result<(), PolicyError> {
        self.with_lock(|| {
            let mut state = self.read_state()?;
            let trusted_now = trusted_clock();
            let session = state
                .normal_chat_session
                .as_mut()
                .ok_or(NormalChatEgressDenialV1::GrantMissing)?;
            if trusted_now < report_recorded_at
                || trusted_now < session.opened_at
                || session.closed_at.is_some_and(|closed| trusted_now < closed)
                || state
                    .parent_revoked_at
                    .is_some_and(|revoked| trusted_now < revoked)
                || session
                    .reservations
                    .values()
                    .any(|stored| trusted_now < stored.reserved_at)
            {
                return Err(NormalChatEgressDenialV1::Malformed.into());
            }
            if session.closed_at.is_none() {
                session.closed_at = Some(trusted_now);
                state
                    .normal_chat_session
                    .as_ref()
                    .ok_or(NormalChatEgressDenialV1::GrantMissing)?
                    .validate(&state)?;
                self.write_state_with_interruption(&state, interrupt_after)?;
            } else {
                // A previous rename may have committed even if its ACK failed.
                // Repeating the close must finish durability, without rewriting
                // the first close time or changing reservations/revocation.
                self.root.sync_all()?;
                if interrupt_after == Some(PermitTransitionStage::DirectoryFsync) {
                    return Err(PolicyError::InjectedInterruption(
                        PermitTransitionStage::DirectoryFsync,
                    ));
                }
            }
            let reread = self.read_state()?;
            if reread != state {
                return Err(PolicyError::PermitStateConflict);
            }
            Ok(())
        })
    }
}

fn validate_call_context<'a>(
    state: &'a FamilyAuthorityStateV1,
    authority: &NormalChatGrantAuthorityV1,
    operation: &NormalChatOperationV2,
    now: DateTime<Utc>,
) -> Result<&'a NormalChatSessionBudgetV1, PolicyError> {
    use NormalChatEgressDenialV1 as D;
    let session = state.normal_chat_session.as_ref().ok_or(D::GrantMissing)?;
    if session.grant != *authority.grant()
        || operation.conversation_ref != session.conversation_ref
        || operation.parent_run_id != state.grant.root_operation_id
        || now < session.opened_at
        || session
            .reservations
            .values()
            .any(|stored| now < stored.reserved_at)
    {
        return Err(D::Malformed.into());
    }
    if state.parent_revoked_at.is_some() || session.closed_at.is_some() {
        return Err(D::RunClosed.into());
    }
    if now < state.grant.child_run_ceiling.not_before {
        return Err(D::Malformed.into());
    }
    if now >= state.grant.child_run_ceiling.expires_at {
        return Err(D::GrantExpired.into());
    }
    Ok(session)
}
fn plan_new_call(
    state: &FamilyAuthorityStateV1,
    authority: &NormalChatGrantAuthorityV1,
    call: &recursive_agent_contracts::NormalChatCallRequestV2,
    now: DateTime<Utc>,
) -> Result<NormalChatAttemptV2, PolicyError> {
    use NormalChatEgressDenialV1 as D;
    call.operation.validate()?;
    if call.provider_request_bytes > call.operation.budget.max_request_bytes {
        return Err(D::CapExhaustedRequestBytes.into());
    }
    call.validate()?;
    let session = validate_call_context(state, authority, &call.operation, now)?;
    if session.reservations.contains_key(&call.dispatch_intent_ref) {
        return Err(D::IntentConflict.into());
    }
    if session.reservations.len() >= session.grant.caps.max_attempts as usize
        || session.reservations.len() >= state.grant.child_run_ceiling.max_children as usize
    {
        return Err(D::CapExhaustedAttempts.into());
    }
    let prior = session
        .reservations
        .values()
        .filter(|stored| {
            stored.attempt.operation.materialization_ref == call.operation.materialization_ref
        })
        .count();
    let ordinal = u32::try_from(prior)
        .ok()
        .and_then(|n| n.checked_add(1))
        .ok_or(D::CapExhaustedAttempts)?;
    let attempt = NormalChatAttemptV2::new(
        call.operation.clone(),
        ordinal,
        call.provider_request_digest.clone(),
        call.provider_request_bytes,
        call.dispatch_intent_ref.clone(),
        state.grant.root_operation_id.clone(),
    )?;
    authority.check_attempt(&attempt, now)?;
    let output = session
        .reservations
        .values()
        .try_fold(0_u32, |sum, stored| {
            sum.checked_add(stored.attempt.operation.budget.output_reserve)
                .ok_or(D::CapExhaustedOutputTokens)
        })?
        .checked_add(call.operation.budget.output_reserve)
        .ok_or(D::CapExhaustedOutputTokens)?;
    if output > session.grant.caps.max_output_tokens {
        return Err(D::CapExhaustedOutputTokens.into());
    }
    let charged = state
        .children
        .values()
        .try_fold(PermitBudgetV1::zero(), |sum, child| {
            sum.checked_add(&child.request.requested_budget)
        })?
        .checked_add(&normal_chat_metadata_budget_v2(&call.operation)?)?;
    if !charged.is_within(&state.grant.child_run_ceiling.family_budget) {
        return Err(PolicyError::BudgetOverrun(
            "normal-chat family reservation ceiling exceeded".into(),
        ));
    }
    Ok(attempt)
}

pub(super) fn snapshot_from_state_v2(
    state: &FamilyAuthorityStateV1,
) -> Result<NormalChatSessionSnapshotV2, PolicyError> {
    let session = state
        .normal_chat_session
        .as_ref()
        .ok_or(NormalChatEgressDenialV1::GrantMissing)?;
    let reservations = session
        .reservations
        .values()
        .map(|stored| reservation_readback(state, stored))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(NormalChatSessionSnapshotV2 {
        admission: NormalChatSessionAdmissionReadbackV1 {
            run_id: state.grant.root_operation_id.clone(),
            control_permit_id: state.grant.parent_control_permit_id.clone(),
            closed_at: session.closed_at,
            parent_revoked_at: state.parent_revoked_at,
            reservation_count: reservations.len(),
        },
        reservations,
    })
}

pub(super) fn reservation_from_state_v2(
    state: &FamilyAuthorityStateV1,
    intent: &str,
) -> Result<NormalChatFamilyReservationV2, PolicyError> {
    let stored = state
        .normal_chat_session
        .as_ref()
        .and_then(|session| session.reservations.get(intent))
        .ok_or(NormalChatEgressDenialV1::Malformed)?;
    reservation_readback(state, stored)
}

fn reservation_readback(
    state: &FamilyAuthorityStateV1,
    stored: &StoredReservationV1,
) -> Result<NormalChatFamilyReservationV2, PolicyError> {
    let child = state
        .children
        .get(&stored.attempt.run_id()?)
        .ok_or(PolicyError::PermitStateConflict)?;
    Ok(NormalChatFamilyReservationV2 {
        attempt: stored.attempt.clone(),
        child_control: child.clone(),
        reserved_at: stored.reserved_at,
    })
}
