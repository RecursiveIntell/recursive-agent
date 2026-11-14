//! Grant-admitted V2 normal-chat policy consumption and status-only readback.
//!
//! This is not provider execution or the runtime ledger release barrier. The
//! session accounting control remains network-denying. The file grant plus a
//! freshly guarded canonical family reservation admits this one child-local,
//! exact-request control/effect pair. Existing prefixes never mint another native
//! continuation, and no effect is published in an Issued state.

use super::*;
use recursive_agent_contracts::NormalChatAttemptV2;
use serde::{Deserialize, Serialize};

pub const NORMAL_CHAT_EFFECT_TOOL_V2: &str = "normal_chat_v2";
const EFFECT_SCOPE_V2: &str = "native-normal-chat-v2";
const CONTROL_TOOL_V2: &str = "normal_chat_attempt_control_v2";
const CONTROL_SCOPE_V2: &str = "normal-chat-attempt-control/v2";

pub(super) fn is_v2_attempt_tool(tool: &str) -> bool {
    tool == CONTROL_TOOL_V2 || tool == NORMAL_CHAT_EFFECT_TOOL_V2
}
pub(super) fn is_closed_effect_v2(tool: &str, effect: &EffectScopeV1) -> bool {
    tool == NORMAL_CHAT_EFFECT_TOOL_V2
        && effect.scope_name == EFFECT_SCOPE_V2
        && effect.network_allowed
        && effect.read_roots.is_empty()
        && effect.write_roots.is_empty()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatRetainedAdmissionSchemaV2 {
    #[serde(rename = "recursive-agent.normal-chat-policy-admission/v2")]
    V2,
}
/// Historical correlation retained on the canonical local control record only.
/// It cannot grant authority, restore a continuation, or verify current policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatRetainedAdmissionV2 {
    pub schema: NormalChatRetainedAdmissionSchemaV2,
    pub reservation: NormalChatFamilyReservationV2,
    pub context: NormalChatGrantContextV2,
}

/// A closed additive record discriminator. Effect binding is validated against
/// its control's retained admission, never by reconstructing a legacy V1 record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
pub enum NormalChatAttemptRecordV2 {
    Control {
        admission: Box<NormalChatRetainedAdmissionV2>,
    },
    Effect {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        settlement: Option<Box<NormalChatSettlementV2>>,
    },
    /// Explicit owner-observed expiry disposition, never an SDK report.
    Recovered {
        recovery: Box<NormalChatRecoveryRecordV1>,
    },
    Interrupted {
        recovery: Box<NormalChatInterruptedRecoveryRecordV2>,
    },
    PreparedRecovered {
        admission: Box<NormalChatRetainedAdmissionV2>,
        recovery: Box<NormalChatPreparedRecoveryRecordV1>,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalChatAttemptPolicyStateV2 {
    /// No local policy record for the canonical reservation. This is not proof
    /// that missing/replaced storage never contained an earlier admission/send.
    Unbegun,
    Prepared,
    Consumed,
    Settled,
    /// Native observation only; not ledger terminality or send authority.
    RecoveredUnknown,
    RecoveredBeforeRelease,
    RecoveredPrepared,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatAttemptReadbackSchemaV2 {
    #[serde(rename = "recursive-agent.normal-chat-attempt-readback/v2")]
    V2,
}
/// Rebuildable local policy projection. It proves neither send nor no-send and
/// gives no permission to send, renew, retry, or reconstruct a lost continuation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatAttemptReadbackV2 {
    pub schema: NormalChatAttemptReadbackSchemaV2,
    pub state: NormalChatAttemptPolicyStateV2,
    pub attempt: NormalChatAttemptV2,
    pub local_control: Option<PermitEvidenceV1>,
    pub effect: Option<PermitEvidenceV1>,
    pub preflight: Option<PermitPreflightReceiptV1>,
    pub outcome: Option<PermitOutcomeReceiptV1>,
    pub settlement: Option<NormalChatSettlementV2>,
}
/// Returned only for a newly committed policy consumption, not from readback.
/// The runtime must still commit/verify its parent/child ledger release barrier.
pub struct NormalChatAttemptConsumptionV2 {
    admission: NormalChatRetainedAdmissionV2,
    control: ExecutionPermitV1,
    effect: ExecutionPermitV1,
    preflight: PermitPreflightReceiptV1,
    // Keep the exact consumed permit directory alive across native composition.
    _store: DurablePermitStore,
}
impl NormalChatAttemptConsumptionV2 {
    /// Revalidate the retained fresh native transition at RuntimeService's
    /// release boundary. This is NOT ledger verification or provider execution.
    /// It consumes ownership on failure and cannot be reconstructed from status.
    pub fn check_runtime_release_v2(
        self,
        authority: &NormalChatGrantAuthorityV1,
        family: &NormalChatControlledFamilyV1,
        not_before: DateTime<Utc>,
        expected_family: &NormalChatSessionSnapshotV2,
        mut clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<Self, PolicyError> {
        self.with_runtime_release_v2(
            authority,
            family,
            not_before,
            expected_family,
            &mut clock,
            |_| Ok(()),
        )?;
        Ok(self)
    }

    /// Consume fresh native ownership for one synchronous local IPC publication.
    /// The callback runs under child -> family -> root locks and must complete
    /// bounded I/O here; it must not enqueue work or re-enter these owners.
    pub fn publish_runtime_response_v2(
        self,
        authority: &NormalChatGrantAuthorityV1,
        family: &NormalChatControlledFamilyV1,
        not_before: DateTime<Utc>,
        expected_family: &NormalChatSessionSnapshotV2,
        mut clock: impl FnMut() -> DateTime<Utc>,
        publish: impl FnOnce(DateTime<Utc>) -> Result<(), PolicyError>,
    ) -> Result<(), PolicyError> {
        self.with_runtime_release_v2(
            authority,
            family,
            not_before,
            expected_family,
            &mut clock,
            publish,
        )
    }

    fn with_runtime_release_v2<T>(
        &self,
        authority: &NormalChatGrantAuthorityV1,
        family: &NormalChatControlledFamilyV1,
        not_before: DateTime<Utc>,
        expected_family: &NormalChatSessionSnapshotV2,
        clock: &mut dyn FnMut() -> DateTime<Utc>,
        publish: impl FnOnce(DateTime<Utc>) -> Result<T, PolicyError>,
    ) -> Result<T, PolicyError> {
        self._store.with_lock(|| {
            self._store.validate_v2_child_locator()?;
            family.with_runtime_release_fence_v2(
                authority,
                &self.admission,
                not_before,
                expected_family,
                clock,
                |now| {
                    let view = self
                        ._store
                        .read_normal_chat_attempt_snapshot_v2(&self.admission.reservation)?;
                    let control = view
                        .local_control
                        .as_ref()
                        .ok_or(PolicyError::PermitStateConflict)?;
                    if view.state != NormalChatAttemptPolicyStateV2::Consumed
                        || !matches!(control.state, PermitEvidenceStateV1::Issued)
                        || control.permit_id != self.control.permit_id
                        || view.preflight.as_ref() != Some(&self.preflight)
                        || view.effect.as_ref() != Some(&self.preflight.evidence)
                        || view.settlement.is_some()
                        || view.outcome.is_some()
                        || now < self.preflight.recorded_at
                    {
                        return Err(PolicyError::PermitStateConflict);
                    }
                    check_attempt_window(&self.effect.binding, now)?;
                    self._store.validate_v2_child_locator()?;
                    publish(now)
                },
            )
        })
    }

    /// Historical proof projection only; never a serialized continuation.
    pub fn ledger_evidence(&self) -> Result<NormalChatLedgerAdmissionEvidenceV2, PolicyError> {
        let evidence = NormalChatLedgerAdmissionEvidenceV2 {
            schema: NormalChatLedgerAdmissionSchemaV2::V2,
            admission: self.admission.clone(),
            preflight: self.preflight.clone(),
        };
        evidence.validate()?;
        Ok(evidence)
    }
    pub fn attempt(&self) -> &NormalChatAttemptV2 {
        &self.admission.reservation.attempt
    }
    pub fn control_permit(&self) -> &ExecutionPermitV1 {
        &self.control
    }
    pub fn effect_permit(&self) -> &ExecutionPermitV1 {
        &self.effect
    }
    pub fn preflight(&self) -> &PermitPreflightReceiptV1 {
        &self.preflight
    }
}
/// No serialization/clone path can turn Existing status into native consumption.
pub enum NormalChatAttemptBeginV2 {
    Consumed(Box<NormalChatAttemptConsumptionV2>),
    Existing(Box<NormalChatAttemptReadbackV2>),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalChatBeginInterruptionV2 {
    Control(PermitTransitionStage),
    Effect(PermitTransitionStage),
}

impl DurablePermitStore {
    /// Require-existing retained context discovery. Historical evidence only;
    /// never constructs an authority or a fresh continuation.
    pub fn read_retained_normal_chat_admission_v2(
        &self,
    ) -> Result<Option<NormalChatRetainedAdmissionV2>, PolicyError> {
        self.with_lock(|| {
            self.validate_v2_child_locator()?;
            let records = self.read_governed_permit_records()?;
            let mut admission = None;
            for record in records {
                if let Some(
                    NormalChatAttemptRecordV2::Control { admission: value }
                    | NormalChatAttemptRecordV2::PreparedRecovered {
                        admission: value, ..
                    },
                ) = record.normal_chat_attempt_v2
                {
                    if admission.replace(*value).is_some() {
                        return Err(PolicyError::PermitStateConflict);
                    }
                }
            }
            self.validate_v2_child_locator()?;
            Ok(admission)
        })
    }
    pub(super) fn validate_v2_child_locator(&self) -> Result<(), PolicyError> {
        let root = directory_identity(&self.run_root)?;
        let fd = secure_open_at(
            &self.run_root,
            "permits",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let permits = directory_identity(&File::from(fd))?;
        if (root.0, root.1) != self.run_root_identity()
            || (permits.0, permits.1) != (self.permit_root_device, self.permit_root_inode)
            || (root.0, root.1) == (permits.0, permits.1)
        {
            return Err(PolicyError::UnsafePermitRoot(
                "V2 child permit locator no longer matches its pinned root".into(),
            ));
        }
        let fd = secure_open_at(
            &self.root,
            ".permit.lock",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?;
        let observed = File::from(fd).metadata()?;
        let pinned = self.lock.metadata()?;
        if !observed.is_file()
            || observed.dev() != pinned.dev()
            || observed.ino() != pinned.ino()
            || observed.nlink() != 1
            || observed.mode() & 0o777 != 0o600
            || observed.uid() != rustix::process::getuid().as_raw()
        {
            return Err(PolicyError::PermitStateConflict);
        }
        Ok(())
    }

    pub fn begin_normal_chat_attempt_v2(
        &self,
        authority: &NormalChatGrantAuthorityV1,
        family: &NormalChatControlledFamilyV1,
        intent: &str,
        trusted_clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<NormalChatAttemptBeginV2, PolicyError> {
        self.begin_normal_chat_attempt_v2_with_interruption(
            authority,
            family,
            intent,
            trusted_clock,
            None,
        )
    }

    /// Test failpoints interrupt publication only; they cannot relax admission.
    #[doc(hidden)]
    pub fn begin_normal_chat_attempt_v2_with_interruption(
        &self,
        authority: &NormalChatGrantAuthorityV1,
        family: &NormalChatControlledFamilyV1,
        intent: &str,
        mut trusted_clock: impl FnMut() -> DateTime<Utc>,
        interrupt_after: Option<NormalChatBeginInterruptionV2>,
    ) -> Result<NormalChatAttemptBeginV2, PolicyError> {
        let root = self.run_root_identity();
        let permits = (self.permit_root_device, self.permit_root_inode);
        let (parent_root, parent_permits) = family.policy_root_identities_v2();
        // Must precede nested locks. Compatibility from_dir_fd is not a pinned
        // child RunPaths binding and may alias the parent permit lock.
        if root == permits
            || [root, permits]
                .iter()
                .any(|id| *id == parent_root || *id == parent_permits)
        {
            return Err(PolicyError::UnsafePermitRoot(
                "V2 Begin requires a distinct pinned child run root".into(),
            ));
        }
        self.with_lock(|| {
            self.validate_v2_child_locator()?;
            self.reject_legacy_context_admission()?;
            let reservation = family
                .read_normal_chat_reservation(intent)?
                .ok_or(NormalChatEgressDenialV1::Malformed)?;
            let old = self.read_normal_chat_attempt_snapshot_v2(&reservation)?;
            if old.state != NormalChatAttemptPolicyStateV2::Unbegun {
                self.root.sync_all()?;
                return Ok(NormalChatAttemptBeginV2::Existing(Box::new(old)));
            }
            let (current, session_expiry) =
                family.current_reservation_for_begin_v2(authority, intent, &mut trusted_clock)?;
            if current != reservation {
                return Err(PolicyError::PermitStateConflict);
            }
            let admission = NormalChatRetainedAdmissionV2 {
                schema: NormalChatRetainedAdmissionSchemaV2::V2,
                reservation,
                context: family.retained_grant_context_v2(),
            };
            if admission.context.root_control.binding.expires_at != session_expiry {
                return Err(PolicyError::PermitStateConflict);
            }
            let (control, effect) = build_attempt_permits(&admission)?;
            let now = trusted_clock();
            check_attempt_window(&effect.binding, now)?;
            let mut allocation = BTreeMap::new();
            allocation.insert(effect.permit_id.clone(), effect.binding.budget.clone());
            let control_record = PermitRecordV1 {
                permit: control.clone(),
                state: PermitStateV1::Issued,
                child_allocations: allocation,
                preflight_receipt: None,
                outcome_receipt: None,
                retained_normal_chat_admission: None,
                normal_chat_settlement: None,
                normal_chat_attempt_v2: Some(NormalChatAttemptRecordV2::Control {
                    admission: Box::new(admission.clone()),
                }),
            };
            let control_fault = match interrupt_after {
                Some(NormalChatBeginInterruptionV2::Control(stage)) => Some(stage),
                _ => None,
            };
            self.replace_record(&control_record, control_fault)?;
            let (rechecked, expiry) =
                family.current_reservation_for_begin_v2(authority, intent, &mut trusted_clock)?;
            if rechecked != admission.reservation
                || expiry != admission.context.root_control.binding.expires_at
                || family.retained_grant_context_v2() != admission.context
            {
                return Err(PolicyError::PermitStateConflict);
            }
            let consumed_at = trusted_clock();
            if consumed_at < now {
                return Err(NormalChatEgressDenialV1::Malformed.into());
            }
            check_attempt_window(&effect.binding, consumed_at)?;
            self.validate_v2_child_locator()?;
            validate_parent_binding(&effect, &control_record, consumed_at)?;
            let mut record = PermitRecordV1 {
                permit: effect.clone(),
                state: PermitStateV1::Consumed { consumed_at },
                child_allocations: BTreeMap::new(),
                preflight_receipt: None,
                outcome_receipt: None,
                retained_normal_chat_admission: None,
                normal_chat_settlement: None,
                normal_chat_attempt_v2: Some(NormalChatAttemptRecordV2::Effect {
                    settlement: None,
                }),
            };
            let preflight = PermitPreflightReceiptV1::create(
                PermitEvidenceV1::from_record(&record)?,
                consumed_at,
            )?;
            record.preflight_receipt = Some(preflight.clone());
            let effect_fault = match interrupt_after {
                Some(NormalChatBeginInterruptionV2::Effect(stage)) => Some(stage),
                _ => None,
            };
            self.replace_record(&record, effect_fault)?;
            let (after, expiry) =
                family.current_reservation_for_begin_v2(authority, intent, &mut trusted_clock)?;
            if after != admission.reservation
                || expiry != admission.context.root_control.binding.expires_at
                || family.retained_grant_context_v2() != admission.context
            {
                return Err(PolicyError::PermitStateConflict);
            }
            let reread = self.read_normal_chat_attempt_snapshot_v2(&admission.reservation)?;
            if reread.state != NormalChatAttemptPolicyStateV2::Consumed
                || reread.preflight.as_ref() != Some(&preflight)
            {
                return Err(PolicyError::PermitStateConflict);
            }
            let (final_reservation, final_expiry) =
                family.current_reservation_for_begin_v2(authority, intent, &mut trusted_clock)?;
            if final_reservation != admission.reservation
                || final_expiry != admission.context.root_control.binding.expires_at
                || family.retained_grant_context_v2() != admission.context
            {
                return Err(PolicyError::PermitStateConflict);
            }
            self.validate_v2_child_locator()?;
            let release_now = trusted_clock();
            if release_now < consumed_at {
                return Err(NormalChatEgressDenialV1::Malformed.into());
            }
            check_attempt_window(&effect.binding, release_now)?;
            Ok(NormalChatAttemptBeginV2::Consumed(Box::new(
                NormalChatAttemptConsumptionV2 {
                    admission,
                    control,
                    effect,
                    preflight,
                    _store: self.clone(),
                },
            )))
        })
    }

    /// Resolve identity from the canonical family owner, including for an
    /// empty local store. Status never accepts a caller-authored reservation.
    /// The family handle is a read capability, not current egress authority.
    pub fn read_normal_chat_attempt_v2(
        &self,
        family: &FamilyAuthorityStore,
        intent: &str,
    ) -> Result<NormalChatAttemptReadbackV2, PolicyError> {
        self.read_normal_chat_attempt_v2_with_observer(family, intent, || {})
    }

    /// Test synchronization hook after record loading, before the final locator
    /// fence. It cannot grant authority or turn readback into a continuation.
    #[doc(hidden)]
    pub fn read_normal_chat_attempt_v2_with_observer(
        &self,
        family: &FamilyAuthorityStore,
        intent: &str,
        after_snapshot: impl FnOnce(),
    ) -> Result<NormalChatAttemptReadbackV2, PolicyError> {
        let reservation = family
            .read_normal_chat_reservation(intent)?
            .ok_or(NormalChatEgressDenialV1::Malformed)?;
        self.with_lock(|| {
            let view = self.read_normal_chat_attempt_snapshot_v2(&reservation)?;
            after_snapshot();
            self.validate_v2_child_locator()?;
            Ok(view)
        })
    }

    pub(super) fn read_normal_chat_attempt_snapshot_v2(
        &self,
        reservation: &NormalChatFamilyReservationV2,
    ) -> Result<NormalChatAttemptReadbackV2, PolicyError> {
        self.validate_v2_child_locator()?;
        reservation.attempt.validate()?;
        let records = self.read_governed_permit_records()?;
        let mut view = NormalChatAttemptReadbackV2 {
            schema: NormalChatAttemptReadbackSchemaV2::V2,
            state: NormalChatAttemptPolicyStateV2::Unbegun,
            attempt: reservation.attempt.clone(),
            local_control: None,
            effect: None,
            preflight: None,
            outcome: None,
            settlement: None,
        };
        if records.is_empty() {
            self.validate_v2_child_locator()?;
            return Ok(view);
        }
        if records.len() > 2 {
            return Err(PolicyError::PermitStateConflict);
        }
        let control = records
            .iter()
            .find(|record| record.permit.binding.tool == CONTROL_TOOL_V2)
            .ok_or(PolicyError::PermitStateConflict)?;
        let Some(
            NormalChatAttemptRecordV2::Control { admission }
            | NormalChatAttemptRecordV2::PreparedRecovered { admission, .. },
        ) = &control.normal_chat_attempt_v2
        else {
            return Err(PolicyError::PermitStateConflict);
        };
        if admission.reservation != *reservation {
            return Err(PolicyError::PermitStateConflict);
        }
        let (_, expected_effect) = build_attempt_permits(admission)?;
        view.local_control = Some(PermitEvidenceV1::from_record(control)?);
        view.state = NormalChatAttemptPolicyStateV2::Prepared;
        if matches!(
            control.normal_chat_attempt_v2,
            Some(NormalChatAttemptRecordV2::PreparedRecovered { .. })
        ) {
            if records.len() != 1 {
                return Err(PolicyError::PermitStateConflict);
            }
            view.state = NormalChatAttemptPolicyStateV2::RecoveredPrepared;
        }
        if records.len() == 2 {
            let effect = records
                .iter()
                .find(|record| record.permit.permit_id == expected_effect.permit_id)
                .ok_or(PolicyError::PermitStateConflict)?;
            view.effect = Some(PermitEvidenceV1::from_record(effect)?);
            view.preflight = effect.preflight_receipt.clone();
            view.state = NormalChatAttemptPolicyStateV2::Consumed;
            if let Some(NormalChatAttemptRecordV2::Effect {
                settlement: Some(settlement),
            }) = &effect.normal_chat_attempt_v2
            {
                view.outcome = effect.outcome_receipt.clone();
                view.settlement = Some(settlement.as_ref().clone());
                view.state = NormalChatAttemptPolicyStateV2::Settled;
            } else if matches!(
                effect.normal_chat_attempt_v2,
                Some(NormalChatAttemptRecordV2::Recovered { .. })
            ) {
                view.state = NormalChatAttemptPolicyStateV2::RecoveredUnknown;
            } else if matches!(
                effect.normal_chat_attempt_v2,
                Some(NormalChatAttemptRecordV2::Interrupted { .. })
            ) {
                view.state = NormalChatAttemptPolicyStateV2::RecoveredBeforeRelease;
            }
        }
        self.validate_v2_child_locator()?;
        Ok(view)
    }

    pub(super) fn validate_normal_chat_attempt_record_v2(
        &self,
        record: &PermitRecordV1,
    ) -> Result<(), PolicyError> {
        let corrupt = || {
            rejected(
                &record.permit.permit_id,
                PermitRejectionReasonV1::StateCorrupted,
            )
        };
        if record.retained_normal_chat_admission.is_some()
            || record.normal_chat_settlement.is_some()
        {
            return Err(corrupt());
        }
        match &record.normal_chat_attempt_v2 {
            Some(
                NormalChatAttemptRecordV2::Control { admission }
                | NormalChatAttemptRecordV2::PreparedRecovered { admission, .. },
            ) => {
                if let Some(NormalChatAttemptRecordV2::PreparedRecovered { recovery, .. }) =
                    &record.normal_chat_attempt_v2
                {
                    recovery.validate(admission)?;
                    if record.state != recovery.closed_state() {
                        return Err(corrupt());
                    }
                }
                let (control, effect) = build_attempt_permits(admission)?;
                let mut expected = BTreeMap::new();
                expected.insert(effect.permit_id.clone(), effect.binding.budget);
                if record.permit != control
                    || record.child_allocations != expected
                    || record.preflight_receipt.is_some()
                    || record.outcome_receipt.is_some()
                    || matches!(record.state, PermitStateV1::Consumed { .. })
                {
                    return Err(corrupt());
                }
            }
            Some(
                NormalChatAttemptRecordV2::Effect { .. }
                | NormalChatAttemptRecordV2::Recovered { .. }
                | NormalChatAttemptRecordV2::Interrupted { .. },
            ) => {
                let parent_id = record
                    .permit
                    .binding
                    .parent_permit_id
                    .as_ref()
                    .ok_or_else(corrupt)?;
                if parent_id == &record.permit.permit_id {
                    return Err(corrupt());
                }
                // Read material first and demand the Control role BEFORE any
                // recursive validation, so hostile Effect cycles cannot recurse.
                let parent = self.read_record_material(parent_id)?;
                let Some(NormalChatAttemptRecordV2::Control { admission }) =
                    &parent.normal_chat_attempt_v2
                else {
                    return Err(corrupt());
                };
                self.validate_record_bindings(&parent)?;
                let (_, expected_effect) = build_attempt_permits(admission)?;
                let PermitStateV1::Consumed { consumed_at } = record.state else {
                    return Err(corrupt());
                };
                if record.permit != expected_effect
                    || !record.child_allocations.is_empty()
                    || record.preflight_receipt.is_none()
                {
                    return Err(corrupt());
                }
                if matches!(parent.state, PermitStateV1::Revoked { revoked_at, .. } if revoked_at < consumed_at)
                {
                    return Err(corrupt());
                }
                // Historical binding check only: current revocation never grants
                // retry; exact current checks are solely in fresh native Begin.
                validate_parent_permits(&record.permit, &parent.permit, true, consumed_at, None)?;
                match (&record.normal_chat_attempt_v2, &record.outcome_receipt) {
                    (
                        Some(NormalChatAttemptRecordV2::Effect {
                            settlement: Some(settlement),
                        }),
                        Some(outcome),
                    ) if settlement.outcome == *outcome => {
                        settlement.validate_for_attempt(&admission.reservation.attempt)?;
                    }
                    (Some(NormalChatAttemptRecordV2::Effect { settlement: None }), None) => {}
                    (Some(NormalChatAttemptRecordV2::Recovered { recovery }), None) => {
                        let proof = NormalChatLedgerAdmissionEvidenceV2 {
                            schema: NormalChatLedgerAdmissionSchemaV2::V2,
                            admission: admission.as_ref().clone(),
                            preflight: record.preflight_receipt.clone().ok_or_else(corrupt)?,
                        };
                        recovery.validate_for_admission_v1(&proof)?;
                    }
                    (Some(NormalChatAttemptRecordV2::Interrupted { recovery }), None) => {
                        let proof = NormalChatLedgerAdmissionEvidenceV2 {
                            schema: NormalChatLedgerAdmissionSchemaV2::V2,
                            admission: admission.as_ref().clone(),
                            preflight: record.preflight_receipt.clone().ok_or_else(corrupt)?,
                        };
                        recovery.validate_for_admission_v2(&proof)?;
                    }
                    _ => return Err(corrupt()),
                }
            }
            None => return Err(corrupt()),
        }
        Ok(())
    }
}

fn check_attempt_window(binding: &PermitBindingV1, now: DateTime<Utc>) -> Result<(), PolicyError> {
    if now < binding.issued_at || now < binding.not_before {
        return Err(NormalChatEgressDenialV1::Malformed.into());
    }
    if now >= binding.expires_at {
        return Err(NormalChatEgressDenialV1::GrantExpired.into());
    }
    Ok(())
}

pub(super) fn build_attempt_permits(
    admission: &NormalChatRetainedAdmissionV2,
) -> Result<(ExecutionPermitV1, ExecutionPermitV1), PolicyError> {
    admission
        .context
        .validate_reservation(&admission.reservation)?;
    let reservation = &admission.reservation;
    let attempt = &reservation.attempt;
    attempt.validate()?;
    let child = &reservation.child_control;
    let run_id = attempt.run_id()?;
    if child.request.child_run_id != run_id
        || child.request.parent_operation_id != attempt.session_run_id
        || child.request.root_operation_id != attempt.session_run_id
        || child.request.depth != 1
        || child.request.child_operation_digest != content_digest(attempt)?
        || !matches!(child.state, FamilyChildPermitStateV1::Issued)
        || child.request.requested_budget.max_wall_time_ms
            != attempt.operation.budget.max_wall_time_ms
    {
        return Err(PolicyError::PermitStateConflict);
    }
    let issued_at = reservation.reserved_at;
    let timeout = i64::try_from(attempt.operation.budget.max_wall_time_ms)
        .map_err(|_| PolicyError::PermitStateConflict)?;
    if timeout <= 0 || timeout > MAX_LIVE_LEASE_MILLISECONDS {
        return Err(PolicyError::PermitStateConflict);
    }
    let attempt_expiry = issued_at
        .checked_add_signed(chrono::TimeDelta::milliseconds(timeout))
        .ok_or(PolicyError::PermitStateConflict)?;
    let expires_at = std::cmp::min(
        attempt_expiry,
        admission.context.root_control.binding.expires_at,
    );
    if expires_at <= issued_at {
        return Err(PolicyError::PermitStateConflict);
    }
    let actor = admission.context.root_control.binding.actor.clone();
    let policy_version = attempt.operation.policy_basis_ref.clone();
    let budget = child.request.requested_budget.clone();
    let call = ToolCallSpecV1 {
        tool: NORMAL_CHAT_EFFECT_TOOL_V2.into(),
        args: serde_json::to_value(attempt)?,
        frozen_clock: None,
    };
    let effect_scope = EffectScopeV1 {
        scope_name: EFFECT_SCOPE_V2.into(),
        read_roots: Vec::new(),
        write_roots: Vec::new(),
        network_allowed: true,
    };
    let control_scope = EffectScopeV1 {
        scope_name: CONTROL_SCOPE_V2.into(),
        network_allowed: false,
        read_roots: Vec::new(),
        write_roots: Vec::new(),
    };
    let control_call = ToolCallSpecV1 {
        tool: CONTROL_TOOL_V2.into(),
        args: serde_json::to_value(admission)?,
        frozen_clock: None,
    };
    let control_binding = PermitBindingV1 {
        actor: actor.clone(),
        action_digest: content_digest(&control_call)?,
        effect_digest: content_digest(&control_scope)?,
        effect: control_scope,
        budget: budget.clone(),
        policy_version: policy_version.clone(),
        parent_permit_id: None,
        parent_operation_id: None,
        issued_at,
        not_before: issued_at,
        expires_at,
        run_id: run_id.clone(),
        step_id: recursive_agent_contracts::derive_step_id(
            &run_id,
            0,
            CONTROL_TOOL_V2,
            &control_call,
        )?,
        tool: CONTROL_TOOL_V2.into(),
        args_digest: content_digest(&control_call.args)?,
    };
    let ceiling = DelegationCeilingV1 {
        actor: actor.clone(),
        policy_version: policy_version.clone(),
        run_id: run_id.clone(),
        transition: DelegationTransitionV1::ControlToEffect,
        audiences: vec![NORMAL_CHAT_EFFECT_TOOL_V2.into()],
        actions: vec![DelegatedActionV1 {
            tool: NORMAL_CHAT_EFFECT_TOOL_V2.into(),
            action_digest: content_digest(&call)?,
            args_digest: content_digest(&call.args)?,
            effect_digest: content_digest(&effect_scope)?,
            effect: effect_scope.clone(),
            executable_authority: Vec::new(),
        }],
        budget: budget.clone(),
        not_before: issued_at,
        expires_at,
    };
    control_binding.validate()?;
    let control = ExecutionPermitV1::control(control_binding, ceiling)?;
    let binding = PermitBindingV1 {
        actor,
        action_digest: content_digest(&call)?,
        effect_digest: content_digest(&effect_scope)?,
        effect: effect_scope,
        budget,
        policy_version,
        parent_permit_id: Some(control.permit_id.clone()),
        parent_operation_id: Some(run_id.clone()),
        issued_at,
        not_before: issued_at,
        expires_at,
        step_id: recursive_agent_contracts::derive_step_id(
            &run_id,
            0,
            NORMAL_CHAT_EFFECT_TOOL_V2,
            &call,
        )?,
        run_id,
        tool: NORMAL_CHAT_EFFECT_TOOL_V2.into(),
        args_digest: content_digest(&call.args)?,
    };
    binding.validate()?;
    let purpose = PermitPurposeV1::Effect;
    let delegation_identity = Some(derive_delegation_identity(&control, &binding)?);
    let permit_id = derive_permit_id(&execution_identity_material(
        &binding,
        purpose,
        &None,
        &delegation_identity,
        &[],
    )?)?;
    let effect = ExecutionPermitV1 {
        permit_id,
        binding,
        purpose,
        delegation_ceiling: None,
        delegation_identity,
        executable_authority: Vec::new(),
    };
    Ok((control, effect))
}
