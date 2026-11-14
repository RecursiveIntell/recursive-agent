//! Native session-close prerequisite. This narrows existing admission only;
//! runtime child reconciliation and parent terminal receipts remain separate.
use super::*;

/// Historical close readback, not authority, a send continuation, or proof that
/// any child/parent ledger is terminal. Original charges and leases are retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalChatSessionCloseV2 {
    pub snapshot: NormalChatSessionSnapshotV2,
    pub root_control: PermitRecordV1,
}
/// Negative-test seam: interrupts publication, never grants or resumes authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalChatSessionCloseInterruptionV2 {
    FamilyClose(PermitTransitionStage),
    RootClose(PermitTransitionStage),
}
impl DurablePermitStore {
    /// Close a verified native pair against an exact current family snapshot.
    /// Family admission is persisted closed BEFORE revoking the root control.
    /// This is not a cross-store atomic transaction: errors may follow rename.
    /// Read back both canonical owners after error; never refund or recreate.
    ///
    /// `semantic_floor` constrains NEW timed transitions. Runtime must derive it
    /// from complete verified child/parent history. Already closed confirmation
    /// samples no clock and cannot rewrite either original closure timestamp.
    pub fn close_normal_chat_session_v2(
        &self,
        family: &FamilyAuthorityStore,
        context: &NormalChatGrantContextV2,
        expected: &NormalChatSessionSnapshotV2,
        semantic_floor: DateTime<Utc>,
        trusted_clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<NormalChatSessionCloseV2, PolicyError> {
        self.close_normal_chat_session_v2_with_interruption(
            family,
            context,
            expected,
            semantic_floor,
            trusted_clock,
            None,
        )
    }
    #[doc(hidden)]
    pub fn close_normal_chat_session_v2_with_interruption(
        &self,
        family: &FamilyAuthorityStore,
        context: &NormalChatGrantContextV2,
        expected: &NormalChatSessionSnapshotV2,
        semantic_floor: DateTime<Utc>,
        mut trusted_clock: impl FnMut() -> DateTime<Utc>,
        fault: Option<NormalChatSessionCloseInterruptionV2>,
    ) -> Result<NormalChatSessionCloseV2, PolicyError> {
        // Reject cross-root compositions before waiting on either owner lock.
        if self.run_root_identity() != family.root_identity() {
            return Err(PolicyError::PermitStateConflict);
        }
        // Suffix of native Begin's child -> family -> root order. Do not call
        // public lock-taking getters/setters from inside either owner lock.
        family.with_lock(|| {
            self.with_lock(|| {
                let mut state = family.read_state()?;
                require_context(self, family, context, &state)?;
                if snapshot_from_state_v2(&state)? != *expected {
                    return Err(PolicyError::PermitStateConflict);
                }
                let mut record = root_record(self, context)?;
                let session = state
                    .normal_chat_session
                    .as_ref()
                    .ok_or(NormalChatEgressDenialV1::GrantMissing)?;
                if session.closed_at.is_none() {
                    let at = trusted_clock();
                    require_close_time(&state, &record, semantic_floor, at)?;
                    // The callback may delete/replace state. Never republish a
                    // cached authority record after that trusted-time sample.
                    require_unchanged(self, family, context, &state, &record)?;
                    state
                        .normal_chat_session
                        .as_mut()
                        .ok_or(NormalChatEgressDenialV1::GrantMissing)?
                        .closed_at = Some(at);
                    let point = match fault {
                        Some(NormalChatSessionCloseInterruptionV2::FamilyClose(stage)) => {
                            Some(stage)
                        }
                        _ => None,
                    };
                    family.write_state_with_interruption(&state, point)?;
                } else {
                    family.root.sync_all()?;
                    fail_directory_sync(fault, true)?;
                }
                require_unchanged(self, family, context, &state, &record)?;
                if matches!(record.state, PermitStateV1::Issued) {
                    let at = trusted_clock();
                    require_close_time(&state, &record, semantic_floor, at)?;
                    require_unchanged(self, family, context, &state, &record)?;
                    record.state = PermitStateV1::Revoked {
                        revoked_at: at,
                        reason: if state.parent_revoked_at.is_some() {
                            PermitRevocationReasonV1::ParentRevoked
                        } else {
                            PermitRevocationReasonV1::Operator
                        },
                    };
                    let point = match fault {
                        Some(NormalChatSessionCloseInterruptionV2::RootClose(stage)) => Some(stage),
                        _ => None,
                    };
                    self.replace_record(&record, point)?;
                } else {
                    // Preserve ANY existing revocation reason and timestamp. This
                    // is require-existing durability confirmation, not revoke retry.
                    self.root.sync_all()?;
                    fail_directory_sync(fault, false)?;
                }
                confirm_closed_pair_locked(self, family, context, &state, &record, None)
            })
        })
    }
    /// Confirm ONLY an already-closed canonical pair. This API has no clock,
    /// write/revoke branch, grant enrollment or authority reconstruction. The
    /// expected root record (including revocation reason/time) is exact.
    pub fn confirm_closed_normal_chat_session_v2(
        &self,
        family: &FamilyAuthorityStore,
        context: &NormalChatGrantContextV2,
        expected: &NormalChatSessionCloseV2,
    ) -> Result<NormalChatSessionCloseV2, PolicyError> {
        self.confirm_closed_normal_chat_session_v2_with_interruption(
            family, context, expected, None,
        )
    }
    #[doc(hidden)]
    pub fn confirm_closed_normal_chat_session_v2_with_interruption(
        &self,
        family: &FamilyAuthorityStore,
        context: &NormalChatGrantContextV2,
        expected: &NormalChatSessionCloseV2,
        fault: Option<NormalChatSessionCloseInterruptionV2>,
    ) -> Result<NormalChatSessionCloseV2, PolicyError> {
        // Reject an invalid/cross-root composition before waiting on a lock.
        if self.run_root_identity() != family.root_identity()
            || expected.snapshot.admission.closed_at.is_none()
            || !matches!(expected.root_control.state, PermitStateV1::Revoked { .. })
            || expected.root_control.permit != context.root_control
            || !matches!(
                fault,
                None | Some(NormalChatSessionCloseInterruptionV2::FamilyClose(
                    PermitTransitionStage::DirectoryFsync
                )) | Some(NormalChatSessionCloseInterruptionV2::RootClose(
                    PermitTransitionStage::DirectoryFsync
                ))
            )
        {
            return Err(PolicyError::PermitStateConflict);
        }
        family.with_lock(|| {
            self.with_lock(|| {
                let state = family.read_state()?;
                require_context(self, family, context, &state)?;
                let record = root_record(self, context)?;
                if snapshot_from_state_v2(&state)? != expected.snapshot
                    || record != expected.root_control
                {
                    return Err(PolicyError::PermitStateConflict);
                }
                confirm_closed_pair_locked(self, family, context, &state, &record, fault)
            })
        })
    }
}
// Both canonical owner locks are held by the caller. The timed close and the
// historical-only API share exact readback/durability semantics, not creation.
fn confirm_closed_pair_locked(
    store: &DurablePermitStore,
    family: &FamilyAuthorityStore,
    context: &NormalChatGrantContextV2,
    state: &FamilyAuthorityStateV1,
    record: &PermitRecordV1,
    fault: Option<NormalChatSessionCloseInterruptionV2>,
) -> Result<NormalChatSessionCloseV2, PolicyError> {
    if state
        .normal_chat_session
        .as_ref()
        .and_then(|s| s.closed_at)
        .is_none()
        || !matches!(record.state, PermitStateV1::Revoked { .. })
    {
        return Err(PolicyError::PermitStateConflict);
    }
    require_unchanged(store, family, context, state, record)?;
    family.root.sync_all()?;
    fail_directory_sync(fault, true)?;
    store.root.sync_all()?;
    fail_directory_sync(fault, false)?;
    require_unchanged(store, family, context, state, record)?;
    Ok(NormalChatSessionCloseV2 {
        snapshot: snapshot_from_state_v2(state)?,
        root_control: record.clone(),
    })
}
fn root_record(
    store: &DurablePermitStore,
    context: &NormalChatGrantContextV2,
) -> Result<PermitRecordV1, PolicyError> {
    store.validate_v2_child_locator()?;
    let mut records = store.read_governed_permit_records()?;
    if records.len() != 1 {
        return Err(PolicyError::PermitStateConflict);
    }
    let record = records.pop().ok_or(PolicyError::PermitStateConflict)?;
    if !matches!(
        record.state,
        PermitStateV1::Issued | PermitStateV1::Revoked { .. }
    ) {
        return Err(PolicyError::PermitStateConflict);
    }
    let mut original = context.session_root_issued_record_v2()?;
    original.state = record.state.clone();
    if original != record {
        return Err(PolicyError::PermitStateConflict);
    }
    // Reuse the canonical evidence owner for terminal-time and control/ceiling
    // validation; exact persisted bytes alone are not semantic validity.
    PermitEvidenceV1::from_record(&record)?;
    store.validate_v2_child_locator()?;
    Ok(record)
}
fn require_context(
    store: &DurablePermitStore,
    family: &FamilyAuthorityStore,
    context: &NormalChatGrantContextV2,
    state: &FamilyAuthorityStateV1,
) -> Result<(), PolicyError> {
    if store.run_root_identity() != family.root_identity()
        || state.grant != context.session_family_grant_v2()?
    {
        return Err(PolicyError::PermitStateConflict);
    }
    let session = state
        .normal_chat_session
        .as_ref()
        .ok_or(NormalChatEgressDenialV1::GrantMissing)?;
    if session.grant != context.grant
        || session.conversation_ref != context.session.conversation_ref
    {
        return Err(PolicyError::PermitStateConflict);
    }
    store.validate_v2_child_locator()?;
    Ok(())
}
fn require_unchanged(
    store: &DurablePermitStore,
    family: &FamilyAuthorityStore,
    context: &NormalChatGrantContextV2,
    state: &FamilyAuthorityStateV1,
    record: &PermitRecordV1,
) -> Result<(), PolicyError> {
    if family.read_state()? != *state || root_record(store, context)? != *record {
        return Err(PolicyError::PermitStateConflict);
    }
    require_context(store, family, context, state)
}
fn require_close_time(
    state: &FamilyAuthorityStateV1,
    record: &PermitRecordV1,
    semantic_floor: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), PolicyError> {
    let session = state
        .normal_chat_session
        .as_ref()
        .ok_or(NormalChatEgressDenialV1::GrantMissing)?;
    let mut floor = std::cmp::max(semantic_floor, record.permit.binding.issued_at);
    floor = std::cmp::max(floor, record.permit.binding.not_before);
    floor = std::cmp::max(floor, session.opened_at);
    for at in [session.closed_at, state.parent_revoked_at]
        .into_iter()
        .flatten()
    {
        floor = std::cmp::max(floor, at);
    }
    for reservation in session.reservations.values() {
        floor = std::cmp::max(floor, reservation.reserved_at);
    }
    if let PermitStateV1::Revoked { revoked_at, .. } = record.state {
        floor = std::cmp::max(floor, revoked_at);
    }
    if now < floor {
        return Err(NormalChatEgressDenialV1::Malformed.into());
    }
    Ok(())
}
fn fail_directory_sync(
    selected: Option<NormalChatSessionCloseInterruptionV2>,
    family: bool,
) -> Result<(), PolicyError> {
    let point = if family {
        NormalChatSessionCloseInterruptionV2::FamilyClose(PermitTransitionStage::DirectoryFsync)
    } else {
        NormalChatSessionCloseInterruptionV2::RootClose(PermitTransitionStage::DirectoryFsync)
    };
    if selected == Some(point) {
        return Err(PolicyError::InjectedInterruption(
            PermitTransitionStage::DirectoryFsync,
        ));
    }
    Ok(())
}
