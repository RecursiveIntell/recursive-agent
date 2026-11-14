//! File-grant-bound, network-denying session controls in the permit owner.
//!
//! Neither the root binding nor its delegation actions permits network effects.
//! Routes live in grant/accounting state. A future child-local effect gate must
//! freshly check the exact request; this root and its evidence cannot substitute.

use super::*;
use recursive_agent_contracts::{NormalChatSessionSchemaV1, NormalChatSessionV1};

pub(super) const SESSION_CONTROL_TOOL: &str = "normal_chat_session_control";
const SESSION_CONTROL_SCOPE: &str = "normal-chat-session-accounting/v1";
/// These ceilings cover local accounting metadata, not provider response bytes
/// or a conversion from model tokens into bytes.
pub const NORMAL_CHAT_SESSION_METADATA_BYTES_PER_ATTEMPT: u64 = 1024 * 1024;

impl NormalChatGrantAuthorityV1 {
    /// Construct nonauthorizing identity from this loaded grant. No caller grant
    /// revision, home digest, caps, routes, or policy digest is accepted.
    pub fn normal_chat_session(
        &self,
        conversation_ref: &str,
        parent_session_run_id: Option<CurrentRunId>,
    ) -> Result<NormalChatSessionV1, PolicyError> {
        let grant = self.grant();
        let session = NormalChatSessionV1 {
            schema: NormalChatSessionSchemaV1::V1,
            conversation_ref: conversation_ref.into(),
            parent_session_run_id,
            ares_home_digest: grant.ares_home_digest.clone(),
            grant_revision: grant.revision,
            policy_basis_digest: grant.policy_digest.clone(),
        };
        session.validate()?;
        Ok(session)
    }
}

/// Current native capability, not serializable and never minted from a receipt.
/// Every authority-bearing use rechecks the canonical permit record.
#[derive(Clone)]
pub struct ValidatedNormalChatSessionControlV1 {
    store: DurablePermitStore,
    grant: NormalChatEgressGrantV1,
    session: NormalChatSessionV1,
    permit: ExecutionPermitV1,
    family: FamilyRootGrantV1,
}
impl ValidatedNormalChatSessionControlV1 {
    pub fn session(&self) -> &NormalChatSessionV1 {
        &self.session
    }
    pub fn permit(&self) -> &ExecutionPermitV1 {
        &self.permit
    }
    pub fn family_grant(&self) -> FamilyRootGrantV1 {
        self.family.clone()
    }

    fn check_current(
        &self,
        authority: &NormalChatGrantAuthorityV1,
        trusted_clock: &mut dyn FnMut() -> DateTime<Utc>,
    ) -> Result<DateTime<Utc>, PolicyError> {
        if authority.grant() != &self.grant {
            return Err(NormalChatEgressDenialV1::Malformed.into());
        }
        self.store.with_lock(|| {
            let before = trusted_clock();
            let record = self.store.read_record_or_reject(&self.permit.permit_id)?;
            if record.permit != self.permit {
                return Err(PolicyError::PermitStateConflict);
            }
            let now = trusted_clock();
            if now < before || before < authority.loaded_at() {
                return Err(NormalChatEgressDenialV1::Malformed.into());
            }
            validate_control_time_and_state(&record, now)?;
            Ok(now)
        })
    }
}

impl DurablePermitStore {
    /// Issue or reopen exactly one root control in this dedicated run root.
    /// Clock sampling is inside the process/thread lock and repeated immediately
    /// before publication. Reopen preserves the original lease, never renews it.
    pub fn open_normal_chat_session_control(
        &self,
        authority: &NormalChatGrantAuthorityV1,
        conversation_ref: &str,
        parent_session_run_id: Option<CurrentRunId>,
        trusted_clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<ValidatedNormalChatSessionControlV1, PolicyError> {
        self.session_control_checked(
            authority,
            conversation_ref,
            parent_session_run_id,
            None,
            trusted_clock,
        )
    }

    /// Validate only an exact existing canonical record against the loaded
    /// grant. Missing, replaced, revoked or expired authority is never recreated.
    /// The expected projection restricts comparison; it cannot authorize itself.
    pub fn require_existing_normal_chat_session_control(
        &self,
        authority: &NormalChatGrantAuthorityV1,
        conversation_ref: &str,
        parent_session_run_id: Option<CurrentRunId>,
        expected: &PermitRecordV1,
        trusted_clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<ValidatedNormalChatSessionControlV1, PolicyError> {
        self.session_control_checked(
            authority,
            conversation_ref,
            parent_session_run_id,
            Some(expected),
            trusted_clock,
        )
    }

    fn session_control_checked(
        &self,
        authority: &NormalChatGrantAuthorityV1,
        conversation_ref: &str,
        parent_session_run_id: Option<CurrentRunId>,
        required: Option<&PermitRecordV1>,
        mut trusted_clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<ValidatedNormalChatSessionControlV1, PolicyError> {
        let session = authority.normal_chat_session(conversation_ref, parent_session_run_id)?;
        self.with_lock(|| {
            self.validate_v2_child_locator()?;
            self.reject_legacy_context_admission()?;
            let now = trusted_clock();
            if now < authority.loaded_at() {
                return Err(NormalChatEgressDenialV1::Malformed.into());
            }
            if now >= authority.grant().expires_at {
                return Err(NormalChatEgressDenialV1::GrantExpired.into());
            }
            let existing = self.read_session_control_record()?;
            if required.is_some_and(|expected| existing.as_ref() != Some(expected)) {
                return Err(PolicyError::PermitStateConflict);
            }
            let issued_at = existing
                .as_ref()
                .map_or(now, |record| record.permit.binding.issued_at);
            let (permit, family) = build_session_control(authority.grant(), &session, issued_at)?;
            if let Some(record) = &existing {
                if record.permit != permit {
                    return Err(PolicyError::PermitStateConflict);
                }
                validate_control_time_and_state(record, now)?;
            }
            let final_now = trusted_clock();
            if final_now < now || final_now < authority.loaded_at() {
                return Err(NormalChatEgressDenialV1::Malformed.into());
            }
            if final_now >= permit.binding.expires_at {
                return Err(NormalChatEgressDenialV1::GrantExpired.into());
            }
            if existing.is_none() {
                let record = PermitRecordV1 {
                    permit: permit.clone(),
                    state: PermitStateV1::Issued,
                    child_allocations: BTreeMap::new(),
                    preflight_receipt: None,
                    outcome_receipt: None,
                    retained_normal_chat_admission: None,
                    normal_chat_settlement: None,
                    normal_chat_attempt_v2: None,
                };
                // Uses the canonical record/evidence writer, not a second store.
                self.replace_record(&record, None)?;
            } else {
                // Finish an earlier potentially uncertain post-rename commit.
                self.root.sync_all()?;
            }
            let release_now = trusted_clock();
            if release_now < final_now {
                return Err(NormalChatEgressDenialV1::Malformed.into());
            }
            let reread = self.read_record_or_reject(&permit.permit_id)?;
            if reread.permit != permit || required.is_some_and(|expected| &reread != expected) {
                return Err(PolicyError::PermitStateConflict);
            }
            validate_control_time_and_state(&reread, release_now)?;
            self.validate_v2_child_locator()?;
            Ok(ValidatedNormalChatSessionControlV1 {
                store: self.clone(),
                grant: authority.grant().clone(),
                session: session.clone(),
                permit,
                family,
            })
        })
    }

    /// Historical record projection only, never current authority or a native
    /// continuation. A missing record alongside ledger history requires runtime
    /// recovery; it is not permission to issue a replacement control.
    pub fn read_normal_chat_session_control_record(
        &self,
    ) -> Result<Option<PermitRecordV1>, PolicyError> {
        self.with_lock(|| {
            self.validate_v2_child_locator()?;
            let record = self.read_session_control_record()?;
            self.validate_v2_child_locator()?;
            Ok(record)
        })
    }

    /// Descriptor-relative, bounded discovery of the canonical record. This is
    /// not an index or authority pointer. Ambiguous/mixed/corrupt roots reject.
    fn read_session_control_record(&self) -> Result<Option<PermitRecordV1>, PolicyError> {
        let mut records = self.read_governed_permit_records()?;
        if records.len() > 1 {
            return Err(PolicyError::PermitStateConflict);
        }
        let record = records.pop();
        if record.as_ref().is_some_and(|record| {
            record.permit.binding.tool != SESSION_CONTROL_TOOL
                || record.permit.purpose != PermitPurposeV1::Control
        }) {
            return Err(PolicyError::PermitStateConflict);
        }
        Ok(record)
    }

    // Shared descriptor-relative material loader for the closed governed lanes.
    // It validates canonical records, but never mints authority from their hashes.
    pub(super) fn read_governed_permit_records(&self) -> Result<Vec<PermitRecordV1>, PolicyError> {
        let entries =
            rustix::fs::Dir::read_from(self.root.as_fd()).map_err(std::io::Error::from)?;
        let mut found = Vec::new();
        for (index, entry) in entries.enumerate() {
            if index >= 4096 {
                return Err(PolicyError::PermitStateConflict);
            }
            let entry = entry.map_err(std::io::Error::from)?;
            let name = entry.file_name().to_bytes();
            if !name.starts_with(b"permit-") || !name.ends_with(b".json") {
                continue;
            }
            let name = std::str::from_utf8(name).map_err(|_| PolicyError::PermitStateConflict)?;
            let fd = secure_open_at(
                &self.root,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )?;
            let mut file = File::from(fd);
            let metadata = file.metadata()?;
            if !metadata.is_file()
                || metadata.len() > MAX_PERMIT_RECORD_BYTES
                || metadata.uid() != rustix::process::getuid().as_raw()
                || metadata.mode() & 0o777 != 0o600
            {
                return Err(PolicyError::PermitStateConflict);
            }
            let mut bytes = Vec::new();
            (&mut file)
                .take(MAX_PERMIT_RECORD_BYTES + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_PERMIT_RECORD_BYTES {
                return Err(PolicyError::PermitStateConflict);
            }
            let value = recursive_agent_contracts::parse_strict_json_value(&bytes)
                .map_err(|_| PolicyError::PermitStateConflict)?;
            let record: PermitRecordV1 = serde_json::from_value(value)?;
            super::normal_chat_ledger_v2::validate_governed_record_wire(&bytes, &record)?;
            self.validate_record_bindings(&record)?;
            if state_name(&record.permit.permit_id)? != name
                || derive_permit_id(&record.permit.identity_material()?)? != record.permit.permit_id
            {
                return Err(PolicyError::PermitStateConflict);
            }
            found.push(record);
        }
        found.sort_by(|left, right| left.permit.permit_id.cmp(&right.permit.permit_id));
        Ok(found)
    }
}

fn validate_control_time_and_state(
    record: &PermitRecordV1,
    now: DateTime<Utc>,
) -> Result<(), PolicyError> {
    if !matches!(record.state, PermitStateV1::Issued) {
        return Err(NormalChatEgressDenialV1::RunClosed.into());
    }
    if now < record.permit.binding.issued_at || now < record.permit.binding.not_before {
        return Err(NormalChatEgressDenialV1::Malformed.into());
    }
    if now >= record.permit.binding.expires_at {
        return Err(NormalChatEgressDenialV1::GrantExpired.into());
    }
    Ok(())
}

fn build_session_control(
    grant: &NormalChatEgressGrantV1,
    session: &NormalChatSessionV1,
    issued_at: DateTime<Utc>,
) -> Result<(ExecutionPermitV1, FamilyRootGrantV1), PolicyError> {
    let actor =
        ActorPrincipalV1::try_new(format!("ares:uid:{}", rustix::process::getuid().as_raw()))?;
    expected_session_control(grant, session, issued_at, actor)
}

/// Pure historical identity transform; native issuance always enters through
/// build_session_control above with the current filesystem owner's UID.
pub(super) fn expected_session_control(
    grant: &NormalChatEgressGrantV1,
    session: &NormalChatSessionV1,
    issued_at: DateTime<Utc>,
    actor: ActorPrincipalV1,
) -> Result<(ExecutionPermitV1, FamilyRootGrantV1), PolicyError> {
    let spelling = actor
        .as_str()
        .strip_prefix("ares:uid:")
        .ok_or(PolicyError::PermitStateConflict)?;
    let uid = spelling
        .parse::<u32>()
        .map_err(|_| PolicyError::PermitStateConflict)?;
    if uid.to_string() != spelling {
        return Err(PolicyError::PermitStateConflict);
    }
    grant.validate_at(&session.ares_home_digest, issued_at)?;
    session.validate()?;
    if session.grant_revision != grant.revision
        || session.policy_basis_digest != grant.policy_digest
    {
        return Err(PolicyError::PermitStateConflict);
    }
    let run_id = session.run_id()?;
    let maximum_expiry = issued_at
        .checked_add_signed(chrono::TimeDelta::milliseconds(MAX_LIVE_LEASE_MILLISECONDS))
        .ok_or(PolicyError::PermitStateConflict)?;
    let expires_at = std::cmp::min(maximum_expiry, grant.expires_at);
    let attempts = u64::from(grant.caps.max_attempts);
    let budget = PermitBudgetV1 {
        max_wall_time_ms: attempts
            .checked_mul(grant.caps.max_wall_time_ms)
            .ok_or(PolicyError::PermitStateConflict)?,
        max_output_bytes: attempts
            .checked_mul(NORMAL_CHAT_SESSION_METADATA_BYTES_PER_ATTEMPT)
            .ok_or(PolicyError::PermitStateConflict)?,
        max_artifact_bytes: attempts
            .checked_mul(NORMAL_CHAT_SESSION_METADATA_BYTES_PER_ATTEMPT)
            .ok_or(PolicyError::PermitStateConflict)?,
    };
    let effect = EffectScopeV1 {
        scope_name: SESSION_CONTROL_SCOPE.into(),
        read_roots: Vec::new(),
        write_roots: Vec::new(),
        network_allowed: false,
    };
    let call = ToolCallSpecV1 {
        tool: SESSION_CONTROL_TOOL.into(),
        args: serde_json::to_value(session)?,
        frozen_clock: None,
    };

    let policy_version = format!("normal-chat-grant:revision-{}", grant.revision);
    let binding = PermitBindingV1 {
        actor: actor.clone(),
        action_digest: content_digest(&call)?,
        effect: effect.clone(),
        effect_digest: content_digest(&effect)?,
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
            SESSION_CONTROL_TOOL,
            &call,
        )?,
        tool: SESSION_CONTROL_TOOL.into(),
        args_digest: content_digest(&call.args)?,
    };
    // This action is accounting-only. In particular it must NEVER use the
    // network-enabled normal-chat effect scope or encode routes as such actions.
    let ceiling = DelegationCeilingV1 {
        actor: actor.clone(),
        policy_version: policy_version.clone(),
        run_id: run_id.clone(),
        transition: DelegationTransitionV1::ControlToEffect,
        audiences: vec![NORMAL_CHAT_LANE.into()],
        actions: vec![DelegatedActionV1 {
            tool: NORMAL_CHAT_LANE.into(),
            action_digest: content_digest(&(SESSION_CONTROL_SCOPE, session))?,
            args_digest: content_digest(session)?,
            effect: effect.clone(),
            effect_digest: content_digest(&effect)?,
            executable_authority: Vec::new(),
        }],
        budget: budget.clone(),
        not_before: issued_at,
        expires_at,
    };
    binding.validate()?;
    let permit = ExecutionPermitV1::control(binding, ceiling)?;
    let family = FamilyRootGrantV1 {
        root_operation_id: run_id,
        parent_control_permit_id: permit.permit_id.clone(),
        actor,
        policy_version,
        effect_budget: budget.clone(),
        child_run_ceiling: ChildRunCeilingV1 {
            max_depth: 1,
            max_children: grant.caps.max_attempts,
            family_budget: budget,
            not_before: issued_at,
            expires_at,
        },
    };
    Ok((permit, family))
}

/// Native guarded view over existing canonical stores; no independent counters,
/// permit database, implicit authority recovery, or serialization constructor.
#[derive(Clone)]
pub struct NormalChatControlledFamilyV1 {
    family: FamilyAuthorityStore,
    control: ValidatedNormalChatSessionControlV1,
    pinned_root: Arc<File>,
}
impl NormalChatControlledFamilyV1 {
    /// Association-only proof over a real current control and exact pinned
    /// family. Hold existing mutation locks while the funding owner publishes
    /// topology metadata. Never used to mint a long-lived execution parent.
    pub(crate) fn with_campaign_root_witness<T>(
        &self,
        authority: &NormalChatGrantAuthorityV1,
        clock: &mut dyn FnMut() -> DateTime<Utc>,
        inspect: impl FnOnce(
            CampaignFamilyAnchorV1,
            &mut dyn FnMut() -> DateTime<Utc>,
        ) -> Result<T, PolicyError>,
    ) -> Result<T, PolicyError> {
        if authority.grant() != &self.control.grant {
            return Err(PolicyError::PermitStateConflict);
        }
        self.family.with_lock(|| {
            self.control.store.with_lock(|| {
                let root = directory_identity(&self.pinned_root)?;
                let permits = secure_open_at(
                    &self.pinned_root,
                    "permits",
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?;
                let permit_root = directory_identity(&File::from(permits))?;
                if (root.0, root.1) != self.family.root_identity()
                    || (root.0, root.1)
                        != (
                            self.control.store.run_root_device,
                            self.control.store.run_root_inode,
                        )
                    || (permit_root.0, permit_root.1)
                        != (
                            self.control.store.permit_root_device,
                            self.control.store.permit_root_inode,
                        )
                {
                    return Err(PolicyError::PermitStateConflict);
                }
                let check = |at: DateTime<Utc>| -> Result<(), PolicyError> {
                    if at < authority.loaded_at() {
                        return Err(NormalChatEgressDenialV1::Malformed.into());
                    }
                    self.control.store.validate_v2_child_locator()?;
                    let record = self
                        .control
                        .store
                        .read_record_or_reject(&self.control.permit.permit_id)?;
                    if record.permit != self.control.permit {
                        return Err(PolicyError::PermitStateConflict);
                    }
                    validate_control_time_and_state(&record, at)?;
                    let state = self.family.read_state()?;
                    let session = state
                        .normal_chat_session
                        .as_ref()
                        .ok_or(NormalChatEgressDenialV1::GrantMissing)?;
                    if state.grant != self.control.family
                        || state.parent_revoked_at.is_some()
                        || !session
                            .matches_context(authority, &self.control.session.conversation_ref)
                        || !session.allows_dispatch_at(at)
                    {
                        return Err(PolicyError::PermitStateConflict);
                    }
                    Ok(())
                };
                let before = clock();
                check(before)?;
                let result = inspect(
                    CampaignFamilyAnchorV1 {
                        family_grant: self.control.family.clone(),
                        session: self.control.session.clone(),
                        family_root_device: root.0,
                        family_root_inode: root.1,
                        permit_root_device: permit_root.0,
                        permit_root_inode: permit_root.1,
                    },
                    clock,
                );
                let after = clock();
                if after < before {
                    return Err(NormalChatEgressDenialV1::Malformed.into());
                }
                check(after)?;
                result
            })
        })
    }

    pub fn checkpoint_normal_chat_child_storage_v1(
        &self,
        intent: &str,
        child: &File,
        at: DateTime<Utc>,
    ) -> Result<(), PolicyError> {
        self.family
            .checkpoint_normal_chat_child_storage_v1(intent, child, at)
    }
    /// Durable runtime bootstrap checkpoint before any child-root creation. No
    /// counters/lease/permit change; absence in legacy records is not no-send.
    pub fn mark_normal_chat_child_root_started_v1(
        &self,
        authority: &NormalChatGrantAuthorityV1,
        intent: &str,
        mut clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<(), PolicyError> {
        self.current_reservation_for_begin_v2(authority, intent, &mut clock)?;
        self.family
            .mark_normal_chat_child_root_started_v1(intent, clock())
    }

    /// Release linearizes with child -> family -> root-policy locks held. Every
    /// relevant revocation/close writer uses one of these canonical locks. A
    /// later close cannot revoke an already released attempt retroactively.
    /// Downstream locks may block; only the runtime admission gate is nonblocking.
    pub(super) fn with_runtime_release_fence_v2<T>(
        &self,
        authority: &NormalChatGrantAuthorityV1,
        admission: &NormalChatRetainedAdmissionV2,
        floor: DateTime<Utc>,
        expected_family: &NormalChatSessionSnapshotV2,
        clock: &mut dyn FnMut() -> DateTime<Utc>,
        inspect_child: impl FnOnce(DateTime<Utc>) -> Result<T, PolicyError>,
    ) -> Result<T, PolicyError> {
        if self.retained_grant_context_v2() != admission.context
            || authority.grant() != &self.control.grant
        {
            return Err(PolicyError::PermitStateConflict);
        }
        self.family.with_lock(|| {
            self.control.store.with_lock(|| {
                let before = clock();
                if before < floor || before < authority.loaded_at() {
                    return Err(NormalChatEgressDenialV1::Malformed.into());
                }
                self.control.store.validate_v2_child_locator()?;
                let now = clock();
                if now < before {
                    return Err(NormalChatEgressDenialV1::Malformed.into());
                }
                // Read AFTER the final trusted clock sample under all mutation locks.
                let record = self
                    .control
                    .store
                    .read_record_or_reject(&self.control.permit.permit_id)?;
                if record.permit != self.control.permit {
                    return Err(PolicyError::PermitStateConflict);
                }
                validate_control_time_and_state(&record, now)?;
                let state = self.family.read_state()?;
                let session = state
                    .normal_chat_session
                    .as_ref()
                    .ok_or(NormalChatEgressDenialV1::GrantMissing)?;
                if state.grant != self.control.family
                    || normal_chat_family::snapshot_from_state_v2(&state)? != *expected_family
                    || state.parent_revoked_at.is_some()
                    || !session.matches_context(authority, &self.control.session.conversation_ref)
                    || !session.allows_dispatch_at(now)
                    || normal_chat_family::reservation_from_state_v2(
                        &state,
                        &admission.reservation.attempt.dispatch_intent_ref,
                    )? != admission.reservation
                    || !matches!(
                        admission.reservation.child_control.state,
                        FamilyChildPermitStateV1::Issued
                    )
                {
                    return Err(PolicyError::PermitStateConflict);
                }
                authority.check_attempt(&admission.reservation.attempt, now)?;
                self.control.store.validate_v2_child_locator()?;
                inspect_child(now)
            })
        })
    }

    pub(super) fn retained_grant_context_v2(&self) -> NormalChatGrantContextV2 {
        NormalChatGrantContextV2 {
            grant: self.control.grant.clone(),
            session: self.control.session.clone(),
            root_control: self.control.permit.clone(),
        }
    }
    pub(super) fn policy_root_identities_v2(&self) -> ((u64, u64), (u64, u64)) {
        (
            (
                self.control.store.run_root_device,
                self.control.store.run_root_inode,
            ),
            (
                self.control.store.permit_root_device,
                self.control.store.permit_root_inode,
            ),
        )
    }

    pub(super) fn current_reservation_for_begin_v2(
        &self,
        authority: &NormalChatGrantAuthorityV1,
        intent: &str,
        clock: &mut dyn FnMut() -> DateTime<Utc>,
    ) -> Result<(NormalChatFamilyReservationV2, DateTime<Utc>), PolicyError> {
        let before = self.check_current(authority, clock)?;
        let reservation = self
            .family
            .read_normal_chat_reservation(intent)?
            .ok_or(NormalChatEgressDenialV1::Malformed)?;
        if reservation.attempt.session_run_id != self.control.session.run_id()?
            || reservation.child_control.request.parent_control_permit_id
                != self.control.permit.permit_id
        {
            return Err(PolicyError::PermitStateConflict);
        }
        self.family.guard_child_dispatch(
            &reservation.child_control.request.child_run_id,
            &reservation.child_control.child_control_permit_id,
            before,
        )?;
        let after = self.check_current(authority, clock)?;
        if after < before {
            return Err(NormalChatEgressDenialV1::Malformed.into());
        }
        authority.check_attempt(&reservation.attempt, after)?;
        Ok((reservation, self.control.permit.binding.expires_at))
    }

    fn check_current(
        &self,
        authority: &NormalChatGrantAuthorityV1,
        trusted_clock: &mut dyn FnMut() -> DateTime<Utc>,
    ) -> Result<DateTime<Utc>, PolicyError> {
        let root_identity = directory_identity(&self.pinned_root)?;
        let permits = secure_open_at(
            &self.pinned_root,
            "permits",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let identity = directory_identity(&File::from(permits))?;
        if (root_identity.0, root_identity.1)
            != (
                self.control.store.run_root_device,
                self.control.store.run_root_inode,
            )
            || (identity.0, identity.1)
                != (
                    self.control.store.permit_root_device,
                    self.control.store.permit_root_inode,
                )
        {
            return Err(PolicyError::PermitStateConflict);
        }
        self.family.with_lock(|| {
            if self.family.read_state()?.grant != self.control.family {
                return Err(PolicyError::PermitStateConflict);
            }
            Ok(())
        })?;
        self.control.check_current(authority, trusted_clock)
    }
    pub fn read_normal_chat_session_snapshot_v2(
        &self,
    ) -> Result<NormalChatSessionSnapshotV2, PolicyError> {
        self.family.read_normal_chat_session_snapshot_v2()
    }
    pub fn effect_budget(&self) -> Result<PermitBudgetV1, PolicyError> {
        self.family.effect_budget()
    }
    /// Nonauthorizing check under canonical policy ownership; no state is
    /// reserved and no preview identity can be used to dispatch.
    pub fn check_new_normal_chat_call(
        &self,
        authority: &NormalChatGrantAuthorityV1,
        call: &recursive_agent_contracts::NormalChatCallRequestV2,
        mut clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<(), PolicyError> {
        let before = self.check_current(authority, &mut clock)?;
        self.family
            .check_new_normal_chat_call(authority, call, &mut clock)?;
        if self.check_current(authority, &mut clock)? < before {
            return Err(NormalChatEgressDenialV1::Malformed.into());
        }
        Ok(())
    }
    pub fn reserve_normal_chat_attempt(
        &self,
        authority: &NormalChatGrantAuthorityV1,
        request: &NormalChatFamilyReservationRequestV2,
        mut trusted_clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<NormalChatFamilyReservationV2, PolicyError> {
        let now = self.check_current(authority, &mut trusted_clock)?;
        let reservation = self
            .family
            .reserve_normal_chat_attempt(authority, request, now)?;
        // A raced revocation keeps the charge but never promotes this result.
        let after = self.check_current(authority, &mut trusted_clock)?;
        if after < now {
            return Err(NormalChatEgressDenialV1::Malformed.into());
        }
        Ok(reservation)
    }
    pub fn read_normal_chat_reservation(
        &self,
        intent: &str,
    ) -> Result<Option<NormalChatFamilyReservationV2>, PolicyError> {
        self.family.read_normal_chat_reservation(intent)
    }
    /// Read-only reconciliation through canonical parent reservation identity.
    /// This intentionally works after revocation/expiry and never restores a
    /// native effect continuation or creates an admission.
    pub fn read_child_policy_v2(
        &self,
        child: &DurablePermitStore,
        intent: &str,
    ) -> Result<NormalChatAttemptReadbackV2, PolicyError> {
        child.read_normal_chat_attempt_v2(&self.family, intent)
    }
    pub fn guard_child_dispatch(
        &self,
        authority: &NormalChatGrantAuthorityV1,
        child: &CurrentRunId,
        control: &CurrentPermitId,
        mut trusted_clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<(), PolicyError> {
        let now = self.check_current(authority, &mut trusted_clock)?;
        self.family.guard_child_dispatch(child, control, now)?;
        let after = self.check_current(authority, &mut trusted_clock)?;
        if after < now {
            return Err(NormalChatEgressDenialV1::Malformed.into());
        }
        Ok(())
    }
}
impl FamilyAuthorityStore {
    /// Rebind only existing grant-bound accounting. Never use the initializing
    /// opener while verifying retained parent/child history.
    pub fn require_existing_normal_chat_session_family(
        root: &File,
        authority: &NormalChatGrantAuthorityV1,
        control: &ValidatedNormalChatSessionControlV1,
        mut clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<NormalChatControlledFamilyV1, PolicyError> {
        let family = Self::require_existing_from_dir_fd(root, control.family.clone())?;
        let guarded = NormalChatControlledFamilyV1 {
            family,
            control: control.clone(),
            pinned_root: Arc::new(root.try_clone()?),
        };
        guarded.check_current(authority, &mut clock)?;
        let state = guarded.family.with_lock(|| guarded.family.read_state())?;
        let session = state
            .normal_chat_session
            .as_ref()
            .ok_or(NormalChatEgressDenialV1::GrantMissing)?;
        if !session.matches_context(authority, &control.session.conversation_ref) {
            return Err(PolicyError::PermitStateConflict);
        }
        guarded.check_current(authority, &mut clock)?;
        Ok(guarded)
    }

    /// Bind accounting only from a current, native-issued session control on the
    /// exact same pinned run root. This does not issue a child effect permit.
    pub fn from_normal_chat_session_control(
        root: &File,
        authority: &NormalChatGrantAuthorityV1,
        control: &ValidatedNormalChatSessionControlV1,
        mut trusted_clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<NormalChatControlledFamilyV1, PolicyError> {
        let identity = directory_identity(root)?;
        if (identity.0, identity.1) != (control.store.run_root_device, control.store.run_root_inode)
        {
            return Err(PolicyError::PermitStateConflict);
        }
        let permits = secure_open_at(
            root,
            "permits",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let permit_identity = directory_identity(&File::from(permits))?;
        if (permit_identity.0, permit_identity.1)
            != (
                control.store.permit_root_device,
                control.store.permit_root_inode,
            )
        {
            return Err(PolicyError::PermitStateConflict);
        }
        let now = control.check_current(authority, &mut trusted_clock)?;
        let family = Self::open_normal_chat_session_from_grant(
            root,
            control.family.clone(),
            authority,
            &control.session.conversation_ref,
            now,
        )?;
        let guarded = NormalChatControlledFamilyV1 {
            family,
            control: control.clone(),
            pinned_root: Arc::new(root.try_clone()?),
        };
        let after = guarded.check_current(authority, &mut trusted_clock)?;
        if after < now {
            return Err(NormalChatEgressDenialV1::Malformed.into());
        }
        Ok(guarded)
    }
}
