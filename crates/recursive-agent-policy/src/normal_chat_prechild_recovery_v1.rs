//! Native terminal reconciliation for a pre-child prefix after complete siblings.
//! No reservation or child is created. Legacy ambiguous linked/missing children
//! remain quarantined; the new runtime bootstrap checkpoint proves eligible absence.
use super::*;
use recursive_agent_contracts::{
    ArtifactDescriptorV1, NormalChatCallRequestV2, ReceiptKindV1, ReceiptOutcomeV1, ReceiptV1,
};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatPrechildRecoverySchemaV1 {
    #[serde(rename = "recursive-agent.normal-chat-prechild-recovery/v1")]
    V1,
    #[serde(rename = "recursive-agent.normal-chat-prechild-recovery/v2")]
    WithSiblingsV2,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatPrechildRecoveryRecordV1 {
    pub schema: NormalChatPrechildRecoverySchemaV1,
    pub context: NormalChatGrantContextV2,
    pub request: NormalChatCallRequestV2,
    pub reservation: Option<NormalChatFamilyReservationV2>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prior_reservations: Vec<NormalChatFamilyReservationV2>,
    pub parent_prefix: Vec<ReceiptV1>,
    pub retained_artifacts: Vec<ArtifactDescriptorV1>,
    pub observed_at: DateTime<Utc>,
    pub recovery_digest: ContentDigest,
}
impl NormalChatPrechildRecoveryRecordV1 {
    pub fn computed_digest(&self) -> Result<ContentDigest, PolicyError> {
        if self.prior_reservations.is_empty() {
            return Ok(content_digest(&(
                self.schema,
                &self.context,
                &self.request,
                &self.reservation,
                &self.parent_prefix,
                &self.retained_artifacts,
                self.observed_at,
            ))?);
        }
        Ok(content_digest(&(
            self.schema,
            &self.context,
            &self.request,
            &self.reservation,
            &self.prior_reservations,
            &self.parent_prefix,
            &self.retained_artifacts,
            self.observed_at,
        ))?)
    }
    pub fn validate(&self) -> Result<(), PolicyError> {
        use recursive_agent_contracts::{
            derive_child_receipt_step_id, validate_receipt_sequence, LifecycleValidationMode,
        };
        self.context.session_root_issued_record_v2()?;
        self.request.validate()?;
        let rows = &self.parent_prefix;
        let root = &self.context.root_control;
        let preparation = self.request.preparation_digest()?;
        let base = 3 + 3 * self.prior_reservations.len();
        if (self.schema == NormalChatPrechildRecoverySchemaV1::WithSiblingsV2)
            != !self.prior_reservations.is_empty()
            || !(base..=base + 2).contains(&rows.len())
            || self.request.operation.parent_run_id != self.context.session.run_id()?
            || self.request.operation.conversation_ref != self.context.session.conversation_ref
            || self.recovery_digest != self.computed_digest()?
            || rows.iter().any(|r| r.valid_time > self.observed_at)
            || rows[0].kind != ReceiptKindV1::RunStarted
            || rows[1].kind != ReceiptKindV1::StepStarted
            || rows[2].kind != ReceiptKindV1::PermitIssued
        {
            return Err(PolicyError::PermitStateConflict);
        }
        validate_receipt_sequence(rows, LifecycleValidationMode::AppendInProgress)?;
        for row in &rows[..3] {
            if row.run_id != root.binding.run_id
                || row.step_id != root.binding.step_id
                || row.lineage != build_lineage(&root.permit_id, &root.binding.policy_version)
                || row.spec_digest != root.binding.action_digest
                || row.args_digest != root.binding.args_digest
                || row.valid_time != root.binding.issued_at
                || row.outcome != ReceiptOutcomeV1::Ok
            {
                return Err(PolicyError::PermitStateConflict);
            }
        }
        let mut seen = BTreeSet::new();
        let mut sibling_floor = root.binding.issued_at;
        for (group, reservation) in rows[3..base].chunks_exact(3).zip(&self.prior_reservations) {
            self.context.validate_reservation(reservation)?;
            let digest = NormalChatCallRequestV2::from_attempt(&reservation.attempt)?
                .preparation_digest()?;
            if !seen.insert(reservation.attempt.dispatch_intent_ref.clone())
                || reservation.attempt.dispatch_intent_ref == self.request.dispatch_intent_ref
                || group[0].receipt_id
                    != reservation
                        .child_control
                        .request
                        .parent_admission_receipt_id
                || group[0].args_digest != digest
                || group[0].spec_digest != digest
                || group[1].spec_digest != content_digest(&reservation.attempt)?
                || group[2].spec_digest != group[1].spec_digest
                || group[0].valid_time < sibling_floor
                || group[0].valid_time > reservation.reserved_at
                || group[1].valid_time < reservation.reserved_at
                || group[2].valid_time < group[1].valid_time
            {
                return Err(PolicyError::PermitStateConflict);
            }
            for (row, kind, phase) in [
                (
                    &group[0],
                    ReceiptKindV1::ChildAdmissionPrepared,
                    "admission",
                ),
                (&group[1], ReceiptKindV1::ChildLinked, "link"),
                (&group[2], ReceiptKindV1::ChildClosed, "closure"),
            ] {
                if row.kind != kind
                    || row.args_digest != digest
                    || row.run_id != root.binding.run_id
                    || row.lineage != build_lineage(&root.permit_id, &root.binding.policy_version)
                    || row.step_id
                        != derive_child_receipt_step_id(&root.binding.run_id, &digest, phase)?
                    || row.outcome != ReceiptOutcomeV1::Ok
                {
                    return Err(PolicyError::PermitStateConflict);
                }
            }
            sibling_floor = std::cmp::max(sibling_floor, group[2].valid_time);
        }
        if rows.len() > base {
            let row = &rows[base];
            if row.kind != ReceiptKindV1::ChildAdmissionPrepared
                || row.step_id
                    != derive_child_receipt_step_id(
                        &root.binding.run_id,
                        &preparation,
                        "admission",
                    )?
                || row.spec_digest != preparation
                || row.args_digest != preparation
                || !row.artifact_refs.is_empty()
                || row.lineage != build_lineage(&root.permit_id, &root.binding.policy_version)
                || row.outcome != ReceiptOutcomeV1::Ok
                || row.valid_time < sibling_floor
            {
                return Err(PolicyError::PermitStateConflict);
            }
        }
        match &self.reservation {
            Some(reservation) => {
                self.context.validate_reservation(reservation)?;
                if NormalChatCallRequestV2::from_attempt(&reservation.attempt)? != self.request
                    || rows.len() <= base
                    || reservation
                        .child_control
                        .request
                        .parent_admission_receipt_id
                        != rows[base].receipt_id
                    || rows[base].valid_time > reservation.reserved_at
                    || reservation.reserved_at > self.observed_at
                {
                    return Err(PolicyError::PermitStateConflict);
                }
                if rows.len() == base + 2 {
                    let row = &rows[base + 1];
                    if row.kind != ReceiptKindV1::ChildLinked
                        || row.step_id
                            != derive_child_receipt_step_id(
                                &root.binding.run_id,
                                &preparation,
                                "link",
                            )?
                        || row.spec_digest != content_digest(&reservation.attempt)?
                        || row.args_digest != preparation
                        || row.artifact_refs.len() != 1
                        || row.lineage
                            != build_lineage(&root.permit_id, &root.binding.policy_version)
                        || row.outcome != ReceiptOutcomeV1::Ok
                        || row.valid_time < reservation.reserved_at
                    {
                        return Err(PolicyError::PermitStateConflict);
                    }
                }
            }
            None if rows.len() <= base + 1 => {}
            None => return Err(PolicyError::PermitStateConflict),
        }
        let bytes = jcs_canonical(&self.request)?;
        let request = ArtifactDescriptorV1 {
            owner_id: recursive_agent_contracts::derive_artifact_id(&bytes)?,
            digest: ContentDigest::compute(&bytes),
            byte_length: bytes.len() as u64,
            media_type: "application/json".into(),
            encoding: None,
        };
        if !self.retained_artifacts.contains(&request) || jcs_canonical(self)?.len() > 131072 {
            return Err(PolicyError::PermitStateConflict);
        }
        Ok(())
    }
}
impl FamilyAuthorityStore {
    pub(crate) fn mark_normal_chat_child_root_started_v1(
        &self,
        intent: &str,
        at: DateTime<Utc>,
    ) -> Result<(), PolicyError> {
        self.with_lock(|| {
            let mut state = self.read_state()?;
            let session = state
                .normal_chat_session
                .as_mut()
                .ok_or(PolicyError::PermitStateConflict)?;
            if !session.allows_dispatch_at(at) {
                return Err(PolicyError::PermitStateConflict);
            }
            let stored = session
                .reservations
                .get_mut(intent)
                .ok_or(PolicyError::PermitStateConflict)?;
            if !matches!(
                stored.bootstrap,
                Some(NormalChatChildBootstrapV1::ParentReserved { .. })
            ) {
                return Err(PolicyError::PermitStateConflict);
            }
            stored.bootstrap = Some(NormalChatChildBootstrapV1::ChildRootStarted {
                schema: NormalChatChildBootstrapSchemaV1::V1,
                at,
            });
            state
                .normal_chat_session
                .as_ref()
                .ok_or(PolicyError::PermitStateConflict)?
                .validate(&state)?;
            self.write_state(&state)
        })
    }
    /// Historical context discovery from the canonical family and root permit.
    /// This returns no grant authority, guarded control or continuation.
    pub fn require_existing_normal_chat_history_context_v1(
        root: &File,
        session: &recursive_agent_contracts::NormalChatSessionV1,
    ) -> Result<(Self, NormalChatGrantContextV2), PolicyError> {
        let fd = secure_open_at(
            root,
            FAMILY_STATE_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?;
        let file = File::from(fd);
        if !file.metadata()?.is_file() || file.metadata()?.len() > MAX_FAMILY_STATE_BYTES {
            return Err(PolicyError::PermitStateConflict);
        }
        let mut bytes = Vec::new();
        file.take(MAX_FAMILY_STATE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_FAMILY_STATE_BYTES {
            return Err(PolicyError::PermitStateConflict);
        }
        let value = recursive_agent_contracts::parse_strict_json_value(&bytes)
            .map_err(|_| PolicyError::PermitStateConflict)?;
        let material: FamilyAuthorityStateV1 = serde_json::from_value(value)?;
        if jcs_canonical(&material)? != bytes {
            return Err(PolicyError::PermitStateConflict);
        }
        let family = Self::require_existing_from_dir_fd(root, material.grant.clone())?;
        let context = family.with_lock(|| {
            let state = family.read_state()?;
            if state != material {
                return Err(PolicyError::PermitStateConflict);
            }
            let retained = state
                .normal_chat_session
                .as_ref()
                .ok_or(PolicyError::PermitStateConflict)?;
            let policy = DurablePermitStore::require_existing_from_run_root_fd(root)?;
            let control = policy
                .read_normal_chat_session_control_record()?
                .ok_or(PolicyError::PermitStateConflict)?;
            let context = NormalChatGrantContextV2 {
                grant: retained.grant.clone(),
                session: session.clone(),
                root_control: control.permit,
            };
            if context.session_family_grant_v2()? != state.grant
                || session.conversation_ref != retained.conversation_ref
            {
                return Err(PolicyError::PermitStateConflict);
            }
            Ok(context)
        })?;
        Ok((family, context))
    }
    pub fn read_normal_chat_prechild_recovery_v1(
        &self,
    ) -> Result<Option<NormalChatPrechildRecoveryRecordV1>, PolicyError> {
        self.with_lock(|| {
            let state = self.read_state()?;
            Ok(state
                .normal_chat_session
                .ok_or(PolicyError::PermitStateConflict)?
                .prechild_recovery
                .map(|r| *r))
        })
    }
    /// Runtime supplies canonical complete sibling proof; no reservation is created.
    pub fn recover_prechild_normal_chat_admission_v1(
        &self,
        context: &NormalChatGrantContextV2,
        request: &NormalChatCallRequestV2,
        prefix: &[ReceiptV1],
        artifacts: &[ArtifactDescriptorV1],
        mut clock: impl FnMut() -> DateTime<Utc>,
        fault: Option<PermitTransitionStage>,
    ) -> Result<NormalChatPrechildRecoveryRecordV1, PolicyError> {
        if prefix.len() < 3 {
            return Err(PolicyError::PermitStateConflict);
        }
        self.with_lock(|| {
            let mut state = self.read_state()?;
            let session = state
                .normal_chat_session
                .as_ref()
                .ok_or(PolicyError::PermitStateConflict)?;
            if let Some(old) = &session.prechild_recovery {
                if old.context != *context
                    || old.request != *request
                    || old.parent_prefix != prefix
                    || old.retained_artifacts != artifacts
                {
                    return Err(PolicyError::PermitStateConflict);
                }
                self.root.sync_all()?;
                return Ok(old.as_ref().clone());
            }
            if context.session_family_grant_v2()? != state.grant || context.grant != session.grant {
                return Err(PolicyError::PermitStateConflict);
            }
            let prior_count = prefix[3..]
                .chunks_exact(3)
                .take_while(|g| g[2].kind == ReceiptKindV1::ChildClosed)
                .count();
            let base = 3 + prior_count * 3;
            let mut prior_reservations = Vec::new();
            for group in prefix[3..base].chunks_exact(3) {
                let candidates = session
                    .reservations
                    .values()
                    .map(|r| reservation_readback(&state, r))
                    .collect::<Result<Vec<_>, _>>()?;
                let reservation = candidates
                    .into_iter()
                    .find(|r| {
                        r.child_control.request.parent_admission_receipt_id == group[0].receipt_id
                    })
                    .ok_or(PolicyError::PermitStateConflict)?;
                prior_reservations.push(reservation);
            }
            let reservation = match session.reservations.get(&request.dispatch_intent_ref) {
                Some(stored) => {
                    if matches!(
                        stored.bootstrap,
                        Some(
                            NormalChatChildBootstrapV1::ChildRootStarted { .. }
                                | NormalChatChildBootstrapV1::ChildStorageReady { .. }
                        )
                    ) || (prefix.len() == base + 2
                        && !matches!(
                            stored.bootstrap,
                            Some(NormalChatChildBootstrapV1::ParentReserved { .. })
                        ))
                    {
                        return Err(PolicyError::PermitStateConflict);
                    }
                    Some(reservation_readback(&state, stored)?)
                }
                None => None,
            };
            if prior_reservations.len() + usize::from(reservation.is_some())
                != session.reservations.len()
            {
                return Err(PolicyError::PermitStateConflict);
            }
            let at = clock();
            if at < session.opened_at
                || session.closed_at.is_some_and(|t| at < t)
                || state.parent_revoked_at.is_some_and(|t| at < t)
            {
                return Err(PolicyError::PermitStateConflict);
            }
            let mut recovery = NormalChatPrechildRecoveryRecordV1 {
                schema: if prior_reservations.is_empty() {
                    NormalChatPrechildRecoverySchemaV1::V1
                } else {
                    NormalChatPrechildRecoverySchemaV1::WithSiblingsV2
                },
                context: context.clone(),
                request: request.clone(),
                reservation,
                prior_reservations,
                parent_prefix: prefix.to_vec(),
                retained_artifacts: artifacts.to_vec(),
                observed_at: at,
                recovery_digest: ContentDigest::compute(b"uncommitted"),
            };
            recovery.recovery_digest = recovery.computed_digest()?;
            recovery.validate()?;
            let final_at = clock();
            if final_at < at || self.read_state()? != state {
                return Err(PolicyError::PermitStateConflict);
            }
            let session = state
                .normal_chat_session
                .as_mut()
                .ok_or(PolicyError::PermitStateConflict)?;
            if session.closed_at.is_none() {
                session.closed_at = Some(at);
            }
            session.prechild_recovery = Some(Box::new(recovery.clone()));
            state
                .normal_chat_session
                .as_ref()
                .ok_or(PolicyError::PermitStateConflict)?
                .validate(&state)?;
            self.write_state_with_interruption(&state, fault)?;
            if self.read_state()? != state {
                return Err(PolicyError::PermitStateConflict);
            }
            Ok(recovery)
        })
    }
}
