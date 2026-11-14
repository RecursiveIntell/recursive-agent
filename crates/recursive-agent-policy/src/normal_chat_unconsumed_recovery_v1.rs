//! Canonical family-owned terminal observation when no child control committed.
//! A storage-ready checkpoint is mandatory; legacy ChildRootStarted is ambiguous.
use super::*;
use std::os::unix::fs::MetadataExt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatChildStorageCheckpointV1 {
    pub at: DateTime<Utc>,
    pub root: (u64, u64),
    pub permits: (u64, u64),
    pub artifacts: (u64, u64),
    pub receipts: (u64, u64),
}
impl NormalChatChildStorageCheckpointV1 {
    pub fn capture(root: &File, at: DateTime<Utc>) -> Result<Self, PolicyError> {
        fn identity(root: &File, name: &str, directory: bool) -> Result<(u64, u64), PolicyError> {
            let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
            let file = File::from(secure_open_at(
                root,
                name,
                if directory {
                    flags | OFlags::DIRECTORY
                } else {
                    flags
                },
                Mode::empty(),
            )?);
            let m = file.metadata()?;
            if directory != m.is_dir() || (!directory && !m.is_file()) {
                return Err(PolicyError::PermitStateConflict);
            }
            Ok((m.dev(), m.ino()))
        }
        let m = root.metadata()?;
        if !m.is_dir() {
            return Err(PolicyError::PermitStateConflict);
        }
        Ok(Self {
            at,
            root: (m.dev(), m.ino()),
            permits: identity(root, "permits", true)?,
            artifacts: identity(root, "artifacts", true)?,
            receipts: identity(root, "receipts.ndjson", false)?,
        })
    }
    pub fn check(&self, root: &File) -> Result<(), PolicyError> {
        if Self::capture(root, self.at)? != *self {
            return Err(PolicyError::PermitStateConflict);
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatUnconsumedRecoverySchemaV1 {
    #[serde(rename = "recursive-agent.normal-chat-unconsumed-recovery/v1")]
    V1,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatUnconsumedRecoveryRecordV1 {
    pub schema: NormalChatUnconsumedRecoverySchemaV1,
    pub context: NormalChatGrantContextV2,
    pub reservation: NormalChatFamilyReservationV2,
    pub checkpoint: NormalChatChildStorageCheckpointV1,
    pub started_at: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    pub recovery_digest: ContentDigest,
}
impl NormalChatUnconsumedRecoveryRecordV1 {
    pub fn computed_digest(&self) -> Result<ContentDigest, PolicyError> {
        Ok(content_digest(&(
            self.schema,
            &self.context,
            &self.reservation,
            &self.checkpoint,
            self.started_at,
            self.observed_at,
        ))?)
    }
    pub fn validate(&self) -> Result<(), PolicyError> {
        self.context.validate_reservation(&self.reservation)?;
        if self.recovery_digest != self.computed_digest()?
            || self.observed_at < self.checkpoint.at
            || self.started_at < self.reservation.reserved_at
            || self.checkpoint.at < self.started_at
        {
            return Err(PolicyError::PermitStateConflict);
        }
        Ok(())
    }
}
impl FamilyAuthorityStore {
    pub fn checkpoint_normal_chat_child_storage_v1(
        &self,
        intent: &str,
        child: &File,
        at: DateTime<Utc>,
    ) -> Result<(), PolicyError> {
        let checkpoint = NormalChatChildStorageCheckpointV1::capture(child, at)?;
        // Publish the family checkpoint only after all original child storage
        // entries are synced. History readback never recreates any of them.
        for name in ["permits", "artifacts"] {
            File::from(secure_open_at(
                child,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?)
            .sync_all()?;
        }
        child.sync_all()?;
        self.with_lock(|| {
            let mut state = self.read_state()?;
            let session = state.normal_chat_session.as_mut().ok_or(PolicyError::PermitStateConflict)?;
            let stored = session.reservations.get_mut(intent).ok_or(PolicyError::PermitStateConflict)?;
            if !matches!(stored.bootstrap,Some(NormalChatChildBootstrapV1::ChildRootStarted{at: started,..}) if started <= at) || session.closed_at.is_some() {
                return Err(PolicyError::PermitStateConflict);
            }
            let Some(NormalChatChildBootstrapV1::ChildRootStarted{at:started_at,..})=stored.bootstrap else {return Err(PolicyError::PermitStateConflict);};
            stored.bootstrap = Some(NormalChatChildBootstrapV1::ChildStorageReady {schema:NormalChatChildBootstrapSchemaV1::V1, started_at, checkpoint});
            state.normal_chat_session.as_ref().ok_or(PolicyError::PermitStateConflict)?.validate(&state)?;
            self.write_state(&state)
        })
    }
    pub fn read_normal_chat_unconsumed_recovery_v1(
        &self,
    ) -> Result<Option<NormalChatUnconsumedRecoveryRecordV1>, PolicyError> {
        self.with_lock(|| {
            Ok(self
                .read_state()?
                .normal_chat_session
                .ok_or(PolicyError::PermitStateConflict)?
                .unconsumed_recovery
                .map(|r| *r))
        })
    }
    pub fn require_normal_chat_child_checkpoint_v1(
        &self,
        intent: &str,
        child: &File,
    ) -> Result<NormalChatChildStorageCheckpointV1, PolicyError> {
        self.with_lock(|| {
            let state = self.read_state()?;
            let stored = state
                .normal_chat_session
                .as_ref()
                .and_then(|s| s.reservations.get(intent))
                .ok_or(PolicyError::PermitStateConflict)?;
            let Some(NormalChatChildBootstrapV1::ChildStorageReady { checkpoint, .. }) =
                &stored.bootstrap
            else {
                return Err(PolicyError::PermitStateConflict);
            };
            checkpoint.check(child)?;
            Ok(checkpoint.clone())
        })
    }
}
impl DurablePermitStore {
    /// Child lock -> family lock. No control/effect issue, consumption, report,
    /// lease or allocation is synthesized. Runtime proves the empty transcript.
    pub fn recover_unconsumed_normal_chat_attempt_v1(
        &self,
        family: &FamilyAuthorityStore,
        context: &NormalChatGrantContextV2,
        intent: &str,
        mut clock: impl FnMut() -> DateTime<Utc>,
        fault: Option<PermitTransitionStage>,
    ) -> Result<NormalChatUnconsumedRecoveryRecordV1, PolicyError> {
        if [
            self.run_root_identity(),
            (self.permit_root_device, self.permit_root_inode),
        ]
        .contains(&family.root_identity())
        {
            return Err(PolicyError::PermitStateConflict);
        }
        self.with_lock(|| {
            self.validate_v2_child_locator()?;
            if !self.read_governed_permit_records()?.is_empty() {
                return Err(PolicyError::PermitStateConflict);
            }
            family.with_lock(|| {
                let mut state = family.read_state()?;
                let session = state
                    .normal_chat_session
                    .as_ref()
                    .ok_or(PolicyError::PermitStateConflict)?;
                let stored = session
                    .reservations
                    .get(intent)
                    .ok_or(PolicyError::PermitStateConflict)?;
                let Some(NormalChatChildBootstrapV1::ChildStorageReady {
                    checkpoint,
                    started_at,
                    ..
                }) = &stored.bootstrap
                else {
                    return Err(PolicyError::PermitStateConflict);
                };
                checkpoint.check(&self.run_root)?;
                let reservation = reservation_readback(&state, stored)?;
                if context.session_family_grant_v2()? != state.grant
                    || context.grant != session.grant
                {
                    return Err(PolicyError::PermitStateConflict);
                }
                if let Some(old) = &session.unconsumed_recovery {
                    if old.context != *context
                        || old.reservation != reservation
                        || old.checkpoint != *checkpoint
                        || old.started_at != *started_at
                    {
                        return Err(PolicyError::PermitStateConflict);
                    }
                    family.root.sync_all()?;
                    return Ok(old.as_ref().clone());
                }
                let at = clock();
                if session.closed_at.is_some_and(|t| at < t)
                    || state.parent_revoked_at.is_some_and(|t| at < t)
                {
                    return Err(PolicyError::PermitStateConflict);
                }
                let mut record = NormalChatUnconsumedRecoveryRecordV1 {
                    schema: NormalChatUnconsumedRecoverySchemaV1::V1,
                    context: context.clone(),
                    reservation,
                    checkpoint: checkpoint.clone(),
                    started_at: *started_at,
                    observed_at: at,
                    recovery_digest: ContentDigest::compute(b"uncommitted"),
                };
                record.recovery_digest = record.computed_digest()?;
                record.validate()?;
                if clock() < at
                    || family.read_state()? != state
                    || !self.read_governed_permit_records()?.is_empty()
                {
                    return Err(PolicyError::PermitStateConflict);
                }
                record.checkpoint.check(&self.run_root)?;
                let session = state
                    .normal_chat_session
                    .as_mut()
                    .ok_or(PolicyError::PermitStateConflict)?;
                if session.closed_at.is_none() {
                    session.closed_at = Some(at);
                }
                session.unconsumed_recovery = Some(Box::new(record.clone()));
                state
                    .normal_chat_session
                    .as_ref()
                    .ok_or(PolicyError::PermitStateConflict)?
                    .validate(&state)?;
                family.write_state_with_interruption(&state, fault)?;
                self.validate_v2_child_locator()?;
                Ok(record)
            })
        })
    }
}
