//! Runtime-owned, root-only governed-session bootstrap. No child/send authority
//! or terminal-success claim is exposed. Nonempty families require the later
//! runtime reconciler rather than being reopened as an empty session.
use super::{RuntimeService, RuntimeServiceError};
use crate::PinnedRunRoot;
use recursive_agent_contracts::{
    content_digest, jcs_canonical, ArtifactDescriptorV1, ContentDigest, CurrentRunId,
    NormalChatSessionV1, ReceiptKindV1, ReceiptOutcomeV1,
};
use recursive_agent_ledger::{
    appendable_snapshot_expected_run_from_dir_fd, make_receipt, open_from_dir_fd, AppendStage,
    ChainHandle, ReceiptDraftV1, RunPaths,
};
use recursive_agent_policy::{
    build_lineage, DurablePermitStore, FamilyAuthorityStore, NormalChatEgressDenialV1,
    NormalChatGrantAuthorityV1, NormalChatSessionAdmissionReadbackV1, PermitEvidenceV1,
    PermitRecordV1,
};
use rustix::fs::{Mode, OFlags};
use std::fs::File;
use std::path::Path;

/// Private correlation and last-verified-prefix information only. This handle
/// cannot issue a child or send a provider request; it is not terminal evidence.
///
/// ```compile_fail
/// use recursive_agent_runner::RuntimeNormalChatSessionV1;
/// fn forge() -> RuntimeNormalChatSessionV1 { RuntimeNormalChatSessionV1 {} }
/// ```
/// ```compile_fail
/// use recursive_agent_runner::RuntimeNormalChatSessionV1;
/// fn send(handle: RuntimeNormalChatSessionV1) { handle.submit_child(); }
/// ```
pub struct RuntimeNormalChatSessionV1 {
    pub(super) pinned: PinnedRunRoot,
    pub(super) session: NormalChatSessionV1,
    pub(super) run_id: CurrentRunId,
    pub(super) verified_head: ContentDigest,
}
impl RuntimeNormalChatSessionV1 {
    pub fn session(&self) -> &NormalChatSessionV1 {
        &self.session
    }
    pub fn run_id(&self) -> &CurrentRunId {
        &self.run_id
    }
    pub fn run_dir(&self) -> &Path {
        &self.pinned.locator
    }
    /// Head verified at bootstrap return, never a claim about later mutations.
    pub fn verified_prefix_head(&self) -> &ContentDigest {
        &self.verified_head
    }
}

/// Test-only interruption selections; none can skip a required boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalChatSessionBootstrapInterruptionV1 {
    AfterControl,
    AfterFamily,
    AfterIdentityArtifact,
    Receipt { ordinal: usize, stage: AppendStage },
    BeforeRelease,
}

fn recovery(reason: &'static str) -> RuntimeServiceError {
    RuntimeServiceError::NormalChatSessionRecoveryRequired { reason }
}

// Error projection only: the ledger owner holds and validates the single gate.
pub(super) struct SessionGate(recursive_agent_ledger::NormalChatSessionGateV1);
fn gate_error(error: recursive_agent_ledger::NormalChatSessionGateErrorV1) -> RuntimeServiceError {
    use recursive_agent_ledger::NormalChatSessionGateErrorV1 as E;
    match error {
        E::Busy => RuntimeServiceError::NormalChatSessionBusy,
        E::Unsafe => recovery("unsafe runtime session gate"),
        E::LocatorChanged => recovery("runtime session gate locator changed"),
        E::RootMismatch => recovery("runtime session gate root differs"),
        E::Root(error) => error.into(),
        E::Io(error) => error.into(),
    }
}
impl SessionGate {
    pub(super) fn acquire(root: &File) -> Result<Self, RuntimeServiceError> {
        recursive_agent_ledger::NormalChatSessionGateV1::acquire(root)
            .map(Self)
            .map_err(gate_error)
    }
    pub(super) fn acquire_existing(root: &File) -> Result<Self, RuntimeServiceError> {
        recursive_agent_ledger::NormalChatSessionGateV1::acquire_existing(root)
            .map(Self)
            .map_err(gate_error)
    }
    pub(super) fn ledger_guard(&self) -> &recursive_agent_ledger::NormalChatSessionGateV1 {
        &self.0
    }
    pub(super) fn check(&self, root: &File) -> Result<(), RuntimeServiceError> {
        self.0.check(root).map_err(gate_error)
    }
    pub(super) fn unlock(self) -> Result<(), RuntimeServiceError> {
        self.0.unlock().map_err(gate_error)
    }
}

fn existing_family(root: &File) -> Result<bool, RuntimeServiceError> {
    match rustix::fs::openat(
        root,
        "family-authority.json",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => {
            if !File::from(fd).metadata()?.is_file() {
                return Err(recovery("family state is not a regular file"));
            }
            Ok(true)
        }
        Err(error) if error == rustix::io::Errno::NOENT => Ok(false),
        Err(error) => Err(std::io::Error::from(error).into()),
    }
}
fn has_artifact_history(root: &File) -> Result<bool, RuntimeServiceError> {
    let fd = rustix::fs::openat(
        root,
        "artifacts",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let entries = rustix::fs::Dir::read_from(&fd).map_err(std::io::Error::from)?;
    for entry in entries {
        let entry = entry.map_err(std::io::Error::from)?;
        if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
            return Ok(true);
        }
    }
    Ok(false)
}
fn empty_open_family(
    view: &NormalChatSessionAdmissionReadbackV1,
    record: &PermitRecordV1,
) -> Result<(), RuntimeServiceError> {
    if view.run_id != record.permit.binding.run_id
        || view.control_permit_id != record.permit.permit_id
    {
        return Err(recovery("family does not bind canonical session control"));
    }
    if view.closed_at.is_some() || view.parent_revoked_at.is_some() {
        return Err(RuntimeServiceError::Policy(
            NormalChatEgressDenialV1::RunClosed.into(),
        ));
    }
    if view.reservation_count != 0 {
        return Err(recovery("session has unreconciled reservations"));
    }
    Ok(())
}
fn interrupt_at(
    selected: Option<NormalChatSessionBootstrapInterruptionV1>,
    point: NormalChatSessionBootstrapInterruptionV1,
) -> Result<(), RuntimeServiceError> {
    if selected == Some(point) {
        return Err(RuntimeServiceError::NormalChatSessionBootstrapInterrupted);
    }
    Ok(())
}

impl RuntimeService {
    /// Startup-owned authority injection only. It is not an IPC grant loader or
    /// an implicit provider/backend selection. Absence remains default-deny.
    pub fn with_normal_chat_egress_grant(mut self, authority: NormalChatGrantAuthorityV1) -> Self {
        self.normal_chat_grant = Some(authority);
        self
    }
    /// Bootstrap one root session's accounting parent and verified start prefix.
    /// This explicit root-only API cannot claim an unverified subagent parent.
    pub fn open_normal_chat_session(
        &self,
        conversation_ref: &str,
    ) -> Result<RuntimeNormalChatSessionV1, RuntimeServiceError> {
        self.open_normal_chat_session_with_interruption(conversation_ref, None)
    }
    #[doc(hidden)]
    pub fn open_normal_chat_session_with_interruption(
        &self,
        conversation_ref: &str,
        interruption: Option<NormalChatSessionBootstrapInterruptionV1>,
    ) -> Result<RuntimeNormalChatSessionV1, RuntimeServiceError> {
        let authority = self
            .normal_chat_grant
            .as_ref()
            .ok_or(RuntimeServiceError::NormalChatGovernanceDisabled)?;
        let session = authority.normal_chat_session(conversation_ref, None)?;
        let run_id = session.run_id()?;
        if matches!(
            interruption,
            Some(
                NormalChatSessionBootstrapInterruptionV1::Receipt { ordinal: 3.., .. }
                    | NormalChatSessionBootstrapInterruptionV1::Receipt {
                        stage: AppendStage::ArtifactWrite,
                        ..
                    }
            )
        ) {
            return Err(recovery("invalid native bootstrap interruption selection"));
        }
        let key = content_digest(&run_id)?.to_string();
        let pinned = PinnedRunRoot::open(self.dependencies.output_root(), &key)?;
        pinned.ensure_locator_matches()?;
        let gate = SessionGate::acquire(&pinned.root)?;
        let result = self.bootstrap_normal_chat_locked(
            &pinned,
            &gate,
            authority,
            &session,
            &run_id,
            interruption,
        );
        let unlock = gate.unlock();
        let verified_head = match (result, unlock) {
            (Ok(head), Ok(())) => head,
            (Err(error), _) | (Ok(_), Err(error)) => return Err(error),
        };
        pinned.ensure_locator_matches()?;
        Ok(RuntimeNormalChatSessionV1 {
            pinned,
            session,
            run_id,
            verified_head,
        })
    }

    fn bootstrap_normal_chat_locked(
        &self,
        pinned: &PinnedRunRoot,
        gate: &SessionGate,
        authority: &NormalChatGrantAuthorityV1,
        session: &NormalChatSessionV1,
        run_id: &CurrentRunId,
        interruption: Option<NormalChatSessionBootstrapInterruptionV1>,
    ) -> Result<ContentDigest, RuntimeServiceError> {
        gate.check(&pinned.root)?;
        pinned.ensure_locator_matches()?;
        let mut chain = open_from_dir_fd(&RunPaths::new(&pinned.locator), &pinned.root)?;
        if chain.length() > 3 {
            return Err(recovery("session has non-bootstrap ledger history"));
        }
        if chain.length() > 0 {
            appendable_snapshot_expected_run_from_dir_fd(&pinned.root, run_id)?;
        }
        let permits = DurablePermitStore::from_run_root_fd(&pinned.root)?;
        let previous = permits.read_normal_chat_session_control_record()?;
        let family_exists = existing_family(&pinned.root)?;
        if previous.is_none()
            && (chain.length() > 0 || family_exists || has_artifact_history(&pinned.root)?)
        {
            return Err(recovery(
                "canonical control absent alongside retained history",
            ));
        }
        if chain.length() > 0 && !family_exists {
            return Err(recovery("canonical family absent alongside ledger history"));
        }
        let control = if let Some(expected) = &previous {
            permits.require_existing_normal_chat_session_control(
                authority,
                &session.conversation_ref,
                None,
                expected,
                || self.dependencies.clock().now(),
            )?
        } else {
            permits.open_normal_chat_session_control(
                authority,
                &session.conversation_ref,
                None,
                || self.dependencies.clock().now(),
            )?
        };
        interrupt_at(
            interruption,
            NormalChatSessionBootstrapInterruptionV1::AfterControl,
        )?;
        let _guarded = FamilyAuthorityStore::from_normal_chat_session_control(
            &pinned.root,
            authority,
            &control,
            || self.dependencies.clock().now(),
        )?;
        let family = FamilyAuthorityStore::from_dir_fd(&pinned.root, control.family_grant())?;
        let record = permits
            .read_normal_chat_session_control_record()?
            .ok_or_else(|| recovery("control disappeared during bootstrap"))?;
        empty_open_family(&family.read_normal_chat_session_admission()?, &record)?;
        interrupt_at(
            interruption,
            NormalChatSessionBootstrapInterruptionV1::AfterFamily,
        )?;
        let store = chain.artifact_store()?;
        if chain.run_root_identity() != pinned.identity
            || store.run_root_identity() != pinned.identity
            || permits.run_root_identity() != (pinned.identity.device, pinned.identity.inode)
        {
            return Err(crate::RunError::SplitRunRoot.into());
        }
        let identity = store.put(&jcs_canonical(session)?, "application/json", None)?;
        let issued = store.put(
            &jcs_canonical(&PermitEvidenceV1::from_record(&record)?)?,
            "application/json",
            None,
        )?;
        interrupt_at(
            interruption,
            NormalChatSessionBootstrapInterruptionV1::AfterIdentityArtifact,
        )?;
        ensure_bootstrap_prefix(
            &mut chain,
            &pinned.root,
            &record,
            &identity,
            &issued,
            interruption,
        )?;
        chain.sync_all()?;
        // Finish the run-directory entry's durability under the existing owner.
        crate::open_directory_tree(self.dependencies.output_root(), false)?.sync_all()?;
        let rechecked = permits.require_existing_normal_chat_session_control(
            authority,
            &session.conversation_ref,
            None,
            &record,
            || self.dependencies.clock().now(),
        )?;
        if rechecked.permit() != control.permit()
            || permits.read_normal_chat_session_control_record()?.as_ref() != Some(&record)
        {
            return Err(recovery("canonical control changed during bootstrap"));
        }
        empty_open_family(&family.read_normal_chat_session_admission()?, &record)?;
        let verified = appendable_snapshot_expected_run_from_dir_fd(&pinned.root, run_id)?;
        if verified.receipts().len() != 3
            || verified.verification().final_head != chain.head().to_string()
        {
            return Err(recovery("bootstrap verification changed expected prefix"));
        }
        interrupt_at(
            interruption,
            NormalChatSessionBootstrapInterruptionV1::BeforeRelease,
        )?;
        gate.check(&pinned.root)?;
        pinned.ensure_locator_matches()?;
        Ok(chain.head().clone())
    }
}

fn bootstrap_drafts(
    record: &PermitRecordV1,
    identity: &ArtifactDescriptorV1,
    issued: &ArtifactDescriptorV1,
) -> Vec<ReceiptDraftV1> {
    let binding = &record.permit.binding;
    [
        (ReceiptKindV1::RunStarted, vec![identity.clone()]),
        (ReceiptKindV1::StepStarted, vec![]),
        (ReceiptKindV1::PermitIssued, vec![issued.clone()]),
    ]
    .into_iter()
    .map(|(kind, artifact_refs)| ReceiptDraftV1 {
        run_id: binding.run_id.clone(),
        step_id: binding.step_id.clone(),
        kind,
        valid_time: binding.issued_at,
        lineage: build_lineage(&record.permit.permit_id, &binding.policy_version),
        spec_digest: binding.action_digest.clone(),
        args_digest: binding.args_digest.clone(),
        artifact_refs,
        outcome: ReceiptOutcomeV1::Ok,
    })
    .collect()
}
/// Pure retained-prefix comparison; this cannot append missing history.
pub(super) fn verify_bootstrap_prefix(
    rows: &[recursive_agent_contracts::ReceiptV1],
    record: &PermitRecordV1,
    identity: &ArtifactDescriptorV1,
    issued: &ArtifactDescriptorV1,
) -> Result<(), RuntimeServiceError> {
    if rows.len() < 3 {
        return Err(recovery("incomplete retained bootstrap prefix"));
    }
    for (draft, actual) in bootstrap_drafts(record, identity, issued)
        .into_iter()
        .zip(rows)
    {
        let mut expected = make_receipt(draft, actual.prev_chain_digest.clone())?;
        expected.recorded_time = actual.recorded_time;
        if expected.canonical_bytes()? != actual.canonical_bytes()? {
            return Err(recovery(
                "retained bootstrap receipt conflicts with exact draft",
            ));
        }
    }
    Ok(())
}

pub(super) fn ensure_bootstrap_prefix(
    chain: &mut ChainHandle,
    root: &File,
    record: &PermitRecordV1,
    identity: &ArtifactDescriptorV1,
    issued: &ArtifactDescriptorV1,
    interruption: Option<NormalChatSessionBootstrapInterruptionV1>,
) -> Result<(), RuntimeServiceError> {
    let binding = &record.permit.binding;
    let previous = if chain.length() == 0 {
        Vec::new()
    } else {
        appendable_snapshot_expected_run_from_dir_fd(root, &binding.run_id)?
            .receipts()
            .to_vec()
    };
    for (ordinal, draft) in bootstrap_drafts(record, identity, issued)
        .into_iter()
        .enumerate()
    {
        let predecessor = previous
            .get(ordinal)
            .map_or_else(|| chain.head().clone(), |old| old.prev_chain_digest.clone());
        let mut receipt = make_receipt(draft, predecessor)?;
        if let Some(existing) = previous.get(ordinal) {
            receipt.recorded_time = existing.recorded_time;
            if receipt.canonical_bytes()? != existing.canonical_bytes()? {
                return Err(recovery(
                    "retained bootstrap receipt conflicts with exact draft",
                ));
            }
        } else {
            let fault = match interruption {
                Some(NormalChatSessionBootstrapInterruptionV1::Receipt {
                    ordinal: selected,
                    stage,
                }) if selected == ordinal => Some(stage),
                _ => None,
            };
            chain.append_with_interruption(receipt, fault)?;
        }
    }
    Ok(())
}
