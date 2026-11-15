//! Noncreating session correlation and historical attempt readback. No clock,
//! grant enrollment, reservation, continuation restoration or model call.
use super::normal_chat_attempt::{require_parent_history, require_parent_history_context};
use super::normal_chat_family_history::{reconcile_family, FamilyHistoryInputs};
use super::normal_chat_recovery_inspection::discover;
use super::normal_chat_session::SessionGate;
use super::{RuntimeNormalChatSessionV1, RuntimeService, RuntimeServiceError};
use crate::PinnedRunRoot;
use recursive_agent_contracts::{
    content_digest, jcs_canonical, parse_normal_chat_session_v1_bytes, parse_strict_json_value,
    ContentDigest, CurrentRunId, NormalChatCallRequestV2, ReceiptKindV1,
};
use recursive_agent_ledger::{
    open_existing_from_dir_fd, read_only_appendable_snapshot_expected_run_from_dir_fd,
    verify_degraded_normal_chat_session_from_runtime_root_fd, ArtifactStore, ChildRunLinkV1,
    LedgerError, RunPaths,
};
use recursive_agent_policy::{
    NormalChatAttemptReadbackV2, NormalChatGrantContextV2, NormalChatRecoveryRecordV1,
};

fn refused(reason: &'static str) -> RuntimeServiceError {
    RuntimeServiceError::NormalChatSessionRecoveryRequired { reason }
}

/// Rebuildable historical metadata; there is no Fresh or serialization-to-send path.
pub struct RuntimeNormalChatReadbackV2 {
    request: NormalChatCallRequestV2,
    policy: NormalChatAttemptReadbackV2,
    recovery: Option<NormalChatRecoveryRecordV1>,
    parent_head: ContentDigest,
    child_head: ContentDigest,
}
impl RuntimeNormalChatReadbackV2 {
    pub fn request(&self) -> &NormalChatCallRequestV2 {
        &self.request
    }
    pub fn policy(&self) -> &NormalChatAttemptReadbackV2 {
        &self.policy
    }
    pub fn recovery(&self) -> Option<&NormalChatRecoveryRecordV1> {
        self.recovery.as_ref()
    }
    pub fn parent_chain_head(&self) -> &ContentDigest {
        &self.parent_head
    }
    pub fn child_chain_head(&self) -> &ContentDigest {
        &self.child_head
    }
}

impl RuntimeService {
    /// Read-only startup-loaded policy metadata; never an enroll/renew API.
    pub fn normal_chat_egress_policy(
        &self,
    ) -> Option<&recursive_agent_policy::NormalChatEgressGrantV1> {
        self.normal_chat_grant
            .as_ref()
            .map(|authority| authority.grant())
    }

    pub fn open_or_lookup_normal_chat_session(
        &self,
        conversation: &str,
    ) -> Result<RuntimeNormalChatSessionV1, RuntimeServiceError> {
        let authority = self
            .normal_chat_grant
            .as_ref()
            .ok_or(RuntimeServiceError::NormalChatGovernanceDisabled)?;
        let id = authority
            .normal_chat_session(conversation, None)?
            .run_id()?;
        let paths = self.run_paths(&id)?;
        match std::fs::symlink_metadata(&paths.root) {
            Ok(_) => self.lookup_normal_chat_session(&id),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.open_normal_chat_session(conversation)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Existing session correlation only. Each mutation separately verifies the
    /// canonical family and current grant. Pending/closed status is not reopened.
    pub fn lookup_normal_chat_session(
        &self,
        id: &CurrentRunId,
    ) -> Result<RuntimeNormalChatSessionV1, RuntimeServiceError> {
        let authority = self
            .normal_chat_grant
            .as_ref()
            .ok_or(RuntimeServiceError::NormalChatGovernanceDisabled)?;
        let pinned = PinnedRunRoot::open_existing(
            self.dependencies.output_root(),
            &content_digest(id)?.to_string(),
        )?;
        let gate = SessionGate::acquire_existing(&pinned.root)?;
        let result = (|| {
            let snapshot =
                read_only_appendable_snapshot_expected_run_from_dir_fd(&pinned.root, id)?;
            let descriptor = snapshot
                .receipts()
                .first()
                .and_then(|r| r.artifact_refs.first())
                .ok_or_else(|| refused("session identity artifact absent"))?;
            let store = ArtifactStore::from_run_root_fd(&pinned.root, false)?;
            let session = parse_normal_chat_session_v1_bytes(&store.get(descriptor)?)
                .map_err(|_| refused("invalid retained session identity"))?;
            let expected = authority.normal_chat_session(
                &session.conversation_ref,
                session.parent_session_run_id.clone(),
            )?;
            if session != expected || session.run_id()? != *id {
                return Err(refused("session does not bind loaded grant/root"));
            }
            let chain = open_existing_from_dir_fd(&RunPaths::new(&pinned.locator), &pinned.root)?;
            let handle = RuntimeNormalChatSessionV1 {
                pinned: PinnedRunRoot {
                    locator: pinned.locator.clone(),
                    root: pinned.root.try_clone()?,
                    identity: pinned.identity,
                },
                session,
                run_id: id.clone(),
                verified_head: chain.head().clone(),
            };
            require_parent_history(authority, &handle, &chain, &store)?;
            gate.check(&pinned.root)?;
            pinned.ensure_locator_matches()?;
            Ok(handle)
        })();
        let unlock = gate.unlock();
        match (result, unlock) {
            (Ok(value), Ok(())) => {
                pinned.ensure_locator_matches()?;
                Ok(value)
            }
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }

    pub fn read_normal_chat_attempt(
        &self,
        id: &CurrentRunId,
        intent: &str,
    ) -> Result<RuntimeNormalChatReadbackV2, RuntimeServiceError> {
        NormalChatCallRequestV2::validate_dispatch_intent_ref(intent)?;
        let pinned = PinnedRunRoot::open_existing(
            self.dependencies.output_root(),
            &content_digest(id)?.to_string(),
        )?;
        let gate = SessionGate::acquire_existing(&pinned.root)?;
        let result = (|| {
            let root = &pinned.root;
            match read_only_appendable_snapshot_expected_run_from_dir_fd(root, id) {
                Err(LedgerError::NormalChatFamilyScopeRequired) => {
                    let output =
                        crate::open_directory_tree(self.dependencies.output_root(), false)?;
                    let proof = verify_degraded_normal_chat_session_from_runtime_root_fd(
                        &output,
                        id,
                        gate.ledger_guard(),
                    )
                    .map_err(|_| refused("readback degraded native family proof refused"))?;
                    let child = proof
                        .children()
                        .iter()
                        .find(|c| c.native_readback().attempt.dispatch_intent_ref == intent)
                        .ok_or_else(|| refused("readback intent absent from scoped family"))?;
                    let policy = child.native_readback().clone();
                    let recovery = if let recursive_agent_ledger::VerifiedNormalChatDispositionV1::MissingExecutorOutcome = child.disposition() {
                        // Recovery metadata is separately source-bound by this proof;
                        // read it from its canonical native policy owner below.
                        let child_dir = PinnedRunRoot::open_existing(self.dependencies.output_root(), &content_digest(child.run_id())?.to_string())?;
                        let context = child.context();
                        let family = recursive_agent_policy::FamilyAuthorityStore::require_existing_from_dir_fd(root, context.session_family_grant_v2()?)?;
                        recursive_agent_policy::DurablePermitStore::require_existing_from_run_root_fd(&child_dir.root)?
                            .read_normal_chat_recovery_v1(&family, intent)?
                    } else { None };
                    let value = RuntimeNormalChatReadbackV2 {
                        request: NormalChatCallRequestV2::from_attempt(&policy.attempt)?,
                        policy,
                        recovery,
                        parent_head: ContentDigest::from_hex(proof.chain_head())
                            .map_err(|_| refused("invalid parent head"))?,
                        child_head: ContentDigest::from_hex(child.chain_head())
                            .map_err(|_| refused("invalid child head"))?,
                    };
                    proof
                        .recheck()
                        .map_err(|_| refused("scoped readback source changed"))?;
                    return Ok(value);
                }
                Err(error) => return Err(error.into()),
                Ok(_) => {}
            }
            let store = ArtifactStore::from_run_root_fd(root, false)?;
            // Require every child projection to be present before any appendable
            // owner reader can reconcile metadata. Source qualification is not repair.
            let parent_snapshot = read_only_appendable_snapshot_expected_run_from_dir_fd(root, id)?;
            for row in parent_snapshot
                .receipts()
                .iter()
                .filter(|r| r.kind == ReceiptKindV1::ChildLinked)
            {
                let descriptor = row
                    .artifact_refs
                    .first()
                    .ok_or_else(|| refused("child link absent"))?;
                let bytes = store.get(descriptor)?;
                let link: ChildRunLinkV1 = serde_json::from_value(
                    parse_strict_json_value(&bytes).map_err(|_| refused("malformed child link"))?,
                )
                .map_err(|_| refused("malformed typed child link"))?;
                if jcs_canonical(&link)? != bytes {
                    return Err(refused("lossy child link"));
                }
                let child = PinnedRunRoot::open_existing(
                    self.dependencies.output_root(),
                    &content_digest(&link.child_run_id)?.to_string(),
                )?;
                read_only_appendable_snapshot_expected_run_from_dir_fd(
                    &child.root,
                    &link.child_run_id,
                )?;
            }
            let chain = open_existing_from_dir_fd(&RunPaths::new(&pinned.locator), root)?;
            let child = discover(root, &store, self.dependencies.output_root(), id, intent)?;
            let context: &NormalChatGrantContextV2 = &child.proof.admission.context;
            let (_, family, _) = require_parent_history_context(context, root, id, &chain, &store)?;
            let history = reconcile_family(
                &chain,
                root,
                &store,
                FamilyHistoryInputs {
                    family: &family,
                    context,
                },
                None,
            )?;
            let group = history
                .group(intent)
                .ok_or_else(|| refused("readback exact intent missing"))?;
            let policy = child.policy.read_normal_chat_attempt_v2(&family, intent)?;
            if group.child_policy != policy {
                return Err(refused("readback policy changed"));
            }
            let child_snapshot = read_only_appendable_snapshot_expected_run_from_dir_fd(
                &child.pinned.root,
                &policy.attempt.run_id()?,
            )?;
            let value = RuntimeNormalChatReadbackV2 {
                request: group.request.clone(),
                policy,
                recovery: child.policy.read_normal_chat_recovery_v1(&family, intent)?,
                parent_head: history.parent_head.clone(),
                child_head: ContentDigest::from_hex(&child_snapshot.verification().final_head)
                    .map_err(|_| refused("invalid child head"))?,
            };
            history.recheck_closed(&family)?;
            if family.read_normal_chat_session_snapshot_v2()? != history.snapshot
                || read_only_appendable_snapshot_expected_run_from_dir_fd(root, id)?
                    .verification()
                    .final_head
                    != value.parent_head.to_string()
                || child.policy.read_normal_chat_attempt_v2(&family, intent)? != value.policy
            {
                return Err(refused("readback source changed"));
            }
            child.pinned.ensure_locator_matches()?;
            gate.check(root)?;
            pinned.ensure_locator_matches()?;
            Ok(value)
        })();
        let unlock = gate.unlock();
        match (result, unlock) {
            (Ok(value), Ok(())) => {
                pinned.ensure_locator_matches()?;
                Ok(value)
            }
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }
}
