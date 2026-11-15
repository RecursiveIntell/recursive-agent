//! Source-selecting startup recovery. Each concrete mutation reacquires the same
//! canonical gate and re-proves its source; selection is never a permission.
use super::normal_chat_parent_recovery::RuntimeNormalChatRecoveredSessionV1;
use super::normal_chat_prechild_recovery::RuntimeNormalChatPrechildRecoveredV1;
use super::normal_chat_session::SessionGate;
use super::{RuntimeService, RuntimeServiceError};
use crate::PinnedRunRoot;
use recursive_agent_contracts::{
    content_digest, jcs_canonical, parse_normal_chat_call_request_v2_bytes,
    parse_strict_json_value, ContentDigest, CurrentRunId, NormalChatCallRequestV2,
    NormalChatSessionV1, ReceiptKindV1, RunTerminalStateV1,
};
use recursive_agent_ledger::{
    recoverable_normal_chat_preflight_snapshot_from_dir_fd, ArtifactStore, LedgerError,
};
use recursive_agent_policy::{
    DurablePermitStore, FamilyAuthorityStore, NormalChatAttemptPolicyStateV2,
};
fn required(reason: &'static str) -> RuntimeServiceError {
    RuntimeServiceError::NormalChatSessionRecoveryRequired { reason }
}
enum Selection {
    Parent,
    Prechild(String),
    Unconsumed(String),
    Prepared(String),
    Interrupted(String),
    ExpiredUnknown(String),
}
/// Historical terminal evidence only; no serialization, cloning or continuation.
pub enum RuntimeNormalChatRecoveryCompositionV1 {
    Parent(RuntimeNormalChatRecoveredSessionV1),
    Prechild(Box<RuntimeNormalChatPrechildRecoveredV1>),
}
impl RuntimeNormalChatRecoveryCompositionV1 {
    pub fn chain_head(&self) -> &ContentDigest {
        match self {
            Self::Parent(v) => v.chain_head(),
            Self::Prechild(v) => v.chain_head(),
        }
    }
    pub fn terminal_state(&self) -> RunTerminalStateV1 {
        match self {
            Self::Parent(v) => v.terminal_state(),
            Self::Prechild(v) => v.terminal_state(),
        }
    }
    pub fn unknown_attempt_count(&self) -> usize {
        match self {
            Self::Parent(v) => v.unknown_attempt_count(),
            Self::Prechild(_) => 0,
        }
    }
}
impl RuntimeService {
    /// Requires interrupted and parent startup opt-ins. Complete-barrier UNKNOWN
    /// additionally requires the existing expired-recovery opt-in and native TTL.
    /// No grant, caller prefix, clock, preflight digest or proof is accepted.
    pub fn recover_normal_chat_session_from_sources(
        &self,
        session: &CurrentRunId,
    ) -> Result<RuntimeNormalChatRecoveryCompositionV1, RuntimeServiceError> {
        if !self.normal_chat_interrupted_recovery_enabled {
            return Err(RuntimeServiceError::NormalChatRecoveryDisabled);
        }
        if !self.normal_chat_parent_recovery_enabled {
            return Err(RuntimeServiceError::NormalChatParentRecoveryDisabled);
        }
        let parent = PinnedRunRoot::open_existing(
            self.dependencies.output_root(),
            &content_digest(session)?.to_string(),
        )?;
        let gate = SessionGate::acquire_existing(&parent.root)?;
        let selected = (|| {
            let rows =
                match recoverable_normal_chat_preflight_snapshot_from_dir_fd(&parent.root, session)
                {
                    Ok(rows) => rows,
                    Err(LedgerError::NormalChatFamilyScopeRequired) => {
                        return Ok(Selection::Parent)
                    }
                    Err(e) => return Err(e.into()),
                };
            let store = ArtifactStore::from_run_root_fd(&parent.root, false)?;
            let descriptor = rows
                .receipts()
                .first()
                .and_then(|r| r.artifact_refs.first())
                .ok_or_else(|| required("source selection bootstrap absent"))?;
            let bytes = store.get(descriptor)?;
            let identity: NormalChatSessionV1 = serde_json::from_value(
                parse_strict_json_value(&bytes).map_err(|_| required("invalid session JSON"))?,
            )
            .map_err(|_| required("invalid session identity"))?;
            if jcs_canonical(&identity)? != bytes || identity.run_id()? != *session {
                return Err(required("source selection identity differs"));
            }
            let (family, _) =
                FamilyAuthorityStore::require_existing_normal_chat_history_context_v1(
                    &parent.root,
                    &identity,
                )?;
            if let Some(old) = family.read_normal_chat_prechild_recovery_v1()? {
                return Ok(Selection::Prechild(old.request.dispatch_intent_ref));
            }
            let mut pending = Vec::new();
            for descriptor in store.verified_inventory()? {
                let bytes = store.get(&descriptor)?;
                let value = parse_strict_json_value(&bytes)
                    .map_err(|_| required("source inventory invalid JSON"))?;
                if value.get("schema").and_then(|s| s.as_str())
                    == Some("recursive-agent.normal-chat-call-request/v2")
                {
                    let request = parse_normal_chat_call_request_v2_bytes(&bytes)
                        .map_err(|_| required("source request invalid"))?;
                    if request.operation.parent_run_id != *session {
                        return Err(required("source request parent differs"));
                    }
                    let digest = request.preparation_digest()?;
                    if !rows
                        .receipts()
                        .iter()
                        .any(|r| r.kind == ReceiptKindV1::ChildClosed && r.args_digest == digest)
                    {
                        pending.push(request);
                    }
                }
            }
            if pending.is_empty() {
                return Ok(Selection::Parent);
            }
            if pending.len() != 1 {
                return Err(required(
                    "source selection has ambiguous pending request set",
                ));
            }
            let request: NormalChatCallRequestV2 = pending.remove(0);
            let intent = request.dispatch_intent_ref;
            let Some(reservation) = family.read_normal_chat_reservation(&intent)? else {
                return Ok(Selection::Prechild(intent));
            };
            let name = content_digest(&reservation.attempt.run_id()?)?.to_string();
            // Absence chooses only the prechild API, which proves the original
            // ParentReserved checkpoint. Missing ChildRootStarted never qualifies.
            let output = crate::open_directory_tree(self.dependencies.output_root(), false)?;
            match rustix::fs::statat(
                &output,
                name.as_str(),
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Err(e) if e == rustix::io::Errno::NOENT => return Ok(Selection::Prechild(intent)),
                Err(e) => return Err(std::io::Error::from(e).into()),
                Ok(_) => {}
            }
            let child = PinnedRunRoot::open_existing(self.dependencies.output_root(), &name)?;
            let policy = DurablePermitStore::require_existing_from_run_root_fd(&child.root)?;
            let view = policy.read_normal_chat_attempt_v2(&family, &intent)?;
            let selection=match view.state {
                NormalChatAttemptPolicyStateV2::Unbegun=>Selection::Unconsumed(intent),
                NormalChatAttemptPolicyStateV2::Prepared|NormalChatAttemptPolicyStateV2::RecoveredPrepared=>Selection::Prepared(intent),
                NormalChatAttemptPolicyStateV2::RecoveredBeforeRelease=>Selection::Interrupted(intent),
                NormalChatAttemptPolicyStateV2::RecoveredUnknown=>Selection::ExpiredUnknown(intent),
                NormalChatAttemptPolicyStateV2::Consumed=>{
                    let child_rows=recoverable_normal_chat_preflight_snapshot_from_dir_fd(&child.root,&reservation.attempt.run_id()?)?;
                    if child_rows.receipts().len()<7 {Selection::Interrupted(intent)}else{Selection::ExpiredUnknown(intent)}
                }
                NormalChatAttemptPolicyStateV2::Settled=>return Err(required("reported terminal suffix recovery uses existing settlement owner; not an interrupted admission")),
            };
            child.ensure_locator_matches()?;
            gate.check(&parent.root)?;
            parent.ensure_locator_matches()?;
            Ok(selection)
        })();
        let unlock = gate.unlock();
        let selection = match (selected, unlock) {
            (Ok(v), Ok(())) => v,
            (Err(e), _) | (Ok(_), Err(e)) => return Err(e),
        };
        parent.ensure_locator_matches()?;
        match selection {
            Selection::Prechild(intent) => {
                return self
                    .recover_prechild_normal_chat_admission(session, &intent)
                    .map(|v| RuntimeNormalChatRecoveryCompositionV1::Prechild(Box::new(v)))
            }
            Selection::Unconsumed(intent) => {
                self.recover_unconsumed_normal_chat_attempt(session, &intent)?;
            }
            Selection::Prepared(intent) => {
                self.recover_prepared_normal_chat_attempt(session, &intent)?;
            }
            Selection::Interrupted(intent) => {
                self.recover_interrupted_normal_chat_attempt(session, &intent)?;
            }
            Selection::ExpiredUnknown(intent) => {
                self.recover_expired_normal_chat_attempt(session, &intent)?;
            }
            Selection::Parent => {}
        }
        self.recover_normal_chat_session_parent(session)
            .map(RuntimeNormalChatRecoveryCompositionV1::Parent)
    }
}
