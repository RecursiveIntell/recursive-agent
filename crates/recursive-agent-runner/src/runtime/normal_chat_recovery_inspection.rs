//! Require-existing inspection of a complete pending normal-chat preflight.
//! Configured output_root is the read scope, not an egress grant. Historical
//! context never becomes a grant authority, session handle or send continuation.
//! Appendable ledger readers may repair projections/torn tails; this is not a
//! forensic byte-immutable read or an atomic snapshot against same-UID writers.
use super::normal_chat_attempt::{expected_link, preflight_rows, require_parent_history_context};
use super::normal_chat_family_history::{reconcile_family, FamilyHistoryInputs};
use super::normal_chat_session::SessionGate;
use super::normal_chat_terminal::{compare_existing, describe_all, preflight_payloads};
use super::{RuntimeService, RuntimeServiceError};
use crate::PinnedRunRoot;
use recursive_agent_contracts::{
    content_digest, jcs_canonical, parse_strict_json_value, ContentDigest, CurrentRunId,
    NormalChatAttemptV2, NormalChatCallRequestV2, NormalChatSessionV1, ReceiptKindV1,
};
use recursive_agent_ledger::{
    appendable_snapshot_expected_run_from_dir_fd, open_existing_from_dir_fd, ArtifactStore,
    ChainHandle, ChildRunLinkV1, RunPaths,
};
use recursive_agent_policy::{
    parse_normal_chat_ledger_admission_v2_bytes, DurablePermitStore, FamilyAuthorityStore,
    NormalChatAttemptPolicyStateV2, NormalChatAttemptReadbackV2,
    NormalChatLedgerAdmissionEvidenceV2, NormalChatRecoveryRecordV1,
};
use std::path::Path;

fn rejected(reason: &'static str) -> RuntimeServiceError {
    RuntimeServiceError::NormalChatSessionRecoveryRequired { reason }
}
/// Checked historical metadata only. This does not mutate a native disposition,
/// terminalize a child, close a parent, prove send/no-send, or resume authority.
///
/// ```compile_fail
/// use recursive_agent_runner::RuntimeNormalChatRecoveryInspectionV1;
/// fn copy(v: RuntimeNormalChatRecoveryInspectionV1) { let _ = v.clone(); }
/// ```
/// ```compile_fail
/// use recursive_agent_runner::RuntimeNormalChatRecoveryInspectionV1;
/// fn serialize(v: RuntimeNormalChatRecoveryInspectionV1) { let _ = serde_json::to_string(&v); }
/// ```
/// ```compile_fail
/// use recursive_agent_runner::{RuntimeNormalChatRecoveryInspectionV1, RuntimeService};
/// fn send(service: &RuntimeService, view: RuntimeNormalChatRecoveryInspectionV1) {
///     service.begin_normal_chat_attempt(view.session(), view.request());
/// }
/// ```
pub struct RuntimeNormalChatRecoveryInspectionV1 {
    session: NormalChatSessionV1,
    request: NormalChatCallRequestV2,
    attempt: NormalChatAttemptV2,
    preflight: ContentDigest,
    state: NormalChatAttemptPolicyStateV2,
    recovery: Option<NormalChatRecoveryRecordV1>,
    parent_head: ContentDigest,
    child_head: ContentDigest,
}
impl RuntimeNormalChatRecoveryInspectionV1 {
    pub fn session(&self) -> &NormalChatSessionV1 {
        &self.session
    }
    pub fn request(&self) -> &NormalChatCallRequestV2 {
        &self.request
    }
    pub fn attempt(&self) -> &NormalChatAttemptV2 {
        &self.attempt
    }
    pub fn preflight_digest(&self) -> &ContentDigest {
        &self.preflight
    }
    pub fn policy_state(&self) -> NormalChatAttemptPolicyStateV2 {
        self.state
    }
    pub fn native_recovery(&self) -> Option<&NormalChatRecoveryRecordV1> {
        self.recovery.as_ref()
    }
    pub fn parent_chain_head(&self) -> &ContentDigest {
        &self.parent_head
    }
    pub fn child_chain_head(&self) -> &ContentDigest {
        &self.child_head
    }
}
pub(super) struct Discovered {
    pub(super) pinned: PinnedRunRoot,
    pub(super) artifacts: ArtifactStore,
    pub(super) chain: ChainHandle,
    pub(super) policy: DurablePermitStore,
    pub(super) proof: NormalChatLedgerAdmissionEvidenceV2,
}
#[derive(PartialEq)]
struct Observed {
    view: NormalChatAttemptReadbackV2,
    recovery: Option<NormalChatRecoveryRecordV1>,
}
impl Discovered {
    fn inspect(
        &self,
        family: &FamilyAuthorityStore,
        intent: &str,
    ) -> Result<Observed, RuntimeServiceError> {
        let view = self.policy.read_normal_chat_attempt_v2(family, intent)?;
        if !matches!(
            view.state,
            NormalChatAttemptPolicyStateV2::Consumed
                | NormalChatAttemptPolicyStateV2::RecoveredUnknown
        ) || view.outcome.is_some()
            || view.settlement.is_some()
        {
            return Err(rejected(
                "inspection requires pending consumed or native-recovered state",
            ));
        }
        if self
            .policy
            .read_normal_chat_ledger_admission_v2(family, intent)?
            .as_ref()
            != Some(&self.proof)
        {
            return Err(rejected(
                "inspection native proof differs from retained ledger admission",
            ));
        }
        let recovery = self.policy.read_normal_chat_recovery_v1(family, intent)?;
        match (&view.state, &recovery) {
            (NormalChatAttemptPolicyStateV2::Consumed, None) => {}
            (NormalChatAttemptPolicyStateV2::RecoveredUnknown, Some(record)) => {
                record.validate_for_admission_v1(&self.proof)?;
                if family
                    .read_normal_chat_session_snapshot_v2()?
                    .admission
                    .closed_at
                    .is_none()
                {
                    return Err(rejected(
                        "native recovery admission fence missing; inspection cannot repair it",
                    ));
                }
            }
            _ => return Err(rejected("inspection recovery role/record mismatch")),
        }
        let snapshot = appendable_snapshot_expected_run_from_dir_fd(
            &self.pinned.root,
            &self.proof.preflight.evidence.binding.run_id,
        )?;
        if snapshot.receipts().len() != 7
            || snapshot.verification().final_head != self.chain.head().to_string()
        {
            return Err(rejected(
                "inspection requires exact complete nonterminal seven-receipt preflight",
            ));
        }
        let descriptors = describe_all(&preflight_payloads(&self.proof)?)?;
        for (draft, actual) in preflight_rows(
            &self.proof.control_evidence()?,
            &self.proof.issued_effect_evidence()?,
            &self.proof.preflight.evidence,
            self.proof.preflight.recorded_at,
            &descriptors,
        )
        .into_iter()
        .zip(snapshot.receipts())
        {
            compare_existing(draft, actual)?;
        }
        self.artifacts.require_exact_inventory(&descriptors)?;
        self.artifacts.require_locator_matches(&self.pinned.root)?;
        self.pinned.ensure_locator_matches()?;
        Ok(Observed { view, recovery })
    }
}

pub(super) fn discover(
    root: &std::fs::File,
    store: &ArtifactStore,
    output: &Path,
    session: &CurrentRunId,
    intent: &str,
) -> Result<Discovered, RuntimeServiceError> {
    let parent = appendable_snapshot_expected_run_from_dir_fd(root, session)?;
    for row in parent
        .receipts()
        .iter()
        .filter(|row| row.kind == ReceiptKindV1::ChildLinked)
    {
        if row.artifact_refs.len() != 1 {
            return Err(rejected("discovery requires exact immutable child link"));
        }
        let bytes = store.get(&row.artifact_refs[0])?;
        let value = parse_strict_json_value(&bytes)
            .map_err(|_| rejected("child link is not strict JSON"))?;
        let link: ChildRunLinkV1 =
            serde_json::from_value(value).map_err(|_| rejected("child link is malformed"))?;
        if jcs_canonical(&link)? != bytes {
            return Err(rejected("child link lost original canonical wire"));
        }
        let pinned =
            PinnedRunRoot::open_existing(output, &content_digest(&link.child_run_id)?.to_string())?;
        let artifacts = ArtifactStore::from_run_root_fd(&pinned.root, false)?;
        let chain = open_existing_from_dir_fd(&RunPaths::new(&pinned.locator), &pinned.root)?;
        let child = appendable_snapshot_expected_run_from_dir_fd(&pinned.root, &link.child_run_id)?;
        let admitted = child
            .receipts()
            .get(4)
            .ok_or_else(|| rejected("linked child lacks complete admission prefix"))?;
        if admitted.kind != ReceiptKindV1::NormalChatAttemptAdmittedV2
            || admitted.artifact_refs.len() != 1
        {
            return Err(rejected("linked child lacks exact V2 admission metadata"));
        }
        let proof = parse_normal_chat_ledger_admission_v2_bytes(
            &artifacts.get(&admitted.artifact_refs[0])?,
        )?;
        if proof.admission.context.session.run_id()? != *session
            || expected_link(&proof.admission.reservation)? != link
        {
            return Err(rejected(
                "discovered child proof/link belongs to a different context",
            ));
        }
        if proof.admission.reservation.attempt.dispatch_intent_ref != intent {
            continue;
        }
        let policy = DurablePermitStore::require_existing_from_run_root_fd(&pinned.root)?;
        return Ok(Discovered {
            pinned,
            artifacts,
            chain,
            policy,
            proof,
        });
    }
    Err(rejected(
        "intent not discoverable in complete canonical child history",
    ))
}
pub(super) fn discover_interrupted(
    root: &std::fs::File,
    store: &ArtifactStore,
    output: &Path,
    session: &CurrentRunId,
    intent: &str,
) -> Result<Discovered, RuntimeServiceError> {
    let parent = appendable_snapshot_expected_run_from_dir_fd(root, session)?;
    for row in parent
        .receipts()
        .iter()
        .filter(|row| row.kind == ReceiptKindV1::ChildLinked)
    {
        if row.artifact_refs.len() != 1 {
            return Err(rejected("discovery requires exact immutable child link"));
        }
        let bytes = store.get(&row.artifact_refs[0])?;
        let value = parse_strict_json_value(&bytes)
            .map_err(|_| rejected("child link is not strict JSON"))?;
        let link: ChildRunLinkV1 =
            serde_json::from_value(value).map_err(|_| rejected("child link is malformed"))?;
        if jcs_canonical(&link)? != bytes {
            return Err(rejected("child link lost original canonical wire"));
        }
        let pinned =
            PinnedRunRoot::open_existing(output, &content_digest(&link.child_run_id)?.to_string())?;
        let artifacts = ArtifactStore::from_run_root_fd(&pinned.root, false)?;
        recursive_agent_ledger::recoverable_normal_chat_preflight_snapshot_from_dir_fd(
            &pinned.root,
            &link.child_run_id,
        )?;
        let chain = open_existing_from_dir_fd(&RunPaths::new(&pinned.locator), &pinned.root)?;
        let policy = DurablePermitStore::require_existing_from_run_root_fd(&pinned.root)?;
        let retained = policy
            .read_retained_normal_chat_admission_v2()?
            .ok_or_else(|| rejected("child retained admission absent"))?;
        let family = FamilyAuthorityStore::require_existing_from_dir_fd(
            root,
            retained.context.session_family_grant_v2()?,
        )?;
        let proof = policy
            .read_normal_chat_ledger_admission_v2(
                &family,
                &retained.reservation.attempt.dispatch_intent_ref,
            )?
            .ok_or_else(|| rejected("child consumed source absent"))?;
        if proof.admission.context.session.run_id()? != *session
            || expected_link(&proof.admission.reservation)? != link
        {
            return Err(rejected(
                "discovered child proof/link belongs to a different context",
            ));
        }
        if proof.admission.reservation.attempt.dispatch_intent_ref != intent {
            continue;
        }
        let policy = DurablePermitStore::require_existing_from_run_root_fd(&pinned.root)?;
        return Ok(Discovered {
            pinned,
            artifacts,
            chain,
            policy,
            proof,
        });
    }
    Err(rejected(
        "intent not discoverable in complete canonical child history",
    ))
}
impl RuntimeService {
    /// Resolve one complete pending attempt within this service's configured
    /// output-root read scope, without loading a current grant or a clock. This
    /// is not a recovery mutation, terminal status, home enrollment or send API.
    /// No caller-authored filesystem path or transport retry is accepted.
    pub fn inspect_pending_normal_chat_attempt_for_recovery(
        &self,
        session: &CurrentRunId,
        intent: &str,
    ) -> Result<RuntimeNormalChatRecoveryInspectionV1, RuntimeServiceError> {
        self.inspect_pending_normal_chat_attempt_for_recovery_with_observer(session, intent, || {})
    }
    /// Negative-test seam; all canonical/fd/locator rechecks remain mandatory.
    #[doc(hidden)]
    pub fn inspect_pending_normal_chat_attempt_for_recovery_with_observer(
        &self,
        session: &CurrentRunId,
        intent: &str,
        before_return: impl FnOnce(),
    ) -> Result<RuntimeNormalChatRecoveryInspectionV1, RuntimeServiceError> {
        NormalChatCallRequestV2::validate_dispatch_intent_ref(intent)?;
        let parent = PinnedRunRoot::open_existing(
            self.dependencies.output_root(),
            &content_digest(session)?.to_string(),
        )?;
        let gate = SessionGate::acquire_existing(&parent.root)?;
        let result = (|| -> Result<RuntimeNormalChatRecoveryInspectionV1, RuntimeServiceError> {
            let root = &parent.root;
            let store = ArtifactStore::from_run_root_fd(root, false)?;
            let chain = open_existing_from_dir_fd(&RunPaths::new(&parent.locator), root)?;
            let child = discover(
                root,
                &store,
                self.dependencies.output_root(),
                session,
                intent,
            )?;
            let proof = &child.proof;
            let context = &proof.admission.context;
            let request =
                NormalChatCallRequestV2::from_attempt(&proof.admission.reservation.attempt)?;
            let (permits, family, record) =
                require_parent_history_context(context, root, session, &chain, &store)?;
            let inputs = FamilyHistoryInputs {
                family: &family,
                context,
            };
            let history = reconcile_family(&chain, root, &store, inputs, None)?;
            let target = history
                .group(intent)
                .ok_or_else(|| rejected("inspection intent absent from full family"))?;
            if target.closed_index.is_some()
                || history
                    .groups
                    .last()
                    .map(|g| g.request.dispatch_intent_ref.as_str())
                    != Some(intent)
                || target.request != request
                || target.reservation != proof.admission.reservation
            {
                return Err(rejected(
                    "inspection target is not the exact latest pending group",
                ));
            }
            let before = child.inspect(&family, intent)?;
            if target.child_policy != before.view {
                return Err(rejected("inspection family/child readback changed"));
            }
            before_return();
            history.recheck_closed(&family)?;
            let (_, late_family, late_record) =
                require_parent_history_context(context, root, session, &chain, &store)?;
            if late_record != record {
                return Err(rejected("inspection native root changed"));
            }
            let late = reconcile_family(
                &chain,
                root,
                &store,
                FamilyHistoryInputs {
                    family: &late_family,
                    context,
                },
                None,
            )?;
            if late.snapshot != history.snapshot || late.parent_head != history.parent_head {
                return Err(rejected(
                    "inspection canonical family or parent head changed",
                ));
            }
            if child.inspect(&family, intent)? != before {
                return Err(rejected("inspection native child changed"));
            }
            if permits.read_normal_chat_session_control_record()?.as_ref() != Some(&record) {
                return Err(rejected("inspection native root disappeared or changed"));
            }
            history.recheck_closed(&family)?;
            late.recheck_closed(&late_family)?;
            child
                .artifacts
                .require_locator_matches(&child.pinned.root)?;
            child.pinned.ensure_locator_matches()?;
            store.require_locator_matches(root)?;
            gate.check(root)?;
            parent.ensure_locator_matches()?;
            Ok(RuntimeNormalChatRecoveryInspectionV1 {
                session: context.session.clone(),
                request,
                attempt: proof.admission.reservation.attempt.clone(),
                preflight: proof.preflight.receipt_digest.clone(),
                state: before.view.state,
                recovery: before.recovery,
                parent_head: chain.head().clone(),
                child_head: child.chain.head().clone(),
            })
        })();
        let unlock = gate.unlock();
        match (result, unlock) {
            (Ok(view), Ok(())) => {
                parent.ensure_locator_matches()?;
                Ok(view)
            }
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }
}
