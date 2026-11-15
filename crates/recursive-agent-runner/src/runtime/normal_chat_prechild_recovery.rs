//! Parent-only terminal reconciliation after exact complete sibling proof.
use super::normal_chat_attempt::{
    expected_link, request_descriptor, require_parent_history_context, MonotonicClock,
};
use super::normal_chat_session::SessionGate;
use super::normal_chat_terminal::{describe, ensure_suffix, NormalChatTerminalInterruptionV2};
use super::{RuntimeService, RuntimeServiceError};
use crate::PinnedRunRoot;
use recursive_agent_contracts::{
    content_digest, jcs_canonical, parse_normal_chat_call_request_v2_bytes,
    parse_strict_json_value, ContentDigest, CurrentRunId, NormalChatCallRequestV2,
    NormalChatSessionV1, RunTerminalStateV1,
};
use recursive_agent_ledger::{
    normal_chat_prechild_recovery_plan_v1, open_existing_from_dir_fd,
    read_only_appendable_snapshot_expected_run_from_dir_fd,
    recoverable_normal_chat_preflight_snapshot_from_dir_fd,
    verified_snapshot_expected_run_from_dir_fd, verify_child_links_in_runtime_root, AppendStage,
    ArtifactStore, RunPaths,
};
use recursive_agent_policy::{
    FamilyAuthorityStore, NormalChatPrechildRecoveryRecordV1, PermitEvidenceV1,
    PermitRevocationReasonV1, PermitStateV1, PermitTransitionStage,
};
fn required(reason: &'static str) -> RuntimeServiceError {
    RuntimeServiceError::NormalChatSessionRecoveryRequired { reason }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalChatPrechildRuntimeRecoveryInterruptionV1 {
    Family(PermitTransitionStage),
    AfterFamily,
    Control(PermitTransitionStage),
    AfterControl,
    Artifact { ordinal: usize },
    Receipt { ordinal: usize, stage: AppendStage },
    BeforeReturn,
}
/// Historical evidence only; cannot be cloned, deserialized or sent.
/// ```compile_fail
/// use recursive_agent_runner::RuntimeNormalChatPrechildRecoveredV1;
/// fn send(v: RuntimeNormalChatPrechildRecoveredV1) { v.submit_child(); }
/// ```
/// ```compile_fail
/// use recursive_agent_runner::RuntimeNormalChatPrechildRecoveredV1;
/// fn restore() -> Result<(), serde_json::Error> { let _: RuntimeNormalChatPrechildRecoveredV1 = serde_json::from_str("{}")?; Ok(()) }
/// ```
pub struct RuntimeNormalChatPrechildRecoveredV1 {
    run_id: CurrentRunId,
    head: ContentDigest,
    recovery: NormalChatPrechildRecoveryRecordV1,
}
impl RuntimeNormalChatPrechildRecoveredV1 {
    pub fn run_id(&self) -> &CurrentRunId {
        &self.run_id
    }
    pub fn chain_head(&self) -> &ContentDigest {
        &self.head
    }
    pub fn recovery(&self) -> &NormalChatPrechildRecoveryRecordV1 {
        &self.recovery
    }
    pub fn terminal_state(&self) -> RunTerminalStateV1 {
        RunTerminalStateV1::Failed
    }
}
impl RuntimeService {
    pub fn recover_prechild_normal_chat_admission(
        &self,
        session: &CurrentRunId,
        intent: &str,
    ) -> Result<RuntimeNormalChatPrechildRecoveredV1, RuntimeServiceError> {
        self.recover_prechild_normal_chat_admission_with_observer(session, intent, None, || {})
    }
    #[doc(hidden)]
    pub fn recover_prechild_normal_chat_admission_with_observer(
        &self,
        session: &CurrentRunId,
        intent: &str,
        fault: Option<NormalChatPrechildRuntimeRecoveryInterruptionV1>,
        observer: impl FnOnce(),
    ) -> Result<RuntimeNormalChatPrechildRecoveredV1, RuntimeServiceError> {
        use NormalChatPrechildRuntimeRecoveryInterruptionV1 as Stop;
        if !self.normal_chat_interrupted_recovery_enabled {
            return Err(RuntimeServiceError::NormalChatRecoveryDisabled);
        }
        NormalChatCallRequestV2::validate_dispatch_intent_ref(intent)?;
        if matches!(
            fault,
            Some(
                Stop::Artifact { ordinal: 2.. }
                    | Stop::Receipt { ordinal: 3.., .. }
                    | Stop::Receipt {
                        stage: AppendStage::ArtifactWrite,
                        ..
                    }
            )
        ) {
            return Err(required("invalid pre-child recovery interruption"));
        }
        let output = crate::open_directory_tree(self.dependencies.output_root(), false)?;
        let parent = PinnedRunRoot::open_existing(
            self.dependencies.output_root(),
            &content_digest(session)?.to_string(),
        )?;
        let gate = SessionGate::acquire_existing(&parent.root)?;
        let clock = MonotonicClock::new_lazy(self.dependencies.clock());
        let result = (|| {
            let snapshot =
                recoverable_normal_chat_preflight_snapshot_from_dir_fd(&parent.root, session)?;
            let store = ArtifactStore::from_run_root_fd(&parent.root, false)?;
            let identity = snapshot
                .receipts()
                .first()
                .and_then(|r| r.artifact_refs.first())
                .ok_or_else(|| required("pre-child recovery bootstrap absent"))?;
            let bytes = store.get(identity)?;
            let value =
                parse_strict_json_value(&bytes).map_err(|_| required("invalid session JSON"))?;
            let original_session: NormalChatSessionV1 =
                serde_json::from_value(value).map_err(|_| required("invalid session identity"))?;
            if jcs_canonical(&original_session)? != bytes || original_session.run_id()? != *session
            {
                return Err(required("lossy/conflicting session identity"));
            }
            let (_, context) =
                FamilyAuthorityStore::require_existing_normal_chat_history_context_v1(
                    &parent.root,
                    &original_session,
                )?;
            let mut chain =
                open_existing_from_dir_fd(&RunPaths::new(&parent.locator), &parent.root)?;
            let (permits, family, root_record) =
                require_parent_history_context(&context, &parent.root, session, &chain, &store)?;
            let original_family = family.read_normal_chat_session_snapshot_v2()?;
            let old = family.read_normal_chat_prechild_recovery_v1()?;
            let inventory = store.verified_inventory()?;
            let (request, prefix, retained) = if let Some(old) = &old {
                if old.request.dispatch_intent_ref != intent
                    || old.context != context
                    || snapshot.receipts().get(..old.parent_prefix.len())
                        != Some(old.parent_prefix.as_slice())
                {
                    return Err(required("pre-child recovery original source differs"));
                }
                (
                    old.request.clone(),
                    old.parent_prefix.clone(),
                    old.retained_artifacts.clone(),
                )
            } else {
                let mut request = None;
                for descriptor in &inventory {
                    let bytes = store.get(descriptor)?;
                    let value = parse_strict_json_value(&bytes)
                        .map_err(|_| required("invalid inventory metadata JSON"))?;
                    if value.get("schema").and_then(|v| v.as_str())
                        == Some("recursive-agent.normal-chat-call-request/v2")
                    {
                        let candidate = parse_normal_chat_call_request_v2_bytes(&bytes)
                            .map_err(|_| required("invalid original call request"))?;
                        if candidate.dispatch_intent_ref == intent
                            && request.replace(candidate).is_some()
                        {
                            return Err(required("conflicting request inventory"));
                        }
                    }
                }
                (
                    request.ok_or_else(|| required("original request artifact absent"))?,
                    snapshot.receipts().to_vec(),
                    inventory.clone(),
                )
            };
            let reservation = original_family
                .reservations
                .iter()
                .find(|r| r.attempt.dispatch_intent_ref == intent);
            let siblings = super::normal_chat_family_history::reconcile_prechild_family(
                &chain,
                &parent.root,
                &store,
                super::normal_chat_family_history::FamilyHistoryInputs {
                    family: &family,
                    context: &context,
                },
                &request,
            )?;
            if siblings.degraded {
                return Err(required("pre-child prefix after admission-closing degraded sibling is not a normative no-send source"));
            }
            let mut allowed = prefix
                .iter()
                .flat_map(|r| r.artifact_refs.clone())
                .collect::<Vec<_>>();
            let request_descriptor = request_descriptor(&request)?;
            if store.get(&request_descriptor)? != jcs_canonical(&request)? {
                return Err(required("request bytes differ"));
            }
            allowed.push(request_descriptor);
            for group in &siblings.groups {
                allowed.push(super::normal_chat_attempt::request_descriptor(
                    &group.request,
                )?);
            }
            if let Some(reservation) = reservation {
                if NormalChatCallRequestV2::from_attempt(&reservation.attempt)? != request {
                    return Err(required("request/reservation conflict"));
                }
                allowed.push(describe(&jcs_canonical(&expected_link(reservation)?)?)?);
                let name = content_digest(&reservation.attempt.run_id()?)?.to_string();
                match rustix::fs::statat(&output, name.as_str(), rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
                    Err(error) if error == rustix::io::Errno::NOENT => {},
                    Err(error) => return Err(std::io::Error::from(error).into()),
                    Ok(_) => return Err(required("pre-child recovery refuses any existing child root; use native child recovery")),
                }
            }
            if retained.iter().any(|d| !allowed.contains(d))
                || allowed.iter().filter(|d| retained.contains(d)).count() < 3
            {
                return Err(required("unrelated or missing pre-child inventory"));
            }
            for descriptor in &retained {
                store.verify_descriptor(descriptor)?;
            }
            if old.is_none() {
                store.require_inventory_subset(&allowed)?;
                let floor = prefix
                    .iter()
                    .fold(context.root_control.binding.issued_at, |at, r| {
                        std::cmp::max(at, r.valid_time)
                    });
                if clock.sample()
                    < super::normal_chat_attempt::retained_root_floor(&root_record, floor)
                {
                    return Err(required("pre-child recovery clock precedes history"));
                }
                clock.check()?;
            }
            siblings.recheck_closed(&family)?;
            gate.check(&parent.root)?;
            parent.ensure_locator_matches()?;
            let recovery = family.recover_prechild_normal_chat_admission_v1(
                &context,
                &request,
                &prefix,
                &retained,
                || clock.sample(),
                match fault {
                    Some(Stop::Family(stage)) => Some(stage),
                    _ => None,
                },
            )?;
            clock.check()?;
            if fault == Some(Stop::AfterFamily) {
                return Err(required("pre-child recovery interrupted after family"));
            }
            let mut control = permits.state(&root_record.permit.permit_id)?;
            if matches!(control.state, PermitStateV1::Issued) {
                let at = clock.sample();
                clock.check()?;
                if at < recovery.observed_at {
                    return Err(required("pre-child control close clock regressed"));
                }
                control = permits.revoke_with_interruption(
                    &control.permit.permit_id,
                    PermitRevocationReasonV1::Operator,
                    at,
                    match fault {
                        Some(Stop::Control(stage)) => Some(stage),
                        _ => None,
                    },
                )?;
            }
            let closed = PermitEvidenceV1::from_record(&control)?;
            if fault == Some(Stop::AfterControl) {
                return Err(required("pre-child recovery interrupted after control"));
            }
            let (drafts, payloads) = normal_chat_prechild_recovery_plan_v1(&recovery, &closed)?;
            let mut final_inventory = retained.clone();
            for payload in &payloads {
                final_inventory.push(describe(payload)?);
            }
            store.require_inventory_subset(&final_inventory)?;
            for (ordinal, payload) in payloads.iter().enumerate() {
                store.put(payload, "application/json", None)?;
                if fault == Some(Stop::Artifact { ordinal }) {
                    return Err(required("pre-child recovery artifact interrupted"));
                }
            }
            // Map the selected parent suffix row to the existing append owner.
            let prior =
                recoverable_normal_chat_preflight_snapshot_from_dir_fd(&parent.root, session)?;
            for (ordinal, draft) in drafts.into_iter().enumerate() {
                if let Some(actual) = prior.receipts().get(prefix.len() + ordinal) {
                    super::normal_chat_terminal::compare_existing(draft, actual)?;
                } else {
                    ensure_suffix(
                        &mut chain,
                        &parent.root,
                        prefix.len() + ordinal,
                        vec![draft],
                        match fault {
                            Some(Stop::Receipt {
                                ordinal: selected,
                                stage,
                            }) if selected == ordinal => {
                                Some(NormalChatTerminalInterruptionV2::ParentReceipt(stage))
                            }
                            _ => None,
                        },
                        true,
                    )?;
                }
            }
            chain.sync_all()?;
            output.sync_all()?;
            if fault == Some(Stop::BeforeReturn) {
                return Err(required("pre-child recovery interrupted before return"));
            }
            let strict = verified_snapshot_expected_run_from_dir_fd(&parent.root, session)?;
            if strict.receipts().len() != prefix.len() + 3
                || strict.verification().terminal_state != RunTerminalStateV1::Failed
            {
                return Err(required("pre-child terminal differs"));
            }
            verify_child_links_in_runtime_root(
                &strict,
                &store,
                self.dependencies.output_root(),
                true,
            )?;
            observer();
            let final_rows =
                read_only_appendable_snapshot_expected_run_from_dir_fd(&parent.root, session)?;
            let final_family = family.read_normal_chat_session_snapshot_v2()?;
            if final_family.reservations != original_family.reservations
                || final_family.admission.closed_at.is_none()
                || final_rows.verification().final_head != strict.verification().final_head
                || family.read_normal_chat_prechild_recovery_v1()?.as_ref() != Some(&recovery)
                || PermitEvidenceV1::from_record(&permits.state(&control.permit.permit_id)?)?
                    != closed
            {
                return Err(required("pre-child terminal source changed"));
            }
            siblings.recheck_closed(&family)?;
            require_parent_history_context(&context, &parent.root, session, &chain, &store)?;
            store.require_exact_inventory(&final_inventory)?;
            store.require_locator_matches(&parent.root)?;
            gate.check(&parent.root)?;
            parent.ensure_locator_matches()?;
            clock.check()?;
            Ok(RuntimeNormalChatPrechildRecoveredV1 {
                run_id: session.clone(),
                head: chain.head().clone(),
                recovery,
            })
        })();
        let unlock = gate.unlock();
        match (result, unlock) {
            (Ok(value), Ok(())) => {
                parent.ensure_locator_matches()?;
                Ok(value)
            }
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }
}
