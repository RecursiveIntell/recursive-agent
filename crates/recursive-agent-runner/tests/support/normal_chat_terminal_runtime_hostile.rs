use super::*;
use recursive_agent_policy::{
    FamilyAuthorityStore, NormalChatGrantContextV2, NormalChatLedgerAdmissionEvidenceV2,
    NormalChatUsageSourceV2, NormalChatUsageV2, PermitRevocationReasonV1,
};
use std::path::PathBuf;

pub(super) type ChildInfo = (
    FamilyAuthorityStore,
    NormalChatLedgerAdmissionEvidenceV2,
    PathBuf,
    DurablePermitStore,
);
pub(super) fn child_info(
    fx: &Fixture,
    session: &recursive_agent_runner::RuntimeNormalChatSessionV1,
) -> Result<ChildInfo, Box<dyn std::error::Error>> {
    let root = File::open(session.run_dir())?;
    let parent = DurablePermitStore::require_existing_from_run_root_fd(&root)?;
    let record = parent
        .read_normal_chat_session_control_record()?
        .ok_or("control absent")?;
    let context = NormalChatGrantContextV2 {
        grant: fx.authority.grant().clone(),
        session: session.session().clone(),
        root_control: record.permit,
    };
    let family = FamilyAuthorityStore::require_existing_from_dir_fd(
        &root,
        context.session_family_grant_v2()?,
    )?;
    let reservation = family
        .read_normal_chat_reservation("intent:one")?
        .ok_or("reservation absent")?;
    let path = fx
        .root
        .path()
        .join(content_digest(&reservation.attempt.run_id()?)?.to_string());
    let policy = DurablePermitStore::require_existing_from_run_root_fd(&File::open(&path)?)?;
    let proof = policy
        .read_normal_chat_ledger_admission_v2(&family, "intent:one")?
        .ok_or("proof absent")?;
    Ok((family, proof, path, policy))
}

#[test]
fn terminal_overruns_confirm_family_fence_and_unknown_precedes_bound_failure() -> TestResult {
    let mut faults = vec![None];
    for stage in [
        PermitTransitionStage::TempWrite,
        PermitTransitionStage::TempFsync,
        PermitTransitionStage::Rename,
        PermitTransitionStage::DirectoryFsync,
    ] {
        faults.push(Some(TerminalStop::Policy(
            NormalChatSettlementInterruptionV2::FamilyClose(stage),
        )));
    }
    for fault in faults {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let (req, preflight) = fresh(&fx, &service, &session)?;
        let (family, _, _, _) = child_info(&fx, &session)?;
        let mut value = report(NormalChatReportedStateV2::Succeeded)?;
        value.usage = Some(NormalChatUsageV2 {
            source: NormalChatUsageSourceV2::ProviderReported,
            input_tokens: 1,
            output_tokens: 100,
        });
        let result = service.settle_normal_chat_attempt_with_interruption(
            &session, &req, &preflight, &value, fault,
        );
        if fault.is_some() {
            assert!(result.is_err());
        } else {
            assert_eq!(result?.terminal_state(), RunTerminalStateV1::Failed);
        }
        let old_close = family
            .read_normal_chat_session_snapshot_v2()?
            .admission
            .closed_at;
        fx.clock.0.store(100, Ordering::SeqCst);
        let done = service.settle_normal_chat_attempt(&session, &req, &preflight, &value)?;
        assert_eq!(done.terminal_state(), RunTerminalStateV1::Failed);
        let current = family.read_normal_chat_session_snapshot_v2()?;
        assert!(current.admission.closed_at.is_some());
        assert_eq!(current.reservations.len(), 1);
        if old_close.is_some() {
            assert_eq!(old_close, current.admission.closed_at);
        }
        assert!(service
            .begin_normal_chat_attempt(&session, &request(&fx, &session, "intent:two")?)
            .is_err());
    }
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (req, preflight) = fresh(&fx, &service, &session)?;
    let mut value = report(NormalChatReportedStateV2::OutcomeUnknown)?;
    value.duration_ms = 2000;
    let done = service.settle_normal_chat_attempt(&session, &req, &preflight, &value)?;
    assert!(!done.settlement().violations.is_empty());
    let (_, proof, _, _) = child_info(&fx, &session)?;
    assert_eq!(
        done.settlement().ledger_outcome_v2(&proof)?,
        recursive_agent_contracts::ReceiptOutcomeV1::Failed {
            reason: "normal_chat_degraded:OUTCOME_UNKNOWN".into()
        }
    );
    Ok(())
}

#[test]
fn terminal_preserves_prior_revocation_and_never_promotes_nonoperator_to_success() -> TestResult {
    for reason in [
        PermitRevocationReasonV1::Operator,
        PermitRevocationReasonV1::ParentRevoked,
        PermitRevocationReasonV1::PolicySuperseded,
        PermitRevocationReasonV1::OperationCancelled,
    ] {
        for success in [false, true] {
            let fx = Fixture::new()?;
            let service = fx.service()?;
            let session = service.open_normal_chat_session("conversation:fixture")?;
            let (req, preflight) = fresh(&fx, &service, &session)?;
            let (_, proof, _, policy) = child_info(&fx, &session)?;
            let id = proof.control_evidence()?.permit_id;
            let original = policy.revoke(&id, reason.clone(), start())?;
            fx.clock.0.store(400_000, Ordering::SeqCst);
            let value = report(if success {
                NormalChatReportedStateV2::Succeeded
            } else {
                NormalChatReportedStateV2::Failed
            })?;
            let result = service.settle_normal_chat_attempt(&session, &req, &preflight, &value);
            assert_eq!(
                result.is_ok(),
                !success || reason == PermitRevocationReasonV1::Operator,
                "{reason:?} success={success}"
            );
            assert_eq!(policy.state(&id)?, original);
        }
    }
    Ok(())
}

#[test]
fn terminal_rejects_missing_storage_incomplete_preflight_and_wrong_digest_without_authority_recreation(
) -> TestResult {
    for missing in ["artifacts", "permits", "run"] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let (req, preflight) = fresh(&fx, &service, &session)?;
        let (_, _, path, _) = child_info(&fx, &session)?;
        let target = if missing == "run" {
            path.clone()
        } else {
            path.join(missing)
        };
        let detached = if missing == "run" {
            fx.root.path().join("detached-child")
        } else {
            path.join(format!("detached-{missing}"))
        };
        fs::rename(&target, detached)?;
        assert!(service
            .settle_normal_chat_attempt(
                &session,
                &req,
                &preflight,
                &report(NormalChatReportedStateV2::Succeeded)?
            )
            .is_err());
        assert!(!target.exists(), "{missing} was recreated");
    }
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:one")?;
    assert!(service
        .begin_normal_chat_attempt_with_interruption(&session, &req, Some(Stop::AfterPolicyConsume))
        .is_err());
    let (family, proof, _, policy) = child_info(&fx, &session)?;
    let value = report(NormalChatReportedStateV2::Succeeded)?;
    assert!(service
        .settle_normal_chat_attempt(&session, &req, &proof.preflight.receipt_digest, &value)
        .is_err());
    assert!(policy
        .read_normal_chat_attempt_v2(&family, "intent:one")?
        .settlement
        .is_none());
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (req, _) = fresh(&fx, &service, &session)?;
    let (family, _, _, policy) = child_info(&fx, &session)?;
    assert!(service
        .settle_normal_chat_attempt(&session, &req, &ContentDigest::compute(b"wrong"), &value)
        .is_err());
    assert!(policy
        .read_normal_chat_attempt_v2(&family, "intent:one")?
        .settlement
        .is_none());
    Ok(())
}

#[test]
fn terminal_late_locator_content_or_orphan_change_never_returns_success_or_restores_send(
) -> TestResult {
    for event in [
        "parent-artifacts",
        "child-artifacts",
        "child-permits",
        "parent-run",
        "child-run",
        "orphan",
        "content",
        "gate",
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let (req, preflight) = fresh(&fx, &service, &session)?;
        let (_, _, child, _) = child_info(&fx, &session)?;
        let action = std::cell::RefCell::new(Ok::<(), Box<dyn std::error::Error>>(()));
        let value = report(NormalChatReportedStateV2::Succeeded)?;
        let result = service.settle_normal_chat_attempt_with_observer(
            &session,
            &req,
            &preflight,
            &value,
            None,
            || {
                *action.borrow_mut() = (|| -> TestResult {
                    match event {
                        "parent-artifacts" | "child-artifacts" | "child-permits" => {
                            let root = if event == "parent-artifacts" {
                                session.run_dir()
                            } else {
                                child.as_path()
                            };
                            let part = if event == "child-permits" {
                                "permits"
                            } else {
                                "artifacts"
                            };
                            fs::rename(root.join(part), root.join(format!("detached-{part}")))?;
                            fs::create_dir(root.join(part))?;
                            fs::set_permissions(
                                root.join(part),
                                fs::Permissions::from_mode(0o700),
                            )?;
                        }
                        "parent-run" | "child-run" => {
                            let old = if event == "parent-run" {
                                session.run_dir()
                            } else {
                                child.as_path()
                            };
                            fs::rename(old, fx.root.path().join(format!("detached-{event}")))?;
                            fs::create_dir(old)?;
                        }
                        "orphan" => {
                            ArtifactStore::from_run_root_fd(&File::open(&child)?, false)?.put(
                                b"{}",
                                "application/json",
                                None,
                            )?;
                        }
                        "content" => {
                            let path = fs::read_dir(child.join("artifacts"))?
                                .filter_map(Result::ok)
                                .map(|x| x.path())
                                .find(|p| p.extension().is_none())
                                .ok_or("payload absent")?;
                            fs::write(path, b"changed")?;
                        }
                        _ => {
                            let path = session.run_dir().join(".normal-chat-runtime.lock");
                            fs::rename(&path, session.run_dir().join("detached-gate"))?;
                            fs::write(&path, b"")?;
                            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
                        }
                    }
                    Ok(())
                })();
            },
        );
        action.into_inner()?;
        assert!(result.is_err(), "{event} escaped terminal return fence");
        assert!(
            !matches!(
                service.begin_normal_chat_attempt(&session, &req),
                Ok(RuntimeNormalChatBeginV2::Fresh(_))
            ),
            "{event} restored Fresh"
        );
    }
    Ok(())
}

#[test]
fn independent_conflicting_settlers_have_one_immutable_terminal_winner() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = Arc::new(service.open_normal_chat_session("conversation:fixture")?);
    let (req, preflight) = fresh(&fx, &service, &session)?;
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let mut workers = Vec::new();
    for duration in [40, 41] {
        let worker = fx.service()?;
        let session = session.clone();
        let req = req.clone();
        let preflight = preflight.clone();
        let barrier = barrier.clone();
        let mut value = report(NormalChatReportedStateV2::Succeeded)?;
        value.duration_ms = duration;
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            worker
                .settle_normal_chat_attempt(&session, &req, &preflight, &value)
                .is_ok()
        }));
    }
    let mut winners = 0;
    for worker in workers {
        winners += usize::from(worker.join().map_err(|_| "settler panicked")?);
    }
    assert_eq!(winners, 1);
    let (family, _, _, policy) = child_info(&fx, &session)?;
    assert!(policy
        .read_normal_chat_attempt_v2(&family, "intent:one")?
        .settlement
        .is_some());
    Ok(())
}
