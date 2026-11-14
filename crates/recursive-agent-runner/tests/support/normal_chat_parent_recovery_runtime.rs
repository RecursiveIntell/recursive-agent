use super::*;
#[path = "normal_chat_parent_recovery_hostile.rs"]
mod hostile;
use recursive_agent_contracts::RunTerminalStateV1;
use recursive_agent_policy::NormalChatReportedStateV2;

#[test]
fn parent_recovery_mixed_known_and_unknown_keeps_actual_counts() -> TestResult {
    let fx = Fixture::new()?;
    let (session, _) = closed(&fx, Some(NormalChatReportedStateV2::Failed))?;
    let service = fx.service()?;
    let req = request(&fx, &session, "intent:two")?;
    let cap = match service.begin_normal_chat_attempt(&session, &req)? {
        RuntimeNormalChatBeginV2::Fresh(cap) => cap,
        _ => return Err("expected fresh second attempt".into()),
    };
    service.settle_normal_chat_attempt(
        &session,
        &req,
        cap.preflight_digest(),
        &super::super::super::terminal::report(NormalChatReportedStateV2::OutcomeUnknown)?,
    )?;
    let before = verify_closed_normal_chat_family_from_runtime_root_fd(
        &File::open(fx.root.path())?,
        session.run_id(),
    )?;
    let (service, _) = reader(&fx)?;
    let result = service
        .with_normal_chat_parent_recovery(true)
        .recover_normal_chat_session_parent(session.run_id())?;
    assert_eq!(result.attempt_count(), 2);
    assert_eq!(result.unknown_attempt_count(), 1);
    assert_eq!(result.terminal_state(), RunTerminalStateV1::Failed);
    let root = File::open(session.run_dir())?;
    let family = FamilyAuthorityStore::require_existing_from_dir_fd(
        &root,
        before.context().session_family_grant_v2()?,
    )?;
    let after = family.read_normal_chat_session_snapshot_v2()?;
    let mut expected = before.native_snapshot().clone();
    expected.admission.closed_at = after.admission.closed_at;
    assert_eq!(
        after, expected,
        "only family closure may change; charges stay exact"
    );
    Ok(())
}

#[test]
fn parent_recovery_closes_real_unknown_history_and_retry_is_clock_free() -> TestResult {
    for state in [None, Some(NormalChatReportedStateV2::OutcomeUnknown)] {
        let fx = Fixture::new()?;
        let (session, _) = closed(&fx, state)?;
        fs::remove_file(fx._grant_root.path().join("grant.json"))?;
        let evidence = std::env::var_os("RA_PARENT_RECOVERY_EVIDENCE_ROOT").map(PathBuf::from);
        let label = if state.is_none() {
            "missing-executor"
        } else {
            "reported-unknown"
        };
        if let Some(base) = &evidence {
            copy_tree(fx.root.path(), &base.join(format!("{label}-before")))?;
        }
        let (service, calls) = reader(&fx)?;
        let service = service.with_normal_chat_parent_recovery(true);
        let recovered: recursive_agent_runner::RuntimeNormalChatRecoveredSessionV1 =
            service.recover_normal_chat_session_parent(session.run_id())?;
        assert_eq!(recovered.run_id(), session.run_id());
        assert_eq!(recovered.terminal_state(), RunTerminalStateV1::Failed);
        assert_eq!(recovered.attempt_count(), 1);
        assert_eq!(recovered.unknown_attempt_count(), 1);
        assert!(calls.load(Ordering::SeqCst) > 0);
        let before = tree(fx.root.path())?;
        let (cold, calls) = reader(&fx)?;
        let again = cold
            .with_normal_chat_parent_recovery(true)
            .recover_normal_chat_session_parent(session.run_id())?;
        assert_eq!(again.chain_head(), recovered.chain_head());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(tree(fx.root.path())?, before);
        if let Some(base) = &evidence {
            copy_tree(fx.root.path(), &base.join(format!("{label}-after")))?;
        }
    }
    Ok(())
}

#[test]
fn parent_recovery_is_separate_default_off_and_known_only_refuses() -> TestResult {
    for state in [
        NormalChatReportedStateV2::Failed,
        NormalChatReportedStateV2::NotSent,
    ] {
        let fx = Fixture::new()?;
        let (session, _) = closed(&fx, Some(state))?;
        let before = tree(fx.root.path())?;
        for service in [
            fx.service()?,
            fx.service()?.with_expired_normal_chat_recovery(),
            fx.service()?
                .with_normal_chat_parent_recovery(true)
                .with_normal_chat_parent_recovery(false),
        ] {
            assert!(matches!(
                service.recover_normal_chat_session_parent(session.run_id()),
                Err(RuntimeServiceError::NormalChatParentRecoveryDisabled)
            ));
        }
        let (service, calls) = reader(&fx)?;
        assert!(service
            .with_normal_chat_parent_recovery(true)
            .recover_normal_chat_session_parent(session.run_id())
            .is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(tree(fx.root.path())?, before);
    }
    Ok(())
}
