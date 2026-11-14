use super::*;
#[path = "normal_chat_parent_close_runtime_hostile.rs"]
mod hostile;
use recursive_agent_contracts::RunTerminalStateV1;
use recursive_agent_ledger::verified_snapshot_expected_run_from_dir_fd;

#[test]
fn empty_session_parent_closes_strictly_without_renewal_and_exact_retry_is_immutable() -> TestResult
{
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    fx.clock.0.store(400_000, Ordering::SeqCst);
    let closed = service.close_normal_chat_session(&session)?;
    assert_eq!(closed.terminal_state(), RunTerminalStateV1::Succeeded);
    assert_eq!(closed.attempt_count(), 0);
    let snapshot = verified_snapshot_expected_run_from_dir_fd(
        &File::open(session.run_dir())?,
        session.run_id(),
    )?;
    assert_eq!(snapshot.receipts().len(), 5);
    assert_eq!(snapshot.receipts()[3].kind, ReceiptKindV1::PermitRevoked);
    assert_eq!(snapshot.receipts()[4].kind, ReceiptKindV1::RunFinalized);
    let before = fs::read(session.run_dir().join("receipts.ndjson"))?;
    let family = fs::read(session.run_dir().join("family-authority.json"))?;
    fx.clock.0.store(0, Ordering::SeqCst);
    let again = service.close_normal_chat_session(&session)?;
    assert_eq!(closed.chain_head(), again.chain_head());
    assert_eq!(before, fs::read(session.run_dir().join("receipts.ndjson"))?);
    assert_eq!(
        family,
        fs::read(session.run_dir().join("family-authority.json"))?
    );
    assert!(service
        .resume_normal_chat_session("conversation:fixture")
        .is_err());
    assert!(service
        .begin_normal_chat_attempt(&session, &request(&fx, &session, "intent:late")?)
        .is_err());
    Ok(())
}
#[test]
fn parent_lifecycle_success_does_not_promote_known_failed_model_attempts() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let mut calls = Vec::new();
    for (intent, state) in [
        ("intent:z", NormalChatReportedStateV2::NotSent),
        ("intent:a", NormalChatReportedStateV2::Failed),
        ("intent:m", NormalChatReportedStateV2::Succeeded),
    ] {
        calls.push(call(
            &fx,
            &service,
            &session,
            intent,
            "materialization:one",
            state,
        )?);
    }
    let closed = service.close_normal_chat_session(&session)?;
    assert_eq!(closed.terminal_state(), RunTerminalStateV1::Succeeded);
    assert_eq!(closed.attempt_count(), 3);
    assert!(!closed.all_attempts_reported_success());
    for (req, _) in &calls {
        assert!(matches!(
            service.begin_normal_chat_attempt(&session, req)?,
            RuntimeNormalChatBeginV2::Existing(_)
        ));
    }
    let before = fs::read(session.run_dir().join("receipts.ndjson"))?;
    let (req, digest) = &calls[0];
    service.settle_normal_chat_attempt(
        &session,
        req,
        digest,
        &super::super::terminal::report(NormalChatReportedStateV2::NotSent)?,
    )?;
    assert_eq!(before, fs::read(session.run_dir().join("receipts.ndjson"))?);
    Ok(())
}
#[test]
fn pending_or_degraded_family_cannot_be_promoted_to_parent_terminal() -> TestResult {
    for unknown in [false, true] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        if unknown {
            call(
                &fx,
                &service,
                &session,
                "intent:first",
                "materialization:one",
                NormalChatReportedStateV2::OutcomeUnknown,
            )?;
        } else {
            assert!(matches!(
                service.begin_normal_chat_attempt(
                    &session,
                    &request(&fx, &session, "intent:first")?
                )?,
                RuntimeNormalChatBeginV2::Fresh(_)
            ));
        }
        let family = fs::read(session.run_dir().join("family-authority.json"))?;
        let ledger = fs::read(session.run_dir().join("receipts.ndjson"))?;
        let root =
            DurablePermitStore::require_existing_from_run_root_fd(&File::open(session.run_dir())?)?
                .read_normal_chat_session_control_record()?;
        assert!(service.close_normal_chat_session(&session).is_err());
        assert_eq!(
            family,
            fs::read(session.run_dir().join("family-authority.json"))?
        );
        assert_eq!(ledger, fs::read(session.run_dir().join("receipts.ndjson"))?);
        assert_eq!(
            root,
            DurablePermitStore::require_existing_from_run_root_fd(&File::open(session.run_dir())?)?
                .read_normal_chat_session_control_record()?
        );
    }
    Ok(())
}

#[test]
fn parent_close_preserves_denial_cancellation_and_native_revocation_history() -> TestResult {
    use recursive_agent_policy::PermitRevocationReasonV1 as Reason;
    for (reason, cancel, expected) in [
        (Some(Reason::Operator), false, RunTerminalStateV1::Succeeded),
        (
            Some(Reason::PolicySuperseded),
            false,
            RunTerminalStateV1::Denied,
        ),
        (
            Some(Reason::OperationCancelled),
            false,
            RunTerminalStateV1::Cancelled,
        ),
        (
            Some(Reason::ParentRevoked),
            false,
            RunTerminalStateV1::Cancelled,
        ),
        (None, true, RunTerminalStateV1::Cancelled),
        (Some(Reason::Operator), true, RunTerminalStateV1::Cancelled),
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let store =
            DurablePermitStore::require_existing_from_run_root_fd(&File::open(session.run_dir())?)?;
        let mut old = None;
        if let Some(reason) = reason {
            let record = store
                .read_normal_chat_session_control_record()?
                .ok_or("control absent")?;
            old = Some(store.revoke(&record.permit.permit_id, reason, start())?);
        }
        fx.clock.0.store(10, Ordering::SeqCst);
        if cancel {
            family(&fx, &session)?.revoke_parent(fx.clock.now())?;
        }
        let done = service.close_normal_chat_session(&session)?;
        assert_eq!(done.terminal_state(), expected);
        if let Some(old) = old {
            assert_eq!(store.read_normal_chat_session_control_record()?, Some(old));
        }
        let snapshot = verified_snapshot_expected_run_from_dir_fd(
            &File::open(session.run_dir())?,
            session.run_id(),
        )?;
        assert_eq!(snapshot.verification().terminal_state, expected);
        assert_eq!(
            snapshot
                .receipts()
                .iter()
                .filter(|r| r.kind == ReceiptKindV1::ParentCancelled)
                .count(),
            usize::from(expected == RunTerminalStateV1::Cancelled)
        );
    }
    Ok(())
}
