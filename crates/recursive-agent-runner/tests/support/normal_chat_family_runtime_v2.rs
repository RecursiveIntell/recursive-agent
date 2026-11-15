use super::*;
#[path = "normal_chat_family_runtime_hostile.rs"]
mod hostile;
#[path = "normal_chat_parent_close_runtime.rs"]
mod parent_close;
use recursive_agent_policy::{
    FamilyAuthorityStore, NormalChatGrantContextV2, NormalChatReportedStateV2,
};

fn call(
    fx: &Fixture,
    service: &RuntimeService,
    session: &recursive_agent_runner::RuntimeNormalChatSessionV1,
    intent: &str,
    materialization: &str,
    state: NormalChatReportedStateV2,
) -> Result<(NormalChatCallRequestV2, ContentDigest), Box<dyn std::error::Error>> {
    let mut req = request(fx, session, intent)?;
    req.operation.materialization_ref = materialization.into();
    let cap = match service.begin_normal_chat_attempt(session, &req)? {
        RuntimeNormalChatBeginV2::Fresh(cap) => cap,
        _ => return Err("not Fresh".into()),
    };
    let digest = cap.preflight_digest().clone();
    service.settle_normal_chat_attempt(session, &req, &digest, &super::terminal::report(state)?)?;
    Ok((req, digest))
}
fn family(
    fx: &Fixture,
    session: &recursive_agent_runner::RuntimeNormalChatSessionV1,
) -> Result<FamilyAuthorityStore, Box<dyn std::error::Error>> {
    let root = File::open(session.run_dir())?;
    let record = DurablePermitStore::require_existing_from_run_root_fd(&root)?
        .read_normal_chat_session_control_record()?
        .ok_or("control absent")?;
    let context = NormalChatGrantContextV2 {
        grant: fx.authority.grant().clone(),
        session: session.session().clone(),
        root_control: record.permit,
    };
    Ok(FamilyAuthorityStore::require_existing_from_dir_fd(
        &root,
        context.session_family_grant_v2()?,
    )?)
}

#[test]
fn serial_family_respects_receipt_order_equal_times_materializations_and_cumulative_caps(
) -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let mut calls = Vec::new();
    for (intent, materialization, state, ordinal) in [
        (
            "intent:z",
            "materialization:one",
            NormalChatReportedStateV2::NotSent,
            1,
        ),
        (
            "intent:a",
            "materialization:two",
            NormalChatReportedStateV2::Failed,
            1,
        ),
        (
            "intent:m",
            "materialization:one",
            NormalChatReportedStateV2::Succeeded,
            2,
        ),
    ] {
        let (req, digest) = call(&fx, &service, &session, intent, materialization, state)?;
        let stored = family(&fx, &session)?
            .read_normal_chat_reservation(intent)?
            .ok_or("reservation absent")?;
        assert_eq!(stored.attempt.attempt_number, ordinal);
        calls.push((req, digest));
    }
    let snapshot = family(&fx, &session)?.read_normal_chat_session_snapshot_v2()?;
    assert_eq!(snapshot.reservations.len(), 3);
    assert_eq!(
        snapshot
            .reservations
            .iter()
            .map(|r| r.attempt.operation.budget.output_reserve)
            .sum::<u32>(),
        30
    );
    let parent = appendable_snapshot_expected_run_from_dir_fd(
        &File::open(session.run_dir())?,
        session.run_id(),
    )?;
    assert_eq!(parent.receipts().len(), 12);
    let before = fs::read(session.run_dir().join("receipts.ndjson"))?;
    let count = fs::read_dir(session.run_dir().join("artifacts"))?.count();
    assert!(service
        .begin_normal_chat_attempt(&session, &request(&fx, &session, "intent:fourth")?)
        .is_err());
    assert_eq!(before, fs::read(session.run_dir().join("receipts.ndjson"))?);
    assert_eq!(
        count,
        fs::read_dir(session.run_dir().join("artifacts"))?.count()
    );
    for (req, _) in calls {
        assert!(matches!(
            service.begin_normal_chat_attempt(&session, &req)?,
            RuntimeNormalChatBeginV2::Existing(_)
        ));
    }
    Ok(())
}

#[test]
fn resume_preserves_original_control_and_old_retry_cannot_append_over_newer_pending_history(
) -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (first, digest) = call(
        &fx,
        &service,
        &session,
        "intent:z",
        "materialization:one",
        NormalChatReportedStateV2::NotSent,
    )?;
    fx.clock.0.store(10, Ordering::SeqCst);
    call(
        &fx,
        &service,
        &session,
        "intent:a",
        "materialization:two",
        NormalChatReportedStateV2::Succeeded,
    )?;
    let store =
        DurablePermitStore::require_existing_from_run_root_fd(&File::open(session.run_dir())?)?;
    let control = store.read_normal_chat_session_control_record()?;
    let fresh_service = fx.service()?;
    let resumed = fresh_service.resume_normal_chat_session("conversation:fixture")?;
    assert_eq!(resumed.run_id(), session.run_id());
    assert_eq!(store.read_normal_chat_session_control_record()?, control);
    fx.clock.0.store(20, Ordering::SeqCst);
    let third = request(&fx, &resumed, "intent:m")?;
    let third_cap = match fresh_service.begin_normal_chat_attempt(&resumed, &third)? {
        RuntimeNormalChatBeginV2::Fresh(cap) => cap,
        _ => return Err("third not Fresh".into()),
    };
    let before = fs::read(resumed.run_dir().join("receipts.ndjson"))?;
    fresh_service.settle_normal_chat_attempt(
        &resumed,
        &first,
        &digest,
        &super::terminal::report(NormalChatReportedStateV2::NotSent)?,
    )?;
    assert_eq!(before, fs::read(resumed.run_dir().join("receipts.ndjson"))?);
    fresh_service.settle_normal_chat_attempt(
        &resumed,
        &third,
        third_cap.preflight_digest(),
        &super::terminal::report(NormalChatReportedStateV2::Succeeded)?,
    )?;
    let closed = fs::read(resumed.run_dir().join("receipts.ndjson"))?;
    fresh_service.settle_normal_chat_attempt(
        &resumed,
        &first,
        &digest,
        &super::terminal::report(NormalChatReportedStateV2::NotSent)?,
    )?;
    assert_eq!(closed, fs::read(resumed.run_dir().join("receipts.ndjson"))?);
    Ok(())
}

#[test]
fn output_denial_is_nonmutating_and_a_smaller_valid_reserve_can_follow() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let mut first = request(&fx, &session, "intent:first")?;
    first.operation.budget.output_reserve = 60;
    let cap = match service.begin_normal_chat_attempt(&session, &first)? {
        RuntimeNormalChatBeginV2::Fresh(cap) => cap,
        _ => return Err("not Fresh".into()),
    };
    service.settle_normal_chat_attempt(
        &session,
        &first,
        cap.preflight_digest(),
        &super::terminal::report(NormalChatReportedStateV2::NotSent)?,
    )?;
    let mut large = request(&fx, &session, "intent:large")?;
    large.operation.budget.output_reserve = 50;
    let before = fs::read(session.run_dir().join("receipts.ndjson"))?;
    let count = fs::read_dir(session.run_dir().join("artifacts"))?.count();
    assert!(service.begin_normal_chat_attempt(&session, &large).is_err());
    assert_eq!(before, fs::read(session.run_dir().join("receipts.ndjson"))?);
    assert_eq!(
        count,
        fs::read_dir(session.run_dir().join("artifacts"))?.count()
    );
    let mut small = request(&fx, &session, "intent:small")?;
    small.operation.budget.output_reserve = 40;
    assert!(matches!(
        service.begin_normal_chat_attempt(&session, &small)?,
        RuntimeNormalChatBeginV2::Fresh(_)
    ));
    Ok(())
}

#[test]
fn cross_call_clock_regression_unknown_outcome_and_unclosed_prefix_never_admit_next() -> TestResult
{
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:first")?;
    let cap = match service.begin_normal_chat_attempt(&session, &req)? {
        RuntimeNormalChatBeginV2::Fresh(cap) => cap,
        _ => return Err("not Fresh".into()),
    };
    fx.clock.0.store(100, Ordering::SeqCst);
    service.settle_normal_chat_attempt(
        &session,
        &req,
        cap.preflight_digest(),
        &super::terminal::report(NormalChatReportedStateV2::Succeeded)?,
    )?;
    fx.clock.0.store(50, Ordering::SeqCst);
    let before = fs::read(session.run_dir().join("receipts.ndjson"))?;
    assert!(service
        .begin_normal_chat_attempt(&session, &request(&fx, &session, "intent:backwards")?)
        .is_err());
    assert_eq!(before, fs::read(session.run_dir().join("receipts.ndjson"))?);
    for unknown in [true, false] {
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
            let req = request(&fx, &session, "intent:first")?;
            assert!(service
                .begin_normal_chat_attempt_with_interruption(
                    &session,
                    &req,
                    Some(Stop::AfterPreparation)
                )
                .is_err());
        }
        assert!(service
            .begin_normal_chat_attempt(&session, &request(&fx, &session, "intent:next")?)
            .is_err());
        assert!(service
            .resume_normal_chat_session("conversation:fixture")
            .is_err());
    }
    Ok(())
}
