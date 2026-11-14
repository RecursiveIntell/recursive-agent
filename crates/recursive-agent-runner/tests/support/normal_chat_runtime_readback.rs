use super::*;
use recursive_agent_policy::NormalChatReportedStateV2;

#[test]
fn existing_session_lookup_is_noncreating_and_preserves_pending_identity() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let expected = fx
        .authority
        .normal_chat_session("conversation:fixture", None)?
        .run_id()?;
    assert!(service.lookup_normal_chat_session(&expected).is_err());
    assert_eq!(std::fs::read_dir(fx.root.path())?.count(), 0);
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:lookup")?;
    service.begin_normal_chat_attempt(&session, &req)?;
    let loaded = service.lookup_normal_chat_session(session.run_id())?;
    assert_eq!(loaded.run_id(), session.run_id());
    assert_eq!(loaded.session(), session.session());
    assert!(matches!(
        service.begin_normal_chat_attempt(&loaded, &req)?,
        RuntimeNormalChatBeginV2::Existing(_)
    ));
    Ok(())
}
#[test]
fn readback_reconstructs_request_and_native_state_without_current_grant_or_send() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:readback")?;
    let fresh = match service.begin_normal_chat_attempt(&session, &req)? {
        RuntimeNormalChatBeginV2::Fresh(v) => v,
        _ => return Err("not fresh".into()),
    };
    let cold = runtime(fx.root.path(), fx.clock.clone())?;
    let pending = cold.read_normal_chat_attempt(session.run_id(), &req.dispatch_intent_ref)?;
    assert_eq!(pending.request(), &req);
    assert_eq!(
        pending.policy().state,
        NormalChatAttemptPolicyStateV2::Consumed
    );
    let report = super::terminal::report(NormalChatReportedStateV2::Succeeded)?;
    service.settle_normal_chat_attempt(&session, &req, fresh.preflight_digest(), &report)?;
    let done = cold.read_normal_chat_attempt(session.run_id(), &req.dispatch_intent_ref)?;
    assert_eq!(done.request(), &req);
    assert_eq!(done.policy().state, NormalChatAttemptPolicyStateV2::Settled);
    assert_eq!(
        done.policy()
            .settlement
            .as_ref()
            .ok_or("settlement absent")?
            .report,
        report
    );
    assert!(cold
        .read_normal_chat_attempt(session.run_id(), "intent:absent")
        .is_err());
    Ok(())
}
