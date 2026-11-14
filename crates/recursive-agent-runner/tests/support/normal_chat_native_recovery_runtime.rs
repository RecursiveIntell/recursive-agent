use super::*;

#[test]
fn native_recovery_is_status_only_and_unintegrated_runtime_remains_fail_closed() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (request, preflight) = fresh(&fx, &service, &session)?;
    let (family, proof, child, policy) = super::hostile::child_info(&fx, &session)?;
    let parent_before = fs::read(session.run_dir().join("receipts.ndjson"))?;
    let child_before = fs::read(child.join("receipts.ndjson"))?;
    fx.clock.0.store(2000, Ordering::SeqCst);
    let recovery =
        policy.recover_expired_normal_chat_attempt_v1(&family, "intent:one", &preflight, || {
            fx.clock.now()
        })?;
    recovery.validate_for_admission_v1(&proof)?;
    assert_eq!(
        fs::read(session.run_dir().join("receipts.ndjson"))?,
        parent_before
    );
    assert_eq!(fs::read(child.join("receipts.ndjson"))?, child_before);
    let status = match service.begin_normal_chat_attempt(&session, &request)? {
        RuntimeNormalChatBeginV2::Existing(value) => value,
        RuntimeNormalChatBeginV2::Fresh(_) => {
            return Err("recovery restored a fresh continuation".into())
        }
    };
    assert_eq!(
        status.child_policy.ok_or("policy status absent")?.state,
        recursive_agent_policy::NormalChatAttemptPolicyStateV2::RecoveredUnknown
    );
    assert!(service
        .begin_normal_chat_attempt(
            &session,
            &super::super::request(&fx, &session, "intent:later")?
        )
        .is_err());
    assert!(service
        .settle_normal_chat_attempt(
            &session,
            &request,
            &preflight,
            &report(NormalChatReportedStateV2::Succeeded)?
        )
        .is_err());
    assert!(service.close_normal_chat_session(&session).is_err());
    assert!(service
        .resume_normal_chat_session("conversation:fixture")
        .is_err());
    assert!(verified_snapshot_expected_run_from_dir_fd(
        &File::open(&child)?,
        &proof.admission.reservation.attempt.run_id()?
    )
    .is_err());
    assert_eq!(
        fs::read(session.run_dir().join("receipts.ndjson"))?,
        parent_before
    );
    assert_eq!(fs::read(child.join("receipts.ndjson"))?, child_before);
    assert_eq!(
        policy.read_normal_chat_recovery_v1(&family, "intent:one")?,
        Some(recovery)
    );
    Ok(())
}
