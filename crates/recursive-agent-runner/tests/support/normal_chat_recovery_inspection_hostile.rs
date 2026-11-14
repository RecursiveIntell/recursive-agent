use super::*;
use recursive_agent_policy::PermitRevocationReasonV1;

#[test]
fn changed_startup_grant_does_not_replace_the_historical_context() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (request, _, _, _) = admitted(&fx, &service, &session)?;
    let other = tempfile::tempdir()?;
    fs::set_permissions(other.path(), fs::Permissions::from_mode(0o700))?;
    let mut grant = fx.authority.grant().clone();
    grant.revision += 1;
    grant.caps.max_attempts += 1;
    grant.policy_digest = grant.computed_policy_digest()?;
    let path = other.path().join("grant.json");
    fs::write(&path, serde_json::to_vec(&grant)?)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let authority = NormalChatEgressGrantStore::from_dir_fd(&File::open(other.path())?)?
        .load_from_path(&path, HOME, start())?;
    let before = tree(fx.root.path())?;
    let (reader, calls) = reader(&fx)?;
    let reader = reader.with_normal_chat_egress_grant(authority);
    let view =
        reader.inspect_pending_normal_chat_attempt_for_recovery(session.run_id(), "intent:one")?;
    assert_eq!(view.session().grant_revision, fx.authority.grant().revision);
    assert_eq!(view.request(), &request);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}

#[test]
fn revoked_root_is_inspectable_but_cannot_authorize_or_renew() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (request, _, _, _) = admitted(&fx, &service, &session)?;
    let policy =
        DurablePermitStore::require_existing_from_run_root_fd(&File::open(session.run_dir())?)?;
    let original = policy
        .read_normal_chat_session_control_record()?
        .ok_or("root absent")?;
    let revoked = policy.revoke(
        &original.permit.permit_id,
        PermitRevocationReasonV1::OperationCancelled,
        start() + TimeDelta::seconds(2),
    )?;
    let before = tree(fx.root.path())?;
    let (reader, calls) = reader(&fx)?;
    let view =
        reader.inspect_pending_normal_chat_attempt_for_recovery(session.run_id(), "intent:one")?;
    assert_eq!(view.request(), &request);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        policy.read_normal_chat_session_control_record()?,
        Some(revoked)
    );
    assert_eq!(tree(fx.root.path())?, before);
    assert!(!matches!(
        service.begin_normal_chat_attempt(&session, &request),
        Ok(RuntimeNormalChatBeginV2::Fresh(_))
    ));
    Ok(())
}

#[test]
fn complete_prior_sibling_is_verified_and_its_old_locator_fence_is_retained() -> TestResult {
    for substitute in [false, true] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let old_request = request(&fx, &session, "intent:closed")?;
        let old = match service.begin_normal_chat_attempt(&session, &old_request)? {
            RuntimeNormalChatBeginV2::Fresh(cap) => cap,
            _ => return Err("first not Fresh".into()),
        };
        service.settle_normal_chat_attempt(
            &session,
            &old_request,
            old.preflight_digest(),
            &super::super::terminal::report(
                recursive_agent_policy::NormalChatReportedStateV2::NotSent,
            )?,
        )?;
        admitted(&fx, &service, &session)?;
        let (reader, calls) = reader(&fx)?;
        let mut error = None;
        let result = reader.inspect_pending_normal_chat_attempt_for_recovery_with_observer(
            session.run_id(),
            "intent:one",
            || {
                if substitute {
                    error = replace(&old.child_run_dir().join("artifacts")).err();
                }
            },
        );
        if let Some(error) = error {
            return Err(error.into());
        }
        assert_eq!(result.is_err(), substitute);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn sdk_report_without_ledger_terminal_cannot_be_read_as_missing_executor_outcome() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (_, preflight, child, family) = admitted(&fx, &service, &session)?;
    let policy = DurablePermitStore::require_existing_from_run_root_fd(&File::open(child)?)?;
    policy.settle_normal_chat_attempt_v2(
        &family,
        "intent:one",
        &preflight,
        &super::super::terminal::report(
            recursive_agent_policy::NormalChatReportedStateV2::NotSent,
        )?,
        || start() + TimeDelta::seconds(2),
    )?;
    let before = tree(fx.root.path())?;
    assert!(reader(&fx)?
        .0
        .inspect_pending_normal_chat_attempt_for_recovery(session.run_id(), "intent:one")
        .is_err());
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}

#[test]
fn native_disposition_during_inspection_is_detected_without_refund_or_sdk_fiction() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (_, preflight, child, family) = admitted(&fx, &service, &session)?;
    let policy = DurablePermitStore::require_existing_from_run_root_fd(&File::open(child)?)?;
    let old = family.read_normal_chat_session_snapshot_v2()?;
    let mut observed = None;
    let result = reader(&fx)?
        .0
        .inspect_pending_normal_chat_attempt_for_recovery_with_observer(
            session.run_id(),
            "intent:one",
            || {
                observed = Some(policy.recover_expired_normal_chat_attempt_v1(
                    &family,
                    "intent:one",
                    &preflight,
                    || start() + TimeDelta::seconds(2),
                ));
            },
        );
    let recovery = observed.ok_or("observer not reached")??;
    assert!(result.is_err());
    assert_eq!(
        policy.read_normal_chat_recovery_v1(&family, "intent:one")?,
        Some(recovery)
    );
    let after = family.read_normal_chat_session_snapshot_v2()?;
    assert_eq!(after.reservations, old.reservations);
    assert!(after.admission.closed_at.is_some());
    assert!(policy
        .read_normal_chat_attempt_v2(&family, "intent:one")?
        .outcome
        .is_none());
    Ok(())
}
