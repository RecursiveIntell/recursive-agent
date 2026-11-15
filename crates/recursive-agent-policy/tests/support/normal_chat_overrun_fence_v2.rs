use super::*;

fn next_request(fx: &Fixture, intent: &str) -> NormalChatFamilyReservationRequestV2 {
    NormalChatFamilyReservationRequestV2 {
        operation: fx.reservation.attempt.operation.clone(),
        provider_request_digest: ContentDigest::compute(b"next-body"),
        provider_request_bytes: b"next-body".len() as u64,
        dispatch_intent_ref: intent.into(),
        parent_admission_receipt_id: fx
            .reservation
            .child_control
            .request
            .parent_admission_receipt_id
            .clone(),
        requested_budget: fx
            .reservation
            .child_control
            .request
            .requested_budget
            .clone(),
    }
}
fn overrun(output: bool) -> Result<NormalChatExecutorReportV2, Box<dyn std::error::Error>> {
    let mut value = report()?;
    if output {
        if let Some(usage) = &mut value.usage {
            usage.output_tokens = 11;
        }
    } else {
        value.duration_ms = 1001;
    }
    Ok(value)
}
fn family_bytes(fx: &Fixture) -> Result<Vec<u8>, std::io::Error> {
    fs::read(fx._parent_root.path().join("family-authority.json"))
}
fn closed_at(fx: &Fixture) -> Result<Option<DateTime<Utc>>, Box<dyn std::error::Error>> {
    let value: serde_json::Value = serde_json::from_slice(&family_bytes(fx)?)?;
    Ok(serde_json::from_value(
        value["normal_chat_session"]["closed_at"].clone(),
    )?)
}

#[test]
fn reported_overrun_closes_new_admission_durably_without_refund() -> TestResult {
    for output in [false, true] {
        let fx = Fixture::new()?;
        let cap = fresh(fx.begin()?)?;
        let family = historical(&fx)?;
        let charged = family.reserved_budget()?;
        let result = fx.child_store.settle_normal_chat_attempt_v2(
            &family,
            "intent:first",
            &cap.preflight().receipt_digest,
            &overrun(output)?,
            now,
        )?;
        assert!(!result.violations.is_empty());
        assert_eq!(closed_at(&fx)?, Some(now()));
        let reopened = historical(&fx)?;
        assert!(matches!(
            reopened.reserve_normal_chat_attempt(
                &fx.authority,
                &next_request(&fx, "intent:after-overrun"),
                now()
            ),
            Err(recursive_agent_policy::PolicyError::NormalChatEgressDenied(
                recursive_agent_policy::NormalChatEgressDenialV1::RunClosed
            ))
        ));
        assert_eq!(reopened.reserved_budget()?, charged);
        assert_eq!(
            reopened.read_normal_chat_reservation("intent:first")?,
            Some(fx.reservation.clone())
        );
        let before = family_bytes(&fx)?;
        let retried = fx.child_store.settle_normal_chat_attempt_v2(
            &reopened,
            "intent:first",
            &cap.preflight().receipt_digest,
            &overrun(output)?,
            || now() + TimeDelta::hours(2),
        )?;
        assert_eq!(result, retried);
        assert_eq!(family_bytes(&fx)?, before);
    }
    Ok(())
}

#[test]
fn already_reserved_sibling_cannot_begin_after_overrun_fence() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let sibling = fx.family.reserve_normal_chat_attempt(
        &fx.authority,
        &next_request(&fx, "intent:sibling"),
        now,
    )?;
    let sibling_root = tempfile::tempdir()?;
    let sibling_store = store(sibling_root.path())?;
    fx.child_store.settle_normal_chat_attempt_v2(
        &historical(&fx)?,
        "intent:first",
        &cap.preflight().receipt_digest,
        &overrun(true)?,
        now,
    )?;
    assert!(fx
        .family
        .guard_child_dispatch(
            &fx.authority,
            &sibling.attempt.run_id()?,
            &sibling.child_control.child_control_permit_id,
            now
        )
        .is_err());
    assert!(sibling_store
        .begin_normal_chat_attempt_v2(&fx.authority, &fx.family, "intent:sibling", now)
        .is_err());
    assert!(permit_paths(sibling_root.path())?.is_empty());
    assert!(matches!(fx.begin()?, NormalChatAttemptBeginV2::Existing(_)));
    Ok(())
}

#[test]
fn parent_close_failure_never_publishes_child_settlement() -> TestResult {
    for stage in [
        PermitTransitionStage::TempWrite,
        PermitTransitionStage::TempFsync,
        PermitTransitionStage::Rename,
        PermitTransitionStage::DirectoryFsync,
    ] {
        let fx = Fixture::new()?;
        let cap = fresh(fx.begin()?)?;
        let family = historical(&fx)?;
        let charged = family.reserved_budget()?;
        assert!(fx
            .child_store
            .settle_normal_chat_attempt_v2_with_interruption(
                &family,
                "intent:first",
                &cap.preflight().receipt_digest,
                &overrun(true)?,
                now,
                Some(NormalChatSettlementInterruptionV2::FamilyClose(stage)),
            )
            .is_err());
        let view = fx
            .child_store
            .read_normal_chat_attempt_v2(&family, "intent:first")?;
        assert_eq!(view.state, NormalChatAttemptPolicyStateV2::Consumed);
        assert!(view.outcome.is_none());
        assert!(view.settlement.is_none());
        let published = matches!(
            stage,
            PermitTransitionStage::Rename | PermitTransitionStage::DirectoryFsync
        );
        assert_eq!(closed_at(&fx)?.is_some(), published);
        let before = family_bytes(&fx)?;
        let reopened = historical(&fx)?;
        if published {
            assert!(reopened
                .reserve_normal_chat_attempt(
                    &fx.authority,
                    &next_request(&fx, "intent:blocked"),
                    now()
                )
                .is_err());
        }
        fx.child_store.settle_normal_chat_attempt_v2(
            &reopened,
            "intent:first",
            &cap.preflight().receipt_digest,
            &overrun(true)?,
            || now() + TimeDelta::milliseconds(10),
        )?;
        if published {
            assert_eq!(family_bytes(&fx)?, before);
        }
        assert!(closed_at(&fx)?.is_some());
        assert_eq!(reopened.reserved_budget()?, charged);
    }
    Ok(())
}

#[test]
fn child_publication_failure_preserves_closed_admission() -> TestResult {
    for stage in [
        PermitTransitionStage::TempWrite,
        PermitTransitionStage::TempFsync,
        PermitTransitionStage::Rename,
        PermitTransitionStage::DirectoryFsync,
    ] {
        let fx = Fixture::new()?;
        let cap = fresh(fx.begin()?)?;
        let family = historical(&fx)?;
        assert!(fx
            .child_store
            .settle_normal_chat_attempt_v2_with_interruption(
                &family,
                "intent:first",
                &cap.preflight().receipt_digest,
                &overrun(true)?,
                now,
                Some(NormalChatSettlementInterruptionV2::ChildOutcome(stage)),
            )
            .is_err());
        assert_eq!(closed_at(&fx)?, Some(now()));
        let reopened = historical(&fx)?;
        assert!(reopened
            .reserve_normal_chat_attempt(&fx.authority, &next_request(&fx, "intent:blocked"), now())
            .is_err());
        let before = family_bytes(&fx)?;
        let view = fx
            .child_store
            .read_normal_chat_attempt_v2(&reopened, "intent:first")?;
        let settled = fx.child_store.settle_normal_chat_attempt_v2(
            &reopened,
            "intent:first",
            &cap.preflight().receipt_digest,
            &overrun(true)?,
            || now() + TimeDelta::milliseconds(10),
        )?;
        if let Some(existing) = view.settlement {
            assert_eq!(settled, existing);
        }
        assert_eq!(family_bytes(&fx)?, before);
    }
    Ok(())
}

#[test]
fn exact_ack_retry_still_executes_family_durability_fence() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    let first = fx.child_store.settle_normal_chat_attempt_v2(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        &overrun(true)?,
        now,
    )?;
    let before = family_bytes(&fx)?;
    assert!(fx
        .child_store
        .settle_normal_chat_attempt_v2_with_interruption(
            &family,
            "intent:first",
            &cap.preflight().receipt_digest,
            &overrun(true)?,
            now,
            Some(NormalChatSettlementInterruptionV2::FamilyClose(
                PermitTransitionStage::DirectoryFsync
            )),
        )
        .is_err());
    assert_eq!(family_bytes(&fx)?, before);
    let retried = fx.child_store.settle_normal_chat_attempt_v2(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        &overrun(true)?,
        now,
    )?;
    assert_eq!(retried, first);
    Ok(())
}

#[test]
fn preexisting_unfenced_settlement_is_fenced_on_exact_retry() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    let first = fx.child_store.settle_normal_chat_attempt_v2(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        &overrun(true)?,
        now,
    )?;
    // Offline fixture for the preceding unpublished P2 version, which stored
    // overrun metadata without family closure. Production never reopens state.
    let mut prior: serde_json::Value = serde_json::from_slice(&family_bytes(&fx)?)?;
    prior["normal_chat_session"]["closed_at"] = serde_json::Value::Null;
    fs::write(
        fx._parent_root.path().join("family-authority.json"),
        serde_json::to_vec(&prior)?,
    )?;
    let reopened = historical(&fx)?;
    assert_eq!(closed_at(&fx)?, None);
    let retry = fx.child_store.settle_normal_chat_attempt_v2(
        &reopened,
        "intent:first",
        &cap.preflight().receipt_digest,
        &overrun(true)?,
        || now() + TimeDelta::hours(2),
    )?;
    assert_eq!(retry, first);
    assert_eq!(closed_at(&fx)?, Some(now() + TimeDelta::hours(2)));
    Ok(())
}

#[test]
fn clock_regression_before_fence_does_not_publish_or_mutate_admission() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    let before = family_bytes(&fx)?;
    let mut samples = 0;
    assert!(fx
        .child_store
        .settle_normal_chat_attempt_v2(
            &family,
            "intent:first",
            &cap.preflight().receipt_digest,
            &overrun(true)?,
            || {
                samples += 1;
                now() + TimeDelta::milliseconds(if samples == 1 { 20 } else { 19 })
            }
        )
        .is_err());
    assert_eq!(samples, 2);
    assert_eq!(family_bytes(&fx)?, before);
    assert!(fx
        .child_store
        .read_normal_chat_attempt_v2(&family, "intent:first")?
        .settlement
        .is_none());
    Ok(())
}

#[test]
fn existing_closure_and_parent_revocation_are_preserved_on_late_report() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    family.close_normal_chat_session(now() + TimeDelta::milliseconds(10))?;
    family.revoke_parent(now() + TimeDelta::milliseconds(20))?;
    let before = family_bytes(&fx)?;
    let settled = fx.child_store.settle_normal_chat_attempt_v2(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        &overrun(true)?,
        || now() + TimeDelta::hours(2),
    )?;
    assert!(!settled.violations.is_empty());
    assert_eq!(family_bytes(&fx)?, before);
    assert!(family.parent_is_revoked()?);
    assert_eq!(closed_at(&fx)?, Some(now() + TimeDelta::milliseconds(10)));
    Ok(())
}

#[test]
fn independent_children_can_report_concurrently_across_a_fence() -> TestResult {
    let fx = Fixture::new()?;
    let first = fresh(fx.begin()?)?;
    fx.family.reserve_normal_chat_attempt(
        &fx.authority,
        &next_request(&fx, "intent:sibling"),
        now,
    )?;
    let sibling_root = tempfile::tempdir()?;
    let sibling_store = store(sibling_root.path())?;
    let second = fresh(sibling_store.begin_normal_chat_attempt_v2(
        &fx.authority,
        &fx.family,
        "intent:sibling",
        now,
    )?)?;
    let family_one = historical(&fx)?;
    let family_two = historical(&fx)?;
    let child_one = fx.child_store.clone();
    let child_two = sibling_store.clone();
    let digest_one = first.preflight().receipt_digest.clone();
    let digest_two = second.preflight().receipt_digest.clone();
    let report_one = overrun(true)?;
    let report_two = report()?;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let first_barrier = barrier.clone();
    let one = std::thread::spawn(move || {
        first_barrier.wait();
        child_one.settle_normal_chat_attempt_v2(
            &family_one,
            "intent:first",
            &digest_one,
            &report_one,
            now,
        )
    });
    let two = std::thread::spawn(move || {
        barrier.wait();
        child_two.settle_normal_chat_attempt_v2(
            &family_two,
            "intent:sibling",
            &digest_two,
            &report_two,
            now,
        )
    });
    let over = one
        .join()
        .map_err(|_| "first reporting thread panicked")??;
    let ordinary = two
        .join()
        .map_err(|_| "second reporting thread panicked")??;
    assert!(!over.violations.is_empty());
    assert!(ordinary.violations.is_empty());
    assert_eq!(
        ordinary.outcome.reported.state,
        ReportedEffectStateV1::Succeeded
    );
    assert_eq!(closed_at(&fx)?, Some(now()));
    Ok(())
}

#[test]
fn fence_clock_is_fresh_after_a_new_reservation_and_preserves_its_charge() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    let request = next_request(&fx, "intent:concurrent");
    let mut samples = 0;
    let mut reserved = None;
    fx.child_store.settle_normal_chat_attempt_v2(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        &overrun(true)?,
        || {
            samples += 1;
            if samples == 1 {
                reserved = Some(family.reserve_normal_chat_attempt(
                    &fx.authority,
                    &request,
                    now() + TimeDelta::milliseconds(10),
                ));
                now() + TimeDelta::milliseconds(5)
            } else {
                now() + TimeDelta::milliseconds(20)
            }
        },
    )?;
    let reserved = reserved.ok_or("concurrent reservation was not exercised")??;
    assert_eq!(closed_at(&fx)?, Some(now() + TimeDelta::milliseconds(20)));
    assert_eq!(
        family.read_normal_chat_reservation("intent:concurrent")?,
        Some(reserved)
    );
    assert_eq!(samples, 2);
    Ok(())
}

#[test]
fn violations_in_failed_or_ambiguous_reports_also_close_admission() -> TestResult {
    for state in [
        NormalChatReportedStateV2::Failed,
        NormalChatReportedStateV2::OutcomeUnknown,
    ] {
        let fx = Fixture::new()?;
        let cap = fresh(fx.begin()?)?;
        let mut value = overrun(true)?;
        value.state = state;
        let settled = fx.child_store.settle_normal_chat_attempt_v2(
            &historical(&fx)?,
            "intent:first",
            &cap.preflight().receipt_digest,
            &value,
            now,
        )?;
        assert_eq!(settled.report, value);
        assert_eq!(closed_at(&fx)?, Some(now()));
        assert!(!settled.violations.is_empty());
        if state == NormalChatReportedStateV2::OutcomeUnknown {
            assert_eq!(
                settled.outcome.reported.state,
                ReportedEffectStateV1::OutcomeAmbiguous
            );
        }
    }
    Ok(())
}

#[test]
fn nonviolating_report_does_not_close_session_admission() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    fx.child_store.settle_normal_chat_attempt_v2(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        &report()?,
        now,
    )?;
    assert_eq!(closed_at(&fx)?, None);
    family.reserve_normal_chat_attempt(
        &fx.authority,
        &next_request(&fx, "intent:allowed"),
        now(),
    )?;
    Ok(())
}

#[test]
fn malformed_wrong_binding_and_conflicting_reports_do_not_close_admission() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    let mut malformed = overrun(true)?;
    malformed.response = None;
    assert!(fx
        .child_store
        .settle_normal_chat_attempt_v2(
            &family,
            "intent:first",
            &cap.preflight().receipt_digest,
            &malformed,
            now
        )
        .is_err());
    assert!(fx
        .child_store
        .settle_normal_chat_attempt_v2(
            &family,
            "intent:first",
            &ContentDigest::compute(b"wrong"),
            &overrun(true)?,
            now
        )
        .is_err());
    fx.child_store.settle_normal_chat_attempt_v2(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        &report()?,
        now,
    )?;
    assert!(fx
        .child_store
        .settle_normal_chat_attempt_v2(
            &family,
            "intent:first",
            &cap.preflight().receipt_digest,
            &overrun(true)?,
            now
        )
        .is_err());
    assert_eq!(closed_at(&fx)?, None);
    family.reserve_normal_chat_attempt(
        &fx.authority,
        &next_request(&fx, "intent:allowed"),
        now(),
    )?;
    Ok(())
}
