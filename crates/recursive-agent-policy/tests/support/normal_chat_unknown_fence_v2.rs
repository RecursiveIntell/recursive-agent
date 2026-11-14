use super::*;

fn unknown_report() -> Result<NormalChatExecutorReportV2, Box<dyn std::error::Error>> {
    Ok(parse_normal_chat_executor_report_v2_bytes(
        &serde_json::to_vec(&json!({
            "schema":"recursive-agent.normal-chat-executor-report/v2","state":"outcome_unknown",
            "duration_ms":0,"response":null,"usage":null,
        }))?,
    )?)
}
fn sibling(fx: &Fixture) -> NormalChatFamilyReservationRequestV2 {
    NormalChatFamilyReservationRequestV2 {
        operation: fx.reservation.attempt.operation.clone(),
        provider_request_digest: ContentDigest::compute(b"sibling"),
        provider_request_bytes: 7,
        dispatch_intent_ref: "intent:sibling".into(),
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
fn close_time(
    family: &FamilyAuthorityStore,
) -> Result<Option<DateTime<Utc>>, Box<dyn std::error::Error>> {
    Ok(family
        .read_normal_chat_session_snapshot_v2()?
        .admission
        .closed_at)
}
#[test]
fn explicit_unknown_without_overrun_closes_native_admission_and_retains_charge() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    let charged = family.reserved_budget()?;
    let result = fx.child_store.settle_normal_chat_attempt_v2(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        &unknown_report()?,
        now,
    )?;
    assert!(result.violations.is_empty());
    assert_eq!(
        result.outcome.reported.state,
        ReportedEffectStateV1::OutcomeAmbiguous
    );
    assert_eq!(
        close_time(&family)?,
        Some(now()),
        "unknown report left admission open"
    );
    assert_eq!(family.reserved_budget()?, charged);
    assert!(family
        .reserve_normal_chat_attempt(&fx.authority, &sibling(&fx), now())
        .is_err());
    assert!(matches!(fx.begin()?, NormalChatAttemptBeginV2::Existing(_)));
    let degradation = result
        .degradation_record_v1(&cap.ledger_evidence()?)?
        .ok_or("degradation absent")?;
    assert_eq!(
        degradation.provider_send_state,
        recursive_agent_policy::NormalChatProviderSendStateV1::MayHaveBeenSent
    );
    Ok(())
}
#[test]
fn reserved_unbegun_sibling_never_consumes_after_unknown_report() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let next = fx
        .family
        .reserve_normal_chat_attempt(&fx.authority, &sibling(&fx), now)?;
    let root = tempfile::tempdir()?;
    let child = store(root.path())?;
    fx.child_store.settle_normal_chat_attempt_v2(
        &historical(&fx)?,
        "intent:first",
        &cap.preflight().receipt_digest,
        &unknown_report()?,
        now,
    )?;
    assert!(
        child
            .begin_normal_chat_attempt_v2(&fx.authority, &fx.family, "intent:sibling", now)
            .is_err(),
        "unknown report allowed sibling consumption"
    );
    assert!(fx
        .family
        .guard_child_dispatch(
            &fx.authority,
            &next.attempt.run_id()?,
            &next.child_control.child_control_permit_id,
            now
        )
        .is_err());
    assert!(permit_paths(root.path())?.is_empty());
    Ok(())
}
#[test]
fn unknown_fence_and_child_write_faults_preserve_uncertain_commits_and_charges() -> TestResult {
    for child_fault in [false, true] {
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
            let stop = if child_fault {
                NormalChatSettlementInterruptionV2::ChildOutcome(stage)
            } else {
                NormalChatSettlementInterruptionV2::FamilyClose(stage)
            };
            assert!(
                fx.child_store
                    .settle_normal_chat_attempt_v2_with_interruption(
                        &family,
                        "intent:first",
                        &cap.preflight().receipt_digest,
                        &unknown_report()?,
                        now,
                        Some(stop)
                    )
                    .is_err(),
                "{stop:?}"
            );
            let at = close_time(&family)?;
            let renamed = matches!(
                stage,
                PermitTransitionStage::Rename | PermitTransitionStage::DirectoryFsync
            );
            assert_eq!(at.is_some(), child_fault || renamed, "{stop:?}");
            let view = fx
                .child_store
                .read_normal_chat_attempt_v2(&family, "intent:first")?;
            assert_eq!(
                view.settlement.is_some(),
                child_fault && renamed,
                "{stop:?}"
            );
            let settled = fx.child_store.settle_normal_chat_attempt_v2(
                &family,
                "intent:first",
                &cap.preflight().receipt_digest,
                &unknown_report()?,
                || now() + TimeDelta::milliseconds(20),
            )?;
            if let Some(old) = view.settlement {
                assert_eq!(settled, old);
            }
            if at.is_some() {
                assert_eq!(close_time(&family)?, at);
            }
            assert!(close_time(&family)?.is_some());
            assert_eq!(family.reserved_budget()?, charged);
        }
    }
    Ok(())
}
#[test]
fn unknown_historical_confirmation_requires_existing_fence_and_never_repairs_it() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    let first = fx.child_store.settle_normal_chat_attempt_v2(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        &unknown_report()?,
        now,
    )?;
    let path = fx._parent_root.path().join("family-authority.json");
    let bytes = fs::read(&path)?;
    assert_eq!(
        fx.child_store.confirm_normal_chat_settlement_v2(
            &family,
            "intent:first",
            &cap.preflight().receipt_digest,
            &unknown_report()?
        )?,
        first
    );
    assert_eq!(bytes, fs::read(&path)?);
    // Explicit corrupt/unpublished-generation fixture, not a production reopen.
    let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
    value["normal_chat_session"]["closed_at"] = serde_json::Value::Null;
    fs::write(&path, serde_json::to_vec(&value)?)?;
    let broken = fs::read(&path)?;
    assert!(
        fx.child_store
            .confirm_normal_chat_settlement_v2(
                &family,
                "intent:first",
                &cap.preflight().receipt_digest,
                &unknown_report()?
            )
            .is_err(),
        "confirmation accepted unknown without durable fence"
    );
    assert_eq!(broken, fs::read(path)?);
    Ok(())
}
#[test]
fn consumed_sibling_can_report_without_reopening_unknown_admission() -> TestResult {
    let fx = Fixture::new()?;
    let first = fresh(fx.begin()?)?;
    fx.family
        .reserve_normal_chat_attempt(&fx.authority, &sibling(&fx), now)?;
    let root = tempfile::tempdir()?;
    let child = store(root.path())?;
    let cap = fresh(child.begin_normal_chat_attempt_v2(
        &fx.authority,
        &fx.family,
        "intent:sibling",
        now,
    )?)?;
    let family = historical(&fx)?;
    let charged = family.reserved_budget()?;
    fx.child_store.settle_normal_chat_attempt_v2(
        &family,
        "intent:first",
        &first.preflight().receipt_digest,
        &unknown_report()?,
        now,
    )?;
    let closed = close_time(&family)?;
    assert!(closed.is_some());
    let result = child.settle_normal_chat_attempt_v2(
        &family,
        "intent:sibling",
        &cap.preflight().receipt_digest,
        &report()?,
        || now() + TimeDelta::hours(2),
    )?;
    assert_eq!(result.report.state, NormalChatReportedStateV2::Succeeded);
    assert_eq!(close_time(&family)?, closed);
    assert_eq!(family.reserved_budget()?, charged);
    Ok(())
}
#[test]
fn unknown_fence_preserves_existing_close_revocation_and_rejects_clock_regression() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    let path = fx._parent_root.path().join("family-authority.json");
    let before = fs::read(&path)?;
    let count = std::cell::Cell::new(0);
    assert!(fx
        .child_store
        .settle_normal_chat_attempt_v2(
            &family,
            "intent:first",
            &cap.preflight().receipt_digest,
            &unknown_report()?,
            || {
                count.set(count.get() + 1);
                now() + TimeDelta::milliseconds(if count.get() == 1 { 20 } else { 19 })
            }
        )
        .is_err());
    assert_eq!(before, fs::read(&path)?);
    assert!(fx
        .child_store
        .read_normal_chat_attempt_v2(&family, "intent:first")?
        .settlement
        .is_none());
    family.close_normal_chat_session(now() + TimeDelta::milliseconds(30))?;
    family.revoke_parent(now() + TimeDelta::milliseconds(40))?;
    let old = fs::read(&path)?;
    fx.child_store.settle_normal_chat_attempt_v2(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        &unknown_report()?,
        || now() + TimeDelta::hours(2),
    )?;
    assert_eq!(old, fs::read(path)?);
    Ok(())
}

#[test]
fn fence_predicate_preserves_ordinary_reports_and_all_overrun_cases() -> TestResult {
    for state in [
        NormalChatReportedStateV2::Succeeded,
        NormalChatReportedStateV2::Failed,
        NormalChatReportedStateV2::Cancelled,
        NormalChatReportedStateV2::Interrupted,
        NormalChatReportedStateV2::TimedOut,
        NormalChatReportedStateV2::NotSent,
        NormalChatReportedStateV2::OutcomeUnknown,
    ] {
        for overrun in [false, true] {
            if state == NormalChatReportedStateV2::NotSent && overrun {
                continue;
            }
            let fx = Fixture::new()?;
            let cap = fresh(fx.begin()?)?;
            let family = historical(&fx)?;
            let mut value = report()?;
            value.state = state;
            if state == NormalChatReportedStateV2::NotSent
                || state == NormalChatReportedStateV2::OutcomeUnknown
            {
                value.duration_ms = 0;
                value.response = None;
                value.usage = None;
            }
            if overrun {
                value.duration_ms = 1001;
            }
            let done = fx.child_store.settle_normal_chat_attempt_v2(
                &family,
                "intent:first",
                &cap.preflight().receipt_digest,
                &value,
                now,
            )?;
            assert_eq!(done.report, value);
            assert_eq!(
                close_time(&family)?.is_some(),
                state == NormalChatReportedStateV2::OutcomeUnknown || overrun,
                "{state:?} overrun={overrun}"
            );
        }
    }
    Ok(())
}
