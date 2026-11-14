use super::*;
#[path = "normal_chat_overrun_fence_v2.rs"]
mod overrun_fence;
#[path = "normal_chat_terminal_metadata_v2.rs"]
mod terminal_metadata;
#[path = "normal_chat_unknown_fence_v2.rs"]
mod unknown_fence;
use recursive_agent_policy::{
    parse_normal_chat_executor_report_v2_bytes, NormalChatBoundViolationV2,
    NormalChatExecutorReportV2, NormalChatReportedStateV2, NormalChatSettlementInterruptionV2,
};

pub(super) fn report() -> Result<NormalChatExecutorReportV2, Box<dyn std::error::Error>> {
    Ok(parse_normal_chat_executor_report_v2_bytes(
        &serde_json::to_vec(&json!({
            "schema": "recursive-agent.normal-chat-executor-report/v2",
            "state": "succeeded", "duration_ms": 40,
            "response": {"projection_schema": "ares-response-json-sorted-v1", "digest": HOME,
                         "byte_length": 42, "complete": true},
            "usage": {"source": "provider_reported", "input_tokens": 12, "output_tokens": 4}
        }))?,
    )?)
}
pub(super) fn historical(fx: &Fixture) -> Result<FamilyAuthorityStore, Box<dyn std::error::Error>> {
    Ok(FamilyAuthorityStore::from_dir_fd(
        &File::open(fx._parent_root.path())?,
        fx.control.family_grant(),
    )?)
}

#[test]
fn strict_report_rejects_raw_content_unknown_duplicate_and_incoherent_states() -> TestResult {
    let valid = serde_json::to_value(report()?)?;
    for field in ["prompt", "response_content", "error_message", "extra"] {
        let mut bad = valid.clone();
        bad[field] = json!("do not retain me");
        assert!(parse_normal_chat_executor_report_v2_bytes(&serde_json::to_vec(&bad)?).is_err());
    }
    let mut bad = valid.clone();
    bad["response"]["complete"] = json!(false);
    assert!(parse_normal_chat_executor_report_v2_bytes(&serde_json::to_vec(&bad)?).is_err());
    bad = valid.clone();
    bad["response"]["digest"] = json!("sha256:ABC");
    assert!(parse_normal_chat_executor_report_v2_bytes(&serde_json::to_vec(&bad)?).is_err());
    bad = valid.clone();
    bad["state"] = json!("not_sent");
    assert!(parse_normal_chat_executor_report_v2_bytes(&serde_json::to_vec(&bad)?).is_err());
    bad = valid.clone();
    bad["usage"]["source"] = json!("verified");
    assert!(parse_normal_chat_executor_report_v2_bytes(&serde_json::to_vec(&bad)?).is_err());
    let duplicate = serde_json::to_string(&valid)?.replacen(
        "\"duration_ms\":40",
        "\"duration_ms\":40,\"duration_ms\":40",
        1,
    );
    assert!(parse_normal_chat_executor_report_v2_bytes(duplicate.as_bytes()).is_err());
    assert!(parse_normal_chat_executor_report_v2_bytes(&vec![b' '; 20_000]).is_err());
    Ok(())
}

#[test]
fn settlement_is_atomic_exact_idempotent_and_status_only_after_reopen() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    let settled = fx.child_store.settle_normal_chat_attempt_v2(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        &report()?,
        now,
    )?;
    assert_eq!(settled.report, report()?);
    assert_eq!(
        settled.outcome.reported.state,
        ReportedEffectStateV1::Succeeded
    );
    assert!(settled.violations.is_empty());
    let reopened = store(fx.child_root.path())?;
    let retry = reopened.settle_normal_chat_attempt_v2(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        &report()?,
        || now() + TimeDelta::seconds(300),
    )?;
    assert_eq!(retry, settled);
    let view = reopened.read_normal_chat_attempt_v2(&family, "intent:first")?;
    assert_eq!(view.state, NormalChatAttemptPolicyStateV2::Settled);
    assert_eq!(view.settlement, Some(settled.clone()));
    assert_eq!(view.outcome, Some(settled.outcome.clone()));
    assert!(matches!(fx.begin()?, NormalChatAttemptBeginV2::Existing(_)));
    let mut conflicting = report()?;
    conflicting.duration_ms += 1;
    assert!(reopened
        .settle_normal_chat_attempt_v2(
            &family,
            "intent:first",
            &cap.preflight().receipt_digest,
            &conflicting,
            now
        )
        .is_err());
    let bytes = serde_json::to_vec(&view)?;
    let wire = String::from_utf8(bytes)?;
    assert!(!wire.contains("physical-body"));
    assert!(!wire.contains("response_content"));
    Ok(())
}

#[test]
fn settlement_needs_canonical_consumed_attempt_and_exact_preflight() -> TestResult {
    let fx = Fixture::new()?;
    let family = historical(&fx)?;
    let wrong = ContentDigest::compute(b"wrong");
    assert!(fx
        .child_store
        .settle_normal_chat_attempt_v2(&family, "intent:first", &wrong, &report()?, now)
        .is_err());
    let cap = fresh(fx.begin()?)?;
    for intent in ["intent:first", "intent:unreserved"] {
        assert!(fx
            .child_store
            .settle_normal_chat_attempt_v2(&family, intent, &wrong, &report()?, now)
            .is_err());
    }
    let other = tempfile::tempdir()?;
    assert!(store(other.path())?
        .settle_normal_chat_attempt_v2(
            &family,
            "intent:first",
            &cap.preflight().receipt_digest,
            &report()?,
            now
        )
        .is_err());
    assert!(fx
        .child_store
        .settle_normal_chat_attempt_v2(
            &family,
            "intent:first",
            &cap.preflight().receipt_digest,
            &report()?,
            || now() - TimeDelta::milliseconds(1)
        )
        .is_err());
    assert_eq!(
        fx.child_store
            .read_normal_chat_attempt_v2(&family, "intent:first")?
            .state,
        NormalChatAttemptPolicyStateV2::Consumed
    );
    Ok(())
}

#[test]
fn outcome_reporting_survives_expiry_and_revocation_without_refund_or_retry() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    fx.parent_store.revoke(
        &fx.control.permit().permit_id,
        PermitRevocationReasonV1::Operator,
        now(),
    )?;
    let settled = fx.child_store.settle_normal_chat_attempt_v2(
        &historical(&fx)?,
        "intent:first",
        &cap.preflight().receipt_digest,
        &report()?,
        || now() + TimeDelta::hours(2),
    )?;
    assert_eq!(settled.report.state, NormalChatReportedStateV2::Succeeded);
    assert_eq!(
        fx.family.read_normal_chat_reservation("intent:first")?,
        Some(fx.reservation.clone())
    );
    assert!(matches!(fx.begin()?, NormalChatAttemptBeginV2::Existing(_)));
    Ok(())
}

#[test]
fn simultaneous_conflicting_settlements_have_one_immutable_winner() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    let first_store = store(fx.child_root.path())?;
    let second_store = store(fx.child_root.path())?;
    let first_family = family.clone();
    let second_family = family.clone();
    let first_digest = cap.preflight().receipt_digest.clone();
    let second_digest = first_digest.clone();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let first_barrier = barrier.clone();
    let first_report = report()?;
    let mut second_report = report()?;
    second_report.duration_ms += 1;
    let first = std::thread::spawn(move || {
        first_barrier.wait();
        first_store.settle_normal_chat_attempt_v2(
            &first_family,
            "intent:first",
            &first_digest,
            &first_report,
            now,
        )
    });
    let second = std::thread::spawn(move || {
        barrier.wait();
        second_store.settle_normal_chat_attempt_v2(
            &second_family,
            "intent:first",
            &second_digest,
            &second_report,
            now,
        )
    });
    let first = first.join().map_err(|_| "settler thread panicked")?;
    let second = second.join().map_err(|_| "settler thread panicked")?;
    assert_ne!(first.is_ok(), second.is_ok());
    let winner = match (first, second) {
        (Ok(value), Err(_)) | (Err(_), Ok(value)) => value,
        _ => return Err("settlements did not produce one winner".into()),
    };
    assert_eq!(
        fx.child_store
            .read_normal_chat_attempt_v2(&family, "intent:first")?
            .settlement,
        Some(winner)
    );
    Ok(())
}

#[test]
fn settled_snapshot_rejects_detached_locator() -> TestResult {
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
    let swap = std::cell::RefCell::new(Ok::<(), std::io::Error>(()));
    let result =
        fx.child_store
            .read_normal_chat_attempt_v2_with_observer(&family, "intent:first", || {
                *swap.borrow_mut() = (|| {
                    fs::rename(
                        fx.child_root.path().join("permits"),
                        fx.child_root.path().join("detached"),
                    )?;
                    fs::create_dir(fx.child_root.path().join("permits"))
                })();
            });
    swap.into_inner()?;
    assert!(result.is_err());
    assert!(fx
        .child_store
        .settle_normal_chat_attempt_v2(
            &family,
            "intent:first",
            &cap.preflight().receipt_digest,
            &report()?,
            now
        )
        .is_err());
    Ok(())
}

#[test]
fn overruns_are_retained_as_reported_evidence_and_cannot_be_success_receipts() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let mut over = report()?;
    over.duration_ms = 1001;
    if let Some(usage) = &mut over.usage {
        usage.output_tokens = 11;
    }
    let settled = fx.child_store.settle_normal_chat_attempt_v2(
        &historical(&fx)?,
        "intent:first",
        &cap.preflight().receipt_digest,
        &over,
        now,
    )?;
    assert_eq!(settled.report, over);
    assert_eq!(
        settled.violations,
        vec![
            NormalChatBoundViolationV2::WallTime,
            NormalChatBoundViolationV2::OutputTokens
        ]
    );
    assert_eq!(
        settled.outcome.reported.state,
        ReportedEffectStateV1::Failed
    );
    Ok(())
}

#[test]
fn every_closed_transport_outcome_is_recorded_without_inventing_success() -> TestResult {
    for state in [
        "failed",
        "cancelled",
        "interrupted",
        "timed_out",
        "not_sent",
        "outcome_unknown",
    ] {
        let fx = Fixture::new()?;
        let cap = fresh(fx.begin()?)?;
        let input = json!({"schema":"recursive-agent.normal-chat-executor-report/v2", "state":state,
            "duration_ms":0, "response":null, "usage":null});
        let reported = parse_normal_chat_executor_report_v2_bytes(&serde_json::to_vec(&input)?)?;
        let settled = fx.child_store.settle_normal_chat_attempt_v2(
            &historical(&fx)?,
            "intent:first",
            &cap.preflight().receipt_digest,
            &reported,
            now,
        )?;
        assert_ne!(
            settled.outcome.reported.state,
            ReportedEffectStateV1::Succeeded
        );
        if state == "outcome_unknown" {
            assert_eq!(
                settled.outcome.reported.state,
                ReportedEffectStateV1::OutcomeAmbiguous
            );
        }
    }
    Ok(())
}

#[test]
fn uncertain_settlement_ack_preserves_one_outcome_and_requires_exact_retry() -> TestResult {
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
                &report()?,
                now,
                Some(NormalChatSettlementInterruptionV2::ChildOutcome(stage))
            )
            .is_err());
        let reopened = store(fx.child_root.path())?;
        let view = reopened.read_normal_chat_attempt_v2(&family, "intent:first")?;
        let published = matches!(
            stage,
            PermitTransitionStage::Rename | PermitTransitionStage::DirectoryFsync
        );
        assert_eq!(view.settlement.is_some(), published);
        let before_retry = permit_paths(fx.child_root.path())?
            .into_iter()
            .map(|path| Ok((path.clone(), fs::read(path)?)))
            .collect::<Result<Vec<_>, std::io::Error>>()?;
        let result = reopened.settle_normal_chat_attempt_v2(
            &family,
            "intent:first",
            &cap.preflight().receipt_digest,
            &report()?,
            || now() + TimeDelta::milliseconds(10),
        )?;
        if let Some(existing) = view.settlement {
            assert_eq!(result, existing);
            for (path, bytes) in before_retry {
                assert_eq!(fs::read(path)?, bytes);
            }
        }
        assert_eq!(
            reopened
                .read_normal_chat_attempt_v2(&family, "intent:first")?
                .settlement,
            Some(result)
        );
        let mut conflict = report()?;
        conflict.duration_ms += 1;
        assert!(reopened
            .settle_normal_chat_attempt_v2(
                &family,
                "intent:first",
                &cap.preflight().receipt_digest,
                &conflict,
                now
            )
            .is_err());
    }
    Ok(())
}

#[test]
fn settlement_tampering_cannot_separate_report_from_outcome() -> TestResult {
    for change in ["report", "digest", "outcome", "strip_outcome"] {
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
        for path in permit_paths(fx.child_root.path())? {
            let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
            if value["normal_chat_attempt_v2"]["role"] != "effect" {
                continue;
            }
            match change {
                "report" => {
                    value["normal_chat_attempt_v2"]["settlement"]["report"]["duration_ms"] =
                        json!(999)
                }
                "digest" => {
                    value["normal_chat_attempt_v2"]["settlement"]["settlement_digest"] =
                        json!(ContentDigest::compute(b"wrong"))
                }
                "outcome" => {
                    value["normal_chat_attempt_v2"]["settlement"]["outcome"]["recorded_at"] =
                        json!(now() + TimeDelta::seconds(1))
                }
                _ => value["outcome_receipt"] = serde_json::Value::Null,
            }
            fs::write(path, serde_json::to_vec(&value)?)?;
        }
        assert!(
            fx.child_store
                .read_normal_chat_attempt_v2(&family, "intent:first")
                .is_err(),
            "tamper {change}"
        );
    }
    Ok(())
}
