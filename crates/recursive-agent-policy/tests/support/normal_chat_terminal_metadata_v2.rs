use super::*;
use recursive_agent_contracts::{jcs_canonical, ReceiptOutcomeV1};
use recursive_agent_policy::{
    parse_normal_chat_settlement_metadata_v2_bytes, PermitEvidenceStateV1, PermitPreflightReceiptV1,
};

#[test]
fn terminal_metadata_is_canonical_closed_and_binds_exact_consumed_admission() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let proof = cap.ledger_evidence()?;
    let settled = fx.child_store.settle_normal_chat_attempt_v2(
        &historical(&fx)?,
        "intent:first",
        &cap.preflight().receipt_digest,
        &report()?,
        || now() + TimeDelta::hours(2),
    )?;
    let bytes = jcs_canonical(&settled)?;
    assert_eq!(
        parse_normal_chat_settlement_metadata_v2_bytes(&bytes, &proof)?,
        settled
    );
    assert_eq!(settled.ledger_outcome_v2(&proof)?, ReceiptOutcomeV1::Ok);
    assert!(settled.degradation_record_v1(&proof)?.is_none());
    let mut different = proof.clone();
    let later = proof.preflight.recorded_at + TimeDelta::milliseconds(1);
    let mut evidence = proof.preflight.evidence.clone();
    evidence.state = PermitEvidenceStateV1::Consumed { at: later };
    // Synthetic HISTORICAL evidence for a negative binding test, never a native
    // issuer/continuation. Keep its own digest valid to isolate the mismatch.
    let permit_id = evidence.permit_id.clone();
    different.preflight = PermitPreflightReceiptV1 {
        receipt_digest: content_digest(&(&permit_id, &evidence, later))?,
        permit_id,
        evidence,
        recorded_at: later,
    };
    different.validate()?;
    assert!(parse_normal_chat_settlement_metadata_v2_bytes(&bytes, &different).is_err());
    let mut unknown = serde_json::to_value(&settled)?;
    unknown["raw_response"] = json!("forbidden");
    assert!(
        parse_normal_chat_settlement_metadata_v2_bytes(&jcs_canonical(&unknown)?, &proof).is_err()
    );
    let duplicate = String::from_utf8(bytes.clone())?.replacen(
        "\"violations\":[]",
        "\"violations\":[],\"violations\":[]",
        1,
    );
    assert!(parse_normal_chat_settlement_metadata_v2_bytes(duplicate.as_bytes(), &proof).is_err());
    let padded = serde_json::to_vec_pretty(&settled)?;
    assert!(parse_normal_chat_settlement_metadata_v2_bytes(&padded, &proof).is_err());
    assert!(parse_normal_chat_settlement_metadata_v2_bytes(&vec![b' '; 40_000], &proof).is_err());
    Ok(())
}

#[test]
fn self_consistent_checksums_do_not_replace_consumed_identity_or_time_binding() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let proof = cap.ledger_evidence()?;
    let original = fx.child_store.settle_normal_chat_attempt_v2(
        &historical(&fx)?,
        "intent:first",
        &proof.preflight.receipt_digest,
        &report()?,
        now,
    )?;
    for mode in ["permit", "preflight", "time", "violation"] {
        let mut changed = original.clone();
        match mode {
            "permit" => {
                changed.outcome.permit_id = proof.admission.context.root_control.permit_id.clone()
            }
            "preflight" => {
                changed.outcome.preflight_receipt_digest =
                    ContentDigest::compute(b"other-preflight")
            }
            "time" => {
                changed.outcome.recorded_at =
                    proof.preflight.recorded_at - TimeDelta::milliseconds(1)
            }
            _ => changed
                .violations
                .push(recursive_agent_policy::NormalChatBoundViolationV2::WallTime),
        }
        changed.outcome.receipt_digest = content_digest(&(
            &changed.outcome.permit_id,
            &changed.outcome.preflight_receipt_digest,
            &changed.outcome.reported,
            changed.outcome.recorded_at,
        ))?;
        changed.settlement_digest = content_digest(&(
            changed.schema,
            &changed.attempt_id,
            &changed.report,
            &changed.violations,
            &changed.outcome,
        ))?;
        changed.outcome.validate()?;
        assert!(
            parse_normal_chat_settlement_metadata_v2_bytes(&jcs_canonical(&changed)?, &proof)
                .is_err(),
            "{mode}"
        );
    }
    Ok(())
}

#[test]
fn terminal_outcome_and_degradation_are_policy_owned_reported_projections() -> TestResult {
    for state in [
        NormalChatReportedStateV2::Succeeded,
        NormalChatReportedStateV2::Failed,
        NormalChatReportedStateV2::Cancelled,
        NormalChatReportedStateV2::Interrupted,
        NormalChatReportedStateV2::TimedOut,
        NormalChatReportedStateV2::NotSent,
        NormalChatReportedStateV2::OutcomeUnknown,
    ] {
        let fx = Fixture::new()?;
        let cap = fresh(fx.begin()?)?;
        let proof = cap.ledger_evidence()?;
        let mut value = report()?;
        value.state = state;
        if state == NormalChatReportedStateV2::NotSent {
            value.duration_ms = 0;
            value.response = None;
            value.usage = None;
        }
        let settled = fx.child_store.settle_normal_chat_attempt_v2(
            &historical(&fx)?,
            "intent:first",
            &cap.preflight().receipt_digest,
            &value,
            now,
        )?;
        let outcome = settled.ledger_outcome_v2(&proof)?;
        assert_eq!(
            outcome == ReceiptOutcomeV1::Ok,
            state == NormalChatReportedStateV2::Succeeded
        );
        let degraded = settled.degradation_record_v1(&proof)?;
        assert_eq!(
            degraded.is_some(),
            state == NormalChatReportedStateV2::OutcomeUnknown
        );
        if let Some(degraded) = degraded {
            assert_eq!(
                serde_json::to_value(degraded)?,
                json!({
                    "schema":"recursive-agent.normal-chat-degradation/v1",
                    "attempt_id":proof.admission.reservation.attempt.attempt_id,
                    "permit_id":proof.preflight.permit_id,
                    "reason_code":"OUTCOME_UNKNOWN","provider_send_state":"may_have_been_sent",
                    "preflight_receipt_digest":proof.preflight.receipt_digest,
                    "recorded_at":settled.outcome.recorded_at,
                })
            );
            assert_eq!(
                outcome,
                ReceiptOutcomeV1::Failed {
                    reason: "normal_chat_degraded:OUTCOME_UNKNOWN".into()
                }
            );
        }
    }
    Ok(())
}
