use super::settlement::{historical, report};
#[path = "normal_chat_recovery_confirmation_v1.rs"]
mod confirmation;
use super::*;
use recursive_agent_policy::{
    parse_normal_chat_recovery_record_v1_bytes, NormalChatProviderSendStateV1,
    NormalChatRecoveryInterruptionV1 as Stop,
};

#[test]
fn expired_missing_outcome_is_distinct_from_an_executor_report() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    let charged = family.reserved_budget()?;
    let expiry = cap.effect_permit().binding.expires_at;
    assert!(fx
        .child_store
        .recover_expired_normal_chat_attempt_v1(
            &family,
            "intent:first",
            &cap.preflight().receipt_digest,
            || expiry - TimeDelta::milliseconds(1)
        )
        .is_err());
    assert!(family
        .read_normal_chat_session_snapshot_v2()?
        .admission
        .closed_at
        .is_none());
    let value = fx.child_store.recover_expired_normal_chat_attempt_v1(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        || expiry,
    )?;
    assert_eq!(value.observed_at, expiry);
    assert_eq!(
        value.provider_send_state,
        NormalChatProviderSendStateV1::MayHaveBeenSent
    );
    let proof = cap.ledger_evidence()?;
    value.validate_for_admission_v1(&proof)?;
    let wire = recursive_agent_contracts::jcs_canonical(&value)?;
    assert_eq!(
        parse_normal_chat_recovery_record_v1_bytes(&wire, &proof)?,
        value
    );
    let json: serde_json::Value = serde_json::from_slice(&wire)?;
    for key in [
        "report",
        "duration_ms",
        "response",
        "usage",
        "outcome_receipt",
    ] {
        assert!(json.get(key).is_none());
    }
    let view = fx
        .child_store
        .read_normal_chat_attempt_v2(&family, "intent:first")?;
    assert_eq!(view.state, NormalChatAttemptPolicyStateV2::RecoveredUnknown);
    assert!(view.outcome.is_none() && view.settlement.is_none());
    assert_eq!(family.reserved_budget()?, charged);
    assert_eq!(
        fx.child_store
            .read_normal_chat_recovery_v1(&family, "intent:first")?,
        Some(value)
    );
    assert!(matches!(fx.begin()?, NormalChatAttemptBeginV2::Existing(_)));
    Ok(())
}
#[test]
fn sdk_report_and_recovery_cannot_overwrite_each_other() -> TestResult {
    for report_first in [false, true] {
        let fx = Fixture::new()?;
        let cap = fresh(fx.begin()?)?;
        let family = historical(&fx)?;
        let expiry = cap.effect_permit().binding.expires_at;
        if report_first {
            fx.child_store.settle_normal_chat_attempt_v2(
                &family,
                "intent:first",
                &cap.preflight().receipt_digest,
                &report()?,
                || expiry,
            )?;
            let bytes = fs::read(fx._parent_root.path().join("family-authority.json"))?;
            assert!(fx
                .child_store
                .recover_expired_normal_chat_attempt_v1(
                    &family,
                    "intent:first",
                    &cap.preflight().receipt_digest,
                    || expiry
                )
                .is_err());
            assert_eq!(
                bytes,
                fs::read(fx._parent_root.path().join("family-authority.json"))?
            );
            assert!(fx
                .child_store
                .read_normal_chat_recovery_v1(&family, "intent:first")?
                .is_none());
        } else {
            let value = fx.child_store.recover_expired_normal_chat_attempt_v1(
                &family,
                "intent:first",
                &cap.preflight().receipt_digest,
                || expiry,
            )?;
            assert!(fx
                .child_store
                .settle_normal_chat_attempt_v2(
                    &family,
                    "intent:first",
                    &cap.preflight().receipt_digest,
                    &report()?,
                    || expiry + TimeDelta::seconds(1)
                )
                .is_err());
            assert!(fx
                .child_store
                .confirm_normal_chat_settlement_v2(
                    &family,
                    "intent:first",
                    &cap.preflight().receipt_digest,
                    &report()?
                )
                .is_err());
            assert_eq!(
                fx.child_store
                    .read_normal_chat_recovery_v1(&family, "intent:first")?,
                Some(value)
            );
        }
    }
    Ok(())
}
#[test]
fn exact_recovery_retry_is_clock_free_and_missing_fence_is_not_repaired() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    let expiry = cap.effect_permit().binding.expires_at;
    let first = fx.child_store.recover_expired_normal_chat_attempt_v1(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        || expiry,
    )?;
    let path = fx._parent_root.path().join("family-authority.json");
    let bytes = fs::read(&path)?;
    let calls = std::cell::Cell::new(0);
    let again = fx.child_store.recover_expired_normal_chat_attempt_v1(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        || {
            calls.set(calls.get() + 1);
            now() - TimeDelta::seconds(1)
        },
    )?;
    assert_eq!(calls.get(), 0);
    assert_eq!(first, again);
    assert_eq!(bytes, fs::read(&path)?);
    let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
    value["normal_chat_session"]["closed_at"] = serde_json::Value::Null;
    fs::write(&path, serde_json::to_vec(&value)?)?;
    let corrupted = fs::read(&path)?;
    assert!(fx
        .child_store
        .recover_expired_normal_chat_attempt_v1(
            &family,
            "intent:first",
            &cap.preflight().receipt_digest,
            || expiry + TimeDelta::seconds(5)
        )
        .is_err());
    assert_eq!(corrupted, fs::read(path)?);
    Ok(())
}
#[test]
fn native_recovery_faults_preserve_uncertain_commit_and_first_family_fence() -> TestResult {
    for child in [false, true] {
        for stage in [
            PermitTransitionStage::TempWrite,
            PermitTransitionStage::TempFsync,
            PermitTransitionStage::Rename,
            PermitTransitionStage::DirectoryFsync,
        ] {
            let fx = Fixture::new()?;
            let cap = fresh(fx.begin()?)?;
            let family = historical(&fx)?;
            let expiry = cap.effect_permit().binding.expires_at;
            let charged = family.reserved_budget()?;
            let point = if child {
                Stop::ChildRecovery(stage)
            } else {
                Stop::FamilyClose(stage)
            };
            assert!(
                fx.child_store
                    .recover_expired_normal_chat_attempt_v1_with_interruption(
                        &family,
                        "intent:first",
                        &cap.preflight().receipt_digest,
                        || expiry,
                        Some(point)
                    )
                    .is_err(),
                "{point:?}"
            );
            let old = fx
                .child_store
                .read_normal_chat_recovery_v1(&family, "intent:first")?;
            let closed = family
                .read_normal_chat_session_snapshot_v2()?
                .admission
                .closed_at;
            let renamed = matches!(
                stage,
                PermitTransitionStage::Rename | PermitTransitionStage::DirectoryFsync
            );
            assert_eq!(closed.is_some(), child || renamed);
            assert_eq!(old.is_some(), child && renamed);
            let result = fx.child_store.recover_expired_normal_chat_attempt_v1(
                &family,
                "intent:first",
                &cap.preflight().receipt_digest,
                || expiry + TimeDelta::milliseconds(20),
            )?;
            if let Some(old) = old {
                assert_eq!(result, old);
            }
            if closed.is_some() {
                assert_eq!(
                    family
                        .read_normal_chat_session_snapshot_v2()?
                        .admission
                        .closed_at,
                    closed
                );
            }
            assert_eq!(family.reserved_budget()?, charged);
        }
    }
    Ok(())
}
#[test]
fn recovery_ingress_is_closed_and_rehash_does_not_replace_binding() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    let expiry = cap.effect_permit().binding.expires_at;
    let proof = cap.ledger_evidence()?;
    let record = fx.child_store.recover_expired_normal_chat_attempt_v1(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        || expiry,
    )?;
    let valid = serde_json::to_value(&record)?;
    for key in [
        "report",
        "duration_ms",
        "usage",
        "response",
        "force",
        "expires_at",
        "error_message",
    ] {
        let mut bad = valid.clone();
        bad[key] = serde_json::Value::Null;
        assert!(
            parse_normal_chat_recovery_record_v1_bytes(
                &recursive_agent_contracts::jcs_canonical(&bad)?,
                &proof
            )
            .is_err(),
            "{key}"
        );
    }
    let bytes = recursive_agent_contracts::jcs_canonical(&record)?;
    let mut whitespace = bytes.clone();
    whitespace.push(b' ');
    assert!(parse_normal_chat_recovery_record_v1_bytes(&whitespace, &proof).is_err());
    assert!(parse_normal_chat_recovery_record_v1_bytes(&vec![b' '; 20_000], &proof).is_err());
    let duplicate = String::from_utf8(bytes.clone())?
        .replace("\"observed_at\":", "\"observed_at\":null,\"observed_at\":");
    assert!(parse_normal_chat_recovery_record_v1_bytes(duplicate.as_bytes(), &proof).is_err());
    for which in ["preflight", "permit", "time"] {
        let mut bad = record.clone();
        match which {
            "preflight" => bad.preflight_receipt_digest = ContentDigest::compute(b"wrong"),
            "permit" => bad.permit_id = cap.control_permit().permit_id.clone(),
            _ => bad.observed_at = expiry - TimeDelta::milliseconds(1),
        }
        bad.recovery_digest = bad.computed_digest()?;
        assert!(
            parse_normal_chat_recovery_record_v1_bytes(
                &recursive_agent_contracts::jcs_canonical(&bad)?,
                &proof
            )
            .is_err(),
            "{which}"
        );
    }
    Ok(())
}
#[test]
fn missing_unconsumed_or_wrong_preflight_never_publishes_recovery() -> TestResult {
    for prepared in [false, true] {
        let fx = Fixture::new()?;
        if prepared {
            assert!(fx
                .child_store
                .begin_normal_chat_attempt_v2_with_interruption(
                    &fx.authority,
                    &fx.family,
                    "intent:first",
                    now,
                    Some(NormalChatBeginInterruptionV2::Control(
                        PermitTransitionStage::DirectoryFsync
                    ))
                )
                .is_err());
        }
        let family = historical(&fx)?;
        let before = fs::read(fx._parent_root.path().join("family-authority.json"))?;
        assert!(fx
            .child_store
            .recover_expired_normal_chat_attempt_v1(
                &family,
                "intent:first",
                &ContentDigest::compute(b"wrong"),
                || now() + TimeDelta::hours(1)
            )
            .is_err());
        assert_eq!(
            before,
            fs::read(fx._parent_root.path().join("family-authority.json"))?
        );
    }
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    assert!(fx
        .child_store
        .recover_expired_normal_chat_attempt_v1(
            &family,
            "intent:first",
            &ContentDigest::compute(b"wrong"),
            || cap.effect_permit().binding.expires_at
        )
        .is_err());
    assert!(fx
        .child_store
        .read_normal_chat_recovery_v1(&family, "intent:first")?
        .is_none());
    Ok(())
}

#[test]
fn independent_report_and_recovery_writers_have_one_terminal_slot_winner() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let expiry = cap.effect_permit().binding.expires_at;
    let a =
        DurablePermitStore::require_existing_from_run_root_fd(&File::open(fx.child_root.path())?)?;
    let b =
        DurablePermitStore::require_existing_from_run_root_fd(&File::open(fx.child_root.path())?)?;
    let fa = historical(&fx)?;
    let fb = historical(&fx)?;
    let digest = cap.preflight().receipt_digest.clone();
    let input = report()?;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let (sdk, recovered) = std::thread::scope(|scope| -> Result<_, Box<dyn std::error::Error>> {
        let ba = barrier.clone();
        let bd = &digest;
        let one = scope.spawn(move || {
            ba.wait();
            a.settle_normal_chat_attempt_v2(&fa, "intent:first", bd, &input, || expiry)
                .is_ok()
        });
        let bb = barrier.clone();
        let bd = &digest;
        let two = scope.spawn(move || {
            bb.wait();
            b.recover_expired_normal_chat_attempt_v1(&fb, "intent:first", bd, || expiry)
                .is_ok()
        });
        Ok((
            one.join().map_err(|_| "SDK writer panicked")?,
            two.join().map_err(|_| "recovery writer panicked")?,
        ))
    })?;
    assert_ne!(sdk, recovered);
    let family = historical(&fx)?;
    let view = fx
        .child_store
        .read_normal_chat_attempt_v2(&family, "intent:first")?;
    assert_eq!(
        family
            .read_normal_chat_session_snapshot_v2()?
            .admission
            .closed_at
            .is_some(),
        recovered
    );
    assert_eq!(
        view.state,
        if recovered {
            NormalChatAttemptPolicyStateV2::RecoveredUnknown
        } else {
            NormalChatAttemptPolicyStateV2::Settled
        }
    );
    assert_eq!(view.outcome.is_some(), sdk);
    assert_eq!(view.settlement.is_some(), sdk);
    assert_eq!(
        fx.child_store
            .read_normal_chat_recovery_v1(&family, "intent:first")?
            .is_some(),
        recovered
    );
    Ok(())
}
#[test]
fn recovery_state_cannot_release_cached_native_consumption_even_with_rewound_fixture() -> TestResult
{
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    let expiry = cap.effect_permit().binding.expires_at;
    fx.child_store.recover_expired_normal_chat_attempt_v1(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        || expiry,
    )?;
    // Deliberately corrupt/reopen ONLY a disposable fixture and rewind its
    // clock. The recovered native role must independently deny continuation.
    let path = fx._parent_root.path().join("family-authority.json");
    let mut state: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    state["normal_chat_session"]["closed_at"] = serde_json::Value::Null;
    fs::write(path, serde_json::to_vec(&state)?)?;
    let expected = family.read_normal_chat_session_snapshot_v2()?;
    assert!(cap
        .check_runtime_release_v2(&fx.authority, &fx.family, now(), &expected, now)
        .is_err());
    Ok(())
}
#[test]
fn old_role_and_state_readers_reject_new_recovery_without_changing_old_wire() -> TestResult {
    #[allow(dead_code)]
    #[derive(serde::Deserialize)]
    #[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
    enum OldRole {
        Control {
            admission: serde_json::Value,
        },
        Effect {
            #[serde(default)]
            settlement: Option<serde_json::Value>,
        },
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum OldState {
        Unbegun,
        Prepared,
        Consumed,
        Settled,
    }
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let proof = cap.ledger_evidence()?;
    let control = fx.child_store.state(&cap.control_permit().permit_id)?;
    let effect = fx.child_store.state(&cap.effect_permit().permit_id)?;
    let cw = recursive_agent_contracts::jcs_canonical(&control.normal_chat_attempt_v2)?;
    let ew = recursive_agent_contracts::jcs_canonical(&effect.normal_chat_attempt_v2)?;
    assert_eq!(
        cw,
        recursive_agent_contracts::jcs_canonical(
            &json!({"role":"control","admission":proof.admission})
        )?
    );
    assert_eq!(
        ew,
        recursive_agent_contracts::jcs_canonical(&json!({"role":"effect"}))?
    );
    serde_json::from_slice::<OldRole>(&cw)?;
    serde_json::from_slice::<OldRole>(&ew)?;
    let family = historical(&fx)?;
    fx.child_store.recover_expired_normal_chat_attempt_v1(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        || cap.effect_permit().binding.expires_at,
    )?;
    let record = fx.child_store.state(&cap.effect_permit().permit_id)?;
    let wire = recursive_agent_contracts::jcs_canonical(&record.normal_chat_attempt_v2)?;
    assert!(serde_json::from_slice::<OldRole>(&wire).is_err());
    let view = fx
        .child_store
        .read_normal_chat_attempt_v2(&family, "intent:first")?;
    assert!(serde_json::from_value::<OldState>(serde_json::to_value(view.state)?).is_err());
    let mut extra = serde_json::to_value(record.normal_chat_attempt_v2)?;
    extra["settlement"] = json!(null);
    assert!(
        serde_json::from_value::<recursive_agent_policy::NormalChatAttemptRecordV2>(extra).is_err()
    );
    Ok(())
}
#[test]
fn new_recovery_role_rejects_even_a_well_formed_sdk_outcome_sidecar() -> TestResult {
    let reported = Fixture::new()?;
    let reported_cap = fresh(reported.begin()?)?;
    let outcome = reported
        .child_store
        .settle_normal_chat_attempt_v2(
            &historical(&reported)?,
            "intent:first",
            &reported_cap.preflight().receipt_digest,
            &report()?,
            now,
        )?
        .outcome;
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    fx.child_store.recover_expired_normal_chat_attempt_v1(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        || cap.effect_permit().binding.expires_at,
    )?;
    let mut record = fx.child_store.state(&cap.effect_permit().permit_id)?;
    record.outcome_receipt = Some(outcome);
    let path = effect_path(fx.child_root.path(), &record.permit.permit_id)?;
    fs::write(path, recursive_agent_contracts::jcs_canonical(&record)?)?;
    assert!(fx
        .child_store
        .read_normal_chat_recovery_v1(&family, "intent:first")
        .is_err());
    Ok(())
}
#[test]
fn recovery_cannot_recreate_records_deleted_at_either_clock_sample() -> TestResult {
    for selected in [1, 2] {
        let fx = Fixture::new()?;
        let cap = fresh(fx.begin()?)?;
        let family = historical(&fx)?;
        let target = effect_path(fx.child_root.path(), &cap.effect_permit().permit_id)?;
        let count = std::cell::Cell::new(0);
        let failed = std::cell::Cell::new(false);
        let result = fx.child_store.recover_expired_normal_chat_attempt_v1(
            &family,
            "intent:first",
            &cap.preflight().receipt_digest,
            || {
                count.set(count.get() + 1);
                if count.get() == selected {
                    failed.set(fs::remove_file(&target).is_err());
                }
                cap.effect_permit().binding.expires_at
            },
        );
        assert!(!failed.get());
        assert!(count.get() >= selected);
        assert!(result.is_err());
        assert!(!target.exists());
        assert_eq!(
            family
                .read_normal_chat_session_snapshot_v2()?
                .admission
                .closed_at
                .is_some(),
            selected == 2
        );
    }
    Ok(())
}

fn effect_path(
    root: &Path,
    id: &recursive_agent_contracts::CurrentPermitId,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let wanted = serde_json::to_value(id)?;
    for path in permit_paths(root)? {
        let value: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
        if value["permit"]["permit_id"] == wanted {
            return Ok(path);
        }
    }
    Err("effect file absent".into())
}

#[test]
fn recovered_ack_requires_both_sync_barriers_without_new_clock() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    let expiry = cap.effect_permit().binding.expires_at;
    let first = fx.child_store.recover_expired_normal_chat_attempt_v1(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        || expiry,
    )?;
    for stop in [
        Stop::FamilyClose(PermitTransitionStage::DirectoryFsync),
        Stop::ChildRecovery(PermitTransitionStage::DirectoryFsync),
    ] {
        let count = std::cell::Cell::new(0);
        assert!(fx
            .child_store
            .recover_expired_normal_chat_attempt_v1_with_interruption(
                &family,
                "intent:first",
                &cap.preflight().receipt_digest,
                || {
                    count.set(count.get() + 1);
                    now()
                },
                Some(stop)
            )
            .is_err());
        assert_eq!(count.get(), 0);
        assert_eq!(
            fx.child_store
                .read_normal_chat_recovery_v1(&family, "intent:first")?,
            Some(first.clone())
        );
    }
    Ok(())
}
#[test]
fn recovery_clock_regression_before_family_fence_publishes_no_disposition() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    let expiry = cap.effect_permit().binding.expires_at;
    let before = fs::read(fx._parent_root.path().join("family-authority.json"))?;
    let count = std::cell::Cell::new(0);
    assert!(fx
        .child_store
        .recover_expired_normal_chat_attempt_v1(
            &family,
            "intent:first",
            &cap.preflight().receipt_digest,
            || {
                count.set(count.get() + 1);
                if count.get() == 1 {
                    expiry
                } else {
                    expiry - TimeDelta::milliseconds(1)
                }
            }
        )
        .is_err());
    assert_eq!(count.get(), 2);
    assert_eq!(
        before,
        fs::read(fx._parent_root.path().join("family-authority.json"))?
    );
    assert!(fx
        .child_store
        .read_normal_chat_recovery_v1(&family, "intent:first")?
        .is_none());
    Ok(())
}

#[test]
fn new_recovery_time_cannot_precede_retained_local_control_revocation() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    let expiry = cap.effect_permit().binding.expires_at;
    let closed_at = expiry + TimeDelta::seconds(1);
    let old = fx.child_store.revoke(
        &cap.control_permit().permit_id,
        PermitRevocationReasonV1::Operator,
        closed_at,
    )?;
    assert!(fx
        .child_store
        .recover_expired_normal_chat_attempt_v1(
            &family,
            "intent:first",
            &cap.preflight().receipt_digest,
            || expiry
        )
        .is_err());
    assert!(family
        .read_normal_chat_session_snapshot_v2()?
        .admission
        .closed_at
        .is_none());
    let value = fx.child_store.recover_expired_normal_chat_attempt_v1(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        || closed_at,
    )?;
    assert_eq!(value.observed_at, closed_at);
    assert_eq!(fx.child_store.state(&cap.control_permit().permit_id)?, old);
    Ok(())
}
#[test]
fn recovery_wire_rejects_wrong_schema_reason_and_send_state() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    let proof = cap.ledger_evidence()?;
    let recovery = fx.child_store.recover_expired_normal_chat_attempt_v1(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        || cap.effect_permit().binding.expires_at,
    )?;
    let valid = serde_json::to_value(recovery)?;
    for (key, value) in [
        ("schema", "recursive-agent.normal-chat-recovery/v0"),
        ("reason", "executor_failed"),
        ("provider_send_state", "not_sent"),
    ] {
        let mut bad = valid.clone();
        bad[key] = json!(value);
        assert!(
            parse_normal_chat_recovery_record_v1_bytes(
                &recursive_agent_contracts::jcs_canonical(&bad)?,
                &proof
            )
            .is_err(),
            "{key}"
        );
    }
    Ok(())
}
