use super::*;
#[path = "normal_chat_runtime_recovery_hostile.rs"]
mod hostile_recovery;
use recursive_agent_contracts::{ReceiptV1, RunTerminalStateV1};
use recursive_agent_ledger::{
    verified_snapshot_expected_run_from_dir_fd, verify_child_links_in_runtime_root, AppendStage,
    ArtifactStore,
};
use recursive_agent_policy::{
    NormalChatRecoveryInterruptionV1 as NativeStop, PermitRevocationReasonV1,
    PermitTransitionStage as Stage,
};
use recursive_agent_runner::NormalChatRuntimeRecoveryInterruptionV1 as StopRecovery;

fn no_grant(fx: &Fixture) -> Result<RuntimeService, Box<dyn std::error::Error>> {
    Ok(runtime(fx.root.path(), fx.clock.clone())?.with_expired_normal_chat_recovery())
}
fn assert_closed(
    fx: &Fixture,
    session: &recursive_agent_runner::RuntimeNormalChatSessionV1,
    child: &Path,
) -> TestResult {
    let root = File::open(child)?;
    let rows: Vec<ReceiptV1> = fs::read_to_string(child.join("receipts.ndjson"))?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    let snapshot = verified_snapshot_expected_run_from_dir_fd(&root, &rows[0].run_id)?;
    assert_eq!(snapshot.receipts().len(), 10);
    assert_eq!(
        snapshot.verification().terminal_state,
        RunTerminalStateV1::Failed
    );
    assert_eq!(
        snapshot.receipts()[7].kind,
        ReceiptKindV1::NormalChatAttemptRecoveredV1
    );
    assert!(snapshot
        .receipts()
        .iter()
        .all(|r| r.kind != ReceiptKindV1::NormalChatAttemptSettledV2));
    let parent = appendable_snapshot_expected_run_from_dir_fd(
        &File::open(session.run_dir())?,
        session.run_id(),
    )?;
    assert_eq!(
        parent.receipts().last().ok_or("parent absent")?.kind,
        ReceiptKindV1::ChildClosed
    );
    verify_child_links_in_runtime_root(
        &parent,
        &ArtifactStore::from_run_root_fd(&File::open(session.run_dir())?, false)?,
        fx.root.path(),
        true,
    )?;
    assert!(!parent.verification().current_strict_success);
    Ok(())
}
fn complete_prefix(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };
    let mut prefix = Vec::new();
    for part in bytes.split_inclusive(|b| *b == b'\n') {
        if serde_json::from_slice::<ReceiptV1>(part).is_ok() {
            prefix.extend_from_slice(part);
        } else {
            break;
        }
    }
    Ok(prefix)
}

#[test]
fn default_read_scope_or_current_grant_does_not_enable_recovery_mutation() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    admitted(&fx, &service, &session)?;
    fx.clock.0.store(2000, Ordering::SeqCst);
    let before = tree(fx.root.path())?;
    assert!(matches!(
        service.recover_expired_normal_chat_attempt(session.run_id(), "intent:one"),
        Err(RuntimeServiceError::NormalChatRecoveryDisabled)
    ));
    let (reader, calls) = reader(&fx)?;
    assert!(matches!(
        reader.recover_expired_normal_chat_attempt(session.run_id(), "intent:one"),
        Err(RuntimeServiceError::NormalChatRecoveryDisabled)
    ));
    reader.inspect_pending_normal_chat_attempt_for_recovery(session.run_id(), "intent:one")?;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}
#[test]
fn cold_runtime_recovery_closes_child_and_parent_link_without_grant_or_sdk_report() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (request, preflight, child, family) = admitted(&fx, &service, &session)?;
    let root_policy =
        DurablePermitStore::require_existing_from_run_root_fd(&File::open(session.run_dir())?)?;
    let original_root = root_policy.read_normal_chat_session_control_record()?;
    let original_family = family.read_normal_chat_session_snapshot_v2()?;
    fs::remove_file(fx._grant_root.path().join("grant.json"))?;
    fx.clock.0.store(700_000, Ordering::SeqCst);
    let result =
        no_grant(&fx)?.recover_expired_normal_chat_attempt(session.run_id(), "intent:one")?;
    assert_eq!(result.recovery().preflight_receipt_digest, preflight);
    assert_eq!(result.terminal_state(), RunTerminalStateV1::Failed);
    assert_eq!(
        root_policy.read_normal_chat_session_control_record()?,
        original_root
    );
    assert_eq!(
        family.read_normal_chat_session_snapshot_v2()?.reservations,
        original_family.reservations
    );
    assert!(family
        .read_normal_chat_session_snapshot_v2()?
        .admission
        .closed_at
        .is_some());
    assert_closed(&fx, &session, &child)?;
    let policy = DurablePermitStore::require_existing_from_run_root_fd(&File::open(&child)?)?;
    let view = policy.read_normal_chat_attempt_v2(&family, "intent:one")?;
    assert!(view.outcome.is_none() && view.settlement.is_none());
    assert!(matches!(
        service.begin_normal_chat_attempt(&session, &request)?,
        RuntimeNormalChatBeginV2::Existing(_)
    ));
    assert!(service
        .begin_normal_chat_attempt(
            &session,
            &super::super::request(&fx, &session, "intent:later")?
        )
        .is_err());
    assert!(service
        .resume_normal_chat_session("conversation:fixture")
        .is_err());
    assert!(service.close_normal_chat_session(&session).is_err());
    Ok(())
}

#[test]
fn capacity_rejection_retains_native_narrowing_without_publishing_terminal_payloads() -> TestResult
{
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (_, _, child, family) = admitted(&fx, &service, &session)?;
    fx.clock.0.store(2000, Ordering::SeqCst);
    let before = tree(&child.join("artifacts"))?;
    let slots = family.read_normal_chat_session_snapshot_v2()?.reservations;
    assert!(no_grant(&fx)?
        .recover_expired_normal_chat_attempt_with_interruption(
            session.run_id(),
            "intent:one",
            Some(StopRecovery::MetadataCapacity)
        )
        .is_err());
    assert_eq!(tree(&child.join("artifacts"))?, before);
    assert_eq!(
        family.read_normal_chat_session_snapshot_v2()?.reservations,
        slots
    );
    assert!(family
        .read_normal_chat_session_snapshot_v2()?
        .admission
        .closed_at
        .is_some());
    let native = DurablePermitStore::require_existing_from_run_root_fd(&File::open(&child)?)?;
    let record = native
        .read_normal_chat_recovery_v1(&family, "intent:one")?
        .ok_or("narrowing absent")?;
    let result =
        no_grant(&fx)?.recover_expired_normal_chat_attempt(session.run_id(), "intent:one")?;
    assert_eq!(result.recovery(), &record);
    assert_closed(&fx, &session, &child)?;
    Ok(())
}
#[test]
fn recovery_before_actual_effect_expiry_is_narrowing_denial_with_no_mutation() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    admitted(&fx, &service, &session)?;
    let before = tree(fx.root.path())?;
    assert!(no_grant(&fx)?
        .recover_expired_normal_chat_attempt(session.run_id(), "intent:one")
        .is_err());
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}

#[test]
fn exact_closed_recovery_retry_uses_no_clock_and_preserves_all_bytes() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    admitted(&fx, &service, &session)?;
    fx.clock.0.store(2000, Ordering::SeqCst);
    let first =
        no_grant(&fx)?.recover_expired_normal_chat_attempt(session.run_id(), "intent:one")?;
    let before = tree(fx.root.path())?;
    let (reader, calls) = reader(&fx)?;
    let reader = reader.with_expired_normal_chat_recovery();
    let repeated = reader.recover_expired_normal_chat_attempt(session.run_id(), "intent:one")?;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(first.recovery(), repeated.recovery());
    assert_eq!(first.child_chain_head(), repeated.child_chain_head());
    assert_eq!(first.parent_chain_head(), repeated.parent_chain_head());
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}

#[test]
fn existing_native_recovery_and_any_prior_child_revocation_keep_their_original_times() -> TestResult
{
    for reason in [
        PermitRevocationReasonV1::Operator,
        PermitRevocationReasonV1::ParentRevoked,
        PermitRevocationReasonV1::OperationCancelled,
        PermitRevocationReasonV1::PolicySuperseded,
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let (_, preflight, child, family) = admitted(&fx, &service, &session)?;
        let policy = DurablePermitStore::require_existing_from_run_root_fd(&File::open(&child)?)?;
        let view = policy.read_normal_chat_attempt_v2(&family, "intent:one")?;
        let control = view.local_control.ok_or("control absent")?;
        let closed = policy.revoke(&control.permit_id, reason, start() + TimeDelta::seconds(1))?;
        let recovery = policy.recover_expired_normal_chat_attempt_v1(
            &family,
            "intent:one",
            &preflight,
            || start() + TimeDelta::seconds(2),
        )?;
        let (reader, calls) = reader(&fx)?;
        let reader = reader.with_expired_normal_chat_recovery();
        let result = reader.recover_expired_normal_chat_attempt(session.run_id(), "intent:one")?;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(result.recovery(), &recovery);
        assert_eq!(policy.state(&control.permit_id)?, closed);
        assert_closed(&fx, &session, &child)?;
    }
    Ok(())
}

#[test]
fn sdk_report_and_incomplete_preflight_cannot_be_promoted_to_runtime_recovery() -> TestResult {
    for mode in [
        "sdk-native",
        "sdk-runtime",
        "partial",
        "no-ledger",
        "prepared",
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let req = super::super::request(&fx, &session, "intent:one")?;
        if mode == "sdk-native" || mode == "sdk-runtime" {
            let (_, preflight, child, family) = admitted(&fx, &service, &session)?;
            let report = super::super::terminal::report(
                recursive_agent_policy::NormalChatReportedStateV2::NotSent,
            )?;
            if mode == "sdk-native" {
                DurablePermitStore::require_existing_from_run_root_fd(&File::open(child)?)?
                    .settle_normal_chat_attempt_v2(
                        &family,
                        "intent:one",
                        &preflight,
                        &report,
                        || start() + TimeDelta::seconds(2),
                    )?;
            } else {
                service.settle_normal_chat_attempt(&session, &req, &preflight, &report)?;
            }
        } else {
            let point = match mode {
                "partial" => super::Stop::ChildReceipt {
                    ordinal: 6,
                    stage: AppendStage::PartialRecord,
                },
                "prepared" => super::Stop::AfterLink,
                _ => super::Stop::AfterPolicyConsume,
            };
            assert!(service
                .begin_normal_chat_attempt_with_interruption(&session, &req, Some(point))
                .is_err());
        }
        fx.clock.0.store(2000, Ordering::SeqCst);
        let family_before = fs::read(session.run_dir().join("family-authority.json"))?;
        assert!(
            no_grant(&fx)?
                .recover_expired_normal_chat_attempt(session.run_id(), "intent:one")
                .is_err(),
            "{mode}"
        );
        assert_eq!(
            fs::read(session.run_dir().join("family-authority.json"))?,
            family_before
        );
    }
    Ok(())
}

#[test]
fn every_recovery_write_and_receipt_fault_retains_charge_and_retries_exact_prefix_only(
) -> TestResult {
    let mut points = vec![
        StopRecovery::AfterNative,
        StopRecovery::AfterControlClose,
        StopRecovery::Artifact { ordinal: 0 },
        StopRecovery::Artifact { ordinal: 1 },
        StopRecovery::ParentArtifact,
        StopRecovery::BeforeReturn,
    ];
    for stage in [
        Stage::TempWrite,
        Stage::TempFsync,
        Stage::Rename,
        Stage::DirectoryFsync,
    ] {
        points.push(StopRecovery::Native(NativeStop::FamilyClose(stage)));
        points.push(StopRecovery::Native(NativeStop::ChildRecovery(stage)));
        points.push(StopRecovery::ControlClose(stage));
    }
    for stage in [
        AppendStage::PartialRecord,
        AppendStage::FullReceiptAppend,
        AppendStage::LogFsync,
        AppendStage::MetadataTempWrite,
        AppendStage::MetadataFsync,
        AppendStage::MetadataRename,
        AppendStage::DirectoryFsync,
    ] {
        for ordinal in 0..3 {
            points.push(StopRecovery::ChildReceipt { ordinal, stage });
        }
        points.push(StopRecovery::ParentReceipt(stage));
    }
    for point in points {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let (_, _, child, family) = admitted(&fx, &service, &session)?;
        fx.clock.0.store(2000, Ordering::SeqCst);
        let slots = family.read_normal_chat_session_snapshot_v2()?.reservations;
        assert!(
            no_grant(&fx)?
                .recover_expired_normal_chat_attempt_with_interruption(
                    session.run_id(),
                    "intent:one",
                    Some(point)
                )
                .is_err(),
            "{point:?}"
        );
        let parent_prefix = complete_prefix(&session.run_dir().join("receipts.ndjson"))?;
        let child_prefix = complete_prefix(&child.join("receipts.ndjson"))?;
        let policy = DurablePermitStore::require_existing_from_run_root_fd(&File::open(&child)?)?;
        let old = policy.read_normal_chat_recovery_v1(&family, "intent:one")?;
        let result =
            no_grant(&fx)?.recover_expired_normal_chat_attempt(session.run_id(), "intent:one")?;
        if let Some(old) = old {
            assert_eq!(result.recovery(), &old, "{point:?}");
        }
        assert_eq!(
            family.read_normal_chat_session_snapshot_v2()?.reservations,
            slots,
            "{point:?}"
        );
        assert!(
            fs::read(session.run_dir().join("receipts.ndjson"))?.starts_with(&parent_prefix),
            "{point:?}"
        );
        assert!(
            fs::read(child.join("receipts.ndjson"))?.starts_with(&child_prefix),
            "{point:?}"
        );
        assert_closed(&fx, &session, &child)?;
    }
    Ok(())
}

#[test]
fn lost_newline_of_complete_terminal_rows_preserves_original_heads_and_valid_times() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (_, _, child, _) = admitted(&fx, &service, &session)?;
    fx.clock.0.store(2000, Ordering::SeqCst);
    let first =
        no_grant(&fx)?.recover_expired_normal_chat_attempt(session.run_id(), "intent:one")?;
    for base in [session.run_dir(), child.as_path()] {
        let p = base.join("receipts.ndjson");
        let mut bytes = fs::read(&p)?;
        assert_eq!(bytes.pop(), Some(b'\n'));
        fs::write(p, bytes)?;
    }
    let (reader, calls) = reader(&fx)?;
    let reader = reader.with_expired_normal_chat_recovery();
    let repeated = reader.recover_expired_normal_chat_attempt(session.run_id(), "intent:one")?;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(first.child_chain_head(), repeated.child_chain_head());
    assert_eq!(first.parent_chain_head(), repeated.parent_chain_head());
    assert_closed(&fx, &session, &child)?;
    Ok(())
}

#[test]
fn unknown_or_partial_terminal_artifacts_are_not_deleted_or_accepted() -> TestResult {
    for partial in [false, true] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let (_, _, child, family) = admitted(&fx, &service, &session)?;
        fx.clock.0.store(2000, Ordering::SeqCst);
        let store = ArtifactStore::from_run_root_fd(&File::open(&child)?, false)?;
        if partial {
            assert!(no_grant(&fx)?
                .recover_expired_normal_chat_attempt_with_interruption(
                    session.run_id(),
                    "intent:one",
                    Some(StopRecovery::AfterControlClose)
                )
                .is_err());
            let record =
                DurablePermitStore::require_existing_from_run_root_fd(&File::open(&child)?)?
                    .read_normal_chat_recovery_v1(&family, "intent:one")?
                    .ok_or("recovery absent")?;
            let d = store.put(
                &recursive_agent_contracts::jcs_canonical(&record)?,
                "application/json",
                None,
            )?;
            fs::remove_file(
                child
                    .join("artifacts")
                    .join(format!("{}.meta", d.digest.hex())),
            )?;
        } else {
            store.put(b"unknown complete artifact", "text/plain", None)?;
        }
        let before = tree(fx.root.path())?;
        assert!(no_grant(&fx)?
            .recover_expired_normal_chat_attempt(session.run_id(), "intent:one")
            .is_err());
        assert_eq!(tree(fx.root.path())?, before);
    }
    Ok(())
}
