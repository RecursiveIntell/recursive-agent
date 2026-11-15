use super::*;
use recursive_agent_contracts::{jcs_canonical, ReceiptOutcomeV1};
use recursive_agent_policy::{
    FamilyAuthorityStore, NormalChatBeginInterruptionV2, PermitRevocationReasonV1 as Reason,
    PermitTransitionStage as Stage,
};
use recursive_agent_runner::NormalChatUnconsumedRuntimeRecoveryInterruptionV1 as Recover;
fn unconsumed(
    fx: &Fixture,
    service: &RuntimeService,
    session: &recursive_agent_runner::RuntimeNormalChatSessionV1,
) -> TestResult {
    let req = request(fx, session, "intent:one")?;
    assert!(service
        .begin_normal_chat_attempt_with_interruption(
            session,
            &req,
            Some(Stop::Policy(NormalChatBeginInterruptionV2::Control(
                Stage::TempFsync
            )))
        )
        .is_err());
    Ok(())
}
fn child_path(
    fx: &Fixture,
    session: &recursive_agent_runner::RuntimeNormalChatSessionV1,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let (family, _) = FamilyAuthorityStore::require_existing_normal_chat_history_context_v1(
        &File::open(session.run_dir())?,
        session.session(),
    )?;
    let res = family
        .read_normal_chat_reservation("intent:one")?
        .ok_or("reservation absent")?;
    Ok(fx
        .root
        .path()
        .join(content_digest(&res.attempt.run_id()?)?.to_string()))
}
#[test]
fn remaining_unconsumed_missing_replaced_and_legacy_storage_never_becomes_no_send() -> TestResult {
    for mode in 0..8 {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        unconsumed(&fx, &service, &session)?;
        let child = child_path(&fx, &session)?;
        match mode {
            0 => fs::rename(&child, child.with_extension("retained"))?,
            1..=3 => {
                let path = child.join(match mode {
                    1 => "permits",
                    2 => "artifacts",
                    _ => "receipts.ndjson",
                });
                fs::rename(&path, path.with_extension("retained"))?;
                if mode < 3 {
                    fs::create_dir(&path)?;
                } else {
                    fs::write(&path, b"")?;
                }
            }
            4 => {
                let path = session.run_dir().join("family-authority.json");
                let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
                value["normal_chat_session"]["reservations"]["intent:one"]["bootstrap"] = json!({"phase":"child_root_started","schema":"recursive-agent.normal-chat-child-bootstrap/v1","at":start()});
                fs::write(path, jcs_canonical(&value)?)?;
            }
            5 => fs::remove_file(child.join("receipts.ndjson"))?,
            6 => {
                let path = child.join("artifacts");
                fs::remove_dir(&path)?;
                std::os::unix::fs::symlink("missing", path)?;
            }
            _ => {
                let path = child.join("chain.meta");
                fs::remove_file(path)?;
            }
        }
        let recovery = runtime(fx.root.path(), fx.clock.clone())?
            .with_interrupted_normal_chat_recovery()
            .with_expired_normal_chat_recovery()
            .with_normal_chat_parent_recovery(true);
        let before = tree(fx.root.path()).ok();
        assert!(
            recovery
                .recover_normal_chat_session_from_sources(session.run_id())
                .is_err(),
            "mode {mode}"
        );
        if let Some(before) = before {
            assert_eq!(tree(fx.root.path())?, before, "mode {mode}");
        }
    }
    Ok(())
}
#[test]
fn remaining_unconsumed_recovery_crash_boundaries_cold_retry_exact() -> TestResult {
    let mut stops = vec![
        Recover::AfterNative,
        Recover::ParentArtifact,
        Recover::BeforeReturn,
    ];
    for stage in [
        Stage::TempWrite,
        Stage::TempFsync,
        Stage::Rename,
        Stage::DirectoryFsync,
    ] {
        stops.push(Recover::Native(stage));
    }
    for ordinal in 0..3 {
        for stage in [
            recursive_agent_ledger::AppendStage::PartialRecord,
            recursive_agent_ledger::AppendStage::FullReceiptAppend,
            recursive_agent_ledger::AppendStage::LogFsync,
            recursive_agent_ledger::AppendStage::MetadataRename,
        ] {
            stops.push(Recover::ChildReceipt { ordinal, stage });
        }
    }
    for stage in [
        recursive_agent_ledger::AppendStage::PartialRecord,
        recursive_agent_ledger::AppendStage::FullReceiptAppend,
        recursive_agent_ledger::AppendStage::LogFsync,
        recursive_agent_ledger::AppendStage::MetadataRename,
    ] {
        stops.push(Recover::ParentReceipt(stage));
    }
    for stop in stops {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        unconsumed(&fx, &service, &session)?;
        let recovery =
            runtime(fx.root.path(), fx.clock.clone())?.with_interrupted_normal_chat_recovery();
        assert!(
            recovery
                .recover_unconsumed_normal_chat_attempt_with_observer(
                    session.run_id(),
                    "intent:one",
                    Some(stop),
                    || {}
                )
                .is_err(),
            "{stop:?}"
        );
        recovery.recover_unconsumed_normal_chat_attempt(session.run_id(), "intent:one")?;
        let before = tree(fx.root.path())?;
        runtime(fx.root.path(), fx.clock.clone())?
            .with_interrupted_normal_chat_recovery()
            .recover_unconsumed_normal_chat_attempt(session.run_id(), "intent:one")?;
        assert_eq!(tree(fx.root.path())?, before, "{stop:?}");
    }
    Ok(())
}
#[test]
fn remaining_known_parent_preserves_original_cancel_denial_and_failure_precedence() -> TestResult {
    for mode in 0..3 {
        for reason in [
            Reason::Operator,
            Reason::OperationCancelled,
            Reason::ParentRevoked,
            Reason::PolicySuperseded,
        ] {
            let fx = Fixture::new()?;
            let service = fx.service()?;
            let session = service.open_normal_chat_session("conversation:fixture")?;
            let req = request(&fx, &session, "intent:one")?;
            let stop = match mode {
                0 => Stop::Policy(NormalChatBeginInterruptionV2::Control(Stage::TempWrite)),
                1 => Stop::Policy(NormalChatBeginInterruptionV2::Control(Stage::Rename)),
                _ => Stop::AfterPolicyConsume,
            };
            assert!(service
                .begin_normal_chat_attempt_with_interruption(&session, &req, Some(stop))
                .is_err());
            let recovery = runtime(fx.root.path(), fx.clock.clone())?
                .with_interrupted_normal_chat_recovery()
                .with_normal_chat_parent_recovery(true);
            match mode {
                0 => {
                    recovery
                        .recover_unconsumed_normal_chat_attempt(session.run_id(), "intent:one")?;
                }
                1 => {
                    recovery
                        .recover_prepared_normal_chat_attempt(session.run_id(), "intent:one")?;
                }
                _ => {
                    recovery
                        .recover_interrupted_normal_chat_attempt(session.run_id(), "intent:one")?;
                }
            }
            let policy = DurablePermitStore::require_existing_from_run_root_fd(&File::open(
                session.run_dir(),
            )?)?;
            let root = policy
                .read_normal_chat_session_control_record()?
                .ok_or("root absent")?;
            let original = policy.revoke(&root.permit.permit_id, reason.clone(), start())?;
            let closed = recovery.recover_normal_chat_session_parent(session.run_id())?;
            assert_eq!(closed.unknown_attempt_count(), 0);
            assert_eq!(
                policy.read_normal_chat_session_control_record()?.as_ref(),
                Some(&original)
            );
            let rows: Vec<recursive_agent_contracts::ReceiptV1> =
                fs::read_to_string(session.run_dir().join("receipts.ndjson"))?
                    .lines()
                    .map(serde_json::from_str)
                    .collect::<Result<_, _>>()?;
            let expected = match reason {
                Reason::OperationCancelled | Reason::ParentRevoked => ReceiptOutcomeV1::Cancelled {
                    reason: "normal_chat_session_cancelled".into(),
                },
                Reason::PolicySuperseded => ReceiptOutcomeV1::Denied,
                _ => ReceiptOutcomeV1::Failed {
                    reason: "normal_chat_interrupted:CHILD_ADMISSION_NOT_RELEASED".into(),
                },
            };
            assert_eq!(rows.last().ok_or("terminal absent")?.outcome, expected);
        }
    }
    Ok(())
}
#[test]
fn remaining_opt_in_and_cold_terminal_composition_do_not_require_a_clock_or_grant() -> TestResult {
    struct NoClock(std::sync::atomic::AtomicUsize);
    impl Clock for NoClock {
        fn now(&self) -> DateTime<Utc> {
            self.0.fetch_add(1, Ordering::SeqCst);
            start() - TimeDelta::hours(1)
        }
    }
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    unconsumed(&fx, &service, &session)?;
    let before = tree(fx.root.path())?;
    assert!(service
        .recover_normal_chat_session_from_sources(session.run_id())
        .is_err());
    assert_eq!(tree(fx.root.path())?, before);
    let recovery = runtime(fx.root.path(), fx.clock.clone())?
        .with_interrupted_normal_chat_recovery()
        .with_normal_chat_parent_recovery(true);
    let closed = recovery.recover_normal_chat_session_from_sources(session.run_id())?;
    fs::remove_file(fx._grant_root.path().join("grant.json"))?;
    let clock = Arc::new(NoClock(std::sync::atomic::AtomicUsize::new(0)));
    let cold = runtime(fx.root.path(), clock.clone())?
        .with_interrupted_normal_chat_recovery()
        .with_normal_chat_parent_recovery(true);
    let before = tree(fx.root.path())?;
    assert_eq!(
        closed.chain_head(),
        cold.recover_normal_chat_session_from_sources(session.run_id())?
            .chain_head()
    );
    assert_eq!(clock.0.load(Ordering::SeqCst), 0);
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}

#[test]
fn remaining_orphan_request_after_unknown_sibling_cannot_erase_unknown() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:prior")?;
    let cap = match service.begin_normal_chat_attempt(&session, &req)? {
        RuntimeNormalChatBeginV2::Fresh(cap) => cap,
        _ => return Err("not fresh".into()),
    };
    service.settle_normal_chat_attempt(
        &session,
        &req,
        cap.preflight_digest(),
        &super::super::terminal::report(
            recursive_agent_policy::NormalChatReportedStateV2::OutcomeUnknown,
        )?,
    )?;
    let next = request(&fx, &session, "intent:next")?;
    // Not a normative runtime prefix: admission is already closed by UNKNOWN.
    // An orphan request cannot convert that source to a known-no-send cause.
    let store = recursive_agent_ledger::ArtifactStore::from_run_root_fd(
        &File::open(session.run_dir())?,
        false,
    )?;
    store.put(&jcs_canonical(&next)?, "application/json", None)?;
    let before = tree(fx.root.path())?;
    let recovery =
        runtime(fx.root.path(), fx.clock.clone())?.with_interrupted_normal_chat_recovery();
    assert!(recovery
        .recover_prechild_normal_chat_admission(session.run_id(), "intent:next")
        .is_err());
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}

#[test]
fn remaining_storage_ready_retains_original_root_started_time() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    unconsumed(&fx, &service, &session)?;
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(session.run_dir().join("family-authority.json"))?)?;
    assert_eq!(
        value["normal_chat_session"]["reservations"]["intent:one"]["bootstrap"]["started_at"],
        serde_json::to_value(start())?
    );
    Ok(())
}
