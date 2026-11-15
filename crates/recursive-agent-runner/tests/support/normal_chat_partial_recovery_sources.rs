use super::*;
use recursive_agent_contracts::{jcs_canonical, NormalChatCallRequestV2};
use recursive_agent_policy::{
    parse_normal_chat_interrupted_recovery_record_v2_bytes, FamilyAuthorityStore,
    NormalChatBeginInterruptionV2, PermitTransitionStage,
};
use std::sync::atomic::AtomicUsize;
struct UnusableClock(AtomicUsize);
fn retain_fixture(label: &str, source: &Path) -> TestResult {
    let Some(base) = std::env::var_os("RA_PARTIAL_ADMISSION_EVIDENCE_DIR") else {
        return Ok(());
    };
    let target = PathBuf::from(base).join(label);
    fs::create_dir_all(target.parent().ok_or("fixture parent absent")?)?;
    fs::create_dir(&target)?; // Never overwrite a previous run's evidence.
    fn copy(source: &Path, target: &Path) -> TestResult {
        fs::set_permissions(target, fs::metadata(source)?.permissions())?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let destination = target.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                fs::create_dir(&destination)?;
                copy(&entry.path(), &destination)?;
            } else {
                fs::copy(entry.path(), destination)?;
            }
        }
        Ok(())
    }
    copy(source, &target)?;
    assert_eq!(tree(source)?, tree(&target)?);
    Ok(())
}

impl Clock for UnusableClock {
    fn now(&self) -> DateTime<Utc> {
        self.0.fetch_add(1, Ordering::SeqCst);
        start() - TimeDelta::hours(1)
    }
}
#[test]
fn partial_source_cold_terminal_retries_do_not_sample_clock_or_require_grant() -> TestResult {
    for mode in 0..3 {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let req = request(&fx, &session, "intent:one")?;
        let stop = match mode {
            0 => Stop::AfterRequestArtifact,
            1 => Stop::Policy(NormalChatBeginInterruptionV2::Control(
                PermitTransitionStage::Rename,
            )),
            _ => Stop::AfterPolicyConsume,
        };
        assert!(service
            .begin_normal_chat_attempt_with_interruption(&session, &req, Some(stop))
            .is_err());
        let recovery =
            runtime(fx.root.path(), fx.clock.clone())?.with_interrupted_normal_chat_recovery();
        match mode {
            0 => {
                recovery.recover_prechild_normal_chat_admission(session.run_id(), "intent:one")?;
            }
            1 => {
                recovery.recover_prepared_normal_chat_attempt(session.run_id(), "intent:one")?;
            }
            _ => {
                recovery.recover_interrupted_normal_chat_attempt(session.run_id(), "intent:one")?;
            }
        }
        fs::remove_file(fx._grant_root.path().join("grant.json"))?;
        let clock = Arc::new(UnusableClock(AtomicUsize::new(0)));
        let cold = runtime(fx.root.path(), clock.clone())?.with_interrupted_normal_chat_recovery();
        let before = tree(fx.root.path())?;
        match mode {
            0 => {
                cold.recover_prechild_normal_chat_admission(session.run_id(), "intent:one")?;
            }
            1 => {
                cold.recover_prepared_normal_chat_attempt(session.run_id(), "intent:one")?;
            }
            _ => {
                cold.recover_interrupted_normal_chat_attempt(session.run_id(), "intent:one")?;
            }
        }
        assert_eq!(clock.0.load(Ordering::SeqCst), 0);
        assert_eq!(tree(fx.root.path())?, before);
        retain_fixture(&format!("terminal-mode-{mode}"), fx.root.path())?;
    }
    Ok(())
}
#[test]
fn partial_source_future_native_root_revocation_refuses_new_observation() -> TestResult {
    for mode in 0..3 {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let req = request(&fx, &session, "intent:one")?;
        let stop = match mode {
            0 => Stop::AfterRequestArtifact,
            1 => Stop::Policy(NormalChatBeginInterruptionV2::Control(
                PermitTransitionStage::Rename,
            )),
            _ => Stop::AfterPolicyConsume,
        };
        assert!(service
            .begin_normal_chat_attempt_with_interruption(&session, &req, Some(stop))
            .is_err());
        let policy =
            DurablePermitStore::require_existing_from_run_root_fd(&File::open(session.run_dir())?)?;
        let root = policy
            .read_normal_chat_session_control_record()?
            .ok_or("root absent")?;
        policy.revoke(
            &root.permit.permit_id,
            recursive_agent_policy::PermitRevocationReasonV1::Operator,
            start() + TimeDelta::seconds(10),
        )?;
        let before = tree(fx.root.path())?;
        let recovery =
            runtime(fx.root.path(), fx.clock.clone())?.with_interrupted_normal_chat_recovery();
        let refused = match mode {
            0 => recovery
                .recover_prechild_normal_chat_admission(session.run_id(), "intent:one")
                .is_err(),
            1 => recovery
                .recover_prepared_normal_chat_attempt(session.run_id(), "intent:one")
                .is_err(),
            _ => recovery
                .recover_interrupted_normal_chat_attempt(session.run_id(), "intent:one")
                .is_err(),
        };
        assert!(refused);
        assert_eq!(tree(fx.root.path())?, before);
    }
    Ok(())
}
#[test]
fn partial_source_closed_recovery_parser_refuses_missing_unknown_and_lossy_members() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:one")?;
    assert!(service
        .begin_normal_chat_attempt_with_interruption(&session, &req, Some(Stop::AfterPolicyConsume))
        .is_err());
    let result = runtime(fx.root.path(), fx.clock.clone())?
        .with_interrupted_normal_chat_recovery()
        .recover_interrupted_normal_chat_attempt(session.run_id(), "intent:one")?;
    let (family, _) = FamilyAuthorityStore::require_existing_normal_chat_history_context_v1(
        &File::open(session.run_dir())?,
        session.session(),
    )?;
    let proof = DurablePermitStore::require_existing_from_run_root_fd(&File::open(
        result.child_run_dir(),
    )?)?
    .read_normal_chat_ledger_admission_v2(&family, "intent:one")?
    .ok_or("proof absent")?;
    let wire = serde_json::to_value(result.recovery())?;
    assert_eq!(
        parse_normal_chat_interrupted_recovery_record_v2_bytes(&jcs_canonical(&wire)?, &proof)?,
        *result.recovery()
    );
    for field in [
        "schema",
        "attempt_id",
        "permit_id",
        "preflight_receipt_digest",
        "reason",
        "prefix_receipts",
        "observed_at",
        "recovery_digest",
    ] {
        let mut missing = wire.clone();
        missing
            .as_object_mut()
            .ok_or("record not object")?
            .remove(field);
        assert!(
            parse_normal_chat_interrupted_recovery_record_v2_bytes(
                &jcs_canonical(&missing)?,
                &proof
            )
            .is_err(),
            "missing {field}"
        );
    }
    let mut unknown = wire.clone();
    unknown["unexpected"] = json!(true);
    assert!(parse_normal_chat_interrupted_recovery_record_v2_bytes(
        &jcs_canonical(&unknown)?,
        &proof
    )
    .is_err());
    let mut lossy = wire.clone();
    lossy["reason"] = json!({"admission_response_not_released":null});
    assert!(parse_normal_chat_interrupted_recovery_record_v2_bytes(
        &jcs_canonical(&lossy)?,
        &proof
    )
    .is_err());
    let mut unknown_version = wire;
    unknown_version["schema"] = json!("recursive-agent.normal-chat-interrupted-recovery/v999");
    assert!(parse_normal_chat_interrupted_recovery_record_v2_bytes(
        &jcs_canonical(&unknown_version)?,
        &proof
    )
    .is_err());
    Ok(())
}
#[test]
fn partial_source_prechild_legacy_checkpoint_missing_or_child_source_present_quarantines(
) -> TestResult {
    for mode in 0..3 {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let req: NormalChatCallRequestV2 = request(&fx, &session, "intent:one")?;
        let stop = if mode == 2 {
            Stop::AfterPolicyConsume
        } else {
            Stop::AfterLink
        };
        assert!(service
            .begin_normal_chat_attempt_with_interruption(&session, &req, Some(stop))
            .is_err());
        let (family, _) = FamilyAuthorityStore::require_existing_normal_chat_history_context_v1(
            &File::open(session.run_dir())?,
            session.session(),
        )?;
        let res = family
            .read_normal_chat_reservation("intent:one")?
            .ok_or("reservation absent")?;
        let child = fx
            .root
            .path()
            .join(content_digest(&res.attempt.run_id()?)?.to_string());
        match mode {
            0 => {
                let path = session.run_dir().join("family-authority.json");
                let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
                value["normal_chat_session"]["reservations"]["intent:one"]
                    .as_object_mut()
                    .ok_or("stored reservation absent")?
                    .remove("bootstrap");
                fs::write(path, jcs_canonical(&value)?)?;
            }
            1 => fs::create_dir(&child)?,
            _ => fs::rename(&child, child.with_extension("retained-but-relocated"))?,
        }
        let before = tree(fx.root.path())?;
        let recovery =
            runtime(fx.root.path(), fx.clock.clone())?.with_interrupted_normal_chat_recovery();
        assert!(recovery
            .recover_prechild_normal_chat_admission(session.run_id(), "intent:one")
            .is_err());
        assert_eq!(tree(fx.root.path())?, before);
    }
    Ok(())
}
