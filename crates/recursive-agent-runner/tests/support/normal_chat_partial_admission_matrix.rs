use super::*;
use recursive_agent_contracts::{jcs_canonical, ReceiptV1};
use recursive_agent_ledger::{AppendStage, ArtifactStore};
use recursive_agent_policy::{
    FamilyAuthorityStore, NormalChatAttemptPolicyStateV2, NormalChatBeginInterruptionV2,
    PermitTransitionStage,
};
fn stages() -> [AppendStage; 7] {
    [
        AppendStage::PartialRecord,
        AppendStage::FullReceiptAppend,
        AppendStage::LogFsync,
        AppendStage::MetadataTempWrite,
        AppendStage::MetadataFsync,
        AppendStage::MetadataRename,
        AppendStage::DirectoryFsync,
    ]
}
fn complete_bytes(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };
    let mut result = Vec::new();
    for row in bytes.split_inclusive(|b| *b == b'\n') {
        if row.last() == Some(&b'\n') && serde_json::from_slice::<ReceiptV1>(row).is_ok() {
            result.extend_from_slice(row);
        } else {
            break;
        }
    }
    Ok(result)
}
fn admission_matrix(ordinal: usize) -> TestResult {
    for stage in stages() {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let req = request(&fx, &session, "intent:one")?;
        assert!(service
            .begin_normal_chat_attempt_with_interruption(
                &session,
                &req,
                Some(Stop::ChildReceipt { ordinal, stage })
            )
            .is_err());
        let (family, _) = FamilyAuthorityStore::require_existing_normal_chat_history_context_v1(
            &File::open(session.run_dir())?,
            session.session(),
        )?;
        let before = family.read_normal_chat_session_snapshot_v2()?;
        let reservation = before.reservations.first().ok_or("reservation absent")?;
        let child = fx
            .root
            .path()
            .join(content_digest(&reservation.attempt.run_id()?)?.to_string());
        let retained_child = complete_bytes(&child.join("receipts.ndjson"))?;
        let retained_parent = fs::read(session.run_dir().join("receipts.ndjson"))?;
        let policy = DurablePermitStore::require_existing_from_run_root_fd(&File::open(&child)?)?;
        let native_before = policy.read_normal_chat_attempt_v2(&family, "intent:one")?;
        let recovery = runtime(fx.root.path(), fx.clock.clone())?
            .with_interrupted_normal_chat_recovery()
            .with_expired_normal_chat_recovery();
        if ordinal == 6 && stage != AppendStage::PartialRecord {
            assert!(
                recovery
                    .recover_interrupted_normal_chat_attempt(session.run_id(), "intent:one")
                    .is_err(),
                "complete barrier {stage:?}"
            );
            fx.clock.0.store(700_000, Ordering::SeqCst);
            let unknown =
                recovery.recover_expired_normal_chat_attempt(session.run_id(), "intent:one")?;
            assert_eq!(
                unknown.recovery().provider_send_state,
                recursive_agent_policy::NormalChatProviderSendStateV1::MayHaveBeenSent
            );
        } else {
            let result =
                recovery.recover_interrupted_normal_chat_attempt(session.run_id(), "intent:one")?;
            assert_eq!(
                result.terminal_state(),
                recursive_agent_contracts::RunTerminalStateV1::Failed
            );
            assert!(result.recovery().prefix_receipts.len() < 7);
        }
        let native_after = policy.read_normal_chat_attempt_v2(&family, "intent:one")?;
        assert_eq!(native_before.effect, native_after.effect);
        assert_eq!(native_before.preflight, native_after.preflight);
        assert!(native_after.outcome.is_none() && native_after.settlement.is_none());
        assert_eq!(
            family.read_normal_chat_session_snapshot_v2()?.reservations,
            before.reservations
        );
        assert!(fs::read(child.join("receipts.ndjson"))?.starts_with(&retained_child));
        assert!(fs::read(session.run_dir().join("receipts.ndjson"))?.starts_with(&retained_parent));
    }
    Ok(())
}
#[test]
fn partial_admission_row_0_matrix() -> TestResult {
    admission_matrix(0)
}
#[test]
fn partial_admission_row_1_matrix() -> TestResult {
    admission_matrix(1)
}
#[test]
fn partial_admission_row_2_matrix() -> TestResult {
    admission_matrix(2)
}
#[test]
fn partial_admission_row_3_matrix() -> TestResult {
    admission_matrix(3)
}
#[test]
fn partial_admission_row_4_matrix() -> TestResult {
    admission_matrix(4)
}
#[test]
fn partial_admission_row_5_matrix() -> TestResult {
    admission_matrix(5)
}
#[test]
fn partial_admission_row_6_matrix() -> TestResult {
    admission_matrix(6)
}
#[test]
fn partial_admission_preflight_artifact_boundaries() -> TestResult {
    for ordinal in 0..4 {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let req = request(&fx, &session, "intent:one")?;
        assert!(service
            .begin_normal_chat_attempt_with_interruption(
                &session,
                &req,
                Some(Stop::PreflightArtifact { ordinal })
            )
            .is_err());
        runtime(fx.root.path(), fx.clock.clone())?
            .with_interrupted_normal_chat_recovery()
            .recover_interrupted_normal_chat_attempt(session.run_id(), "intent:one")?;
    }
    Ok(())
}
#[test]
fn partial_admission_native_commit_boundaries() -> TestResult {
    for stage in [
        PermitTransitionStage::Rename,
        PermitTransitionStage::DirectoryFsync,
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let req = request(&fx, &session, "intent:one")?;
        assert!(service
            .begin_normal_chat_attempt_with_interruption(
                &session,
                &req,
                Some(Stop::Policy(NormalChatBeginInterruptionV2::Control(stage)))
            )
            .is_err());
        runtime(fx.root.path(), fx.clock.clone())?
            .with_interrupted_normal_chat_recovery()
            .recover_prepared_normal_chat_attempt(session.run_id(), "intent:one")?;
    }
    for stage in [
        PermitTransitionStage::TempWrite,
        PermitTransitionStage::TempFsync,
        PermitTransitionStage::Rename,
        PermitTransitionStage::DirectoryFsync,
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let req = request(&fx, &session, "intent:one")?;
        assert!(service
            .begin_normal_chat_attempt_with_interruption(
                &session,
                &req,
                Some(Stop::Policy(NormalChatBeginInterruptionV2::Effect(stage)))
            )
            .is_err());
        let recovery =
            runtime(fx.root.path(), fx.clock.clone())?.with_interrupted_normal_chat_recovery();
        if matches!(
            stage,
            PermitTransitionStage::TempWrite | PermitTransitionStage::TempFsync
        ) {
            recovery.recover_prepared_normal_chat_attempt(session.run_id(), "intent:one")?;
        } else {
            recovery.recover_interrupted_normal_chat_attempt(session.run_id(), "intent:one")?;
        }
    }
    Ok(())
}
#[test]
fn partial_admission_quarantines_metadata_inventory_missing_native_and_clock() -> TestResult {
    for variant in 0..7 {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let req = request(&fx, &session, "intent:one")?;
        assert!(service
            .begin_normal_chat_attempt_with_interruption(
                &session,
                &req,
                Some(Stop::AfterPolicyConsume)
            )
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
        match variant {
            0 => fs::write(child.join("chain.meta"), b"{}")?,
            1 => {
                fs::remove_file(child.join("chain.meta"))?;
            }
            2 => {
                let mut meta: serde_json::Value =
                    serde_json::from_slice(&fs::read(child.join("chain.meta"))?)?;
                meta["head"] = json!(ContentDigest::compute(b"conflicting"));
                fs::write(child.join("chain.meta"), jcs_canonical(&meta)?)?;
            }
            3 => {
                ArtifactStore::from_run_root_fd(&File::open(&child)?, false)?.put(
                    b"foreign",
                    "application/octet-stream",
                    None,
                )?;
            }
            4 => {
                let policy =
                    DurablePermitStore::require_existing_from_run_root_fd(&File::open(&child)?)?;
                let view = policy.read_normal_chat_attempt_v2(&family, "intent:one")?;
                let id = &view.effect.ok_or("effect absent")?.permit_id;
                for entry in fs::read_dir(child.join("permits"))? {
                    let entry = entry?;
                    if entry.path().extension().is_some_and(|e| e == "json") {
                        let value: serde_json::Value =
                            serde_json::from_slice(&fs::read(entry.path())?)?;
                        if value["permit"]["permit_id"] == serde_json::to_value(id)? {
                            fs::remove_file(entry.path())?;
                        }
                    }
                }
            }
            5 => fs::write(session.run_dir().join("chain.meta"), b"{}")?,
            _ => fx.clock.0.store(-1, Ordering::SeqCst),
        }
        let before = tree(fx.root.path())?;
        assert!(
            runtime(fx.root.path(), fx.clock.clone())?
                .with_interrupted_normal_chat_recovery()
                .recover_interrupted_normal_chat_attempt(session.run_id(), "intent:one")
                .is_err(),
            "variant {variant}"
        );
        assert_eq!(
            tree(fx.root.path())?,
            before,
            "variant {variant} mutated quarantined evidence"
        );
    }
    Ok(())
}
#[test]
fn partial_admission_default_gate_and_complete_before_release_unknown() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:one")?;
    assert!(service
        .begin_normal_chat_attempt_with_interruption(&session, &req, Some(Stop::BeforeRelease))
        .is_err());
    assert!(matches!(
        service.recover_interrupted_normal_chat_attempt(session.run_id(), "intent:one"),
        Err(RuntimeServiceError::NormalChatRecoveryDisabled)
    ));
    let before = tree(fx.root.path())?;
    let recovery = runtime(fx.root.path(), fx.clock.clone())?
        .with_interrupted_normal_chat_recovery()
        .with_expired_normal_chat_recovery();
    assert!(recovery
        .recover_interrupted_normal_chat_attempt(session.run_id(), "intent:one")
        .is_err());
    assert_eq!(tree(fx.root.path())?, before);
    fx.clock.0.store(700_000, Ordering::SeqCst);
    recovery.recover_expired_normal_chat_attempt(session.run_id(), "intent:one")?;
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
    assert_eq!(
        DurablePermitStore::require_existing_from_run_root_fd(&File::open(child)?)?
            .read_normal_chat_attempt_v2(&family, "intent:one")?
            .state,
        NormalChatAttemptPolicyStateV2::RecoveredUnknown
    );
    Ok(())
}
