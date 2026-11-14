use super::*;
use recursive_agent_ledger::AppendStage;
use recursive_agent_policy::{
    NormalChatBeginInterruptionV2, NormalChatInterruptedRecoveryInterruptionV2 as Native,
    NormalChatPreparedRecoveryInterruptionV1 as NativePrepared, PermitTransitionStage as Stage,
};
use recursive_agent_runner::{
    NormalChatInterruptedRuntimeRecoveryInterruptionV2 as Recover,
    NormalChatPrechildRuntimeRecoveryInterruptionV1 as Prechild,
    NormalChatPreparedRuntimeRecoveryInterruptionV1 as Prepared,
};
fn native_stages() -> [Stage; 4] {
    [
        Stage::TempWrite,
        Stage::TempFsync,
        Stage::Rename,
        Stage::DirectoryFsync,
    ]
}
fn ledger_stages() -> [AppendStage; 7] {
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
fn consumed_retry(fault: Recover) -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:one")?;
    assert!(service
        .begin_normal_chat_attempt_with_interruption(&session, &req, Some(Stop::AfterPolicyConsume))
        .is_err());
    let recovery =
        runtime(fx.root.path(), fx.clock.clone())?.with_interrupted_normal_chat_recovery();
    assert!(
        recovery
            .recover_interrupted_normal_chat_attempt_with_interruption(
                session.run_id(),
                "intent:one",
                Some(fault)
            )
            .is_err(),
        "fault {fault:?} did not interrupt"
    );
    let result = runtime(fx.root.path(), fx.clock.clone())?
        .with_interrupted_normal_chat_recovery()
        .recover_interrupted_normal_chat_attempt(session.run_id(), "intent:one")?;
    assert!(result.recovery().prefix_receipts.is_empty());
    Ok(())
}
#[test]
fn partial_recovery_consumed_native_crash_matrix() -> TestResult {
    for stage in native_stages() {
        consumed_retry(Recover::Native(Native::FamilyClose(stage)))?;
        consumed_retry(Recover::Native(Native::ChildRecovery(stage)))?;
        consumed_retry(Recover::ControlClose(stage))?;
    }
    Ok(())
}
#[test]
fn partial_recovery_consumed_projection_crash_matrix() -> TestResult {
    for ordinal in 0..4 {
        consumed_retry(Recover::PreflightArtifact { ordinal })?;
    }
    for ordinal in 0..7 {
        consumed_retry(Recover::PreflightReceipt {
            ordinal,
            stage: AppendStage::PartialRecord,
        })?;
    }
    for ordinal in 0..3 {
        consumed_retry(Recover::ChildReceipt {
            ordinal,
            stage: AppendStage::MetadataRename,
        })?;
    }
    for fault in [
        Recover::AfterNative,
        Recover::AfterControlClose,
        Recover::BeforeReturn,
        Recover::ParentArtifact,
        Recover::Artifact { ordinal: 0 },
        Recover::Artifact { ordinal: 1 },
    ] {
        consumed_retry(fault)?;
    }
    for stage in ledger_stages() {
        consumed_retry(Recover::ParentReceipt(stage))?;
    }
    Ok(())
}
fn prepared_retry(fault: Prepared) -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:one")?;
    assert!(service
        .begin_normal_chat_attempt_with_interruption(
            &session,
            &req,
            Some(Stop::Policy(NormalChatBeginInterruptionV2::Control(
                Stage::Rename
            )))
        )
        .is_err());
    let recovery =
        runtime(fx.root.path(), fx.clock.clone())?.with_interrupted_normal_chat_recovery();
    assert!(
        recovery
            .recover_prepared_normal_chat_attempt_with_observer(
                session.run_id(),
                "intent:one",
                Some(fault),
                || {}
            )
            .is_err(),
        "fault {fault:?} did not interrupt"
    );
    runtime(fx.root.path(), fx.clock.clone())?
        .with_interrupted_normal_chat_recovery()
        .recover_prepared_normal_chat_attempt(session.run_id(), "intent:one")?;
    Ok(())
}
#[test]
fn partial_recovery_prepared_crash_matrix() -> TestResult {
    for stage in native_stages() {
        prepared_retry(Prepared::Native(NativePrepared::Family(stage)))?;
        prepared_retry(Prepared::Native(NativePrepared::Control(stage)))?;
    }
    for ordinal in 0..5 {
        prepared_retry(Prepared::ChildReceipt {
            ordinal,
            stage: AppendStage::PartialRecord,
        })?;
    }
    for fault in [
        Prepared::AfterNative,
        Prepared::ParentArtifact,
        Prepared::BeforeReturn,
        Prepared::ParentReceipt(AppendStage::MetadataRename),
    ] {
        prepared_retry(fault)?;
    }
    Ok(())
}
fn prechild_retry(fault: Prechild) -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:one")?;
    assert!(service
        .begin_normal_chat_attempt_with_interruption(&session, &req, Some(Stop::AfterLinkArtifact))
        .is_err());
    let recovery =
        runtime(fx.root.path(), fx.clock.clone())?.with_interrupted_normal_chat_recovery();
    assert!(
        recovery
            .recover_prechild_normal_chat_admission_with_observer(
                session.run_id(),
                "intent:one",
                Some(fault),
                || {}
            )
            .is_err(),
        "fault {fault:?} did not interrupt"
    );
    runtime(fx.root.path(), fx.clock.clone())?
        .with_interrupted_normal_chat_recovery()
        .recover_prechild_normal_chat_admission(session.run_id(), "intent:one")?;
    Ok(())
}
#[test]
fn partial_recovery_prechild_crash_matrix() -> TestResult {
    for stage in native_stages() {
        prechild_retry(Prechild::Family(stage))?;
        prechild_retry(Prechild::Control(stage))?;
    }
    for ordinal in 0..3 {
        for stage in ledger_stages() {
            prechild_retry(Prechild::Receipt { ordinal, stage })?;
        }
    }
    for fault in [
        Prechild::AfterFamily,
        Prechild::AfterControl,
        Prechild::BeforeReturn,
        Prechild::Artifact { ordinal: 0 },
        Prechild::Artifact { ordinal: 1 },
    ] {
        prechild_retry(fault)?;
    }
    Ok(())
}
#[test]
fn partial_recovery_canonical_gate_blocks_competing_begin_close_and_recovery() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:one")?;
    assert!(service
        .begin_normal_chat_attempt_with_interruption(&session, &req, Some(Stop::AfterPolicyConsume))
        .is_err());
    let recovery =
        runtime(fx.root.path(), fx.clock.clone())?.with_interrupted_normal_chat_recovery();
    recovery.recover_interrupted_normal_chat_attempt_with_observer(
        session.run_id(),
        "intent:one",
        None,
        || {
            assert!(service.begin_normal_chat_attempt(&session, &req).is_err());
            assert!(service.close_normal_chat_session(&session).is_err());
            assert!(recovery
                .recover_interrupted_normal_chat_attempt(session.run_id(), "intent:one")
                .is_err());
        },
    )?;
    Ok(())
}
