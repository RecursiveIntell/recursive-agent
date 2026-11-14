use super::*;
#[path = "normal_chat_parent_recovery_clock.rs"]
mod clock;
use recursive_agent_contracts::{jcs_canonical, CurrentRunId};
use recursive_agent_ledger::{
    AppendStage, NormalChatSessionGateV1 as Gate,
    NormalChatSessionPublicationInterruptionV1 as Publication,
};
use recursive_agent_policy::{
    NormalChatSessionCloseInterruptionV2 as Native, PermitRevocationReasonV1 as Reason,
    PermitTransitionStage as Stage,
};
use recursive_agent_runner::NormalChatParentRecoveryInterruptionV1 as Stop;

fn native_path(
    session: &recursive_agent_runner::RuntimeNormalChatSessionV1,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    for entry in fs::read_dir(session.run_dir().join("permits"))? {
        let p = entry?.path();
        if p.extension().is_some_and(|x| x == "json") {
            return Ok(p);
        }
    }
    Err("root record missing".into())
}
fn close_native(
    fx: &Fixture,
    session: &recursive_agent_runner::RuntimeNormalChatSessionV1,
    reason: Option<Reason>,
    cancel: bool,
) -> TestResult {
    let root = File::open(session.run_dir())?;
    let gate = Gate::acquire_existing(&root)?;
    let proof = verify_closed_normal_chat_family_from_runtime_root_fd(
        &File::open(fx.root.path())?,
        session.run_id(),
    )?;
    let policy = DurablePermitStore::require_existing_from_run_root_fd(&root)?;
    let family = FamilyAuthorityStore::require_existing_from_dir_fd(
        &root,
        proof.context().session_family_grant_v2()?,
    )?;
    if let Some(reason) = reason {
        policy.revoke(
            &proof.context().root_control.permit_id,
            reason,
            start() + TimeDelta::seconds(3),
        )?;
    }
    if cancel {
        family.revoke_parent(start() + TimeDelta::seconds(3))?;
    }
    policy.close_normal_chat_session_v2(
        &family,
        proof.context(),
        &family.read_normal_chat_session_snapshot_v2()?,
        start() + TimeDelta::seconds(4),
        || start() + TimeDelta::seconds(4),
    )?;
    gate.unlock()?;
    Ok(())
}
#[test]
fn parent_recovery_preserves_closed_native_reasons_charges_times_lease_and_precedence() -> TestResult
{
    for (reason, cancel, state) in [
        (None, false, RunTerminalStateV1::Failed),
        (
            Some(Reason::PolicySuperseded),
            false,
            RunTerminalStateV1::Denied,
        ),
        (
            Some(Reason::OperationCancelled),
            false,
            RunTerminalStateV1::Cancelled,
        ),
        (
            Some(Reason::PolicySuperseded),
            true,
            RunTerminalStateV1::Cancelled,
        ),
    ] {
        let fx = Fixture::new()?;
        let (session, _) = closed(&fx, None)?;
        close_native(&fx, &session, reason, cancel)?;
        let record = fs::read(native_path(&session)?)?;
        let family = fs::read(session.run_dir().join("family-authority.json"))?;
        let (service, calls) = reader(&fx)?;
        let result = service
            .with_normal_chat_parent_recovery(true)
            .recover_normal_chat_session_parent(session.run_id())?;
        assert_eq!(result.terminal_state(), state);
        assert_eq!(result.unknown_attempt_count(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(fs::read(native_path(&session)?)?, record);
        assert_eq!(
            fs::read(session.run_dir().join("family-authority.json"))?,
            family
        );
    }
    Ok(())
}
#[test]
fn parent_recovery_native_artifact_suffix_and_lost_ack_boundaries() -> TestResult {
    let mut stops = vec![
        Stop::AfterNative,
        Stop::BeforeReturn,
        Stop::Publication(Publication::AfterRootArtifact),
        Stop::Publication(Publication::AfterMarkerArtifact),
    ];
    for stage in [
        Stage::TempWrite,
        Stage::TempFsync,
        Stage::Rename,
        Stage::DirectoryFsync,
    ] {
        // Real unknown settlement/recovery already closes family admission.
        // Only durability confirmation (DirectoryFsync) is reachable here.
        if stage == Stage::DirectoryFsync {
            stops.push(Stop::Native(Native::FamilyClose(stage)));
        }
        stops.push(Stop::Native(Native::RootClose(stage)));
    }
    for ordinal in 0..3 {
        for stage in [
            AppendStage::PartialRecord,
            AppendStage::FullReceiptAppend,
            AppendStage::LogFsync,
            AppendStage::MetadataTempWrite,
            AppendStage::MetadataFsync,
            AppendStage::MetadataRename,
            AppendStage::DirectoryFsync,
        ] {
            stops.push(Stop::Publication(Publication::Receipt { ordinal, stage }));
        }
    }
    for stop in stops {
        eprintln!("runtime parent recovery boundary {stop:?}");
        let fx = Fixture::new()?;
        let (session, _) = closed(&fx, Some(NormalChatReportedStateV2::OutcomeUnknown))?;
        let old =
            DurablePermitStore::require_existing_from_run_root_fd(&File::open(session.run_dir())?)?
                .read_normal_chat_session_control_record()?
                .ok_or("no root")?;
        let prefix = fs::read(session.run_dir().join("receipts.ndjson"))?;
        let (service, _) = reader(&fx)?;
        assert!(
            service
                .with_normal_chat_parent_recovery(true)
                .recover_normal_chat_session_parent_with_interruption(session.run_id(), Some(stop))
                .is_err(),
            "{stop:?}"
        );
        let interrupted = fs::read(session.run_dir().join("receipts.ndjson"))?;
        let (cold, _) = reader(&fx)?;
        let result = cold
            .with_normal_chat_parent_recovery(true)
            .recover_normal_chat_session_parent(session.run_id())?;
        assert_eq!(result.terminal_state(), RunTerminalStateV1::Failed);
        let now =
            DurablePermitStore::require_existing_from_run_root_fd(&File::open(session.run_dir())?)?
                .read_normal_chat_session_control_record()?
                .ok_or("no root")?;
        assert_eq!(now.permit, old.permit, "{stop:?}: original lease/budget");
        let after = fs::read(session.run_dir().join("receipts.ndjson"))?;
        assert!(after.starts_with(&prefix));
        let end = interrupted
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0, |n| n + 1);
        assert!(
            after.starts_with(&interrupted[..end]),
            "{stop:?}: complete retained prefix"
        );
        let stable = tree(fx.root.path())?;
        let (retry, calls) = reader(&fx)?;
        retry
            .with_normal_chat_parent_recovery(true)
            .recover_normal_chat_session_parent(session.run_id())?;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(tree(fx.root.path())?, stable);
    }
    Ok(())
}
#[test]
fn parent_recovery_missing_wrong_gate_root_child_source_and_pending_refuse() -> TestResult {
    for mode in [
        "gate",
        "busy",
        "root",
        "child",
        "source",
        "pending",
        "wrong-run",
    ] {
        let fx = Fixture::new()?;
        let (session, child) = if mode == "pending" {
            let svc = fx.service()?;
            let s = svc.open_normal_chat_session("conversation:fixture")?;
            let (_, _, p, _) = admitted(&fx, &svc, &s)?;
            (s, p)
        } else {
            closed(&fx, None)?
        };
        let held = if mode == "busy" {
            Some(Gate::acquire_existing(&File::open(session.run_dir())?)?)
        } else {
            None
        };
        match mode {
            "gate" => fs::remove_file(session.run_dir().join(".normal-chat-runtime.lock"))?,
            "root" => fs::remove_file(native_path(&session)?)?,
            "child" => fs::remove_file(child.join("chain.meta"))?,
            "source" => fs::remove_dir_all(child.join("permits"))?,
            _ => (),
        }
        let id = if mode == "wrong-run" {
            fx.authority
                .normal_chat_session("conversation:wrong", None)?
                .run_id()?
        } else {
            session.run_id().clone()
        };
        let before = tree(fx.root.path())?;
        let (service, calls) = reader(&fx)?;
        assert!(
            service
                .with_normal_chat_parent_recovery(true)
                .recover_normal_chat_session_parent(&id)
                .is_err(),
            "{mode}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0, "{mode}");
        assert_eq!(tree(fx.root.path())?, before, "{mode}");
        if let Some(gate) = held {
            gate.unlock()?;
        }
    }
    Ok(())
}
#[test]
fn parent_recovery_final_observer_refuses_downgrades_pins_metadata_and_inventory() -> TestResult {
    for mode in [
        "root-issued",
        "family-open",
        "parent-pin",
        "child-pin",
        "output-pin",
        "gate",
        "meta",
        "inventory",
        "source",
    ] {
        let fx = Fixture::new()?;
        let (session, child) = closed(&fx, None)?;
        let root_path = native_path(&session)?;
        let (service, _) = reader(&fx)?;
        let mut action = Ok(());
        let mut called = false;
        let result = service
            .with_normal_chat_parent_recovery(true)
            .recover_normal_chat_session_parent_with_observer(session.run_id(), None, || {
                called = true;
                action = (|| -> TestResult {
                    match mode {
                        "root-issued" => {
                            let mut v: serde_json::Value =
                                serde_json::from_slice(&fs::read(&root_path)?)?;
                            v["state"] = json!({"state":"issued"});
                            fs::write(&root_path, jcs_canonical(&v)?)?;
                        }
                        "family-open" => {
                            let p = session.run_dir().join("family-authority.json");
                            let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&p)?)?;
                            v["normal_chat_session"]["closed_at"] = json!(null);
                            fs::write(p, jcs_canonical(&v)?)?;
                        }
                        "parent-pin" => replace(session.run_dir())?,
                        "child-pin" => replace(&child)?,
                        "output-pin" => replace(fx.root.path())?,
                        "gate" => replace(&session.run_dir().join(".normal-chat-runtime.lock"))?,
                        "meta" => fs::write(session.run_dir().join("chain.meta"), b"{}")?,
                        "inventory" => {
                            recursive_agent_ledger::ArtifactStore::from_run_root_fd(
                                &File::open(session.run_dir())?,
                                false,
                            )?
                            .put(b"foreign", "text/plain", None)?;
                        }
                        _ => fs::remove_dir_all(child.join("permits"))?,
                    }
                    Ok(())
                })();
            });
        action?;
        assert!(called, "{mode}");
        assert!(result.is_err(), "{mode}");
        if mode == "root-issued" {
            let v: serde_json::Value = serde_json::from_slice(&fs::read(root_path)?)?;
            assert_eq!(v["state"], json!({"state":"issued"}), "must not re-revoke");
        }
    }
    Ok(())
}

#[test]
fn parent_recovery_cold_worker() -> TestResult {
    let Ok(output) = std::env::var("RA_RUNTIME_PARENT_RECOVERY_OUTPUT") else {
        return Ok(());
    };
    let id: CurrentRunId = serde_json::from_str(&std::env::var("RA_RUNTIME_PARENT_RECOVERY_ID")?)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let result = runtime(Path::new(&output), Arc::new(CountingClock(calls.clone())))?
        .with_normal_chat_parent_recovery(true)
        .recover_normal_chat_session_parent(&id)?;
    assert_eq!(result.unknown_attempt_count(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}
#[test]
fn parent_recovery_absent_grant_fresh_process_recovers_interrupted_suffix() -> TestResult {
    let fx = Fixture::new()?;
    let (session, _) = closed(&fx, None)?;
    let id = session.run_id().clone();
    let (service, _) = reader(&fx)?;
    assert!(service
        .with_normal_chat_parent_recovery(true)
        .recover_normal_chat_session_parent_with_interruption(
            &id,
            Some(Stop::Publication(Publication::Receipt {
                ordinal: 1,
                stage: AppendStage::PartialRecord
            }))
        )
        .is_err());
    drop(session);
    fs::remove_file(fx._grant_root.path().join("grant.json"))?;
    let output = std::process::Command::new(std::env::current_exe()?)
        .arg("parent_recovery_cold_worker")
        .arg("--nocapture")
        .env("RA_RUNTIME_PARENT_RECOVERY_OUTPUT", fx.root.path())
        .env("RA_RUNTIME_PARENT_RECOVERY_ID", serde_json::to_string(&id)?)
        .output()?;
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
