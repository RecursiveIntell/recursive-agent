use super::*;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

struct DowngradingClock {
    base: Arc<TestClock>,
    armed: AtomicBool,
    path: PathBuf,
    failed: AtomicBool,
}
impl Clock for DowngradingClock {
    fn now(&self) -> DateTime<Utc> {
        if self.armed.swap(false, Ordering::SeqCst) {
            let action = (|| -> TestResult {
                let mut raw: serde_json::Value = serde_json::from_slice(&fs::read(&self.path)?)?;
                if raw["state"]["state"] != json!("revoked") {
                    return Err("test did not reach closed native state".into());
                }
                raw["state"] = json!({"state":"issued"});
                fs::write(&self.path, recursive_agent_contracts::jcs_canonical(&raw)?)?;
                Ok(())
            })();
            self.failed.store(action.is_err(), Ordering::SeqCst);
        }
        self.base.now()
    }
}
#[test]
fn final_historical_confirmation_cannot_revoke_a_downgraded_root_even_at_same_time() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let path = fs::read_dir(session.run_dir().join("permits"))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "json"))
        .ok_or("root missing")?;
    let clock = Arc::new(DowngradingClock {
        base: fx.clock.clone(),
        armed: AtomicBool::new(false),
        path: path.clone(),
        failed: AtomicBool::new(false),
    });
    let service =
        runtime(fx.root.path(), clock.clone())?.with_normal_chat_egress_grant(fx.authority.clone());
    let result = service.close_normal_chat_session_with_observer(&session, None, || {
        clock.armed.store(true, Ordering::SeqCst)
    });
    assert!(!clock.failed.load(Ordering::SeqCst));
    assert!(
        result.is_err(),
        "historical confirmation silently re-revoked rolled-back native authority"
    );
    let raw: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
    assert_eq!(raw["state"], json!({"state":"issued"}));
    Ok(())
}

struct DeletingClock {
    base: Arc<TestClock>,
    armed: AtomicBool,
    path: PathBuf,
    failed: AtomicBool,
}
impl Clock for DeletingClock {
    fn now(&self) -> DateTime<Utc> {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.failed
                .store(fs::remove_file(&self.path).is_err(), Ordering::SeqCst);
        }
        self.base.now()
    }
}
#[test]
fn final_clock_cannot_remove_native_close_authority_before_successful_return() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let path = fs::read_dir(session.run_dir().join("permits"))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("permit-"))
                && p.extension().is_some_and(|x| x == "json")
        })
        .ok_or("native record absent")?;
    let clock = Arc::new(DeletingClock {
        base: fx.clock.clone(),
        armed: AtomicBool::new(false),
        path: path.clone(),
        failed: AtomicBool::new(false),
    });
    let service =
        runtime(fx.root.path(), clock.clone())?.with_normal_chat_egress_grant(fx.authority.clone());
    let result = service.close_normal_chat_session_with_observer(&session, None, || {
        clock.armed.store(true, Ordering::SeqCst)
    });
    assert!(!clock.failed.load(Ordering::SeqCst));
    assert!(!path.exists());
    assert!(
        result.is_err(),
        "closed success escaped with missing native authority"
    );
    assert!(service.close_normal_chat_session(&session).is_err());
    assert!(!path.exists(), "historical close recreated authority");
    Ok(())
}

use recursive_agent_ledger::{AppendStage, ArtifactStore};
use recursive_agent_policy::{
    NormalChatSessionCloseInterruptionV2 as NativeStop, PermitTransitionStage,
};
use recursive_agent_runner::NormalChatParentCloseInterruptionV2 as Stop;

fn complete_rows(
    path: &std::path::Path,
) -> Result<Vec<recursive_agent_contracts::ReceiptV1>, Box<dyn std::error::Error>> {
    Ok(fs::read_to_string(path)?
        .lines()
        .filter_map(|s| serde_json::from_str(s).ok())
        .collect())
}
#[test]
fn parent_close_fault_matrix_preserves_native_times_charges_and_complete_prefix_rows() -> TestResult
{
    for cancelled in [false, true] {
        let mut stops = vec![
            Stop::AfterNative,
            Stop::AfterArtifact,
            Stop::BeforeReturn,
            Stop::MetadataCapacity,
        ];
        for stage in [
            PermitTransitionStage::TempWrite,
            PermitTransitionStage::TempFsync,
            PermitTransitionStage::Rename,
            PermitTransitionStage::DirectoryFsync,
        ] {
            stops.push(Stop::Native(NativeStop::FamilyClose(stage)));
            stops.push(Stop::Native(NativeStop::RootClose(stage)));
        }
        for ordinal in 0..if cancelled { 3 } else { 2 } {
            for stage in [
                AppendStage::PartialRecord,
                AppendStage::FullReceiptAppend,
                AppendStage::LogFsync,
                AppendStage::MetadataTempWrite,
                AppendStage::MetadataFsync,
                AppendStage::MetadataRename,
                AppendStage::DirectoryFsync,
            ] {
                stops.push(Stop::Receipt { ordinal, stage });
            }
        }
        for stop in stops {
            let fx = Fixture::new()?;
            let service = fx.service()?;
            let session = service.open_normal_chat_session("conversation:fixture")?;
            if cancelled {
                family(&fx, &session)?.revoke_parent(start())?;
            }
            assert!(
                service
                    .close_normal_chat_session_with_interruption(&session, Some(stop))
                    .is_err(),
                "{stop:?}"
            );
            let native = family(&fx, &session)?.read_normal_chat_session_snapshot_v2()?;
            let store = DurablePermitStore::require_existing_from_run_root_fd(&File::open(
                session.run_dir(),
            )?)?;
            let record = store
                .read_normal_chat_session_control_record()?
                .ok_or("record absent")?;
            let prefix = complete_rows(&session.run_dir().join("receipts.ndjson"))?;
            fx.clock.0.store(100, Ordering::SeqCst);
            let fresh_service = fx.service()?;
            let done = fresh_service.close_normal_chat_session(&session)?;
            assert_eq!(
                done.terminal_state(),
                if cancelled {
                    RunTerminalStateV1::Cancelled
                } else {
                    RunTerminalStateV1::Succeeded
                }
            );
            let after = family(&fx, &session)?.read_normal_chat_session_snapshot_v2()?;
            assert_eq!(after.reservations, native.reservations);
            if native.admission.closed_at.is_some() {
                assert_eq!(after.admission.closed_at, native.admission.closed_at);
            }
            if matches!(
                record.state,
                recursive_agent_policy::PermitStateV1::Revoked { .. }
            ) {
                assert_eq!(
                    store.read_normal_chat_session_control_record()?,
                    Some(record)
                );
            }
            let rows = complete_rows(&session.run_dir().join("receipts.ndjson"))?;
            assert!(
                rows.starts_with(&prefix),
                "{stop:?} rewrote acknowledged prefix"
            );
            let stable = fs::read(session.run_dir().join("receipts.ndjson"))?;
            assert_eq!(
                fresh_service
                    .close_normal_chat_session(&session)?
                    .chain_head(),
                done.chain_head()
            );
            assert_eq!(stable, fs::read(session.run_dir().join("receipts.ndjson"))?);
        }
    }
    Ok(())
}
fn copy_dir(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    fs::create_dir(to)?;
    fs::set_permissions(to, fs::Permissions::from_mode(0o700))?;
    for e in fs::read_dir(from)? {
        let e = e?;
        if e.file_type()?.is_dir() {
            copy_dir(&e.path(), &to.join(e.file_name()))?;
        } else {
            fs::copy(e.path(), to.join(e.file_name()))?;
        }
    }
    Ok(())
}
#[test]
fn late_parent_and_closed_child_substitutions_never_return_closed_success() -> TestResult {
    for event in [
        "parent-artifacts",
        "child-artifacts",
        "child-permits",
        "child-root",
        "parent-permits",
        "gate",
        "family-revocation",
        "orphan",
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        call(
            &fx,
            &service,
            &session,
            "intent:first",
            "materialization:one",
            NormalChatReportedStateV2::NotSent,
        )?;
        let native = family(&fx, &session)?;
        let reservation = native
            .read_normal_chat_reservation("intent:first")?
            .ok_or("reservation absent")?;
        let child = fx
            .root
            .path()
            .join(content_digest(&reservation.attempt.run_id()?)?.to_string());
        let error = std::cell::RefCell::new(None);
        let result = service.close_normal_chat_session_with_observer(&session, None, || {
            let action = (|| -> TestResult {
                match event {
                    "family-revocation" => native.revoke_parent(start())?,
                    "orphan" => {
                        ArtifactStore::from_run_root_fd(&File::open(session.run_dir())?, false)?
                            .put(b"unknown", "application/json", None)?;
                    }
                    "gate" => {
                        let path = session.run_dir().join(".normal-chat-runtime.lock");
                        fs::rename(&path, session.run_dir().join("detached-gate"))?;
                        fs::write(&path, b"")?;
                        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
                    }
                    _ => {
                        let path = match event {
                            "parent-artifacts" => session.run_dir().join("artifacts"),
                            "parent-permits" => session.run_dir().join("permits"),
                            "child-artifacts" => child.join("artifacts"),
                            "child-permits" => child.join("permits"),
                            _ => child.clone(),
                        };
                        let detached = fx.root.path().join(format!("detached-{event}"));
                        fs::rename(&path, &detached)?;
                        copy_dir(&detached, &path)?;
                    }
                }
                Ok(())
            })();
            if let Err(e) = action {
                *error.borrow_mut() = Some(e.to_string());
            }
        });
        assert!(error.into_inner().is_none(), "{event}");
        assert!(result.is_err(), "{event} escaped parent return fence");
        assert_eq!(
            native
                .read_normal_chat_session_snapshot_v2()?
                .reservations
                .len(),
            1
        );
        assert!(!matches!(
            service.begin_normal_chat_attempt(&session, &request(&fx, &session, "intent:new")?),
            Ok(RuntimeNormalChatBeginV2::Fresh(_))
        ));
    }
    Ok(())
}
#[test]
fn unknown_or_incomplete_terminal_artifact_is_not_repaired_into_success() -> TestResult {
    for orphan in [true, false] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        assert!(service
            .close_normal_chat_session_with_interruption(&session, Some(Stop::AfterArtifact))
            .is_err());
        if orphan {
            ArtifactStore::from_run_root_fd(&File::open(session.run_dir())?, false)?.put(
                b"foreign",
                "application/json",
                None,
            )?;
        } else {
            let artifact = fs::read_dir(session.run_dir().join("artifacts"))?
                .filter_map(Result::ok)
                .map(|e| e.path())
                .find(|p| p.extension().is_none())
                .ok_or("payload absent")?;
            fs::write(artifact, b"wrong")?;
        }
        let family = fs::read(session.run_dir().join("family-authority.json"))?;
        let ledger = fs::read(session.run_dir().join("receipts.ndjson"))?;
        assert!(service.close_normal_chat_session(&session).is_err());
        assert_eq!(
            family,
            fs::read(session.run_dir().join("family-authority.json"))?
        );
        assert_eq!(ledger, fs::read(session.run_dir().join("receipts.ndjson"))?);
    }
    Ok(())
}
#[test]
fn complete_final_receipt_without_newline_preserves_native_times_and_chain_head() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let done = service.close_normal_chat_session(&session)?;
    let path = session.run_dir().join("receipts.ndjson");
    let mut bytes = fs::read(&path)?;
    assert_eq!(bytes.pop(), Some(b'\n'));
    fs::write(&path, &bytes)?;
    fx.clock.0.store(-1, Ordering::SeqCst);
    assert_eq!(
        service.close_normal_chat_session(&session)?.chain_head(),
        done.chain_head()
    );
    let mut expected = bytes;
    expected.push(b'\n');
    assert_eq!(fs::read(path)?, expected);
    Ok(())
}

#[test]
fn missing_existing_parent_stores_disabled_governance_and_foreign_root_never_initialize(
) -> TestResult {
    for missing in [
        ".normal-chat-runtime.lock",
        ".family-authority.lock",
        "family-authority.json",
        "permits",
        "artifacts",
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let target = session.run_dir().join(missing);
        fs::rename(&target, fx.root.path().join(format!("removed-{missing}")))?;
        assert!(
            service.close_normal_chat_session(&session).is_err(),
            "{missing}"
        );
        assert!(!target.exists(), "close recreated {missing}");
    }
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let before = fs::read(session.run_dir().join("receipts.ndjson"))?;
    assert!(runtime(fx.root.path(), fx.clock.clone())?
        .close_normal_chat_session(&session)
        .is_err());
    let other = tempfile::tempdir()?;
    assert!(runtime(other.path(), fx.clock.clone())?
        .with_normal_chat_egress_grant(fx.authority.clone())
        .close_normal_chat_session(&session)
        .is_err());
    assert_eq!(fs::read_dir(other.path())?.count(), 0);
    assert_eq!(before, fs::read(session.run_dir().join("receipts.ndjson"))?);
    Ok(())
}
#[test]
fn fresh_parent_close_cannot_backdate_a_native_transition_before_child_history() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    fx.clock.0.store(100, Ordering::SeqCst);
    call(
        &fx,
        &service,
        &session,
        "intent:first",
        "materialization:one",
        NormalChatReportedStateV2::NotSent,
    )?;
    let family_bytes = fs::read(session.run_dir().join("family-authority.json"))?;
    let ledger = fs::read(session.run_dir().join("receipts.ndjson"))?;
    fx.clock.0.store(50, Ordering::SeqCst);
    assert!(service.close_normal_chat_session(&session).is_err());
    assert_eq!(
        family_bytes,
        fs::read(session.run_dir().join("family-authority.json"))?
    );
    assert_eq!(ledger, fs::read(session.run_dir().join("receipts.ndjson"))?);
    fx.clock.0.store(100, Ordering::SeqCst);
    service.close_normal_chat_session(&session)?;
    Ok(())
}
