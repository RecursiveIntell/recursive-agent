//! Cold-owner recovery of real provider-disabled publication prefixes.
use super::*;
use recursive_agent_contracts::{jcs_canonical, ReceiptV1};
use recursive_agent_ledger::{
    recover_normal_chat_session_degradation_from_runtime_root_fd as recover, AppendStage,
    NormalChatSessionPublicationInterruptionV1 as Fault,
};

use recursive_agent_ledger::recover_normal_chat_session_degradation_from_runtime_root_fd_with_observer as observe;

#[test]
fn publication_recovery_cold_worker() -> TestResult {
    let Ok(output) = std::env::var("RA_PUBLICATION_RECOVERY_OUTPUT") else {
        return Ok(());
    };
    let id: CurrentRunId = serde_json::from_str(&std::env::var("RA_PUBLICATION_RECOVERY_ID")?)?;
    let parent = std::path::Path::new(&output).join(content_digest(&id)?.to_string());
    let gate = Gate::acquire_existing(&File::open(parent)?)?;
    recover(&File::open(output)?, &id, &gate)?.recheck()?;
    Ok(())
}

#[test]
fn publication_recovery_fresh_process_without_grant() -> TestResult {
    let fx = Fixture::new()?;
    let (session, gate) = native_closed(&fx, None, None, false)?;
    let output = File::open(fx.root.path())?;
    let id = session.run_id().clone();
    assert!(prepare(&output, &id, &gate)?
        .publish_with_interruption(Some(Fault::Receipt {
            ordinal: 1,
            stage: AppendStage::LogFsync
        }))
        .is_err());
    gate.unlock()?;
    drop(session);
    drop(output);
    fs::remove_file(fx._grant_root.path().join("grant.json"))?;
    let result = std::process::Command::new(std::env::current_exe()?)
        .arg("publication_recovery_cold_worker")
        .arg("--nocapture")
        .env("RA_PUBLICATION_RECOVERY_OUTPUT", fx.root.path())
        .env("RA_PUBLICATION_RECOVERY_ID", serde_json::to_string(&id)?)
        .output()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}

#[test]
fn publication_recovery_rejects_corrupt_or_unrelated_inventory_and_metadata() -> TestResult {
    for mode in [
        "extra",
        "partial",
        "conflicting",
        "missing-marker",
        "missing-meta",
        "bad-meta",
        "wrong-head",
        "marker-only",
    ] {
        let fx = Fixture::new()?;
        let (session, gate) = native_closed(&fx, None, None, false)?;
        let output = File::open(fx.root.path())?;
        let plan = prepare(&output, session.run_id(), &gate)?;
        let root = plan.root_revocation_descriptor().clone();
        let marker = plan.marker_descriptor().clone();
        assert!(plan
            .publish_with_interruption(Some(Fault::Receipt {
                ordinal: 1,
                stage: AppendStage::LogFsync
            }))
            .is_err());
        let artifacts = session.run_dir().join("artifacts");
        match mode {
            "extra" => {
                recursive_agent_ledger::ArtifactStore::from_run_root_fd(
                    &File::open(session.run_dir())?,
                    false,
                )?
                .put(b"unrelated", "application/json", None)?;
            }
            "partial" => {
                fs::remove_file(artifacts.join(format!("{}.meta", marker.digest)))?;
            }
            "conflicting" => {
                fs::write(artifacts.join(marker.digest.to_string()), b"wrong")?;
            }
            "missing-marker" => {
                fs::remove_file(artifacts.join(marker.digest.to_string()))?;
                fs::remove_file(artifacts.join(format!("{}.meta", marker.digest)))?;
            }
            "missing-meta" => fs::remove_file(session.run_dir().join("chain.meta"))?,
            "bad-meta" => fs::write(session.run_dir().join("chain.meta"), b"{}")?,
            "wrong-head" => {
                let path = session.run_dir().join("chain.meta");
                let mut meta: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
                meta["head"] = json!("foreign");
                fs::write(path, jcs_canonical(&meta)?)?;
            }
            _ => {
                fs::remove_file(artifacts.join(root.digest.to_string()))?;
                fs::remove_file(artifacts.join(format!("{}.meta", root.digest)))?;
            }
        }
        let before = tree(fx.root.path())?;
        assert!(recover(&output, session.run_id(), &gate).is_err(), "{mode}");
        assert_eq!(tree(fx.root.path())?, before, "{mode}");
    }
    Ok(())
}

#[test]
fn publication_recovery_late_source_gate_child_and_parent_recheck_refuses() -> TestResult {
    for mode in ["gate", "root", "child", "meta", "suffix"] {
        let fx = Fixture::new()?;
        let (session, gate) = native_closed(&fx, None, None, false)?;
        let output = File::open(fx.root.path())?;
        let plan = prepare(&output, session.run_id(), &gate)?;
        let child = fx
            .root
            .path()
            .join(content_digest(&plan.marker().children[0].child_run_id)?.to_string());
        assert!(plan
            .publish_with_interruption(Some(Fault::AfterRootArtifact))
            .is_err());
        let mut action = Ok(());
        let result = observe(&output, session.run_id(), &gate, || {
            action = (|| -> std::io::Result<()> {
                match mode {
                    "gate" => fs::rename(
                        session.run_dir().join(".normal-chat-runtime.lock"),
                        session.run_dir().join("detached-gate"),
                    )?,
                    "root" => fs::remove_file(session.run_dir().join("family-authority.json"))?,
                    "child" => fs::remove_file(child.join("chain.meta"))?,
                    "meta" => fs::write(session.run_dir().join("chain.meta"), b"{}")?,
                    _ => {
                        use std::io::Write;
                        fs::OpenOptions::new()
                            .append(true)
                            .open(session.run_dir().join("receipts.ndjson"))?
                            .write_all(b"foreign")?;
                    }
                }
                Ok(())
            })();
        });
        action?;
        assert!(result.is_err(), "{mode}");
    }
    Ok(())
}

#[test]
fn publication_recovery_all_owned_crash_boundaries() -> TestResult {
    let mut faults = vec![Fault::AfterRootArtifact, Fault::AfterMarkerArtifact];
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
            faults.push(Fault::Receipt { ordinal, stage });
        }
    }
    for batch in faults.chunks(4) {
        std::thread::scope(|scope| -> Result<(), String> {
            let handles: Vec<_> = batch
                .iter()
                .copied()
                .map(|fault| {
                    scope.spawn(move || recovery_boundary(fault).map_err(|e| e.to_string()))
                })
                .collect();
            for handle in handles {
                handle
                    .join()
                    .map_err(|_| "boundary worker panicked".to_owned())??;
            }
            Ok(())
        })?;
    }
    Ok(())
}
fn recovery_boundary(fault: Fault) -> TestResult {
    eprintln!("recovery boundary {fault:?}");
    let fx = Fixture::new()?;
    let (session, gate) = native_closed(&fx, None, None, false)?;
    let output = File::open(fx.root.path())?;
    let path = session.run_dir().to_path_buf();
    let id = session.run_id().clone();
    let prefix = fs::read(path.join("receipts.ndjson"))?;
    let plan = prepare(&output, &id, &gate)?;
    let marker = plan.marker().clone();
    assert!(plan.publish_with_interruption(Some(fault)).is_err());
    eprintln!("published fault {fault:?}");
    let interrupted = fs::read(path.join("receipts.ndjson"))?;
    // Drop all live session/output/gate capabilities; reopen retained history.
    drop(session);
    gate.unlock()?;
    drop(output);
    fs::remove_file(fx._grant_root.path().join("grant.json"))?;
    let cold_output = File::open(fx.root.path())?;
    let cold_gate = Gate::acquire_existing(&File::open(&path)?)?;
    eprintln!("enter cold recovery {fault:?}");
    let proof = recover(&cold_output, &id, &cold_gate).map_err(|e| format!("{fault:?}: {e}"))?;
    eprintln!("returned cold recovery {fault:?}");
    assert_eq!(proof.marker(), &marker);
    assert!(proof.verification().current_strict_success);
    let after = fs::read(path.join("receipts.ndjson"))?;
    assert!(after.starts_with(&prefix));
    let complete_end = interrupted
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |i| i + 1);
    assert!(after.starts_with(&interrupted[..complete_end]));
    let stable = tree(fx.root.path())?;
    recover(&cold_output, &id, &cold_gate)?.recheck()?;
    assert_eq!(tree(fx.root.path())?, stable);
    Ok(())
}

#[test]
fn publication_recovery_wrong_gate_and_native_suffix_time_refuse_without_repair() -> TestResult {
    let fx = Fixture::new()?;
    let (session, gate) = native_closed(&fx, None, None, false)?;
    let output = File::open(fx.root.path())?;
    assert!(prepare(&output, session.run_id(), &gate)?
        .publish_with_interruption(Some(Fault::Receipt {
            ordinal: 0,
            stage: AppendStage::LogFsync
        }))
        .is_err());
    let unrelated = tempfile::tempdir()?;
    let wrong = Gate::acquire(&File::open(unrelated.path())?)?;
    let before = tree(fx.root.path())?;
    assert!(recover(&output, session.run_id(), &wrong).is_err());
    assert_eq!(tree(fx.root.path())?, before);
    let path = session.run_dir().join("receipts.ndjson");
    let raw = fs::read_to_string(&path)?;
    let mut rows: Vec<ReceiptV1> = raw
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    let last = rows.last_mut().ok_or("missing root row")?;
    last.valid_time += TimeDelta::seconds(1);
    let head = recursive_agent_ledger::chain_digest_from_raw(
        &last.prev_chain_digest,
        &last.canonical_bytes()?,
    )?;
    let mut bytes = Vec::new();
    for row in &rows {
        bytes.extend(row.canonical_bytes()?);
        bytes.push(b'\n');
    }
    fs::write(path, bytes)?;
    let path = session.run_dir().join("chain.meta");
    let mut meta: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    meta["head"] = json!(head.to_string());
    meta["length"] = json!(rows.len());
    fs::write(path, jcs_canonical(&meta)?)?;
    let before = tree(fx.root.path())?;
    assert!(recover(&output, session.run_id(), &gate).is_err());
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}

#[test]
fn publication_recovery_final_readback_recheck_refuses() -> TestResult {
    let fx = Fixture::new()?;
    let (session, gate) = native_closed(&fx, None, None, false)?;
    let output = File::open(fx.root.path())?;
    assert!(prepare(&output, session.run_id(), &gate)?
        .publish_with_interruption(Some(Fault::AfterMarkerArtifact))
        .is_err());
    let mut called = false;
    let mut action = Ok(());
    let result = recursive_agent_ledger::recover_normal_chat_session_degradation_from_runtime_root_fd_with_observers(&output, session.run_id(), &gate, || {}, || {
        called = true;
        action = fs::write(session.run_dir().join("chain.meta"), b"{}");
    });
    action?;
    assert!(called);
    assert!(result.is_err());
    assert_eq!(fs::read(session.run_dir().join("chain.meta"))?, b"{}");
    Ok(())
}

#[test]
fn publication_recovery_complete_eof_preserves_receipt_identity_and_times() -> TestResult {
    let fx = Fixture::new()?;
    let (session, gate) = native_closed(&fx, None, None, false)?;
    let output = File::open(fx.root.path())?;
    prepare(&output, session.run_id(), &gate)?.publish()?;
    let path = session.run_dir().join("receipts.ndjson");
    let mut bytes = fs::read(&path)?;
    assert_eq!(bytes.pop(), Some(b'\n'));
    fs::write(&path, &bytes)?;
    recover(&output, session.run_id(), &gate)?.recheck()?;
    let after = fs::read(path)?;
    assert_eq!(&after[..after.len() - 1], bytes);
    Ok(())
}
