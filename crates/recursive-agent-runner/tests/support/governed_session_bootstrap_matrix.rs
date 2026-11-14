use super::*;
use recursive_agent_contracts::{derive_step_id, CurrentReceiptId, ToolCallSpecV1};
use recursive_agent_ledger::{make_receipt, open, AppendStage, ReceiptDraftV1, RunPaths};
use recursive_agent_policy::{
    build_lineage, FamilyAuthorityStore, NormalChatFamilyReservationRequestV2, PermitBudgetV1,
    PermitRevocationReasonV1,
};
use recursive_agent_runner::NormalChatSessionBootstrapInterruptionV1 as Stop;
use std::os::unix::fs::symlink;

fn control_paths(root: &Path) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(root.join("permits"))? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with("permit-") {
            result.push(entry.path());
        }
    }
    Ok(result)
}
fn old_receipts(
    root: &Path,
) -> Result<Vec<recursive_agent_contracts::ReceiptV1>, Box<dyn std::error::Error>> {
    let bytes = match fs::read(root.join("receipts.ndjson")) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut rows = Vec::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        match serde_json::from_slice(line) {
            Ok(row) => rows.push(row),
            Err(error) if error.is_eof() => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(rows)
}

#[test]
fn bootstrap_interruption_matrix_reopens_only_exact_prefix_and_original_lease() -> TestResult {
    let mut stops = vec![
        Stop::AfterControl,
        Stop::AfterFamily,
        Stop::AfterIdentityArtifact,
        Stop::BeforeRelease,
    ];
    for ordinal in 0..3 {
        for stage in [
            AppendStage::PartialRecord,
            AppendStage::FullReceiptAppend,
            AppendStage::LogFsync,
            AppendStage::MetadataRename,
            AppendStage::DirectoryFsync,
        ] {
            stops.push(Stop::Receipt { ordinal, stage });
        }
    }
    for stop in stops {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        assert!(
            service
                .open_normal_chat_session_with_interruption("conversation:fixture", Some(stop))
                .is_err(),
            "{stop:?}"
        );
        let root = fx.run_dir()?;
        let permits = DurablePermitStore::from_run_root_fd(&File::open(&root)?)?;
        let before = permits
            .read_normal_chat_session_control_record()?
            .ok_or("missing interrupted control")?;
        let prior = old_receipts(&root)?;
        fx.clock.0.store(100, Ordering::SeqCst);
        let reopened = fx
            .service()?
            .open_normal_chat_session("conversation:fixture")?;
        let after = permits
            .read_normal_chat_session_control_record()?
            .ok_or("control missing after repair")?;
        assert_eq!(before, after, "{stop:?} renewed the original control");
        let complete = old_receipts(reopened.run_dir())?;
        assert_eq!(complete.len(), 3);
        for (old, new) in prior.iter().zip(&complete) {
            assert_eq!(old.canonical_bytes()?, new.canonical_bytes()?);
        }
    }
    Ok(())
}

#[test]
fn missing_control_or_family_cannot_be_recreated_over_nonempty_ledger() -> TestResult {
    for missing in ["control", "family"] {
        let fx = Fixture::new()?;
        let opened = fx
            .service()?
            .open_normal_chat_session("conversation:fixture")?;
        let receipts = fs::read(opened.run_dir().join("receipts.ndjson"))?;
        if missing == "control" {
            for path in control_paths(opened.run_dir())? {
                fs::remove_file(path)?;
            }
        } else {
            fs::remove_file(opened.run_dir().join("family-authority.json"))?;
        }
        assert!(matches!(
            fx.service()?
                .open_normal_chat_session("conversation:fixture"),
            Err(RuntimeServiceError::NormalChatSessionRecoveryRequired { .. })
        ));
        assert_eq!(
            fs::read(opened.run_dir().join("receipts.ndjson"))?,
            receipts
        );
        if missing == "control" {
            assert!(control_paths(opened.run_dir())?.is_empty());
        } else {
            assert!(!opened.run_dir().join("family-authority.json").exists());
        }
    }
    Ok(())
}

#[test]
fn retained_artifacts_without_control_are_not_a_fresh_session() -> TestResult {
    let fx = Fixture::new()?;
    assert!(fx
        .service()?
        .open_normal_chat_session_with_interruption(
            "conversation:fixture",
            Some(Stop::AfterIdentityArtifact)
        )
        .is_err());
    let root = fx.run_dir()?;
    for path in control_paths(&root)? {
        fs::remove_file(path)?;
    }
    // Family evidence also disappears: orphan artifact bytes still prevent new authority.
    fs::remove_file(root.join("family-authority.json"))?;
    assert!(matches!(
        fx.service()?
            .open_normal_chat_session("conversation:fixture"),
        Err(RuntimeServiceError::NormalChatSessionRecoveryRequired { .. })
    ));
    assert!(control_paths(&root)?.is_empty());
    Ok(())
}

#[test]
fn changed_bootstrap_material_and_extra_receipts_fail_closed() -> TestResult {
    for tamper in ["receipt", "artifact", "extra"] {
        let fx = Fixture::new()?;
        let opened = fx
            .service()?
            .open_normal_chat_session("conversation:fixture")?;
        if tamper == "receipt" {
            let mut rows = old_receipts(opened.run_dir())?;
            rows[0].valid_time += TimeDelta::milliseconds(1);
            let mut data = Vec::new();
            for row in rows {
                data.extend(row.canonical_bytes()?);
                data.push(b'\n');
            }
            fs::write(opened.run_dir().join("receipts.ndjson"), data)?;
        } else if tamper == "artifact" {
            let row = old_receipts(opened.run_dir())?.remove(0);
            let descriptor = row
                .artifact_refs
                .first()
                .ok_or("identity artifact absent")?;
            let store = open(&RunPaths::new(opened.run_dir()))?.artifact_store()?;
            // Use the descriptor's digest-bound blob path, not a substitute artifact.
            let bytes = store.get(descriptor)?;
            for entry in fs::read_dir(opened.run_dir().join("artifacts"))? {
                let entry = entry?;
                if entry.file_type()?.is_file() && fs::read(entry.path())? == bytes {
                    fs::write(entry.path(), b"tampered")?;
                }
            }
        } else {
            let permits = DurablePermitStore::from_run_root_fd(&File::open(opened.run_dir())?)?;
            let record = permits
                .read_normal_chat_session_control_record()?
                .ok_or("control absent")?;
            let call = ToolCallSpecV1 {
                tool: "unknown-phase".into(),
                args: json!({}),
                frozen_clock: None,
            };
            let mut chain = open(&RunPaths::new(opened.run_dir()))?;
            let extra = make_receipt(
                ReceiptDraftV1 {
                    run_id: opened.run_id().clone(),
                    step_id: derive_step_id(opened.run_id(), 1, "extra", &call)?,
                    kind: ReceiptKindV1::StepStarted,
                    valid_time: start(),
                    lineage: build_lineage(
                        &record.permit.permit_id,
                        &record.permit.binding.policy_version,
                    ),
                    spec_digest: content_digest(&call)?,
                    args_digest: content_digest(&call.args)?,
                    artifact_refs: vec![],
                    outcome: recursive_agent_contracts::ReceiptOutcomeV1::Ok,
                },
                chain.head().clone(),
            )?;
            chain.append(extra)?;
        }
        assert!(
            fx.service()?
                .open_normal_chat_session("conversation:fixture")
                .is_err(),
            "{tamper}"
        );
    }
    Ok(())
}

#[test]
fn closed_revoked_or_expired_session_cannot_bootstrap_again() -> TestResult {
    for state in ["closed", "revoked", "expired"] {
        let fx = Fixture::new()?;
        let opened = fx
            .service()?
            .open_normal_chat_session("conversation:fixture")?;
        let permits = DurablePermitStore::from_run_root_fd(&File::open(opened.run_dir())?)?;
        let control = permits.open_normal_chat_session_control(
            &fx.authority,
            "conversation:fixture",
            None,
            start,
        )?;
        match state {
            "closed" => FamilyAuthorityStore::from_dir_fd(
                &File::open(opened.run_dir())?,
                control.family_grant(),
            )?
            .close_normal_chat_session(start())?,
            "revoked" => {
                permits.revoke(
                    &control.permit().permit_id,
                    PermitRevocationReasonV1::Operator,
                    start(),
                )?;
            }
            _ => fx.clock.0.store(300_000, Ordering::SeqCst),
        }
        let before = permits.read_normal_chat_session_control_record()?;
        let receipts = fs::read(opened.run_dir().join("receipts.ndjson"))?;
        assert!(
            fx.service()?
                .open_normal_chat_session("conversation:fixture")
                .is_err(),
            "{state}"
        );
        assert_eq!(permits.read_normal_chat_session_control_record()?, before);
        assert_eq!(
            fs::read(opened.run_dir().join("receipts.ndjson"))?,
            receipts
        );
    }
    Ok(())
}

#[test]
fn an_existing_reservation_requires_runtime_recovery_not_empty_reopen() -> TestResult {
    let fx = Fixture::new()?;
    let opened = fx
        .service()?
        .open_normal_chat_session("conversation:fixture")?;
    let root = File::open(opened.run_dir())?;
    let permits = DurablePermitStore::from_run_root_fd(&root)?;
    let control = permits.open_normal_chat_session_control(
        &fx.authority,
        "conversation:fixture",
        None,
        start,
    )?;
    let family = FamilyAuthorityStore::from_normal_chat_session_control(
        &root,
        &fx.authority,
        &control,
        start,
    )?;
    let operation = recursive_agent_contracts::parse_normal_chat_operation_v2_bytes(
        &serde_json::to_vec(&json!({
            "schema":"recursive-agent.normal-chat/v2", "conversation_ref":"conversation:fixture", "parent_run_id":opened.run_id(),
            "materialization_ref":"materialization:fixture", "materialization_digest":HOME,
            "policy_basis_ref":"normal-chat-grant:revision-1", "policy_basis_digest":fx.authority.grant().policy_digest,
            "source_revision":"source:fixture", "route_class":"conversation", "provider_identity":"openai_compatible:https://provider.test/v1", "model_ref":"model:fixture", "api_mode":"chat_completions",
            "request_digest":HOME, "request_projection_schema":"ares-json-sorted-v1", "budget":{"output_reserve":10,"max_wall_time_ms":1000,"max_request_bytes":4096}, "replay":"unavailable",
            "provenance":[{"source":"urn:test:fixture", "digest":content_digest(&"fixture")?}]
        }))?,
    )?;
    family.reserve_normal_chat_attempt(
        &fx.authority,
        &NormalChatFamilyReservationRequestV2 {
            operation,
            provider_request_digest: content_digest(&"body")?,
            provider_request_bytes: 4,
            dispatch_intent_ref: "intent:fixture".into(),
            parent_admission_receipt_id: CurrentReceiptId::try_new(format!(
                "v1:recursive-agent/receipt/v1:det:{}",
                "c".repeat(64)
            ))?,
            requested_budget: PermitBudgetV1 {
                max_wall_time_ms: 1000,
                max_output_bytes: 1024 * 1024,
                max_artifact_bytes: 1024 * 1024,
            },
        },
        start,
    )?;
    let before = fs::read(opened.run_dir().join("family-authority.json"))?;
    assert!(matches!(
        fx.service()?
            .open_normal_chat_session("conversation:fixture"),
        Err(RuntimeServiceError::NormalChatSessionRecoveryRequired { .. })
    ));
    assert_eq!(
        fs::read(opened.run_dir().join("family-authority.json"))?,
        before
    );
    Ok(())
}

#[test]
fn unsafe_runtime_gate_and_symlink_root_are_rejected_before_policy_writes() -> TestResult {
    for kind in ["symlink", "directory", "mode", "hardlink", "root_symlink"] {
        let fx = Fixture::new()?;
        let root = fx.run_dir()?;
        let elsewhere = tempfile::tempdir()?;
        if kind == "root_symlink" {
            symlink(elsewhere.path(), &root)?;
        } else {
            fs::create_dir(&root)?;
            let gate = root.join(".normal-chat-runtime.lock");
            match kind {
                "symlink" => symlink(elsewhere.path().join("target"), gate)?,
                "directory" => fs::create_dir(gate)?,
                _ => {
                    fs::write(&gate, b"")?;
                    fs::set_permissions(
                        &gate,
                        fs::Permissions::from_mode(if kind == "mode" { 0o644 } else { 0o600 }),
                    )?;
                    if kind == "hardlink" {
                        fs::hard_link(&gate, root.join("other-name"))?;
                    }
                }
            }
        }
        assert!(
            fx.service()?
                .open_normal_chat_session("conversation:fixture")
                .is_err(),
            "{kind}"
        );
        assert!(!root.join("permits").exists());
    }
    Ok(())
}

#[test]
fn runtime_gate_conflict_is_typed_and_never_waits_or_issues_authority() -> TestResult {
    let fx = Fixture::new()?;
    let root = fx.run_dir()?;
    fs::create_dir(&root)?;
    let path = root.join(".normal-chat-runtime.lock");
    fs::write(&path, b"")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let lock = File::open(path)?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)?;
    assert!(matches!(
        fx.service()?
            .open_normal_chat_session("conversation:fixture"),
        Err(RuntimeServiceError::NormalChatSessionBusy)
    ));
    assert!(!root.join("permits").exists());
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::Unlock)?;
    fx.service()?
        .open_normal_chat_session("conversation:fixture")?;
    Ok(())
}

#[test]
fn malformed_conversation_reference_does_not_create_a_run() -> TestResult {
    let fx = Fixture::new()?;
    assert!(fx.service()?.open_normal_chat_session("").is_err());
    assert_eq!(fs::read_dir(fx.root.path())?.count(), 0);
    Ok(())
}
