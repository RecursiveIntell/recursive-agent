use super::*;
use recursive_agent_contracts::{derive_step_id, ReceiptOutcomeV1, ReceiptV1, ToolCallSpecV1};
use recursive_agent_ledger::{make_receipt, open, AppendStage, ReceiptDraftV1, RunPaths};
use recursive_agent_policy::build_lineage;
use std::sync::atomic::AtomicBool;

struct LocatorClock {
    root: std::path::PathBuf,
    kind: &'static str,
    acted: AtomicBool,
    error: std::sync::Mutex<Option<std::io::Error>>,
}
impl Clock for LocatorClock {
    fn now(&self) -> DateTime<Utc> {
        let ready = fs::read(self.root.join("receipts.ndjson"))
            .is_ok_and(|bytes| bytes.iter().filter(|byte| **byte == b'\n').count() >= 3);
        if ready && !self.acted.swap(true, Ordering::SeqCst) {
            let result = match self.kind {
                "root" => (|| {
                    fs::rename(&self.root, self.root.with_extension("detached"))?;
                    fs::create_dir(&self.root)
                })(),
                "gate" => (|| {
                    let gate = self.root.join(".normal-chat-runtime.lock");
                    fs::rename(&gate, self.root.join("detached-gate"))?;
                    fs::write(&gate, b"")?;
                    fs::set_permissions(gate, fs::Permissions::from_mode(0o600))
                })(),
                "delete_control" | "delete_control_advanced" => (|| {
                    for entry in fs::read_dir(self.root.join("permits"))? {
                        let entry = entry?;
                        if entry.file_name().to_string_lossy().starts_with("permit-") {
                            fs::remove_file(entry.path())?;
                        }
                    }
                    Ok(())
                })(),
                _ => Ok(()),
            };
            if let Err(error) = result {
                if let Ok(mut slot) = self.error.lock() {
                    *slot = Some(error);
                }
            }
        }
        if ready && self.kind == "expiry" {
            start() + TimeDelta::milliseconds(300_000)
        } else if ready && self.kind == "delete_control_advanced" {
            start() + TimeDelta::milliseconds(1)
        } else {
            start()
        }
    }
}

#[test]
fn final_release_rejects_swapped_root_gate_and_late_expiry() -> TestResult {
    for kind in ["root", "gate", "expiry"] {
        let fx = Fixture::new()?;
        let clock = Arc::new(LocatorClock {
            root: fx.run_dir()?,
            kind,
            acted: AtomicBool::new(false),
            error: std::sync::Mutex::new(None),
        });
        let service = runtime(fx.root.path(), clock.clone())?
            .with_normal_chat_egress_grant(fx.authority.clone());
        assert!(
            service
                .open_normal_chat_session("conversation:fixture")
                .is_err(),
            "{kind}"
        );
        assert!(
            clock.acted.load(Ordering::SeqCst),
            "{kind} did not reach the final-release window"
        );
        let mutation_error = clock
            .error
            .lock()
            .map_err(|_| "clock error lock poisoned")?
            .take();
        if let Some(error) = mutation_error {
            return Err(error.into());
        }
    }
    Ok(())
}

#[test]
fn disappearing_control_is_never_recreated_at_reopen_or_final_release() -> TestResult {
    for preexisting in [false, true] {
        for kind in ["delete_control", "delete_control_advanced"] {
            let fx = Fixture::new()?;
            if preexisting {
                fx.service()?
                    .open_normal_chat_session("conversation:fixture")?;
            }
            let clock = Arc::new(LocatorClock {
                root: fx.run_dir()?,
                kind,
                acted: AtomicBool::new(false),
                error: std::sync::Mutex::new(None),
            });
            let service = runtime(fx.root.path(), clock.clone())?
                .with_normal_chat_egress_grant(fx.authority.clone());
            let result = service.open_normal_chat_session("conversation:fixture");
            assert!(clock.acted.load(Ordering::SeqCst));
            let mutation_error = clock.error.lock().map_err(|_| "clock poisoned")?.take();
            if let Some(error) = mutation_error {
                return Err(error.into());
            }
            assert!(
                result.is_err(),
                "missing authority was accepted: {preexisting}/{kind}"
            );
            let permits = DurablePermitStore::from_run_root_fd(&File::open(fx.run_dir()?)?)?;
            assert!(
                permits.read_normal_chat_session_control_record()?.is_none(),
                "replacement authority was written: {preexisting}/{kind}"
            );
        }
    }
    Ok(())
}

#[test]
fn revoked_family_cannot_be_projected_as_empty_open_admission() -> TestResult {
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
    let family =
        recursive_agent_policy::FamilyAuthorityStore::from_dir_fd(&root, control.family_grant())?;
    family.revoke_parent(start())?;
    let family_before = fs::read(opened.run_dir().join("family-authority.json"))?;
    let receipts_before = fs::read(opened.run_dir().join("receipts.ndjson"))?;
    assert!(fx
        .service()?
        .open_normal_chat_session("conversation:fixture")
        .is_err());
    assert_eq!(
        fs::read(opened.run_dir().join("family-authority.json"))?,
        family_before
    );
    assert_eq!(
        fs::read(opened.run_dir().join("receipts.ndjson"))?,
        receipts_before
    );
    Ok(())
}

fn extra_receipt(
    opened: &recursive_agent_runner::RuntimeNormalChatSessionV1,
    predecessor: recursive_agent_contracts::ContentDigest,
) -> Result<ReceiptV1, Box<dyn std::error::Error>> {
    let permits = DurablePermitStore::from_run_root_fd(&File::open(opened.run_dir())?)?;
    let record = permits
        .read_normal_chat_session_control_record()?
        .ok_or("control absent")?;
    let call = ToolCallSpecV1 {
        tool: "test.pending".into(),
        args: json!({}),
        frozen_clock: None,
    };
    Ok(make_receipt(
        ReceiptDraftV1 {
            run_id: opened.run_id().clone(),
            step_id: derive_step_id(opened.run_id(), 1, "pending", &call)?,
            kind: ReceiptKindV1::StepStarted,
            valid_time: start(),
            lineage: build_lineage(
                &record.permit.permit_id,
                &record.permit.binding.policy_version,
            ),
            spec_digest: content_digest(&call)?,
            args_digest: content_digest(&call.args)?,
            artifact_refs: vec![],
            outcome: ReceiptOutcomeV1::Ok,
        },
        predecessor,
    )?)
}

#[test]
fn ledger_sync_recovers_complete_append_ack_without_a_duplicate_receipt() -> TestResult {
    let fx = Fixture::new()?;
    let opened = fx
        .service()?
        .open_normal_chat_session("conversation:fixture")?;
    let mut chain = open(&RunPaths::new(opened.run_dir()))?;
    let receipt = extra_receipt(&opened, chain.head().clone())?;
    assert!(chain
        .append_with_interruption(receipt, Some(AppendStage::FullReceiptAppend))
        .is_err());
    assert_eq!(chain.length(), 3);
    let before = fs::read(opened.run_dir().join("receipts.ndjson"))?;
    chain.sync_all()?;
    assert_eq!(chain.length(), 4);
    assert_eq!(fs::read(opened.run_dir().join("receipts.ndjson"))?, before);
    assert_eq!(
        appendable_snapshot_expected_run_from_dir_fd(
            &File::open(opened.run_dir())?,
            opened.run_id()
        )?
        .verification()
        .final_head,
        chain.head().to_string()
    );
    Ok(())
}

#[test]
fn ledger_sync_rejects_truncated_or_self_consistently_changed_retained_prefix() -> TestResult {
    for altered in [false, true] {
        let fx = Fixture::new()?;
        let opened = fx
            .service()?
            .open_normal_chat_session("conversation:fixture")?;
        let mut chain = open(&RunPaths::new(opened.run_dir()))?;
        let old_head = chain.head().clone();
        let snapshot = appendable_snapshot_expected_run_from_dir_fd(
            &File::open(opened.run_dir())?,
            opened.run_id(),
        )?;
        let mut bytes = Vec::new();
        let mut predecessor = snapshot
            .receipts()
            .first()
            .ok_or("run start absent")?
            .prev_chain_digest
            .clone();
        let limit = if altered { 3 } else { 2 };
        for (index, old) in snapshot.receipts().iter().take(limit).enumerate() {
            let mut row = make_receipt(
                ReceiptDraftV1 {
                    run_id: old.run_id.clone(),
                    step_id: old.step_id.clone(),
                    kind: old.kind.clone(),
                    valid_time: old.valid_time
                        + if altered && index == 0 {
                            TimeDelta::milliseconds(1)
                        } else {
                            TimeDelta::zero()
                        },
                    lineage: old.lineage.clone(),
                    spec_digest: old.spec_digest.clone(),
                    args_digest: old.args_digest.clone(),
                    artifact_refs: old.artifact_refs.clone(),
                    outcome: old.outcome.clone(),
                },
                predecessor,
            )?;
            row.recorded_time = old.recorded_time;
            let canonical = row.canonical_bytes()?;
            predecessor =
                recursive_agent_ledger::chain_digest_from_raw(&row.prev_chain_digest, &canonical)?;
            bytes.extend(canonical);
            bytes.push(b'\n');
        }
        fs::write(opened.run_dir().join("receipts.ndjson"), bytes)?;
        assert!(chain.sync_all().is_err());
        assert_eq!(chain.head(), &old_head);
    }
    Ok(())
}

#[test]
fn child_bootstrap_process() -> TestResult {
    let Ok(root) = std::env::var("GMC_BOOTSTRAP_TEST_ROOT") else {
        return Ok(());
    };
    let grant_root = std::env::var("GMC_BOOTSTRAP_TEST_GRANT")?;
    let grant_root = std::path::PathBuf::from(grant_root);
    let authority = NormalChatEgressGrantStore::from_dir_fd(&File::open(&grant_root)?)?
        .load_from_path(&grant_root.join("grant.json"), HOME, start())?;
    let service = runtime(Path::new(&root), Arc::new(TestClock::default()))?
        .with_normal_chat_egress_grant(authority);
    match service.open_normal_chat_session("conversation:fixture") {
        Ok(opened) => println!("GMC_BOOTSTRAP_RESULT:{}", opened.verified_prefix_head()),
        Err(RuntimeServiceError::NormalChatSessionBusy) => println!("GMC_BOOTSTRAP_RESULT:busy"),
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[test]
fn independent_processes_share_one_session_gate_and_canonical_prefix() -> TestResult {
    let fx = Fixture::new()?;
    let mut children = Vec::new();
    for _ in 0..2 {
        children.push(
            std::process::Command::new(std::env::current_exe()?)
                .args(["--exact", "hostile::child_bootstrap_process", "--nocapture"])
                .env("GMC_BOOTSTRAP_TEST_ROOT", fx.root.path())
                .env("GMC_BOOTSTRAP_TEST_GRANT", fx._grant_root.path())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()?,
        );
    }
    let mut heads = Vec::new();
    for child in children {
        let output = child.wait_with_output()?;
        assert!(
            output.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout)?;
        let markers = text
            .lines()
            .filter_map(|line| line.strip_prefix("GMC_BOOTSTRAP_RESULT:"))
            .collect::<Vec<_>>();
        assert_eq!(markers.len(), 1, "child did not exercise bootstrap: {text}");
        if markers[0] != "busy" {
            heads.push(markers[0].to_owned());
        }
    }
    assert!(!heads.is_empty());
    let reopened = fx
        .service()?
        .open_normal_chat_session("conversation:fixture")?;
    assert!(heads
        .iter()
        .all(|head| head == &reopened.verified_prefix_head().to_string()));
    assert_eq!(
        appendable_snapshot_expected_run_from_dir_fd(
            &File::open(reopened.run_dir())?,
            reopened.run_id()
        )?
        .receipts()
        .len(),
        3
    );
    Ok(())
}
