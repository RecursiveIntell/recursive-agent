use chrono::{DateTime, Utc};
use recursive_agent_contracts::{
    content_digest, derive_permit_id, derive_run_id, derive_step_id, AuthorityLineageEntryV1,
    CurrentRunId, CurrentStepId, LineageOrigin, PermitIdentityMaterialV1, ReceiptKindV1,
    ReceiptOutcomeV1, RunSpecV1, StepSpecV1, ToolCallSpecV1,
};
use recursive_agent_ledger::{
    chain_digest_from_raw, inspect_legacy_integrity, make_receipt, open, AppendStage, RunPaths,
};
use std::io::Write;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Clone)]
struct Fixture {
    run: CurrentRunId,
    step: CurrentStepId,
    time: DateTime<Utc>,
    lineage: Vec<AuthorityLineageEntryV1>,
}

fn fixture() -> TestResultValue<Fixture> {
    let time = DateTime::from_timestamp(1_700_000_000, 0).ok_or("fixed time is invalid")?;
    let call = ToolCallSpecV1 {
        tool: "echo".into(),
        args: serde_json::json!({"text": "x"}),
        frozen_clock: Some(time),
    };
    let spec = RunSpecV1 {
        name: "ledger".into(),
        steps: vec![StepSpecV1 {
            name: "step".into(),
            call: call.clone(),
        }],
        frozen_clock: Some(time),
        policy_version: "policy-v1".into(),
    };
    let run = derive_run_id(&spec)?;
    let step = derive_step_id(&run, 1, "lifecycle", &call)?;
    let permit = derive_permit_id(&PermitIdentityMaterialV1 {
        binding_digest: content_digest(&"ledger-fixture")?,
        requested_not_before_delay_ms: 0,
        requested_validity_ms: 1_000,
    })?;
    let lineage = [
        LineageOrigin::Request,
        LineageOrigin::Plan,
        LineageOrigin::Policy,
        LineageOrigin::Tool,
        LineageOrigin::Effect,
    ]
    .into_iter()
    .map(|origin| AuthorityLineageEntryV1 {
        origin,
        principal: "test".into(),
        permit_id: Some(permit.clone()),
        policy_version: "policy-v1".into(),
    })
    .collect();
    Ok(Fixture {
        run,
        step,
        time,
        lineage,
    })
}

type TestResultValue<T> = Result<T, Box<dyn std::error::Error>>;

fn receipt(
    fixture: &Fixture,
    kind: ReceiptKindV1,
    outcome: ReceiptOutcomeV1,
    head: recursive_agent_contracts::ContentDigest,
) -> TestResultValue<recursive_agent_contracts::ReceiptV1> {
    Ok(make_receipt(
        recursive_agent_ledger::ReceiptDraftV1 {
            run_id: fixture.run.clone(),
            step_id: fixture.step.clone(),
            kind,
            valid_time: fixture.time,
            lineage: fixture.lineage.clone(),
            spec_digest: content_digest(&serde_json::json!({"spec": 1}))?,
            args_digest: content_digest(&serde_json::json!({"args": 1}))?,
            artifact_refs: vec![],
            outcome,
        },
        head,
    )?)
}

#[test]
fn missing_newline_is_finalized_and_incomplete_tail_is_truncated() -> TestResult {
    let root = tempfile::tempdir()?;
    let paths = RunPaths::new(root.path());
    let fixture = fixture()?;
    let mut chain = open(&paths)?;
    chain.append(receipt(
        &fixture,
        ReceiptKindV1::RunStarted,
        ReceiptOutcomeV1::Ok,
        chain.head().clone(),
    )?)?;
    let bytes = std::fs::read(paths.receipts_path())?;
    std::fs::write(paths.receipts_path(), &bytes[..bytes.len() - 1])?;
    let reopened = open(&paths)?;
    assert_eq!(reopened.length(), 1);
    assert_eq!(std::fs::read(paths.receipts_path())?.last(), Some(&b'\n'));

    let mut log = std::fs::OpenOptions::new()
        .append(true)
        .open(paths.receipts_path())?;
    log.write_all(br#"{"receipt_id":"#)?;
    log.sync_all()?;
    let recovered = open(&paths)?;
    assert_eq!(recovered.length(), 1);
    Ok(())
}

#[test]
fn ambiguous_tail_is_rejected_without_deleting_valid_receipt() -> TestResult {
    let root = tempfile::tempdir()?;
    let paths = RunPaths::new(root.path());
    let fixture = fixture()?;
    let mut chain = open(&paths)?;
    chain.append(receipt(
        &fixture,
        ReceiptKindV1::RunStarted,
        ReceiptOutcomeV1::Ok,
        chain.head().clone(),
    )?)?;
    let durable_len = std::fs::metadata(paths.receipts_path())?.len();
    let mut log = std::fs::OpenOptions::new()
        .append(true)
        .open(paths.receipts_path())?;
    log.write_all(b"not-json")?;
    log.sync_all()?;
    assert!(open(&paths).is_err());
    assert!(std::fs::metadata(paths.receipts_path())?.len() > durable_len);
    Ok(())
}

#[test]
fn append_failpoints_reopen_to_previous_or_new_chain() -> TestResult {
    for stage in [
        AppendStage::PartialRecord,
        AppendStage::FullReceiptAppend,
        AppendStage::LogFsync,
        AppendStage::MetadataTempWrite,
        AppendStage::MetadataFsync,
        AppendStage::MetadataRename,
        AppendStage::DirectoryFsync,
    ] {
        let root = tempfile::tempdir()?;
        let paths = RunPaths::new(root.path());
        let fixture = fixture()?;
        let mut chain = open(&paths)?;
        let candidate = receipt(
            &fixture,
            ReceiptKindV1::RunStarted,
            ReceiptOutcomeV1::Ok,
            chain.head().clone(),
        )?;
        let _ = chain.append_with_interruption(candidate, Some(stage));
        let direct = inspect_legacy_integrity(&paths)?;
        assert!(
            matches!(direct.length, 0 | 1),
            "direct verification failed at {stage:?}"
        );
        let reopened = open(&paths)?;
        assert!(matches!(reopened.length(), 0 | 1), "stage {stage:?}");
        let report = inspect_legacy_integrity(&paths)?;
        assert!(matches!(report.length, 0 | 1));
    }
    Ok(())
}

#[test]
fn two_handles_cannot_fork_the_predecessor() -> TestResult {
    let root = tempfile::tempdir()?;
    let paths = RunPaths::new(root.path());
    let fixture = fixture()?;
    let mut left = open(&paths)?;
    let mut right = open(&paths)?;
    let left_receipt = receipt(
        &fixture,
        ReceiptKindV1::RunStarted,
        ReceiptOutcomeV1::Ok,
        left.head().clone(),
    )?;
    let right_receipt = left_receipt.clone();
    let left_thread = std::thread::spawn(move || left.append(left_receipt));
    let right_thread = std::thread::spawn(move || right.append(right_receipt));
    let results = [
        left_thread
            .join()
            .map_err(|_| "left append thread panicked")?,
        right_thread
            .join()
            .map_err(|_| "right append thread panicked")?,
    ];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(open(&paths)?.length(), 1);
    Ok(())
}

#[cfg(unix)]
#[test]
fn run_root_is_pinned_and_intermediate_symlinks_are_rejected() -> TestResult {
    use std::os::unix::fs::symlink;

    let parent = tempfile::tempdir()?;
    let root = parent.path().join("run");
    let pinned = parent.path().join("pinned");
    let attacker = parent.path().join("attacker");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(&attacker)?;
    let paths = RunPaths::new(&root);
    let fixture = fixture()?;
    let mut chain = open(&paths)?;
    std::fs::rename(&root, &pinned)?;
    symlink(&attacker, &root)?;
    chain.append(receipt(
        &fixture,
        ReceiptKindV1::RunStarted,
        ReceiptOutcomeV1::Ok,
        chain.head().clone(),
    )?)?;
    assert_eq!(open(&RunPaths::new(&pinned))?.length(), 1);
    assert_eq!(std::fs::read_dir(&attacker)?.count(), 0);
    assert!(open(&paths).is_err());

    let real_parent = parent.path().join("real-parent");
    let linked_parent = parent.path().join("linked-parent");
    std::fs::create_dir(&real_parent)?;
    symlink(&real_parent, &linked_parent)?;
    assert!(open(&RunPaths::new(linked_parent.join("nested"))).is_err());
    assert_eq!(std::fs::read_dir(&real_parent)?.count(), 0);
    Ok(())
}

#[test]
fn raw_predecessor_chain_vector_is_fixed() -> TestResult {
    let predecessor = recursive_agent_contracts::ContentDigest::from_hex("00".repeat(32))?;
    let digest = chain_digest_from_raw(&predecessor, br#"{"a":1}"#)?;
    assert_eq!(
        digest.hex(),
        "7e94084bce94902db91a1fcd90448c118e748e57c8c812348e09af0d03830054"
    );
    Ok(())
}

#[test]
fn process_kill_failpoint_matrix_recovers_previous_or_new_chain() -> TestResult {
    if let Some(root) = std::env::var_os("RA_LEDGER_KILL_ROOT") {
        let paths = RunPaths::new(std::path::PathBuf::from(root));
        let stage = std::env::var("RA_LEDGER_KILL_STAGE")?;
        if stage == "artifact_write" {
            let store = open(&paths)?.artifact_store()?;
            let _ = store.put(b"orphan", "application/octet-stream", None)?;
            std::process::abort();
        }
        let stage = match stage.as_str() {
            "partial_record" => AppendStage::PartialRecord,
            "full_receipt_append" => AppendStage::FullReceiptAppend,
            "log_fsync" => AppendStage::LogFsync,
            "metadata_temp_write" => AppendStage::MetadataTempWrite,
            "metadata_fsync" => AppendStage::MetadataFsync,
            "metadata_rename" => AppendStage::MetadataRename,
            "directory_fsync" => AppendStage::DirectoryFsync,
            _ => return Err("unknown kill stage".into()),
        };
        let fixture = fixture()?;
        let mut chain = open(&paths)?;
        let candidate = receipt(
            &fixture,
            ReceiptKindV1::RunStarted,
            ReceiptOutcomeV1::Ok,
            chain.head().clone(),
        )?;
        let _ = chain.append_with_interruption(candidate, Some(stage));
        std::process::abort();
    }

    let executable = std::env::current_exe()?;
    for stage in [
        "artifact_write",
        "partial_record",
        "full_receipt_append",
        "log_fsync",
        "metadata_temp_write",
        "metadata_fsync",
        "metadata_rename",
        "directory_fsync",
    ] {
        let root = tempfile::tempdir()?;
        let output = std::process::Command::new(&executable)
            .args([
                "--exact",
                "process_kill_failpoint_matrix_recovers_previous_or_new_chain",
                "--nocapture",
            ])
            .env("RA_LEDGER_KILL_ROOT", root.path())
            .env("RA_LEDGER_KILL_STAGE", stage)
            .output()?;
        assert!(!output.status.success(), "stage {stage} did not terminate");
        let paths = RunPaths::new(root.path());
        assert!(
            matches!(inspect_legacy_integrity(&paths)?.length, 0 | 1),
            "direct verification failed before reopen at {stage}"
        );
        let reopened = open(&paths)?;
        assert!(matches!(reopened.length(), 0 | 1), "stage {stage}");
        assert!(matches!(inspect_legacy_integrity(&paths)?.length, 0 | 1));
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn root_and_legacy_lock_entry_replacement_cannot_split_pinned_handles() -> TestResult {
    let parent = tempfile::tempdir()?;
    let root = parent.path().join("run");
    let pinned = parent.path().join("pinned-run");
    std::fs::create_dir(&root)?;
    let paths = RunPaths::new(&root);
    let fixture = fixture()?;
    let mut left = open(&paths)?;
    let mut right = open(&paths)?;
    std::fs::rename(&root, &pinned)?;
    std::fs::create_dir(&root)?;
    std::fs::write(root.join(".ledger.lock"), b"replaceable decoy")?;
    let left_receipt = receipt(
        &fixture,
        ReceiptKindV1::RunStarted,
        ReceiptOutcomeV1::Ok,
        left.head().clone(),
    )?;
    let right_receipt = left_receipt.clone();
    let left_thread = std::thread::spawn(move || left.append(left_receipt));
    let right_thread = std::thread::spawn(move || right.append(right_receipt));
    let results = [
        left_thread.join().map_err(|_| "left thread panicked")?,
        right_thread.join().map_err(|_| "right thread panicked")?,
    ];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let pinned_paths = RunPaths::new(&pinned);
    assert_eq!(open(&pinned_paths)?.length(), 1);
    assert!(!root.join("receipts.ndjson").exists());
    Ok(())
}

#[test]
fn two_process_append_race_has_one_predecessor_owner() -> TestResult {
    if let Some(root) = std::env::var_os("RA_LEDGER_RACE_ROOT") {
        let root = std::path::PathBuf::from(root);
        let slot = std::env::var("RA_LEDGER_RACE_SLOT")?;
        let paths = RunPaths::new(&root);
        let fixture = fixture()?;
        let mut chain = open(&paths)?;
        let candidate = receipt(
            &fixture,
            ReceiptKindV1::RunStarted,
            ReceiptOutcomeV1::Ok,
            chain.head().clone(),
        )?;
        std::fs::write(root.join(format!("ready-{slot}")), b"ready")?;
        let go = root.join("go");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !go.exists() {
            if std::time::Instant::now() >= deadline {
                return Err("race barrier timed out".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        chain.append(candidate)?;
        return Ok(());
    }

    let root = tempfile::tempdir()?;
    let executable = std::env::current_exe()?;
    let mut children = Vec::new();
    for slot in ["left", "right"] {
        children.push(
            std::process::Command::new(&executable)
                .args([
                    "--exact",
                    "two_process_append_race_has_one_predecessor_owner",
                    "--nocapture",
                ])
                .env("RA_LEDGER_RACE_ROOT", root.path())
                .env("RA_LEDGER_RACE_SLOT", slot)
                .spawn()?,
        );
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !(root.path().join("ready-left").exists() && root.path().join("ready-right").exists()) {
        if std::time::Instant::now() >= deadline {
            return Err("children did not reach race barrier".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    std::fs::write(root.path().join("go"), b"go")?;
    let mut success = 0;
    for mut child in children {
        if child.wait()?.success() {
            success += 1;
        }
    }
    assert_eq!(success, 1);
    assert_eq!(open(&RunPaths::new(root.path()))?.length(), 1);
    Ok(())
}
