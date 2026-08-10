mod valid_chain_fixture {
    include!("artifact_tamper.rs");

    type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;

    pub(super) struct CompletedRun {
        pub paths: RunPaths,
        pub descriptor: ArtifactDescriptorV1,
    }

    pub(super) fn completed_run(root: &std::path::Path) -> FixtureResult<CompletedRun> {
        let fixture = fixture()?;
        let run_root =
            root.join(recursive_agent_contracts::content_digest(&fixture.run)?.to_string());
        std::fs::create_dir(&run_root)?;
        let paths = RunPaths::new(run_root);
        let store = artifact_store(&paths)?;
        let descriptor = store.put(b"evidence", "text/plain", Some("utf-8".into()))?;
        complete_chain(&paths, descriptor.clone())?;
        Ok(CompletedRun { paths, descriptor })
    }
}

use recursive_agent_contracts::{content_digest, RunPackManifestV1, RunPackProjectionOriginV1};
use recursive_agent_ledger::{export_run_pack, verify_run_pack, PackVault};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn exported_pack() -> Result<
    (
        tempfile::TempDir,
        valid_chain_fixture::CompletedRun,
        std::path::PathBuf,
    ),
    Box<dyn std::error::Error>,
> {
    let root = tempfile::tempdir()?;
    let run = valid_chain_fixture::completed_run(root.path())?;
    let pack = root.path().join("pack");
    export_run_pack(&run.paths, &pack)?;
    Ok((root, run, pack))
}

fn rewrite_manifest(
    pack: &std::path::Path,
    mutate: impl FnOnce(&mut RunPackManifestV1) -> TestResult,
) -> TestResult {
    let path = pack.join("PACK_MANIFEST.json");
    let mut manifest: RunPackManifestV1 = serde_json::from_slice(&std::fs::read(&path)?)?;
    mutate(&mut manifest)?;
    std::fs::write(path, recursive_agent_contracts::jcs_canonical(&manifest)?)?;
    Ok(())
}

fn copy_pack(source: &std::path::Path, destination: &std::path::Path) -> TestResult {
    std::fs::create_dir(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_pack(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            std::fs::copy(source_path, destination_path)?;
        } else {
            return Err("exported pack unexpectedly contains a non-regular entry".into());
        }
    }
    Ok(())
}

#[test]
fn copied_pack_verifies_when_its_original_run_is_unavailable() -> TestResult {
    let (_root, run, pack) = exported_pack()?;
    let fresh = tempfile::tempdir()?;
    let copied = fresh.path().join("only-pack");
    copy_pack(&pack, &copied)?;
    std::fs::remove_dir_all(&run.paths.root)?;

    assert!(verify_run_pack(&copied)?.ok);
    Ok(())
}

#[test]
fn verified_admission_builds_projection_from_pack_evidence_only() -> TestResult {
    let (_root, _run, pack) = exported_pack()?;
    let vault_root = tempfile::tempdir()?;
    let vault = PackVault::new(vault_root.path())?;
    let admission = vault.admit(&pack)?;
    let time = "2026-08-10T00:00:00Z".parse()?;
    let projection = admission.build_evidence_projection(RunPackProjectionOriginV1 {
        operator_adapter: "hermes-native".into(),
        source_device_ref: None,
        observed_at: Some(time),
        recorded_at: time,
    })?;
    let snapshot = vault.verify(admission.object_id())?;
    assert_eq!(
        projection.run_id,
        snapshot
            .verification()
            .verified_run_id
            .clone()
            .ok_or("missing run")?
    );
    assert_eq!(
        projection.pack_manifest_digest,
        snapshot.pack_verification().manifest_digest
    );
    projection.validate()?;
    Ok(())
}

#[test]
fn verifier_rejects_manifest_receipt_chain_metadata_and_artifact_tampering() -> TestResult {
    for kind in ["manifest", "receipt", "chain-meta", "artifact"] {
        let (_root, run, pack) = exported_pack()?;
        match kind {
            "manifest" => std::fs::write(pack.join("PACK_MANIFEST.json"), b"{}")?,
            "receipt" => std::fs::write(pack.join("receipts.ndjson"), b"tampered\n")?,
            "chain-meta" => std::fs::write(pack.join("chain.meta"), b"tampered")?,
            "artifact" => std::fs::write(
                pack.join("artifacts").join(run.descriptor.digest.hex()),
                b"tampered artifact",
            )?,
            _ => unreachable!(),
        }
        assert!(verify_run_pack(&pack).is_err(), "{kind}");
    }
    Ok(())
}

#[test]
fn verifier_rejects_missing_extra_and_hostile_manifest_paths() -> TestResult {
    let (_root, _run, pack) = exported_pack()?;
    std::fs::remove_file(pack.join("receipts.ndjson"))?;
    assert!(verify_run_pack(&pack).is_err());

    let (_root, _run, pack) = exported_pack()?;
    std::fs::write(pack.join("unexpected"), b"extra")?;
    assert!(verify_run_pack(&pack).is_err());

    for path in ["../escape", "/absolute", "artifacts\\backslash"] {
        let (_root, _run, pack) = exported_pack()?;
        rewrite_manifest(&pack, |manifest| {
            manifest.files[0].path = path.into();
            Ok(())
        })?;
        assert!(verify_run_pack(&pack).is_err(), "{path}");
    }

    let (_root, _run, pack) = exported_pack()?;
    rewrite_manifest(&pack, |manifest| {
        manifest.files.push(manifest.files[0].clone());
        Ok(())
    })?;
    assert!(verify_run_pack(&pack).is_err());
    Ok(())
}

#[test]
fn verifier_rejects_chain_metadata_rebound_by_a_tampered_manifest() -> TestResult {
    let (_root, _run, pack) = exported_pack()?;
    let chain_meta = pack.join("chain.meta");
    let mut metadata: serde_json::Value = serde_json::from_slice(&std::fs::read(&chain_meta)?)?;
    metadata["created_at"] = serde_json::Value::String("2025-01-01T00:00:00Z".into());
    let changed = recursive_agent_contracts::jcs_canonical(&metadata)?;
    std::fs::write(&chain_meta, &changed)?;
    rewrite_manifest(&pack, |manifest| {
        let entry = manifest
            .files
            .iter_mut()
            .find(|entry| entry.path == "chain.meta")
            .ok_or("chain meta entry is absent")?;
        entry.byte_length = changed.len() as u64;
        entry.digest = content_digest(&changed)?;
        Ok(())
    })?;

    assert!(verify_run_pack(&pack).is_err());
    Ok(())
}

#[test]
fn pack_vault_admits_then_verifies_after_source_is_deleted() -> TestResult {
    let (_root, run, pack) = exported_pack()?;
    let vault_root = tempfile::tempdir()?;
    let vault = PackVault::new(vault_root.path())?;
    let admitted = vault.admit(&pack)?;
    let retried = vault.admit(&pack)?;
    assert_eq!(retried.object_id(), admitted.object_id());
    std::fs::remove_dir_all(&run.paths.root)?;
    let reopened = PackVault::new(vault_root.path())?;
    let recovered = reopened.admission(admitted.object_id())?;
    assert_eq!(recovered.recorded_at(), admitted.recorded_at());
    let snapshot = reopened.verify(admitted.object_id())?;
    assert!(snapshot.pack_verification().ok);
    assert_eq!(vault.get(admitted.object_id())?, admitted.path());
    Ok(())
}

#[test]
fn pack_vault_quarantines_tampering_and_rejects_escape() -> TestResult {
    let (_root, _run, pack) = exported_pack()?;
    let vault_root = tempfile::tempdir()?;
    let vault = PackVault::new(vault_root.path())?;
    let admitted = vault.admit(&pack)?;
    std::fs::write(admitted.path().join("receipts.ndjson"), b"tampered\\n")?;
    assert!(vault.verify(admitted.object_id()).is_err());
    assert!(vault.quarantine(admitted.object_id())?.exists());
    assert!(PackVault::validate_relative_ref("../escape").is_err());
    Ok(())
}

#[test]
fn pack_vault_persists_distinct_server_admission_facts() -> TestResult {
    let (_root, _run, pack) = exported_pack()?;
    let vault_root = tempfile::tempdir()?;
    let vault = PackVault::new(vault_root.path())?;
    let admission = vault.admit(&pack)?;

    assert_ne!(
        admission.object_id(),
        admission.manifest_digest().to_string()
    );
    let receipt_path = vault_root
        .path()
        .join("admissions")
        .join(format!("{}.json", admission.object_id()));
    let receipts = std::fs::read_to_string(receipt_path)?;
    let receipt: serde_json::Value = serde_json::from_str(receipts.trim())?;
    assert_ne!(
        receipt["source_pack_digest"], receipt["final_manifest_digest"],
        "source input identity must not alias the manifest identity"
    );
    assert_eq!(receipt["object_id"], admission.object_id());

    let forged_time = "2000-01-01T00:00:00Z".parse()?;
    let projection = admission.build_evidence_projection(RunPackProjectionOriginV1 {
        operator_adapter: "hermes-native".into(),
        source_device_ref: None,
        observed_at: Some(forged_time),
        recorded_at: forged_time,
    })?;
    assert_eq!(projection.origin.recorded_at, admission.recorded_at());
    assert_eq!(
        projection.vault.relative_ref,
        format!("objects/{}", admission.object_id())
    );
    Ok(())
}

#[test]
fn pack_vault_rejects_invalid_candidate_without_publication() -> TestResult {
    let (_root, _run, pack) = exported_pack()?;
    std::fs::write(pack.join("receipts.ndjson"), b"tampered\\n")?;
    let vault_root = tempfile::tempdir()?;
    let vault = PackVault::new(vault_root.path())?;
    assert!(vault.admit(&pack).is_err());
    assert!(vault.object_ids()?.is_empty());
    assert!(!vault_root.path().join("admissions.ndjson").exists());
    Ok(())
}

#[test]
fn pack_vault_interrupted_staging_is_not_published() -> TestResult {
    let (_root, _run, pack) = exported_pack()?;
    let vault_root = tempfile::tempdir()?;
    let vault = PackVault::new(vault_root.path())?;
    assert!(vault.admit_with_interruption(&pack)?.is_err());
    assert!(vault.object_ids()?.is_empty());
    Ok(())
}

#[cfg(unix)]
#[test]
fn verifier_rejects_symlink_and_fifo_entries_without_following_them() -> TestResult {
    use std::os::unix::fs::symlink;

    let (_root, _run, pack) = exported_pack()?;
    let receipt = pack.join("receipts.ndjson");
    std::fs::remove_file(&receipt)?;
    symlink("/etc/passwd", &receipt)?;
    assert!(verify_run_pack(&pack).is_err());

    let (_root, run, pack) = exported_pack()?;
    let artifact = pack.join("artifacts").join(run.descriptor.digest.hex());
    std::fs::remove_file(&artifact)?;
    let status = std::process::Command::new("mkfifo")
        .arg(&artifact)
        .status()?;
    assert!(status.success());
    assert!(verify_run_pack(&pack).is_err());
    Ok(())
}
