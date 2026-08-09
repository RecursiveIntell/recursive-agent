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

use recursive_agent_contracts::{content_digest, RunPackManifestV1};
use recursive_agent_ledger::{export_run_pack, verify_run_pack};

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
