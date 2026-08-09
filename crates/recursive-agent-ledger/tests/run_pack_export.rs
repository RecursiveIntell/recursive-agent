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

use recursive_agent_contracts::RunPackManifestV1;
use recursive_agent_ledger::{
    export_run_pack, export_run_pack_with_interruption, verify_run_pack, RunPackExportStage,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn export_materializes_a_verified_terminal_run_with_a_canonical_manifest() -> TestResult {
    let root = tempfile::tempdir()?;
    let run = valid_chain_fixture::completed_run(root.path())?;
    let destination = root.path().join("portable-pack");

    let exported = export_run_pack(&run.paths, &destination)?;
    assert!(exported.ok);
    assert_eq!(exported, verify_run_pack(&destination)?);
    let manifest_bytes = std::fs::read(destination.join("PACK_MANIFEST.json"))?;
    let manifest: RunPackManifestV1 = serde_json::from_slice(&manifest_bytes)?;
    assert_eq!(manifest.canonical_bytes()?, manifest_bytes);
    assert!(destination.join("receipts.ndjson").is_file());
    assert!(destination.join("chain.meta").is_file());
    assert!(destination
        .join("artifacts")
        .join(run.descriptor.digest.hex())
        .is_file());
    Ok(())
}

#[test]
fn export_rejects_every_preexisting_destination_and_leaves_it_untouched() -> TestResult {
    let root = tempfile::tempdir()?;
    let run = valid_chain_fixture::completed_run(root.path())?;
    for kind in ["file", "empty-directory", "nonempty-directory"] {
        let destination = root.path().join(format!("preexisting-{kind}"));
        match kind {
            "file" => std::fs::write(&destination, b"keep")?,
            "empty-directory" => std::fs::create_dir(&destination)?,
            "nonempty-directory" => {
                std::fs::create_dir(&destination)?;
                std::fs::write(destination.join("keep"), b"keep")?;
            }
            _ => unreachable!(),
        }
        assert!(export_run_pack(&run.paths, &destination).is_err(), "{kind}");
        assert!(std::fs::symlink_metadata(&destination).is_ok(), "{kind}");
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn export_rejects_existing_and_dangling_destination_symlinks() -> TestResult {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir()?;
    let run = valid_chain_fixture::completed_run(root.path())?;
    for (name, target) in [
        ("destination-symlink", "."),
        ("dangling-symlink", "missing"),
    ] {
        let destination = root.path().join(name);
        symlink(target, &destination)?;
        assert!(export_run_pack(&run.paths, &destination).is_err(), "{name}");
        assert!(std::fs::symlink_metadata(&destination)?
            .file_type()
            .is_symlink());
    }
    let fifo = root.path().join("destination-fifo");
    let status = std::process::Command::new("mkfifo").arg(&fifo).status()?;
    assert!(status.success());
    assert!(export_run_pack(&run.paths, &fifo).is_err());
    Ok(())
}

#[test]
fn source_tampering_rejects_export_without_publishing_a_pack_or_deleting_other_files() -> TestResult
{
    let root = tempfile::tempdir()?;
    let run = valid_chain_fixture::completed_run(root.path())?;
    let destination = root.path().join("pack");
    let sentinel = root.path().join("sentinel");
    std::fs::write(&sentinel, b"do not remove")?;
    std::fs::write(
        run.paths.artifacts_dir().join(run.descriptor.digest.hex()),
        b"changed after completion",
    )?;

    assert!(export_run_pack(&run.paths, &destination).is_err());
    assert!(!destination.exists());
    assert_eq!(std::fs::read(&sentinel)?, b"do not remove");
    assert!(std::fs::read_dir(root.path())?
        .filter_map(Result::ok)
        .all(|entry| !entry
            .file_name()
            .to_string_lossy()
            .starts_with(".run-pack-")));
    Ok(())
}

#[test]
fn interrupted_export_removes_only_its_same_parent_temporary_directory() -> TestResult {
    let root = tempfile::tempdir()?;
    let run = valid_chain_fixture::completed_run(root.path())?;
    let destination = root.path().join("pack");
    let sentinel = root.path().join("sentinel");
    std::fs::write(&sentinel, b"do not remove")?;

    assert!(export_run_pack_with_interruption(
        &run.paths,
        &destination,
        Some(RunPackExportStage::CopyComplete),
    )
    .is_err());
    assert!(!destination.exists());
    assert_eq!(std::fs::read(&sentinel)?, b"do not remove");
    assert!(std::fs::read_dir(root.path())?
        .filter_map(Result::ok)
        .all(|entry| !entry
            .file_name()
            .to_string_lossy()
            .starts_with(".run-pack.")));
    Ok(())
}
