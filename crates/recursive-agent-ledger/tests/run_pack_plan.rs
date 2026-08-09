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

    pub(super) fn empty_run(root: &std::path::Path) -> FixtureResult<RunPaths> {
        let fixture = fixture()?;
        let run_root =
            root.join(recursive_agent_contracts::content_digest(&fixture.run)?.to_string());
        std::fs::create_dir(&run_root)?;
        let paths = RunPaths::new(run_root);
        paths.ensure()?;
        Ok(paths)
    }
}

use recursive_agent_ledger::plan_run_pack;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn plan_is_strict_deterministic_and_limited_to_canonical_evidence() -> TestResult {
    let root = tempfile::tempdir()?;
    let run = valid_chain_fixture::completed_run(root.path())?;

    let first = plan_run_pack(&run.paths)?;
    let second = plan_run_pack(&run.paths)?;
    assert_eq!(first.source_run_id, second.source_run_id);
    assert_eq!(first.files, second.files);
    assert!(first
        .files
        .windows(2)
        .all(|pair| pair[0].path < pair[1].path));
    assert!(first
        .files
        .iter()
        .any(|entry| entry.path == "receipts.ndjson" && entry.role == "receipts"));
    assert!(first
        .files
        .iter()
        .any(|entry| entry.path == "chain.meta" && entry.role == "chain-meta"));
    assert!(first.files.iter().any(|entry| {
        entry.path == format!("artifacts/{}", run.descriptor.digest.hex())
            && entry.role == "artifact"
    }));
    assert!(first.files.iter().any(|entry| {
        entry.path == format!("artifacts/{}.meta", run.descriptor.digest.hex())
            && entry.role == "artifact-descriptor"
    }));
    assert!(first
        .files
        .iter()
        .all(|entry| !entry.path.contains("permit.lock") && !entry.path.contains("..")));
    first.manifest().validate()?;
    Ok(())
}

#[test]
fn plan_rejects_unverified_or_tampered_source_evidence() -> TestResult {
    let root = tempfile::tempdir()?;
    let empty_root = root.path().join("empty");
    std::fs::create_dir(&empty_root)?;
    let empty = valid_chain_fixture::empty_run(&empty_root)?;
    assert!(plan_run_pack(&empty).is_err());

    let completed_root = root.path().join("completed");
    std::fs::create_dir(&completed_root)?;
    let run = valid_chain_fixture::completed_run(&completed_root)?;
    std::fs::write(
        run.paths.artifacts_dir().join(run.descriptor.digest.hex()),
        b"tampered evidence",
    )?;
    assert!(plan_run_pack(&run.paths).is_err());
    Ok(())
}
