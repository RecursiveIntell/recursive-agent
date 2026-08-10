mod valid_chain_fixture {
    include!("artifact_tamper.rs");

    type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;

    pub(super) fn completed_run(
        root: &std::path::Path,
    ) -> FixtureResult<recursive_agent_ledger::RunPaths> {
        let fixture = fixture()?;
        let run_root =
            root.join(recursive_agent_contracts::content_digest(&fixture.run)?.to_string());
        std::fs::create_dir(&run_root)?;
        let paths = recursive_agent_ledger::RunPaths::new(run_root);
        let store = artifact_store(&paths)?;
        let descriptor = store.put(b"evidence", "text/plain", Some("utf-8".into()))?;
        complete_chain(&paths, descriptor)?;
        Ok(paths)
    }
}

use recursive_agent_ledger::{export_run_pack, verify_run_pack};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn provenance_documents_are_canonical_manifest_bound_and_descriptive_only() -> TestResult {
    let root = tempfile::tempdir()?;
    let run = valid_chain_fixture::completed_run(root.path())?;
    let pack = root.path().join("pack");
    export_run_pack(&run, &pack)?;

    for name in [
        "OPERATOR_REPORT.json",
        "SOURCE_PROVENANCE.json",
        "TOOLCHAIN.json",
    ] {
        let bytes = std::fs::read(pack.join(name))?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(recursive_agent_contracts::jcs_canonical(&value)?, bytes);
    }
    let provenance: serde_json::Value =
        serde_json::from_slice(&std::fs::read(pack.join("SOURCE_PROVENANCE.json"))?)?;
    assert_eq!(provenance["source_verification_outcome"], "verified");
    assert_eq!(provenance["source_verification_ref"], "chain.meta");
    assert!(provenance["source_commit"].is_string());
    assert!(provenance["source_diff_state"].is_string());
    assert!(provenance["rust_version"].is_string());
    assert!(provenance["cargo_version"].is_string());
    assert!(provenance["command_argv"].is_array());
    assert!(provenance["timestamp_classification"].is_string());
    assert!(verify_run_pack(&pack)?.ok);
    Ok(())
}

#[test]
fn provenance_or_operator_report_tampering_cannot_override_verified_evidence() -> TestResult {
    for name in [
        "OPERATOR_REPORT.json",
        "SOURCE_PROVENANCE.json",
        "TOOLCHAIN.json",
    ] {
        let root = tempfile::tempdir()?;
        let run = valid_chain_fixture::completed_run(root.path())?;
        let pack = root.path().join("pack");
        export_run_pack(&run, &pack)?;
        std::fs::write(
            pack.join(name),
            br#"{"terminal_classification":"succeeded","verification_outcome":"verified"}"#,
        )?;
        assert!(
            verify_run_pack(&pack).is_err(),
            "{name} must be manifest-bound"
        );
    }
    Ok(())
}
