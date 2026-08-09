use recursive_agent_contracts::{
    content_digest, derive_run_id, jcs_canonical, CurrentRunId, RunPackFileEntryV1,
    RunPackManifestV1, RunSpecV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn run_id() -> Result<CurrentRunId, recursive_agent_contracts::ContractError> {
    derive_run_id(&RunSpecV1 {
        name: "pack-contract".into(),
        steps: Vec::new(),
        frozen_clock: None,
        policy_version: "policy-v1".into(),
    })
}

fn entry(path: &str) -> Result<RunPackFileEntryV1, recursive_agent_contracts::ContractError> {
    Ok(RunPackFileEntryV1 {
        path: path.into(),
        role: "receipts".into(),
        byte_length: 9,
        digest: content_digest(&b"evidence".to_vec())?,
    })
}

fn manifest(
    files: Vec<RunPackFileEntryV1>,
) -> Result<RunPackManifestV1, recursive_agent_contracts::ContractError> {
    Ok(RunPackManifestV1 {
        schema_version: RunPackManifestV1::SCHEMA_VERSION,
        source_run_id: run_id()?,
        files,
    })
}

#[test]
fn valid_manifest_is_jcs_canonical_and_round_trips() -> TestResult {
    let manifest = manifest(vec![
        entry("receipts.ndjson")?,
        entry("artifacts/evidence.meta")?,
    ])?;

    let first = manifest.canonical_bytes()?;
    assert_eq!(first, manifest.canonical_bytes()?);
    assert_eq!(
        serde_json::from_slice::<RunPackManifestV1>(&first)?,
        manifest
    );
    assert_eq!(jcs_canonical(&manifest)?, first);
    Ok(())
}

#[test]
fn deserialization_rejects_every_required_manifest_and_entry_field() -> TestResult {
    let source_run_id = serde_json::to_value(run_id()?)?;
    let digest = serde_json::to_value(content_digest(&b"evidence".to_vec())?)?;
    let cases = [
        serde_json::json!({"source_run_id": source_run_id, "files": []}),
        serde_json::json!({"schema_version": 1, "files": []}),
        serde_json::json!({"schema_version": 1, "source_run_id": source_run_id}),
        serde_json::json!({
            "schema_version": 1,
            "source_run_id": source_run_id,
            "files": [{"role": "receipts", "byte_length": 1, "digest": digest}]
        }),
        serde_json::json!({
            "schema_version": 1,
            "source_run_id": source_run_id,
            "files": [{"path": "receipts.ndjson", "byte_length": 1, "digest": digest}]
        }),
        serde_json::json!({
            "schema_version": 1,
            "source_run_id": source_run_id,
            "files": [{"path": "receipts.ndjson", "role": "receipts", "digest": digest}]
        }),
        serde_json::json!({
            "schema_version": 1,
            "source_run_id": source_run_id,
            "files": [{"path": "receipts.ndjson", "role": "receipts", "byte_length": 1}]
        }),
    ];

    for value in cases {
        assert!(serde_json::from_value::<RunPackManifestV1>(value).is_err());
    }
    Ok(())
}

#[test]
fn validation_rejects_unsupported_schema_and_hostile_or_duplicate_paths() -> TestResult {
    let hostile = [
        "",
        ".",
        "./receipts.ndjson",
        "../receipts.ndjson",
        "artifacts/../receipts.ndjson",
        "/receipts.ndjson",
        "C:/receipts.ndjson",
        "artifacts\\escape",
        "artifacts//nested",
    ];
    for path in hostile {
        assert!(manifest(vec![entry(path)?])?.validate().is_err(), "{path}");
    }

    let mut unsupported = manifest(vec![entry("receipts.ndjson")?])?;
    unsupported.schema_version += 1;
    assert!(unsupported.validate().is_err());

    let mut blank_role = entry("receipts.ndjson")?;
    blank_role.role.clear();
    assert!(manifest(vec![blank_role])?.validate().is_err());

    assert!(
        manifest(vec![entry("receipts.ndjson")?, entry("receipts.ndjson")?])?
            .validate()
            .is_err()
    );
    Ok(())
}
