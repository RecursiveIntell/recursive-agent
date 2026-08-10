use chrono::{DateTime, Utc};
use recursive_agent_contracts::{
    content_digest, derive_run_id, CurrentRunId, RunPackEventSummaryV1,
    RunPackEvidenceProjectionV1, RunPackProjectionOriginV1, RunPackRetentionStateV1,
    RunPackVaultRefV1, RunPackVerificationOutcomeV1, RunPackVerificationV1, RunSpecV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn run_id() -> Result<CurrentRunId, recursive_agent_contracts::ContractError> {
    derive_run_id(&RunSpecV1 {
        name: "witnessed-workbench-projection".into(),
        steps: Vec::new(),
        frozen_clock: None,
        policy_version: "policy-v1".into(),
    })
}

fn fixed_time() -> Result<DateTime<Utc>, Box<dyn std::error::Error>> {
    Ok("2026-08-10T00:00:00Z".parse()?)
}

fn projection() -> Result<RunPackEvidenceProjectionV1, Box<dyn std::error::Error>> {
    let artifact_a = content_digest(&"artifact-a")?;
    let artifact_b = content_digest(&"artifact-b")?;
    let mut artifacts = vec![artifact_a, artifact_b];
    artifacts.sort_by_key(ToString::to_string);
    let mut projection = RunPackEvidenceProjectionV1 {
        schema: RunPackEvidenceProjectionV1::SCHEMA.into(),
        projection_id: content_digest(&"placeholder")?,
        run_id: run_id()?,
        pack_manifest_digest: content_digest(&"manifest")?,
        pack_content_digest: content_digest(&"pack-index")?,
        verification: RunPackVerificationV1 {
            verifier_contract_version: "recursive-agent.run-pack-verifier/v1".into(),
            verified_at: fixed_time()?,
            verification_receipt_digest: content_digest(&"verification-receipt")?,
            outcome: RunPackVerificationOutcomeV1::Verified,
        },
        vault: RunPackVaultRefV1 {
            object_id: "vault-object-1".into(),
            relative_ref: "objects/pack-1".into(),
            retention_state: RunPackRetentionStateV1::Available,
        },
        origin: RunPackProjectionOriginV1 {
            operator_adapter: "hermes-native".into(),
            source_device_ref: Some("device:opaque-1".into()),
            observed_at: Some(fixed_time()?),
            recorded_at: fixed_time()?,
        },
        event_summary: RunPackEventSummaryV1 {
            terminal_state: recursive_agent_contracts::RunTerminalStateV1::Succeeded,
            receipt_chain_digest: content_digest(&"receipt-chain")?,
            artifact_digests: artifacts,
        },
    };
    projection.projection_id = projection.derived_projection_id()?;
    Ok(projection)
}

#[test]
fn valid_projection_is_canonical_and_projection_id_is_deterministic() -> TestResult {
    let projection = projection()?;
    projection.validate()?;
    let bytes = projection.canonical_bytes()?;
    assert_eq!(bytes, projection.canonical_bytes()?);
    assert_eq!(
        serde_json::from_slice::<RunPackEvidenceProjectionV1>(&bytes)?,
        projection
    );
    Ok(())
}

#[test]
fn projection_rejects_forged_identity_unknown_fields_and_hostile_vault_references() -> TestResult {
    let mut forged = projection()?;
    forged.projection_id = content_digest(&"forged")?;
    assert!(forged.validate().is_err());

    for relative_ref in [
        "../escape",
        "/absolute",
        "objects//pack",
        "objects\\pack",
        "C:/pack",
    ] {
        let mut hostile = projection()?;
        hostile.vault.relative_ref = relative_ref.into();
        assert!(hostile.validate().is_err(), "{relative_ref}");
    }

    let mut unknown = serde_json::to_value(projection()?)?;
    unknown["client_forged_verified"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<RunPackEvidenceProjectionV1>(unknown).is_err());
    Ok(())
}

#[test]
fn projection_rejects_wrong_adapter_unsorted_artifacts_and_forward_schema() -> TestResult {
    let mut wrong_adapter = projection()?;
    wrong_adapter.origin.operator_adapter = "client-forged".into();
    assert!(wrong_adapter.validate().is_err());

    let mut unsorted = projection()?;
    unsorted.event_summary.artifact_digests.reverse();
    assert!(unsorted.validate().is_err());

    let mut forward_schema = projection()?;
    forward_schema.schema = "RunPackEvidenceProjectionV2".into();
    assert!(forward_schema.validate().is_err());
    Ok(())
}
