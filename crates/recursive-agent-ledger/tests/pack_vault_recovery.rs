use recursive_agent_ledger::{export_run_pack, PackVault, RunPackExportStage};
use serde_json::Value;

mod fixture {
    include!("run_pack_export.rs");
    pub(super) fn run_paths(
        root: &std::path::Path,
    ) -> Result<recursive_agent_ledger::RunPaths, Box<dyn std::error::Error>> {
        Ok(valid_chain_fixture::completed_run(root)?.paths)
    }
}

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn admission_boundaries_reconcile_without_publishing_unverified_objects() -> TestResult {
    let root = tempfile::tempdir()?;
    let paths = fixture::run_paths(root.path())?;
    let pack = root.path().join("pack");
    export_run_pack(&paths, &pack)?;
    let vault_root = tempfile::tempdir()?;
    let vault = PackVault::new(vault_root.path())?;

    for stage in [
        RunPackExportStage::CopyComplete,
        RunPackExportStage::VerifyComplete,
    ] {
        assert!(vault.admit_with_interruption_at(&pack, stage)?.is_err());
        assert!(vault.object_ids()?.is_empty());
    }

    assert!(vault
        .admit_with_interruption_at(&pack, RunPackExportStage::ReceiptPersisted)?
        .is_err());
    assert!(vault.object_ids()?.is_empty());

    let admission_paths = std::fs::read_dir(vault_root.path().join("admissions"))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(admission_paths.len(), 1);
    let durable_receipt: Value = serde_json::from_slice(&std::fs::read(&admission_paths[0])?)?;
    let durable_object_id = durable_receipt["object_id"]
        .as_str()
        .ok_or("admission receipt has no object_id")?
        .to_owned();
    let durable_recorded_at = chrono::DateTime::parse_from_rfc3339(
        durable_receipt["recorded_at"]
            .as_str()
            .ok_or("admission receipt has no recorded_at")?,
    )?
    .with_timezone(&chrono::Utc);
    assert!(matches!(
        vault.admission(&durable_object_id),
        Err(recursive_agent_ledger::LedgerError::ArtifactMissing(_))
    ));
    let recovered = vault.admit(&pack)?;
    assert_eq!(recovered.object_id(), durable_object_id);
    assert_eq!(recovered.recorded_at(), durable_recorded_at);
    assert!(vault.admission(recovered.object_id()).is_ok());

    let published_root = tempfile::tempdir()?;
    let published_vault = PackVault::new(published_root.path())?;
    let published =
        published_vault.admit_with_interruption_at(&pack, RunPackExportStage::Published)?;
    assert!(published.is_err());
    let retried = published_vault.admit(&pack)?;
    assert_eq!(published_vault.object_ids()?.len(), 1);
    assert!(published_vault.admission(retried.object_id()).is_ok());
    Ok(())
}
