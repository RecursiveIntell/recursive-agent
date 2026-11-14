use super::*;

#[test]
fn unknown_issued_state_member_is_rejected_for_local_control() -> TestResult {
    let fx = Fixture::new()?;
    let mut chain = fx.chain()?;
    let store = chain.artifact_store()?;
    let control = fx.proof.control_evidence()?;
    append(&mut chain, &control, ReceiptKindV1::RunStarted, vec![])?;
    append(&mut chain, &control, ReceiptKindV1::StepStarted, vec![])?;
    let mut raw = serde_json::to_value(&control)?;
    raw["state"] = json!({"state":"issued","unexpected":"must-reject"});
    let descriptor = store.put(&jcs_canonical(&raw)?, "application/json", None)?;
    let head = chain.head().clone();
    assert!(append(
        &mut chain,
        &control,
        ReceiptKindV1::PermitIssued,
        vec![descriptor]
    )
    .is_err());
    assert_eq!(chain.head(), &head);
    Ok(())
}

#[test]
fn unknown_issued_state_member_is_rejected_for_effect() -> TestResult {
    let fx = Fixture::new()?;
    let mut chain = fx.prefix(true)?;
    let store = chain.artifact_store()?;
    let effect = fx.proof.issued_effect_evidence()?;
    let mut raw = serde_json::to_value(&effect)?;
    raw["state"] = json!({"state":"issued","unexpected":"must-reject"});
    let descriptor = store.put(&jcs_canonical(&raw)?, "application/json", None)?;
    let head = chain.head().clone();
    assert!(append(
        &mut chain,
        &effect,
        ReceiptKindV1::PermitIssued,
        vec![descriptor]
    )
    .is_err());
    assert_eq!(chain.head(), &head);
    Ok(())
}

#[test]
fn delayed_consumption_preserves_historical_nonmonotonic_valid_time_order() -> TestResult {
    let fx = Fixture::new_with_delay(50)?;
    let mut chain = fx.prefix(true)?;
    let store = chain.artifact_store()?;
    let issued = fx.proof.issued_effect_evidence()?;
    append(
        &mut chain,
        &issued,
        ReceiptKindV1::PermitIssued,
        vec![put(&store, &issued)?],
    )?;
    append(
        &mut chain,
        &fx.proof.preflight.evidence,
        ReceiptKindV1::PermitConsumed,
        vec![put(&store, &fx.proof.preflight.evidence)?],
    )?;
    let snapshot = appendable_snapshot_expected_run_from_dir_fd(
        &File::open(fx.child.path())?,
        &issued.binding.run_id,
    )?;
    assert_eq!(snapshot.receipts().len(), 7);
    assert!(snapshot.receipts()[4].valid_time > snapshot.receipts()[5].valid_time);
    assert_eq!(snapshot.receipts()[5].valid_time, now());
    assert_eq!(
        snapshot.receipts()[6].valid_time,
        now() + TimeDelta::milliseconds(50)
    );
    Ok(())
}

#[test]
fn metadata_parser_rejects_alternate_lossy_unit_variant_representation() -> TestResult {
    let fx = Fixture::new()?;
    let mut raw = serde_json::to_value(&fx.proof)?;
    raw["admission"]["context"]["root_control"]["purpose"] = json!({"control":null});
    assert!(parse_normal_chat_ledger_admission_v2_bytes(&jcs_canonical(&raw)?).is_err());
    Ok(())
}
