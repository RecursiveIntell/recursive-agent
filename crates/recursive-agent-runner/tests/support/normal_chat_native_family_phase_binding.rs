use super::*;
use recursive_agent_ledger::{chain_digest_from_raw, make_receipt, ReceiptDraftV1};

fn reject_phase_substitution(index: usize) -> TestResult {
    let fx = Fixture::new()?;
    let (session, _) = closed(&fx, None)?;
    let snapshot = recursive_agent_ledger::appendable_snapshot_expected_run_from_dir_fd(
        &File::open(session.run_dir())?,
        session.run_id(),
    )?;
    let mut rows = snapshot.receipts().to_vec();
    rows[index].step_id = rows[1].step_id.clone();
    let mut previous = rows[0].prev_chain_digest.clone();
    let mut bytes = Vec::new();
    for old in rows {
        let mut row = make_receipt(
            ReceiptDraftV1 {
                run_id: old.run_id,
                step_id: old.step_id,
                kind: old.kind,
                valid_time: old.valid_time,
                lineage: old.lineage,
                spec_digest: old.spec_digest,
                args_digest: old.args_digest,
                artifact_refs: old.artifact_refs,
                outcome: old.outcome,
            },
            previous,
        )?;
        row.recorded_time = old.recorded_time;
        let canonical = row.canonical_bytes()?;
        previous = chain_digest_from_raw(&row.prev_chain_digest, &canonical)?;
        bytes.extend(canonical);
        bytes.push(b'\n');
    }
    fs::write(session.run_dir().join("receipts.ndjson"), bytes)?;
    // All material receipt IDs/checksums and the generic appendable ledger are
    // valid. The native-family owner must enforce the exact phase binding.
    recursive_agent_ledger::appendable_snapshot_expected_run_from_dir_fd(
        &File::open(session.run_dir())?,
        session.run_id(),
    )?;
    let before = tree(fx.root.path())?;
    assert!(
        verify_closed_normal_chat_family_from_runtime_root_fd(
            &File::open(fx.root.path())?,
            session.run_id(),
        )
        .is_err(),
        "phase identity substitution escaped native family proof at {index}"
    );
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}

#[test]
fn noncanonical_link_phase_rejects_even_with_valid_material_chain() -> TestResult {
    reject_phase_substitution(4)
}
#[test]
fn noncanonical_closure_phase_rejects_even_with_valid_material_chain() -> TestResult {
    reject_phase_substitution(5)
}
