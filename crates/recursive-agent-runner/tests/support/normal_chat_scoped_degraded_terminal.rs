//! Offline candidate fixtures ONLY; no production publication claim.
#[path = "normal_chat_scoped_degraded_terminal_hostile.rs"]
mod hostile;
use super::*;
use recursive_agent_contracts::{jcs_canonical, ContentDigest, ReceiptKindV1, ReceiptV1};
use recursive_agent_ledger::{
    chain_digest_from_raw, verify_degraded_normal_chat_session_from_runtime_root_fd as verify,
    ArtifactStore, LedgerError, ReceiptDraftV1, RunPaths,
};
fn terminal_candidate(
    fx: &Fixture,
    state: Option<NormalChatReportedStateV2>,
    reason: Option<PermitRevocationReasonV1>,
    cancel: bool,
) -> Result<Source, Box<dyn std::error::Error>> {
    let (session, gate) = native_closed(fx, state, reason, cancel)?;
    write_candidate(fx, &session, &gate)?;
    Ok((session, gate))
}
fn write_candidate(
    fx: &Fixture,
    session: &recursive_agent_runner::RuntimeNormalChatSessionV1,
    gate: &Gate,
) -> TestResult {
    let root = File::open(session.run_dir())?;
    let out = File::open(fx.root.path())?;
    let plan = prepare(&out, session.run_id(), gate)?;
    let prefix = appendable_snapshot_expected_run_from_dir_fd(&root, session.run_id())?;
    let store = ArtifactStore::from_run_root_fd(&root, false)?;
    assert_eq!(
        store.put(plan.root_revocation_bytes(), "application/json", None)?,
        *plan.root_revocation_descriptor()
    );
    assert_eq!(
        store.put(plan.marker_bytes(), "application/json", None)?,
        *plan.marker_descriptor()
    );
    let mut raw = fs::read(session.run_dir().join("receipts.ndjson"))?;
    let mut head = ContentDigest::from_hex(prefix.verification().final_head.clone())?;
    for kind in [
        ReceiptKindV1::PermitRevoked,
        ReceiptKindV1::NormalChatSessionDegradedV1,
        ReceiptKindV1::RunFinalized,
    ] {
        let mut draft = plan.root_revocation_draft();
        draft.kind = kind.clone();
        if kind != ReceiptKindV1::PermitRevoked {
            draft.valid_time = plan.marker().finalized_at;
            draft.outcome = plan.outcome().clone();
            draft.artifact_refs = if kind == ReceiptKindV1::NormalChatSessionDegradedV1 {
                vec![plan.marker_descriptor().clone()]
            } else {
                vec![]
            };
        }
        let row = make_receipt(draft, head)?;
        let bytes = row.canonical_bytes()?;
        head = chain_digest_from_raw(&row.prev_chain_digest, &bytes)?;
        raw.extend(bytes);
        raw.push(b'\n');
    }
    let mut meta: serde_json::Value =
        serde_json::from_slice(&fs::read(session.run_dir().join("chain.meta"))?)?;
    meta["head"] = json!(head.to_string());
    meta["length"] = json!(prefix.receipts().len() + 3);
    // Deliberately construct an internally consistent OFFLINE candidate.
    // The generic owner still refuses this marker and has not published it.
    fs::write(session.run_dir().join("receipts.ndjson"), raw)?;
    fs::write(session.run_dir().join("chain.meta"), jcs_canonical(&meta)?)?;
    drop(plan);
    Ok(())
}
fn rewrite(path: &std::path::Path, mut rows: Vec<ReceiptV1>) -> TestResult {
    let mut previous = rows[0].prev_chain_digest.clone();
    let mut raw = Vec::new();
    for old in rows.drain(..) {
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
        let bytes = row.canonical_bytes()?;
        previous = chain_digest_from_raw(&row.prev_chain_digest, &bytes)?;
        raw.extend(bytes);
        raw.push(b'\n');
    }
    let count = raw.split(|b| *b == b'\n').filter(|l| !l.is_empty()).count();
    let mut meta: serde_json::Value = serde_json::from_slice(&fs::read(path.join("chain.meta"))?)?;
    meta["head"] = json!(previous.to_string());
    meta["length"] = json!(count);
    fs::write(path.join("receipts.ndjson"), raw)?;
    fs::write(path.join("chain.meta"), jcs_canonical(&meta)?)?;
    Ok(())
}
#[test]
fn scoped_terminal_proof_joins_real_recovered_and_reported_unknown_without_enabling_generic_acceptance(
) -> TestResult {
    for state in [None, Some(NormalChatReportedStateV2::OutcomeUnknown)] {
        let fx = Fixture::new()?;
        let (session, gate) = terminal_candidate(&fx, state, None, false)?;
        fs::remove_file(fx._grant_root.path().join("grant.json"))?;
        let before = tree(fx.root.path())?;
        let out = File::open(fx.root.path())?;
        let proof = verify(&out, session.run_id(), &gate)?;
        assert_eq!(proof.terminal_state(), RunTerminalStateV1::Failed);
        assert_eq!(proof.child_count(), 1);
        assert_eq!(proof.unknown_child_count(), 1);
        assert!(proof.verification().current_strict_success);
        assert_eq!(proof.marker().parent_run_id, *session.run_id());
        proof.recheck()?;
        for result in [
            recursive_agent_ledger::verify_directory_bound(&RunPaths::new(session.run_dir()))
                .map(|_| ()),
            recursive_agent_ledger::open_existing_from_dir_fd(
                &RunPaths::new(session.run_dir()),
                &File::open(session.run_dir())?,
            )
            .map(|_| ()),
            recursive_agent_ledger::committed_events_directory_bound(
                &RunPaths::new(session.run_dir()),
                None,
            )
            .map(|_| ()),
            recursive_agent_ledger::export_run_pack(
                &RunPaths::new(session.run_dir()),
                &fx._grant_root.path().join("forbidden-pack"),
            )
            .map(|_| ()),
        ] {
            assert!(matches!(
                result,
                Err(LedgerError::NormalChatFamilyScopeRequired)
            ));
        }
        assert!(!fx._grant_root.path().join("forbidden-pack").exists());
        assert!(recursive_agent_runner::replay(&RunPaths::new(session.run_dir())).is_err());
        assert_eq!(tree(fx.root.path())?, before);
    }
    Ok(())
}
#[test]
fn scoped_terminal_proof_reconciles_a_mixed_two_child_family_in_receipt_order() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    for (intent, state) in [
        ("intent:known", NormalChatReportedStateV2::NotSent),
        ("intent:unknown", NormalChatReportedStateV2::OutcomeUnknown),
    ] {
        let request = super::super::super::super::request(&fx, &session, intent)?;
        let fresh = match service.begin_normal_chat_attempt(&session, &request)? {
            RuntimeNormalChatBeginV2::Fresh(f) => f,
            _ => return Err("expected Fresh".into()),
        };
        service.settle_normal_chat_attempt(
            &session,
            &request,
            fresh.preflight_digest(),
            &super::super::super::super::terminal::report(state)?,
        )?;
    }
    let root = File::open(session.run_dir())?;
    let gate = Gate::acquire_existing(&root)?;
    let family_proof = verify_closed_normal_chat_family_from_runtime_root_fd(
        &File::open(fx.root.path())?,
        session.run_id(),
    )?;
    let policy = DurablePermitStore::require_existing_from_run_root_fd(&root)?;
    let family = FamilyAuthorityStore::require_existing_from_dir_fd(
        &root,
        family_proof.context().session_family_grant_v2()?,
    )?;
    policy.close_normal_chat_session_v2(
        &family,
        family_proof.context(),
        family_proof.native_snapshot(),
        start() + TimeDelta::seconds(4),
        || start() + TimeDelta::seconds(4),
    )?;
    write_candidate(&fx, &session, &gate)?;
    let before = tree(fx.root.path())?;
    let proof = verify(&File::open(fx.root.path())?, session.run_id(), &gate)?;
    assert_eq!(proof.child_count(), 2);
    assert_eq!(proof.unknown_child_count(), 1);
    assert!(proof.marker().children[0].unknown_source.is_none());
    assert!(proof.marker().children[1].unknown_source.is_some());
    assert_eq!(proof.verification().length, 12);
    assert_eq!(proof.terminal_state(), RunTerminalStateV1::Failed);
    proof.recheck()?;
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}
#[test]
fn scoped_terminal_proof_retains_actual_cancellation_and_denial_precedence() -> TestResult {
    for (reason, cancel, expected) in [
        (
            Some(PermitRevocationReasonV1::PolicySuperseded),
            false,
            RunTerminalStateV1::Denied,
        ),
        (
            Some(PermitRevocationReasonV1::OperationCancelled),
            false,
            RunTerminalStateV1::Cancelled,
        ),
        (
            Some(PermitRevocationReasonV1::PolicySuperseded),
            true,
            RunTerminalStateV1::Cancelled,
        ),
    ] {
        let fx = Fixture::new()?;
        let (session, gate) = terminal_candidate(&fx, None, reason, cancel)?;
        let proof = verify(&File::open(fx.root.path())?, session.run_id(), &gate)?;
        assert_eq!(proof.terminal_state(), expected);
        proof.recheck()?;
    }
    Ok(())
}
#[test]
fn partial_parent_tail_and_missing_or_stale_meta_are_rejected_without_parent_repair() -> TestResult
{
    for mode in [
        "missing-meta",
        "stale-meta",
        "missing-newline",
        "partial-tail",
    ] {
        let fx = Fixture::new()?;
        let (session, gate) = terminal_candidate(&fx, None, None, false)?;
        let path = session.run_dir();
        match mode {
            "missing-meta" => fs::remove_file(path.join("chain.meta"))?,
            "stale-meta" => {
                let mut m: serde_json::Value =
                    serde_json::from_slice(&fs::read(path.join("chain.meta"))?)?;
                m["length"] = json!(1);
                fs::write(path.join("chain.meta"), jcs_canonical(&m)?)?;
            }
            "missing-newline" => {
                let mut raw = fs::read(path.join("receipts.ndjson"))?;
                raw.pop();
                fs::write(path.join("receipts.ndjson"), raw)?;
            }
            _ => {
                let mut raw = fs::read(path.join("receipts.ndjson"))?;
                raw.extend(b"{\"partial\":");
                fs::write(path.join("receipts.ndjson"), raw)?;
            }
        }
        let before = tree(fx.root.path())?;
        assert!(
            verify(&File::open(fx.root.path())?, session.run_id(), &gate).is_err(),
            "{mode}"
        );
        assert_eq!(tree(fx.root.path())?, before, "{mode}");
    }
    Ok(())
}
#[test]
fn exact_suffix_bindings_times_outcomes_and_cardinality_are_not_adapter_claims() -> TestResult {
    for mode in [
        "root-time",
        "marker-time",
        "final-binding",
        "missing-final",
        "duplicate-marker",
        "reordered",
    ] {
        let fx = Fixture::new()?;
        let (session, gate) = terminal_candidate(&fx, None, None, false)?;
        let path = session.run_dir();
        let mut rows: Vec<ReceiptV1> = fs::read_to_string(path.join("receipts.ndjson"))?
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        match mode {
            "root-time" => rows[6].valid_time -= TimeDelta::milliseconds(1),
            "marker-time" => {
                rows[7].valid_time += TimeDelta::milliseconds(1);
                rows[8].valid_time = rows[7].valid_time;
            }
            "final-binding" => rows[8].args_digest = ContentDigest::compute(b"wrong"),
            "missing-final" => {
                rows.pop();
            }
            "duplicate-marker" => {
                rows.insert(8, rows[7].clone());
            }
            _ => rows.swap(6, 7),
        };
        rewrite(path, rows)?;
        let before = tree(fx.root.path())?;
        assert!(
            verify(&File::open(fx.root.path())?, session.run_id(), &gate).is_err(),
            "{mode}"
        );
        assert_eq!(tree(fx.root.path())?, before, "{mode}");
    }
    Ok(())
}
#[test]
fn wrong_gate_cannot_repair_or_read_another_terminal_root() -> TestResult {
    let fx = Fixture::new()?;
    let (session, _gate) = terminal_candidate(&fx, None, None, false)?;
    fs::remove_file(session.run_dir().join("chain.meta"))?;
    let other = tempfile::tempdir()?;
    let wrong = Gate::acquire(&File::open(other.path())?)?;
    let before = tree(fx.root.path())?;
    assert!(verify(&File::open(fx.root.path())?, session.run_id(), &wrong).is_err());
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}
