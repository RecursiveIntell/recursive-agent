//! Hostile marker proposals; no scoped writer or successful parent is invented.
use super::*;
use recursive_agent_contracts::{
    NormalChatDegradedChildRefV1, NormalChatSessionDegradationSchemaV1,
    NormalChatSessionDegradationV1, NormalChatUnknownSourceRefV1, ReceiptV1,
    NORMAL_CHAT_CHILD_OUTCOME_UNKNOWN_REASON_V1,
};
use recursive_agent_ledger::{
    chain_digest_from_raw, make_receipt, open_existing_from_dir_fd, ArtifactStore, ChainHandle,
    LedgerError, ReceiptDraftV1, RunPaths,
};
use recursive_agent_policy::{build_lineage, DurablePermitStore, PermitEvidenceV1, PermitStateV1};

fn proposal(fx: &Fixture) -> Result<(PathBuf, ChainHandle, ReceiptV1), Box<dyn std::error::Error>> {
    let (session, _) = closed(fx, None)?;
    let proof = verify_closed_normal_chat_family_from_runtime_root_fd(
        &File::open(fx.root.path())?,
        session.run_id(),
    )?;
    assert_eq!(proof.unknown_child_count(), 1);
    let root = File::open(session.run_dir())?;
    let policy = DurablePermitStore::require_existing_from_run_root_fd(&root)?;
    let family = FamilyAuthorityStore::require_existing_from_dir_fd(
        &root,
        proof.context().session_family_grant_v2()?,
    )?;
    let native = policy.close_normal_chat_session_v2(
        &family,
        proof.context(),
        proof.native_snapshot(),
        start() + TimeDelta::seconds(3),
        || start() + TimeDelta::seconds(3),
    )?;
    let native = policy.confirm_closed_normal_chat_session_v2(&family, proof.context(), &native)?;
    let evidence = PermitEvidenceV1::from_record(&native.root_control)?;
    let at = match native.root_control.state {
        PermitStateV1::Revoked { revoked_at, .. } => revoked_at,
        _ => return Err("not closed".into()),
    };
    let store = ArtifactStore::from_run_root_fd(&root, false)?;
    let descriptor = store.put(
        &recursive_agent_contracts::jcs_canonical(&evidence)?,
        "application/json",
        None,
    )?;
    let mut chain = open_existing_from_dir_fd(&RunPaths::new(session.run_dir()), &root)?;
    let draft = |kind, valid_time, artifact_refs, outcome| ReceiptDraftV1 {
        run_id: evidence.binding.run_id.clone(),
        step_id: evidence.binding.step_id.clone(),
        kind,
        valid_time,
        lineage: build_lineage(&evidence.permit_id, &evidence.binding.policy_version),
        spec_digest: evidence.binding.action_digest.clone(),
        args_digest: evidence.binding.args_digest.clone(),
        artifact_refs,
        outcome,
    };
    let revoke = make_receipt(
        draft(
            ReceiptKindV1::PermitRevoked,
            at,
            vec![descriptor.clone()],
            recursive_agent_contracts::ReceiptOutcomeV1::Ok,
        ),
        chain.head().clone(),
    )?;
    let revocation_id = revoke.receipt_id.clone();
    chain.append(revoke)?;
    let rows = appendable_snapshot_expected_run_from_dir_fd(&root, session.run_id())?;
    let child = &proof.children()[0];
    let marker = NormalChatSessionDegradationV1 {
        schema: NormalChatSessionDegradationSchemaV1::V1,
        parent_run_id: session.run_id().clone(),
        root_step_id: evidence.binding.step_id.clone(),
        root_permit_id: evidence.permit_id.clone(),
        root_revocation_receipt_id: revocation_id,
        root_revocation_evidence: descriptor,
        family_closed_at: native.snapshot.admission.closed_at.ok_or("not closed")?,
        family_parent_revoked_at: native.snapshot.admission.parent_revoked_at,
        finalized_at: at,
        children: vec![NormalChatDegradedChildRefV1 {
            prepared_receipt_id: rows.receipts()[3].receipt_id.clone(),
            linked_receipt_id: rows.receipts()[4].receipt_id.clone(),
            closed_receipt_id: rows.receipts()[5].receipt_id.clone(),
            child_run_id: child.run_id().clone(),
            child_terminal_receipt_id: child.terminal_receipt().receipt_id.clone(),
            child_chain_head: ContentDigest::from_hex(child.chain_head())?,
            child_closed_artifact: rows.receipts()[5].artifact_refs[0].clone(),
            unknown_source: Some(NormalChatUnknownSourceRefV1::MissingExecutorOutcomeV1 {
                evidence: child.source_artifacts()[0].clone(),
            }),
        }],
    };
    marker.validate()?;
    let bytes = recursive_agent_contracts::jcs_canonical(&marker)?;
    assert_eq!(
        recursive_agent_contracts::parse_normal_chat_session_degradation_v1_bytes(&bytes)?,
        marker
    );
    let artifact = store.put(&bytes, "application/json", None)?;
    let row = make_receipt(
        draft(
            ReceiptKindV1::NormalChatSessionDegradedV1,
            at,
            vec![artifact],
            recursive_agent_contracts::ReceiptOutcomeV1::Failed {
                reason: NORMAL_CHAT_CHILD_OUTCOME_UNKNOWN_REASON_V1.into(),
            },
        ),
        chain.head().clone(),
    )?;
    Ok((session.run_dir().to_path_buf(), chain, row))
}

#[test]
fn generic_append_refuses_even_a_source_grounded_marker_without_scoped_owner() -> TestResult {
    let fx = Fixture::new()?;
    let (path, mut chain, marker) = proposal(&fx)?;
    let before = tree(fx.root.path())?;
    let head = chain.head().clone();
    assert!(matches!(
        chain.append(marker),
        Err(LedgerError::NormalChatFamilyScopeRequired)
    ));
    assert_eq!(chain.head(), &head);
    assert_eq!(tree(fx.root.path())?, before);
    assert_eq!(
        fs::read_to_string(path.join("receipts.ndjson"))?
            .lines()
            .count(),
        7
    );
    Ok(())
}
fn hostile_wire(
    fx: &Fixture,
    finalized: bool,
) -> Result<(PathBuf, recursive_agent_contracts::CurrentRunId), Box<dyn std::error::Error>> {
    let (path, chain, marker) = proposal(fx)?;
    let id = marker.run_id.clone();
    drop(chain);
    let mut raw = fs::read(path.join("receipts.ndjson"))?;
    let bytes = marker.canonical_bytes()?;
    let previous = chain_digest_from_raw(&marker.prev_chain_digest, &bytes)?;
    raw.extend(bytes);
    raw.push(b'\n');
    if finalized {
        let final_row = make_receipt(
            ReceiptDraftV1 {
                run_id: marker.run_id,
                step_id: marker.step_id,
                kind: ReceiptKindV1::RunFinalized,
                valid_time: marker.valid_time,
                lineage: marker.lineage,
                spec_digest: marker.spec_digest,
                args_digest: marker.args_digest,
                artifact_refs: vec![],
                outcome: marker.outcome,
            },
            previous,
        )?;
        raw.extend(final_row.canonical_bytes()?);
        raw.push(b'\n');
    }
    // Adversarial file construction ONLY, not canonical successful append.
    // Bind metadata as well, so strict pack verification reaches the scope
    // refusal rather than merely detecting stale chain.meta from the attack.
    let rows: Vec<ReceiptV1> = std::str::from_utf8(&raw)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    let last = rows.last().ok_or("last candidate row absent")?;
    let head = chain_digest_from_raw(&last.prev_chain_digest, &last.canonical_bytes()?)?;
    let meta_path = path.join("chain.meta");
    let mut meta: serde_json::Value = serde_json::from_slice(&fs::read(&meta_path)?)?;
    meta["head"] = json!(head.to_string());
    meta["length"] = json!(rows.len());
    fs::write(path.join("receipts.ndjson"), raw)?;
    fs::write(meta_path, recursive_agent_contracts::jcs_canonical(&meta)?)?;
    Ok((path, id))
}
#[test]
fn unscoped_read_verify_and_event_routes_do_not_promote_marker_shape_to_family_proof() -> TestResult
{
    for finalized in [false, true] {
        let fx = Fixture::new()?;
        let (path, id) = hostile_wire(&fx, finalized)?;
        let root = File::open(&path)?;
        let before = tree(fx.root.path())?;
        for result in [
            open_existing_from_dir_fd(&RunPaths::new(&path), &root).map(|_| ()),
            recursive_agent_ledger::appendable_snapshot_expected_run_from_dir_fd(&root, &id)
                .map(|_| ()),
            recursive_agent_ledger::verify_expected_run_from_dir_fd(&root, &id).map(|_| ()),
            recursive_agent_ledger::verify_directory_bound(&RunPaths::new(&path)).map(|_| ()),
            recursive_agent_ledger::verified_snapshot_directory_bound(&RunPaths::new(&path))
                .map(|_| ()),
            recursive_agent_ledger::committed_events_directory_bound(&RunPaths::new(&path), None)
                .map(|_| ()),
        ] {
            assert!(matches!(
                result,
                Err(LedgerError::NormalChatFamilyScopeRequired)
            ));
        }
        assert!(verify_closed_normal_chat_family_from_runtime_root_fd(
            &File::open(fx.root.path())?,
            &id
        )
        .is_err());
        assert_eq!(tree(fx.root.path())?, before);
    }
    Ok(())
}
#[test]
fn unscoped_replay_and_pack_export_reject_marker_without_publishing_a_projection() -> TestResult {
    let fx = Fixture::new()?;
    let (path, _) = hostile_wire(&fx, true)?;
    let before = tree(fx.root.path())?;
    let destination = fx._grant_root.path().join("pack");
    assert!(matches!(
        recursive_agent_ledger::export_run_pack(&RunPaths::new(&path), &destination),
        Err(LedgerError::NormalChatFamilyScopeRequired)
    ));
    assert!(!destination.exists());
    let result = recursive_agent_runner::replay(&RunPaths::new(&path));
    assert!(result.is_err());
    assert!(result
        .err()
        .ok_or("error absent")?
        .to_string()
        .contains("requires scoped native-family proof"));
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}
