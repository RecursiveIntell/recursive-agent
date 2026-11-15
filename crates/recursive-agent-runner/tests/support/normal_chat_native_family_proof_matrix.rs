use super::*;

#[test]
fn empty_pending_and_finalized_parents_are_not_complete_prefinalization_proofs() -> TestResult {
    for phase in ["empty", "pending", "finalized"] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        if phase != "empty" {
            let (request, preflight, _, _) = admitted(&fx, &service, &session)?;
            if phase == "finalized" {
                service.settle_normal_chat_attempt(
                    &session,
                    &request,
                    &preflight,
                    &super::super::super::terminal::report(
                        recursive_agent_policy::NormalChatReportedStateV2::NotSent,
                    )?,
                )?;
                service.close_normal_chat_session(&session)?;
            }
        }
        let before = tree(fx.root.path())?;
        assert!(
            verify_closed_normal_chat_family_from_runtime_root_fd(
                &File::open(fx.root.path())?,
                session.run_id(),
            )
            .is_err(),
            "{phase}"
        );
        assert_eq!(tree(fx.root.path())?, before, "{phase}");
    }
    Ok(())
}

#[test]
fn incomplete_parent_groups_cannot_be_promoted_or_repaired_into_complete_proof() -> TestResult {
    for kept in [3, 4, 5] {
        let fx = Fixture::new()?;
        let (session, _) = closed(&fx, None)?;
        let bytes = fs::read(session.run_dir().join("receipts.ndjson"))?;
        let end = bytes
            .iter()
            .enumerate()
            .filter(|(_, b)| **b == b'\n')
            .nth(kept - 1)
            .ok_or("prefix absent")?
            .0
            + 1;
        fs::write(session.run_dir().join("receipts.ndjson"), &bytes[..end])?;
        // Reconcile the deliberately shortened appendable chain through its
        // canonical owner first. The proof must not append missing group rows.
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
            "prefix {kept}"
        );
        assert_eq!(tree(fx.root.path())?, before, "prefix {kept}");
    }
    Ok(())
}

#[test]
fn owner_scope_wrong_parent_or_output_cannot_resolve_a_sibling_elsewhere() -> TestResult {
    let fx = Fixture::new()?;
    let (session, _) = closed(&fx, None)?;
    let other = Fixture::new()?;
    let service = other.service()?;
    let unrelated = service.open_normal_chat_session("conversation:unrelated")?;
    let before = tree(fx.root.path())?;
    assert!(verify_closed_normal_chat_family_from_runtime_root_fd(
        &File::open(fx.root.path())?,
        unrelated.run_id(),
    )
    .is_err());
    assert!(verify_closed_normal_chat_family_from_runtime_root_fd(
        &File::open(other.root.path())?,
        session.run_id(),
    )
    .is_err());
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}

#[test]
fn already_returned_proof_rejects_late_native_and_parent_inventory_changes() -> TestResult {
    for mode in ["native-fence", "parent-orphan", "child-head", "parent-head"] {
        let fx = Fixture::new()?;
        let (session, child) = closed(&fx, None)?;
        let proof = verify_closed_normal_chat_family_from_runtime_root_fd(
            &File::open(fx.root.path())?,
            session.run_id(),
        )?;
        match mode {
            "native-fence" => {
                let path = session.run_dir().join("family-authority.json");
                let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
                value["normal_chat_session"]["closed_at"] = json!(null);
                fs::write(path, recursive_agent_contracts::jcs_canonical(&value)?)?;
            }
            "parent-orphan" => {
                recursive_agent_ledger::ArtifactStore::from_run_root_fd(
                    &File::open(session.run_dir())?,
                    false,
                )?
                .put(b"unreferenced parent payload", "text/plain", None)?;
            }
            _ => {
                let root = if mode == "parent-head" {
                    session.run_dir()
                } else {
                    &child
                };
                let path = root.join("receipts.ndjson");
                let mut rows: Vec<recursive_agent_contracts::ReceiptV1> =
                    fs::read_to_string(&path)?
                        .lines()
                        .map(serde_json::from_str)
                        .collect::<Result<_, _>>()?;
                // A final recorded_time change is itself canonical and leaves
                // receipt identity valid, but changes the acknowledged head.
                rows.last_mut().ok_or("last row absent")?.recorded_time +=
                    TimeDelta::milliseconds(1);
                let mut data = Vec::new();
                for row in rows {
                    data.extend(row.canonical_bytes()?);
                    data.push(b'\n');
                }
                fs::write(path, data)?;
            }
        }
        let before = tree(fx.root.path())?;
        assert!(proof.recheck().is_err(), "{mode}");
        // Appendable verification may reconcile chain.meta; no semantic rows
        // or native state may be repaired. Other cases leave the tree exact.
        if !mode.ends_with("head") {
            assert_eq!(tree(fx.root.path())?, before);
        }
    }
    Ok(())
}
