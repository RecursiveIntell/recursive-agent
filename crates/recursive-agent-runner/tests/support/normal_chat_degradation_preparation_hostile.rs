use super::*;
use recursive_agent_ledger::prepare_normal_chat_session_degradation_from_runtime_root_fd_with_observer as observe;
#[test]
fn wrong_gate_cannot_repair_missing_chain_metadata_before_scope_admission() -> TestResult {
    let fx = Fixture::new()?;
    let (session, _gate) = native_closed(&fx, None, None, false)?;
    let meta = session.run_dir().join("chain.meta");
    fs::remove_file(&meta)?;
    let other = tempfile::tempdir()?;
    let wrong = Gate::acquire(&File::open(other.path())?)?;
    let before = tree(fx.root.path())?;
    assert!(matches!(
        prepare(&File::open(fx.root.path())?, session.run_id(), &wrong),
        Err(Error::Gate(_))
    ));
    assert!(!meta.exists());
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}
#[test]
fn core_final_gate_fence_precedes_any_reconciliation_after_negative_observer() -> TestResult {
    let fx = Fixture::new()?;
    let (session, gate) = native_closed(&fx, None, None, false)?;
    let mut changed = Ok(());
    let mut called = false;
    let meta = session.run_dir().join("chain.meta");
    let result = observe(
        &File::open(fx.root.path())?,
        session.run_id(),
        &gate,
        || {
            called = true;
            changed = (|| -> std::io::Result<()> {
                fs::rename(
                    session.run_dir().join(".normal-chat-runtime.lock"),
                    session.run_dir().join("detached-gate"),
                )?;
                fs::write(session.run_dir().join(".normal-chat-runtime.lock"), b"")?;
                fs::set_permissions(
                    session.run_dir().join(".normal-chat-runtime.lock"),
                    fs::Permissions::from_mode(0o600),
                )?;
                fs::remove_file(&meta)?;
                Ok(())
            })();
        },
    );
    changed?;
    assert!(called);
    assert!(result.is_err());
    assert!(
        !meta.exists(),
        "scope loss repaired metadata before failing"
    );
    Ok(())
}
#[test]
fn native_child_and_parent_source_substitutions_never_return_a_preparation() -> TestResult {
    for target in ["root-record", "family", "child-artifacts", "parent-root"] {
        let fx = Fixture::new()?;
        let (session, gate) = native_closed(&fx, None, None, false)?;
        let proof = verify_closed_normal_chat_family_from_runtime_root_fd(
            &File::open(fx.root.path())?,
            session.run_id(),
        )?;
        let child = fx
            .root
            .path()
            .join(content_digest(proof.children()[0].run_id())?.to_string());
        let mut action = Ok(());
        let mut removed = None;
        let mut called = false;
        let result = observe(
            &File::open(fx.root.path())?,
            session.run_id(),
            &gate,
            || {
                called = true;
                action = (|| -> std::io::Result<()> {
                    match target {
                        "root-record" => {
                            let entries = fs::read_dir(session.run_dir().join("permits"))?;
                            for entry in entries {
                                let p = entry?.path();
                                if p.extension().is_some_and(|x| x == "json") {
                                    fs::remove_file(&p)?;
                                    removed = Some(p);
                                }
                            }
                        }
                        "family" => {
                            let p = session.run_dir().join("family-authority.json");
                            fs::remove_file(&p)?;
                            removed = Some(p);
                        }
                        "child-artifacts" => super::super::replace(&child.join("artifacts"))?,
                        _ => super::super::replace(session.run_dir())?,
                    }
                    Ok(())
                })();
            },
        );
        action?;
        assert!(called);
        assert!(result.is_err(), "{target}");
        if let Some(p) = removed {
            assert!(!p.exists(), "{target} recreated");
        }
    }
    Ok(())
}
#[test]
fn returned_preparation_rechecks_sources_and_does_not_revoke_or_recreate() -> TestResult {
    let fx = Fixture::new()?;
    let (session, gate) = native_closed(&fx, None, None, false)?;
    let plan = prepare(&File::open(fx.root.path())?, session.run_id(), &gate)?;
    let path = session.run_dir().join("family-authority.json");
    fs::remove_file(&path)?;
    assert!(plan.recheck().is_err());
    assert!(!path.exists());
    Ok(())
}
#[test]
fn projected_capacity_includes_every_existing_payload_and_the_two_new_payloads() -> TestResult {
    let fx = Fixture::new()?;
    let (session, gate) = native_closed(&fx, None, None, false)?;
    let before = tree(fx.root.path())?;
    let plan = prepare(&File::open(fx.root.path())?, session.run_id(), &gate)?;
    let mut payloads = std::collections::BTreeMap::new();
    for entry in fs::read_dir(session.run_dir().join("artifacts"))? {
        let entry = entry?;
        if entry.path().extension().is_none() {
            payloads.insert(
                entry.file_name().to_string_lossy().to_string(),
                fs::metadata(entry.path())?.len(),
            );
        }
    }
    payloads.insert(
        plan.root_revocation_descriptor().digest.to_string(),
        plan.root_revocation_bytes().len() as u64,
    );
    payloads.insert(
        plan.marker_descriptor().digest.to_string(),
        plan.marker_bytes().len() as u64,
    );
    let total: u64 = payloads.values().sum();
    assert_eq!(total, plan.projected_artifact_bytes());
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}
#[test]
fn a_preparation_does_not_enable_generic_marker_append_or_suffix_resume() -> TestResult {
    let fx = Fixture::new()?;
    let (session, gate) = native_closed(&fx, None, None, false)?;
    let plan = prepare(&File::open(fx.root.path())?, session.run_id(), &gate)?;
    let root = File::open(session.run_dir())?;
    let mut chain = recursive_agent_ledger::open_existing_from_dir_fd(
        &recursive_agent_ledger::RunPaths::new(session.run_dir()),
        &root,
    )?;
    let mut draft = plan.root_revocation_draft();
    draft.kind = recursive_agent_contracts::ReceiptKindV1::NormalChatSessionDegradedV1;
    draft.valid_time = plan.marker().finalized_at;
    draft.artifact_refs = vec![plan.marker_descriptor().clone()];
    draft.outcome = plan.outcome().clone();
    let marker = make_receipt(draft, chain.head().clone())?;
    let before = tree(fx.root.path())?;
    assert!(matches!(
        chain.append(marker),
        Err(recursive_agent_ledger::LedgerError::NormalChatFamilyScopeRequired)
    ));
    assert_eq!(tree(fx.root.path())?, before);
    let store = recursive_agent_ledger::ArtifactStore::from_run_root_fd(&root, false)?;
    store.put(plan.root_revocation_bytes(), "application/json", None)?;
    let revoke = make_receipt(plan.root_revocation_draft(), chain.head().clone())?;
    chain.append(revoke)?;
    assert!(plan.recheck().is_err());
    assert!(prepare(&File::open(fx.root.path())?, session.run_id(), &gate).is_err());
    Ok(())
}
