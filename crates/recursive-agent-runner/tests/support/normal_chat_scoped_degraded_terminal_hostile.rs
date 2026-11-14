//! Deterministic negative seams for the scoped read-only terminal proof.
use super::*;
use recursive_agent_ledger::verify_degraded_normal_chat_session_from_runtime_root_fd_with_observer as observe;
fn child_path(
    fx: &Fixture,
    session: &recursive_agent_runner::RuntimeNormalChatSessionV1,
    gate: &Gate,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let p = verify(&File::open(fx.root.path())?, session.run_id(), gate)?;
    Ok(fx
        .root
        .path()
        .join(content_digest(&p.marker().children[0].child_run_id)?.to_string()))
}
#[test]
fn late_gate_native_parent_and_child_substitutions_never_return_terminal_evidence() -> TestResult {
    for mode in [
        "gate",
        "root-record",
        "family",
        "parent-artifacts",
        "child-artifacts",
        "parent-root",
        "child-root",
        "parent-meta",
    ] {
        let fx = Fixture::new()?;
        let (session, gate) = terminal_candidate(&fx, None, None, false)?;
        let child = child_path(&fx, &session, &gate)?;
        let mut action = Ok(());
        let mut called = false;
        let result = observe(
            &File::open(fx.root.path())?,
            session.run_id(),
            &gate,
            || {
                called = true;
                action = (|| -> std::io::Result<()> {
                    match mode {
                        "gate" => {
                            fs::rename(
                                session.run_dir().join(".normal-chat-runtime.lock"),
                                session.run_dir().join("detached-gate"),
                            )?;
                            fs::write(session.run_dir().join(".normal-chat-runtime.lock"), b"")?;
                            fs::set_permissions(
                                session.run_dir().join(".normal-chat-runtime.lock"),
                                fs::Permissions::from_mode(0o600),
                            )?;
                            fs::remove_file(session.run_dir().join("chain.meta"))?;
                        }
                        "root-record" => {
                            for e in fs::read_dir(session.run_dir().join("permits"))? {
                                let p = e?.path();
                                if p.extension().is_some_and(|x| x == "json") {
                                    fs::remove_file(p)?;
                                }
                            }
                        }
                        "family" => {
                            fs::remove_file(session.run_dir().join("family-authority.json"))?
                        }
                        "parent-artifacts" => {
                            super::super::super::replace(&session.run_dir().join("artifacts"))?
                        }
                        "child-artifacts" => {
                            super::super::super::replace(&child.join("artifacts"))?
                        }
                        "parent-root" => super::super::super::replace(session.run_dir())?,
                        "child-root" => super::super::super::replace(&child)?,
                        _ => fs::remove_file(session.run_dir().join("chain.meta"))?,
                    }
                    Ok(())
                })();
            },
        );
        action?;
        assert!(called);
        assert!(result.is_err(), "{mode}");
        if mode == "gate" || mode == "parent-meta" {
            assert!(
                !session.run_dir().join("chain.meta").exists(),
                "terminal parent metadata repaired"
            );
        }
        if mode == "family" {
            assert!(!session.run_dir().join("family-authority.json").exists());
        }
        if mode == "root-record" {
            assert!(fs::read_dir(session.run_dir().join("permits"))?
                .all(|e| e.is_ok_and(|v| v.path().extension().map_or(true, |x| x != "json"))));
        }
    }
    Ok(())
}
#[test]
fn retained_terminal_proof_rechecks_exact_log_meta_inventory_and_child_source() -> TestResult {
    for mode in [
        "recorded-time",
        "metadata",
        "extra-artifact",
        "missing-marker",
        "child-native",
    ] {
        let fx = Fixture::new()?;
        let (session, gate) = terminal_candidate(&fx, None, None, false)?;
        let child = child_path(&fx, &session, &gate)?;
        let p = verify(&File::open(fx.root.path())?, session.run_id(), &gate)?;
        match mode {
            "recorded-time" => {
                let mut rows: Vec<ReceiptV1> =
                    fs::read_to_string(session.run_dir().join("receipts.ndjson"))?
                        .lines()
                        .map(serde_json::from_str)
                        .collect::<Result<_, _>>()?;
                rows[8].recorded_time += TimeDelta::milliseconds(1);
                rewrite(session.run_dir(), rows)?;
            }
            "metadata" => {
                let path = session.run_dir().join("chain.meta");
                let mut m: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
                m["created_at"] = json!("2026-10-01T00:00:00Z");
                fs::write(path, jcs_canonical(&m)?)?;
            }
            "extra-artifact" => {
                ArtifactStore::from_run_root_fd(&File::open(session.run_dir())?, false)?.put(
                    b"unexplained",
                    "application/json",
                    None,
                )?;
            }
            "missing-marker" => {
                fs::remove_file(
                    session
                        .run_dir()
                        .join("artifacts")
                        .join(content_digest(p.marker())?.to_string()),
                )?;
            }
            _ => {
                fs::remove_file(child.join("family-authority.json")).or_else(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        fs::remove_dir_all(child.join("permits"))
                    } else {
                        Err(e)
                    }
                })?;
            }
        }
        let before = tree(fx.root.path())?;
        assert!(p.recheck().is_err(), "{mode}");
        assert_eq!(tree(fx.root.path())?, before, "{mode}");
    }
    Ok(())
}
#[test]
fn internally_consistent_marker_substitutions_do_not_replace_native_source_projection() -> TestResult
{
    for mode in ["child-head", "source-time", "child-phase"] {
        let fx = Fixture::new()?;
        let (session, gate) = terminal_candidate(&fx, None, None, false)?;
        let mut rows: Vec<ReceiptV1> =
            fs::read_to_string(session.run_dir().join("receipts.ndjson"))?
                .lines()
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()?;
        let store = ArtifactStore::from_run_root_fd(&File::open(session.run_dir())?, false)?;
        let old = rows[7].artifact_refs[0].clone();
        let mut marker = recursive_agent_contracts::parse_normal_chat_session_degradation_v1_bytes(
            &store.get(&old)?,
        )?;
        match mode {
            "child-head" => {
                marker.children[0].child_chain_head = ContentDigest::compute(b"not-the-child-head")
            }
            "source-time" => marker.family_closed_at -= TimeDelta::milliseconds(1),
            _ => {
                let row = &rows[3];
                marker.children[0].prepared_receipt_id =
                    recursive_agent_contracts::derive_receipt_id(
                        &recursive_agent_contracts::ReceiptIdentityMaterialV1 {
                            run_id: &row.run_id,
                            step_id: &row.step_id,
                            kind: &row.kind,
                            lineage: &row.lineage,
                            spec_digest: &row.spec_digest,
                            args_digest: &ContentDigest::compute(b"foreign-preparation"),
                            outcome: &row.outcome,
                            artifact_refs: &row.artifact_refs,
                            predecessor_chain_digest: &row.prev_chain_digest,
                        },
                    )?;
            }
        }
        marker.validate()?;
        rows[7].artifact_refs =
            vec![store.put(&jcs_canonical(&marker)?, "application/json", None)?];
        for name in [old.digest.to_string(), format!("{}.meta", old.digest)] {
            fs::remove_file(session.run_dir().join("artifacts").join(name))?;
        }
        rewrite(session.run_dir(), rows)?;
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
fn unknown_child_ledger_cannot_override_a_known_native_settlement() -> TestResult {
    let fx = Fixture::new()?;
    let (session, gate) = terminal_candidate(
        &fx,
        Some(NormalChatReportedStateV2::OutcomeUnknown),
        None,
        false,
    )?;
    let child = child_path(&fx, &session, &gate)?;
    let other = Fixture::new()?;
    let (known, known_child) = closed(&other, Some(NormalChatReportedStateV2::NotSent))?;
    assert_eq!(session.run_id(), known.run_id());
    assert_eq!(child.file_name(), known_child.file_name());
    fs::rename(
        child.join("permits"),
        fx._grant_root.path().join("original-child-permits"),
    )?;
    copy_tree(&known_child.join("permits"), &child.join("permits"))?;
    let before = tree(fx.root.path())?;
    assert!(verify(&File::open(fx.root.path())?, session.run_id(), &gate).is_err());
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}
