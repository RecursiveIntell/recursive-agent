use super::*;
#[path = "normal_chat_degradation_preparation.rs"]
mod degradation_preparation;
#[path = "normal_chat_native_family_proof_hostile.rs"]
mod hostile;
#[path = "normal_chat_session_marker_refusal.rs"]
mod marker_refusal;
#[path = "normal_chat_native_family_proof_matrix.rs"]
mod matrix;
#[path = "normal_chat_parent_recovery_runtime.rs"]
mod parent_recovery;
#[path = "normal_chat_native_family_phase_binding.rs"]
mod phase_binding;
use recursive_agent_ledger::{
    verify_closed_normal_chat_family_from_runtime_root_fd,
    verify_closed_normal_chat_family_from_runtime_root_fd_with_observer,
};

fn closed(
    fx: &Fixture,
    state: Option<recursive_agent_policy::NormalChatReportedStateV2>,
) -> Result<(recursive_agent_runner::RuntimeNormalChatSessionV1, PathBuf), Box<dyn std::error::Error>>
{
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (request, preflight, child, _) = admitted(fx, &service, &session)?;
    if let Some(state) = state {
        service.settle_normal_chat_attempt(
            &session,
            &request,
            &preflight,
            &super::super::terminal::report(state)?,
        )?;
    } else {
        fx.clock.0.store(2000, Ordering::SeqCst);
        runtime(fx.root.path(), fx.clock.clone())?
            .with_expired_normal_chat_recovery()
            .recover_expired_normal_chat_attempt(session.run_id(), "intent:one")?;
    }
    Ok((session, child))
}
#[test]
fn descriptor_root_family_proof_distinguishes_native_unknown_from_known_failed_children(
) -> TestResult {
    for state in [
        None,
        Some(recursive_agent_policy::NormalChatReportedStateV2::OutcomeUnknown),
        Some(recursive_agent_policy::NormalChatReportedStateV2::NotSent),
        Some(recursive_agent_policy::NormalChatReportedStateV2::Failed),
        Some(recursive_agent_policy::NormalChatReportedStateV2::Succeeded),
    ] {
        let fx = Fixture::new()?;
        let (session, _) = closed(&fx, state)?;
        let before = tree(fx.root.path())?;
        fs::remove_file(fx._grant_root.path().join("grant.json"))?;
        let proof = verify_closed_normal_chat_family_from_runtime_root_fd(
            &File::open(fx.root.path())?,
            session.run_id(),
        )?;
        assert_eq!(proof.parent_run_id(), session.run_id());
        assert_eq!(proof.child_count(), 1);
        assert_eq!(
            proof.unknown_child_count() > 0,
            state.is_none()
                || state == Some(recursive_agent_policy::NormalChatReportedStateV2::OutcomeUnknown)
        );
        proof.recheck()?;
        assert_eq!(tree(fx.root.path())?, before);
    }
    Ok(())
}
#[test]
fn pending_or_missing_native_and_child_evidence_never_becomes_a_closed_family_proof() -> TestResult
{
    for missing in [
        "pending",
        "child-native",
        "parent-native",
        "family",
        "child-artifacts",
    ] {
        let fx = Fixture::new()?;
        let (session, child) = if missing == "pending" {
            let service = fx.service()?;
            let session = service.open_normal_chat_session("conversation:fixture")?;
            let (_, _, child, _) = admitted(&fx, &service, &session)?;
            (session, child)
        } else {
            closed(&fx, None)?
        };
        let path = match missing {
            "child-native" => Some(child.join("permits")),
            "parent-native" => Some(session.run_dir().join("permits")),
            "family" => Some(session.run_dir().join("family-authority.json")),
            "child-artifacts" => Some(child.join("artifacts")),
            _ => None,
        };
        if let Some(path) = &path {
            fs::rename(path, fx._grant_root.path().join("detached"))?;
        }
        let before = tree(fx.root.path())?;
        assert!(
            verify_closed_normal_chat_family_from_runtime_root_fd(
                &File::open(fx.root.path())?,
                session.run_id()
            )
            .is_err(),
            "{missing}"
        );
        if let Some(path) = path {
            assert!(!path.exists(), "{missing} recreated");
        }
        assert_eq!(tree(fx.root.path())?, before);
    }
    Ok(())
}
#[test]
fn proof_rechecks_retained_native_root_and_child_locator_identities() -> TestResult {
    for target in [
        "parent-root",
        "child-root",
        "parent-artifacts",
        "child-artifacts",
        "parent-permits",
        "child-permits",
    ] {
        let fx = Fixture::new()?;
        let (session, child) = closed(&fx, None)?;
        let path = match target {
            "parent-root" => session.run_dir().to_path_buf(),
            "child-root" => child.clone(),
            "parent-artifacts" => session.run_dir().join("artifacts"),
            "child-artifacts" => child.join("artifacts"),
            "parent-permits" => session.run_dir().join("permits"),
            _ => child.join("permits"),
        };
        let mut error = None;
        let mut called = false;
        let result = verify_closed_normal_chat_family_from_runtime_root_fd_with_observer(
            &File::open(fx.root.path())?,
            session.run_id(),
            || {
                called = true;
                error = replace(&path).err();
            },
        );
        if let Some(error) = error {
            return Err(error.into());
        }
        assert!(called, "{target} observer not reached");
        assert!(result.is_err(), "{target} escaped pinned proof");
    }
    Ok(())
}
#[test]
fn extra_child_inventory_and_native_role_downgrade_reject_without_repair() -> TestResult {
    for mode in ["orphan", "downgrade", "fence"] {
        let fx = Fixture::new()?;
        let (session, child) = closed(&fx, None)?;
        if mode == "orphan" {
            recursive_agent_ledger::ArtifactStore::from_run_root_fd(&File::open(&child)?, false)?
                .put(b"unknown artifact", "text/plain", None)?;
        } else if mode == "fence" {
            let p = session.run_dir().join("family-authority.json");
            let mut raw: serde_json::Value = serde_json::from_slice(&fs::read(&p)?)?;
            raw["normal_chat_session"]["closed_at"] = json!(null);
            fs::write(p, recursive_agent_contracts::jcs_canonical(&raw)?)?;
        } else {
            for entry in fs::read_dir(child.join("permits"))? {
                let e = entry?;
                if e.path().extension().is_some_and(|x| x == "json") {
                    let mut raw: serde_json::Value = serde_json::from_slice(&fs::read(e.path())?)?;
                    if raw["normal_chat_attempt_v2"]["role"] == json!("recovered") {
                        raw["normal_chat_attempt_v2"] = json!({"role":"effect"});
                        fs::write(e.path(), recursive_agent_contracts::jcs_canonical(&raw)?)?;
                    }
                }
            }
        }
        let before = tree(fx.root.path())?;
        assert!(
            verify_closed_normal_chat_family_from_runtime_root_fd(
                &File::open(fx.root.path())?,
                session.run_id()
            )
            .is_err(),
            "{mode}"
        );
        assert_eq!(tree(fx.root.path())?, before);
    }
    Ok(())
}
