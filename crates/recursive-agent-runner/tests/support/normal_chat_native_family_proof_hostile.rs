use super::*;
use recursive_agent_policy::{DurablePermitStore, NormalChatGrantContextV2};
#[test]
fn native_root_close_changes_the_old_proof_but_remains_verifiable_before_ledger_finalization(
) -> TestResult {
    let fx = Fixture::new()?;
    let (session, _) = closed(&fx, None)?;
    let output = File::open(fx.root.path())?;
    let before = verify_closed_normal_chat_family_from_runtime_root_fd(&output, session.run_id())?;
    let context = before.context().clone();
    let root = File::open(session.run_dir())?;
    let policy = DurablePermitStore::require_existing_from_run_root_fd(&root)?;
    let family = FamilyAuthorityStore::require_existing_from_dir_fd(
        &root,
        context.session_family_grant_v2()?,
    )?;
    let closed = policy.close_normal_chat_session_v2(
        &family,
        &context,
        before.native_snapshot(),
        start() + TimeDelta::seconds(3),
        || start() + TimeDelta::seconds(3),
    )?;
    assert!(before.recheck().is_err());
    let after = verify_closed_normal_chat_family_from_runtime_root_fd(&output, session.run_id())?;
    assert_eq!(after.native_root_record(), &closed.root_control);
    assert_eq!(after.unknown_child_count(), 1);
    after.recheck()?;
    Ok(())
}
#[test]
fn known_and_unknown_children_form_one_exact_complete_native_family() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    for (intent, state) in [
        (
            "intent:known",
            recursive_agent_policy::NormalChatReportedStateV2::NotSent,
        ),
        (
            "intent:unknown",
            recursive_agent_policy::NormalChatReportedStateV2::OutcomeUnknown,
        ),
    ] {
        let request = super::super::super::request(&fx, &session, intent)?;
        let cap = match service.begin_normal_chat_attempt(&session, &request)? {
            RuntimeNormalChatBeginV2::Fresh(cap) => cap,
            _ => return Err("not Fresh".into()),
        };
        service.settle_normal_chat_attempt(
            &session,
            &request,
            cap.preflight_digest(),
            &super::super::super::terminal::report(state)?,
        )?;
    }
    let before = tree(fx.root.path())?;
    let proof = verify_closed_normal_chat_family_from_runtime_root_fd(
        &File::open(fx.root.path())?,
        session.run_id(),
    )?;
    assert_eq!(proof.child_count(), 2);
    assert_eq!(proof.unknown_child_count(), 1);
    assert!(!proof.children()[0].disposition().is_unknown());
    assert!(proof.children()[1].disposition().is_unknown());
    proof.recheck()?;
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}
#[test]
fn returned_proof_recheck_rejects_later_source_changes_and_exposes_no_mutator() -> TestResult {
    let fx = Fixture::new()?;
    let (session, child) = closed(&fx, None)?;
    let proof = verify_closed_normal_chat_family_from_runtime_root_fd(
        &File::open(fx.root.path())?,
        session.run_id(),
    )?;
    replace(&child.join("artifacts"))?;
    assert!(proof.recheck().is_err());
    Ok(())
}
#[test]
fn symlinked_run_locator_is_not_followed_outside_pinned_output_scope() -> TestResult {
    let fx = Fixture::new()?;
    let (session, child) = closed(&fx, None)?;
    let detached = fx._grant_root.path().join("detached-child");
    fs::rename(&child, &detached)?;
    std::os::unix::fs::symlink(&detached, &child)?;
    assert!(verify_closed_normal_chat_family_from_runtime_root_fd(
        &File::open(fx.root.path())?,
        session.run_id()
    )
    .is_err());
    Ok(())
}
#[test]
fn self_consistent_unknown_chain_cannot_override_a_known_native_outcome() -> TestResult {
    let fx = Fixture::new()?;
    let (session, child) = closed(
        &fx,
        Some(recursive_agent_policy::NormalChatReportedStateV2::NotSent),
    )?;
    let other = Fixture::new()?;
    let (other_session, other_child) = closed(
        &other,
        Some(recursive_agent_policy::NormalChatReportedStateV2::OutcomeUnknown),
    )?;
    assert_eq!(session.run_id(), other_session.run_id());
    assert_eq!(child.file_name(), other_child.file_name());
    let original = fx._grant_root.path().join("original-artifacts");
    fs::rename(child.join("artifacts"), &original)?;
    copy_tree(&other_child.join("artifacts"), &child.join("artifacts"))?;
    for name in ["receipts.ndjson", "chain.meta"] {
        fs::copy(other_child.join(name), child.join(name))?;
    }
    let root = File::open(&child)?;
    let rows: Vec<recursive_agent_contracts::ReceiptV1> =
        fs::read_to_string(child.join("receipts.ndjson"))?
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
    let snapshot =
        recursive_agent_ledger::verified_snapshot_expected_run_from_dir_fd(&root, &rows[0].run_id)?;
    assert_eq!(
        snapshot.verification().terminal_state,
        recursive_agent_contracts::RunTerminalStateV1::Failed
    );
    let parent = File::open(session.run_dir())?;
    let native_root = DurablePermitStore::require_existing_from_run_root_fd(&parent)?;
    let context = NormalChatGrantContextV2 {
        grant: fx.authority.grant().clone(),
        session: session.session().clone(),
        root_control: native_root
            .read_normal_chat_session_control_record()?
            .ok_or("root absent")?
            .permit,
    };
    let family = FamilyAuthorityStore::require_existing_from_dir_fd(
        &parent,
        context.session_family_grant_v2()?,
    )?;
    let reservation = family
        .read_normal_chat_reservation("intent:one")?
        .ok_or("reservation absent")?;
    let before = tree(fx.root.path())?;
    assert!(
        recursive_agent_ledger::verify_closed_normal_chat_child_from_dir_fd(
            &root,
            &family,
            &context,
            &reservation
        )
        .is_err()
    );
    assert!(verify_closed_normal_chat_family_from_runtime_root_fd(
        &File::open(fx.root.path())?,
        session.run_id()
    )
    .is_err());
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}
