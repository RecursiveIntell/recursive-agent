use super::*;
#[path = "normal_chat_degradation_preparation_hostile.rs"]
mod hostile;
#[path = "normal_chat_degradation_publication.rs"]
mod publication;
#[path = "normal_chat_degradation_publication_recovery.rs"]
mod publication_recovery;
#[path = "normal_chat_scoped_degraded_terminal.rs"]
mod scoped_terminal;
use recursive_agent_contracts::{
    ReceiptOutcomeV1, RunTerminalStateV1, NORMAL_CHAT_CHILD_OUTCOME_UNKNOWN_REASON_V1,
    NORMAL_CHAT_SESSION_CANCELLED_REASON_V1,
};
use recursive_agent_ledger::{
    make_receipt, prepare_normal_chat_session_degradation_from_runtime_root_fd as prepare,
    NormalChatSessionDegradationPreparationErrorV1 as Error, NormalChatSessionGateV1 as Gate,
};
use recursive_agent_policy::{
    DurablePermitStore, NormalChatReportedStateV2, PermitRevocationReasonV1,
};
type Source = (recursive_agent_runner::RuntimeNormalChatSessionV1, Gate);
fn native_closed(
    fx: &Fixture,
    state: Option<NormalChatReportedStateV2>,
    reason: Option<PermitRevocationReasonV1>,
    cancel_family: bool,
) -> Result<Source, Box<dyn std::error::Error>> {
    let (session, _) = closed(fx, state)?;
    let root = File::open(session.run_dir())?;
    let held = Gate::acquire_existing(&root)?;
    let proof = verify_closed_normal_chat_family_from_runtime_root_fd(
        &File::open(fx.root.path())?,
        session.run_id(),
    )?;
    let policy = DurablePermitStore::require_existing_from_run_root_fd(&root)?;
    let family = FamilyAuthorityStore::require_existing_from_dir_fd(
        &root,
        proof.context().session_family_grant_v2()?,
    )?;
    if let Some(reason) = reason {
        policy.revoke(
            &proof.context().root_control.permit_id,
            reason,
            start() + TimeDelta::seconds(3),
        )?;
    }
    if cancel_family {
        family.revoke_parent(start() + TimeDelta::seconds(3))?;
    }
    policy.close_normal_chat_session_v2(
        &family,
        proof.context(),
        &family.read_normal_chat_session_snapshot_v2()?,
        start() + TimeDelta::seconds(4),
        || start() + TimeDelta::seconds(4),
    )?;
    Ok((session, held))
}
#[test]
fn pure_preparation_requires_real_closed_unknown_sources_and_is_byte_idempotent() -> TestResult {
    for state in [None, Some(NormalChatReportedStateV2::OutcomeUnknown)] {
        let fx = Fixture::new()?;
        let (session, gate) = native_closed(&fx, state, None, false)?;
        fs::remove_file(fx._grant_root.path().join("grant.json"))?;
        let before = tree(fx.root.path())?;
        let output = File::open(fx.root.path())?;
        let plan = prepare(&output, session.run_id(), &gate)?;
        let second = prepare(&output, session.run_id(), &gate)?;
        assert_eq!(plan.marker_bytes(), second.marker_bytes());
        assert_eq!(plan.marker().parent_run_id, *session.run_id());
        assert_eq!(
            plan.outcome(),
            &ReceiptOutcomeV1::Failed {
                reason: NORMAL_CHAT_CHILD_OUTCOME_UNKNOWN_REASON_V1.into()
            }
        );
        assert_eq!(
            plan.outcome().terminal_state(),
            Some(RunTerminalStateV1::Failed)
        );
        assert_eq!(
            recursive_agent_contracts::parse_normal_chat_session_degradation_v1_bytes(
                plan.marker_bytes()
            )?,
            *plan.marker()
        );
        let prefix = appendable_snapshot_expected_run_from_dir_fd(
            &File::open(session.run_dir())?,
            session.run_id(),
        )?;
        let head = ContentDigest::from_hex(prefix.verification().final_head.clone())?;
        let row = make_receipt(plan.root_revocation_draft(), head)?;
        assert_eq!(row.receipt_id, plan.marker().root_revocation_receipt_id);
        assert_eq!(
            plan.marker().children[0].prepared_receipt_id,
            prefix.receipts()[3].receipt_id
        );
        assert_eq!(
            plan.marker().children[0].closed_receipt_id,
            prefix.receipts()[5].receipt_id
        );
        assert_eq!(plan.marker().finalized_at, start() + TimeDelta::seconds(4));
        assert_eq!(plan.marker().children[0].unknown_source.as_ref().map(|s|matches!(s,recursive_agent_contracts::NormalChatUnknownSourceRefV1::MissingExecutorOutcomeV1{..})),Some(state.is_none()));
        plan.recheck()?;
        assert!(plan.projected_artifact_bytes() <= plan.artifact_ceiling());
        assert_eq!(tree(fx.root.path())?, before);
    }
    Ok(())
}
#[test]
fn known_only_families_never_become_unknown_even_when_cancelled_or_denied() -> TestResult {
    for (state, reason) in [
        (NormalChatReportedStateV2::Succeeded, None),
        (NormalChatReportedStateV2::Failed, None),
        (NormalChatReportedStateV2::NotSent, None),
        (
            NormalChatReportedStateV2::NotSent,
            Some(PermitRevocationReasonV1::OperationCancelled),
        ),
        (
            NormalChatReportedStateV2::Failed,
            Some(PermitRevocationReasonV1::PolicySuperseded),
        ),
    ] {
        let fx = Fixture::new()?;
        let (session, gate) = native_closed(&fx, Some(state), reason, false)?;
        let before = tree(fx.root.path())?;
        assert!(matches!(
            prepare(&File::open(fx.root.path())?, session.run_id(), &gate),
            Err(Error::Invalid("no actual unknown child"))
        ));
        assert_eq!(tree(fx.root.path())?, before);
    }
    Ok(())
}
#[test]
fn actual_native_cancellation_precedes_policy_denial_without_retiming_sources() -> TestResult {
    for (reason, cancel, outcome) in [
        (
            Some(PermitRevocationReasonV1::PolicySuperseded),
            false,
            ReceiptOutcomeV1::Denied,
        ),
        (
            Some(PermitRevocationReasonV1::OperationCancelled),
            false,
            ReceiptOutcomeV1::Cancelled {
                reason: NORMAL_CHAT_SESSION_CANCELLED_REASON_V1.into(),
            },
        ),
        (
            Some(PermitRevocationReasonV1::PolicySuperseded),
            true,
            ReceiptOutcomeV1::Cancelled {
                reason: NORMAL_CHAT_SESSION_CANCELLED_REASON_V1.into(),
            },
        ),
    ] {
        let fx = Fixture::new()?;
        let (session, gate) = native_closed(&fx, None, reason, cancel)?;
        let before = tree(fx.root.path())?;
        let plan = prepare(&File::open(fx.root.path())?, session.run_id(), &gate)?;
        assert_eq!(plan.outcome(), &outcome);
        assert_eq!(plan.marker().finalized_at, start() + TimeDelta::seconds(3));
        plan.recheck()?;
        assert_eq!(tree(fx.root.path())?, before);
    }
    Ok(())
}
#[test]
fn issued_root_or_wrong_root_guard_cannot_prepare_or_repair_source() -> TestResult {
    let fx = Fixture::new()?;
    let (session, _) = closed(&fx, None)?;
    let root = File::open(session.run_dir())?;
    let gate = Gate::acquire_existing(&root)?;
    let before = tree(fx.root.path())?;
    assert!(matches!(
        prepare(&File::open(fx.root.path())?, session.run_id(), &gate),
        Err(Error::Policy(_))
    ));
    assert_eq!(tree(fx.root.path())?, before);
    let other = tempfile::tempdir()?;
    let wrong = Gate::acquire(&File::open(other.path())?)?;
    assert!(matches!(
        prepare(&File::open(fx.root.path())?, session.run_id(), &wrong),
        Err(Error::Gate(
            recursive_agent_ledger::NormalChatSessionGateErrorV1::RootMismatch
        ))
    ));
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}
