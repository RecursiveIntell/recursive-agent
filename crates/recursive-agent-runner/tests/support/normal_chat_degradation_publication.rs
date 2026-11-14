//! Canonical owned publication, not an offline candidate rewrite.
use super::*;
use recursive_agent_ledger::{
    verify_degraded_normal_chat_session_from_runtime_root_fd,
    NormalChatSessionPublicationInterruptionV1 as Fault,
};

#[test]
fn owned_publication_verifies_real_unknown_history_and_preserves_prefix() -> TestResult {
    for state in [None, Some(NormalChatReportedStateV2::OutcomeUnknown)] {
        let fx = Fixture::new()?;
        let (session, gate) = native_closed(&fx, state, None, false)?;
        let prefix = fs::read(session.run_dir().join("receipts.ndjson"))?;
        let output = File::open(fx.root.path())?;
        let plan = prepare(&output, session.run_id(), &gate)?;
        let marker = plan.marker().clone();
        let proof = plan.publish()?;
        assert_eq!(proof.terminal_state(), RunTerminalStateV1::Failed);
        assert_eq!(proof.marker(), &marker);
        assert_eq!(proof.child_count(), 1);
        assert_eq!(proof.unknown_child_count(), 1);
        assert!(proof.verification().current_strict_success);
        assert!(fs::read(session.run_dir().join("receipts.ndjson"))?.starts_with(&prefix));
        proof.recheck()?;
        let after = tree(fx.root.path())?;
        verify_degraded_normal_chat_session_from_runtime_root_fd(&output, session.run_id(), &gate)?
            .recheck()?;
        assert_eq!(tree(fx.root.path())?, after);
        assert!(matches!(
            recursive_agent_ledger::verify_directory_bound(&recursive_agent_ledger::RunPaths::new(
                session.run_dir()
            )),
            Err(recursive_agent_ledger::LedgerError::NormalChatFamilyScopeRequired)
        ));
    }
    Ok(())
}

#[test]
fn publication_interruption_preserves_closed_authority_and_never_returns_terminal_proof(
) -> TestResult {
    for fault in [
        Fault::AfterRootArtifact,
        Fault::AfterMarkerArtifact,
        Fault::Receipt {
            ordinal: 0,
            stage: recursive_agent_ledger::AppendStage::PartialRecord,
        },
        Fault::Receipt {
            ordinal: 1,
            stage: recursive_agent_ledger::AppendStage::LogFsync,
        },
        Fault::Receipt {
            ordinal: 2,
            stage: recursive_agent_ledger::AppendStage::MetadataRename,
        },
    ] {
        let fx = Fixture::new()?;
        let (session, gate) = native_closed(&fx, None, None, false)?;
        let root = File::open(session.run_dir())?;
        let policy = DurablePermitStore::require_existing_from_run_root_fd(&root)?;
        let native_before = policy.read_normal_chat_session_control_record()?;
        let prefix = fs::read(session.run_dir().join("receipts.ndjson"))?;
        let output = File::open(fx.root.path())?;
        let plan = prepare(&output, session.run_id(), &gate)?;
        assert!(plan.publish_with_interruption(Some(fault)).is_err());
        assert_eq!(
            policy.read_normal_chat_session_control_record()?,
            native_before
        );
        assert!(fs::read(session.run_dir().join("receipts.ndjson"))?.starts_with(&prefix));
        // Initial publication has no repair/retry branch. Scoped recovery is a
        // separate required gate, never implicit re-admission or success.
        assert!(prepare(&output, session.run_id(), &gate).is_err());
    }
    Ok(())
}
