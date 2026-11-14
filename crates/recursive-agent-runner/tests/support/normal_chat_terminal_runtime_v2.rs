use super::*;
#[path = "normal_chat_historical_report_repair.rs"]
mod historical_repair;
#[path = "normal_chat_terminal_runtime_hostile.rs"]
mod hostile;
#[path = "normal_chat_native_recovery_runtime.rs"]
mod native_recovery;
#[path = "normal_chat_unknown_fence_runtime.rs"]
mod unknown_fence;
use recursive_agent_contracts::RunTerminalStateV1;
use recursive_agent_ledger::{
    verified_snapshot_expected_run_from_dir_fd, verify_child_links_in_runtime_root, AppendStage,
    ArtifactStore,
};
use recursive_agent_policy::{
    parse_normal_chat_executor_report_v2_bytes, NormalChatExecutorReportV2,
    NormalChatReportedStateV2, NormalChatSettlementInterruptionV2, PermitTransitionStage,
};
use recursive_agent_runner::NormalChatTerminalInterruptionV2 as TerminalStop;

fn complete_prefix(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let mut prefix = Vec::new();
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        if serde_json::from_slice::<recursive_agent_contracts::ReceiptV1>(line).is_err() {
            break;
        }
        prefix.extend_from_slice(line);
    }
    Ok(prefix)
}

pub(super) fn report(
    state: NormalChatReportedStateV2,
) -> Result<NormalChatExecutorReportV2, Box<dyn std::error::Error>> {
    let sent = state != NormalChatReportedStateV2::NotSent
        && state != NormalChatReportedStateV2::OutcomeUnknown;
    Ok(parse_normal_chat_executor_report_v2_bytes(
        &serde_json::to_vec(&json!({
            "schema":"recursive-agent.normal-chat-executor-report/v2","state":state,"duration_ms":if sent { 40 } else { 0 },
            "response":if sent { json!({"projection_schema":"ares-response-json-sorted-v1","digest":HOME,"byte_length":42,"complete":true}) } else { json!(null) },"usage":null,
        }))?,
    )?)
}
fn fresh(
    fx: &Fixture,
    service: &RuntimeService,
    session: &recursive_agent_runner::RuntimeNormalChatSessionV1,
) -> Result<(NormalChatCallRequestV2, ContentDigest), Box<dyn std::error::Error>> {
    let req = request(fx, session, "intent:one")?;
    let cap = match service.begin_normal_chat_attempt(session, &req)? {
        RuntimeNormalChatBeginV2::Fresh(cap) => cap,
        _ => return Err("Fresh absent".into()),
    };
    Ok((req, cap.preflight_digest().clone()))
}

#[test]
fn terminal_runtime_reports_all_states_and_verifies_child_parent_closure_after_expiry() -> TestResult
{
    for state in [
        NormalChatReportedStateV2::Succeeded,
        NormalChatReportedStateV2::Failed,
        NormalChatReportedStateV2::Cancelled,
        NormalChatReportedStateV2::Interrupted,
        NormalChatReportedStateV2::TimedOut,
        NormalChatReportedStateV2::NotSent,
        NormalChatReportedStateV2::OutcomeUnknown,
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let (req, preflight) = fresh(&fx, &service, &session)?;
        fx.clock.0.store(400_000, Ordering::SeqCst);
        let done =
            service.settle_normal_chat_attempt(&session, &req, &preflight, &report(state)?)?;
        let expected = if state == NormalChatReportedStateV2::Succeeded {
            RunTerminalStateV1::Succeeded
        } else {
            RunTerminalStateV1::Failed
        };
        assert_eq!(done.terminal_state(), expected);
        let child = verified_snapshot_expected_run_from_dir_fd(
            &File::open(done.child_run_dir())?,
            &done.attempt().run_id()?,
        )?;
        let _ = child;
        let parent = appendable_snapshot_expected_run_from_dir_fd(
            &File::open(session.run_dir())?,
            session.run_id(),
        )?;
        assert_eq!(parent.receipts().len(), 6);
        assert_eq!(
            parent.receipts().last().ok_or("closure absent")?.kind,
            ReceiptKindV1::ChildClosed
        );
        verify_child_links_in_runtime_root(
            &parent,
            &ArtifactStore::from_run_root_fd(&File::open(session.run_dir())?, false)?,
            fx.root.path(),
            true,
        )?;
        assert!(!parent.verification().current_strict_success);
        assert!(matches!(
            service.begin_normal_chat_attempt(&session, &req)?,
            RuntimeNormalChatBeginV2::Existing(_)
        ));
        assert!(service
            .begin_normal_chat_attempt(&session, &request(&fx, &session, "intent:two")?)
            .is_err());
    }
    Ok(())
}

#[test]
fn complete_canonical_eof_receipt_without_newline_keeps_original_bytes_times_and_heads(
) -> TestResult {
    for parent_eof in [false, true] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let (req, preflight) = fresh(&fx, &service, &session)?;
        let value = report(NormalChatReportedStateV2::Succeeded)?;
        let original = service.settle_normal_chat_attempt(&session, &req, &preflight, &value)?;
        let path = if parent_eof {
            session.run_dir().join("receipts.ndjson")
        } else {
            original.child_run_dir().join("receipts.ndjson")
        };
        let bytes = fs::read(&path)?;
        assert_eq!(bytes.last(), Some(&b'\n'));
        fs::write(&path, &bytes[..bytes.len() - 1])?;
        let prefix = complete_prefix(&path)?;
        assert_eq!(prefix, bytes[..bytes.len() - 1]);
        fx.clock.0.store(500_000, Ordering::SeqCst);
        let retried = service.settle_normal_chat_attempt(&session, &req, &preflight, &value)?;
        assert_eq!(fs::read(&path)?, bytes);
        assert_eq!(original.child_chain_head(), retried.child_chain_head());
        assert_eq!(original.parent_chain_head(), retried.parent_chain_head());
        assert_eq!(original.settlement(), retried.settlement());
    }
    Ok(())
}

#[test]
fn terminal_runtime_exact_retry_preserves_receipts_and_conflicting_report_rejects() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (req, preflight) = fresh(&fx, &service, &session)?;
    let value = report(NormalChatReportedStateV2::Succeeded)?;
    let done = service.settle_normal_chat_attempt(&session, &req, &preflight, &value)?;
    let child = fs::read(done.child_run_dir().join("receipts.ndjson"))?;
    let parent = fs::read(session.run_dir().join("receipts.ndjson"))?;
    let family = fs::read(session.run_dir().join("family-authority.json"))?;
    fx.clock.0.store(900_000, Ordering::SeqCst);
    let retried = service.settle_normal_chat_attempt(&session, &req, &preflight, &value)?;
    assert_eq!(done.settlement(), retried.settlement());
    assert_eq!(
        child,
        fs::read(done.child_run_dir().join("receipts.ndjson"))?
    );
    assert_eq!(parent, fs::read(session.run_dir().join("receipts.ndjson"))?);
    assert_eq!(
        family,
        fs::read(session.run_dir().join("family-authority.json"))?
    );
    let mut conflict = value;
    conflict.duration_ms += 1;
    assert!(service
        .settle_normal_chat_attempt(&session, &req, &preflight, &conflict)
        .is_err());
    Ok(())
}

#[test]
fn terminal_runtime_fault_matrix_recovers_only_exact_metadata_without_refund_or_send() -> TestResult
{
    let mut faults = vec![
        TerminalStop::AfterPolicy,
        TerminalStop::AfterControlClose,
        TerminalStop::Artifact { ordinal: 0 },
        TerminalStop::ParentArtifact,
        TerminalStop::BeforeReturn,
    ];
    for stage in [
        PermitTransitionStage::TempWrite,
        PermitTransitionStage::TempFsync,
        PermitTransitionStage::Rename,
        PermitTransitionStage::DirectoryFsync,
    ] {
        faults.push(TerminalStop::Policy(
            NormalChatSettlementInterruptionV2::ChildOutcome(stage),
        ));
        faults.push(TerminalStop::ControlClose(stage));
    }
    for stage in [
        AppendStage::PartialRecord,
        AppendStage::FullReceiptAppend,
        AppendStage::LogFsync,
        AppendStage::MetadataTempWrite,
        AppendStage::MetadataFsync,
        AppendStage::MetadataRename,
        AppendStage::DirectoryFsync,
    ] {
        for ordinal in 0..3 {
            faults.push(TerminalStop::ChildReceipt { ordinal, stage });
        }
        faults.push(TerminalStop::ParentReceipt(stage));
    }
    for fault in faults {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let (req, preflight) = fresh(&fx, &service, &session)?;
        let value = report(NormalChatReportedStateV2::Succeeded)?;
        let family = fs::read(session.run_dir().join("family-authority.json"))?;
        assert!(
            service
                .settle_normal_chat_attempt_with_interruption(
                    &session,
                    &req,
                    &preflight,
                    &value,
                    Some(fault)
                )
                .is_err(),
            "{fault:?}"
        );
        let (canonical_family, _, child_dir, policy) = hostile::child_info(&fx, &session)?;
        let child_prefix = complete_prefix(&child_dir.join("receipts.ndjson"))?;
        let parent_prefix = complete_prefix(&session.run_dir().join("receipts.ndjson"))?;
        let old_view = policy.read_normal_chat_attempt_v2(&canonical_family, "intent:one")?;
        fx.clock.0.store(100, Ordering::SeqCst);
        let done = service.settle_normal_chat_attempt(&session, &req, &preflight, &value)?;
        assert!(
            fs::read(child_dir.join("receipts.ndjson"))?.starts_with(&child_prefix),
            "{fault:?} changed retained child bytes"
        );
        assert!(
            fs::read(session.run_dir().join("receipts.ndjson"))?.starts_with(&parent_prefix),
            "{fault:?} changed retained parent bytes"
        );
        if let Some(old) = old_view.settlement {
            assert_eq!(
                &old,
                done.settlement(),
                "{fault:?} rewrote settlement time/digest"
            );
        }
        if let Some(old) = old_view.local_control {
            if matches!(
                old.state,
                recursive_agent_policy::PermitEvidenceStateV1::Revoked { .. }
            ) {
                assert_eq!(
                    policy
                        .read_normal_chat_attempt_v2(&canonical_family, "intent:one")?
                        .local_control
                        .as_ref(),
                    Some(&old),
                    "{fault:?} rewrote closure"
                );
            }
        }
        assert_eq!(
            done.terminal_state(),
            RunTerminalStateV1::Succeeded,
            "{fault:?}"
        );
        assert_eq!(
            family,
            fs::read(session.run_dir().join("family-authority.json"))?,
            "{fault:?}"
        );
        assert!(
            !matches!(
                service.begin_normal_chat_attempt(&session, &req),
                Ok(RuntimeNormalChatBeginV2::Fresh(_))
            ),
            "{fault:?}"
        );
    }
    Ok(())
}
