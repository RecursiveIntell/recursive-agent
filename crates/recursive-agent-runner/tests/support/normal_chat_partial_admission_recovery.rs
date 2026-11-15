use super::*;
#[path = "normal_chat_partial_admission_matrix.rs"]
mod matrix;
#[path = "normal_chat_partial_recovery_publication.rs"]
mod publication;
#[path = "normal_chat_remaining_recovery_hostile.rs"]
mod remaining;
#[path = "normal_chat_partial_recovery_sources.rs"]
mod sources;
use std::collections::BTreeMap;
use std::path::PathBuf;
fn tree(path: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>, Box<dyn std::error::Error>> {
    fn visit(base: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) -> TestResult {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                visit(base, &entry.path(), out)?;
            } else {
                out.insert(
                    entry.path().strip_prefix(base)?.to_path_buf(),
                    fs::read(entry.path())?,
                );
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    visit(path, path, &mut out)?;
    Ok(out)
}

#[test]
fn prechild_prefixes_terminalize_explicitly_without_allocating_a_child() -> TestResult {
    for stop in [
        Stop::AfterRequestArtifact,
        Stop::AfterPreparation,
        Stop::AfterReservation,
        Stop::AfterLinkArtifact,
        Stop::AfterLink,
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let req = request(&fx, &session, "intent:one")?;
        assert!(service
            .begin_normal_chat_attempt_with_interruption(&session, &req, Some(stop))
            .is_err());
        let result = runtime(fx.root.path(), fx.clock.clone())?
            .with_interrupted_normal_chat_recovery()
            .recover_prechild_normal_chat_admission(session.run_id(), "intent:one")?;
        assert_eq!(
            result.terminal_state(),
            recursive_agent_contracts::RunTerminalStateV1::Failed
        );
        let before = tree(fx.root.path())?;
        let again = runtime(fx.root.path(), fx.clock.clone())?
            .with_interrupted_normal_chat_recovery()
            .recover_prechild_normal_chat_admission(session.run_id(), "intent:one")?;
        assert_eq!(result.chain_head(), again.chain_head());
        assert_eq!(tree(fx.root.path())?, before);
        assert!(service.close_normal_chat_session(&session).is_err());
        assert!(service
            .resume_normal_chat_session("conversation:fixture")
            .is_err());
        assert!(!matches!(
            service.begin_normal_chat_attempt(&session, &req),
            Ok(RuntimeNormalChatBeginV2::Fresh(_))
        ));
    }
    Ok(())
}

#[test]
fn interrupted_prepared_control_recovers_without_fabricating_consumption() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:one")?;
    let stop = Stop::Policy(
        recursive_agent_policy::NormalChatBeginInterruptionV2::Control(
            recursive_agent_policy::PermitTransitionStage::Rename,
        ),
    );
    assert!(service
        .begin_normal_chat_attempt_with_interruption(&session, &req, Some(stop))
        .is_err());
    let result = runtime(fx.root.path(), fx.clock.clone())?
        .with_interrupted_normal_chat_recovery()
        .recover_prepared_normal_chat_attempt(session.run_id(), "intent:one")?;
    assert_eq!(
        result.terminal_state(),
        recursive_agent_contracts::RunTerminalStateV1::Failed
    );
    let rows: Vec<recursive_agent_contracts::ReceiptV1> =
        fs::read_to_string(result.child_run_dir().join("receipts.ndjson"))?
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
    assert!(rows.iter().all(|r| r.kind != ReceiptKindV1::PermitConsumed
        && r.kind != ReceiptKindV1::NormalChatAttemptAdmittedV2));
    let before = tree(fx.root.path())?;
    runtime(fx.root.path(), fx.clock.clone())?
        .with_interrupted_normal_chat_recovery()
        .recover_prepared_normal_chat_attempt(session.run_id(), "intent:one")?;
    assert!(service.close_normal_chat_session(&session).is_err());
    assert!(service
        .resume_normal_chat_session("conversation:fixture")
        .is_err());
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}

#[test]
fn interrupted_consumed_admission_recovers_terminal_without_report_or_send() -> TestResult {
    for stop in [
        Stop::AfterPolicyConsume,
        Stop::ChildReceipt {
            ordinal: 3,
            stage: recursive_agent_ledger::AppendStage::FullReceiptAppend,
        },
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let req = request(&fx, &session, "intent:one")?;
        assert!(service
            .begin_normal_chat_attempt_with_interruption(&session, &req, Some(stop))
            .is_err());
        let recovery =
            runtime(fx.root.path(), fx.clock.clone())?.with_interrupted_normal_chat_recovery();
        let result =
            recovery.recover_interrupted_normal_chat_attempt(session.run_id(), "intent:one")?;
        assert_eq!(
            result.terminal_state(),
            recursive_agent_contracts::RunTerminalStateV1::Failed
        );
        let before = tree(fx.root.path())?;
        let again = runtime(fx.root.path(), fx.clock.clone())?
            .with_interrupted_normal_chat_recovery()
            .recover_interrupted_normal_chat_attempt(session.run_id(), "intent:one")?;
        assert_eq!(result.child_chain_head(), again.child_chain_head());
        assert_eq!(tree(fx.root.path())?, before);
        assert!(service.close_normal_chat_session(&session).is_err());
        assert!(service
            .resume_normal_chat_session("conversation:fixture")
            .is_err());
        assert!(!matches!(
            service.begin_normal_chat_attempt(&session, &req),
            Ok(RuntimeNormalChatBeginV2::Fresh(_))
        ));
    }
    Ok(())
}

#[test]
fn known_interrupted_parent_is_distinct_from_unknown_and_cold_idempotent() -> TestResult {
    for stop in [
        Stop::Policy(
            recursive_agent_policy::NormalChatBeginInterruptionV2::Control(
                recursive_agent_policy::PermitTransitionStage::Rename,
            ),
        ),
        Stop::AfterPolicyConsume,
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let req = request(&fx, &session, "intent:one")?;
        assert!(service
            .begin_normal_chat_attempt_with_interruption(&session, &req, Some(stop))
            .is_err());
        let recovery = runtime(fx.root.path(), fx.clock.clone())?
            .with_interrupted_normal_chat_recovery()
            .with_normal_chat_parent_recovery(true);
        if stop == Stop::AfterPolicyConsume {
            recovery.recover_interrupted_normal_chat_attempt(session.run_id(), "intent:one")?;
        } else {
            recovery.recover_prepared_normal_chat_attempt(session.run_id(), "intent:one")?;
        }
        let closed = recovery.recover_normal_chat_session_parent(session.run_id())?;
        assert_eq!(closed.unknown_attempt_count(), 0);
        assert_eq!(closed.attempt_count(), 1);
        assert_eq!(
            closed.terminal_state(),
            recursive_agent_contracts::RunTerminalStateV1::Failed
        );
        let rows: Vec<recursive_agent_contracts::ReceiptV1> =
            fs::read_to_string(session.run_dir().join("receipts.ndjson"))?
                .lines()
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()?;
        assert!(matches!(&rows.last().ok_or("terminal absent")?.outcome,
            recursive_agent_contracts::ReceiptOutcomeV1::Failed { reason }
            if reason == "normal_chat_interrupted:CHILD_ADMISSION_NOT_RELEASED"));
        let before = tree(fx.root.path())?;
        let again = runtime(fx.root.path(), fx.clock.clone())?
            .with_normal_chat_parent_recovery(true)
            .recover_normal_chat_session_parent(session.run_id())?;
        assert_eq!(again.chain_head(), closed.chain_head());
        assert_eq!(tree(fx.root.path())?, before);
    }
    Ok(())
}

#[test]
fn prechild_pending_preparation_cannot_precede_closed_sibling_floor() -> TestResult {
    for pending_ms in [100, 1] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let prior = request(&fx, &session, "intent:prior")?;
        let cap = match service.begin_normal_chat_attempt(&session, &prior)? {
            RuntimeNormalChatBeginV2::Fresh(cap) => cap,
            _ => return Err("prior was not fresh".into()),
        };
        fx.clock.0.store(20, Ordering::SeqCst);
        service.settle_normal_chat_attempt(
            &session,
            &prior,
            cap.preflight_digest(),
            &super::terminal::report(recursive_agent_policy::NormalChatReportedStateV2::NotSent)?,
        )?;
        let next = request(&fx, &session, "intent:next")?;
        let root = File::open(session.run_dir())?;
        let (_, context) = recursive_agent_policy::FamilyAuthorityStore::require_existing_normal_chat_history_context_v1(
            &root, session.session())?;
        let mut chain = recursive_agent_ledger::open_existing_from_dir_fd(
            &recursive_agent_ledger::RunPaths::new(session.run_dir()),
            &root,
        )?;
        chain.artifact_store()?.put(
            &recursive_agent_contracts::jcs_canonical(&next)?,
            "application/json",
            None,
        )?;
        let digest = next.preparation_digest()?;
        let draft = recursive_agent_ledger::ReceiptDraftV1 {
            run_id: session.run_id().clone(),
            step_id: recursive_agent_contracts::derive_child_receipt_step_id(
                session.run_id(),
                &digest,
                "admission",
            )?,
            kind: ReceiptKindV1::ChildAdmissionPrepared,
            valid_time: start() + TimeDelta::milliseconds(pending_ms),
            lineage: recursive_agent_policy::build_lineage(
                &context.root_control.permit_id,
                &context.root_control.binding.policy_version,
            ),
            spec_digest: digest.clone(),
            args_digest: digest,
            artifact_refs: vec![],
            outcome: recursive_agent_contracts::ReceiptOutcomeV1::Ok,
        };
        let receipt = recursive_agent_ledger::make_receipt(draft, chain.head().clone())?;
        chain.append(receipt)?;
        drop(chain);
        fx.clock.0.store(200, Ordering::SeqCst);
        let before = tree(fx.root.path())?;
        let recovery =
            runtime(fx.root.path(), fx.clock.clone())?.with_interrupted_normal_chat_recovery();
        if pending_ms == 100 {
            recovery.recover_prechild_normal_chat_admission(session.run_id(), "intent:next")?;
            let (family, _) = recursive_agent_policy::FamilyAuthorityStore::require_existing_normal_chat_history_context_v1(
                &root, session.session())?;
            let mut record = family
                .read_normal_chat_prechild_recovery_v1()?
                .ok_or("native prechild record absent")?;
            record.validate()?;
            let row = record
                .parent_prefix
                .last()
                .ok_or("pending preparation absent")?
                .clone();
            let candidate = recursive_agent_ledger::make_receipt(
                recursive_agent_ledger::ReceiptDraftV1 {
                    run_id: row.run_id.clone(),
                    step_id: row.step_id.clone(),
                    kind: row.kind.clone(),
                    valid_time: start() + TimeDelta::milliseconds(1),
                    lineage: row.lineage.clone(),
                    spec_digest: row.spec_digest.clone(),
                    args_digest: row.args_digest.clone(),
                    artifact_refs: row.artifact_refs.clone(),
                    outcome: row.outcome.clone(),
                },
                row.prev_chain_digest.clone(),
            )?;
            *record
                .parent_prefix
                .last_mut()
                .ok_or("pending preparation absent")? = candidate;
            record.recovery_digest = record.computed_digest()?;
            assert!(
                record.validate().is_err(),
                "native record parser accepted a backdated pending preparation"
            );
        } else {
            assert!(
                recovery
                    .recover_prechild_normal_chat_admission(session.run_id(), "intent:next")
                    .is_err(),
                "backdated pending preparation was promoted to recovery"
            );
            assert_eq!(tree(fx.root.path())?, before);
            let cold =
                runtime(fx.root.path(), fx.clock.clone())?.with_interrupted_normal_chat_recovery();
            assert!(cold
                .recover_prechild_normal_chat_admission(session.run_id(), "intent:next")
                .is_err());
            assert_eq!(tree(fx.root.path())?, before);
        }
    }
    Ok(())
}

#[test]
fn prechild_after_closed_siblings_retains_complete_reservations() -> TestResult {
    for stop in [
        Stop::AfterRequestArtifact,
        Stop::AfterPreparation,
        Stop::AfterReservation,
        Stop::AfterLinkArtifact,
        Stop::AfterLink,
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let req = request(&fx, &session, "intent:prior")?;
        let cap = match service.begin_normal_chat_attempt(&session, &req)? {
            RuntimeNormalChatBeginV2::Fresh(cap) => cap,
            _ => return Err("not fresh".into()),
        };
        service.settle_normal_chat_attempt(
            &session,
            &req,
            cap.preflight_digest(),
            &super::terminal::report(recursive_agent_policy::NormalChatReportedStateV2::Succeeded)?,
        )?;
        let before = fs::read(session.run_dir().join("receipts.ndjson"))?;
        let next = request(&fx, &session, "intent:next")?;
        assert!(service
            .begin_normal_chat_attempt_with_interruption(&session, &next, Some(stop))
            .is_err());
        let result = runtime(fx.root.path(), fx.clock.clone())?
            .with_interrupted_normal_chat_recovery()
            .recover_prechild_normal_chat_admission(session.run_id(), "intent:next")?;
        assert_eq!(
            result.terminal_state(),
            recursive_agent_contracts::RunTerminalStateV1::Failed
        );
        assert!(fs::read(session.run_dir().join("receipts.ndjson"))?.starts_with(&before));
        let bytes = tree(fx.root.path())?;
        runtime(fx.root.path(), fx.clock.clone())?
            .with_interrupted_normal_chat_recovery()
            .recover_prechild_normal_chat_admission(session.run_id(), "intent:next")?;
        assert_eq!(tree(fx.root.path())?, bytes);
        assert!(!matches!(
            service.begin_normal_chat_attempt(&session, &next),
            Ok(RuntimeNormalChatBeginV2::Fresh(_))
        ));
    }
    Ok(())
}

#[test]
fn no_control_bootstrap_prefix_recovers_without_inventing_a_permit() -> TestResult {
    for stage in [
        recursive_agent_policy::PermitTransitionStage::TempWrite,
        recursive_agent_policy::PermitTransitionStage::TempFsync,
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let req = request(&fx, &session, "intent:one")?;
        let begin = service.begin_normal_chat_attempt_with_interruption(
            &session,
            &req,
            Some(Stop::Policy(
                recursive_agent_policy::NormalChatBeginInterruptionV2::Control(stage),
            )),
        );
        assert!(begin.is_err());
        let recovery = runtime(fx.root.path(), fx.clock.clone())?
            .with_interrupted_normal_chat_recovery()
            .with_normal_chat_parent_recovery(true);
        let result =
            recovery.recover_unconsumed_normal_chat_attempt(session.run_id(), "intent:one")?;
        let rows: Vec<recursive_agent_contracts::ReceiptV1> =
            fs::read_to_string(result.child_run_dir().join("receipts.ndjson"))?
                .lines()
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()?;
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|r| !matches!(
            r.kind,
            ReceiptKindV1::PermitIssued
                | ReceiptKindV1::PermitConsumed
                | ReceiptKindV1::NormalChatAttemptAdmittedV2
        )));
        let before = tree(fx.root.path())?;
        recovery.recover_unconsumed_normal_chat_attempt(session.run_id(), "intent:one")?;
        assert_eq!(tree(fx.root.path())?, before);
        let parent = recovery.recover_normal_chat_session_parent(session.run_id())?;
        assert_eq!(parent.unknown_attempt_count(), 0);
        assert_eq!(parent.attempt_count(), 1);
    }
    Ok(())
}

#[test]
fn source_selecting_recovery_composes_prefixes_and_complete_barrier_unknown() -> TestResult {
    for (stop, unknown) in [
        (Stop::AfterRequestArtifact, false),
        (Stop::AfterPreparation, false),
        (Stop::AfterReservation, false),
        (Stop::AfterLink, false),
        (
            Stop::Policy(
                recursive_agent_policy::NormalChatBeginInterruptionV2::Control(
                    recursive_agent_policy::PermitTransitionStage::TempWrite,
                ),
            ),
            false,
        ),
        (
            Stop::Policy(
                recursive_agent_policy::NormalChatBeginInterruptionV2::Control(
                    recursive_agent_policy::PermitTransitionStage::Rename,
                ),
            ),
            false,
        ),
        (Stop::AfterPolicyConsume, false),
        (Stop::BeforeRelease, true),
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let req = request(&fx, &session, "intent:one")?;
        assert!(service
            .begin_normal_chat_attempt_with_interruption(&session, &req, Some(stop))
            .is_err());
        let recovery = runtime(fx.root.path(), fx.clock.clone())?
            .with_interrupted_normal_chat_recovery()
            .with_expired_normal_chat_recovery()
            .with_normal_chat_parent_recovery(true);
        if unknown {
            assert!(recovery
                .recover_normal_chat_session_from_sources(session.run_id())
                .is_err());
            fx.clock.0.store(700_000, Ordering::SeqCst);
        }
        let result = recovery.recover_normal_chat_session_from_sources(session.run_id())?;
        assert_eq!(
            result.terminal_state(),
            recursive_agent_contracts::RunTerminalStateV1::Failed
        );
        assert_eq!(result.unknown_attempt_count(), usize::from(unknown));
        let before = tree(fx.root.path())?;
        let again = recovery.recover_normal_chat_session_from_sources(session.run_id())?;
        assert_eq!(result.chain_head(), again.chain_head());
        assert_eq!(tree(fx.root.path())?, before);
    }
    Ok(())
}
