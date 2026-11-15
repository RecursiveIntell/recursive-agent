//! Historical suffix repair must use retained executor evidence, not current
//! grant authority, a synthetic report, a clock transition, or send capability.
use super::*;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Default)]
struct PolicyClockSamples(std::sync::atomic::AtomicUsize);
impl Clock for PolicyClockSamples {
    fn now(&self) -> DateTime<Utc> {
        self.0.fetch_add(1, Ordering::SeqCst);
        start()
    }
}
impl PolicyClockSamples {
    fn assert_unsampled(&self) {
        assert_eq!(
            self.0.load(Ordering::SeqCst),
            0,
            "historical repair sampled the trusted policy clock"
        );
    }
}
fn historical_service(
    root: &Path,
    enabled: bool,
) -> Result<(RuntimeService, Arc<PolicyClockSamples>), Box<dyn std::error::Error>> {
    let clock = Arc::new(PolicyClockSamples::default());
    let service = runtime(root, clock.clone())?;
    let service = if enabled {
        service.with_interrupted_normal_chat_recovery()
    } else {
        service
    };
    Ok((service, clock))
}

fn retained(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>, Box<dyn std::error::Error>> {
    let mut result = BTreeMap::new();
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let kind = fs::symlink_metadata(&path)?.file_type();
            if kind.is_dir() {
                directories.push(path);
            } else if kind.is_file() {
                result.insert(path.strip_prefix(root)?.to_path_buf(), fs::read(path)?);
            }
        }
    }
    Ok(result)
}

fn native_map(files: &BTreeMap<PathBuf, Vec<u8>>) -> BTreeMap<PathBuf, Vec<u8>> {
    files
        .iter()
        .filter(|(path, _)| {
            path.components().any(|part| part.as_os_str() == "permits")
                || path.ends_with("family-authority.json")
        })
        .map(|(path, bytes)| (path.clone(), bytes.clone()))
        .collect()
}

#[test]
fn retained_report_repair_without_grant_is_clock_free_exact_and_idempotent() -> TestResult {
    for state in [
        NormalChatReportedStateV2::Succeeded,
        NormalChatReportedStateV2::OutcomeUnknown,
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let (request, preflight) = fresh(&fx, &service, &session)?;
        let value = report(state)?;
        assert!(service
            .settle_normal_chat_attempt_with_interruption(
                &session,
                &request,
                &preflight,
                &value,
                Some(TerminalStop::AfterControlClose)
            )
            .is_err());
        let parent = session.run_id().clone();
        let family = fs::read(session.run_dir().join("family-authority.json"))?;
        let native_before: BTreeMap<_, _> = retained(fx.root.path())?
            .into_iter()
            .filter(|(path, _)| {
                path.components().any(|part| part.as_os_str() == "permits")
                    || path.ends_with("family-authority.json")
            })
            .collect();
        drop(session);
        drop(service);
        let (cold, policy_clock) = historical_service(fx.root.path(), true)?;
        let done =
            cold.repair_retained_normal_chat_settlement(&parent, &request.dispatch_intent_ref)?;
        assert_eq!(done.settlement().report, value);
        assert_eq!(
            done.attempt().dispatch_intent_ref,
            request.dispatch_intent_ref
        );
        let child = verified_snapshot_expected_run_from_dir_fd(
            &File::open(done.child_run_dir())?,
            &done.attempt().run_id()?,
        )?;
        assert_eq!(child.receipts().len(), 10);
        let parent_dir = fx.run_dir()?;
        let parent_snapshot =
            appendable_snapshot_expected_run_from_dir_fd(&File::open(&parent_dir)?, &parent)?;
        assert_eq!(
            parent_snapshot
                .receipts()
                .last()
                .ok_or("closure absent")?
                .kind,
            ReceiptKindV1::ChildClosed
        );
        assert_eq!(fs::read(parent_dir.join("family-authority.json"))?, family);
        let native_after: BTreeMap<_, _> = retained(fx.root.path())?
            .into_iter()
            .filter(|(path, _)| {
                path.components().any(|part| part.as_os_str() == "permits")
                    || path.ends_with("family-authority.json")
            })
            .collect();
        assert_eq!(
            native_before, native_after,
            "historical repair changed native policy or charges"
        );
        let once = retained(fx.root.path())?;
        let again =
            cold.repair_retained_normal_chat_settlement(&parent, &request.dispatch_intent_ref)?;
        assert_eq!(done.settlement(), again.settlement());
        assert_eq!(done.child_chain_head(), again.child_chain_head());
        assert_eq!(done.parent_chain_head(), again.parent_chain_head());
        assert_eq!(once, retained(fx.root.path())?);
        assert!(matches!(
            cold.open_normal_chat_session("conversation:no-new-authority"),
            Err(RuntimeServiceError::NormalChatGovernanceDisabled)
        ));
        policy_clock.assert_unsampled();
    }
    Ok(())
}

#[test]
fn retained_report_repair_refuses_missing_report_or_unclosed_control_without_mutation() -> TestResult
{
    for durable_report in [false, true] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let (request, preflight) = fresh(&fx, &service, &session)?;
        if durable_report {
            assert!(service
                .settle_normal_chat_attempt_with_interruption(
                    &session,
                    &request,
                    &preflight,
                    &report(NormalChatReportedStateV2::Succeeded)?,
                    Some(TerminalStop::AfterPolicy)
                )
                .is_err());
        }
        let before = retained(fx.root.path())?;
        let (cold, policy_clock) = historical_service(fx.root.path(), true)?;
        assert!(cold
            .repair_retained_normal_chat_settlement(session.run_id(), &request.dispatch_intent_ref)
            .is_err());
        assert_eq!(before, retained(fx.root.path())?);
        policy_clock.assert_unsampled();
    }
    Ok(())
}

#[test]
fn retained_report_repair_is_opt_in_and_never_creates_absent_roots_or_gates() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let run = session.run_id().clone();
    let before = retained(fx.root.path())?;
    let (disabled, disabled_clock) = historical_service(fx.root.path(), false)?;
    assert!(matches!(
        disabled.repair_retained_normal_chat_settlement(&run, "intent:absent"),
        Err(RuntimeServiceError::NormalChatRecoveryDisabled)
    ));
    disabled_clock.assert_unsampled();
    assert_eq!(before, retained(fx.root.path())?);
    let empty = tempfile::tempdir()?;
    let (cold, empty_clock) = historical_service(empty.path(), true)?;
    assert!(cold
        .repair_retained_normal_chat_settlement(&run, "intent:absent")
        .is_err());
    assert_eq!(fs::read_dir(empty.path())?.count(), 0);
    empty_clock.assert_unsampled();
    fs::remove_file(session.run_dir().join(".normal-chat-runtime.lock"))?;
    let without_gate = retained(fx.root.path())?;
    let (cold, policy_clock) = historical_service(fx.root.path(), true)?;
    assert!(cold
        .repair_retained_normal_chat_settlement(&run, "intent:absent")
        .is_err());
    assert!(!session.run_dir().join(".normal-chat-runtime.lock").exists());
    assert_eq!(without_gate, retained(fx.root.path())?);
    policy_clock.assert_unsampled();
    Ok(())
}

#[test]
fn retained_report_repair_refuses_wrong_intent_and_extra_inventory() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (request, preflight) = fresh(&fx, &service, &session)?;
    assert!(service
        .settle_normal_chat_attempt_with_interruption(
            &session,
            &request,
            &preflight,
            &report(NormalChatReportedStateV2::Succeeded)?,
            Some(TerminalStop::AfterControlClose),
        )
        .is_err());
    let (cold, policy_clock) = historical_service(fx.root.path(), true)?;
    let before = retained(fx.root.path())?;
    assert!(cold
        .repair_retained_normal_chat_settlement(session.run_id(), "intent:unrelated")
        .is_err());
    assert_eq!(before, retained(fx.root.path())?);
    let view = service.read_normal_chat_attempt(session.run_id(), &request.dispatch_intent_ref)?;
    let child_dir = fx
        .root
        .path()
        .join(content_digest(&view.policy().attempt.run_id()?)?.to_string());
    fs::write(
        child_dir.join("artifacts/unrelated"),
        b"not a retained terminal projection",
    )?;
    let tampered = retained(fx.root.path())?;
    assert!(cold
        .repair_retained_normal_chat_settlement(session.run_id(), &request.dispatch_intent_ref)
        .is_err());
    assert_eq!(tampered, retained(fx.root.path())?);
    policy_clock.assert_unsampled();
    Ok(())
}

#[test]
fn retained_report_repair_covers_owned_terminal_publication_interruptions() -> TestResult {
    let mut faults = vec![
        TerminalStop::Artifact { ordinal: 0 },
        TerminalStop::Artifact { ordinal: 1 },
        TerminalStop::ParentArtifact,
        TerminalStop::BeforeReturn,
    ];
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
    assert_eq!(faults.len(), 32);
    for fault in faults {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let (request, preflight) = fresh(&fx, &service, &session)?;
        let value = report(NormalChatReportedStateV2::Succeeded)?;
        assert!(
            service
                .settle_normal_chat_attempt_with_interruption(
                    &session,
                    &request,
                    &preflight,
                    &value,
                    Some(fault),
                )
                .is_err(),
            "fault did not interrupt: {fault:?}"
        );
        let before = retained(fx.root.path())?;
        let parent_prefix = complete_prefix(&session.run_dir().join("receipts.ndjson"))?;
        let child_log = before
            .keys()
            .find(|path| {
                path.ends_with("receipts.ndjson")
                    && fx.root.path().join(path) != session.run_dir().join("receipts.ndjson")
            })
            .ok_or("child receipt log absent")?;
        let child_prefix = complete_prefix(&fx.root.path().join(child_log))?;
        let (cold, policy_clock) = historical_service(fx.root.path(), true)?;
        let done = cold.repair_retained_normal_chat_settlement(
            session.run_id(),
            &request.dispatch_intent_ref,
        )?;
        assert_eq!(done.settlement().report, value);
        let after = retained(fx.root.path())?;
        assert_eq!(
            native_map(&before),
            native_map(&after),
            "native file set or source changed at {fault:?}"
        );
        assert!(fs::read(done.child_run_dir().join("receipts.ndjson"))?.starts_with(&child_prefix));
        assert!(fs::read(session.run_dir().join("receipts.ndjson"))?.starts_with(&parent_prefix));
        assert_eq!(
            verified_snapshot_expected_run_from_dir_fd(
                &File::open(done.child_run_dir())?,
                &done.attempt().run_id()?,
            )?
            .receipts()
            .len(),
            10
        );
        let again = cold.repair_retained_normal_chat_settlement(
            session.run_id(),
            &request.dispatch_intent_ref,
        )?;
        assert_eq!(done.settlement(), again.settlement());
        assert_eq!(done.child_chain_head(), again.child_chain_head());
        assert_eq!(done.parent_chain_head(), again.parent_chain_head());
        assert_eq!(after, retained(fx.root.path())?);
        policy_clock.assert_unsampled();
    }
    Ok(())
}

#[test]
fn ordinary_settlement_without_grant_still_denies_before_storage_reconciliation() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (request, preflight) = fresh(&fx, &service, &session)?;
    fs::remove_file(session.run_dir().join("chain.meta"))?;
    let before = retained(fx.root.path())?;
    let disabled = runtime(fx.root.path(), fx.clock.clone())?;
    assert!(matches!(
        disabled.settle_normal_chat_attempt(
            &session,
            &request,
            &preflight,
            &report(NormalChatReportedStateV2::Succeeded)?,
        ),
        Err(RuntimeServiceError::NormalChatGovernanceDisabled)
    ));
    assert!(!session.run_dir().join("chain.meta").exists());
    assert_eq!(before, retained(fx.root.path())?);
    Ok(())
}
