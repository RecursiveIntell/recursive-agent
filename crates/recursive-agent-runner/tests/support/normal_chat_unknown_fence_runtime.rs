use super::*;

#[test]
fn explicit_unknown_has_durable_fence_and_historical_retry_never_reopens_it() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (request, preflight) = fresh(&fx, &service, &session)?;
    let (family, _, _, _) = super::hostile::child_info(&fx, &session)?;
    let done = service.settle_normal_chat_attempt(
        &session,
        &request,
        &preflight,
        &report(NormalChatReportedStateV2::OutcomeUnknown)?,
    )?;
    assert_eq!(done.terminal_state(), RunTerminalStateV1::Failed);
    let snapshot = family.read_normal_chat_session_snapshot_v2()?;
    assert!(
        snapshot.admission.closed_at.is_some(),
        "unknown runtime completion lacks native fence"
    );
    assert_eq!(snapshot.reservations.len(), 1);
    let parent_bytes = fs::read(session.run_dir().join("receipts.ndjson"))?;
    let family_bytes = fs::read(session.run_dir().join("family-authority.json"))?;
    assert!(service
        .begin_normal_chat_attempt(
            &session,
            &super::super::request(&fx, &session, "intent:new")?
        )
        .is_err());
    assert!(service.close_normal_chat_session(&session).is_err());
    assert!(service
        .resume_normal_chat_session("conversation:fixture")
        .is_err());
    fx.clock.0.store(-1, Ordering::SeqCst);
    let again = fx.service()?.settle_normal_chat_attempt(
        &session,
        &request,
        &preflight,
        &report(NormalChatReportedStateV2::OutcomeUnknown)?,
    )?;
    assert_eq!(again.child_chain_head(), done.child_chain_head());
    assert_eq!(
        parent_bytes,
        fs::read(session.run_dir().join("receipts.ndjson"))?
    );
    assert_eq!(
        family_bytes,
        fs::read(session.run_dir().join("family-authority.json"))?
    );
    Ok(())
}
#[test]
fn unknown_return_requires_native_fence_after_final_observer() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (request, preflight) = fresh(&fx, &service, &session)?;
    let (family, _, _, _) = super::hostile::child_info(&fx, &session)?;
    // A native close precedes the explicit report. Only the synthetic observer
    // corrupts it; production has no reopen operation.
    family.close_normal_chat_session(start())?;
    let path = session.run_dir().join("family-authority.json");
    let failure = std::cell::RefCell::new(None);
    let result = service.settle_normal_chat_attempt_with_observer(
        &session,
        &request,
        &preflight,
        &report(NormalChatReportedStateV2::OutcomeUnknown)?,
        None,
        || {
            let action = (|| -> TestResult {
                let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
                value["normal_chat_session"]["closed_at"] = serde_json::Value::Null;
                fs::write(&path, serde_json::to_vec(&value)?)?;
                Ok(())
            })();
            if let Err(e) = action {
                *failure.borrow_mut() = Some(e.to_string());
            }
        },
    );
    assert!(failure.into_inner().is_none());
    assert!(
        result.is_err(),
        "unknown terminal success escaped without its native fence"
    );
    assert!(
        family
            .read_normal_chat_session_snapshot_v2()?
            .admission
            .closed_at
            .is_none(),
        "failed confirmation silently repaired the missing fence"
    );
    Ok(())
}

struct FenceRemovingClock {
    base: Arc<TestClock>,
    path: std::path::PathBuf,
    armed: std::sync::atomic::AtomicBool,
    failed: std::sync::atomic::AtomicBool,
}
impl Clock for FenceRemovingClock {
    fn now(&self) -> DateTime<Utc> {
        if self.armed.swap(false, Ordering::SeqCst) {
            let result = (|| -> TestResult {
                let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&self.path)?)?;
                value["normal_chat_session"]["closed_at"] = serde_json::Value::Null;
                fs::write(&self.path, serde_json::to_vec(&value)?)?;
                Ok(())
            })();
            self.failed.store(result.is_err(), Ordering::SeqCst);
        }
        self.base.now()
    }
}
#[test]
fn final_clock_fence_removal_is_rejected_without_native_repair() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (request, preflight) = fresh(&fx, &service, &session)?;
    let (family, _, _, _) = super::hostile::child_info(&fx, &session)?;
    let clock = Arc::new(FenceRemovingClock {
        base: fx.clock.clone(),
        path: session.run_dir().join("family-authority.json"),
        armed: std::sync::atomic::AtomicBool::new(false),
        failed: std::sync::atomic::AtomicBool::new(false),
    });
    let service =
        runtime(fx.root.path(), clock.clone())?.with_normal_chat_egress_grant(fx.authority.clone());
    let result = service.settle_normal_chat_attempt_with_observer(
        &session,
        &request,
        &preflight,
        &report(NormalChatReportedStateV2::OutcomeUnknown)?,
        None,
        || clock.armed.store(true, Ordering::SeqCst),
    );
    assert!(!clock.armed.load(Ordering::SeqCst));
    assert!(!clock.failed.load(Ordering::SeqCst));
    assert!(
        result.is_err(),
        "last clock removed fence before a successful terminal return"
    );
    assert!(family
        .read_normal_chat_session_snapshot_v2()?
        .admission
        .closed_at
        .is_none());
    Ok(())
}
