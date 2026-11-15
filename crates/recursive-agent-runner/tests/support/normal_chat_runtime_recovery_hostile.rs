use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize};

struct Prior {
    request: NormalChatCallRequestV2,
    preflight: ContentDigest,
    child: PathBuf,
    pending: PathBuf,
    family: FamilyAuthorityStore,
}
fn prior(
    fx: &Fixture,
    service: &RuntimeService,
    session: &recursive_agent_runner::RuntimeNormalChatSessionV1,
) -> Result<Prior, Box<dyn std::error::Error>> {
    let request = super::super::super::request(fx, session, "intent:closed")?;
    let cap = match service.begin_normal_chat_attempt(session, &request)? {
        RuntimeNormalChatBeginV2::Fresh(cap) => cap,
        _ => return Err("first not Fresh".into()),
    };
    let preflight = cap.preflight_digest().clone();
    let child = cap.child_run_dir().to_path_buf();
    service.settle_normal_chat_attempt(
        session,
        &request,
        &preflight,
        &super::super::super::terminal::report(
            recursive_agent_policy::NormalChatReportedStateV2::NotSent,
        )?,
    )?;
    let (_, _, pending, family) = admitted(fx, service, session)?;
    Ok(Prior {
        request,
        preflight,
        child,
        pending,
        family,
    })
}
#[test]
fn known_prior_child_and_old_retries_survive_latest_recovery_parent_orphan_without_closing_it(
) -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let p = prior(&fx, &service, &session)?;
    let old = fs::read(p.child.join("receipts.ndjson"))?;
    fx.clock.0.store(2000, Ordering::SeqCst);
    assert!(no_grant(&fx)?
        .recover_expired_normal_chat_attempt_with_interruption(
            session.run_id(),
            "intent:one",
            Some(StopRecovery::ParentArtifact)
        )
        .is_err());
    let before = tree(fx.root.path())?;
    assert!(matches!(
        service.begin_normal_chat_attempt(&session, &p.request)?,
        RuntimeNormalChatBeginV2::Existing(_)
    ));
    service.settle_normal_chat_attempt(
        &session,
        &p.request,
        &p.preflight,
        &super::super::super::terminal::report(
            recursive_agent_policy::NormalChatReportedStateV2::NotSent,
        )?,
    )?;
    assert_eq!(tree(fx.root.path())?, before);
    no_grant(&fx)?.recover_expired_normal_chat_attempt(session.run_id(), "intent:one")?;
    assert_closed(&fx, &session, &p.pending)?;
    assert_eq!(fs::read(p.child.join("receipts.ndjson"))?, old);
    let after = tree(fx.root.path())?;
    service.begin_normal_chat_attempt(&session, &p.request)?;
    service.settle_normal_chat_attempt(
        &session,
        &p.request,
        &p.preflight,
        &super::super::super::terminal::report(
            recursive_agent_policy::NormalChatReportedStateV2::NotSent,
        )?,
    )?;
    assert_eq!(tree(fx.root.path())?, after);
    assert_eq!(
        p.family
            .read_normal_chat_session_snapshot_v2()?
            .reservations
            .len(),
        2
    );
    Ok(())
}
#[test]
fn late_target_and_prior_sibling_substitutions_never_acknowledge_recovery_success() -> TestResult {
    for target in [
        "parent-root",
        "child-root",
        "parent-artifacts",
        "child-artifacts",
        "parent-permits",
        "child-permits",
        "runtime-gate",
        "prior-artifacts",
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let p = prior(&fx, &service, &session)?;
        fx.clock.0.store(2000, Ordering::SeqCst);
        let slots = p
            .family
            .read_normal_chat_session_snapshot_v2()?
            .reservations;
        let path = match target {
            "parent-root" => session.run_dir().to_path_buf(),
            "child-root" => p.pending.clone(),
            "parent-artifacts" => session.run_dir().join("artifacts"),
            "child-artifacts" => p.pending.join("artifacts"),
            "parent-permits" => session.run_dir().join("permits"),
            "child-permits" => p.pending.join("permits"),
            "runtime-gate" => session.run_dir().join(".normal-chat-runtime.lock"),
            _ => p.child.join("artifacts"),
        };
        let mut error = None;
        let mut called = false;
        let result = no_grant(&fx)?.recover_expired_normal_chat_attempt_with_observer(
            session.run_id(),
            "intent:one",
            None,
            || {
                called = true;
                error = replace(&path).err();
            },
        );
        if let Some(error) = error {
            return Err(error.into());
        }
        assert!(called, "{target}");
        assert!(result.is_err(), "late {target} escaped recovery fence");
        assert_eq!(
            p.family
                .read_normal_chat_session_snapshot_v2()?
                .reservations,
            slots
        );
    }
    Ok(())
}
#[test]
fn missing_fence_after_final_observer_is_not_repaired_by_return_or_retry() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    admitted(&fx, &service, &session)?;
    fx.clock.0.store(2000, Ordering::SeqCst);
    let path = session.run_dir().join("family-authority.json");
    let mut action = Ok(());
    let result = no_grant(&fx)?.recover_expired_normal_chat_attempt_with_observer(
        session.run_id(),
        "intent:one",
        None,
        || {
            action = (|| -> TestResult {
                let mut raw: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
                raw["normal_chat_session"]["closed_at"] = json!(null);
                fs::write(&path, recursive_agent_contracts::jcs_canonical(&raw)?)?;
                Ok(())
            })();
        },
    );
    action?;
    assert!(result.is_err());
    let before = tree(fx.root.path())?;
    assert!(no_grant(&fx)?
        .recover_expired_normal_chat_attempt(session.run_id(), "intent:one")
        .is_err());
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}
struct DeleteRootClock {
    calls: AtomicUsize,
    path: PathBuf,
    deleted: AtomicBool,
}
impl Clock for DeleteRootClock {
    fn now(&self) -> DateTime<Utc> {
        if self.calls.fetch_add(1, Ordering::SeqCst) + 1 == 4 {
            self.deleted
                .store(fs::remove_file(&self.path).is_ok(), Ordering::SeqCst);
        }
        start() + TimeDelta::seconds(2)
    }
}
#[test]
fn root_disappearing_during_last_transition_clock_is_not_recreated_or_acknowledged() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (_, _, child, family) = admitted(&fx, &service, &session)?;
    let mut files = Vec::new();
    for e in fs::read_dir(session.run_dir().join("permits"))? {
        let e = e?;
        if e.path().extension().is_some_and(|x| x == "json") {
            files.push(e.path());
        }
    }
    assert_eq!(files.len(), 1);
    let path = files.remove(0);
    let clock = Arc::new(DeleteRootClock {
        calls: AtomicUsize::new(0),
        path: path.clone(),
        deleted: AtomicBool::new(false),
    });
    let recovery = runtime(fx.root.path(), clock.clone())?.with_expired_normal_chat_recovery();
    assert!(recovery
        .recover_expired_normal_chat_attempt(session.run_id(), "intent:one")
        .is_err());
    assert!(clock.deleted.load(Ordering::SeqCst));
    assert!(!path.exists());
    let native = DurablePermitStore::require_existing_from_run_root_fd(&File::open(child)?)?;
    assert!(native
        .read_normal_chat_recovery_v1(&family, "intent:one")?
        .is_some());
    assert!(family
        .read_normal_chat_session_snapshot_v2()?
        .admission
        .closed_at
        .is_some());
    let before = tree(fx.root.path())?;
    assert!(no_grant(&fx)?
        .recover_expired_normal_chat_attempt(session.run_id(), "intent:one")
        .is_err());
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}
struct Regress {
    calls: AtomicUsize,
    at: usize,
}
impl Clock for Regress {
    fn now(&self) -> DateTime<Utc> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        start() + TimeDelta::seconds(if n >= self.at { 1 } else { 2 })
    }
}
#[test]
fn regression_at_native_family_or_control_transition_cannot_backdate_recovery() -> TestResult {
    for at in [3, 4] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let (_, _, child, family) = admitted(&fx, &service, &session)?;
        let recovery = runtime(
            fx.root.path(),
            Arc::new(Regress {
                calls: AtomicUsize::new(0),
                at,
            }),
        )?
        .with_expired_normal_chat_recovery();
        assert!(recovery
            .recover_expired_normal_chat_attempt(session.run_id(), "intent:one")
            .is_err());
        let native = DurablePermitStore::require_existing_from_run_root_fd(&File::open(child)?)?;
        assert_eq!(
            native
                .read_normal_chat_recovery_v1(&family, "intent:one")?
                .is_some(),
            at == 4
        );
        assert!(native
            .read_normal_chat_attempt_v2(&family, "intent:one")?
            .outcome
            .is_none());
    }
    Ok(())
}
#[test]
fn concurrent_report_and_runtime_recovery_have_only_one_native_terminal_winner() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (request, preflight, child, family) = admitted(&fx, &service, &session)?;
    fx.clock.0.store(2000, Ordering::SeqCst);
    let recover = no_grant(&fx)?;
    let barrier = std::sync::Barrier::new(2);
    let report = super::super::super::terminal::report(
        recursive_agent_policy::NormalChatReportedStateV2::NotSent,
    )?;
    let (sdk, unknown) = std::thread::scope(|scope| {
        let one = scope.spawn(|| {
            barrier.wait();
            service
                .settle_normal_chat_attempt(&session, &request, &preflight, &report)
                .is_ok()
        });
        let two = scope.spawn(|| {
            barrier.wait();
            recover
                .recover_expired_normal_chat_attempt(session.run_id(), "intent:one")
                .is_ok()
        });
        (one.join(), two.join())
    });
    let sdk = sdk.map_err(|_| "report thread panicked")?;
    let unknown = unknown.map_err(|_| "recovery thread panicked")?;
    assert_ne!(sdk, unknown);
    let native = DurablePermitStore::require_existing_from_run_root_fd(&File::open(child)?)?;
    let view = native.read_normal_chat_attempt_v2(&family, "intent:one")?;
    assert_eq!(view.settlement.is_some(), sdk);
    assert_eq!(
        native
            .read_normal_chat_recovery_v1(&family, "intent:one")?
            .is_some(),
        unknown
    );
    Ok(())
}
