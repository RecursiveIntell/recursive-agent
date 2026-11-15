use super::*;
#[path = "normal_chat_recovery_inspection_hostile.rs"]
mod hostile_more;
#[path = "normal_chat_native_family_proof.rs"]
mod native_family_proof;
#[path = "normal_chat_runtime_recovery.rs"]
mod runtime_recovery;
use recursive_agent_contracts::{CurrentRunId, NormalChatCallRequestV2};
use recursive_agent_policy::{
    FamilyAuthorityStore, NormalChatAttemptPolicyStateV2, NormalChatGrantContextV2,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;

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
fn copy_tree(source: &Path, dest: &Path) -> std::io::Result<()> {
    fs::create_dir(dest)?;
    fs::set_permissions(dest, fs::Permissions::from_mode(0o700))?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &dest.join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dest.join(entry.file_name()))?;
        }
    }
    Ok(())
}
fn replace(path: &Path) -> std::io::Result<()> {
    let detached = path.with_extension("inspection-detached");
    fs::rename(path, &detached)?;
    if detached.is_dir() {
        copy_tree(&detached, path)?;
    } else {
        fs::copy(&detached, path)?;
    }
    Ok(())
}
struct CountingClock(Arc<AtomicUsize>);
impl Clock for CountingClock {
    fn now(&self) -> DateTime<Utc> {
        self.0.fetch_add(1, Ordering::SeqCst);
        start() + TimeDelta::hours(1)
    }
}
fn reader(fx: &Fixture) -> Result<(RuntimeService, Arc<AtomicUsize>), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    Ok((
        runtime(fx.root.path(), Arc::new(CountingClock(calls.clone())))?,
        calls,
    ))
}
fn admitted(
    fx: &Fixture,
    service: &RuntimeService,
    session: &recursive_agent_runner::RuntimeNormalChatSessionV1,
) -> Result<
    (
        NormalChatCallRequestV2,
        ContentDigest,
        PathBuf,
        FamilyAuthorityStore,
    ),
    Box<dyn std::error::Error>,
> {
    let request = request(fx, session, "intent:one")?;
    let cap = match service.begin_normal_chat_attempt(session, &request)? {
        RuntimeNormalChatBeginV2::Fresh(cap) => cap,
        _ => return Err("expected fresh fixture admission".into()),
    };
    let permits =
        DurablePermitStore::require_existing_from_run_root_fd(&File::open(session.run_dir())?)?;
    let record = permits
        .read_normal_chat_session_control_record()?
        .ok_or("root control absent")?;
    let context = NormalChatGrantContextV2 {
        grant: fx.authority.grant().clone(),
        session: session.session().clone(),
        root_control: record.permit,
    };
    let family = FamilyAuthorityStore::require_existing_from_dir_fd(
        &File::open(session.run_dir())?,
        context.session_family_grant_v2()?,
    )?;
    Ok((
        request,
        cap.preflight_digest().clone(),
        cap.child_run_dir().into(),
        family,
    ))
}

#[test]
fn pending_inspection_without_grant_or_clock_is_historical_and_does_not_change_tree() -> TestResult
{
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (request, preflight, _, _) = admitted(&fx, &service, &session)?;
    fx.clock.0.store(700_000, Ordering::SeqCst);
    fs::remove_file(fx._grant_root.path().join("grant.json"))?;
    let before = tree(fx.root.path())?;
    let (reader, calls) = reader(&fx)?;
    let view =
        reader.inspect_pending_normal_chat_attempt_for_recovery(session.run_id(), "intent:one")?;
    assert_eq!(view.session(), session.session());
    assert_eq!(view.request(), &request);
    assert_eq!(view.preflight_digest(), &preflight);
    assert_eq!(
        view.policy_state(),
        NormalChatAttemptPolicyStateV2::Consumed
    );
    assert!(view.native_recovery().is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(tree(fx.root.path())?, before);
    assert!(reader
        .open_normal_chat_session("conversation:fixture")
        .is_err());
    Ok(())
}

#[test]
fn native_recovered_inspection_preserves_distinct_origin_and_never_settles_or_repairs() -> TestResult
{
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (_, preflight, child, family) = admitted(&fx, &service, &session)?;
    let policy = DurablePermitStore::require_existing_from_run_root_fd(&File::open(&child)?)?;
    let recovered =
        policy.recover_expired_normal_chat_attempt_v1(&family, "intent:one", &preflight, || {
            start() + TimeDelta::seconds(2)
        })?;
    let before = tree(fx.root.path())?;
    let (reader, calls) = reader(&fx)?;
    let view =
        reader.inspect_pending_normal_chat_attempt_for_recovery(session.run_id(), "intent:one")?;
    assert_eq!(
        view.policy_state(),
        NormalChatAttemptPolicyStateV2::RecoveredUnknown
    );
    assert_eq!(view.native_recovery(), Some(&recovered));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(tree(fx.root.path())?, before);
    assert!(policy
        .read_normal_chat_attempt_v2(&family, "intent:one")?
        .outcome
        .is_none());
    Ok(())
}

#[test]
fn absent_roots_and_invalid_or_unknown_literal_intents_cannot_create_storage() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    admitted(&fx, &service, &session)?;
    let (reader, _) = reader(&fx)?;
    for intent in [
        "",
        " intent:one",
        "intent:one ",
        "intent:ONE",
        "../intent:one",
        "intent:one\0",
        "intent:absent",
    ] {
        let before = tree(fx.root.path())?;
        assert!(
            reader
                .inspect_pending_normal_chat_attempt_for_recovery(session.run_id(), intent)
                .is_err(),
            "{intent:?}"
        );
        assert_eq!(tree(fx.root.path())?, before);
    }
    let other = fx
        .authority
        .normal_chat_session("conversation:absent", None)?
        .run_id()?;
    let before = tree(fx.root.path())?;
    assert!(reader
        .inspect_pending_normal_chat_attempt_for_recovery(&other, "intent:one")
        .is_err());
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}

#[test]
fn missing_parent_child_authority_artifacts_or_gate_are_not_recreated() -> TestResult {
    for missing in [
        "parent-permits",
        "parent-family",
        "family-lock",
        "runtime-gate",
        "child-permits",
        "parent-artifacts",
        "child-artifacts",
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let (_, _, child, _) = admitted(&fx, &service, &session)?;
        let path = match missing {
            "parent-permits" => session.run_dir().join("permits"),
            "parent-family" => session.run_dir().join("family-authority.json"),
            "family-lock" => session.run_dir().join(".family-authority.lock"),
            "runtime-gate" => session.run_dir().join(".normal-chat-runtime.lock"),
            "child-permits" => child.join("permits"),
            "parent-artifacts" => session.run_dir().join("artifacts"),
            _ => child.join("artifacts"),
        };
        let detached = fx._grant_root.path().join(missing);
        fs::rename(&path, detached)?;
        let before = tree(fx.root.path())?;
        assert!(
            reader(&fx)?
                .0
                .inspect_pending_normal_chat_attempt_for_recovery(session.run_id(), "intent:one")
                .is_err(),
            "{missing}"
        );
        assert!(!path.exists(), "{missing} recreated");
        assert_eq!(tree(fx.root.path())?, before);
    }
    Ok(())
}

#[test]
fn incomplete_preflight_and_already_reported_attempts_remain_outside_recovery_inspection(
) -> TestResult {
    for point in [
        Some(Stop::AfterPolicyConsume),
        Some(Stop::ChildReceipt {
            ordinal: 6,
            stage: recursive_agent_ledger::AppendStage::PartialRecord,
        }),
        None,
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let request = request(&fx, &session, "intent:one")?;
        if let Some(point) = point {
            assert!(service
                .begin_normal_chat_attempt_with_interruption(&session, &request, Some(point))
                .is_err());
        } else {
            let cap = match service.begin_normal_chat_attempt(&session, &request)? {
                RuntimeNormalChatBeginV2::Fresh(cap) => cap,
                _ => return Err("not Fresh".into()),
            };
            service.settle_normal_chat_attempt(
                &session,
                &request,
                cap.preflight_digest(),
                &super::terminal::report(
                    recursive_agent_policy::NormalChatReportedStateV2::NotSent,
                )?,
            )?;
        }
        assert!(reader(&fx)?
            .0
            .inspect_pending_normal_chat_attempt_for_recovery(session.run_id(), "intent:one")
            .is_err());
    }
    Ok(())
}

#[test]
fn late_byte_identical_storage_substitutions_reject_before_inspection_return() -> TestResult {
    for target in [
        "parent-root",
        "child-root",
        "parent-artifacts",
        "child-artifacts",
        "parent-permits",
        "child-permits",
        "runtime-gate",
        "child-lock",
        "parent-lock",
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let (_, _, child, family) = admitted(&fx, &service, &session)?;
        let before = family.read_normal_chat_session_snapshot_v2()?;
        let path = match target {
            "parent-root" => session.run_dir().into(),
            "child-root" => child.clone(),
            "parent-artifacts" => session.run_dir().join("artifacts"),
            "child-artifacts" => child.join("artifacts"),
            "parent-permits" => session.run_dir().join("permits"),
            "child-permits" => child.join("permits"),
            "runtime-gate" => session.run_dir().join(".normal-chat-runtime.lock"),
            "child-lock" => child.join("permits/.permit.lock"),
            _ => session.run_dir().join("permits/.permit.lock"),
        };
        let mut called = false;
        let mut error = None;
        let result = reader(&fx)?
            .0
            .inspect_pending_normal_chat_attempt_for_recovery_with_observer(
                session.run_id(),
                "intent:one",
                || {
                    called = true;
                    error = replace(&path).err();
                },
            );
        if let Some(error) = error {
            return Err(error.into());
        }
        assert!(called, "{target} observer not reached");
        assert!(result.is_err(), "{target} escaped inspection fence");
        assert_eq!(family.read_normal_chat_session_snapshot_v2()?, before);
    }
    Ok(())
}

#[test]
fn a_recovered_record_with_a_missing_native_fence_is_rejected_without_repair() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (_, preflight, child, family) = admitted(&fx, &service, &session)?;
    DurablePermitStore::require_existing_from_run_root_fd(&File::open(&child)?)?
        .recover_expired_normal_chat_attempt_v1(&family, "intent:one", &preflight, || {
            start() + TimeDelta::seconds(2)
        })?;
    let path = session.run_dir().join("family-authority.json");
    let mut raw: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    raw["normal_chat_session"]["closed_at"] = json!(null);
    fs::write(path, recursive_agent_contracts::jcs_canonical(&raw)?)?;
    let before = tree(fx.root.path())?;
    assert!(reader(&fx)?
        .0
        .inspect_pending_normal_chat_attempt_for_recovery(session.run_id(), "intent:one")
        .is_err());
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}

#[test]
fn inspection_in_a_new_process_needs_no_live_session_or_grant() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (_, preflight, _, _) = admitted(&fx, &service, &session)?;
    let input = fx._grant_root.path().join("inspection-input.json");
    fs::write(
        &input,
        serde_json::to_vec(
            &json!({"root":fx.root.path(),"run_id":session.run_id(),"preflight":preflight}),
        )?,
    )?;
    fs::remove_file(fx._grant_root.path().join("grant.json"))?;
    let before = tree(fx.root.path())?;
    let result = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "attempts::inspection::cold_process_inspection_child",
            "--nocapture",
        ])
        .env("GMC_INSPECTION_FIXTURE", &input)
        .output()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}
#[test]
fn cold_process_inspection_child() -> TestResult {
    let Some(input) = std::env::var_os("GMC_INSPECTION_FIXTURE") else {
        return Ok(());
    };
    let input: serde_json::Value = serde_json::from_slice(&fs::read(input)?)?;
    let root = Path::new(input["root"].as_str().ok_or("root absent")?);
    let id = CurrentRunId::try_new(input["run_id"].as_str().ok_or("id absent")?)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let service = runtime(root, Arc::new(CountingClock(calls.clone())))?;
    let view = service.inspect_pending_normal_chat_attempt_for_recovery(&id, "intent:one")?;
    assert_eq!(
        serde_json::to_value(view.preflight_digest())?,
        input["preflight"]
    );
    assert_eq!(
        view.policy_state(),
        NormalChatAttemptPolicyStateV2::Consumed
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}
