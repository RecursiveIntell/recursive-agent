use super::*;
use recursive_agent_ledger::NormalChatSessionGateV1 as Gate;
use recursive_agent_policy::NormalChatReportedStateV2;
use std::{collections::BTreeMap, path::PathBuf};
type FixtureImage = BTreeMap<PathBuf, (bool, u32, Vec<u8>)>;
fn image(base: &Path) -> Result<FixtureImage, Box<dyn std::error::Error>> {
    fn visit(base: &Path, dir: &Path, out: &mut FixtureImage) -> TestResult {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let p = entry.path();
            let meta = entry.metadata()?;
            if meta.is_dir() {
                out.insert(
                    p.strip_prefix(base)?.to_path_buf(),
                    (true, meta.permissions().mode() & 0o777, Vec::new()),
                );
                visit(base, &p, out)?;
            } else if meta.is_file() {
                out.insert(
                    p.strip_prefix(base)?.to_path_buf(),
                    (false, meta.permissions().mode() & 0o777, fs::read(&p)?),
                );
            } else {
                return Err("unexpected fixture component".into());
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    visit(base, base, &mut out)?;
    Ok(out)
}
#[test]
fn ledger_owned_guard_excludes_runtime_bootstrap_before_authority_creation() -> TestResult {
    let fx = Fixture::new()?;
    let path = fx.run_dir()?;
    fs::create_dir(&path)?;
    let root = File::open(&path)?;
    let held = Gate::acquire(&root)?;
    let before = image(fx.root.path())?;
    assert!(matches!(
        fx.service()?
            .open_normal_chat_session("conversation:fixture"),
        Err(RuntimeServiceError::NormalChatSessionBusy)
    ));
    assert_eq!(image(fx.root.path())?, before);
    assert!(!path.join("permits").exists());
    held.check(&root)?;
    held.unlock()?;
    let session = fx
        .service()?
        .open_normal_chat_session("conversation:fixture")?;
    assert_eq!(
        appendable_snapshot_expected_run_from_dir_fd(&root, session.run_id())?
            .receipts()
            .len(),
        3
    );
    Ok(())
}
#[test]
fn ledger_owned_guard_excludes_all_current_session_paths_without_a_second_lock_namespace(
) -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:shared-gate")?;
    let fresh = match service.begin_normal_chat_attempt(&session, &req)? {
        RuntimeNormalChatBeginV2::Fresh(f) => f,
        _ => return Err("first admission not Fresh".into()),
    };
    let preflight = fresh.preflight_digest().clone();
    drop(fresh);
    fx.clock.0.store(2000, Ordering::SeqCst);
    let root = File::open(session.run_dir())?;
    let held = Gate::acquire_existing(&root)?;
    let before = image(fx.root.path())?;
    let report = super::terminal::report(NormalChatReportedStateV2::NotSent)?;
    macro_rules! busy {
        ($name:expr,$call:expr) => {{
            let value = $call;
            assert!(
                matches!(&value, Err(RuntimeServiceError::NormalChatSessionBusy)),
                "{}: {:?}",
                $name,
                value.as_ref().map(|_| ())
            );
            assert_eq!(
                image(fx.root.path())?,
                before,
                "{} changed retained state",
                $name
            );
        }};
    }
    busy!(
        "open",
        service.open_normal_chat_session("conversation:fixture")
    );
    busy!("begin", service.begin_normal_chat_attempt(&session, &req));
    busy!(
        "settle",
        service.settle_normal_chat_attempt(&session, &req, &preflight, &report)
    );
    busy!("close", service.close_normal_chat_session(&session));
    busy!(
        "resume",
        service.resume_normal_chat_session("conversation:fixture")
    );
    busy!(
        "inspect",
        service.inspect_pending_normal_chat_attempt_for_recovery(
            session.run_id(),
            "intent:shared-gate"
        )
    );
    let recovery = runtime(fx.root.path(), fx.clock.clone())?.with_expired_normal_chat_recovery();
    busy!(
        "recover",
        recovery.recover_expired_normal_chat_attempt(session.run_id(), "intent:shared-gate")
    );
    held.check(&root)?;
    held.unlock()?;
    service.settle_normal_chat_attempt(&session, &req, &preflight, &report)?;
    assert!(matches!(
        service.begin_normal_chat_attempt(&session, &req)?,
        RuntimeNormalChatBeginV2::Existing(_)
    ));
    service.resume_normal_chat_session("conversation:fixture")?;
    Ok(())
}
