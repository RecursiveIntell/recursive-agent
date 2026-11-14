use super::*;
use std::sync::atomic::AtomicBool;
struct MutatingClock {
    armed: AtomicBool,
    failed: AtomicBool,
    path: PathBuf,
    family: bool,
}
impl Clock for MutatingClock {
    fn now(&self) -> DateTime<Utc> {
        if self.armed.swap(false, Ordering::SeqCst) {
            let action = (|| -> TestResult {
                let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&self.path)?)?;
                if self.family {
                    value["normal_chat_session"]["closed_at"] = json!(null);
                } else {
                    if value["state"]["state"] != json!("revoked") {
                        return Err("not closed at final clock".into());
                    }
                    value["state"] = json!({"state":"issued"});
                }
                fs::write(&self.path, jcs_canonical(&value)?)?;
                Ok(())
            })();
            self.failed.store(action.is_err(), Ordering::SeqCst);
        }
        start() + TimeDelta::hours(1)
    }
}
#[test]
fn parent_recovery_final_clock_cannot_reclose_downgraded_native_pair() -> TestResult {
    for family in [false, true] {
        let fx = Fixture::new()?;
        let (session, _) = closed(&fx, None)?;
        let path = if family {
            session.run_dir().join("family-authority.json")
        } else {
            native_path(&session)?
        };
        let clock = Arc::new(MutatingClock {
            armed: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            path: path.clone(),
            family,
        });
        let result = runtime(fx.root.path(), clock.clone())?
            .with_normal_chat_parent_recovery(true)
            .recover_normal_chat_session_parent_with_observer(session.run_id(), None, || {
                clock.armed.store(true, Ordering::SeqCst);
            });
        assert!(!clock.failed.load(Ordering::SeqCst));
        assert!(
            !clock.armed.load(Ordering::SeqCst),
            "final clock not exercised"
        );
        assert!(result.is_err());
        let raw: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
        if family {
            assert_eq!(raw["normal_chat_session"]["closed_at"], json!(null));
        } else {
            assert_eq!(raw["state"], json!({"state":"issued"}));
        }
    }
    Ok(())
}
#[test]
fn parent_recovery_published_suffix_against_issued_root_refuses_without_repair() -> TestResult {
    let fx = Fixture::new()?;
    let (session, _) = closed(&fx, None)?;
    let (service, _) = reader(&fx)?;
    service
        .with_normal_chat_parent_recovery(true)
        .recover_normal_chat_session_parent(session.run_id())?;
    let path = native_path(&session)?;
    let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    v["state"] = json!({"state":"issued"});
    fs::write(path, jcs_canonical(&v)?)?;
    let before = tree(fx.root.path())?;
    let (service, calls) = reader(&fx)?;
    assert!(service
        .with_normal_chat_parent_recovery(true)
        .recover_normal_chat_session_parent(session.run_id())
        .is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(tree(fx.root.path())?, before);
    Ok(())
}
