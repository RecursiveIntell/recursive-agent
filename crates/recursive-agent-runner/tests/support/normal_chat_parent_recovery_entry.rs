//! Entry-point boundary: recovery never bootstraps a missing canonical parent.
use super::*;
#[test]
fn parent_recovery_existing_only_does_not_create_parent_or_gate() -> TestResult {
    let fx = Fixture::new()?;
    let id = fx
        .authority
        .normal_chat_session("conversation:fixture", None)?
        .run_id()?;
    let service = runtime(fx.root.path(), fx.clock.clone())?.with_normal_chat_parent_recovery(true);
    assert!(service.recover_normal_chat_session_parent(&id).is_err());
    assert_eq!(fs::read_dir(fx.root.path())?.count(), 0);
    assert!(!fx.run_dir()?.exists());
    Ok(())
}
