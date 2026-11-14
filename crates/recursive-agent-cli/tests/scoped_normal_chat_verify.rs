//! Explicit native-family scope must never be inferred from an ordinary verify.
use std::process::Command;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn scoped_verify_missing_root_is_noncreating_and_explicitly_refused() -> TestResult {
    let home = tempfile::tempdir()?;
    let root = home.path().join("absent-runtime");
    let run = root.join("a".repeat(64));
    let output = Command::new(env!("CARGO_BIN_EXE_ra"))
        .arg("verify")
        .arg("--run")
        .arg(&run)
        .arg("--normal-chat-runtime-root")
        .arg(&root)
        .output()?;
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr)?;
    assert!(error.contains("native normal-chat verification"), "{error}");
    assert!(!root.exists());
    Ok(())
}

#[test]
fn scoped_verify_rejects_a_different_runtime_parent_without_creating_a_gate() -> TestResult {
    let home = tempfile::tempdir()?;
    let root = home.path().join("runtime");
    let unrelated = home.path().join("other");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(&unrelated)?;
    let run = unrelated.join("b".repeat(64));
    std::fs::create_dir(&run)?;
    let output = Command::new(env!("CARGO_BIN_EXE_ra"))
        .arg("verify")
        .arg("--run")
        .arg(&run)
        .arg("--normal-chat-runtime-root")
        .arg(&root)
        .output()?;
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr)?;
    assert!(error.contains("native normal-chat verification"), "{error}");
    assert!(!run.join(".normal-chat-runtime.lock").exists());
    Ok(())
}
