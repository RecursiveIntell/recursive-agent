//! Contract tests for the bounded source-audit primitive.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;

use recursive_agent_daemon::repo_audit::{audit_root, AuditError, AuditLimits};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn audit_is_stable_and_reports_only_regular_files_beneath_the_fixed_root() -> TestResult {
    let root = tempfile::tempdir()?;
    fs::create_dir(root.path().join("src"))?;
    fs::write(
        root.path().join("src/lib.rs"),
        "// TODO: bounded audit\nfn ok() {}\n",
    )?;
    fs::write(root.path().join("README.md"), "# audit fixture\n")?;
    #[cfg(unix)]
    std::os::unix::fs::symlink("/etc/passwd", root.path().join("escape"))?;

    let first = audit_root(root.path(), AuditLimits::test_defaults())?;
    let second = audit_root(root.path(), AuditLimits::test_defaults())?;

    assert_eq!(first, second, "audit output must be deterministic");
    assert_eq!(first.schema, "recursive-agent.repo-audit/v4");
    assert_eq!(
        first.marker_scope,
        "ordinary-rust-line-comments-v1; executable-panic-macros-v1"
    );
    assert_eq!(first.files_scanned, 2);
    assert_eq!(first.todo_markers.len(), 1);
    assert_eq!(first.todo_markers[0].path, "src/lib.rs");
    assert_eq!(first.todo_markers[0].line, 1);
    assert_eq!(first.proposal_candidates.len(), 1);
    assert_eq!(first.proposal_candidates[0].path, "src/lib.rs");
    assert_eq!(first.proposal_candidates[0].line, 1);
    assert_eq!(first.proposal_candidates[0].marker, "TODO");
    assert_eq!(
        first.proposal_candidates[0].advisory_action,
        "Review and resolve the source marker; no source change is authorized by this audit."
    );
    assert!(first.skipped_symlinks >= 1);
    assert!(!serde_json::to_string(&first)?.contains("/etc/passwd"));
    Ok(())
}

#[test]
fn audit_reports_only_executable_panic_macro_candidates() -> TestResult {
    let root = tempfile::tempdir()?;
    fs::create_dir(root.path().join("src"))?;
    fs::write(
        root.path().join("src/lib.rs"),
        r##"
// todo!()
/* unimplemented!() */
let a = "todo!()";
let b = r#"unimplemented!()"#;
fn actual() { todo!() }
fn also_actual() { unimplemented!() }
"##,
    )?;

    let audit = audit_root(root.path(), AuditLimits::test_defaults())?;

    assert_eq!(audit.panic_macros.len(), 2);
    assert_eq!(audit.panic_macros[0].line, 6);
    assert_eq!(audit.panic_macros[0].macro_name, "todo!");
    assert_eq!(audit.panic_macros[1].line, 7);
    assert_eq!(audit.panic_macros[1].macro_name, "unimplemented!");
    assert_eq!(audit.proposal_candidates.len(), 2);
    assert!(audit
        .proposal_candidates
        .iter()
        .all(|candidate| candidate.advisory_action.contains("panic macro")));
    Ok(())
}

#[test]
fn audit_reports_only_actionable_rust_comment_markers() -> TestResult {
    let root = tempfile::tempdir()?;
    fs::create_dir(root.path().join("src"))?;
    fs::create_dir_all(root.path().join("tests/fixtures"))?;
    fs::create_dir_all(root.path().join("docs/receipts"))?;
    fs::write(
        root.path().join("src/lib.rs"),
        concat!(
            "let quoted = \"TODO: false positive\";\n",
            "let raw = r#\"FIXME: false positive\"#;\n",
            "// TODO: bound retry delay\n",
            "// FIXME\n",
        ),
    )?;
    fs::write(
        root.path().join("tests/fixtures/example.rs"),
        "// TODO: fixture must not report\n",
    )?;
    fs::write(
        root.path().join("docs/receipts/HISTORY.md"),
        "<!-- TODO: historical receipt -->\n",
    )?;

    let audit = audit_root(root.path(), AuditLimits::test_defaults())?;

    assert_eq!(audit.todo_markers.len(), 1);
    assert_eq!(audit.todo_markers[0].path, "src/lib.rs");
    assert_eq!(audit.todo_markers[0].line, 3);
    assert_eq!(audit.todo_markers[0].marker, "TODO");
    Ok(())
}

#[test]
fn audit_rejects_a_root_outside_its_configured_canonical_boundary() -> TestResult {
    let configured = tempfile::tempdir()?;
    let other = tempfile::tempdir()?;
    let limits = AuditLimits::test_defaults();
    let error = audit_root(
        other.path(),
        limits.with_configured_root(configured.path())?,
    )
    .expect_err("different root must not be audited");
    assert!(matches!(error, AuditError::RootMismatch));
    Ok(())
}

#[test]
fn audit_fails_closed_when_directory_entry_budget_is_exceeded() -> TestResult {
    let root = tempfile::tempdir()?;
    for name in ["one", "two", "three"] {
        fs::create_dir(root.path().join(name))?;
    }

    let limits = AuditLimits::test_defaults().with_max_directory_entries(2)?;
    let error = audit_root(root.path(), limits).expect_err("traversal must stop at entry budget");

    assert!(matches!(error, AuditError::TraversalLimitExceeded));
    Ok(())
}

#[test]
fn audit_fails_closed_when_directory_depth_budget_is_exceeded() -> TestResult {
    let root = tempfile::tempdir()?;
    fs::create_dir_all(root.path().join("one/two"))?;

    let limits = AuditLimits::test_defaults().with_max_directory_depth(1)?;
    let error = audit_root(root.path(), limits).expect_err("traversal must stop at depth budget");

    assert!(matches!(error, AuditError::TraversalLimitExceeded));
    Ok(())
}

#[test]
fn audit_fails_closed_when_regular_file_budget_is_exceeded() -> TestResult {
    let root = tempfile::tempdir()?;
    fs::write(root.path().join("one.rs"), "fn one() {}\n")?;
    fs::write(root.path().join("two.rs"), "fn two() {}\n")?;
    let limits = AuditLimits::test_defaults().with_max_files(1)?;
    let error = audit_root(root.path(), limits).expect_err("limit must fail closed");
    assert!(matches!(error, AuditError::FileLimitExceeded));
    Ok(())
}
