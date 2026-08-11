//! Cross-owner regression contract for the daemon-emitted `repo_audit` operation.
#![allow(clippy::expect_used)]

use std::process::Command;

use recursive_agent_contracts::OperationEnvelopeV1;

#[test]
fn emitted_repo_audit_operation_carries_no_caller_filesystem_authority(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let output = Command::new(env!("CARGO_BIN_EXE_ra-daemon"))
        .args([
            "emit-repo-audit-envelope",
            "--audit-root",
            root.path().to_str().expect("temporary path is utf-8"),
        ])
        .output()?;
    assert!(
        output.status.success(),
        "envelope command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let envelope: OperationEnvelopeV1 = serde_json::from_slice(&output.stdout)?;
    let step = &envelope.run_spec.steps[0];
    assert_eq!(step.call.tool, "repo_audit");
    assert!(
        step.call
            .args
            .get("scope_digest")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|digest| digest.len() == 64),
        "repo_audit must bind a non-path configured-scope digest"
    );
    let other_root = tempfile::tempdir()?;
    let other_output = Command::new(env!("CARGO_BIN_EXE_ra-daemon"))
        .args([
            "emit-repo-audit-envelope",
            "--audit-root",
            other_root.path().to_str().expect("temporary path is utf-8"),
        ])
        .output()?;
    assert!(other_output.status.success());
    let other_envelope: OperationEnvelopeV1 = serde_json::from_slice(&other_output.stdout)?;
    assert_ne!(
        step.call.args["scope_digest"], other_envelope.run_spec.steps[0].call.args["scope_digest"],
        "the operation identity must bind the configured audit scope without exposing a path"
    );

    assert!(envelope.effects.read_roots.is_empty());
    assert!(envelope.effects.write_roots.is_empty());
    assert!(!envelope.effects.network_allowed);
    envelope.validate()?;
    Ok(())
}
