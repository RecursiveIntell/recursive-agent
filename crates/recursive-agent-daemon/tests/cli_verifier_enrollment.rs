use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use base64::Engine;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn serve_with_enrollment(
    enrollment: &std::path::Path,
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let parent = enrollment
        .parent()
        .ok_or("enrollment lacks parent directory")?;
    let root = parent.join("runs");
    let socket = parent.join("ra.sock");
    Ok(Command::new(env!("CARGO_BIN_EXE_ra-daemon"))
        .arg("serve")
        .arg("--root")
        .arg(root)
        .arg("--socket")
        .arg(socket)
        .arg("--production-verifier-file")
        .arg(enrollment)
        .output()?)
}

fn write_enrollment(
    dir: &std::path::Path,
    value: serde_json::Value,
    mode: u32,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("verifier.json");
    std::fs::write(&path, serde_json::to_vec(&value)?)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
    Ok(path)
}

#[test]
fn daemon_refuses_world_readable_production_verifier_enrollment() -> TestResult {
    let temp = tempfile::tempdir()?;
    let enrollment = write_enrollment(
        temp.path(),
        serde_json::json!({
            "schema": "recursive-agent.desktop-production-public-key/v1",
            "key_id": "desktop-key",
            "public_key": base64::engine::general_purpose::STANDARD.encode([7_u8; 32]),
        }),
        0o644,
    )?;
    let output = serve_with_enrollment(&enrollment)?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("mode 0600"));
    Ok(())
}

#[test]
fn daemon_refuses_unknown_or_malformed_production_verifier_enrollment() -> TestResult {
    let temp = tempfile::tempdir()?;
    let enrollment = write_enrollment(
        temp.path(),
        serde_json::json!({
            "schema": "recursive-agent.desktop-production-public-key/v1",
            "key_id": "desktop-key",
            "public_key": "not-base64",
            "unexpected": true,
        }),
        0o600,
    )?;
    let output = serve_with_enrollment(&enrollment)?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown field"));
    Ok(())
}

#[test]
fn daemon_refuses_wrong_length_production_verifier_key() -> TestResult {
    let temp = tempfile::tempdir()?;
    let enrollment = write_enrollment(
        temp.path(),
        serde_json::json!({
            "schema": "recursive-agent.desktop-production-public-key/v1",
            "key_id": "desktop-key",
            "public_key": base64::engine::general_purpose::STANDARD.encode([7_u8; 31]),
        }),
        0o600,
    )?;
    let output = serve_with_enrollment(&enrollment)?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("exactly 32 bytes"));
    Ok(())
}
