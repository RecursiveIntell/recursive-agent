use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn run(raw: &[u8], out: &std::path::Path) -> Result<std::process::Output, std::io::Error> {
    let input = tempfile::NamedTempFile::new()?;
    std::fs::write(input.path(), raw)?;
    Command::new(env!("CARGO_BIN_EXE_ra"))
        .args(["run", "--spec"])
        .arg(input.path())
        .arg("--out")
        .arg(out)
        .output()
}

fn run_root_count(path: &std::path::Path) -> Result<usize, std::io::Error> {
    Ok(std::fs::read_dir(path)?.count())
}

fn echo_spec(extra: &str) -> Vec<u8> {
    format!(
        r#"{{"name":"ingress-red","policy_version":"m0-2","steps":[{{"name":"echo","call":{{"tool":"echo","args":{{"text":"ok"}}}}}}]{extra}}}"#
    )
    .into_bytes()
}

#[test]
fn unknown_fields_reject_before_run_creation() -> TestResult {
    for raw in [
        echo_spec(",\"unknown_top\":true"),
        br#"{"name":"u-step","policy_version":"m0-2","steps":[{"name":"echo","unknown_step":true,"call":{"tool":"echo","args":{"text":"ok"}}}]}"#.to_vec(),
        br#"{"name":"u-call","policy_version":"m0-2","steps":[{"name":"echo","call":{"tool":"echo","unknown_call":true,"args":{"text":"ok"}}}]}"#.to_vec(),
        br#"{"name":"u-shell","policy_version":"m0-2","steps":[{"name":"shell","call":{"tool":"shell","args":{"command":"/usr/bin/printf","args":["ok"],"allowed_read_paths":[],"allowed_write_paths":[],"allow_network":false,"timeout_ms":1000,"max_output_bytes":1024,"unknown_shell":true}}}]}"#.to_vec(),
    ] {
        let out = tempfile::tempdir()?;
        let result = run(&raw, out.path())?;
        assert_eq!(result.status.code(), Some(2));
        assert_eq!(run_root_count(out.path())?, 0);
    }
    Ok(())
}

#[test]
fn recursive_duplicate_keys_reject_before_run_creation() -> TestResult {
    let out = tempfile::tempdir()?;
    let raw = br#"{"name":"dup","policy_version":"m0-2","steps":[{"name":"shell","call":{"tool":"shell","args":{"command":"/usr/bin/printf","args":["ok"],"allowed_read_paths":[],"allowed_write_paths":[],"allow_network":true,"allow_network":false,"timeout_ms":1000,"max_output_bytes":1024}}}]}"#;
    let result = run(raw, out.path())?;
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(run_root_count(out.path())?, 0);
    Ok(())
}

#[test]
fn oversized_whitespace_and_aggregate_material_reject_at_transport_boundary() -> TestResult {
    let out = tempfile::tempdir()?;
    let mut whitespace = vec![b' '; 2 * 1024 * 1024];
    whitespace.extend(echo_spec(""));
    let result = run(&whitespace, out.path())?;
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(run_root_count(out.path())?, 0);

    let out = tempfile::tempdir()?;
    let material = "x".repeat(600 * 1024);
    let raw = serde_json::to_vec(&serde_json::json!({
        "name": "aggregate",
        "policy_version": "m0-2",
        "steps": [{"name": "echo", "call": {"tool": "echo", "args": {"text": material}}}]
    }))?;
    let result = run(&raw, out.path())?;
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(run_root_count(out.path())?, 0);
    Ok(())
}

#[test]
fn excess_steps_reject_before_identity_or_dispatch() -> TestResult {
    let out = tempfile::tempdir()?;
    let steps = (0..5)
        .map(|index| {
            serde_json::json!({
                "name": format!("step-{index}"),
                "call": {"tool": "echo", "args": {"text": "ok"}}
            })
        })
        .collect::<Vec<_>>();
    let raw = serde_json::to_vec(&serde_json::json!({
        "name": "too-many",
        "policy_version": "m0-2",
        "steps": steps
    }))?;
    let result = run(&raw, out.path())?;
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(run_root_count(out.path())?, 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn fifo_device_and_symlink_inputs_are_rejected_without_blocking() -> TestResult {
    let root = tempfile::tempdir()?;
    let fifo = root.path().join("spec.fifo");
    let mkfifo = Command::new("mkfifo").arg(&fifo).status()?;
    assert!(mkfifo.success());
    let out = tempfile::tempdir()?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_ra"))
        .args(["run", "--spec"])
        .arg(&fifo)
        .arg("--out")
        .arg(out.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_millis(250);
    while Instant::now() < deadline && child.try_wait()?.is_none() {
        std::thread::sleep(Duration::from_millis(5));
    }
    if child.try_wait()?.is_none() {
        child.kill()?;
    }
    let output = child.wait_with_output()?;
    assert_eq!(
        output.status.code(),
        Some(2),
        "FIFO input blocked or entered parsing"
    );
    assert_eq!(run_root_count(out.path())?, 0);

    for path in [
        std::path::Path::new("/dev/null"),
        std::path::Path::new("/dev/zero"),
    ] {
        let out = tempfile::tempdir()?;
        let output = Command::new(env!("CARGO_BIN_EXE_ra"))
            .args(["run", "--spec"])
            .arg(path)
            .arg("--out")
            .arg(out.path())
            .output()?;
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("regular file"));
        assert_eq!(run_root_count(out.path())?, 0);
    }

    let target = root.path().join("target.json");
    std::fs::write(&target, echo_spec(""))?;
    let link = root.path().join("link.json");
    std::os::unix::fs::symlink(&target, &link)?;
    let out = tempfile::tempdir()?;
    let output = Command::new(env!("CARGO_BIN_EXE_ra"))
        .args(["run", "--spec"])
        .arg(&link)
        .arg("--out")
        .arg(out.path())
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(run_root_count(out.path())?, 0);
    Ok(())
}

#[test]
fn rejected_input_never_reaches_shell_dispatch() -> TestResult {
    let marker_root = tempfile::tempdir()?;
    let marker = marker_root.path().join("dispatch-marker");
    let out = tempfile::tempdir()?;
    let raw = serde_json::to_vec(&serde_json::json!({
        "name": "reject-no-dispatch",
        "unknown_top": true,
        "policy_version": "m0-2",
        "steps": [{"name": "shell", "call": {"tool": "shell", "args": {
            "command": "/usr/bin/bash",
            "args": ["-c", format!("printf x > {}", marker.display())],
            "allowed_read_paths": [],
            "allowed_write_paths": [marker_root.path()],
            "allow_network": false,
            "timeout_ms": 1000,
            "max_output_bytes": 1024
        }}}]
    }))?;
    let result = run(&raw, out.path())?;
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(run_root_count(out.path())?, 0);
    assert!(!marker.exists());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn hostile_launcher_environment_cannot_execute_before_sandbox() -> TestResult {
    let hostile_root = tempfile::tempdir()?;
    let marker = hostile_root.path().join("bash-env-escaped");
    let bash_env = hostile_root.path().join("bash-env.sh");
    std::fs::write(
        &bash_env,
        format!("printf escaped > {}\n", marker.display()),
    )?;
    let spec = tempfile::NamedTempFile::new()?;
    std::fs::write(
        spec.path(),
        serde_json::to_vec(&serde_json::json!({
            "name": "hostile-launcher-environment",
            "policy_version": "m0-2",
            "steps": [{
                "name": "safe-command",
                "call": {"tool": "shell", "args": {
                    "command": "/usr/bin/printf",
                    "args": ["safe"],
                    "allowed_read_paths": [],
                    "allowed_write_paths": [],
                    "allow_network": false,
                    "timeout_ms": 2000,
                    "max_output_bytes": 1024
                }}
            }]
        }))?,
    )?;
    let out = tempfile::tempdir()?;
    let output = Command::new(env!("CARGO_BIN_EXE_ra"))
        .args(["run", "--spec"])
        .arg(spec.path())
        .arg("--out")
        .arg(out.path())
        .env("BASH_ENV", &bash_env)
        .output()?;

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(!marker.exists(), "BASH_ENV executed before Bubblewrap");
    Ok(())
}

#[test]
fn valid_multi_step_sibling_keys_decode_and_execute() -> TestResult {
    let out = tempfile::tempdir()?;
    let raw = br#"{"name":"valid-siblings","policy_version":"m0-2","steps":[{"name":"one","call":{"tool":"echo","args":{"text":"first"}}},{"name":"two","call":{"tool":"echo","args":{"text":"second"}}}]}"#;
    let output = run(raw, out.path())?;
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(run_root_count(out.path())?, 1);
    Ok(())
}
