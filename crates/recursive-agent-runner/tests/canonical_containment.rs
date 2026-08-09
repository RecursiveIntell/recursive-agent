mod support;

use recursive_agent_contracts::{RunSpecV1, RunTerminalStateV1, StepSpecV1, ToolCallSpecV1};
use recursive_agent_ledger::{open, verified_snapshot_directory_bound, RunPaths};
use recursive_agent_sandbox::{EnforcementOutcome, SandboxResult, SandboxSpec};
use std::fmt::{Display, Formatter};
use support::run_spec;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn shell_spec(script: String) -> SandboxSpec {
    SandboxSpec {
        command: "/usr/bin/bash".into(),
        args: vec!["-c".into(), script],
        allowed_read_paths: vec![],
        allowed_write_paths: vec![],
        allow_network: false,
        timeout_ms: 1_000,
        max_output_bytes: 64 * 1024,
    }
}

#[derive(Debug)]
enum CanonicalError {
    Terminal(RunTerminalStateV1),
    Other(String),
}

impl Display for CanonicalError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Terminal(state) => write!(formatter, "canonical run terminal: {state:?}"),
            Self::Other(reason) => formatter.write_str(reason),
        }
    }
}

impl std::error::Error for CanonicalError {}

fn execute(spec: &SandboxSpec) -> Result<SandboxResult, CanonicalError> {
    let root = tempfile::tempdir().map_err(|error| CanonicalError::Other(error.to_string()))?;
    let call = ToolCallSpecV1 {
        tool: "shell".into(),
        args: serde_json::to_value(spec)
            .map_err(|error| CanonicalError::Other(error.to_string()))?,
        frozen_clock: None,
    };
    let run = RunSpecV1 {
        name: "canonical-containment".into(),
        steps: vec![StepSpecV1 {
            name: "shell".into(),
            call,
        }],
        frozen_clock: None,
        policy_version: "m0-2".into(),
    };
    let summary =
        run_spec(&run, root.path()).map_err(|error| CanonicalError::Other(error.to_string()))?;
    let paths = RunPaths::new(summary.run_dir.clone());
    let snapshot = verified_snapshot_directory_bound(&paths)
        .map_err(|error| CanonicalError::Other(error.to_string()))?;
    let store = open(&paths)
        .and_then(|chain| chain.artifact_store())
        .map_err(|error| CanonicalError::Other(error.to_string()))?;
    for receipt in snapshot.receipts().iter().rev() {
        for descriptor in receipt.artifact_refs.iter().rev() {
            let bytes = store
                .get(descriptor)
                .map_err(|error| CanonicalError::Other(error.to_string()))?;
            if let Ok(result) = serde_json::from_slice::<SandboxResult>(&bytes) {
                return Ok(result);
            }
        }
    }
    Err(CanonicalError::Terminal(summary.terminal_state))
}

fn assert_fail_closed(result: Result<SandboxResult, CanonicalError>) -> TestResult {
    match result {
        Ok(result) => assert_eq!(result.enforcement.outcome, EnforcementOutcome::Enforced),
        Err(CanonicalError::Terminal(state)) => {
            assert_ne!(state, RunTerminalStateV1::Succeeded);
        }
        Err(other) => return Err(format!("unexpected canonical runner error: {other:?}").into()),
    }
    Ok(())
}

fn assert_rejected_before_or_during_run(result: Result<SandboxResult, CanonicalError>) {
    match result {
        Ok(result) => assert_ne!(result.exit_code, Some(0)),
        Err(CanonicalError::Terminal(state)) => assert_ne!(state, RunTerminalStateV1::Succeeded),
        Err(CanonicalError::Other(_)) => {}
    }
}

#[test]
fn implementation_contains_no_local_unsafe_or_landlock_claim() {
    let engine = include_str!("../src/sandbox_engine.rs");
    let public_sandbox = include_str!("../../recursive-agent-sandbox/src/lib.rs");
    assert!(!engine.contains("unsafe {"));
    assert!(!engine.contains("allow(unsafe_code)"));
    assert!(!engine.contains("Landlock"));
    assert!(!engine.contains("pre_exec"));
    assert!(!engine.contains("fcntl_setfd"));
    assert!(!engine.contains("fn inherit_fd"));
    assert!(engine.contains("PosixSpawnFileActions"));
    assert!(!public_sandbox.contains("Command::new"));
    assert!(!public_sandbox.contains("pub fn execute"));
}

#[test]
fn runner_private_dispatch_and_zero_timeout_fail_before_effect() -> TestResult {
    let public_sandbox = include_str!("../../recursive-agent-sandbox/src/lib.rs");
    let engine = include_str!("../src/sandbox_engine.rs");
    assert!(!public_sandbox.contains("pub fn execute"));
    assert!(engine.contains("pub(super) fn execute"));
    assert!(engine.contains("context: DispatchToken"));
    let root = tempfile::tempdir()?;
    let marker = root.path().join("effect-ran");
    let mut spec = shell_spec(format!("touch {}", marker.display()));
    spec.allowed_write_paths
        .push(root.path().display().to_string());
    spec.timeout_ms = 0;
    assert_rejected_before_or_during_run(execute(&spec));
    assert!(!marker.exists());
    Ok(())
}

#[test]
fn one_consumed_dispatch_is_not_replayed_on_second_run() -> TestResult {
    let output = tempfile::tempdir()?;
    let writable = tempfile::tempdir()?;
    let marker = writable.path().join("one-shot-marker");
    let sandbox = SandboxSpec {
        command: "/usr/bin/bash".into(),
        args: vec!["-c".into(), format!("printf x >> {}", marker.display())],
        allowed_read_paths: vec![],
        allowed_write_paths: vec![writable.path().display().to_string()],
        allow_network: false,
        timeout_ms: 2_000,
        max_output_bytes: 1_024,
    };
    let run = RunSpecV1 {
        name: "one-shot-dispatch".into(),
        steps: vec![StepSpecV1 {
            name: "shell".into(),
            call: ToolCallSpecV1 {
                tool: "shell".into(),
                args: serde_json::to_value(sandbox)?,
                frozen_clock: None,
            },
        }],
        frozen_clock: None,
        policy_version: "m0-2".into(),
    };
    let first = run_spec(&run, output.path())?;
    assert_eq!(first.terminal_state, RunTerminalStateV1::Succeeded);
    assert_eq!(std::fs::read(&marker)?, b"x");
    let second = run_spec(&run, output.path())?;
    assert_eq!(second.chain_head, first.chain_head);
    assert_eq!(second.chain_length, first.chain_length);
    assert_eq!(std::fs::read(&marker)?, b"x");
    Ok(())
}

#[test]
fn missing_allow_path_fails_before_launcher() {
    let mut spec = shell_spec("true".into());
    spec.allowed_read_paths
        .push("/definitely/missing/recursive-agent-path".into());
    assert_rejected_before_or_during_run(execute(&spec));
}

#[test]
fn filesystem_and_network_attempts_are_denied_or_host_fails_closed() -> TestResult {
    let root = tempfile::tempdir()?;
    let writable = root.path().join("writable");
    std::fs::create_dir(&writable)?;
    let outside = root.path().join("outside");
    std::fs::write(&outside, b"original")?;
    let script = format!(
        "set +e; touch {0}; rm -f {0}; mv {0} {0}.moved; : > {0}; touch {1}/inside; cat /etc/passwd; exit 0",
        outside.display(),
        writable.display()
    );
    let mut spec = shell_spec(script);
    spec.allowed_read_paths
        .push(root.path().display().to_string());
    spec.allowed_write_paths
        .push(writable.display().to_string());
    match execute(&spec) {
        Ok(result) => {
            assert_eq!(result.enforcement.outcome, EnforcementOutcome::Enforced);
            assert_eq!(std::fs::read(&outside)?, b"original");
            assert!(!root.path().join("outside.moved").exists());
            assert!(writable.join("inside").exists());
            assert!(!result.stdout.contains("root:"));
            assert!(result.enforcement.network_isolated);
        }
        error => assert_fail_closed(error)?,
    }

    let network = SandboxSpec {
        command: "/usr/bin/python3.14".into(),
        args: vec![
            "-c".into(),
            "import socket; s=socket.socket(); s.settimeout(.2); s.connect(('127.0.0.1',9))".into(),
        ],
        allowed_read_paths: vec![],
        allowed_write_paths: vec![],
        allow_network: false,
        timeout_ms: 1_000,
        max_output_bytes: 64 * 1024,
    };
    match execute(&network) {
        Ok(result) => {
            assert_eq!(result.enforcement.outcome, EnforcementOutcome::Enforced);
            assert_ne!(result.exit_code, Some(0));
        }
        error => assert_fail_closed(error)?,
    }
    Ok(())
}

#[test]
fn fixed_printf_is_mandatorily_enforced_on_this_host() -> TestResult {
    let spec = SandboxSpec {
        command: "/usr/bin/printf".into(),
        args: vec!["sandbox-positive".into()],
        allowed_read_paths: vec![],
        allowed_write_paths: vec![],
        allow_network: false,
        timeout_ms: 2_000,
        max_output_bytes: 1_024,
    };
    let result = execute(&spec)?;
    assert_eq!(result.enforcement.outcome, EnforcementOutcome::Enforced);
    assert_eq!(result.stdout, "sandbox-positive");
    assert!(result.enforcement.network_isolated);
    assert!(result.enforcement.setup_proof_verified);
    assert!(result.enforcement.seccomp_policy_digest.is_some());
    assert!(result
        .enforcement
        .effective_runtime_read_roots
        .iter()
        .any(|root| root == "/usr"));
    Ok(())
}

#[test]
fn network_socket_creation_receives_eperm_under_enforcement() -> TestResult {
    let spec = SandboxSpec {
        command: "/usr/bin/python3.14".into(),
        args: vec![
            "-c".into(),
            "import errno,socket,sys\ntry:\n socket.socket()\nexcept OSError as e:\n print(e.errno)\n sys.exit(0 if e.errno == errno.EPERM else 3)\nsys.exit(4)".into(),
        ],
        allowed_read_paths: vec![],
        allowed_write_paths: vec![],
        allow_network: false,
        timeout_ms: 2_000,
        max_output_bytes: 1_024,
    };
    let result = execute(&spec)?;
    assert_eq!(result.enforcement.outcome, EnforcementOutcome::Enforced);
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.stdout.trim(), "1");
    assert!(result
        .enforcement
        .denied_network_syscalls
        .iter()
        .any(|name| name == "socket"));
    Ok(())
}

#[test]
fn undeclared_read_and_descendant_are_mandatorily_bounded() -> TestResult {
    let root = tempfile::tempdir()?;
    let sentinel = root.path().join("undeclared-sentinel");
    std::fs::write(&sentinel, b"must-not-read")?;
    let mut read_spec = shell_spec(format!(
        "if cat {} 2>/dev/null; then exit 7; else printf denied; fi",
        sentinel.display()
    ));
    read_spec.timeout_ms = 2_000;
    let read = execute(&read_spec)?;
    assert_eq!(read.enforcement.outcome, EnforcementOutcome::Enforced);
    assert_eq!(read.exit_code, Some(0));
    assert_eq!(read.stdout, "denied");

    let mut descendant = shell_spec("sleep 30 & wait".into());
    descendant.timeout_ms = 100;
    let started = std::time::Instant::now();
    let result = execute(&descendant)?;
    assert_eq!(result.enforcement.outcome, EnforcementOutcome::Enforced);
    assert!(result.timed_out);
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    Ok(())
}

#[cfg(unix)]
#[test]
fn active_mount_source_replacement_never_exposes_attacker_bytes() -> TestResult {
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let root = tempfile::tempdir()?;
    let declared = root.path().join("declared");
    let parked = root.path().join("parked");
    let attacker = root.path().join("attacker");
    std::fs::create_dir(&declared)?;
    std::fs::create_dir(&attacker)?;
    std::fs::write(declared.join("sentinel"), b"safe")?;
    std::fs::write(attacker.join("sentinel"), b"attacker")?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let declared_for_thread = declared.clone();
    let parked_for_thread = parked.clone();
    let attacker_for_thread = attacker.clone();
    let replacer = std::thread::spawn(move || {
        while !thread_stop.load(Ordering::Relaxed) {
            if std::fs::rename(&declared_for_thread, &parked_for_thread).is_ok() {
                let _ = symlink(&attacker_for_thread, &declared_for_thread);
                let _ = std::fs::remove_file(&declared_for_thread);
                let _ = std::fs::rename(&parked_for_thread, &declared_for_thread);
            }
        }
    });
    for _ in 0..20 {
        let mut spec = shell_spec(format!("cat {}/sentinel", declared.display()));
        spec.allowed_read_paths.push(declared.display().to_string());
        match execute(&spec) {
            Ok(result) => {
                assert_eq!(result.enforcement.outcome, EnforcementOutcome::Enforced);
                assert_eq!(result.stdout, "safe");
            }
            Err(CanonicalError::Terminal(_)) => {}
            Err(CanonicalError::Other(_)) => {}
        }
    }
    stop.store(true, Ordering::Relaxed);
    replacer.join().map_err(|_| "replacement thread panicked")?;
    Ok(())
}

#[test]
fn descendants_output_and_signal_races_are_bounded_or_fail_closed() -> TestResult {
    for script in [
        "setsid sh -c 'sleep 30' >/dev/null 2>&1 & wait",
        "(while :; do printf x; done) & exit 0",
        "sleep 30 & exit 0",
    ] {
        let mut spec = shell_spec(script.into());
        spec.timeout_ms = 150;
        let started = std::time::Instant::now();
        let result = execute(&spec);
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
        assert_fail_closed(result)?;
    }
    for _ in 0..10 {
        let mut spec = shell_spec("sleep 0.01".into());
        spec.timeout_ms = 10;
        assert_fail_closed(execute(&spec))?;
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn malicious_sibling_helper_is_never_consulted_by_production_execute() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    if std::env::var_os("RA_MALICIOUS_SIBLING_CHILD").is_some() {
        let spec = SandboxSpec {
            command: "/usr/bin/printf".into(),
            args: vec!["authorized".into()],
            allowed_read_paths: vec![],
            allowed_write_paths: vec![],
            allow_network: false,
            timeout_ms: 2_000,
            max_output_bytes: 1_024,
        };
        let result = execute(&spec)?;
        assert_eq!(result.enforcement.outcome, EnforcementOutcome::Enforced);
        assert_eq!(result.stdout, "authorized");
        return Ok(());
    }

    let current_exe = std::env::current_exe()?;
    let executable_parent = current_exe
        .parent()
        .ok_or("test executable has no parent")?;
    let root = tempfile::Builder::new()
        .prefix("malicious-sibling-")
        .tempdir_in(executable_parent)?;
    let consumer = root.path().join("sandbox-consumer");
    std::fs::hard_link(&current_exe, &consumer)?;
    let helper = root.path().join("recursive-agent-sandbox-launcher");
    let marker = root.path().join("malicious-helper-ran");
    let nonce_copy = root.path().join("copied-nonce");
    let direct_marker = root.path().join("direct-payload-ran");
    std::fs::write(
        &helper,
        format!(
            "#!/usr/bin/bash\nfor arg in \"$@\"; do case \"$arg\" in recursive-agent-setup-v2:*) printf '%s' \"$arg\" > '{}' ;; esac; done\ntouch '{}'\ntouch '{}'\nexit 0\n",
            nonce_copy.display(),
            marker.display(),
            direct_marker.display()
        ),
    )?;
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700))?;
    let output = std::process::Command::new(&consumer)
        .args([
            "--exact",
            "malicious_sibling_helper_is_never_consulted_by_production_execute",
            "--nocapture",
        ])
        .env("RA_MALICIOUS_SIBLING_CHILD", "1")
        .output()?;
    assert!(
        output.status.success(),
        "copied consumer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!marker.exists());
    assert!(!nonce_copy.exists());
    assert!(!direct_marker.exists());
    Ok(())
}

#[test]
fn operation_root_identity_and_access_mode_change_policy_digest() -> TestResult {
    let root = tempfile::tempdir()?;
    let declared = root.path().join("declared");
    let parked = root.path().join("parked");
    std::fs::create_dir(&declared)?;

    let mut read_spec = shell_spec("true".into());
    read_spec
        .allowed_read_paths
        .push(declared.display().to_string());
    let read = execute(&read_spec)?;
    assert_eq!(read.enforcement.outcome, EnforcementOutcome::Enforced);
    assert!(read
        .enforcement
        .effective_operation_roots
        .iter()
        .any(|entry| entry.path == declared.display().to_string() && entry.access_mode == "read"));

    let mut write_spec = shell_spec("true".into());
    write_spec
        .allowed_write_paths
        .push(declared.display().to_string());
    let write = execute(&write_spec)?;
    assert_eq!(write.enforcement.outcome, EnforcementOutcome::Enforced);
    assert_ne!(
        read.enforcement.policy_digest,
        write.enforcement.policy_digest
    );

    std::fs::rename(&declared, &parked)?;
    std::fs::create_dir(&declared)?;
    let replaced = execute(&read_spec)?;
    assert_eq!(replaced.enforcement.outcome, EnforcementOutcome::Enforced);
    assert_ne!(
        read.enforcement.policy_digest,
        replaced.enforcement.policy_digest
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn inherited_non_cloexec_descriptor_is_not_visible_to_payload() -> TestResult {
    use std::os::fd::{AsFd, AsRawFd};

    let root = tempfile::tempdir()?;
    let secret_path = root.path().join("inherited-only");
    let file = std::fs::File::create(&secret_path)?;
    rustix::io::fcntl_setfd(file.as_fd(), rustix::io::FdFlags::empty())?;
    let spec = shell_spec(format!(
        "readlink /proc/self/fd/{} || true",
        file.as_raw_fd()
    ));
    match execute(&spec) {
        Ok(result) => {
            assert_eq!(result.enforcement.outcome, EnforcementOutcome::Enforced);
            assert!(!result.stdout.contains(&secret_path.display().to_string()));
        }
        error => assert_fail_closed(error)?,
    }
    Ok(())
}
