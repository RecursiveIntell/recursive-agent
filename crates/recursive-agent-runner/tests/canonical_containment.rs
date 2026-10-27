mod support;

use recursive_agent_contracts::{
    ReceiptKindV1, RunSpecV1, RunTerminalStateV1, StepSpecV1, ToolCallSpecV1,
};
use recursive_agent_ledger::{open, verified_snapshot_directory_bound, RunPaths};
use recursive_agent_sandbox::{
    EnforcementOutcome, EnforcementRecord, SandboxFailureReason, SandboxResult, SandboxSpec,
};
use std::fmt::{Display, Formatter};
use support::run_spec;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn canonical_system_python() -> Result<String, Box<dyn std::error::Error>> {
    let path = std::fs::canonicalize("/usr/bin/python3")?;
    let text = path.to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "canonical system Python path is not UTF-8",
        )
    })?;
    Ok(text.to_owned())
}

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
    Terminal {
        state: RunTerminalStateV1,
        diagnostics: String,
    },
    Other(String),
}

impl Display for CanonicalError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Terminal { state, diagnostics } => {
                write!(
                    formatter,
                    "canonical run terminal: {state:?}; {diagnostics}"
                )
            }
            Self::Other(reason) => formatter.write_str(reason),
        }
    }
}

impl std::error::Error for CanonicalError {}

// This is the existing runner failure-observation shape, not a new receipt type.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SandboxFailureObservation {
    timed_out: bool,
    enforcement: EnforcementRecord,
}

fn decode_sandbox_artifact(bytes: &[u8]) -> Result<SandboxResult, String> {
    if let Ok(result) = serde_json::from_slice::<SandboxResult>(bytes) {
        return Ok(result);
    }
    let detail = match serde_json::from_slice::<SandboxFailureObservation>(bytes) {
        Ok(failure) => {
            let ambiguity = if failure.enforcement.reason_code
                == Some(SandboxFailureReason::LauncherTimedOut)
            {
                "; launcher_timed_out is not proof of deadline expiry: the current engine also maps supervisor/pipe-reader errors to this reason"
            } else {
                ""
            };
            format!(
                "timed_out={}; enforcement={:?}{ambiguity}",
                failure.timed_out, failure.enforcement
            )
        }
        Err(_) => "no typed sandbox enforcement observation retained".into(),
    };
    // Keep the verified artifact contents even when the failure has no
    // enforcement record (for example, a parent-authority tool_failure).
    let raw = match std::str::from_utf8(bytes) {
        Ok(text) => text.to_owned(),
        Err(_) => format!("non-UTF8 artifact bytes={bytes:?}"),
    };
    Err(format!("{detail}; artifact_json={raw}"))
}

fn execute(spec: &SandboxSpec) -> Result<SandboxResult, CanonicalError> {
    execute_case("canonical-containment", spec)
}

fn execute_case(case_name: &str, spec: &SandboxSpec) -> Result<SandboxResult, CanonicalError> {
    let root = tempfile::tempdir().map_err(|error| CanonicalError::Other(error.to_string()))?;
    let call = ToolCallSpecV1 {
        tool: "shell".into(),
        args: serde_json::to_value(spec)
            .map_err(|error| CanonicalError::Other(error.to_string()))?,
        frozen_clock: None,
    };
    let run = RunSpecV1 {
        name: case_name.into(),
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
    let mut diagnostics = format!("case={case_name}; run_id={}", summary.run_id);
    for receipt in snapshot.receipts().iter().rev() {
        for descriptor in receipt.artifact_refs.iter().rev() {
            let bytes = store
                .get(descriptor)
                .map_err(|error| CanonicalError::Other(error.to_string()))?;
            match decode_sandbox_artifact(&bytes) {
                Ok(result) => {
                    if summary.terminal_state != RunTerminalStateV1::Succeeded {
                        eprintln!(
                            "{case_name}: terminal={:?}; receipt={}; outcome={:?}; artifact={}; result={result:?}; artifact_json={}",
                            summary.terminal_state, receipt.receipt_id, receipt.outcome,
                            descriptor.digest, std::str::from_utf8(&bytes)
                                .map_err(|error| CanonicalError::Other(error.to_string()))?
                        );
                    }
                    return Ok(result);
                }
                Err(detail) if receipt.kind == ReceiptKindV1::StepFailed => {
                    diagnostics.push_str(&format!(
                        "; receipt={}; outcome={:?}; artifact={}; bytes={}; {detail}",
                        receipt.receipt_id,
                        receipt.outcome,
                        descriptor.digest,
                        descriptor.byte_length
                    ));
                }
                Err(_) => {}
            }
        }
    }
    Err(CanonicalError::Terminal {
        state: summary.terminal_state,
        diagnostics,
    })
}

fn assert_fail_closed(result: Result<SandboxResult, CanonicalError>) -> TestResult {
    match result {
        Ok(result) => assert_eq!(result.enforcement.outcome, EnforcementOutcome::Enforced),
        Err(CanonicalError::Terminal { state, .. }) => {
            assert_ne!(state, RunTerminalStateV1::Succeeded);
        }
        Err(other) => return Err(format!("unexpected canonical runner error: {other:?}").into()),
    }
    Ok(())
}

fn assert_rejected_before_or_during_run(result: Result<SandboxResult, CanonicalError>) {
    match result {
        Ok(result) => assert_ne!(result.exit_code, Some(0)),
        Err(CanonicalError::Terminal { state, .. }) => {
            assert_ne!(state, RunTerminalStateV1::Succeeded)
        }
        Err(CanonicalError::Other(_)) => {}
    }
}

// Data-only diagnostic fixtures: these do not dispatch a native command.
fn diagnostic_enforcement() -> EnforcementRecord {
    EnforcementRecord {
        mechanism: recursive_agent_sandbox::SandboxMechanism::Bubblewrap,
        outcome: EnforcementOutcome::Failed,
        policy_digest: "fixture-policy".into(),
        launcher_path: "/usr/bin/bwrap".into(),
        launcher_version: None,
        bash_trampoline_path: None,
        launcher_argv: Vec::new(),
        private_pid_namespace: false,
        parent_death_control: false,
        network_isolated: false,
        network_mechanism: None,
        seccomp_policy_digest: None,
        denied_network_syscalls: Vec::new(),
        effective_operation_roots: Vec::new(),
        effective_runtime_read_roots: Vec::new(),
        trusted_executables: Vec::new(),
        authorization: None,
        setup_proof_digest: None,
        setup_proof_verified: false,
        reason_code: Some(SandboxFailureReason::LauncherTimedOut),
    }
}

#[test]
fn diagnostic_retains_failed_setup_timeout_classification() -> TestResult {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "timed_out": true,
        "enforcement": diagnostic_enforcement(),
    }))?;
    let diagnostic = decode_sandbox_artifact(&bytes)
        .err()
        .ok_or("failure evidence missing")?;
    assert!(diagnostic.contains("timed_out=true"));
    assert!(diagnostic.contains("setup_proof_verified: false"));
    assert!(diagnostic.contains("LauncherTimedOut"));
    assert!(diagnostic.contains(std::str::from_utf8(&bytes)?));
    Ok(())
}

#[test]
fn diagnostic_retains_enforced_descendant_timeout_with_setup_proof() -> TestResult {
    let mut enforcement = diagnostic_enforcement();
    enforcement.outcome = EnforcementOutcome::Enforced;
    enforcement.setup_proof_verified = true;
    enforcement.setup_proof_digest = Some("fixture-proof".into());
    enforcement.reason_code = None;
    let bytes = serde_json::to_vec(&SandboxResult {
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        stdout_truncated: false,
        stderr_truncated: false,
        stdout_dropped_bytes: 0,
        stderr_dropped_bytes: 0,
        timed_out: true,
        authority_terminated: false,
        wall_time_ms: 100,
        enforcement,
    })?;
    let result = decode_sandbox_artifact(&bytes)?;
    assert!(result.timed_out);
    assert!(!result.authority_terminated);
    assert!(result.enforcement.setup_proof_verified);
    assert_eq!(result.enforcement.outcome, EnforcementOutcome::Enforced);
    Ok(())
}

#[test]
fn diagnostic_does_not_claim_pipe_reader_failure_is_deadline_expiry() -> TestResult {
    // The current engine collapses supervisor/reader errors to this SAME
    // persisted observation. Its original cause cannot be recovered here.
    let bytes = serde_json::to_vec(&serde_json::json!({
        "timed_out": true,
        "enforcement": diagnostic_enforcement(),
    }))?;
    let diagnostic = decode_sandbox_artifact(&bytes)
        .err()
        .ok_or("failure evidence missing")?;
    assert!(diagnostic.contains("not proof of deadline expiry"));
    assert!(diagnostic.contains("supervisor/pipe-reader errors"));
    assert!(diagnostic.contains(std::str::from_utf8(&bytes)?));
    Ok(())
}

#[test]
fn diagnostic_retains_parent_authority_failure_without_enforcement() -> TestResult {
    let bytes =
        br#"{"kind":"tool_failure","reason":"parent authority ended during effect execution"}"#;
    let diagnostic = decode_sandbox_artifact(bytes)
        .err()
        .ok_or("failure evidence missing")?;
    assert!(diagnostic.contains("no typed sandbox enforcement observation retained"));
    assert!(diagnostic.contains(std::str::from_utf8(bytes)?));
    Ok(())
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
        command: canonical_system_python()?,
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
        command: canonical_system_python()?,
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
fn undeclared_read_is_mandatorily_denied() -> TestResult {
    let root = tempfile::tempdir()?;
    let sentinel = root.path().join("undeclared-sentinel");
    std::fs::write(&sentinel, b"must-not-read")?;
    let mut read_spec = shell_spec(format!(
        "if cat {} 2>/dev/null; then exit 7; else printf denied; fi",
        sentinel.display()
    ));
    read_spec.timeout_ms = 2_000;
    let read = execute_case("undeclared-read-2000ms", &read_spec)?;
    assert_eq!(read.enforcement.outcome, EnforcementOutcome::Enforced);
    assert_eq!(read.exit_code, Some(0));
    assert_eq!(read.stdout, "denied");
    Ok(())
}

#[test]
fn descendant_is_mandatorily_bounded() -> TestResult {
    let mut descendant = shell_spec("sleep 30 & wait".into());
    descendant.timeout_ms = 100;
    let started = std::time::Instant::now();
    let result = execute_case("descendant-100ms", &descendant)?;
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
            Err(CanonicalError::Terminal { .. }) => {}
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
