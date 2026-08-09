mod support;

use chrono::{DateTime, TimeDelta, Utc};
use recursive_agent_contracts::{RunSpecV1, RunTerminalStateV1, StepSpecV1, ToolCallSpecV1};
use recursive_agent_ledger::{verify_expected_run, RunPaths};
use recursive_agent_runner::{Clock, RunError};
use std::sync::atomic::{AtomicUsize, Ordering};
use support::{run_spec, run_spec_with_clock};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn shell_run(
    name: &str,
    command: &str,
    args: Vec<String>,
    timeout_ms: u64,
    max_output_bytes: u64,
) -> RunSpecV1 {
    RunSpecV1 {
        name: name.into(),
        steps: vec![StepSpecV1 {
            name: "shell".into(),
            call: ToolCallSpecV1 {
                tool: "shell".into(),
                args: serde_json::json!({
                    "command": command,
                    "args": args,
                    "allowed_read_paths": [],
                    "allowed_write_paths": [],
                    "allow_network": false,
                    "timeout_ms": timeout_ms,
                    "max_output_bytes": max_output_bytes,
                }),
                frozen_clock: None,
            },
        }],
        frozen_clock: None,
        policy_version: "m0-2".into(),
    }
}

fn assert_non_success(spec: &RunSpecV1, expected: RunTerminalStateV1) -> TestResult {
    let root = tempfile::tempdir()?;
    let summary = run_spec(spec, root.path())?;
    assert_eq!(summary.terminal_state, expected, "run {}", spec.name);
    let verified = verify_expected_run(&RunPaths::new(&summary.run_dir), &summary.run_id)?;
    assert_eq!(verified.terminal_state, expected);
    assert_ne!(verified.terminal_state, RunTerminalStateV1::Succeeded);
    Ok(())
}

#[test]
fn false_signal_stdout_stderr_and_timeout_never_complete_successfully() -> TestResult {
    assert_non_success(
        &shell_run("false", "/usr/bin/false", vec![], 2_000, 1_024),
        RunTerminalStateV1::Failed,
    )?;
    assert_non_success(
        &shell_run(
            "signal",
            "/usr/bin/bash",
            vec!["-c".into(), "kill -TERM $$".into()],
            2_000,
            1_024,
        ),
        RunTerminalStateV1::Failed,
    )?;
    assert_non_success(
        &shell_run(
            "stdout-overrun",
            "/usr/bin/bash",
            vec!["-c".into(), "for i in {1..2048}; do printf x; done".into()],
            2_000,
            32,
        ),
        RunTerminalStateV1::Failed,
    )?;
    assert_non_success(
        &shell_run(
            "stderr-overrun",
            "/usr/bin/bash",
            vec![
                "-c".into(),
                "for i in {1..2048}; do printf x >&2; done".into(),
            ],
            2_000,
            32,
        ),
        RunTerminalStateV1::Failed,
    )?;
    assert_non_success(
        &shell_run(
            "timeout",
            "/usr/bin/bash",
            vec!["-c".into(), "sleep 2".into()],
            50,
            1_024,
        ),
        RunTerminalStateV1::TimedOut,
    )?;
    Ok(())
}

#[test]
fn network_true_and_wrong_policy_version_fail_before_process_dispatch() -> TestResult {
    let root = tempfile::tempdir()?;
    let marker = root.path().join("must-not-run");
    let mut network = shell_run(
        "network-denied",
        "/usr/bin/touch",
        vec![marker.display().to_string()],
        2_000,
        1_024,
    );
    network.steps[0].call.args["allow_network"] = serde_json::Value::Bool(true);
    let network_error = match run_spec(&network, root.path()) {
        Ok(_) => return Err("network-enabled run unexpectedly succeeded".into()),
        Err(error) => error,
    };
    assert!(
        matches!(
            network_error.downcast_ref::<RunError>(),
            Some(RunError::Policy(
                recursive_agent_policy::PolicyError::NetworkUnavailable
            ))
        ),
        "unexpected network rejection: {network_error}"
    );
    assert!(!marker.exists());

    let mut wrong_version = shell_run(
        "wrong-policy",
        "/usr/bin/touch",
        vec![marker.display().to_string()],
        2_000,
        1_024,
    );
    wrong_version.policy_version = "m0-stale".into();
    let wrong_version_error = match run_spec(&wrong_version, root.path()) {
        Ok(_) => return Err("stale policy version unexpectedly succeeded".into()),
        Err(error) => error,
    };
    assert!(
        matches!(
            wrong_version_error.downcast_ref::<RunError>(),
            Some(RunError::Policy(
                recursive_agent_policy::PolicyError::PolicyVersionMismatch { .. }
            ))
        ),
        "unexpected policy-version rejection: {wrong_version_error}"
    );
    assert!(!marker.exists());
    Ok(())
}

struct SequencedClock {
    base: DateTime<Utc>,
    switch_at: usize,
    switched_offset: TimeDelta,
    wall_calls: AtomicUsize,
    monotonic_calls: AtomicUsize,
    monotonic_rollback_at: Option<usize>,
}

impl SequencedClock {
    fn wall(switch_at: usize, switched_offset: TimeDelta) -> Self {
        Self {
            base: DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(1_700_000_000),
            switch_at,
            switched_offset,
            wall_calls: AtomicUsize::new(0),
            monotonic_calls: AtomicUsize::new(0),
            monotonic_rollback_at: None,
        }
    }

    fn monotonic_rollback(at: usize) -> Self {
        Self {
            monotonic_rollback_at: Some(at),
            ..Self::wall(usize::MAX, TimeDelta::seconds(0))
        }
    }
}

impl Clock for SequencedClock {
    fn now(&self) -> DateTime<Utc> {
        let call = self.wall_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call >= self.switch_at {
            self.base + self.switched_offset
        } else {
            self.base
        }
    }

    fn monotonic_now(&self) -> std::time::Duration {
        let call = self.monotonic_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.monotonic_rollback_at == Some(call) {
            std::time::Duration::ZERO
        } else {
            std::time::Duration::from_millis(1_000 + call as u64)
        }
    }
}

fn two_echo_steps() -> RunSpecV1 {
    let call = || ToolCallSpecV1 {
        tool: "echo".into(),
        args: serde_json::json!({"text": "ok"}),
        frozen_clock: None,
    };
    RunSpecV1 {
        name: "clock-boundary".into(),
        steps: vec![
            StepSpecV1 {
                name: "one".into(),
                call: call(),
            },
            StepSpecV1 {
                name: "two".into(),
                call: call(),
            },
        ],
        frozen_clock: None,
        policy_version: "m0-2".into(),
    }
}

#[test]
fn advancing_and_rollback_clocks_prevent_affected_dispatch() -> TestResult {
    for (clock, expected) in [
        (
            SequencedClock::wall(9, TimeDelta::seconds(301)),
            RunTerminalStateV1::Denied,
        ),
        (
            SequencedClock::wall(6, TimeDelta::seconds(301)),
            RunTerminalStateV1::Denied,
        ),
        (
            SequencedClock::monotonic_rollback(4),
            RunTerminalStateV1::Denied,
        ),
    ] {
        let root = tempfile::tempdir()?;
        let summary = run_spec_with_clock(&two_echo_steps(), root.path(), clock)?;
        assert_eq!(summary.terminal_state, expected);
        let verification = verify_expected_run(&RunPaths::new(&summary.run_dir), &summary.run_id)?;
        assert_eq!(verification.terminal_state, expected);
    }
    Ok(())
}

#[test]
fn verified_replay_snapshot_is_immutable_bounded_and_directory_bound() -> TestResult {
    let root = tempfile::tempdir()?;
    let spec = RunSpecV1 {
        name: "snapshot".into(),
        steps: vec![StepSpecV1 {
            name: "echo".into(),
            call: ToolCallSpecV1 {
                tool: "echo".into(),
                args: serde_json::json!({"text": "snapshot"}),
                frozen_clock: None,
            },
        }],
        frozen_clock: None,
        policy_version: "m0-2".into(),
    };
    let summary = run_spec(&spec, root.path())?;
    let paths = RunPaths::new(&summary.run_dir);
    let snapshot = recursive_agent_ledger::verified_snapshot_directory_bound(&paths)?;
    let receipt_ids = snapshot
        .receipts()
        .iter()
        .map(|receipt| receipt.receipt_id.to_string())
        .collect::<Vec<_>>();
    let original_bytes = std::fs::read(paths.receipts_path())?;

    let receipt_path = paths.receipts_path();
    let racing_path = receipt_path.clone();
    let racer = std::thread::spawn(move || -> std::io::Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.append(true);
        use std::io::Write;
        options.open(racing_path)?.write_all(b"{\"partial\":")?;
        Ok(())
    });
    let raced = recursive_agent_ledger::verified_snapshot_directory_bound(&paths);
    racer.join().map_err(|_| "append racer panicked")??;
    if let Ok(observed) = raced {
        assert!(observed
            .receipts()
            .iter()
            .all(|receipt| receipt.run_id == summary.run_id));
        assert_eq!(
            observed.receipts().len() as u64,
            observed.verification().length
        );
    }
    assert_eq!(
        snapshot
            .receipts()
            .iter()
            .map(|receipt| receipt.receipt_id.to_string())
            .collect::<Vec<_>>(),
        receipt_ids
    );

    std::fs::write(&receipt_path, &original_bytes)?;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&receipt_path)?;
    file.set_len(64 * 1024 * 1024 + 1)?;
    let started = std::time::Instant::now();
    assert!(recursive_agent_ledger::verified_snapshot_directory_bound(&paths).is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(5));

    std::fs::write(&receipt_path, &original_bytes)?;
    let truncate_path = receipt_path.clone();
    let truncater = std::thread::spawn(move || -> std::io::Result<()> {
        std::fs::OpenOptions::new()
            .write(true)
            .open(truncate_path)?
            .set_len(0)
    });
    let truncated = recursive_agent_ledger::verified_snapshot_directory_bound(&paths);
    truncater.join().map_err(|_| "truncate racer panicked")??;
    if let Ok(observed) = truncated {
        assert_eq!(
            observed.verification().verified_run_id.as_ref(),
            Some(&summary.run_id)
        );
    }

    std::fs::write(&receipt_path, &original_bytes)?;
    let parked = summary.run_dir.join("receipts.parked");
    let replace_source = receipt_path.clone();
    let replace_target = parked.clone();
    let replacer = std::thread::spawn(move || -> std::io::Result<()> {
        std::fs::rename(&replace_source, &replace_target)?;
        std::fs::write(&replace_source, b"{}\n")
    });
    let replaced = recursive_agent_ledger::verified_snapshot_directory_bound(&paths);
    replacer
        .join()
        .map_err(|_| "replacement racer panicked")??;
    if let Ok(observed) = replaced {
        assert_eq!(
            observed.verification().verified_run_id.as_ref(),
            Some(&summary.run_id)
        );
    }
    assert_eq!(
        snapshot
            .receipts()
            .iter()
            .map(|receipt| receipt.receipt_id.to_string())
            .collect::<Vec<_>>(),
        receipt_ids
    );
    Ok(())
}
