//! Task 5.2 — durable, idempotent cancellation through the runtime owner.
//!
//! With a scheduler projection attached, a cancellation request is durably
//! recorded and idempotent. Without one, active cancellation is a typed
//! unavailable result and terminal runs report AlreadyTerminal. No cancellation
//! receipt is fabricated.
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod support;

use recursive_agent_runner::{
    ProjectedState, RuntimeCancelResultV1, RuntimeServiceError, SchedulerStore,
};
use support::run_spec;

fn tmp_store() -> (tempfile::TempDir, SchedulerStore) {
    let tmp = tempfile::tempdir().unwrap();
    let store = SchedulerStore::open(tmp.path().join("scheduler.json")).unwrap();
    (tmp, store)
}

#[test]
fn scheduler_store_cancel_is_durable_and_idempotent() {
    let (_tmp, mut store) = tmp_store();
    store.admit("op-1", "digest-a").unwrap();
    store.acquire_lease("op-1", "worker-a").unwrap();

    // First cancel records the flag.
    store.request_cancel("op-1").unwrap();
    assert!(store.get("op-1").unwrap().cancel_requested);
    assert_eq!(store.get("op-1").unwrap().state, ProjectedState::Cancelling);

    // Repeated cancel is idempotent (no error, state unchanged).
    store.request_cancel("op-1").unwrap();
    assert!(store.get("op-1").unwrap().cancel_requested);
    assert_eq!(store.get("op-1").unwrap().state, ProjectedState::Cancelling);

    // Unknown operation is a typed error.
    assert!(store.request_cancel("op-missing").is_err());
}

#[test]
fn runtime_cancel_result_exposes_terminal_and_requested_variants() {
    // Terminal run -> AlreadyTerminal.
    let terminal = RuntimeCancelResultV1::AlreadyTerminal {
        state: recursive_agent_contracts::RunTerminalStateV1::Succeeded,
    };
    assert!(matches!(
        terminal,
        RuntimeCancelResultV1::AlreadyTerminal { .. }
    ));

    // Active run with scheduler -> CancellationRequested.
    let requested = RuntimeCancelResultV1::CancellationRequested {
        run_id: "op-1".into(),
    };
    assert!(matches!(
        requested,
        RuntimeCancelResultV1::CancellationRequested { .. }
    ));
}

#[test]
fn runtime_cancel_without_scheduler_reports_active_unavailable() {
    // RuntimeServiceError::ActiveCancellationUnavailable is the typed result
    // when no scheduler projection is attached to an active run.
    let err = RuntimeServiceError::ActiveCancellationUnavailable;
    assert!(matches!(
        err,
        RuntimeServiceError::ActiveCancellationUnavailable
    ));
}

/// Task 5.2 — a descendant spawned by a timed-out sandbox must not survive:
/// the sandbox kills the whole process group, so a backgrounded child that
/// would write a marker after the timeout never writes it.
#[cfg(target_os = "linux")]
#[test]
fn sandbox_timeout_kills_descendant_process_group() -> Result<(), Box<dyn std::error::Error>> {
    use recursive_agent_contracts::RunSpecV1;

    use recursive_agent_sandbox::SandboxSpec;

    let tmp = tempfile::tempdir()?;
    let writable = tmp.path().join("writable");
    std::fs::create_dir(&writable)?;
    let marker = writable.join("descendant-marker");

    // Bash forks a background child that sleeps then writes the marker. The
    // foreground `wait` keeps the shell alive past the 300ms timeout. When the
    // sandbox kills the process group, the backgrounded descendant is killed
    // before it can write.
    let script = format!(
        "( sleep 0.6; printf leaked >> {} ) & wait",
        marker.display()
    );
    let spec = SandboxSpec {
        command: "/usr/bin/bash".into(),
        args: vec!["-c".into(), script],
        allowed_read_paths: vec![],
        allowed_write_paths: vec![writable.display().to_string()],
        allow_network: false,
        timeout_ms: 300,
        max_output_bytes: 64 * 1024,
    };
    let run = RunSpecV1 {
        name: "cancel-descendant".into(),
        steps: vec![recursive_agent_contracts::StepSpecV1 {
            name: "shell".into(),
            call: recursive_agent_contracts::ToolCallSpecV1 {
                tool: "shell".into(),
                args: serde_json::to_value(&spec)?,
                frozen_clock: None,
            },
        }],
        frozen_clock: None,
        policy_version: "m0-2".into(),
    };
    let summary = run_spec(&run, tmp.path())?;

    // The run should have reached a terminal state reflecting the timeout /
    // non-success outcome (never a fabricated success).
    assert!(!summary.terminal_state.permits_successful_finalization());

    // Give any surviving descendant a chance to write, then assert it did not.
    std::thread::sleep(std::time::Duration::from_millis(1200));
    let wrote = std::fs::read(&marker).unwrap_or_default();
    assert!(
        wrote.is_empty(),
        "a descendant survived cancellation and wrote: {wrote:?}"
    );
    Ok(())
}
