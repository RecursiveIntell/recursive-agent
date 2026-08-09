#![allow(deprecated)]

use recursive_agent_contracts::{
    derive_run_id, derive_step_id, ReceiptOutcomeV1, RunSpecV1, StepSpecV1, ToolCallSpecV1,
};
use recursive_agent_runner::run_spec;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn failed_step_dominates_run_terminal_state() -> TestResult {
    let root = tempfile::tempdir()?;
    let spec = RunSpecV1 {
        name: "failure-dominance".into(),
        steps: vec![
            StepSpecV1 {
                name: "valid-nonzero-shell".into(),
                call: ToolCallSpecV1 {
                    tool: "shell".into(),
                    args: serde_json::json!({
                        "command": "/usr/bin/false",
                        "args": [],
                        "allowed_read_paths": [],
                        "allowed_write_paths": [],
                        "allow_network": false,
                        "timeout_ms": 1_000,
                        "max_output_bytes": 1_024
                    }),
                    frozen_clock: None,
                },
            },
            StepSpecV1 {
                name: "must-not-run".into(),
                call: ToolCallSpecV1 {
                    tool: "echo".into(),
                    args: serde_json::json!({"text": "later"}),
                    frozen_clock: None,
                },
            },
        ],
        frozen_clock: None,
        policy_version: "m0-2".into(),
    };
    let run_id = derive_run_id(&spec)?;
    let later = spec.steps.get(1).ok_or("later step missing")?;
    let later_step_id = derive_step_id(&run_id, 1, &later.name, &later.call)?;
    let summary = run_spec(&spec, root.path())?;
    let text = std::fs::read_to_string(summary.run_dir.join("receipts.ndjson"))?;
    let receipts: Vec<recursive_agent_contracts::ReceiptV1> = text
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert!(
        receipts
            .iter()
            .all(|receipt| receipt.step_id != later_step_id),
        "later step must not execute"
    );
    assert_eq!(
        summary.terminal_state,
        recursive_agent_contracts::RunTerminalStateV1::Failed
    );
    let final_receipt = receipts.last().ok_or("final receipt missing")?;
    assert!(matches!(
        final_receipt.outcome,
        ReceiptOutcomeV1::Failed { .. }
    ));
    Ok(())
}

#[test]
fn terminal_matrix_rejects_success_for_every_non_success_terminal() -> TestResult {
    use recursive_agent_contracts::RunTerminalStateV1;
    use recursive_agent_runner::RunLifecycle;

    let terminals = [
        RunTerminalStateV1::Succeeded,
        RunTerminalStateV1::Failed,
        RunTerminalStateV1::Denied,
        RunTerminalStateV1::TimedOut,
        RunTerminalStateV1::Cancelled,
        RunTerminalStateV1::SandboxFailed,
        RunTerminalStateV1::Corrupted,
        RunTerminalStateV1::LegacyUnknown,
    ];
    for terminal in terminals {
        let mut lifecycle = RunLifecycle::new();
        lifecycle.transition_terminal(terminal)?;
        assert_eq!(lifecycle.terminal()?, terminal);
        for attempted in terminals {
            assert!(lifecycle.transition_terminal(attempted).is_err());
        }
        assert_eq!(
            terminal.permits_successful_finalization(),
            terminal == RunTerminalStateV1::Succeeded
        );
    }
    Ok(())
}
