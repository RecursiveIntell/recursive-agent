use std::process::Command;

use recursive_agent_contracts::RunTerminalStateV1;
use recursive_agent_ledger::{verify_directory_bound, RunPaths};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Case<'a> {
    name: &'a str,
    command: &'a str,
    args: Vec<&'a str>,
    timeout_ms: u64,
    max_output_bytes: u64,
    terminal: RunTerminalStateV1,
}

#[test]
fn real_cli_non_success_matrix_exits_nonzero_and_retains_strict_runs() -> TestResult {
    for case in [
        Case {
            name: "false",
            command: "/usr/bin/false",
            args: vec![],
            timeout_ms: 2_000,
            max_output_bytes: 1_024,
            terminal: RunTerminalStateV1::Failed,
        },
        Case {
            name: "signal",
            command: "/usr/bin/bash",
            args: vec!["-c", "kill -TERM $$"],
            timeout_ms: 2_000,
            max_output_bytes: 1_024,
            terminal: RunTerminalStateV1::Failed,
        },
        // The sandbox timeout covers setup as well as child execution. A 20 ms
        // budget can expire while probing the launcher, yielding the correct
        // fail-closed `SandboxFailed` outcome before `sleep` starts. Give setup
        // a realistic envelope, then make the child exceed it deterministically.
        Case {
            name: "timeout",
            command: "/usr/bin/bash",
            args: vec!["-c", "sleep 2"],
            timeout_ms: 1_000,
            max_output_bytes: 1_024,
            terminal: RunTerminalStateV1::TimedOut,
        },
        Case {
            name: "stdout-overrun",
            command: "/usr/bin/bash",
            args: vec!["-c", "yes x | head -c 2048"],
            timeout_ms: 2_000,
            max_output_bytes: 16,
            terminal: RunTerminalStateV1::Failed,
        },
        Case {
            name: "stderr-overrun",
            command: "/usr/bin/bash",
            args: vec!["-c", "yes x | head -c 2048 >&2"],
            timeout_ms: 2_000,
            max_output_bytes: 16,
            terminal: RunTerminalStateV1::Failed,
        },
    ] {
        let root = tempfile::tempdir()?;
        let spec_path = root.path().join("spec.json");
        let runs = root.path().join("runs");
        std::fs::write(
            &spec_path,
            serde_json::to_vec(&serde_json::json!({
                "name": format!("cli-{}", case.name),
                "policy_version": "m0-2",
                "steps": [{
                    "name": "shell",
                    "call": {
                        "tool": "shell",
                        "args": {
                            "command": case.command,
                            "args": case.args,
                            "allowed_read_paths": [],
                            "allowed_write_paths": [],
                            "allow_network": false,
                            "timeout_ms": case.timeout_ms,
                            "max_output_bytes": case.max_output_bytes
                        }
                    }
                }]
            }))?,
        )?;
        let output = Command::new(env!("CARGO_BIN_EXE_ra"))
            .args(["run", "--spec"])
            .arg(&spec_path)
            .arg("--out")
            .arg(&runs)
            .output()?;
        assert!(
            !output.status.success(),
            "{} exited successfully",
            case.name
        );
        assert_eq!(output.status.code(), Some(1), "{} exit code", case.name);
        let summary: recursive_agent_runner::RunSummary = serde_json::from_slice(&output.stdout)?;
        assert_eq!(
            summary.terminal_state, case.terminal,
            "{} terminal",
            case.name
        );
        let verified = verify_directory_bound(&RunPaths::new(&summary.run_dir))?;
        assert_eq!(
            verified.terminal_state, case.terminal,
            "{} verified terminal",
            case.name
        );
        assert!(verified.ok);
    }
    Ok(())
}

#[test]
fn phase_one_cli_exposes_no_unadmitted_serve_commands() -> TestResult {
    for command in ["serve", "mcp-serve"] {
        let output = Command::new(env!("CARGO_BIN_EXE_ra"))
            .args([command, "--help"])
            .output()?;
        assert!(
            !output.status.success(),
            "{command} was unexpectedly active"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand"),
            "{command} did not fail as an unknown command"
        );
    }
    Ok(())
}
