#!/usr/bin/env python3
"""Run and hash the Phase 1 hardening-v4 admission-candidate gates."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[5]
OUT = pathlib.Path(
    os.environ.get("RA_PHASE1_CONTROLLER_OUT", pathlib.Path(__file__).resolve().parent)
)
OUT.mkdir(parents=True, exist_ok=True)

MATRIX = [
    ("fmt_pre", "cargo fmt --all -- --check"),
    ("contracts", "cargo test -p recursive-agent-contracts --all-targets"),
    ("policy", "cargo test -p recursive-agent-policy --all-targets"),
    ("ledger", "cargo test -p recursive-agent-ledger --all-targets"),
    ("sandbox", "cargo test -p recursive-agent-sandbox --all-targets"),
    ("provider", "cargo test -p recursive-agent-provider --all-targets"),
    ("runner", "cargo test -p recursive-agent-runner --all-targets"),
    ("tools", "cargo test -p recursive-agent-tools --all-targets"),
    ("cli", "cargo test -p recursive-agent-cli --all-targets"),
    ("daemon", "cargo test -p recursive-agent-daemon --all-targets"),
    ("workspace", "cargo test --workspace --all-targets"),
    ("clippy", "cargo clippy --workspace --all-targets -- -D warnings"),
    ("fmt_post", "cargo fmt --all -- --check"),
    ("diff_check", "git diff --check"),
]

FOCUSED = [
    (
        "focus_public_effect_surface",
        "cargo test -p recursive-agent-contracts --test phase1_effect_surface -- --nocapture",
    ),
    (
        "focus_workspace_lints",
        "cargo test -p recursive-agent-contracts --test workspace_lints -- --nocapture",
    ),
    (
        "focus_runner_containment_one_shot",
        "cargo test -p recursive-agent-runner --test canonical_containment -- --nocapture",
    ),
    (
        "focus_pinned_root_races",
        "cargo test -p recursive-agent-runner --lib pinned_root_tests -- --nocapture",
    ),
    (
        "focus_permit_continuity",
        "cargo test -p recursive-agent-ledger --test lifecycle_validation -- --nocapture",
    ),
    (
        "focus_cli_terminal_exit",
        "cargo test -p recursive-agent-cli --test terminal_exit -- --nocapture",
    ),
    (
        "focus_daemon_envelope",
        "cargo test -p recursive-agent-daemon --all-targets -- --nocapture",
    ),
    (
        "focus_deterministic_ids",
        "cargo test -p recursive-agent-runner --test deterministic_identity -- --nocapture",
    ),
    (
        "focus_crash_recovery",
        "cargo test -p recursive-agent-ledger --test crash_recovery -- --nocapture",
    ),
    (
        "focus_replay_artifact_races",
        "cargo test -p recursive-agent-ledger --test artifact_tamper -- --nocapture",
    ),
    (
        "focus_memory_corruption",
        "cargo test -p recursive-agent-memory --all-targets -- --nocapture",
    ),
    (
        "focus_provider_secret",
        "cargo test -p recursive-agent-provider --test secret_contract -- --nocapture",
    ),
    (
        "focus_skill_traversal",
        "cargo test -p recursive-agent-skills --all-targets -- --nocapture",
    ),
    (
        "focus_doctor_truth",
        "cargo test -p recursive-agent-cli --bin ra tests::doctor_reports_exact_phase_one_candidate_surface -- --exact --nocapture",
    ),
    (
        "focus_sandbox_compile_fail",
        "cargo test -p recursive-agent-sandbox --doc",
    ),
]

SCANS = [
    (
        "scan_process_owner",
        r"""set -euo pipefail
hits=$(rg -l 'Command::new|[.]spawn[(]|CommandExt::exec|[.]exec[(]' crates/*/src --glob '*.rs' | sort)
expected=$'crates/recursive-agent-memory/src/lib.rs\ncrates/recursive-agent-runner/src/sandbox_engine.rs'
test "$hits" = "$expected"
rg -n '^#\[cfg\(test\)\]$|^mod tests|Command::new' crates/recursive-agent-memory/src/lib.rs
rg -n 'Command::new|[.]spawn[(]|pub\(super\) fn execute' crates/recursive-agent-runner/src/sandbox_engine.rs""",
    ),
    (
        "scan_dispatch_token",
        r"""set -euo pipefail
rg -n 'pub\(super\) struct DispatchToken|context: DispatchToken' crates/recursive-agent-runner/src/sandbox_engine.rs
if rg -n 'impl Clone for DispatchToken|Serialize for DispatchToken|Deserialize for DispatchToken|derive\([^)]*(Clone|Serialize|Deserialize)[^)]*\)[[:space:]]*pub\(super\) struct DispatchToken' crates/recursive-agent-runner/src/sandbox_engine.rs; then exit 1; fi""",
    ),
    (
        "scan_child_store_reopen",
        r"""set -euo pipefail
if rg -n 'ArtifactStore::new|DurablePermitStore::open' crates --glob '*.rs'; then exit 1; fi
if rg -n 'recursive_agent_ledger::open\(|DurablePermitStore::from_dir_fd' crates/recursive-agent-runner/src --glob '*.rs'; then exit 1; fi
rg -n 'open_from_dir_fd|from_run_root_fd|verified_snapshot_expected_run_from_dir_fd' crates/recursive-agent-runner/src/lib.rs""",
    ),
    (
        "scan_unbound_unbounded",
        r"""set -euo pipefail
if rg -n 'pub fn verify\(' crates/recursive-agent-ledger/src; then exit 1; fi
if rg -n 'read_to_string.*receipts|receipts.*read_to_string|std::fs::read\([^)]*receipts' crates/recursive-agent-runner/src crates/recursive-agent-cli/src; then exit 1; fi
rg -n 'take\(maximum \+ 1\)|MAX_RECEIPT_LOG_BYTES|MAX_ARTIFACT_SIZE' crates/recursive-agent-ledger/src/lib.rs""",
    ),
    (
        "scan_unsafe_lint_ignore",
        r"""set -euo pipefail
if rg -n 'unsafe[[:space:]]*\{|#!\[(allow|warn|expect)|#\[(ignore|should_panic)' crates --glob '*.rs' --glob '!**/tests/**'; then exit 1; fi
if rg -n '#!\[(allow|warn|expect)|#\[(ignore|should_panic)' crates --glob '*.rs'; then exit 1; fi""",
    ),
    (
        "scan_quarantine_cli",
        r"""set -euo pipefail
if rg -n '(^|[[:space:]])(Serve|McpServe)([[:space:]]|\{|,)|mcp-serve|runner-private one-shot dispatch.*daemon available' crates/recursive-agent-cli/src/main.rs crates/recursive-agent-cli/Cargo.toml; then exit 1; fi
rg -n 'runner-private one-shot dispatch|MCP client: unavailable|provider execution: unavailable|runtime memory: unavailable|skills: unavailable|delegation/MCTS: unavailable' crates/recursive-agent-cli/src/main.rs""",
    ),
    (
        "scan_quarantine_daemon",
        r"""set -euo pipefail
if rg -n 'pub fn start|UnixListener|UnixStream|std::thread::spawn|remove_file|create_dir_all|recursive_agent_runner|(^|[^[:alnum:]_])run_spec[(]|Command::new|[.]spawn[(]|append_receipt|DurablePermitStore' crates/recursive-agent-daemon/src/lib.rs crates/recursive-agent-daemon/Cargo.toml; then exit 1; fi
rg -n 'Pure future-daemon protocol decoding|pub fn decode_run_spec|parse_run_spec_bytes' crates/recursive-agent-daemon/src/lib.rs""",
    ),
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_digest() -> str:
    files = [ROOT / "Cargo.toml", ROOT / "Cargo.lock"]
    files.extend(path for path in (ROOT / "crates").rglob("*") if path.is_file())
    records = []
    for path in sorted(files):
        relative = path.relative_to(ROOT).as_posix()
        records.append(f"{sha256(path.read_bytes())}  {relative}\n")
    return sha256("".join(records).encode())


def command_text(command: str) -> bytes:
    completed = subprocess.run(
        ["bash", "-c", command],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return completed.returncode, completed.stdout


def git_text(*arguments: str) -> str:
    return subprocess.check_output(["git", *arguments], cwd=ROOT, text=True).strip()


def run_gate(group: str, name: str, command: str) -> dict[str, object]:
    exit_code, output = command_text(command)
    output_path = OUT / f"{name}.txt"
    output_path.write_bytes(output)
    successes = re.findall(rb"test result: ok\. (\d+) passed; (\d+) failed", output)
    passed = sum(int(match[0]) for match in successes)
    failed = sum(int(match[1]) for match in successes)
    result: dict[str, object] = {
        "group": group,
        "name": name,
        "command": command,
        "exit_code": exit_code,
        "output_bytes": len(output),
        "output_sha256": sha256(output),
        "passed": passed,
        "failed": failed,
    }
    print(f"{name}: exit={exit_code} passed={passed} failed={failed}", flush=True)
    return result


def main() -> int:
    generation = source_digest()
    diff = subprocess.check_output(
        ["git", "diff", "--binary", "--", "Cargo.toml", "Cargo.lock", "crates"],
        cwd=ROOT,
    )
    results = []
    for name, command in MATRIX:
        results.append(run_gate("required_matrix", name, command))
    for name, command in FOCUSED:
        results.append(run_gate("focused_gate", name, command))
    for name, command in SCANS:
        results.append(run_gate("source_scan", name, command))
    manifest = {
        "schema": "recursive-agent/phase-1-hardening-v4-controller-candidate/v1",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "repository": str(ROOT),
        "branch": git_text("branch", "--show-current"),
        "head": git_text("rev-parse", "HEAD"),
        "disposition": "controller hostile admission required",
        "phase_status": "rejected_pending_controller_hostile_admission",
        "source_generation_digest": {
            "algorithm": "sha256",
            "value": generation,
            "construction": "sha256 of sorted per-file sha256 records for Cargo.toml, Cargo.lock, and every regular file below crates/",
        },
        "tracked_binary_diff_digest": {
            "algorithm": "sha256",
            "value": sha256(diff),
            "scope": "git diff --binary -- Cargo.toml Cargo.lock crates",
        },
        "results": results,
        "all_gates_passed": all(result["exit_code"] == 0 for result in results),
        "notes": [
            "The crash-recovery process race intentionally prints one inner losing harness failure; the enclosing test and command must exit zero.",
            "These receipts are admission-candidate evidence only; they neither admit Phase 1 nor advance Phase 2.",
        ],
    }
    encoded = json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"
    (OUT / "manifest.json").write_bytes(encoded)
    print(f"manifest_sha256={sha256(encoded)}", flush=True)
    return 0 if manifest["all_gates_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
