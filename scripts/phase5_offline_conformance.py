#!/usr/bin/env python3
"""Disposable, offline Phase-5 conformance smoke harness.

This is a test harness, not a deployment or server-readiness check. It runs
only local owner tests, records their exit status, and writes a disposable
machine-readable receipt.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

RA = Path(__file__).resolve().parents[1]
CLAIM = Path(os.environ.get("CLAIMLEDGER_ROOT", "/home/sikmindz/Coding/ClaimLedger"))
MNEMES = Path(os.environ.get("MNEMES_ROOT", "/home/sikmindz/Coding/mnemes"))
FIXTURE = "fixtures/witnessed-workbench/run-pack-evidence-projection-v1.json"


def required(path: Path, label: str) -> None:
    if not path.is_dir():
        raise SystemExit(f"{label} source root is absent: {path}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(name: str, cmd: list[str], cwd: Path, env: dict[str, str], logs: Path) -> dict[str, Any]:
    """Run one owner gate and preserve its full local receipt log."""
    p = subprocess.run(cmd, cwd=cwd, env=env, text=True, capture_output=True)
    log = logs / f"{name}.log"
    log.write_text(
        f"$ {' '.join(cmd)}\n# cwd: {cwd}\n# exit: {p.returncode}\n\n"
        f"[stdout]\n{p.stdout}\n[stderr]\n{p.stderr}",
        encoding="utf-8",
    )
    return {
        "case": name,
        "command": cmd,
        "cwd": str(cwd),
        "returncode": p.returncode,
        "log_path": str(log),
        "log_sha256": sha256(log),
        "state": "passed" if p.returncode == 0 else "failed",
    }


def fixture_conformance(out: Path) -> dict[str, Any]:
    owners = {"recursive_agent": RA, "claim_ledger": CLAIM, "mnemes": MNEMES}
    paths = {name: root / FIXTURE for name, root in owners.items()}
    missing = [str(path) for path in paths.values() if not path.is_file()]
    digests = {name: sha256(path) for name, path in paths.items() if path.is_file()}
    expected = next(iter(digests.values()), None)
    return {
        "case": "frozen_cross_owner_fixture",
        "paths": {name: str(path) for name, path in paths.items()},
        "sha256": digests,
        "state": "passed" if not missing and len(set(digests.values())) == 1 else "failed",
        "diagnostics": [] if not missing else [f"missing fixture: {path}" for path in missing],
        "expected_shared_digest": expected,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, help="disposable receipt root")
    ns = ap.parse_args()
    required(CLAIM, "ClaimLedger")
    required(MNEMES, "Mnemes")
    out = ns.root or Path(tempfile.mkdtemp(prefix="ra-phase5-"))
    out.mkdir(parents=True, exist_ok=True)
    logs = out / "logs"
    logs.mkdir(exist_ok=True)

    # Test roots are explicit and disposable. Toolchain homes are intentionally
    # inherited: replacing HOME without preserving Rustup/Cargo makes an offline
    # harness fail before any owner code executes.
    env = os.environ.copy()
    env.update({"CARGO_NET_OFFLINE": "true", "PYTHONHASHSEED": "0", "RA_PHASE5_TEST_ONLY": "1"})
    matrix = [fixture_conformance(out)]
    matrix.append(run(
        "recursive_agent_pack_replay_after_client_deletion",
        ["cargo", "test", "-p", "recursive-agent-runner", "--test", "run_pack_replay"], RA, env, logs,
    ))
    matrix.append(run(
        "recursive_agent_vault_verify_and_tamper_quarantine",
        ["cargo", "test", "-p", "recursive-agent-ledger", "--test", "run_pack_verify"], RA, env, logs,
    ))
    matrix.append(run(
        "claimledger_admitted_import_idempotence_and_tamper_rejection",
        ["uv", "run", "--python", "3.11", "--extra", "dev", "python", "-m", "pytest", "-q", "tests/test_run_pack_import.py"], CLAIM, env, logs,
    ))
    matrix.append(run(
        "mnemes_authenticated_observation_idempotence_and_rejection",
        ["cargo", "test", "--test", "run_pack_observation", "--test", "run_pack_server"], MNEMES, env, logs,
    ))
    passed = all(item["state"] == "passed" for item in matrix)
    receipt = {
        "schema": "witnessed-workbench.phase5.offline-conformance/v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "test_only": True,
        "network": "forbidden for Rust owner gates (CARGO_NET_OFFLINE=true)",
        "source_roots": {"recursive_agent": str(RA), "claim_ledger": str(CLAIM), "mnemes": str(MNEMES)},
        "matrix": matrix,
        "passed": passed,
        "scope_note": "This is an owner-conformance harness. It proves shared frozen fixtures and independent owner gates; it does not claim a deployed service, shared production storage, live Hermes session, or a single cross-process import transaction.",
    }
    receipt_path = out / "phase5-conformance.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"receipt": str(receipt_path), "receipt_sha256": sha256(receipt_path), "passed": passed}))
    return 0 if passed else 1

if __name__ == "__main__":
    raise SystemExit(main())
