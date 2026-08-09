#!/usr/bin/env python3
"""Capture immutable pre-fix RED outputs for hardening pass 5."""

from __future__ import annotations

import hashlib
import pathlib
import subprocess


ROOT = pathlib.Path(__file__).resolve().parents[4]
CASES = {
    "R1": "cargo test -p recursive-agent-policy --test hardening_v5_attenuation -- --nocapture",
    "R2": "cargo test -p recursive-agent-cli --test hardening_v5_ingress -- --nocapture",
    "R3": "cargo test -p recursive-agent-runner --test hardening_v5_executable_bytes -- --nocapture",
    "R4": "cargo test -p recursive-agent-contracts --test hardening_v5_quarantine -- --nocapture",
}


def main() -> int:
    for name, command in CASES.items():
        completed = subprocess.run(
            ["bash", "-c", command],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        body = (
            f"command: {command}\n"
            f"exit_code: {completed.returncode}\n"
            f"output_sha256: {hashlib.sha256(completed.stdout).hexdigest()}\n"
            "output:\n"
        ).encode() + completed.stdout
        destination = pathlib.Path(__file__).resolve().parent / name / "red.txt"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body)
        print(f"{name}: exit={completed.returncode} sha256={hashlib.sha256(body).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
