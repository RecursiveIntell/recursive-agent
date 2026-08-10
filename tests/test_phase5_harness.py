import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[1]
HARNESS = ROOT / "scripts" / "phase5_offline_conformance.py"


def test_phase5_harness_requires_and_runs_real_projection_lifecycle(tmp_path):
    result = subprocess.run(["python3", str(HARNESS), "--root", str(tmp_path)], text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    receipt = json.loads((tmp_path / "phase5-conformance.json").read_text())
    assert receipt["passed"] is True
    projection_digest = receipt["projection"]["sha256"]
    assert len(projection_digest) == 64
    assert receipt["owner_results"]["claim_ledger"]["projection_sha256"] == projection_digest
    assert receipt["owner_results"]["mnemes"]["projection_sha256"] == projection_digest
    assert receipt["owner_results"]["claim_ledger"]["idempotent"] is True
    assert receipt["owner_results"]["mnemes"]["different_bytes_same_key_rejected"] is True
    assert all(case["state"] == "passed" for case in receipt["matrix"])


def test_phase5_harness_fails_loudly_when_sibling_is_missing(tmp_path):
    env = {"PATH": "/usr/bin:/bin", "CLAIMLEDGER_ROOT": str(tmp_path / "missing")}
    result = subprocess.run(["python3", str(HARNESS), "--root", str(tmp_path)], env=env, text=True, capture_output=True)
    assert result.returncode != 0
    assert "ClaimLedger" in result.stderr
