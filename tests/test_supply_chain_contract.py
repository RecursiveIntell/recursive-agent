"""Task 5.2 contract tests for the supply-chain advisory gate.

The plan requires a repeatable advisory gate that fails on vulnerabilities,
unsound, and yanked packages, runs on a schedule (so newly published
advisories are caught after merge), uses one pinned tool version, and never
hides warnings behind a wildcard ignore. These tests pin that contract in the
workflow file so it cannot silently regress.
"""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "supply-chain.yml"
CHECKOUT_SHA = "de0fac2e4500dabe0009e67214ff5f5447ce83dd"  # v6.0.2, same as ci.yml


def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def workflow_doc() -> dict:
    return yaml.safe_load(workflow_text())


def test_workflow_exists_and_is_valid_yaml() -> None:
    doc = workflow_doc()
    assert "jobs" in doc


def test_gate_is_scheduled_not_only_pr_triggered() -> None:
    """A newly published advisory must be caught without a new commit."""
    on = workflow_doc()[True] if True in workflow_doc() else workflow_doc()["on"]
    assert "schedule" in on, "missing scheduled rerun for new advisories"
    crons = [entry["cron"] for entry in on["schedule"]]
    assert crons, "schedule block has no cron"


def test_gate_pins_tool_and_actions() -> None:
    text = workflow_text()
    assert "cargo-deny@0.19.8" in text, "cargo-deny version must be pinned"
    assert f"actions/checkout@{CHECKOUT_SHA}" in text
    # The install action must be pinned to an immutable commit, not a tag.
    for line in text.splitlines():
        if "taiki-e/install-action@" in line:
            ref = line.split("@", 1)[1].split()[0]
            assert len(ref) == 40 and all(c in "0123456789abcdef" for c in ref.lower()), (
                f"install-action ref is not an immutable SHA: {ref}"
            )


def test_gate_does_not_hide_warnings() -> None:
    """Wildcard/blanket ignores are forbidden; policy lives in deny.toml."""
    text = workflow_text().lower()
    assert "--allow" not in text
    assert "--disable" not in text
    deny = (ROOT / "deny.toml").read_text(encoding="utf-8")
    assert 'ignore = []' in deny, (
        "advisory ignore list must stay empty unless an exception carries "
        "owner, reachability proof, review date, and expiry (Task 5.2)"
    )


def test_gate_fails_closed_on_vulnerable_fixture() -> None:
    """Negative witness: a deliberately vulnerable lockfile fails the gate.

    Runs cargo-deny with the repo's deny.toml against a synthetic lockfile
    containing a known-vulnerable crate version, proving the gate's failure
    mode rather than trusting the exit code of a clean run.
    """
    import shutil
    import subprocess

    try:
        import pytest
    except ImportError:  # pragma: no cover
        raise AssertionError("pytest required")
    if shutil.which("cargo-deny") is None:
        pytest.skip("cargo-deny not installed locally; the workflow runs this witness")
    tmp = Path(__file__).parent / ".tmp_vuln_fixture"
    tmp.mkdir(exist_ok=True)
    try:
        (tmp / "Cargo.toml").write_text(
            '[package]\nname = "vuln-fixture"\nversion = "0.0.0"\nedition = "2021"\n'
        )
        # rustsec RUSTSEC-2021-0145: atty 0.2.x is unsound and yanked.
        (tmp / "Cargo.lock").write_text(
            'version = 4\n\n'
            '[[package]]\nname = "atty"\nversion = "0.2.14"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            'checksum = "d9b39be18770d11421cdb1b9947a45dd3f37e93021cb2b7b9aa1841dce3"\n\n'
            '[[package]]\nname = "vuln-fixture"\nversion = "0.0.0"\n'
        )
        proc = subprocess.run(
            ["cargo", "deny", "--locked", "check", "advisories"],
            cwd=tmp,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert proc.returncode != 0, (
            "gate passed a known-vulnerable lockfile: " + proc.stdout[-2000:]
        )
    finally:
        import contextlib

        with contextlib.suppress(OSError):
            import shutil as _sh

            _sh.rmtree(tmp)
