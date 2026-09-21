from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
LIBRARIES_SHA = "6b55d85fb9ebf4ed5b5228f4d33f2cf7bc393f6a"
CHECKOUT_SHA = "de0fac2e4500dabe0009e67214ff5f5447ce83dd"


def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_workflow_uses_immutable_paired_sources_and_sibling_topology() -> None:
    text = workflow_text()
    assert f"actions/checkout@{CHECKOUT_SHA}" in text
    assert f"LIBRARIES_SHA: {LIBRARIES_SHA}" in text
    assert f"ref: {LIBRARIES_SHA}" in text
    assert "path: recursive-agent" in text
    assert "path: Libraries" in text
    assert 'path = "../Libraries/' in text
    assert "absolute dependency path" in text


def test_workflow_runs_canonical_locked_workspace_gates() -> None:
    text = workflow_text()
    assert 'CARGO_BUILD_JOBS: "2"' in text
    assert "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER: /usr/bin/env" in text
    assert "timeout-minutes: 45" in text
    assert "cargo metadata --locked --format-version 1 --no-deps" in text
    assert "cargo fmt --all -- --check" in text
    assert "cargo check --locked --workspace" in text
    assert "cargo clippy --locked --workspace --all-targets -- -D warnings" in text
    assert "cargo test --locked --workspace --all-targets --no-fail-fast" in text
    assert "bubblewrap libseccomp-dev strace" in text
    assert "kernel.apparmor_restrict_unprivileged_userns=0" in text
    assert "kernel.unprivileged_userns_clone=1" in text
    assert "bwrap --ro-bind / / -- /usr/bin/true" in text


def test_workflow_proves_relocated_sibling_resolution() -> None:
    text = workflow_text()
    assert "cp -a recursive-agent relocated/recursive-agent" in text
    assert "cp -a Libraries relocated/Libraries" in text
    assert "--manifest-path relocated/recursive-agent/Cargo.toml" in text
    relocated = text.split("Verify the same pair from a relocated root", 1)[1]
    assert "--no-deps" not in relocated


def test_workflow_does_not_depend_on_host_user_systemd_mutation() -> None:
    text = workflow_text()
    assert "systemd-run" not in text
    assert "loginctl" not in text
    assert "user-runtime-dir@" not in text
    assert "user@${uid}.service" not in text


def test_terminal_check_fails_closed_unless_paired_root_succeeds() -> None:
    text = workflow_text()
    assert "name: All required checks pass" in text
    assert "needs: paired-root" in text
    assert "if: always()" in text
    assert "PAIRED_ROOT_RESULT: ${{ needs.paired-root.result }}" in text
    assert 'if [ "$PAIRED_ROOT_RESULT" != success ]; then' in text
