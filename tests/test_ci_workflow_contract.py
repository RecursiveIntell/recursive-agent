from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
LIBRARIES_SHA = "650263d29394ab064f00eab68434c112782876f3"
CHECKOUT_SHA = "de0fac2e4500dabe0009e67214ff5f5447ce83dd"


def test_paired_root_workflow_declares_pinned_checkouts_and_stable_gate():
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "name: Recursive Agent paired-root CI" in text
    assert "pull_request:" in text
    assert "workflow_dispatch:" in text
    assert f"actions/checkout@{CHECKOUT_SHA}" in text
    assert f"LIBRARIES_SHA: {LIBRARIES_SHA}" in text
    assert "path: recursive-agent" in text
    assert "path: Libraries" in text
    assert "name: Paired root" in text
    assert "name: Paired root required" in text
    assert 'sudo apt-get install --no-install-recommends -y dbus-user-session libseccomp-dev' in text
    assert 'sudo loginctl enable-linger "$(id -un)"' in text
    assert 'sudo systemctl start "user-runtime-dir@${uid}.service"' in text
    assert 'sudo systemctl start "user@${uid}.service"' in text
    assert 'runtime_started=0' in text
    assert 'user_started=0' in text
    assert 'trap cleanup EXIT' in text
    assert 'runtime_started=1' in text
    assert 'user_started=1' in text
    assert 'export XDG_RUNTIME_DIR="$runtime"' in text
    assert 'export DBUS_SESSION_BUS_ADDRESS="unix:path=${runtime}/bus"' in text
    assert '[[ -S "$runtime/bus" ]]' in text
    assert text.index("trap cleanup EXIT") < text.index('sudo systemctl start "user-runtime-dir@${uid}.service"')


def test_paired_root_workflow_refuses_wrong_library_sha_and_absolute_dependency_paths():
    text = WORKFLOW.read_text(encoding="utf-8")

    assert 'actual="$(git -C Libraries rev-parse HEAD)"' in text
    assert 'if [ "$actual" != "$LIBRARIES_SHA" ]; then' in text
    assert "cargo metadata --locked --format-version 1" in text
    assert "absolute dependency path" in text
    assert "path = \"../Libraries/" in text


def test_paired_root_workflow_runs_locked_full_gates_and_relocated_metadata():
    text = WORKFLOW.read_text(encoding="utf-8")

    for command in (
        "cargo fmt --all -- --check",
        "cargo check --locked --workspace",
        "cargo clippy --locked --workspace --all-targets -- -D warnings",
        "cargo test --locked --workspace --all-targets --no-fail-fast",
        "relocated/recursive-agent",
        "relocated/Libraries",
    ):
        assert command in text


def test_workflow_keeps_ci_permissions_read_only_and_no_provider_execution():
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "contents: read" in text
    assert "contents: write" not in text
    assert "secrets: inherit" not in text
    assert "OPENAI_API_KEY" not in text
    assert "OLLAMA" not in text
    assert "curl" not in text
