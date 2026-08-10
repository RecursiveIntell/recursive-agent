"""Task 4.2 — real native-IPC vertical slice end to end.

Spawns the real ``ra-daemon`` binary, emits a canonical envelope via its
``emit-envelope`` command, and drives the plugin's handler over authenticated
IPC. Asserts the run reaches terminal state through the plugin's exact handler
path (no direct Rust-runner call from this test).
"""

import importlib.util
import json
import os
import subprocess
import sys
import time
from types import SimpleNamespace

PLUGIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(os.path.dirname(PLUGIN_DIR))
sys.path.insert(0, PLUGIN_DIR)

_SPEC = importlib.util.spec_from_file_location(
    "hermes_native", os.path.join(PLUGIN_DIR, "__init__.py")
)
assert _SPEC is not None and _SPEC.loader is not None
plugin = importlib.util.module_from_spec(_SPEC)
plugin.__package__ = "hermes_native"
plugin.__path__ = [PLUGIN_DIR]
sys.modules["hermes_native"] = plugin
_SPEC.loader.exec_module(plugin)

DAEMON_BIN = os.path.join(REPO_ROOT, "target", "debug", "ra-daemon")
CLI_BIN = os.path.join(REPO_ROOT, "target", "debug", "ra")


def _wait_for_socket(socket_path, timeout=10.0):
    import socket as _socket

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            try:
                s.settimeout(0.5)
                s.connect(socket_path)
                return True
            finally:
                s.close()
        except OSError:
            time.sleep(0.1)
    return False


def test_plugin_handler_submits_and_verifies_over_real_daemon(tmp_path):
    assert os.path.exists(DAEMON_BIN), f"ra-daemon not built at {DAEMON_BIN}"

    # A real configured run root may contain spaces; operator-visible handler
    # output must therefore not be reparsed as whitespace-delimited fields.
    runs_root = str(tmp_path / "runs with spaces")
    socket_path = str(tmp_path / "ra.sock")

    # Emit a canonical envelope from the Rust side.
    emitted = subprocess.run(
        [DAEMON_BIN, "emit-envelope", "--text", "hermes-e2e-ok"],
        capture_output=True,
        text=True,
        check=True,
    )
    envelope = json.loads(emitted.stdout)
    assert envelope["run_spec"]["steps"][0]["call"]["tool"] == "echo"

    # Spawn the real daemon.
    daemon = subprocess.Popen(
        [
            DAEMON_BIN,
            "serve",
            "--root",
            runs_root,
            "--socket",
            socket_path,
            "--max-concurrent",
            "4",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert _wait_for_socket(socket_path), "daemon socket did not appear"
        envelope_path = tmp_path / "operation.json"
        envelope_path.write_text(json.dumps(envelope), encoding="utf-8")
        ctx = SimpleNamespace(
            config={
                "plugins": {
                    "entries": {"recursive-agent-native": {"socket_path": socket_path}}
                }
            }
        )
        result = json.loads(plugin._handler(ctx, {"envelope_path": str(envelope_path)}))
        assert result["schema"] == "recursive-agent.hermes-result/v1"
        assert result["state"] == "terminal"
        assert result["run_id"]
        assert result["run_dir"].startswith(runs_root + os.sep)
        assert result["verified"] is True
        assert isinstance(result["chain_length"], int)
        assert result["final_head"]
        assert "receipt" not in result

        run_dir = result["run_dir"]
        pack_dir = tmp_path / "run-pack"
        subprocess.run(
            [CLI_BIN, "pack", "export", "--run", run_dir, "--out", str(pack_dir)],
            capture_output=True,
            text=True,
            check=True,
        )
        verified_pack = subprocess.run(
            [CLI_BIN, "pack", "verify", "--pack", str(pack_dir)],
            capture_output=True,
            text=True,
            check=True,
        )
        assert json.loads(verified_pack.stdout)["ok"] is True
        replayed_pack = subprocess.run(
            [CLI_BIN, "pack", "replay", "--pack", str(pack_dir)],
            capture_output=True,
            text=True,
            check=True,
        )
        assert json.loads(replayed_pack.stdout)["mode"] == "recorded_evidence"
    finally:
        daemon.terminate()
        try:
            daemon.wait(timeout=5)
        except subprocess.TimeoutExpired:
            daemon.kill()


def test_plugin_handler_refuses_missing_daemon_verification_facts(tmp_path, monkeypatch):
    """The presentation adapter fails closed rather than inventing evidence."""
    envelope_path = tmp_path / "operation.json"
    envelope_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        plugin,
        "submit_and_status",
        lambda _socket_path, _envelope: {"state": "terminal", "run_id": "run-x"},
    )

    result = plugin._handler(SimpleNamespace(config={}), {"envelope_path": str(envelope_path)})

    assert result == (
        "recursive_agent_execute: unavailable: daemon verification facts missing"
    )
