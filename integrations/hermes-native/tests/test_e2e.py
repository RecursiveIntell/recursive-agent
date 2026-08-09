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

    runs_root = str(tmp_path / "runs")
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
        result = plugin.submit_and_status(socket_path, envelope)
        assert result["state"] == "terminal", result
        assert result["run_id"]
        assert result["receipt_ref"] == f"run:{result['run_id']}"
    finally:
        daemon.terminate()
        try:
            daemon.wait(timeout=5)
        except subprocess.TimeoutExpired:
            daemon.kill()
