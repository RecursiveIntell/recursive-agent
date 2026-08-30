"""Task 4.1 — registration, service gating, and malformed-response rejection.

The plugin is tested through the same `register(ctx)` / `ctx.register_tool(...)`
contract Hermes uses (its plugin loader calls `register_fn(ctx)` with a real
`PluginContext`). We use a stub ctx that records the registration call — the
full real-loader wiring is the Task 4.2 E2E.
"""

import importlib.util
import json
import os
import socket
import sys
import threading

import pytest

PLUGIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PLUGIN_DIR)

# Hermes loads plugins by directory path (a hyphenated dir name is valid for
# its loader but not for a plain `import`). Mirror that: load __init__.py from
# the plugin directory explicitly.
_SPEC = importlib.util.spec_from_file_location(
    "hermes_native", os.path.join(PLUGIN_DIR, "__init__.py")
)
assert _SPEC is not None and _SPEC.loader is not None
# Register the package name BEFORE exec so the plugin's relative imports
# (``from .client import ...``) resolve against the directory package.
plugin = importlib.util.module_from_spec(_SPEC)
plugin.__package__ = "hermes_native"
plugin.__path__ = [PLUGIN_DIR]
sys.modules["hermes_native"] = plugin
_SPEC.loader.exec_module(plugin)


class StubCtx:
    """Records the single tool registration exactly as Hermes' loader drives it."""

    def __init__(self):
        self.registrations = []

    def register_tool(self, **kwargs):
        self.registrations.append(kwargs)


def test_register_exposes_one_non_overriding_tool_in_recursive_agent_toolset():
    ctx = StubCtx()
    plugin.register(ctx)
    assert len(ctx.registrations) == 1
    reg = ctx.registrations[0]
    assert reg["name"] == "recursive_agent_execute"
    assert reg["toolset"] == "recursive_agent"
    # A non-overriding plugin must not request override.
    assert reg.get("override") is None or reg.get("override") is False
    # Hermes dispatches registered handlers as handler(args), not handler(ctx, args).
    # The closure must retain the registration context without a TypeError.
    assert reg["handler"]({}) == "recursive_agent_execute: unavailable: envelope_path required"


def test_check_fn_returns_false_when_socket_absent(tmp_path):
    # Point the plugin at a socket that does not exist.
    missing = str(tmp_path / "does-not-exist.sock")
    assert plugin.check_recursive_agent_available_stub(missing) is False


def test_check_fn_returns_true_when_socket_answers(tmp_path):
    sock_path = str(tmp_path / "ra.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.listen(1)
    stop = threading.Event()

    def _accept():
        try:
            while not stop.is_set():
                server.settimeout(0.1)
                try:
                    conn, _ = server.accept()
                    try:
                        header = conn.recv(4)
                        if len(header) == 4:
                            length = int.from_bytes(header, "big")
                            conn.recv(length)
                            payload = b'{"schema":"recursive-agent.ipc/request/v1","protocol_version":1,"request_id":"plugin-ping-1","pong":true}'
                            conn.sendall(len(payload).to_bytes(4, "big") + payload)
                    finally:
                        conn.close()
                except socket.timeout:
                    continue
        except OSError:
            pass

    thread = threading.Thread(target=_accept, daemon=True)
    thread.start()
    try:
        # The service gate only checks reachability of the private socket.
        assert plugin.check_recursive_agent_available_stub(sock_path) is True
    finally:
        stop.set()
        server.close()


def test_malformed_runtime_response_is_rejected():
    from hermes_native import client

    # An oversized frame length must be rejected without parsing.
    with pytest.raises(client.DaemonClientError):
        client._frame_len_check((1024 * 1024) + (64 * 1024) + 1)


def test_terminal_run_failure_preserves_daemon_facts(monkeypatch):
    from hermes_native import client

    monkeypatch.setattr(
        client,
        "submit_envelope",
        lambda _socket_path, _envelope: {"run_id": "run-1", "run_dir": "/runs/run-1"},
    )
    monkeypatch.setattr(
        client,
        "status_of_run",
        lambda _socket_path, _run_id: {
            "run_id": "run-1",
            "status": {"state": "terminal", "terminal_state": "failed"},
        },
    )
    monkeypatch.setattr(
        client,
        "verify_run",
        lambda _socket_path, _run_id: {
            "run_id": "run-1",
            "verification": {
                "ok": True,
                "current_strict_success": False,
                "length": 4,
                "final_head": "head-1",
                "terminal_state": "failed",
            },
        },
    )

    with pytest.raises(client.DaemonRunFailure) as raised:
        client.submit_and_status("/tmp/ra.sock", {"operation": "fixture"})

    failure = raised.value
    assert failure.code == "terminal_run_failed"
    assert failure.run_id == "run-1"
    assert failure.run_dir == "/runs/run-1"
    assert failure.status["status"]["terminal_state"] == "failed"
    assert failure.verification["verification"]["current_strict_success"] is False


def test_strict_verification_failure_preserves_divergence_facts(monkeypatch):
    from hermes_native import client

    monkeypatch.setattr(
        client,
        "submit_envelope",
        lambda _socket_path, _envelope: {"run_id": "run-2", "run_dir": "/runs/run-2"},
    )
    monkeypatch.setattr(
        client,
        "status_of_run",
        lambda _socket_path, _run_id: {
            "run_id": "run-2",
            "status": {"state": "terminal", "terminal_state": "succeeded"},
        },
    )
    monkeypatch.setattr(
        client,
        "verify_run",
        lambda _socket_path, _run_id: {
            "run_id": "run-2",
            "verification": {
                "ok": False,
                "current_strict_success": False,
                "length": 1,
                "final_head": "head-2",
                "terminal_state": "legacy_unknown",
                "first_divergence": {
                    "index": 1,
                    "reason": "receipt chain mismatch",
                },
            },
        },
    )

    with pytest.raises(client.DaemonRunFailure) as raised:
        client.submit_and_status("/tmp/ra.sock", {"operation": "fixture"})

    failure = raised.value
    assert failure.code == "strict_verification_failed"
    assert failure.verification["verification"]["first_divergence"]["reason"] == (
        "receipt chain mismatch"
    )


def test_strict_verification_error_response_preserves_daemon_error(monkeypatch):
    from hermes_native import client

    monkeypatch.setattr(
        client,
        "submit_envelope",
        lambda _socket_path, _envelope: {"run_id": "run-4", "run_dir": "/runs/run-4"},
    )
    monkeypatch.setattr(
        client,
        "status_of_run",
        lambda _socket_path, _run_id: {
            "run_id": "run-4",
            "status": {"state": "terminal", "terminal_state": "succeeded"},
        },
    )
    monkeypatch.setattr(
        client,
        "verify_run",
        lambda _socket_path, _run_id: {
            "run_id": "run-4",
            "error": {
                "code": "runtime_error",
                "message": "runtime: ledger: chain divergence at receipt 0",
            },
        },
    )

    with pytest.raises(client.DaemonRunFailure) as raised:
        client.submit_and_status("/tmp/ra.sock", {"operation": "fixture"})

    failure = raised.value
    assert failure.code == "strict_verification_error"
    assert failure.verification["error"]["code"] == "runtime_error"
    assert "chain divergence" in str(failure)


def test_plugin_projects_terminal_failure_instead_of_unavailable(monkeypatch, tmp_path):
    from hermes_native import client

    envelope = tmp_path / "envelope.json"
    envelope.write_text("{}", encoding="utf-8")
    failure = client.DaemonRunFailure(
        code="terminal_run_failed",
        message="daemon terminal state is failed",
        run_id="run-3",
        run_dir="/runs/run-3",
        status={"run_id": "run-3", "status": {"state": "terminal", "terminal_state": "failed"}},
        verification={"run_id": "run-3", "verification": {"ok": True, "current_strict_success": False}},
    )
    monkeypatch.setattr(plugin, "submit_and_status", lambda _socket_path, _envelope: (_ for _ in ()).throw(failure))

    result = json.loads(plugin._handler(None, {"envelope_path": str(envelope)}))
    assert result["state"] == "terminal"
    assert result["verified"] is False
    assert result["failure"]["code"] == "terminal_run_failed"
    assert result["status"]["status"]["terminal_state"] == "failed"
    assert result["verification"]["verification"]["current_strict_success"] is False


def test_plugin_preserves_verified_success_result_shape(monkeypatch, tmp_path):
    envelope = tmp_path / "envelope.json"
    envelope.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        plugin,
        "submit_and_status",
        lambda _socket_path, _envelope: {
            "state": "terminal",
            "run_id": "run-ok",
            "run_dir": "/runs/run-ok",
            "verification": {
                "ok": True,
                "length": 2,
                "final_head": "head-ok",
            },
        },
    )

    assert json.loads(plugin._handler(None, {"envelope_path": str(envelope)})) == {
        "schema": "recursive-agent.hermes-result/v1",
        "state": "terminal",
        "run_id": "run-ok",
        "run_dir": "/runs/run-ok",
        "verified": True,
        "chain_length": 2,
        "final_head": "head-ok",
    }


def test_plugin_keeps_transport_failure_unavailable(monkeypatch, tmp_path):
    from hermes_native import client

    envelope = tmp_path / "envelope.json"
    envelope.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        plugin,
        "submit_and_status",
        lambda _socket_path, _envelope: (_ for _ in ()).throw(
            client.DaemonClientError("cannot reach daemon")
        ),
    )

    assert plugin._handler(None, {"envelope_path": str(envelope)}) == (
        "recursive_agent_execute: unavailable: cannot reach daemon"
    )
