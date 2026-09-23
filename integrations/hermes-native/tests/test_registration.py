"""Task 4.1 — registration, service gating, and malformed-response rejection.

The plugin is tested through the same `register(ctx)` / `ctx.register_tool(...)`
contract Hermes uses (its plugin loader calls `register_fn(ctx)` with a real
`PluginContext`). We use a stub ctx that records the registration call — the
full real-loader wiring is the Task 4.2 E2E.
"""

import base64
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

    def get_config(self, key, default=None):
        assert key == "socket_path"
        return default

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
        client._frame_len_check(client.MAX_FRAME_PAYLOAD_BYTES + 1)


def test_response_frame_accepts_fragmented_header():
    from hermes_native import client

    class FragmentedHeader:
        def __init__(self, conn):
            self.conn = conn
            self.header_reads = 0

        def recv(self, size):
            if self.header_reads < 4:
                self.header_reads += 1
                return self.conn.recv(min(size, 1))
            return self.conn.recv(size)

    reader, writer = socket.socketpair()
    try:
        payload = b'{"request_id":"fragmented-header","pong":true}'
        writer.sendall(len(payload).to_bytes(4, "big") + payload)
        fragmented = FragmentedHeader(reader)
        assert client._read_frame(fragmented) == {
            "request_id": "fragmented-header", "pong": True
        }
        assert fragmented.header_reads == 4
    finally:
        reader.close()
        writer.close()


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
    monkeypatch.setattr(plugin, "submit_and_status_raw", lambda _socket_path, _envelope: (_ for _ in ()).throw(failure))

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
        "submit_and_status_raw",
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


def test_v3_ipc_client_sends_exact_operation_and_rejects_runtime_error(tmp_path):
    from hermes_native import client

    socket_path = str(tmp_path / "recorded.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    server.listen(2)
    observed = []
    request_id = "plugin-read-recorded-provider-v3-1"

    def serve_two():
        server.settimeout(3)
        for result in (
            {"request_id": request_id, "output": {"model": "fixture-model", "text": "recorded"}},
            {"request_id": request_id, "error": {"code": "runtime_error", "message": "policy expired"}},
        ):
            conn, _ = server.accept()
            with conn:
                header = conn.recv(4)
                length = int.from_bytes(header, "big")
                body = bytearray()
                while len(body) < length:
                    chunk = conn.recv(length - len(body))
                    if not chunk:
                        return
                    body.extend(chunk)
                observed.append(json.loads(body))
                payload = json.dumps(result).encode("utf-8")
                conn.sendall(len(payload).to_bytes(4, "big") + payload)

    thread = threading.Thread(target=serve_two, daemon=True)
    thread.start()
    operation = {"schema": "recursive-agent.operation/v3", "sealed_completion": {"id": "sealed"}}
    try:
        assert client.read_recorded_provider_output_v3(socket_path, operation) == {
            "model": "fixture-model", "text": "recorded"
        }
        with pytest.raises(client.DaemonClientError, match="policy expired"):
            client.read_recorded_provider_output_v3(socket_path, operation)
    finally:
        server.close()
        thread.join(timeout=3)
    assert not thread.is_alive()
    assert [entry["request"] for entry in observed] == [
        {"kind": "read_recorded_provider_output_v3", "operation": operation}
    ] * 2
    assert all(entry["request_id"] == request_id for entry in observed)


def test_v3_consumer_requires_exact_operation_and_projects_daemon_output(monkeypatch, tmp_path):
    from hermes_native import client

    envelope = {"schema": "recursive-agent.operation/v3", "sealed_completion": {"id": "sealed"}}
    path = tmp_path / "operation.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    calls = []

    def submit(_socket_path, supplied):
        calls.append(("submit", supplied))
        return {"run_id": "run-v3", "run_dir": "/runs/run-v3"}

    def read(_socket_path, supplied):
        calls.append(("read", supplied))
        return {"model": "fixture-model", "text": "recorded-response"}

    monkeypatch.setattr(client, "submit_provider_egress_v3", submit)
    monkeypatch.setattr(client, "submit_envelope", lambda *_: pytest.fail("V1 downgrade"))
    monkeypatch.setattr(client, "status_of_run", lambda *_: {
        "status": {"state": "terminal", "terminal_state": "succeeded"}
    })
    monkeypatch.setattr(client, "verify_run", lambda *_: {
        "run_id": "run-v3", "verification": {
            "ok": True, "current_strict_success": True, "length": 2, "final_head": "head-v3"
        }
    })
    monkeypatch.setattr(client, "read_recorded_provider_output_v3", read, raising=False)

    result = client.submit_and_status("/tmp/ra.sock", envelope)
    assert result["recorded_output"] == {"model": "fixture-model", "text": "recorded-response"}
    assert calls == [("submit", envelope), ("read", envelope)]
    # The plugin projects the owner's response; it must never open run_dir to read it.
    monkeypatch.setattr(plugin, "submit_and_status_raw", lambda *_: {**result, "operation_family": "provider_egress_v3"})
    projected = json.loads(plugin._handler(None, {"envelope_path": str(path)}))
    assert projected["recorded_output"] == result["recorded_output"]


def test_v3_unavailable_read_does_not_present_a_verified_completion(monkeypatch):
    from hermes_native import client

    envelope = {"schema": "recursive-agent.operation/v3"}
    monkeypatch.setattr(client, "submit_provider_egress_v3", lambda *_: {
        "run_id": "run-v3", "run_dir": "/runs/run-v3"
    })
    monkeypatch.setattr(client, "status_of_run", lambda *_: {
        "status": {"state": "terminal", "terminal_state": "succeeded"}
    })
    monkeypatch.setattr(client, "verify_run", lambda *_: {
        "run_id": "run-v3", "verification": {
            "ok": True, "current_strict_success": True, "length": 2, "final_head": "head-v3"
        }
    })
    monkeypatch.setattr(client, "read_recorded_provider_output_v3", lambda *_: (
        _ for _ in ()
    ).throw(client.DaemonClientError("current policy denied")), raising=False)
    with pytest.raises(client.DaemonRunFailure) as raised:
        client.submit_and_status("/tmp/ra.sock", envelope)
    assert raised.value.code == "recorded_output_unavailable"
    assert raised.value.run_id == "run-v3"


def test_plugin_keeps_transport_failure_unavailable(monkeypatch, tmp_path):
    from hermes_native import client

    envelope = tmp_path / "envelope.json"
    envelope.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        plugin,
        "submit_and_status_raw",
        lambda _socket_path, _envelope: (_ for _ in ()).throw(
            client.DaemonClientError("cannot reach daemon")
        ),
    )

    assert plugin._handler(None, {"envelope_path": str(envelope)}) == (
        "recursive_agent_execute: unavailable: cannot reach daemon"
    )


def test_handler_transports_original_escaped_duplicate_without_mapping(monkeypatch, tmp_path):
    from hermes_native import client

    raw = b'{"schema":"recursive-agent.operation/v3","nested":{"x":1,"\\u0078":2}}'
    path = tmp_path / "untrusted-operation.json"
    path.write_bytes(raw)
    seen = []

    def capture(_socket_path, supplied):
        seen.append(supplied)
        raise client.DaemonClientError("canonical daemon rejection")

    monkeypatch.setattr(plugin, "submit_and_status_raw", capture, raising=False)
    monkeypatch.setattr(plugin, "submit_and_status", lambda *_: pytest.fail("lossy map transport"), raising=False)
    assert "unavailable" in plugin._handler(None, {"envelope_path": str(path)})
    assert seen == [raw]


def test_plugin_rejects_oversize_before_submission(monkeypatch, tmp_path):
    from hermes_native import client

    path = tmp_path / "oversize.json"
    path.write_bytes(b"x" * (client.MAX_OPERATION_INPUT_BYTES + 1))
    monkeypatch.setattr(plugin, "submit_and_status_raw", lambda *_: pytest.fail("submitted oversize"))
    assert "exceeds byte limit" in plugin._handler(None, {"envelope_path": str(path)})


def test_raw_ipc_transport_preserves_original_bytes_to_daemon(tmp_path):
    from hermes_native import client

    socket_path = str(tmp_path / "raw.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    server.listen(1)
    seen = []

    def serve_one():
        server.settimeout(3)
        conn, _ = server.accept()
        with conn:
            header = conn.recv(4)
            length = int.from_bytes(header, "big")
            body = bytearray()
            while len(body) < length:
                body.extend(conn.recv(length - len(body)))
            request = json.loads(body)
            seen.append(base64.b64decode(request["request"]["operation_json_b64"], validate=True))
            result = {
                "request_id": request["request_id"],
                "error": {"code": "runtime_error", "message": "duplicate key"},
            }
            payload = json.dumps(result).encode("utf-8")
            conn.sendall(len(payload).to_bytes(4, "big") + payload)

    worker = threading.Thread(target=serve_one, daemon=True)
    worker.start()
    raw = b'{"schema":"recursive-agent.operation/v3","nested":{"x":1,"\\u0078":2}}'
    try:
        with pytest.raises(client.DaemonClientError, match="duplicate key"):
            client.submit_native_raw(socket_path, raw)
    finally:
        server.close()
        worker.join(timeout=3)
    assert not worker.is_alive()
    assert seen == [raw]


def test_raw_v3_completion_uses_daemon_family_and_reuses_original_bytes(monkeypatch):
    from hermes_native import client

    raw = b'{"schema":"recursive-agent.operation/v3"}'
    calls = []
    def submit(_socket_path, supplied):
        calls.append(("submit", supplied))
        return {"run_id": "raw-run", "run_dir": "/fixture/run", "operation_family": "provider_egress_v3"}
    def read(_socket_path, supplied):
        calls.append(("read", supplied))
        return {"model": "fixture", "text": "output"}
    monkeypatch.setattr(client, "submit_native_raw", submit)
    monkeypatch.setattr(client, "status_of_run", lambda *_: {"status": {"state": "terminal", "terminal_state": "succeeded"}})
    monkeypatch.setattr(client, "verify_run", lambda *_: {"run_id": "raw-run", "verification": {
        "ok": True, "current_strict_success": True, "length": 1, "final_head": "head"
    }})
    monkeypatch.setattr(client, "read_recorded_native_raw", read)
    result = client.submit_and_status_raw("/fixture/socket", raw)
    assert result["recorded_output"] == {"model": "fixture", "text": "output"}
    assert calls == [("submit", raw), ("read", raw)]
