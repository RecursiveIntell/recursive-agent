"""Exercise the registered opt-in route and real framed transport, not a second parser."""
import base64
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import socket
import struct
import sys
import threading

import pytest

PLUGIN_DIR = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "hermes_native_raw_durable", PLUGIN_DIR / "__init__.py",
    submodule_search_locations=[str(PLUGIN_DIR)],
)
assert SPEC and SPEC.loader
plugin = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = plugin
SPEC.loader.exec_module(plugin)
client = sys.modules[SPEC.name + ".client"]
RUN_ID = "v1:recursive-agent/run/v1:det:raw-fixture"
RUN_DIR = "/fixture/raw-run"


class Context:
    def __init__(self, socket_path, durable=True):
        self.config = {"socket_path": socket_path, "durable_start": durable}
        self.tools = []

    def get_config(self, key):
        return self.config.get(key)

    def register_tool(self, **tool):
        self.tools.append(tool)


def invoke(tmp_path, socket_path, raw, durable=True):
    operation = tmp_path / "input.json"
    operation.write_bytes(raw)
    ctx = Context(socket_path, durable)
    plugin.register(ctx)
    assert len(ctx.tools) == 1
    return ctx.tools[0]["handler"]({"envelope_path": str(operation)})


def read_exact(conn, n):
    data = bytearray()
    while len(data) < n:
        part = conn.recv(n - len(data))
        if not part:
            raise EOFError("fixture peer closed")
        data.extend(part)
    return bytes(data)


@contextmanager
def daemon(tmp_path, replies):
    path = str(tmp_path / "r.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(8)
    server.settimeout(0.05)
    stop = threading.Event()
    seen, errors = [], []

    def serve():
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                with conn:
                    conn.settimeout(2)
                    length = struct.unpack(">I", read_exact(conn, 4))[0]
                    assert length <= client.MAX_FRAME_PAYLOAD_BYTES
                    frame = json.loads(read_exact(conn, length))
                    seen.append(frame)
                    reply = replies(frame, len(seen))
                    if reply is None:
                        continue
                    reply = dict(reply)
                    reply.setdefault("request_id", frame["request_id"])
                    payload = json.dumps(reply).encode()
                    conn.sendall(struct.pack(">I", len(payload)) + payload)
            except Exception as exc:
                errors.append(exc)
                return

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        yield path, seen
    finally:
        stop.set()
        server.close()
        thread.join(timeout=3)
        assert not thread.is_alive()
        assert not errors, errors


def started(family="provider_egress_v3"):
    return {"started": True, "run_id": RUN_ID, "run_dir": RUN_DIR, "operation_family": family}


def status(state):
    return {"run_id": RUN_ID, "status": {"state": state, "terminal_state": "succeeded"}}


def verified():
    return {"run_id": RUN_ID, "verification": {
        "ok": True, "current_strict_success": True, "length": 3, "final_head": "blake3:fixture",
    }}


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":1,"\\u0078":2}', b'\xff', b'{} {}'])
def test_optin_forwards_original_bytes_to_native_admission(tmp_path, raw):
    def replies(frame, _):
        assert frame["request"]["kind"] == "start_native_raw"
        assert base64.b64decode(frame["request"]["operation_json_b64"]) == raw
        return {"error": {"message": "native fixture rejects original bytes"}}

    with daemon(tmp_path, replies) as (path, seen):
        result = invoke(tmp_path, path, raw)
    assert "native fixture rejects original bytes" in result
    assert len(seen) == 1


def test_registered_optin_exposes_pending_without_verification_or_resubmit(tmp_path):
    def replies(frame, n):
        return started() if n == 1 else None

    with daemon(tmp_path, replies) as (path, seen):
        result = json.loads(invoke(tmp_path, path, b'{"schema":"recursive-agent.operation/v3"}'))
    assert result["state"] == "pending"
    assert result["verified"] is False
    assert result["run_id"] == RUN_ID
    assert result["resumable"] is True
    assert "final_head" not in result and "recorded_output" not in result
    assert [f["request"]["kind"] for f in seen] == ["start_native_raw", "status"]


def test_raw_follower_polls_then_verifies_and_reads_exact_original_operation(tmp_path):
    raw = b' {"schema":"recursive-agent.operation/v3", "fixture":1} '
    def replies(frame, n):
        kind = frame["request"]["kind"]
        if n == 1:
            return started()
        if kind == "status":
            return status("active" if n == 2 else "terminal")
        if kind == "verify":
            return verified()
        assert kind == "read_recorded_provider_output_native_raw"
        assert base64.b64decode(frame["request"]["operation_json_b64"]) == raw
        return {"output": {"model": "fixture", "text": "recorded"}}
    with daemon(tmp_path, replies) as (path, seen):
        result = client.start_and_follow_raw(path, raw, poll_interval=0.001, deadline=2)
    assert result["recorded_output"] == {"model": "fixture", "text": "recorded"}
    assert result["operation_family"] == "provider_egress_v3"
    assert [f["request"]["kind"] for f in seen] == [
        "start_native_raw", "status", "status", "verify", "read_recorded_provider_output_native_raw",
    ]


@pytest.mark.parametrize("bad", ["wrong-request", "wrong-run"])
def test_raw_follower_never_verifies_mismatched_status(tmp_path, bad):
    def replies(frame, n):
        if n == 1:
            return started()
        value = status("terminal")
        value["request_id" if bad == "wrong-request" else "run_id"] = "wrong"
        return value
    with daemon(tmp_path, replies) as (path, seen):
        with pytest.raises(client.DaemonClientError, match="mismatch"):
            client.start_and_follow_raw(path, b'{}', poll_interval=0.001, deadline=1)
    assert [f["request"]["kind"] for f in seen] == ["start_native_raw", "status"]


def test_raw_v1_preserves_synchronous_terminal_projection(tmp_path):
    def replies(frame, n):
        return {1: started("v1"), 2: status("terminal"), 3: verified()}[n]
    with daemon(tmp_path, replies) as (path, seen):
        result = client.start_and_follow_raw(path, b'{}', poll_interval=0.001, deadline=1)
    assert result["operation_family"] == "v1"
    assert result["state"] == "terminal"
    assert "recorded_output" not in result
    assert [f["request"]["kind"] for f in seen] == ["start_native_raw", "status", "verify"]


def test_lost_start_ack_is_explicit_ambiguity_not_retryable_unavailability(tmp_path):
    with daemon(tmp_path, lambda frame, n: None) as (path, seen):
        result = json.loads(invoke(tmp_path, path, b'{}'))
    assert result["state"] == "ambiguous"
    assert result["verified"] is False
    assert result["retry_allowed"] is False
    assert "run_id" not in result
    assert len(seen) == 1


def test_deadline_returns_pending_and_never_verifies_active(tmp_path):
    with daemon(tmp_path, lambda frame, n: started() if n == 1 else status("active")) as (path, seen):
        result = client.start_and_follow_raw(path, b'{}', poll_interval=0.001, deadline=0)
    assert result["state"] == "pending"
    assert result["reason"] == "deadline_reached_while_active"
    assert [f["request"]["kind"] for f in seen] == ["start_native_raw", "status"]


@pytest.mark.parametrize("bounds", [(0, 1), (-1, 1), (float('inf'), 1), (1, float('nan')), (True, 1)])
def test_invalid_poll_bounds_deny_before_start(monkeypatch, bounds):
    def forbidden(*args, **kwargs):
        raise AssertionError("invalid bounds started an operation")
    monkeypatch.setattr(client, "_raw_request", forbidden)
    with pytest.raises(client.DaemonClientError, match="invalid polling bounds"):
        client.start_and_follow_raw('/missing.sock', b'{}', poll_interval=bounds[0], deadline=bounds[1])


def test_terminal_verification_failure_never_reads_output(tmp_path):
    def replies(frame, n):
        if n == 1:
            return started()
        if n == 2:
            return status("terminal")
        value = verified()
        value["verification"]["current_strict_success"] = False
        return value
    with daemon(tmp_path, replies) as (path, seen):
        with pytest.raises(client.DaemonRunFailure, match="strict success"):
            client.start_and_follow_raw(path, b'{}', poll_interval=0.001, deadline=1)
    assert [f["request"]["kind"] for f in seen] == ["start_native_raw", "status", "verify"]


def test_missing_daemon_before_send_is_unavailable_not_ambiguous(tmp_path):
    value = invoke(tmp_path, str(tmp_path / 'missing.sock'), b'{}')
    assert value.startswith('recursive_agent_execute: unavailable:')
