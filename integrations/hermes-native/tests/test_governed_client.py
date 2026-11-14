"""Closed V2 native IPC client tests (synthetic transport fixtures only)."""
from __future__ import annotations
import contextlib
import importlib.util
import json
from pathlib import Path
import socket
import struct
import threading
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
import importlib
import sys
SPEC = importlib.util.spec_from_file_location("native_governed_plugin", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
assert SPEC and SPEC.loader
package = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = package
SPEC.loader.exec_module(package)
client = importlib.import_module("native_governed_plugin.governed_client")

RUN = "v1:recursive-agent/run/v1:det:" + "a" * 64

def read_exact(conn, count):
    data = b""
    while len(data) < count:
        chunk = conn.recv(count - len(data))
        if not chunk:
            raise EOFError("fixture request incomplete")
        data += chunk
    return data

@contextlib.contextmanager
def server(tmp_path, respond):
    path = str(tmp_path / "native.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    Path(path).chmod(0o600)
    listener.listen(1)
    requests, errors = [], []
    def worker():
        try:
            listener.settimeout(2)
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(2)
                size = struct.unpack(">I", read_exact(conn, 4))[0]
                request = json.loads(read_exact(conn, size))
                requests.append(request)
                respond(conn, request)
        except (BrokenPipeError, ConnectionResetError):
            pass  # Expected only when the tested client rejects a partial frame.
        except Exception as error:
            errors.append(error)
    thread = threading.Thread(target=worker)
    thread.start()
    try:
        yield path, requests
    finally:
        listener.close()
        thread.join(3)
        assert not thread.is_alive()
        assert not errors, errors

def framed(request, result, **extra):
    value = dict(schema="recursive-agent.ipc/response/v2", protocol_version=2,
                 request_id=request["request_id"], result=result, **extra)
    body = json.dumps(value).encode()
    return struct.pack(">I", len(body)) + body


def test_v2_readback_uses_distinct_closed_wire_and_split_header(tmp_path):
    result = dict(kind="normal_chat_attempt_readback", send_authorized=False,
                  request={}, policy={}, recovery=None, parent_chain_head="b" * 64,
                  child_chain_head="c" * 64)
    def respond(conn, request):
        data = framed(request, result)
        for byte in data[:4]:
            conn.sendall(bytes([byte]))
            time.sleep(0.005)
        conn.sendall(data[4:])
    with server(tmp_path, respond) as (path, requests):
        got = client.NativeGovernanceClient(path).attempt_readback(RUN, "intent:fixture")
        assert got == result
    assert len(requests) == 1
    assert requests[0]["schema"] == "recursive-agent.ipc/request/v2"
    assert requests[0]["protocol_version"] == 2
    assert requests[0]["request"] == dict(kind="normal_chat_attempt_readback", session_run_id=RUN,
                                           dispatch_intent_ref="intent:fixture")

@pytest.mark.parametrize("failure", ["schema", "version", "correlation", "unknown", "duplicate", "oversize", "truncated"])
def test_invalid_or_legacy_response_cannot_be_promoted(tmp_path, failure):
    def respond(conn, request):
        value = dict(schema="recursive-agent.ipc/response/v2", protocol_version=2,
                     request_id=request["request_id"], result=dict(kind="denied", code="RUN_CLOSED", provider_attempted=False))
        if failure == "schema": value["schema"] = "recursive-agent.ipc/request/v1"
        if failure == "version": value["protocol_version"] = True
        if failure == "correlation": value["request_id"] = "other-request"
        if failure == "unknown": value["untrusted"] = True
        body = json.dumps(value).encode()
        if failure == "duplicate": body = body.replace(b'"protocol_version": 2', b'"protocol_version": 2, "protocol_version": 2')
        if failure == "oversize": conn.sendall(struct.pack(">I", 2**32-1)); return
        if failure == "truncated": conn.sendall(struct.pack(">I", len(body)) + body[:8]); return
        conn.sendall(struct.pack(">I", len(body)) + body)
    with server(tmp_path, respond) as (path, requests):
        with pytest.raises(client.DaemonGovernanceError):
            client.NativeGovernanceClient(path).attempt_readback(RUN, "intent:fixture")
    assert len(requests) == 1


def test_live_policy_denial_preserves_exact_code_without_retry(tmp_path):
    def respond(conn, request):
        conn.sendall(framed(request, dict(kind="denied", code="CAP_EXHAUSTED_ATTEMPTS", provider_attempted=False)))
    with server(tmp_path, respond) as (path, requests):
        with pytest.raises(client.DaemonGovernanceError) as caught:
            client.NativeGovernanceClient(path).session_open("session:fixture")
        assert caught.value.code == "CAP_EXHAUSTED_ATTEMPTS"
    assert len(requests) == 1


def test_one_absolute_rpc_deadline_not_renewed_by_dripping_bytes(tmp_path):
    def respond(conn, request):
        frame = framed(request, dict(kind="denied", code="RUN_CLOSED", provider_attempted=False))
        for byte in frame:
            conn.sendall(bytes([byte]))
            time.sleep(0.025)
    with server(tmp_path, respond) as (path, requests):
        started = time.monotonic()
        with pytest.raises(client.DaemonGovernanceError) as caught:
            client.NativeGovernanceClient(path, timeout=0.12).session_open("session:fixture")
        assert caught.value.code == "DAEMON_TIMEOUT"
        assert time.monotonic() - started < 1.5
    assert len(requests) == 1


def test_capability_query_is_nonauthorizing_and_has_no_session_fields(tmp_path):
    result = dict(kind="normal_chat_capabilities", grant_loaded=False, grant=None,
                  response_projection_schemas=["ares-response-json-sorted-v1"])
    def respond(conn, request):
        conn.sendall(framed(request, result))
    with server(tmp_path, respond) as (path, requests):
        got = client.NativeGovernanceClient(path).capabilities()
        assert got == result
    assert requests[0]["request"] == {"kind":"normal_chat_capabilities"}
    assert len(requests) == 1


@pytest.mark.parametrize("result", [
    dict(kind=["denied"], code="RUN_CLOSED", provider_attempted=False),
    dict(kind="denied", code=["RUN_CLOSED"], provider_attempted=False),
])
def test_non_scalar_native_discriminants_are_typed_rejections(tmp_path, result):
    def respond(conn, request):
        conn.sendall(framed(request, result))
    with server(tmp_path, respond) as (path, requests):
        with pytest.raises(client.DaemonGovernanceError) as caught:
            client.NativeGovernanceClient(path).attempt_readback(RUN, "intent:fixture")
        assert caught.value.code == "MALFORMED"
    assert len(requests) == 1


@pytest.mark.parametrize('terminal', [None,'not-a-native-terminal-state','succeeded'])
def test_partial_settlement_acknowledgment_is_rejected(monkeypatch,terminal):
    report=dict(schema='recursive-agent.normal-chat-executor-report/v2',state='not_sent',duration_ms=0,response=None,usage=None)
    result=dict(kind='normal_chat_attempt_settled',settlement={'report':report},terminal_state=terminal,
        child_chain_head='b'*64,parent_chain_head='c'*64)
    rpc=client.NativeGovernanceClient('/unused/native.sock')
    monkeypatch.setattr(rpc,'_rpc',lambda *args,**kwargs:result)
    with pytest.raises(client.DaemonGovernanceError):
        rpc.attempt_settle(RUN,'intent:fixture','a'*64,report)
