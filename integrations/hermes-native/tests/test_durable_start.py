"""Task 3.2 RED: durable-start plugin polling and ambiguity handling.

Contract (from the audit closure plan, Task 3.2):
- The plugin uses the durable start kind, not the blocking submit.
- A status that is still ``active`` is polled with bounded backoff until
  terminal. A single poll is not sufficient.
- Only after terminal status is strict verification called, and only then is
  the recorded output consumed.
- A transport loss AFTER durable submission returns an explicit pending result
  that carries the run id. It must never resubmit and never report failure.
- A transport loss BEFORE a durable submission is ordinary unavailability.

These tests drive the real ``client`` module against an in-process fake daemon
speaking the framed protocol over a Unix socket. They fail until the client
exposes ``start_and_follow`` with that contract.
"""

import importlib.util
import json
import os
import socket
import struct
import sys
import threading

PLUGIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PLUGIN_DIR)
_SPEC = importlib.util.spec_from_file_location(
    "hermes_native_client", os.path.join(PLUGIN_DIR, "client.py")
)
assert _SPEC is not None and _SPEC.loader is not None
client = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(client)

RUN_ID = "v1:recursive-agent/run/v1:det:test-run"
RUN_DIR = "/tmp/fake-run"


def _read_frame(conn):
    header = b""
    while len(header) < 4:
        chunk = conn.recv(4 - len(header))
        if not chunk:
            return None
        header += chunk
    (length,) = struct.unpack(">I", header)
    body = b""
    while len(body) < length:
        chunk = conn.recv(length - len(body))
        if not chunk:
            return None
        body += chunk
    return json.loads(body.decode("utf-8"))


def _write_frame(conn, payload):
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    conn.sendall(struct.pack(">I", len(data)) + data)


class FakeDaemon:
    """Answers each request from a scripted list; records every request kind."""

    def __init__(self, socket_path, script):
        self.socket_path = socket_path
        self.script = list(script)
        self.kinds = []
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(socket_path)
        self.server.listen(8)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            with conn:
                frame = _read_frame(conn)
                if frame is None:
                    continue
                kind = frame["request"]["kind"]
                self.kinds.append(kind)
                action = self.script.pop(0) if self.script else {"reply": None}
                if action.get("drop"):
                    # Accept the request, then close without replying.
                    continue
                reply = dict(action["reply"])
                reply.setdefault("request_id", frame["request_id"])
                _write_frame(conn, reply)

    def close(self):
        self.server.close()


def _started_reply():
    return {
        "request_id": "x",
        "started": True,
        "run_id": RUN_ID,
        "run_dir": RUN_DIR,
        "operation_family": "provider_egress_v3",
    }


def _status(state, terminal_state=None):
    body = {"state": state}
    if terminal_state is not None:
        body["terminal_state"] = terminal_state
    return {"status": body}


def _verified():
    return {
        "verification": {
            "ok": True,
            "current_strict_success": True,
            "length": 3,
            "final_head": "blake3:abc",
        },
        "run_id": RUN_ID,
    }


def _recorded():
    return {"output": {"model": "fixture-model", "text": "ok"}}


def _envelope():
    return {"schema": "recursive-agent.operation/v3"}


def test_durable_start_polls_active_until_terminal_then_verifies(tmp_path):
    sock = str(tmp_path / "d.sock")
    daemon = FakeDaemon(
        sock,
        [
            {"reply": _started_reply()},
            {"reply": _status("active")},
            {"reply": _status("active")},
            {"reply": _status("terminal", "succeeded")},
            {"reply": _verified()},
            {"reply": _recorded()},
        ],
    )
    try:
        result = client.start_and_follow(sock, _envelope(), poll_interval=0.01, deadline=5.0)
    finally:
        daemon.close()
    assert result["state"] == "terminal"
    assert result["run_id"] == RUN_ID
    # Exactly one durable start; status polled until terminal; verify, then read.
    assert daemon.kinds.count("start_provider_egress_v3") == 1
    assert daemon.kinds.count("status") >= 3
    assert daemon.kinds.index("verify") > daemon.kinds.index("status")
    assert daemon.kinds[-1] == "read_recorded_provider_output_v3"


def test_transport_loss_after_durable_start_is_pending_not_resubmitted(tmp_path):
    sock = str(tmp_path / "d.sock")
    # The start succeeds durably; the next status poll is dropped mid-flight.
    daemon = FakeDaemon(
        sock,
        [
            {"reply": _started_reply()},
            {"drop": True},
        ],
    )
    try:
        result = client.start_and_follow(sock, _envelope(), poll_interval=0.01, deadline=0.2)
    finally:
        daemon.close()
    assert result["state"] == "pending"
    assert result["run_id"] == RUN_ID
    assert result["resumable"] is True
    # Never resubmitted: a single durable start was ever sent.
    assert daemon.kinds.count("start_provider_egress_v3") == 1


def test_unreachable_before_durable_start_is_unavailable_not_pending(tmp_path):
    sock = str(tmp_path / "missing.sock")  # no daemon listening
    try:
        client.start_and_follow(sock, _envelope(), poll_interval=0.01, deadline=0.2)
    except client.DaemonClientError:
        return
    raise AssertionError("no durable start happened, so this must be unavailable")
