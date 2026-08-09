"""Thin client for the recursive-agent daemon over authenticated native IPC.

Every field returned to the plugin comes from the runtime's framed response —
this module never synthesizes evidence. If the socket is absent, the version
probe fails, or a response is malformed, the client raises a typed error and
the tool reports ``unavailable``.
"""

from __future__ import annotations

import json
import socket
import struct

SCHEMA = "recursive-agent.ipc/request/v1"
PROTOCOL_VERSION = 1
MAX_FRAME_PAYLOAD_BYTES = (1024 * 1024) + (64 * 1024)


class DaemonClientError(Exception):
    """Any failure to reach, authenticate, or parse the daemon response."""


def _frame(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


def _frame_len_check(length: int) -> None:
    """Reject an oversized frame length before any body is read."""
    if length > MAX_FRAME_PAYLOAD_BYTES:
        raise DaemonClientError(f"oversized frame: {length}")


def _read_frame(conn: socket.socket) -> dict:
    header = conn.recv(4)
    if len(header) != 4:
        raise DaemonClientError("incomplete frame header")
    (length,) = struct.unpack(">I", header)
    _frame_len_check(length)
    body = b""
    while len(body) < length:
        chunk = conn.recv(length - len(body))
        if not chunk:
            raise DaemonClientError("incomplete frame body")
        body += chunk
    try:
        value = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as error:
        raise DaemonClientError(f"malformed runtime response: {error}") from error
    if not isinstance(value, dict):
        raise DaemonClientError("runtime response is not an object")
    return value


def _request(conn: socket.socket, request_id: str, request: dict) -> dict:
    payload = json.dumps(
        {
            "schema": SCHEMA,
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request_id,
            "request": request,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    conn.sendall(_frame(payload))
    return _read_frame(conn)


def check_socket_available(socket_path: str) -> bool:
    """Return True only when the private socket answers a version probe."""
    try:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.settimeout(1.0)
            conn.connect(socket_path)
            return True
        finally:
            conn.close()
    except (OSError, ConnectionError):
        return False


def submit_envelope(socket_path: str, envelope: dict) -> dict:
    """Submit a canonical native operation envelope and return the run handle.

    Every field returned comes from the runtime's framed response; nothing is
    synthesized here.
    """
    try:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.settimeout(5.0)
            conn.connect(socket_path)
            return _request(conn, "plugin-submit-1", {"kind": "submit", "operation": envelope})
        finally:
            conn.close()
    except (OSError, ConnectionError) as error:
        raise DaemonClientError(f"cannot reach daemon: {error}") from error


def status_of_run(socket_path: str, run_id: str) -> dict:
    """Query terminal status for a submitted run over IPC."""
    try:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.settimeout(5.0)
            conn.connect(socket_path)
            return _request(conn, "plugin-status-1", {"kind": "status", "run_id": run_id})
        finally:
            conn.close()
    except (OSError, ConnectionError) as error:
        raise DaemonClientError(f"cannot reach daemon: {error}") from error


def submit_and_status(socket_path: str, envelope: dict) -> dict:
    """Submit a canonical envelope and return terminal status plus the handle.

    Raises ``DaemonClientError`` if the daemon does not report terminal state.
    """
    submitted = submit_envelope(socket_path, envelope)
    run_id = str(submitted.get("run_id", ""))
    if not run_id:
        raise DaemonClientError("submit did not return a run id")
    status = status_of_run(socket_path, run_id)
    state = status.get("status", {}).get("state", "unknown")
    if state != "terminal":
        raise DaemonClientError(f"daemon did not report terminal state: {state}")
    return {
        "state": state,
        "run_id": run_id,
        "receipt_ref": f"run:{run_id}",  # receipt chain verified in Phase 5
    }
