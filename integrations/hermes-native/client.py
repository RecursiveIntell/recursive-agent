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


def verify_run(socket_path: str, run_id: str) -> dict:
    """Return daemon-computed strict verification for an authoritative run."""
    try:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.settimeout(5.0)
            conn.connect(socket_path)
            return _request(conn, "plugin-verify-1", {"kind": "verify", "run_id": run_id})
        finally:
            conn.close()
    except (OSError, ConnectionError) as error:
        raise DaemonClientError(f"cannot reach daemon: {error}") from error


def submit_and_status(socket_path: str, envelope: dict) -> dict:
    """Submit, observe terminal status, then require daemon strict verification.

    The returned verification mapping is copied from the daemon response after
    structural validation. This client never derives a receipt reference or a
    verification outcome from a run identifier.
    """
    submitted = submit_envelope(socket_path, envelope)
    run_id = str(submitted.get("run_id", ""))
    run_dir = submitted.get("run_dir")
    if not run_id:
        raise DaemonClientError("submit did not return a run id")
    if not isinstance(run_dir, str) or not run_dir:
        raise DaemonClientError("submit did not return a run directory")
    status = status_of_run(socket_path, run_id)
    state = status.get("status", {}).get("state", "unknown")
    if state != "terminal":
        raise DaemonClientError(f"daemon did not report terminal state: {state}")
    verification_response = verify_run(socket_path, run_id)
    if verification_response.get("run_id") != run_id:
        raise DaemonClientError("verification response run id mismatch")
    verification = verification_response.get("verification")
    if not isinstance(verification, dict):
        raise DaemonClientError("verification response missing verification object")
    if verification.get("ok") is not True or verification.get("current_strict_success") is not True:
        raise DaemonClientError("daemon strict verification did not succeed")
    if not isinstance(verification.get("length"), int) or verification["length"] < 1:
        raise DaemonClientError("verification response has invalid chain length")
    if not isinstance(verification.get("final_head"), str) or not verification["final_head"]:
        raise DaemonClientError("verification response missing final chain head")
    return {
        "state": state,
        "run_id": run_id,
        "run_dir": run_dir,
        "verification": verification,
    }
