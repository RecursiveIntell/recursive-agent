"""Thin client for the recursive-agent daemon over authenticated native IPC.

Every field returned to the plugin comes from the runtime's framed response —
this module never synthesizes evidence. If the socket is absent, the version
probe fails, or a response is malformed, the client raises a transport/error
boundary exception and the tool reports ``unavailable``. If the daemon answers
with terminal failure evidence, ``DaemonRunFailure`` preserves those facts so
the tool does not mislabel a real failed run as unavailable.
"""

from __future__ import annotations

import base64
import json
import socket
import struct

SCHEMA = "recursive-agent.ipc/request/v1"
PROTOCOL_VERSION = 1
MAX_OPERATION_INPUT_BYTES = 1024 * 1024
MAX_FRAME_PAYLOAD_BYTES = ((MAX_OPERATION_INPUT_BYTES + 2) // 3) * 4 + (64 * 1024)


class DaemonClientError(Exception):
    """Any failure to reach, authenticate, or parse the daemon response."""


class DaemonRunFailure(DaemonClientError):
    """A daemon-confirmed terminal run or strict-verification failure.

    Transport failures remain ``DaemonClientError`` and are reported as
    unavailable by the plugin. This subtype is different: the daemon answered
    and supplied authoritative terminal/verification facts, so callers must
    not collapse it into an availability claim.
    """

    def __init__(
        self,
        *,
        code: str,
        message: str,
        run_id: str,
        run_dir: str,
        status: dict,
        verification: dict,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.run_id = run_id
        self.run_dir = run_dir
        self.status = status
        self.verification = verification


def _frame(payload: bytes) -> bytes:
    _frame_len_check(len(payload))
    return struct.pack(">I", len(payload)) + payload


def _frame_len_check(length: int) -> None:
    """Reject an oversized frame length before any body is read."""
    if length > MAX_FRAME_PAYLOAD_BYTES:
        raise DaemonClientError(f"oversized frame: {length}")


def _read_frame(conn: socket.socket) -> dict:
    header = b""
    while len(header) < 4:
        chunk = conn.recv(4 - len(header))
        if not chunk:
            raise DaemonClientError("incomplete frame header")
        header += chunk
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
            response = _request(conn, "plugin-ping-1", {"kind": "ping"})
            return (
                response.get("pong") is True
                and response.get("protocol_version") == PROTOCOL_VERSION
                and response.get("schema") == SCHEMA
            )
        finally:
            conn.close()
    except (OSError, ConnectionError, DaemonClientError):
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


def submit_provider_egress_v3(socket_path: str, envelope: dict) -> dict:
    """Submit one closed native V3 provider-egress envelope.

    The distinct request kind prevents a V3 operation from being parsed or
    dispatched through the legacy V1 operation family.
    """
    try:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.settimeout(5.0)
            conn.connect(socket_path)
            return _request(
                conn,
                "plugin-submit-provider-egress-v3-1",
                {"kind": "submit_provider_egress_v3", "operation": envelope},
            )
        finally:
            conn.close()
    except (OSError, ConnectionError) as error:
        raise DaemonClientError(f"cannot reach daemon: {error}") from error


def _raw_request(socket_path: str, kind: str, raw: bytes) -> dict:
    if len(raw) > MAX_OPERATION_INPUT_BYTES:
        raise DaemonClientError("operation exceeds byte limit")
    request_id = "plugin-" + kind + "-1"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(5.0)
            conn.connect(socket_path)
            response = _request(conn, request_id, {
                "kind": kind,
                "operation_json_b64": base64.b64encode(raw).decode("ascii"),
            })
    except (OSError, ConnectionError) as error:
        raise DaemonClientError(f"cannot reach daemon: {error}") from error
    if response.get("request_id") != request_id:
        raise DaemonClientError("native response request id mismatch")
    if isinstance(response.get("error"), dict):
        raise DaemonClientError("native operation denied: " + str(response["error"].get("message", "runtime error")))
    return response


def submit_native_raw(socket_path: str, raw: bytes) -> dict:
    return _raw_request(socket_path, "submit_native_raw", raw)


def read_recorded_native_raw(socket_path: str, raw: bytes) -> dict:
    response = _raw_request(socket_path, "read_recorded_provider_output_native_raw", raw)
    output = response.get("output")
    if (not isinstance(output, dict) or set(output) != {"model", "text"}
            or not isinstance(output["model"], str) or not output["model"]
            or not isinstance(output["text"], str)):
        raise DaemonClientError("recorded output response malformed")
    return output


def read_recorded_provider_output_v3(socket_path: str, envelope: dict) -> dict:
    """Consume owner-verified V3 output by exact sealed operation, never a path.

    The daemon rechecks current policy and pins the recorded evidence root
    while reading. Its runtime errors are not transport success.
    """
    request_id = "plugin-read-recorded-provider-v3-1"
    try:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.settimeout(5.0)
            conn.connect(socket_path)
            response = _request(conn, request_id, {
                "kind": "read_recorded_provider_output_v3", "operation": envelope,
            })
        finally:
            conn.close()
    except (OSError, ConnectionError) as error:
        raise DaemonClientError(f"cannot reach daemon: {error}") from error
    if response.get("request_id") != request_id:
        raise DaemonClientError("recorded output response request id mismatch")
    if isinstance(response.get("error"), dict):
        raise DaemonClientError(f"recorded output denied: {response['error'].get('message', 'runtime error')}")
    output = response.get("output")
    if (not isinstance(output, dict) or set(output) != {"model", "text"}
            or not isinstance(output["model"], str) or not output["model"]
            or not isinstance(output["text"], str)):
        raise DaemonClientError("recorded output response malformed")
    return output


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


def cancel_run(socket_path: str, run_id: str) -> dict:
    """Request cancellation; the daemon remains the sole authority."""
    try:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.settimeout(5.0)
            conn.connect(socket_path)
            return _request(conn, "plugin-cancel-1", {"kind": "cancel", "run_id": run_id})
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
    if envelope.get("schema") == "recursive-agent.operation/v3":
        submitted = submit_provider_egress_v3(socket_path, envelope)
    else:
        submitted = submit_envelope(socket_path, envelope)
    return _follow_submission(socket_path, submitted, envelope=envelope)


def submit_and_status_raw(socket_path: str, raw: bytes) -> dict:
    """Only the native owner may parse or select the operation family."""
    submitted = submit_native_raw(socket_path, raw)
    if submitted.get("operation_family") not in ("v1", "provider_egress_v3"):
        raise DaemonClientError("native response missing operation family")
    return _follow_submission(socket_path, submitted, raw=raw)


def _follow_submission(socket_path: str, submitted: dict, *, envelope=None, raw=None) -> dict:
    run_id = str(submitted.get("run_id", ""))
    run_dir = submitted.get("run_dir")
    if not run_id:
        raise DaemonClientError("submit did not return a run id")
    if not isinstance(run_dir, str) or not run_dir:
        raise DaemonClientError("submit did not return a run directory")
    status = status_of_run(socket_path, run_id)
    status_payload = status.get("status")
    if not isinstance(status_payload, dict):
        raise DaemonClientError("status response missing status object")
    state = status_payload.get("state", "unknown")
    if state != "terminal":
        raise DaemonClientError(f"daemon did not report terminal state: {state}")
    verification_response = verify_run(socket_path, run_id)
    if verification_response.get("run_id") != run_id:
        raise DaemonClientError("verification response run id mismatch")
    response_error = verification_response.get("error")
    if isinstance(response_error, dict):
        message = response_error.get("message")
        if not isinstance(message, str) or not message:
            message = "daemon verification request failed"
        raise DaemonRunFailure(
            code="strict_verification_error",
            message=message,
            run_id=run_id,
            run_dir=run_dir,
            status=status,
            verification=verification_response,
        )
    verification = verification_response.get("verification")
    if not isinstance(verification, dict):
        raise DaemonClientError("verification response missing verification object")
    if verification.get("ok") is not True or verification.get("current_strict_success") is not True:
        terminal_state = status_payload.get("terminal_state")
        code = (
            "terminal_run_failed"
            if terminal_state not in (None, "succeeded")
            else "strict_verification_failed"
        )
        raise DaemonRunFailure(
            code=code,
            message="daemon terminal evidence did not satisfy strict success",
            run_id=run_id,
            run_dir=run_dir,
            status=status,
            verification=verification_response,
        )
    if not isinstance(verification.get("length"), int) or verification["length"] < 1:
        raise DaemonClientError("verification response has invalid chain length")
    if not isinstance(verification.get("final_head"), str) or not verification["final_head"]:
        raise DaemonClientError("verification response missing final chain head")
    result = {
        "state": state,
        "run_id": run_id,
        "run_dir": run_dir,
        "verification": verification,
    }
    is_v3 = (submitted.get("operation_family") == "provider_egress_v3") if raw is not None else (
        envelope is not None and envelope.get("schema") == "recursive-agent.operation/v3"
    )
    if is_v3:
        try:
            if raw is not None:
                result["recorded_output"] = read_recorded_native_raw(socket_path, raw)
            elif envelope is not None:
                result["recorded_output"] = read_recorded_provider_output_v3(socket_path, envelope)
        except DaemonClientError as error:
            raise DaemonRunFailure(
                code="recorded_output_unavailable",
                message=str(error),
                run_id=run_id,
                run_dir=run_dir,
                status=status,
                verification=verification_response,
            ) from error
    if raw is not None:
        result["operation_family"] = submitted["operation_family"]
    return result
