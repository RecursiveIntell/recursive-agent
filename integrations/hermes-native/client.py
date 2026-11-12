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


class DaemonSubmissionAmbiguous(DaemonClientError):
    """A start may have reached the owner but no correlated handle was read.

    No run identity or durable acceptance is invented. Callers must reconcile
    with the native owner; automatically retrying this submission is forbidden.
    """


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


def _raw_request(socket_path: str, kind: str, raw: bytes, *, ambiguous_start=False) -> dict:
    if len(raw) > MAX_OPERATION_INPUT_BYTES:
        raise DaemonClientError("operation exceeds byte limit")
    request_id = "plugin-" + kind + "-1"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(5.0)
            conn.connect(socket_path)
            try:
                response = _request(conn, request_id, {
                    "kind": kind,
                    "operation_json_b64": base64.b64encode(raw).decode("ascii"),
                })
            except (OSError, ConnectionError, DaemonClientError) as error:
                if ambiguous_start:
                    raise DaemonSubmissionAmbiguous("start acknowledgement unavailable") from error
                raise
    except (OSError, ConnectionError) as error:
        raise DaemonClientError(f"cannot reach daemon: {error}") from error
    if response.get("request_id") != request_id:
        error_type = DaemonSubmissionAmbiguous if ambiguous_start else DaemonClientError
        raise error_type("native response request id mismatch")
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


def start_provider_egress_v3_durable(socket_path: str, envelope: dict) -> dict:
    """Durably start one V3 operation; returns once the daemon accepts it.

    Uses the additive ``start_provider_egress_v3`` kind (Task 3.1). The provider
    may still be in flight when this returns. A transport failure here is
    ordinary unavailability because no durable start is known to have happened.
    """
    try:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.settimeout(5.0)
            conn.connect(socket_path)
            return _request(
                conn,
                "plugin-start-provider-egress-v3-1",
                {"kind": "start_provider_egress_v3", "operation": envelope},
            )
        finally:
            conn.close()
    except (OSError, ConnectionError) as error:
        raise DaemonClientError(f"cannot reach daemon: {error}") from error


def start_and_follow(
    socket_path: str,
    envelope: dict,
    *,
    poll_interval: float = 0.5,
    deadline: float = 600.0,
) -> dict:
    """Durably start a V3 run, then poll status with bounded backoff to terminal.

    Contract (Task 3.2):
    - One durable start; it is never resubmitted.
    - Poll ``status`` with bounded exponential backoff until terminal, or until
      the monotonic ``deadline`` is reached.
    - Only after terminal status is strict verification requested, and only
      then is the recorded output consumed.
    - A transport loss AFTER the durable start returns an explicit ``pending``
      result that carries the run id and ``resumable=True``. It is not an error
      and must not trigger a resubmission.
    - A transport loss BEFORE the durable start raises ``DaemonClientError``
      (ordinary unavailability).
    """
    _validate_poll_bounds(poll_interval, deadline)
    started = start_provider_egress_v3_durable(socket_path, envelope)
    return _poll_started(socket_path, started, poll_interval=poll_interval,
                         deadline=deadline, envelope=envelope)


def start_and_follow_raw(
    socket_path: str, raw: bytes, *, poll_interval: float = 0.5, deadline: float = 600.0,
) -> dict:
    """Preserve original bytes; only the native owner chooses V1 or V3.

    V1 remains synchronous. V3 uses the existing owner start/poll lifecycle.
    No acknowledgement means ambiguity, not evidence of a failed submission.
    """
    _validate_poll_bounds(poll_interval, deadline)
    started = _raw_request(socket_path, "start_native_raw", raw, ambiguous_start=True)
    if (started.get("started") is not True
            or started.get("operation_family") not in ("v1", "provider_egress_v3")):
        raise DaemonSubmissionAmbiguous("start acknowledgement malformed")
    return _poll_started(socket_path, started, poll_interval=poll_interval,
                         deadline=deadline, raw=raw)


def _validate_poll_bounds(poll_interval, deadline):
    import math

    if (isinstance(poll_interval, bool) or isinstance(deadline, bool)
            or not isinstance(poll_interval, (int, float))
            or not isinstance(deadline, (int, float))
            or not math.isfinite(poll_interval) or not math.isfinite(deadline)
            or poll_interval <= 0 or deadline < 0):
        raise DaemonClientError("invalid polling bounds")


def _poll_started(socket_path, started, *, poll_interval, deadline, envelope=None, raw=None):
    import time

    _validate_poll_bounds(poll_interval, deadline)
    run_id = started.get("run_id")
    run_dir = started.get("run_dir")
    if not isinstance(run_id, str) or not run_id or not isinstance(run_dir, str) or not run_dir:
        raise DaemonSubmissionAmbiguous("durable start did not return run id and run directory")
    family = started.get("operation_family", "provider_egress_v3")

    def pending(reason):
        return {"state": "pending", "run_id": run_id, "run_dir": run_dir,
                "resumable": True, "reason": reason, "operation_family": family}

    end = time.monotonic() + deadline
    delay = poll_interval
    while True:
        try:
            status = status_of_run(socket_path, run_id)
        except DaemonClientError:
            # The admitted start may still be running. Never resubmit it.
            return pending("transport_lost_after_durable_start")
        if raw is not None:
            if status.get("request_id") != "plugin-status-1":
                raise DaemonClientError("status response request id mismatch")
            if status.get("run_id") != run_id:
                raise DaemonClientError("status response run id mismatch")
        if isinstance(status.get("error"), dict):
            raise DaemonClientError("native status denied")
        status_payload = status.get("status")
        if not isinstance(status_payload, dict):
            raise DaemonClientError("status response missing status object")
        state = status_payload.get("state", "unknown")
        if state == "terminal":
            break
        if state not in ("active", "interrupted_non_resumable"):
            raise DaemonClientError(f"unexpected status state: {state}")
        if state == "interrupted_non_resumable":
            raise DaemonRunFailure(
                code="interrupted_non_resumable",
                message="durable run was interrupted by a process exit and is not resumable",
                run_id=run_id,
                run_dir=run_dir,
                status=status,
                verification={},
            )
        if state != "active" or family != "provider_egress_v3":
            raise DaemonClientError(f"unexpected nonterminal state: {state}")
        if time.monotonic() >= end:
            return pending("deadline_reached_while_active")
        time.sleep(min(delay, max(0.0, end - time.monotonic())))
        delay = min(delay * 2, 5.0)

    # Terminal: only now ask the daemon for strict verification and output.
    # The status just read is reused, not re-requested.
    return _finish_terminal(
        socket_path,
        run_id=run_id,
        run_dir=run_dir,
        status=status,
        submitted={"run_id": run_id, "run_dir": run_dir, "operation_family": family},
        envelope=envelope,
        raw=raw,
        strict_correlation=raw is not None,
    )


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
    return _finish_terminal(
        socket_path,
        run_id=run_id,
        run_dir=run_dir,
        status=status,
        submitted=submitted,
        envelope=envelope,
        raw=raw,
    )


def _finish_terminal(socket_path, *, run_id, run_dir, status, submitted, envelope=None, raw=None, strict_correlation=False):
    """Strict verification and recorded-output read for an already-terminal run.

    Split out so a caller that has already read terminal status (the durable
    poll loop) does not read status a second time.
    """
    status_payload = status.get("status")
    state = status_payload.get("state", "unknown") if isinstance(status_payload, dict) else "unknown"
    verification_response = verify_run(socket_path, run_id)
    if strict_correlation and verification_response.get("request_id") != "plugin-verify-1":
        raise DaemonClientError("verification response request id mismatch")
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
