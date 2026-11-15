"""Closed V2 native-governance RPCs; no retry, grant enrollment or send replay.

Returned records are daemon-reported evidence. Only a fresh admitted response
for the exact request may be consumed by the separate physical-send governor.
Historical status and lost ACKs never recreate that response.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import math
import os
import re
import secrets
import socket
import stat
import struct
import time

from .client import DaemonClientError, _frame, _frame_len_check

_REQUEST_SCHEMA = "recursive-agent.ipc/request/v2"
_RESPONSE_SCHEMA = "recursive-agent.ipc/response/v2"
_RUN = re.compile(r"v1:recursive-agent/run/v1:det:[0-9a-f]{64}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_POLICY_DENIALS = frozenset({
    "GRANT_MISSING", "GRANT_EXPIRED", "ROUTE_NOT_ALLOWED",
    "CAP_EXHAUSTED_ATTEMPTS", "CAP_EXHAUSTED_OUTPUT_TOKENS",
    "CAP_EXHAUSTED_WALL_TIME_MS", "CAP_EXHAUSTED_REQUEST_BYTES",
    "RUN_CLOSED", "INTENT_CONFLICT", "MATERIALIZATION_UNAVAILABLE",
    "SOURCE_REVISION_UNAVAILABLE", "MALFORMED", "DAEMON_OVERLOADED",
})


class DaemonGovernanceError(DaemonClientError):
    def __init__(self, code: str, message: str = "native governance RPC refused"):
        super().__init__(message)
        self.code = code


def _malformed(message="malformed native governance response"):
    return DaemonGovernanceError("MALFORMED", message)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _malformed("duplicate native response member")
        result[key] = value
    return result


def _closed(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise _malformed("unknown or missing native response member")


def _ref(value):
    if not isinstance(value, str):
        raise _malformed("invalid native correlation reference")
    try:
        length = len(value.encode("utf-8"))
    except UnicodeError as error:
        raise _malformed("invalid native correlation reference") from error
    if not value.strip() or length > 4096 or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value):
        raise _malformed("invalid native correlation reference")


def _run(value):
    if not isinstance(value, str) or _RUN.fullmatch(value) is None:
        raise _malformed("invalid native session identifier")


def _hex(value):
    if not isinstance(value, str) or _HEX.fullmatch(value) is None:
        raise _malformed("invalid native content digest")


def _timestamp(value):
    if not isinstance(value, str):
        raise _malformed("invalid native lease timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise _malformed("invalid native lease timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise _malformed("native lease timestamp is not UTC")
    return parsed


def _same_json_types(value, expected):
    """Exact JSON correlation: bool/int/float equality is not typed equality."""
    if type(value) is not type(expected):
        return False
    if type(value) is dict:
        return set(value) == set(expected) and all(_same_json_types(value[k], expected[k]) for k in value)
    if type(value) is list:
        return len(value) == len(expected) and all(_same_json_types(a, b) for a, b in zip(value, expected))
    return value == expected


def _validate_executor_report(value):
    """Closed report ingress, including the ACK echo, with no coercion/defaults."""
    _closed(value, {'schema','state','duration_ms','response','usage'})
    states = {'succeeded','failed','cancelled','interrupted','timed_out','not_sent','outcome_unknown'}
    if (value['schema'] != 'recursive-agent.normal-chat-executor-report/v2'
            or type(value['state']) is not str or value['state'] not in states
            or type(value['duration_ms']) is not int or not 0 <= value['duration_ms'] <= 9007199254740991):
        raise _malformed('invalid typed executor report')
    response = value['response']
    if response is not None:
        _closed(response, {'projection_schema','digest','byte_length','complete'})
        if (type(response['projection_schema']) is not str
                or response['projection_schema'] not in {'ares-response-json-sorted-v1','ares.transport-response-body/v1'}
                or type(response['byte_length']) is not int or not 0 <= response['byte_length'] <= 9007199254740991
                or type(response['complete']) is not bool or type(response['digest']) is not str
                or not response['digest'].startswith('sha256:')):
            raise _malformed('invalid typed response projection')
        _hex(response['digest'][7:])
        if response['byte_length'] == 0 and response['projection_schema'] == 'ares-response-json-sorted-v1':
            raise _malformed('empty sorted JSON response is invalid')
    usage = value['usage']
    if usage is not None:
        _closed(usage, {'source','input_tokens','output_tokens'})
        if usage['source'] != 'provider_reported' or any(type(usage[k]) is not int or not 0 <= usage[k] <= 4294967295 for k in ('input_tokens','output_tokens')):
            raise _malformed('invalid typed provider-reported usage')
    if value['state'] == 'succeeded' and (response is None or response['complete'] is not True):
        raise _malformed('successful report lacks a complete response projection')
    if value['state'] == 'not_sent' and (value['duration_ms'] != 0 or response is not None or usage is not None):
        raise _malformed('not-sent report contains transport evidence')


def _validate_settlement_response(result, preflight_receipt_digest, report):
    """Closed, correlated ACK validation, not independent ledger verification."""
    _closed(result, {'kind','settlement','terminal_state','child_chain_head','parent_chain_head'})
    if result['kind'] != 'normal_chat_attempt_settled' or not isinstance(result['terminal_state'],str) or result['terminal_state'] not in {'succeeded','failed'}:
        raise _malformed('invalid native settlement terminal state')
    _hex(result['child_chain_head'])
    _hex(result['parent_chain_head'])
    settlement = result['settlement']
    _closed(settlement, {'schema','attempt_id','report','violations','outcome','settlement_digest'})
    _validate_executor_report(report)
    _validate_executor_report(settlement['report'])
    if settlement['schema'] != 'recursive-agent.normal-chat-settlement/v2' or not _same_json_types(settlement['report'], report):
        raise _malformed('settlement differs from exact report/schema')
    if not isinstance(settlement['attempt_id'],str) or re.fullmatch(r'v1:recursive-agent/normal-chat-attempt/v2:det:[0-9a-f]{64}',settlement['attempt_id']) is None:
        raise _malformed('invalid settlement attempt identity')
    _hex(settlement['settlement_digest'])
    violations = settlement['violations']
    if type(violations) is not list or any(not isinstance(v,str) for v in violations) or violations not in [[],['wall_time'],['output_tokens'],['wall_time','output_tokens']]:
        raise _malformed('invalid ordered settlement violations')
    outcome = settlement['outcome']
    _closed(outcome, {'permit_id','preflight_receipt_digest','reported','recorded_at','receipt_digest'})
    if not isinstance(outcome['permit_id'],str) or re.fullmatch(r'v1:recursive-agent/permit/v1:det:[0-9a-f]{64}',outcome['permit_id']) is None:
        raise _malformed('invalid settlement permit identity')
    _hex(outcome['preflight_receipt_digest'])
    _hex(outcome['receipt_digest'])
    _timestamp(outcome['recorded_at'])
    if outcome['preflight_receipt_digest'] != preflight_receipt_digest:
        raise _malformed('settlement ACK is for another preflight')
    reported = outcome['reported']
    _closed(reported, {'state','duration_ms','error_type'})
    states = {'succeeded':('succeeded',None), 'failed':('failed','NORMAL_CHAT_FAILED'),
        'cancelled':('failed','NORMAL_CHAT_CANCELLED'), 'interrupted':('failed','NORMAL_CHAT_INTERRUPTED'),
        'timed_out':('failed','NORMAL_CHAT_TIMED_OUT'), 'not_sent':('failed','NORMAL_CHAT_NOT_SENT'),
        'outcome_unknown':('outcome_ambiguous','NORMAL_CHAT_OUTCOME_UNKNOWN')}
    if not isinstance(report['state'],str) or report['state'] not in states:
        raise _malformed('unknown original reported state')
    state, error = states[report['state']]
    if report['state'] != 'outcome_unknown' and violations:
        state, error = 'failed', 'NORMAL_CHAT_BOUND_EXCEEDED'
    if (reported['state'] != state or reported['error_type'] != error
            or type(reported['duration_ms']) is not int or reported['duration_ms'] != report['duration_ms']
            or result['terminal_state'] != ('succeeded' if state == 'succeeded' else 'failed')):
        raise _malformed('settlement ACK reported/terminal fields conflict')
    return result


class NativeGovernanceClient:
    """One authenticated request/response per connection, one total deadline."""
    def __init__(self, socket_path: str, *, timeout: float = 2.0):
        if not isinstance(socket_path, str) or not socket_path or "\0" in socket_path:
            raise _malformed("invalid native socket path")
        if isinstance(timeout, bool) or not isinstance(timeout, (float, int)) or not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise _malformed("invalid native RPC timeout")
        self.socket_path = socket_path
        self.timeout = float(timeout)

    @staticmethod
    def _remaining(conn, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DaemonGovernanceError("DAEMON_TIMEOUT")
        conn.settimeout(remaining)

    @classmethod
    def _read_exact(cls, conn, count, deadline):
        parts, remaining = [], count
        while remaining:
            cls._remaining(conn, deadline)
            chunk = conn.recv(remaining)
            if not chunk:
                raise _malformed("incomplete native response frame")
            parts.append(chunk)
            remaining -= len(chunk)
        return b"".join(parts)

    def _rpc(self, request, expected):
        deadline = time.monotonic() + self.timeout
        request_id = "native-governance-" + secrets.token_hex(12)
        try:
            payload = json.dumps(dict(schema=_REQUEST_SCHEMA, protocol_version=2,
                                      request_id=request_id, request=request),
                                 separators=(",", ":"), ensure_ascii=False,
                                 allow_nan=False).encode()
            frame = _frame(payload)
            metadata = os.lstat(self.socket_path)
            if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
                raise DaemonGovernanceError("DAEMON_UNREACHABLE", "native socket ownership/permissions refused")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                self._remaining(conn, deadline)
                conn.connect(self.socket_path)
                if not hasattr(socket, "SO_PEERCRED"):
                    raise DaemonGovernanceError("DAEMON_AUTHENTICATION_UNAVAILABLE")
                _, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
                if uid != os.getuid():
                    raise DaemonGovernanceError("DAEMON_UNREACHABLE", "native peer UID differs")
                offset = 0
                while offset < len(frame):
                    self._remaining(conn, deadline)
                    count = conn.send(frame[offset:])
                    if not count:
                        raise _malformed("incomplete native request write")
                    offset += count
                length = struct.unpack(">I", self._read_exact(conn, 4, deadline))[0]
                _frame_len_check(length)
                body = self._read_exact(conn, length, deadline)
                value = json.loads(body.decode(), object_pairs_hook=_pairs,
                                   parse_constant=lambda _: (_ for _ in ()).throw(_malformed()))
                self._remaining(conn, deadline)
        except DaemonGovernanceError:
            raise
        except (TimeoutError, socket.timeout) as error:
            raise DaemonGovernanceError("DAEMON_TIMEOUT") from error
        except OSError as error:
            raise DaemonGovernanceError("DAEMON_UNREACHABLE") from error
        except (ValueError, TypeError, UnicodeError, DaemonClientError) as error:
            raise _malformed() from error
        _closed(value, {"schema", "protocol_version", "request_id", "result"})
        if value["schema"] != _RESPONSE_SCHEMA or type(value["protocol_version"]) is not int or value["protocol_version"] != 2 or value["request_id"] != request_id:
            raise _malformed("native response version/correlation differs")
        result = value["result"]
        if type(result) is not dict:
            raise _malformed()
        if not isinstance(result.get("kind"), str):
            raise _malformed("invalid native result discriminator")
        if result.get("kind") == "denied":
            _closed(result, {"kind", "code", "provider_attempted"})
            if not isinstance(result["code"], str) or result["code"] not in _POLICY_DENIALS or result["provider_attempted"] is not False:
                raise _malformed()
            raise DaemonGovernanceError(result["code"])
        if result.get("kind") not in expected:
            raise _malformed("unexpected native result kind")
        return result

    def capabilities(self):
        """Read parser/startup metadata only; this never authorizes a send."""
        result = self._rpc(dict(kind="normal_chat_capabilities"), {"normal_chat_capabilities"})
        _closed(result, {"kind", "grant_loaded", "grant", "response_projection_schemas"})
        if type(result["grant_loaded"]) is not bool or result["grant_loaded"] != (result["grant"] is not None):
            raise _malformed()
        if result["grant"] is not None and type(result["grant"]) is not dict:
            raise _malformed()
        schemas = result["response_projection_schemas"]
        known = {"ares-response-json-sorted-v1", "ares.transport-response-body/v1"}
        if type(schemas) is not list or not schemas or any(not isinstance(v, str) or v not in known for v in schemas):
            raise _malformed("unknown native response-projection capability")
        if len(set(schemas)) != len(schemas):
            raise _malformed("duplicate native projection capability")
        return result

    def session_open(self, conversation_ref, parent_session_run_id=None):
        _ref(conversation_ref)
        if parent_session_run_id is not None:
            _run(parent_session_run_id)
        result = self._rpc(dict(kind="normal_chat_session_open", conversation_ref=conversation_ref,
                                parent_session_run_id=parent_session_run_id), {"normal_chat_session_opened"})
        _closed(result, {"kind", "session_run_id", "session", "grant", "parent_chain_head"})
        _run(result["session_run_id"])
        _hex(result["parent_chain_head"])
        if type(result["session"]) is not dict or result["session"].get("conversation_ref") != conversation_ref or result["session"].get("parent_session_run_id") != parent_session_run_id or type(result["grant"]) is not dict:
            raise _malformed("opened session differs from exact correlation")
        return result

    def attempt_begin(self, session_run_id, call):
        _run(session_run_id)
        if type(call) is not dict:
            raise _malformed()
        result = self._rpc(dict(kind="normal_chat_attempt_begin", session_run_id=session_run_id,
                                call=call), {"normal_chat_attempt_admitted", "normal_chat_attempt_existing"})
        if result["kind"] == "normal_chat_attempt_existing":
            _closed(result, {"kind", "send_authorized", "attempt", "policy"})
            if result["send_authorized"] is not False:
                raise _malformed()
            raise DaemonGovernanceError("ADMISSION_NOT_FRESH", "historical consumption cannot authorize another send")
        _closed(result, {"kind", "send_authorized", "attempt", "permit_id", "preflight_receipt_digest",
                         "expires_at", "admitted_at", "parent_chain_head", "child_chain_head"})
        if result["send_authorized"] is not True:
            raise _malformed()
        attempt = result["attempt"]
        _closed(attempt, {"schema", "operation", "attempt_number", "provider_request_digest", "provider_request_bytes",
                          "dispatch_intent_ref", "session_run_id", "attempt_id"})
        if attempt["schema"] != "recursive-agent.normal-chat-attempt/v2" or attempt["session_run_id"] != session_run_id or type(attempt["attempt_number"]) is not int or attempt["attempt_number"] < 1:
            raise _malformed()
        for name in ("operation", "provider_request_digest", "provider_request_bytes", "dispatch_intent_ref"):
            if not _same_json_types(attempt[name], call.get(name)):
                raise _malformed("admitted attempt differs from exact original call")
        _hex(result["preflight_receipt_digest"])
        _hex(result["parent_chain_head"])
        _hex(result["child_chain_head"])
        if not isinstance(result["permit_id"], str) or re.fullmatch(r"v1:recursive-agent/permit/v1:det:[0-9a-f]{64}", result["permit_id"]) is None:
            raise _malformed()
        if not isinstance(attempt["attempt_id"], str) or re.fullmatch(r"v1:recursive-agent/normal-chat-attempt/v2:det:[0-9a-f]{64}", attempt["attempt_id"]) is None:
            raise _malformed()
        if _timestamp(result["expires_at"]) <= _timestamp(result["admitted_at"]) or _timestamp(result["expires_at"]) <= datetime.now(timezone.utc):
            raise DaemonGovernanceError("ADMISSION_EXPIRED")
        return result

    def attempt_settle(self, session_run_id, dispatch_intent_ref, preflight_receipt_digest, report):
        _run(session_run_id)
        _ref(dispatch_intent_ref)
        _hex(preflight_receipt_digest)
        result = self._rpc(dict(kind="normal_chat_attempt_settle", session_run_id=session_run_id,
                                dispatch_intent_ref=dispatch_intent_ref,
                                preflight_receipt_digest=preflight_receipt_digest, report=report), {"normal_chat_attempt_settled"})
        return _validate_settlement_response(result, preflight_receipt_digest, report)

    def attempt_readback(self, session_run_id, dispatch_intent_ref):
        _run(session_run_id)
        _ref(dispatch_intent_ref)
        result = self._rpc(dict(kind="normal_chat_attempt_readback", session_run_id=session_run_id,
                                dispatch_intent_ref=dispatch_intent_ref), {"normal_chat_attempt_readback"})
        _closed(result, {"kind", "send_authorized", "request", "policy", "recovery", "parent_chain_head", "child_chain_head"})
        if result["send_authorized"] is not False or type(result["request"]) is not dict or type(result["policy"]) is not dict:
            raise _malformed()
        _hex(result["parent_chain_head"])
        _hex(result["child_chain_head"])
        return result

    def run_close(self, session_run_id, reason):
        _run(session_run_id)
        if reason not in {"session_finalized", "session_reset", "ttl_expired"}:
            raise _malformed("invalid session close reason")
        result = self._rpc(dict(kind="normal_chat_run_close", session_run_id=session_run_id,
                                reason=reason), {"normal_chat_run_closed"})
        _closed(result, {"kind", "session_run_id", "terminal_state", "final_chain_digest", "normal_chat_status"})
        if result["session_run_id"] != session_run_id:
            raise _malformed()
        _hex(result["final_chain_digest"])
        return result
