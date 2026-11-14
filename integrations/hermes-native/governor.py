"""Physical-send witness/permit adapter. Native policy remains the authority.

No prompt/body/response retention, grant enrollment, retry, replay or plugin-owned
budget/status store. Session mappings are rebuildable correlation only.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import math
import os
from pathlib import Path
import re
import stat
import threading
import time

from hermes_constants import get_hermes_home
from hermes_cli.middleware import EgressDispatchDenied, EgressOutcomeUnrecorded
from .governed_client import NativeGovernanceClient, _validate_settlement_response

_LOG = logging.getLogger(__name__)
_HEX = re.compile(r'[0-9a-f]{64}\Z')
_RECOVERY = 'Check the configured per-home daemon and grant, or explicitly select governance_mode observe.'


def _deny(code):
    raise EgressDispatchDenied(code, _RECOVERY)


def _positive(value):
    return type(value) is int and 0 < value <= 9223372036854775807


def _diagnostic(code, session_id=None, call_class=None):
    """Private, digest-free diagnostic; never persist arbitrary exception text."""
    import fcntl
    code = code if isinstance(code, str) and re.fullmatch(r'[A-Z][A-Z0-9_]{0,95}', code) else 'GOVERNANCE_ERROR'
    root = Path(get_hermes_home()) / 'recursive-agent'
    root.mkdir(mode=0o700, exist_ok=True)
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise PermissionError('unsafe governance diagnostic directory')
    directory = os.open(root, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open('unwitnessed.ndjson', os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     0o600, dir_fd=directory)
        try:
            value = os.fstat(fd)
            if not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid() or value.st_nlink != 1 or value.st_mode & 0o777 != 0o600:
                raise PermissionError('unsafe governance diagnostic file')
            event = dict(ts=datetime.now(timezone.utc).isoformat(), code=code,
                         session_id=session_id, call_class=call_class)
            data = (json.dumps(event, separators=(',', ':'), ensure_ascii=True) + '\n').encode()
            if len(data) > 16384:
                raise ValueError('diagnostic exceeds metadata bound')
            fcntl.flock(fd, fcntl.LOCK_EX)
            view = memoryview(data)
            while view:
                count = os.write(fd, view)
                if not count:
                    raise OSError('incomplete diagnostic append')
                view = view[count:]
            os.fsync(fd)
            os.fsync(directory)
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def _unwitnessed(code, session_id=None, call_class=None):
    try:
        _diagnostic(code, session_id, call_class)
    except Exception:
        # Observe mode cannot block egress even when its local diagnostic disk
        # fails. This explicit log is degradation, never a successful receipt.
        _LOG.error('recursive-agent unwitnessed diagnostic persistence failed')


def _materialization(payload):
    from ares_runtime.managed_calls import ManagedCallContextV2
    from ares_runtime.collaboration import digest
    record = payload.get('materialization')
    if type(record) is not dict or set(record) != {'schema','context','materialization_digest','materialization_ref'}:
        _deny('MATERIALIZATION_UNAVAILABLE')
    context = ManagedCallContextV2.parse(record['context']).to_dict()
    expected = digest({'schema': record['schema'], 'context': context})
    if (record['schema'] != 'ares.dispatch-materialization/v1' or record['materialization_digest'] != expected
            or record['materialization_ref'] != 'ares-materialization:' + expected.removeprefix('sha256:')):
        _deny('MATERIALIZATION_UNAVAILABLE')
    return record, context


def _conversation(context):
    # Injective projection of actual owner fields, not a fabricated no-session id.
    return 'ares-session:' + json.dumps([context['session_ref'], context['session_generation']], ensure_ascii=True, separators=(',', ':'))


class _Ticket:
    def __init__(self, governor, client, opened, admitted, call):
        self.owner, self.client, self.opened = governor, client, opened
        self.admitted, self.call = admitted, call
        self.started = time.monotonic()
        self.lock = threading.Lock()
        self.report = None
        self.confirmed = False
        self.failed = False
        budget = call['operation']['budget']
        self.transport_lease = None
        if governor.mode == 'enforce':
            expiry = datetime.fromisoformat(admitted['expires_at'])
            self.transport_lease = dict(schema_version='ares.transport-lease/v1',
                expires_at_unix_ms=int(expiry.timestamp() * 1000),
                send_timeout_ms=budget['max_wall_time_ms'], request_bytes_limit=budget['max_request_bytes'],
                output_tokens_limit=budget['output_reserve'])

    def _report(self, outcome, response):
        if outcome == 'denied_by_peer':
            return dict(schema='recursive-agent.normal-chat-executor-report/v2', state='not_sent',
                        duration_ms=0, response=None, usage=None)
        projected = None
        complete = False
        status = None
        duration = math.ceil((time.monotonic() - self.started) * 1000)
        if response is not None:
            fields = {'schema','digest_algorithm','response_digest','response_bytes','response_complete',
                      'http_status','duration_ms','evidence','replay'}
            if (type(response) is not dict or set(response) != fields or response['schema'] != 'ares.transport-response-body/v1'
                    or response['digest_algorithm'] != 'sha256' or response['evidence'] != 'executor_observed'
                    or response['replay'] != 'unavailable' or type(response['response_complete']) is not bool
                    or type(response['response_bytes']) is not int or response['response_bytes'] < 0
                    or type(response['duration_ms']) not in {int,float} or not math.isfinite(response['duration_ms'])
                    or response['duration_ms'] < 0):
                raise ValueError('unsupported transport response evidence')
            complete, status = response['response_complete'], response['http_status']
            if status is not None and (type(status) is not int or not 100 <= status <= 599):
                raise ValueError('invalid observed HTTP status')
            duration = math.ceil(response['duration_ms'])
            value = response['response_digest']
            if value is not None:
                if not isinstance(value, str) or not value.startswith('sha256:') or not _HEX.fullmatch(value[7:]):
                    raise ValueError('invalid response digest')
                projected = dict(projection_schema='ares.transport-response-body/v1', digest=value,
                                 byte_length=response['response_bytes'], complete=complete)
            elif response['response_bytes']:
                raise ValueError('missing observed response digest')
        state = 'outcome_unknown'
        if complete and projected is not None:
            state = 'succeeded' if outcome == 'ok' and status is not None and 200 <= status < 300 else 'failed'
        return dict(schema='recursive-agent.normal-chat-executor-report/v2', state=state,
                    duration_ms=duration, response=projected, usage=None)

    def settle(self, *, outcome, response=None, error=None):
        if outcome not in {'ok','provider_error','interrupted','discarded','abandoned','denied_by_peer'}:
            raise ValueError('unknown dispatch outcome')
        with self.lock:
            try:
                if self.failed:
                    raise ValueError('prior settlement remains unconfirmed')
                report = self._report(outcome, response)
                if self.report is not None:
                    if self.confirmed and self.report == report:
                        return
                    raise ValueError('conflicting or unconfirmed ticket settlement')
                self.report = report
                result = self.client.attempt_settle(self.opened['session_run_id'], self.call['dispatch_intent_ref'],
                    self.admitted['preflight_receipt_digest'], report)
                _validate_settlement_response(result, self.admitted['preflight_receipt_digest'], report)
                settlement = result['settlement']
                if (settlement['attempt_id'] != self.admitted['attempt']['attempt_id']
                        or settlement['outcome']['permit_id'] != self.admitted['permit_id']):
                    raise ValueError('terminal ACK differs from exact fresh attempt/permit')
                self.confirmed = True
            except Exception as failure:
                self.failed = True
                _unwitnessed('DISPATCH_OUTCOME_UNRECORDED')
                if self.owner.mode == 'enforce':
                    raise EgressOutcomeUnrecorded('DISPATCH_OUTCOME_UNRECORDED', _RECOVERY) from failure


class NativeDispatchGovernor:
    def __init__(self, ctx, mode):
        self.ctx, self.mode = ctx, mode
        self.lock = threading.RLock()
        self.sessions = {}
        self.parents = {}
        self.invalid_lineage = set()
        self.closed = set()

    def __call__(self, *, payload, dispatch_phase='sdk_invocation', **context):
        if dispatch_phase == 'sdk_invocation':
            return None
        try:
            if self.mode not in {'observe','enforce'}:
                _deny('GOVERNANCE_MODE_INVALID')
            if dispatch_phase != 'physical_send':
                _deny('UNSUPPORTED_TRANSPORT')
            if type(payload) is not dict:
                _deny('MATERIALIZATION_UNAVAILABLE')
            for key in ('qualification_error','route_qualification_error','output_bound_error'):
                if payload.get(key):
                    _deny(payload[key])
            if payload.get('schema') != 'ares.physical-send/v1' or payload.get('request_body_schema') != 'ares.immutable-provider-body/v1+blake3':
                _deny('UNSUPPORTED_TRANSPORT')
            record, managed = _materialization(payload)
            route = payload.get('resolved_route')
            if type(route) is not dict or route.get('schema') != 'ares.resolved-dispatch-route/v1':
                _deny('ROUTE_IDENTITY_UNAVAILABLE')
            if (not _positive(payload.get('provider_request_bytes')) or not _positive(payload.get('output_token_ceiling'))
                    or not isinstance(payload.get('provider_request_digest'), str) or not _HEX.fullmatch(payload['provider_request_digest'])
                    or not isinstance(payload.get('dispatch_intent_ref'), str) or not payload['dispatch_intent_ref']):
                _deny('MALFORMED')
            socket_path = self.ctx.get_config('socket_path')
            if socket_path is None:
                socket_path = str(Path(get_hermes_home())/'recursive-agent/run/ra.sock')
            terminal_timeout = self.terminal_timeout()
            client = NativeGovernanceClient(socket_path)
            capabilities = client.capabilities()
            if 'ares.transport-response-body/v1' not in capabilities['response_projection_schemas']:
                _deny('RESPONSE_PROJECTION_UNSUPPORTED')
            conversation = _conversation(managed)
            with self.lock:
                if managed['session_ref'] in self.closed:
                    _deny('RUN_CLOSED')
                if managed['session_ref'] in self.invalid_lineage:
                    _deny('PARENT_SESSION_UNAVAILABLE')
                parent = self.parents.get(managed['session_ref'])
                parent_run = None
                if parent is not None:
                    parent_sessions = [v for k,v in self.sessions.items() if k[0] == parent]
                    if len(parent_sessions) != 1:
                        _deny('PARENT_SESSION_UNAVAILABLE')
                    parent_run = parent_sessions[0]['session_run_id']
                opened = client.session_open(conversation, parent_run)
                self.sessions[(managed['session_ref'],managed['session_generation'])] = opened
                grant = opened['grant']
                if self.mode == 'enforce' and grant['mode'] != 'enforce':
                    _deny('GRANT_MODE_MISMATCH')
                caps = grant['caps']
                if any(not _positive(caps.get(key)) for key in ('max_request_bytes','max_output_tokens','max_wall_time_ms')):
                    _deny('MALFORMED')
                operation = dict(schema='recursive-agent.normal-chat/v2', conversation_ref=conversation,
                    parent_run_id=opened['session_run_id'], materialization_ref=record['materialization_ref'],
                    materialization_digest=record['materialization_digest'],
                    policy_basis_ref='normal-chat-grant:revision-'+str(grant['revision']),policy_basis_digest=grant['policy_digest'],
                    source_revision=managed['source_revision'],route_class=managed['purpose'],
                    provider_identity=route['provider_identity'],model_ref=route['model_ref'],api_mode=route['api_mode'],
                    request_digest=managed['request_digest'],request_projection_schema=managed['request_projection_schema'],
                    budget=dict(output_reserve=payload['output_token_ceiling'],max_wall_time_ms=caps['max_wall_time_ms'],
                                max_request_bytes=caps['max_request_bytes']),replay='unavailable',
                    provenance=[dict(source=payload['dispatch_intent_ref'],digest=payload['provider_request_digest'])])
                call = dict(schema='recursive-agent.normal-chat-call-request/v2',operation=operation,
                    provider_request_digest=payload['provider_request_digest'],provider_request_bytes=payload['provider_request_bytes'],
                    dispatch_intent_ref=payload['dispatch_intent_ref'])
                admitted = client.attempt_begin(opened['session_run_id'], call)
            return _Ticket(self, NativeGovernanceClient(socket_path, timeout=terminal_timeout), opened, admitted, call)
        except Exception as error:
            code = getattr(error, 'code', 'DISPATCH_GOVERNOR_ERROR')
            if self.mode == 'observe':
                _unwitnessed(code)
                return None
            if isinstance(error, EgressDispatchDenied):
                raise
            raise EgressDispatchDenied(code, _RECOVERY) from error

    def terminal_timeout(self):
        # Reporting/closure can legitimately outlive an immutable send lease.
        # This does not change the two-second pre-send admission deadline.
        value = self.ctx.get_config('terminal_timeout_seconds', 10.0)
        if type(value) not in {int, float} or not math.isfinite(value) or not 0 < value <= 60:
            _deny('GOVERNANCE_TIMEOUT_INVALID')
        return float(value)

    def subagent_start(self, *, parent_session_id=None, child_session_id=None, **kwargs):
        if not isinstance(child_session_id, str) or not child_session_id.strip():
            _unwitnessed('CHILD_SESSION_UNAVAILABLE')
            return
        with self.lock:
            if (not isinstance(parent_session_id, str) or not parent_session_id.strip()
                    or parent_session_id == child_session_id):
                self.invalid_lineage.add(child_session_id)
                _unwitnessed('PARENT_SESSION_UNAVAILABLE')
                return
            existing = self.parents.get(child_session_id)
            if existing is not None and existing != parent_session_id:
                self.invalid_lineage.add(child_session_id)
                _unwitnessed('PARENT_SESSION_CONFLICT')
                return
            self.parents[child_session_id] = parent_session_id

    def close(self, *, session_id=None, reason, **kwargs):
        if not isinstance(session_id,str):
            return
        with self.lock:
            self.closed.add(session_id)
            for key, opened in self.sessions.items():
                if key[0] != session_id:
                    continue
                socket_path = self.ctx.get_config('socket_path')
                if socket_path is None:
                    socket_path = str(Path(get_hermes_home())/'recursive-agent/run/ra.sock')
                try:
                    NativeGovernanceClient(socket_path, timeout=self.terminal_timeout()).run_close(opened['session_run_id'], reason)
                except Exception:
                    _unwitnessed('SESSION_CLOSE_UNCONFIRMED')


def register_governor(ctx):
    mode = ctx.get_config('governance_mode')
    if mode is None or mode == 'off':
        return None
    owner = NativeDispatchGovernor(ctx, mode)
    ctx.register_middleware('llm_dispatch', owner)
    ctx.register_hook('on_session_finalize', lambda **kw: owner.close(reason='session_finalized', **kw))
    ctx.register_hook('on_session_reset', lambda **kw: owner.close(reason='session_reset', **kw))
    ctx.register_hook('subagent_start', owner.subagent_start)
    return owner
