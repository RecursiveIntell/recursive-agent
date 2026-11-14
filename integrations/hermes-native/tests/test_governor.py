"""Physical-only governor contract; synthetic fixtures never claim live ownership."""
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('native_governor_tests', ROOT/'__init__.py', submodule_search_locations=[str(ROOT)])
package = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = package
SPEC.loader.exec_module(package)

@pytest.fixture
def module():
    return importlib.import_module(SPEC.name+'.governor')

class Context:
    def __init__(self, mode=None):
        self.mode, self.middleware, self.hooks = mode, [], {}
    def get_config(self, key, default=None):
        return {'governance_mode':self.mode, 'socket_path':'/unused/native.sock'}.get(key, default)
    def register_middleware(self, kind, callback):
        self.middleware.append((kind, callback))
    def register_hook(self, key, callback):
        self.hooks[key] = callback

@pytest.mark.parametrize('mode', [None, 'off'])
def test_off_is_no_registration(module, mode):
    ctx = Context(mode)
    assert module.register_governor(ctx) is None
    assert not ctx.middleware and not ctx.hooks

def test_invalid_mode_and_unsupported_are_terminal_before_rpc(module, tmp_path, monkeypatch):
    from hermes_cli.middleware import EgressDispatchDenied
    monkeypatch.setattr(module, 'get_hermes_home', lambda: tmp_path)
    for mode, code in [('wrong','GOVERNANCE_MODE_INVALID'), ('enforce','UNSUPPORTED_TRANSPORT')]:
        ctx=Context(mode); module.register_governor(ctx)
        with pytest.raises(EgressDispatchDenied) as error:
            ctx.middleware[0][1](payload={}, dispatch_phase='unsupported_transport')
        assert error.value.code==code

def test_only_physical_phase_spends_permits(module, tmp_path, monkeypatch):
    monkeypatch.setattr(module, 'get_hermes_home', lambda: tmp_path)
    ctx=Context('enforce'); module.register_governor(ctx)
    assert ctx.middleware[0][1](payload={'private':'not a physical body'}) is None
    assert 'on_session_end' not in ctx.hooks
    assert {'on_session_finalize','on_session_reset','subagent_start'} <= set(ctx.hooks)

def test_unqualified_observe_records_private_bounded_diagnostic(module, tmp_path, monkeypatch):
    monkeypatch.setattr(module, 'get_hermes_home', lambda: tmp_path)
    ctx=Context('observe'); module.register_governor(ctx)
    callback=ctx.middleware[0][1]
    assert callback(payload={'qualification_error':'MATERIALIZATION_UNAVAILABLE','private':'SECRET'}, dispatch_phase='physical_send') is None
    path=tmp_path/'recursive-agent/unwitnessed.ndjson'
    assert path.stat().st_mode & 0o777 == 0o600
    event=json.loads(path.read_text())
    assert event['code']=='MATERIALIZATION_UNAVAILABLE' and 'SECRET' not in path.read_text()

def test_unqualified_enforce_never_constructs_client(module, tmp_path, monkeypatch):
    from hermes_cli.middleware import EgressDispatchDenied
    monkeypatch.setattr(module, 'get_hermes_home', lambda: tmp_path)
    monkeypatch.setattr(module, 'NativeGovernanceClient', lambda *a,**kw: pytest.fail('no IPC before qualification'))
    ctx=Context('enforce'); module.register_governor(ctx)
    with pytest.raises(EgressDispatchDenied):
        ctx.middleware[0][1](payload={'qualification_error':'SESSION_IDENTITY_UNAVAILABLE'}, dispatch_phase='physical_send')

def physical_payload():
    from ares_runtime.managed_calls import ManagedCallContextV2
    from ares_runtime.collaboration import digest
    context=ManagedCallContextV2.create(dict(call_ref='ares-call:fixture', session_ref='session:fixture',
        session_generation=0,turn_ref='turn:fixture',input_digest='sha256:'+'a'*64,
        source_revision='ares-source:'+'b'*40,source_digest='sha256:'+'c'*64,
        provider_identity='openai',model_ref='fixture',api_mode='chat_completions',
        purpose='conversation',request_digest='sha256:'+'d'*64)).to_dict()
    materialization={'schema':'ares.dispatch-materialization/v1','context':context}
    value=digest(materialization)
    materialization.update(materialization_digest=value,materialization_ref='ares-materialization:'+value[7:])
    return dict(schema='ares.physical-send/v1',dispatch_intent_ref='ares-dispatch-intent:fixture',
        materialization=materialization,qualification_error=None,provider_request_digest='e'*64,
        provider_request_bytes=80,request_body_schema='ares.immutable-provider-body/v1+blake3',
        started_monotonic=0,resolved_route=dict(schema='ares.resolved-dispatch-route/v1',
        wire_protocol='openai.chat_completions',provider_identity='openai_compatible:https://fixture.test/v1/chat/completions',
        model_ref='fixture',api_mode='chat_completions'),route_qualification_error=None,
        output_token_ceiling=7,output_bound_error=None)

class Client:
    def __init__(self, *args, **kw):
        self.calls=[]
    def capabilities(self):
        return {'response_projection_schemas':['ares.transport-response-body/v1']}
    def session_open(self, conversation_ref, parent_session_run_id=None):
        self.calls.append(('open',conversation_ref,parent_session_run_id))
        return dict(session_run_id='native-owner-issued-fixture',grant=dict(mode='enforce',revision=1,
            policy_digest='sha256:'+'f'*64,caps=dict(max_request_bytes=4096,max_output_tokens=100,max_wall_time_ms=10000)))
    def attempt_begin(self, run, call):
        self.calls.append(('begin',run,call))
        return dict(attempt={'operation':call['operation'],'attempt_id':'v1:recursive-agent/normal-chat-attempt/v2:det:'+'a'*64},
            permit_id='v1:recursive-agent/permit/v1:det:'+'b'*64,preflight_receipt_digest='a'*64,
            expires_at=(datetime.now(timezone.utc)+timedelta(seconds=8)).isoformat())
    def attempt_settle(self, run, intent, preflight, report):
        self.calls.append(('settle',report))
        states={'succeeded':('succeeded',None),'failed':('failed','NORMAL_CHAT_FAILED'),
            'not_sent':('failed','NORMAL_CHAT_NOT_SENT'),'outcome_unknown':('outcome_ambiguous','NORMAL_CHAT_OUTCOME_UNKNOWN')}
        state,error=states[report['state']]
        return dict(kind='normal_chat_attempt_settled',terminal_state='succeeded' if state=='succeeded' else 'failed',
            child_chain_head='c'*64,parent_chain_head='d'*64,settlement=dict(
            schema='recursive-agent.normal-chat-settlement/v2',attempt_id='v1:recursive-agent/normal-chat-attempt/v2:det:'+'a'*64,
            report=report,violations=[],settlement_digest='e'*64,outcome=dict(
            permit_id='v1:recursive-agent/permit/v1:det:'+'b'*64,preflight_receipt_digest=preflight,
            reported=dict(state=state,duration_ms=report['duration_ms'],error_type=error),
            recorded_at=datetime.now(timezone.utc).isoformat(),receipt_digest='f'*64)))
    def run_close(self, run, reason):
        self.calls.append(('close',run,reason))

@pytest.fixture
def admitted(module,tmp_path,monkeypatch):
    monkeypatch.setattr(module,'get_hermes_home',lambda:tmp_path)
    client=Client()
    monkeypatch.setattr(module,'NativeGovernanceClient',lambda *a,**kw:client)
    ctx=Context('enforce'); module.register_governor(ctx)
    ticket=ctx.middleware[0][1](payload=physical_payload(),dispatch_phase='physical_send')
    return ctx,client,ticket

def test_exact_wire_route_body_budget_and_original_expiry(admitted):
    ctx,client,ticket=admitted
    call=next(v[2] for v in client.calls if v[0]=='begin')
    assert call['operation']['provider_identity'].startswith('openai_compatible:https://fixture.test/')
    assert call['provider_request_bytes']==80 and call['provider_request_digest']=='e'*64
    assert call['operation']['budget']['output_reserve']==7
    assert ticket.transport_lease['schema_version']=='ares.transport-lease/v1'
    assert ticket.transport_lease['output_tokens_limit']==7
    assert ticket.transport_lease['send_timeout_ms']==10000
    assert len([v for v in client.calls if v[0]=='begin'])==1

@pytest.mark.parametrize('outcome,state',[('ok','succeeded'),('provider_error','failed'),('discarded','failed')])
def test_complete_raw_response_is_never_relabelled_json(admitted,outcome,state):
    _,client,ticket=admitted
    body=b'raw response'
    response=dict(schema='ares.transport-response-body/v1',digest_algorithm='sha256',response_digest='sha256:'+hashlib.sha256(body).hexdigest(),
        response_bytes=len(body),response_complete=True,http_status=200,duration_ms=12.2,evidence='executor_observed',replay='unavailable')
    ticket.settle(outcome=outcome,response=response)
    report=client.calls[-1][1]
    assert report['state']==state and report['response']['projection_schema']=='ares.transport-response-body/v1'
    assert report['duration_ms']==13 and report['usage'] is None
    ticket.settle(outcome=outcome,response=response)
    assert len([v for v in client.calls if v[0]=='settle'])==1

def test_denied_peer_is_not_sent_and_stream_abandonment_is_unknown(admitted):
    _,client,ticket=admitted
    ticket.settle(outcome='denied_by_peer')
    assert client.calls[-1][1]==dict(schema='recursive-agent.normal-chat-executor-report/v2',state='not_sent',duration_ms=0,response=None,usage=None)

def test_absent_transport_report_never_becomes_success(admitted):
    _,client,ticket=admitted
    ticket.settle(outcome='abandoned')
    assert client.calls[-1][1]['state']=='outcome_unknown'

def test_settlement_failure_withholds_and_never_retries(admitted):
    from hermes_cli.middleware import EgressOutcomeUnrecorded
    _,client,ticket=admitted
    def broken(*a,**kw): raise OSError('SECRET')
    client.attempt_settle=broken
    with pytest.raises(EgressOutcomeUnrecorded): ticket.settle(outcome='ok')
    with pytest.raises(EgressOutcomeUnrecorded): ticket.settle(outcome='ok')
    assert len([v for v in client.calls if v[0]=='begin'])==1

def test_finalize_closes_only_mapped_native_run(admitted):
    ctx,client,_=admitted
    ctx.hooks['on_session_finalize'](session_id='session:fixture')
    assert client.calls[-1]==('close','native-owner-issued-fixture','session_finalized')


@pytest.mark.parametrize('code', ['DAEMON_UNREACHABLE','DAEMON_TIMEOUT','GRANT_MISSING','GRANT_EXPIRED',
    'ROUTE_NOT_ALLOWED','CAP_EXHAUSTED_ATTEMPTS','CAP_EXHAUSTED_OUTPUT_TOKENS','RUN_CLOSED'])
@pytest.mark.parametrize('mode', ['enforce','observe'])
def test_native_denial_never_retries_or_produces_a_permit(module,tmp_path,monkeypatch,code,mode):
    from hermes_cli.middleware import EgressDispatchDenied
    from importlib import import_module
    native=import_module(SPEC.name+'.governed_client')
    monkeypatch.setattr(module,'get_hermes_home',lambda:tmp_path)
    attempts=[]
    class DeniedClient(Client):
        def capabilities(self):
            attempts.append('capabilities')
            raise native.DaemonGovernanceError(code)
    client=DeniedClient()
    monkeypatch.setattr(module,'NativeGovernanceClient',lambda *a,**kw:client)
    ctx=Context(mode);module.register_governor(ctx)
    if mode=='enforce':
        with pytest.raises(EgressDispatchDenied) as caught:
            ctx.middleware[0][1](payload=physical_payload(),dispatch_phase='physical_send')
        assert caught.value.code==code and caught.value.retryable is False
    else:
        assert ctx.middleware[0][1](payload=physical_payload(),dispatch_phase='physical_send') is None
        diagnostic=json.loads((tmp_path/'recursive-agent/unwitnessed.ndjson').read_text())
        assert diagnostic['code']==code
    assert attempts==['capabilities'] and client.calls==[]


@pytest.mark.parametrize('value', [0,-1,True,'10',float('nan'),float('inf'),61])
def test_invalid_terminal_timeout_fails_before_native_call(module,tmp_path,monkeypatch,value):
    from hermes_cli.middleware import EgressDispatchDenied
    monkeypatch.setattr(module,'get_hermes_home',lambda:tmp_path)
    monkeypatch.setattr(module,'NativeGovernanceClient',lambda *a,**kw:pytest.fail('invalid config reached IPC'))
    ctx=Context('enforce');get=ctx.get_config
    ctx.get_config=lambda key,default=None:value if key=='terminal_timeout_seconds' else get(key,default)
    module.register_governor(ctx)
    with pytest.raises(EgressDispatchDenied) as caught:
        ctx.middleware[0][1](payload=physical_payload(),dispatch_phase='physical_send')
    assert caught.value.code=='GOVERNANCE_TIMEOUT_INVALID'


def test_preflight_and_terminal_deadlines_are_distinct_and_explicit(module,tmp_path,monkeypatch):
    monkeypatch.setattr(module,'get_hermes_home',lambda:tmp_path)
    constructed=[];client=Client()
    def make(*args,**kwargs):
        constructed.append(kwargs.get('timeout',2.0))
        return client
    monkeypatch.setattr(module,'NativeGovernanceClient',make)
    ctx=Context('enforce');module.register_governor(ctx)
    ctx.middleware[0][1](payload=physical_payload(),dispatch_phase='physical_send')
    assert constructed==[2.0,10.0]


def test_enforce_cannot_consume_an_observe_any_route_grant(module,tmp_path,monkeypatch):
    from hermes_cli.middleware import EgressDispatchDenied
    monkeypatch.setattr(module,'get_hermes_home',lambda:tmp_path)
    class ObserveGrant(Client):
        def session_open(self,*args,**kw):
            result=super().session_open(*args,**kw)
            result['grant']['mode']='observe'
            return result
    client=ObserveGrant();monkeypatch.setattr(module,'NativeGovernanceClient',lambda *a,**kw:client)
    ctx=Context('enforce');module.register_governor(ctx)
    with pytest.raises(EgressDispatchDenied) as caught:
        ctx.middleware[0][1](payload=physical_payload(),dispatch_phase='physical_send')
    assert caught.value.code=='GRANT_MODE_MISMATCH'
    assert [v[0] for v in client.calls]==['open']


def test_observe_settlement_failure_returns_without_lease_and_records_degradation(module,tmp_path,monkeypatch):
    monkeypatch.setattr(module,'get_hermes_home',lambda:tmp_path)
    class LostAck(Client):
        def attempt_settle(self,*args,**kw):
            self.calls.append(('settle-lost-ack',))
            raise OSError('private exception content must not be retained')
    client=LostAck();monkeypatch.setattr(module,'NativeGovernanceClient',lambda *a,**kw:client)
    ctx=Context('observe');module.register_governor(ctx)
    ticket=ctx.middleware[0][1](payload=physical_payload(),dispatch_phase='physical_send')
    assert ticket.transport_lease is None
    assert ticket.settle(outcome='ok') is None
    raw=(tmp_path/'recursive-agent/unwitnessed.ndjson').read_text()
    assert json.loads(raw)['code']=='DISPATCH_OUTCOME_UNRECORDED'
    assert 'private exception' not in raw
    assert sum(v[0]=='settle-lost-ack' for v in client.calls)==1


def test_diagnostic_symlink_is_not_followed_even_in_observe(module,tmp_path,monkeypatch):
    monkeypatch.setattr(module,'get_hermes_home',lambda:tmp_path)
    target=tmp_path/'unrelated';target.write_text('preserve')
    root=tmp_path/'recursive-agent';root.mkdir(mode=0o700)
    (root/'unwitnessed.ndjson').symlink_to(target)
    ctx=Context('observe');module.register_governor(ctx)
    assert ctx.middleware[0][1](payload={'qualification_error':'MATERIALIZATION_UNAVAILABLE'},dispatch_phase='physical_send') is None
    assert target.read_text()=='preserve'


@pytest.mark.parametrize('parent', [None, '', '   ', 12])
def test_identifiable_child_with_invalid_parent_never_falls_back_to_root(module,tmp_path,monkeypatch,parent):
    from hermes_cli.middleware import EgressDispatchDenied
    monkeypatch.setattr(module,'get_hermes_home',lambda:tmp_path)
    client=Client();monkeypatch.setattr(module,'NativeGovernanceClient',lambda *a,**kw:client)
    ctx=Context('enforce');module.register_governor(ctx)
    ctx.hooks['subagent_start'](child_session_id='session:fixture',parent_session_id=parent)
    with pytest.raises(EgressDispatchDenied) as caught:
        ctx.middleware[0][1](payload=physical_payload(),dispatch_phase='physical_send')
    assert caught.value.code=='PARENT_SESSION_UNAVAILABLE'
    assert client.calls==[]


def test_incomplete_terminal_ack_never_confirms_ticket(admitted):
    from hermes_cli.middleware import EgressOutcomeUnrecorded
    _,client,ticket=admitted
    client.attempt_settle=lambda *args,**kw:{'settlement':{'report':args[-1]}}
    with pytest.raises(EgressOutcomeUnrecorded):
        ticket.settle(outcome='denied_by_peer')
    assert ticket.confirmed is False


@pytest.mark.parametrize('failure', ['attempt','permit','preflight','terminal','unknown_member','reported_state','schema'])
def test_malformed_or_uncorrelated_terminal_ack_withholds_enforcing_result(admitted,failure):
    from hermes_cli.middleware import EgressOutcomeUnrecorded
    _,client,ticket=admitted
    original=client.attempt_settle
    def changed(*args,**kwargs):
        result=original(*args,**kwargs)
        settlement=result['settlement']
        if failure=='attempt':settlement['attempt_id']='v1:recursive-agent/normal-chat-attempt/v2:det:'+'c'*64
        if failure=='permit':settlement['outcome']['permit_id']='v1:recursive-agent/permit/v1:det:'+'c'*64
        if failure=='preflight':settlement['outcome']['preflight_receipt_digest']='c'*64
        if failure=='terminal':result['terminal_state']='succeeded'
        if failure=='unknown_member':settlement['extra']='discarded fields are not accepted'
        if failure=='reported_state':settlement['outcome']['reported']['state']='succeeded'
        if failure=='schema':settlement['schema']='recursive-agent.normal-chat-settlement/v1'
        return result
    client.attempt_settle=changed
    with pytest.raises(EgressOutcomeUnrecorded):ticket.settle(outcome='denied_by_peer')
    assert ticket.confirmed is False and ticket.failed is True
