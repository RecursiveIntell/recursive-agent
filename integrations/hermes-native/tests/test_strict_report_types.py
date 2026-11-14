"""Type-exact ACK regression; all NativeClient responses are synthetic fixtures."""
import copy
import importlib
import pytest

from test_governor import Client, SPEC, admitted, module  # noqa: F401


def changed_echo(result,case):
    echo=result['settlement']['report']
    if case=='bool_duration':echo['duration_ms']=False
    if case=='float_duration':echo['duration_ms']=13.0
    if case=='integer_complete':echo['response']['complete']=1
    if case=='float_bytes':echo['response']['byte_length']=12.0
    if case=='bool_usage':echo['usage']['output_tokens']=True
    return result


def report_for(case):
    value=dict(schema='recursive-agent.normal-chat-executor-report/v2',state='not_sent',duration_ms=0,response=None,usage=None)
    if case!='bool_duration':
        value.update(state='succeeded',duration_ms=13,response=dict(projection_schema='ares.transport-response-body/v1',
            digest='sha256:'+'a'*64,byte_length=12,complete=True))
    if case=='bool_usage':value['usage']=dict(source='provider_reported',input_tokens=0,output_tokens=1)
    return value


@pytest.mark.parametrize('case',['bool_duration','float_duration','integer_complete','float_bytes','bool_usage'])
def test_client_rejects_coercion_in_echoed_native_report(monkeypatch,case):
    native=importlib.import_module(SPEC.name+'.governed_client')
    report=report_for(case)
    result=changed_echo(copy.deepcopy(Client().attempt_settle('unused','unused','a'*64,report)),case)
    rpc=native.NativeGovernanceClient('/unused/native.sock')
    monkeypatch.setattr(rpc,'_rpc',lambda *args,**kwargs:result)
    with pytest.raises(native.DaemonGovernanceError):
        rpc.attempt_settle('v1:recursive-agent/run/v1:det:'+'a'*64,'intent:fixture','a'*64,report)


@pytest.mark.parametrize('case',['bool_duration','float_duration','integer_complete','float_bytes'])
def test_ticket_never_confirms_a_coercively_equal_echo(admitted,case):
    from hermes_cli.middleware import EgressOutcomeUnrecorded
    _,client,ticket=admitted
    original=client.attempt_settle
    def altered(*args,**kwargs):return changed_echo(copy.deepcopy(original(*args,**kwargs)),case)
    client.attempt_settle=altered
    response=None
    if case!='bool_duration':
        response=dict(schema='ares.transport-response-body/v1',digest_algorithm='sha256',response_digest='sha256:'+'a'*64,
            response_bytes=12,response_complete=True,http_status=200,duration_ms=12.2,evidence='executor_observed',replay='unavailable')
    with pytest.raises(EgressOutcomeUnrecorded):
        ticket.settle(outcome='denied_by_peer' if response is None else 'ok',response=response)
    assert not ticket.confirmed and ticket.failed
    assert sum(item[0]=='settle' for item in client.calls)==1
