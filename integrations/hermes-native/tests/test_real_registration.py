"""Qualify the actual host registry and original envelope-file boundary."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("native_real_registry_package", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
assert SPEC and SPEC.loader
plugin = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = plugin
SPEC.loader.exec_module(plugin)


def test_actual_plugin_context_exports_a_function_parameter_schema(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
    from tools.registry import registry

    manager = PluginManager()
    context = PluginContext(PluginManifest(name="recursive-agent-native", key="recursive-agent-native", source="user"), manager)
    before = registry.snapshot_registration(plugin.TOOL_NAME, scope=manager.scope_key)
    monkeypatch.setattr(plugin, "check_socket_available", lambda _: True)
    try:
        plugin.register(context)
        definitions = registry.get_definitions({plugin.TOOL_NAME}, quiet=True)
        assert len(definitions) == 1
        function = definitions[0]["function"]
        assert function["name"] == plugin.TOOL_NAME
        parameters = function["parameters"]
        assert parameters["type"] == "object"
        assert parameters["additionalProperties"] is False
        assert parameters["required"] == ["envelope_path"]
        assert set(parameters["properties"]) == {"envelope_path"}
        assert parameters["properties"]["envelope_path"]["type"] == "string"
    finally:
        current = registry.snapshot_registration(plugin.TOOL_NAME, scope=manager.scope_key)
        if current is not before:
            registry.restore_registration(plugin.TOOL_NAME, current, before, scope=manager.scope_key)


@pytest.mark.parametrize("raw", [
    '{"schema":"one","schema":"two"}',
    '{"outer":{"budget":1,"budget":2}}',
    '{"number":NaN}',
    '[]',
    '{} ' + ' ' * ((1024 * 1024) + 1),
])
def test_invalid_original_file_bytes_never_reach_native_ipc(tmp_path, monkeypatch, raw):
    file = tmp_path / "operation.json"
    file.write_text(raw)
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(args)
        raise plugin.DaemonClientError("unexpected native call")
    monkeypatch.setattr(plugin, "submit_and_status", forbidden)
    context = SimpleNamespace(get_config=lambda key, default=None: default)
    response = plugin._handler(context, {"envelope_path": str(file)})
    assert "unavailable" in response
    assert calls == [], "a lossy/invalid original envelope was normalized before native ingress"


@pytest.mark.parametrize("args", [None, [], {"envelope_path": 1}, {"envelope_path": True}])
def test_tool_arguments_are_not_coerced_or_widened(tmp_path, monkeypatch, args):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "1").write_text("{}")
    (tmp_path / "True").write_text("{}")
    called = []
    monkeypatch.setattr(plugin, "submit_and_status", lambda *a, **k: called.append(a))
    context = SimpleNamespace(get_config=lambda key, default=None: default)
    response = plugin._handler(context, args)
    assert "unavailable" in response
    assert called == []


def test_unknown_tool_arguments_never_reach_ipc(tmp_path, monkeypatch):
    file = tmp_path / "operation.json"
    file.write_text("{}")
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(args)
        raise plugin.DaemonClientError("unexpected native call")
    monkeypatch.setattr(plugin, "submit_and_status", forbidden)
    context = SimpleNamespace(get_config=lambda key, default=None: default)
    result = plugin._handler(context, {"envelope_path": str(file), "unrecognized": True})
    assert "unavailable" in result
    assert calls == []


@pytest.mark.parametrize('mode', ['off','observe','enforce'])
def test_actual_context_registers_physical_governor_and_only_boundary_hooks(tmp_path,monkeypatch,mode):
    import json
    monkeypatch.setenv('HERMES_HOME',str(tmp_path))
    # JSON is a YAML subset; this goes through actual config and PluginContext,
    # not an invented ctx.config property or a fake registration dictionary.
    (tmp_path/'config.yaml').write_text(json.dumps({'plugins':{'entries':{'recursive-agent-native':{
        'enabled':True,'settings':{'governance_mode':mode,'socket_path':str(tmp_path/'native.sock')}}}}}))
    from hermes_cli.plugins import PluginContext,PluginManager,PluginManifest
    from tools.registry import registry
    manager=PluginManager()
    context=PluginContext(PluginManifest(name='recursive-agent-native',key='recursive-agent-native',source='user'),manager)
    previous=registry.snapshot_registration(plugin.TOOL_NAME,scope=manager.scope_key)
    try:
        assert context.get_config('governance_mode')==mode
        plugin.register(context)
        callbacks=manager._middleware.get('llm_dispatch',[])
        if mode=='off':
            assert callbacks==[] and manager._hooks=={}
        else:
            assert len(callbacks)==1
            assert callbacks[0].mode==mode
            assert callbacks[0](payload={},dispatch_phase='sdk_invocation') is None
            assert set(manager._hooks)=={'on_session_finalize','on_session_reset','subagent_start'}
    finally:
        current=registry.snapshot_registration(plugin.TOOL_NAME,scope=manager.scope_key)
        if current is not previous:
            registry.restore_registration(plugin.TOOL_NAME,current,previous,scope=manager.scope_key)
