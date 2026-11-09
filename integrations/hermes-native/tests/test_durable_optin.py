"""Task 3.2 migration gate: the durable-start path is opt-in and off by default.

The plugin module is loaded by path, as the other plugin tests do. The durable
and blocking paths are replaced with recorders so the test observes routing,
not the transport.
"""

import importlib.util
import os
import sys

PLUGIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PLUGIN_DIR)
_SPEC = importlib.util.spec_from_file_location(
    "hermes_native", os.path.join(PLUGIN_DIR, "__init__.py")
)
assert _SPEC is not None and _SPEC.loader is not None
plugin = importlib.util.module_from_spec(_SPEC)
plugin.__package__ = "hermes_native"
plugin.__path__ = [PLUGIN_DIR]
sys.modules["hermes_native"] = plugin
_SPEC.loader.exec_module(plugin)


class Ctx:
    def __init__(self, config):
        self._config = config

    def get_config(self, key):
        return self._config.get(key)


def _route(monkeypatch, config, envelope_bytes_path):
    calls = []
    monkeypatch.setattr(
        plugin, "submit_and_status_raw", lambda sock, raw: calls.append("blocking") or {"state": "terminal"}
    )
    monkeypatch.setattr(
        plugin, "start_and_follow", lambda sock, env: calls.append("durable") or {"state": "terminal"}
    )
    plugin._handler(Ctx(config), {"envelope_path": str(envelope_bytes_path)})
    return calls


def _envelope_file(tmp_path):
    p = tmp_path / "env.json"
    p.write_text('{"schema":"recursive-agent.operation/v3"}')
    return p


def test_durable_path_is_off_when_unset(tmp_path, monkeypatch):
    assert _route(monkeypatch, {}, _envelope_file(tmp_path)) == ["blocking"]


def test_durable_path_is_off_for_non_true_values(tmp_path, monkeypatch):
    for value in ("true", 1, "yes", False, None):
        assert _route(monkeypatch, {"durable_start": value}, _envelope_file(tmp_path)) == ["blocking"]


def test_durable_path_is_used_only_when_explicitly_true(tmp_path, monkeypatch):
    assert _route(monkeypatch, {"durable_start": True}, _envelope_file(tmp_path)) == ["durable"]
