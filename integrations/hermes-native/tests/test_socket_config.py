"""Real plugin-registration contract: settings and service gate agree."""
from test_registration import plugin, StubCtx
import pytest

class ConfigCtx(StubCtx):
    def __init__(self, socket_path):
        super().__init__()
        self.socket_path = socket_path
        self.keys = []
        # This legacy lookalike must never override the actual plugin API.
        self.config = {"plugins": {"entries": {"recursive-agent-native": {
            "socket_path": "/unrelated-legacy.sock"}}}}

    def get_config(self, key, default=None):
        self.keys.append(key)
        return self.socket_path if key == "socket_path" else default


def test_socket_resolves_plugin_owned_settings_api():
    ctx = ConfigCtx("/run/private-governance/ra.sock")
    assert plugin._resolve_socket(ctx) == ctx.socket_path
    assert ctx.keys == ["socket_path"]


def test_default_is_only_for_absent_setting():
    assert plugin._resolve_socket(ConfigCtx(None)) == plugin.DEFAULT_SOCKET_PATH
    assert plugin._resolve_socket(None) == plugin.DEFAULT_SOCKET_PATH


@pytest.mark.parametrize("value", [False, 3, [], {}, "", "  ", "\x00bad"])
def test_explicit_invalid_socket_never_routes_to_a_different_daemon(value):
    with pytest.raises(ValueError, match="socket_path"):
        plugin._resolve_socket(ConfigCtx(value))


def test_registered_zero_argument_gate_captures_same_context_as_handler(monkeypatch, tmp_path):
    ctx = ConfigCtx(str(tmp_path / "per-home.sock"))
    probes = []
    monkeypatch.setattr(plugin, "check_socket_available", lambda path: probes.append(path) or True)
    plugin.register(ctx)
    assert ctx.registrations[0]["check_fn"]() is True
    assert probes == [ctx.socket_path]
    envelope = tmp_path / "envelope.json"
    envelope.write_text("{}", encoding="utf-8")
    sends = []
    def submit(path, body):
        sends.append(path)
        raise plugin.DaemonClientError("fixture transport refusal")
    monkeypatch.setattr(plugin, "submit_and_status", submit)
    assert "fixture transport refusal" in ctx.registrations[0]["handler"]({"envelope_path":str(envelope)})
    assert sends == probes
