"""Task 4.1 — registration, service gating, and malformed-response rejection.

The plugin is tested through the same `register(ctx)` / `ctx.register_tool(...)`
contract Hermes uses (its plugin loader calls `register_fn(ctx)` with a real
`PluginContext`). We use a stub ctx that records the registration call — the
full real-loader wiring is the Task 4.2 E2E.
"""

import importlib.util
import os
import socket
import sys
import threading

import pytest

PLUGIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PLUGIN_DIR)

# Hermes loads plugins by directory path (a hyphenated dir name is valid for
# its loader but not for a plain `import`). Mirror that: load __init__.py from
# the plugin directory explicitly.
_SPEC = importlib.util.spec_from_file_location(
    "hermes_native", os.path.join(PLUGIN_DIR, "__init__.py")
)
assert _SPEC is not None and _SPEC.loader is not None
# Register the package name BEFORE exec so the plugin's relative imports
# (``from .client import ...``) resolve against the directory package.
plugin = importlib.util.module_from_spec(_SPEC)
plugin.__package__ = "hermes_native"
plugin.__path__ = [PLUGIN_DIR]
sys.modules["hermes_native"] = plugin
_SPEC.loader.exec_module(plugin)


class StubCtx:
    """Records the single tool registration exactly as Hermes' loader drives it."""

    def __init__(self):
        self.registrations = []

    def register_tool(self, **kwargs):
        self.registrations.append(kwargs)


def test_register_exposes_one_non_overriding_tool_in_recursive_agent_toolset():
    ctx = StubCtx()
    plugin.register(ctx)
    assert len(ctx.registrations) == 1
    reg = ctx.registrations[0]
    assert reg["name"] == "recursive_agent_execute"
    assert reg["toolset"] == "recursive_agent"
    # A non-overriding plugin must not request override.
    assert reg.get("override") is None or reg.get("override") is False
    # Hermes dispatches registered handlers as handler(args), not handler(ctx, args).
    # The closure must retain the registration context without a TypeError.
    assert reg["handler"]({}) == "recursive_agent_execute: unavailable: envelope_path required"


def test_check_fn_returns_false_when_socket_absent(tmp_path):
    # Point the plugin at a socket that does not exist.
    missing = str(tmp_path / "does-not-exist.sock")
    assert plugin.check_recursive_agent_available_stub(missing) is False


def test_check_fn_returns_true_when_socket_answers(tmp_path):
    sock_path = str(tmp_path / "ra.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.listen(1)
    stop = threading.Event()

    def _accept():
        try:
            while not stop.is_set():
                server.settimeout(0.1)
                try:
                    conn, _ = server.accept()
                    conn.close()
                except socket.timeout:
                    continue
        except OSError:
            pass

    thread = threading.Thread(target=_accept, daemon=True)
    thread.start()
    try:
        # The service gate only checks reachability of the private socket.
        assert plugin.check_recursive_agent_available_stub(sock_path) is True
    finally:
        stop.set()
        server.close()


def test_malformed_runtime_response_is_rejected():
    from hermes_native import client

    # An oversized frame length must be rejected without parsing.
    with pytest.raises(client.DaemonClientError):
        client._frame_len_check((1024 * 1024) + (64 * 1024) + 1)
