"""Isolated AIAgent V3 turn; driven only by provider_egress_ipc.rs.

The Rust test owns the socket, provider fixture, policy, and run root. Never
point this script at an installed service or selected conversation.
"""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock, patch

import yaml

socket_path = Path(sys.argv[1])
positive_file = Path(sys.argv[2])
runs = Path(sys.argv[3])
plugin_source = Path(sys.argv[4])
agent_root = Path(sys.argv[5]).resolve(strict=True)
assert socket_path.is_socket() and positive_file.is_file()
assert runs.is_dir() and not any(runs.iterdir())
assert plugin_source.is_dir() and (agent_root / "run_agent.py").is_file()


def response(text="", tool_call=None):
    message = SimpleNamespace(content=text, tool_calls=[tool_call] if tool_call else None)
    return SimpleNamespace(
        choices=[SimpleNamespace(message=message, finish_reason="tool_calls" if tool_call else "stop")],
        model="test/disposable-v3", usage=None,
    )


with tempfile.TemporaryDirectory(prefix="ac08-v3-agent-") as tmp:
    home = Path(tmp)
    shutil.copytree(plugin_source, home / "plugins" / "recursive-agent-native",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (home / "config.yaml").write_text(yaml.safe_dump({"plugins": {
        "enabled": ["recursive-agent-native"],
        "entries": {"recursive-agent-native": {"settings": {"socket_path": str(socket_path)}}},
    }}), encoding="utf-8")
    os.environ["HERMES_HOME"] = str(home)
    os.environ.pop("HERMES_SAFE_MODE", None)
    os.environ.pop("HERMES_ENABLE_PROJECT_PLUGINS", None)
    os.environ.pop("ARES_STRICT_EFFECT_TOOL_ARGS_V1", None)

    from hermes_cli.plugins import _ensure_plugins_discovered
    from run_agent import AIAgent
    import run_agent
    from tools.registry import registry

    assert Path(run_agent.__file__).resolve().is_relative_to(agent_root), run_agent.__file__
    manager = _ensure_plugins_discovered()
    try:
        plugin = manager._plugins.get("recursive-agent-native")
        assert plugin and plugin.enabled and plugin.error is None, plugin
        entry = registry.get_entry("recursive_agent_execute", scope=manager.scope_key)
        assert entry and entry.toolset == "recursive_agent" and entry.check_fn()
        with patch("run_agent.OpenAI"):
            agent = cast(Any, AIAgent(
                api_key="disposable-not-a-secret", base_url="http://127.0.0.1:1/v1",
                model="test/disposable-v3", max_iterations=3,
                enabled_toolsets=["recursive_agent"], quiet_mode=True,
                skip_context_files=True, skip_memory=True,
                session_id="disposable-v3-turn", platform="cli",
            ))
        agent.client = MagicMock()
        agent._cached_system_prompt = "Fixture only; never contact a provider."
        agent._use_prompt_caching = False
        agent.compression_enabled = False
        agent.save_trajectories = False
        assert "recursive_agent_execute" in agent.valid_tool_names
        assert any(t["function"]["name"] == "recursive_agent_execute" for t in agent.tools)

        bad = home / "bad-v3.json"
        bad.write_bytes(b'{"schema":"recursive-agent.operation/v3","\\u0073chema":"recursive-agent.operation/v1"}')

        def turn(path, label):
            call = SimpleNamespace(id=f"call-{label}", type="function", function=SimpleNamespace(
                name="recursive_agent_execute", arguments=json.dumps({"envelope_path": str(path)})))
            agent.client.chat.completions.create.reset_mock()
            agent.client.chat.completions.create.side_effect = [response(tool_call=call), response(text=f"done-{label}")]
            result = agent.run_conversation(f"fixture {label}", task_id=f"disposable-v3-{label}")
            assert agent.client.chat.completions.create.call_count == 2, result
            assert result["final_response"] == f"done-{label}", result
            rows = [m["content"] for m in result["messages"] if m.get("role") == "tool" and m.get("tool_call_id") == f"call-{label}"]
            assert len(rows) == 1, rows
            return rows[0]

        denied = turn(bad, "denied")
        assert "native operation denied" in denied and "duplicate object key" in denied, denied
        assert not any(runs.iterdir()), "hostile V3 input created a run"
        positive = json.loads(turn(positive_file, "valid"))
        assert positive["schema"] == "recursive-agent.hermes-result/v1", positive
        assert positive["verified"] is True and positive["state"] == "terminal", positive
        assert positive["recorded_output"] == {"model": "fixture-model", "text": "native-ipc-v3-response"}, positive
        assert len(list(runs.iterdir())) == 1, "positive V3 turn did not create exactly one run"
        print("AC08_V3_RESULT=" + json.dumps({"result": "PASS", "route": "AIAgent.run_conversation -> selected plugin -> Rust provider fixture",
                          "invalid_run_entries": 0, "valid_run_entries": 1, "verified": True,
                          "recorded_output": positive["recorded_output"], "external_provider": False,
                          "installed_route": False}))
    finally:
        manager.unload()
