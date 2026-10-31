"""The model-facing schema must survive Hermes' real tool registry.

Hermes' registry passes a plugin's ``schema`` through as the OpenAI function
definition (``{"name", "description", "parameters"}``) and ``tool_describe``
reads ``parameters`` from it. A bare JSON Schema object registers without
error but reaches the model with no parameters, so every call omits
``envelope_path`` and fails. These tests use the real registry and
``tool_describe`` dispatch when a Hermes runtime is importable.
"""

import importlib.util
import json
import os
import sys

import pytest

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

from hermes_native.schema import RECURSIVE_AGENT_EXECUTE_SCHEMA  # noqa: E402


def test_schema_is_a_function_definition_with_required_envelope_path():
    schema = RECURSIVE_AGENT_EXECUTE_SCHEMA
    assert schema["name"] == plugin.TOOL_NAME
    assert isinstance(schema.get("description"), str) and schema["description"].strip()
    parameters = schema["parameters"]
    assert parameters["type"] == "object"
    assert parameters["properties"]["envelope_path"]["type"] == "string"
    assert parameters["required"] == ["envelope_path"]
    assert parameters["additionalProperties"] is False


def test_real_hermes_registry_and_tool_describe_expose_envelope_path(monkeypatch):
    registry_module = pytest.importorskip(
        "tools.registry", reason="requires a Hermes/Ares runtime on sys.path"
    )
    tool_search = pytest.importorskip("tools.tool_search")
    registry = registry_module.ToolRegistry()

    class _Context:
        def get_config(self, key, default=None):
            return default

        def register_tool(self, name, toolset, schema, handler, **kwargs):
            kwargs.pop("check_fn", None)  # no live daemon in this test
            registry.register(
                name=name, toolset=toolset, schema=schema, handler=handler, **kwargs
            )

    plugin.register(_Context())
    definitions = registry.get_definitions({plugin.TOOL_NAME})
    assert len(definitions) == 1

    monkeypatch.setattr(
        tool_search, "is_deferrable_tool_name", lambda name: name == plugin.TOOL_NAME
    )
    described = json.loads(
        tool_search.dispatch_tool_describe(
            {"names": [plugin.TOOL_NAME]}, current_tool_defs=definitions
        )
    )["tools"][plugin.TOOL_NAME]

    assert described["description"].strip()
    assert described["parameters"]["required"] == ["envelope_path"]
    assert set(described["parameters"]["properties"]) == {"envelope_path"}
