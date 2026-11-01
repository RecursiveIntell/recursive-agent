"""Typed schemas for the recursive-agent Hermes integration.

Hermes registers a plugin tool's ``schema`` as the model-facing OpenAI
function definition: ``{"name", "description", "parameters"}``. A bare JSON
Schema object is accepted at registration but reaches the model with no
parameters, so the argument surface must live under ``parameters``. Anything
outside that bounded surface is rejected by Hermes' schema validation before
the handler runs.
"""

from __future__ import annotations

RECURSIVE_AGENT_EXECUTE_SCHEMA = {
    "name": "recursive_agent_execute",
    "description": (
        "Submit one bounded recursive-agent native action and return "
        "daemon-derived terminal status plus strict verification facts."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "envelope_path": {
                "type": "string",
                "description": "Path to a canonical recursive-agent operation envelope JSON "
                "(produced by `ra-daemon emit-envelope`). The handler submits it "
                "verbatim over authenticated native IPC.",
            }
        },
        "required": ["envelope_path"],
        "additionalProperties": False,
    },
}
