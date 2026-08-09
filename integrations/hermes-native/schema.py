"""Typed schemas for the recursive-agent Hermes integration.

The tool accepts a small, bounded argument surface; anything else is rejected
by Hermes' schema validation before the handler runs.
"""

from __future__ import annotations

RECURSIVE_AGENT_EXECUTE_SCHEMA = {
    "type": "object",
    "properties": {
        "envelope_path": {
            "type": "string",
            "description": "Path to a canonical recursive-agent operation envelope JSON "
            "(produced by `ra-daemon emit-envelope`). The handler submits it "
            "verbatim over authenticated native IPC.",
        }
    },
    "additionalProperties": False,
}
