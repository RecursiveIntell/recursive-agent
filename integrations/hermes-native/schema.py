"""Host function schema for the standalone recursive-agent tool.

The handler independently checks the closed argument/file boundary before IPC;
model-facing JSON Schema is not treated as native authorization or validation.
"""
from __future__ import annotations

RECURSIVE_AGENT_EXECUTE_SCHEMA = {
    "name": "recursive_agent_execute",
    "description": "Submit one bounded recursive-agent native operation and return daemon-reported terminal and verification evidence.",
    "parameters": {
        "type": "object",
        "properties": {
            "envelope_path": {
                "type": "string",
                "minLength": 1,
                "maxLength": 4096,
                "description": "Path to a UTF-8 canonical-operation JSON document, such as the output of ra-daemon emit-envelope. Original duplicate keys, non-finite numbers and oversized/non-regular files are rejected before IPC.",
            }
        },
        "required": ["envelope_path"],
        "additionalProperties": False,
    },
}
