"""recursive-agent Hermes integration — standalone plugin.

Only exposes one non-overriding tool ``recursive_agent_execute`` in the
``recursive_agent`` toolset. No Hermes core is modified, no MCP is used, and no
behavior is configured through new environment variables.
"""

from __future__ import annotations

import os
from pathlib import Path

from .client import check_socket_available, submit_and_status, DaemonClientError
from .schema import RECURSIVE_AGENT_EXECUTE_SCHEMA

# The tool name must not collide with any built-in; Hermes rejects a name that
# another toolset already claims unless the operator explicitly allows an
# override. We deliberately use a unique name and never request an override.
TOOL_NAME = "recursive_agent_execute"
TOOLSET = "recursive_agent"

# The plugin reads its socket location from config.yaml (surfaced here via the
# caller-supplied config), not from a new env var. A sane default points at the
# daemon's private runtime root under the user's home.
DEFAULT_SOCKET_PATH = str(
    Path(os.path.expanduser("~"))
    / ".local"
    / "share"
    / "recursive-agent"
    / "run"
    / "ra.sock"
)


def _resolve_socket(ctx) -> str:
    """Resolve the daemon socket path from plugin config, falling back safely."""
    try:
        cfg = getattr(ctx, "config", None) or {}
        plugins_cfg = cfg.get("plugins", {}).get("entries", {}).get(
            "recursive-agent-native", {}
        )
        sock = plugins_cfg.get("socket_path")
        if sock:
            return str(sock)
    except Exception:
        pass
    return DEFAULT_SOCKET_PATH


def check_recursive_agent_available(ctx=None) -> bool:
    """Service-gate: the tool is only callable when the private socket exists
    and answers the version probe. This prevents the model from invoking a
    dead or missing daemon."""
    socket_path = _resolve_socket(ctx) if ctx is not None else DEFAULT_SOCKET_PATH
    return check_recursive_agent_available_stub(socket_path)


def check_recursive_agent_available_stub(socket_path: str) -> bool:
    """Direct socket-path variant used by tests and callers that already
    resolved the daemon socket."""
    try:
        return check_socket_available(socket_path)
    except DaemonClientError:
        return False


def _handler(ctx, args, **kwargs) -> str:
    """Submit a canonical envelope (from the daemon emitter) and return status."""
    socket_path = _resolve_socket(ctx) if ctx is not None else DEFAULT_SOCKET_PATH
    envelope_path = str((args or {}).get("envelope_path", ""))
    if envelope_path:
        try:
            import json as _json

            with open(envelope_path, encoding="utf-8") as _f:
                envelope = _json.load(_f)
        except (OSError, ValueError) as error:
            return f"recursive_agent_execute: unavailable: cannot read envelope: {error}"
    else:
        return "recursive_agent_execute: unavailable: envelope_path required"
    try:
        result = submit_and_status(socket_path, envelope)
    except DaemonClientError as error:
        return f"recursive_agent_execute: unavailable: {error}"
    return (
        f"recursive_agent_execute: state={result['state']} "
        f"run_id={result['run_id']} receipt={result['receipt_ref']}"
    )


def register(ctx) -> None:
    """Register the single non-overriding tool (Hermes plugin loader entry)."""
    ctx.register_tool(
        name=TOOL_NAME,
        toolset=TOOLSET,
        schema=RECURSIVE_AGENT_EXECUTE_SCHEMA,
        handler=_handler,
        check_fn=check_recursive_agent_available,
        description=(
            "Submit one bounded recursive-agent native action and return "
            "terminal status plus a receipt reference."
        ),
        emoji="\u2699\ufe0f",
    )
