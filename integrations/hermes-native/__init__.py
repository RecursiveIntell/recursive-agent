"""recursive-agent Hermes integration — standalone plugin.

Only exposes one non-overriding tool ``recursive_agent_execute`` in the
``recursive_agent`` toolset. No Hermes core is modified, no MCP is used, and no
behavior is configured through new environment variables.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

try:
    from .client import (
        DaemonClientError,
        DaemonRunFailure,
        check_socket_available,
        submit_and_status,
    )
    from .schema import RECURSIVE_AGENT_EXECUTE_SCHEMA
except ImportError:
    # Pytest and Hermes both load this directory by path, so it may be
    # executed without a conventional package parent. Keep that loader mode
    # explicit rather than making test collection depend on import ordering.
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from client import (
        DaemonClientError,
        DaemonRunFailure,
        check_socket_available,
        submit_and_status,
    )
    from schema import RECURSIVE_AGENT_EXECUTE_SCHEMA

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
    """Read the plugin-owned setting; invalid intent must not reroute IPC."""
    sock = ctx.get_config("socket_path") if ctx is not None else None
    if sock is None:
        return DEFAULT_SOCKET_PATH
    if not isinstance(sock, str) or not sock.strip() or "\x00" in sock:
        raise ValueError("recursive-agent-native socket_path must be a nonempty path string")
    return sock


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


_MAX_ENVELOPE_INPUT_BYTES = 1024 * 1024


def _closed_envelope_pairs(pairs):
    value = {}
    for key, member in pairs:
        if key in value:
            raise ValueError("duplicate operation-envelope member")
        value[key] = member
    return value


def _reject_envelope_constant(_value):
    raise ValueError("non-finite JSON is not an operation envelope")


def _read_envelope_file(path: str) -> dict:
    """Bound the original UTF-8 regular-file ingress before normalizing JSON."""
    import stat

    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_ENVELOPE_INPUT_BYTES:
            raise ValueError("operation envelope must be a bounded regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(_MAX_ENVELOPE_INPUT_BYTES + 1)
        if len(raw) > _MAX_ENVELOPE_INPUT_BYTES:
            raise ValueError("operation envelope exceeds its byte bound")
    finally:
        os.close(descriptor)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_closed_envelope_pairs,
                       parse_constant=_reject_envelope_constant)
    if type(value) is not dict:
        raise ValueError("operation envelope must be a JSON object")
    return value


def _handler(ctx, args, **kwargs) -> str:
    """Submit a canonical envelope and return daemon-derived terminal facts.

    Successful results use a versioned JSON response because callers may need
    the exact daemon-owned ``run_dir`` for a CLI-owned Run Pack operation.
    Terminal failures use the same JSON result channel with ``verified: false``
    plus raw daemon status/verification mappings; transport failures remain
    ``unavailable``. Presentation text is not an interchange format.
    """
    if type(args) is not dict or not args.get("envelope_path"):
        return "recursive_agent_execute: unavailable: envelope_path required"
    if set(args) != {"envelope_path"} or type(args["envelope_path"]) is not str:
        return "recursive_agent_execute: unavailable: invalid arguments (envelope_path only)"
    envelope_path = args["envelope_path"]
    try:
        if len(envelope_path.encode("utf-8")) > 4096 or "\x00" in envelope_path:
            raise ValueError("invalid envelope_path")
        envelope = _read_envelope_file(envelope_path)
    except (OSError, ValueError, RecursionError) as error:
        return f"recursive_agent_execute: unavailable: cannot read envelope: {error}"
    socket_path = _resolve_socket(ctx) if ctx is not None else DEFAULT_SOCKET_PATH
    try:
        result = submit_and_status(socket_path, envelope)
    except DaemonRunFailure as error:
        return json.dumps(
            {
                "schema": "recursive-agent.hermes-result/v1",
                "state": "terminal",
                "run_id": error.run_id,
                "run_dir": error.run_dir,
                "verified": False,
                "failure": {"code": error.code, "message": str(error)},
                "status": error.status,
                "verification": error.verification,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    except DaemonClientError as error:
        return f"recursive_agent_execute: unavailable: {error}"
    try:
        verification = result["verification"]
        state = result["state"]
        run_id = result["run_id"]
        run_dir = result["run_dir"]
        verified = verification["ok"]
        chain_length = verification["length"]
        final_head = verification["final_head"]
    except (KeyError, TypeError):
        return "recursive_agent_execute: unavailable: daemon verification facts missing"
    return json.dumps(
        {
            "schema": "recursive-agent.hermes-result/v1",
            "state": state,
            "run_id": run_id,
            "run_dir": run_dir,
            "verified": verified,
            "chain_length": chain_length,
            "final_head": final_head,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def register(ctx) -> None:
    """Register the single non-overriding tool (Hermes plugin loader entry)."""
    # Hermes dispatches registered handlers as ``handler(args, **kwargs)``.
    # Capture the registration context here so socket configuration remains
    # available without exposing a non-conforming two-argument handler.
    def handler(args, **kwargs) -> str:
        return _handler(ctx, args, **kwargs)

    ctx.register_tool(
        name=TOOL_NAME,
        toolset=TOOLSET,
        schema=RECURSIVE_AGENT_EXECUTE_SCHEMA,
        handler=handler,
        check_fn=lambda: check_recursive_agent_available(ctx),
        description=(
            "Submit one bounded recursive-agent native action and return "
            "daemon-derived terminal status plus strict verification facts."
        ),
        emoji="\u2699\ufe0f",
    )
    # Default/off adds no governor or lifecycle hook and remains loadable by
    # existing standalone-tool hosts without the new core dispatch seam.
    mode = ctx.get_config("governance_mode")
    if mode is not None and mode != "off":
        from .governor import register_governor
        register_governor(ctx)
