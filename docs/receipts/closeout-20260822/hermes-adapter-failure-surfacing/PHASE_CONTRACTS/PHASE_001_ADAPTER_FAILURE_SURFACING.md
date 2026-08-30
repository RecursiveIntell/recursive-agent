# Phase 001 — Adapter failure surfacing

## Goal

When a daemon run reaches a terminal non-success or strict verification rejects its evidence, preserve the daemon-owned status and verification payload through the Hermes-native adapter instead of collapsing it into `unavailable`.

## Allowed paths

- `integrations/hermes-native/client.py`
- `integrations/hermes-native/__init__.py`
- `integrations/hermes-native/tests/test_registration.py`
- `crates/recursive-agent-daemon/src/server.rs`
- `crates/recursive-agent-daemon/tests/ipc_runtime.rs`
- this run packet

## Forbidden paths

- Rust runner/runtime owner code
- operation/schema contracts
- credentials, deployment, gateway, plugin installation, or unrelated dirty paths

## Invariants

1. The daemon remains the only authority for terminal state and verification.
2. Transport failures remain `DaemonClientError` / unavailable.
3. Daemon dispatch errors return a correlated structured error response instead of silently closing the IPC connection.
4. A terminal run failure is a typed adapter failure carrying raw daemon-derived status and verification mappings.
5. The plugin must return a structured non-success result for a terminal run, with `verified: false`; it must not call it unavailable.
6. No fallback evidence, inferred receipt, or success field may be synthesized.
7. Existing successful result shape remains unchanged.

## RED acceptance

Add tests for a failed terminal status and strict-verification rejection before production edits. The tests must fail because current code raises a generic error and the plugin labels the result unavailable.

## GREEN acceptance

- typed failure preserves `run_id`, `run_dir`, status payload, verification payload, and a stable failure code;
- plugin output includes daemon-derived terminal state and verification details with `verified: false`;
- transport/unavailable behavior remains unchanged;
- focused pytest and Ruff pass.

## Rollback

Revert only the three allowed source/test files in this phase. Remove this additive run packet if quarantining the attempt. Do not reset the repository.
