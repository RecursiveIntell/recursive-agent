# Phase 001 — daemon-witnessed Hermes result

## Entry

- Current source and dirty boundary recorded in `PRECHECK.json` and `OWNER_MAP.yaml`.
- Existing daemon tests pass.
- Plugin-suite baseline failure is recorded: normal pytest collection treats the hyphenated plugin directory as a non-package and fails relative imports.

## Allowed implementation paths

- `crates/recursive-agent-daemon/src/protocol.rs`
- `crates/recursive-agent-daemon/src/server.rs`
- `crates/recursive-agent-daemon/tests/`
- `integrations/hermes-native/{__init__.py,client.py,plugin.yaml,tests/}`
- this run packet

## Actions

1. Add a strict `verify` IPC request keyed by an authoritative run ID.
2. Render only RuntimeService verification facts on the response wire.
3. Change the plugin client to require daemon-provided verification facts; remove the adapter-synthesized `run:<id>` receipt reference.
4. Extend real-daemon plugin E2E assertions and exact protocol coverage.
5. Use an explicit test import mode/collection boundary; do not weaken relative imports in the production plugin loader.

## Acceptance

- `verify` cannot be decoded with unknown fields or client-provided verification state.
- A real daemon run returns daemon-derived terminal status plus `verified: true` and a chain fact.
- The plugin cannot return a success-shaped response if verification is absent, false, or malformed.
- Existing pack export/verify/replay is executed separately through `ra pack`/the clean-process gate.

## Stop conditions

- Any change needs Hermes core changes, a new evidence database, provider/network access, or a direct adapter-to-filesystem verification implementation.
- Runtime verification cannot be represented without inventing a wire value.

## Rollback

Revert this phase's tracked source files as one atomic unit. Do not leave a plugin client that expects an IPC variant not present in the daemon protocol.
