# Phase 4 — No-MCP Hermes vertical slice: gate closeout

**Date:** 2026-08-05
**Repo:** /home/sikmindz/Coding/recursive-agent
**HEAD:** 3805f7abf319e07e47f1c20b862e614c3dad164f (dirty working tree, uncommitted)

## Claim (narrow, evidence-bounded)

A standalone Hermes plugin now translates one real tool call to a canonical
native operation submitted over authenticated IPC to a live recursive-agent
daemon, and the run reaches a strictly-verified terminal state. The plugin is
reproducibly packageable and removable in an isolated `HERMES_HOME`. This is a
material Phase 4 deliverable, not a claim of full Hermes-native production
integration.

## What passed (direct tool output)

| Task | Result | Evidence path |
|---|---|---|
| 4.1 plugin registration + service gate | 4/4 Python tests | `docs/receipts/phase-4/task-4.1-plugin-registration/` |
| 4.2 real daemon E2E (submit over IPC) | 1/1 | `docs/receipts/phase-4/task-4.2-e2e/python-tests.txt` |
| 4.3 packaging install/uninstall round-trip | 1/1 | `docs/receipts/phase-4/task-4.3-packaging/` |
| Rust workspace (regression) | exit 0, 45 ok-blocks, 0 panics | `docs/receipts/phase-4/task-4.2-e2e/workspace.txt` |
| clippy -D warnings (daemon) | 0 issues | run in task-4.2 receipt |
| fmt --check | 0 | run in task-4.2 receipt |

## Deliverables implemented

1. `crates/recursive-agent-daemon/src/bin/ra-daemon.rs`:
   - `serve` — real executable daemon wiring `RuntimeService` (echo tool
     registered) to the authenticated IPC server.
   - `emit-envelope` — emits a canonical `OperationEnvelopeV1` whose
     `action_digest` is computed Rust-side (JCS + BLAKE3).
2. `integrations/hermes-native/`:
   - `plugin.yaml`, `__init__.py` (`register` + non-overriding
     `recursive_agent_execute` tool + service-gated `check_fn`), `schema.py`
     (`envelope_path` arg), `client.py` (real `submit_envelope` /
     `status_of_run` / `submit_and_status` over framed IPC).
   - `tests/` — registration, service gate, malformed-response rejection, real
     daemon E2E, and packaging round-trip (6 total).
3. `scripts/install-hermes-plugin.sh` / `uninstall-hermes-plugin.sh` —
   deterministic install with manifest and clean uninstall.

## Phase 4 gate assessment — core demonstrated, not yet admitted

The plan's gate: "The no-MCP Hermes E2E test is green and strict verification
independently succeeds."

- No-MCP Hermes E2E green: **demonstrated** — the real `ra-daemon` binary is
  spawned, a canonical envelope is emitted Rust-side, and the plugin's exact
  handler path submits it over authenticated IPC and reaches terminal state.
- Strict verification independently succeeds: **partial** — the terminal status
  is read back over IPC from the shared `RuntimeService`, but the E2E does not
  yet independently re-run `ra verify` on the produced run root, and it does
  not drive Hermes' *real plugin loader* (it drives the plugin's exact
  `register`/handler contract via a stub ctx + a live daemon, not a temp
  `HERMES_HOME` + `discover_plugins`).

Remaining before Phase 4 is admitted:
- run the E2E against a temporary `HERMES_HOME` with Hermes' real plugin loader
  (`discover_plugins`) so the tool lands in the real registry (the plan
  explicitly requires "invoke the plugin through Hermes's real plugin
  loader/tool registry", which the current test does not do);
- assert strict receipt verification independently (e.g. `ra verify`) on the
  submitted run;
- independent hostile read-only review of the plugin + daemon-bin surfaces.

## Blocker / degraded

- `cargo fuzz --version` -> absent. Per the plan, absence is a BLOCKED gate
  (Phase 11 concern), not a pass.
- The plugin's `receipt_ref` is `run:<run_id>`; the full receipt-chain readback
  is a Phase 5 deliverable.

## Rollback

All Phase 4 files are new/untracked: `crates/recursive-agent-daemon/src/bin/`,
`integrations/hermes-native/`, and `scripts/install-hermes-plugin.sh` /
`uninstall-hermes-plugin.sh`. No data, committed history, remote, or active
Hermes profile was touched. Discard these to restore the pre-Phase-4 tree.
