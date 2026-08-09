# Phase 3 — Safe native IPC and daemon: gate closeout

**Date:** 2026-08-05
**Repo:** /home/sikmindz/Coding/recursive-agent
**HEAD:** 3805f7abf319e07e47f1c20b862e614c3dad164f (dirty working tree, uncommitted)
**Rust:** rustc 1.97.1

## Claim (narrow, evidence-bounded)

The daemon now provides bounded, versioned, authenticated native IPC that serves
the canonical `RuntimeService`. A fresh daemon can submit the Phase 2 native
action over the socket and the resulting run strictly verifies through the same
runtime path. This is a material step toward the Phase 3 gate, not a claim of
Phase 3 completeness.

## What passed (direct tool output)

| Gate | Result | Evidence path |
|---|---|---|
| daemon all-targets tests | 22/22 ok | `docs/receipts/phase-3/task-3.3-request-id-budget/daemon-tests.txt` and task dirs |
| workspace all-targets | exit 0, 44 ok-blocks, 0 parent panics | `task-3.3-ipc-submit-gate/workspace.txt` |
| clippy -D warnings (workspace) | 0 | `task-3.3-ipc-submit-gate/clippy.txt` |
| fmt --check | 0 | `task-3.3-ipc-submit-gate/fmt.txt` |
| ipc submit+status+verify e2e | 3/3 ok | `task-3.3-ipc-submit-gate/ipc-gate.txt` |

## Deliverables implemented this session

1. **Request-id budget** (Task 3.3): `MAX_REQUEST_IDS_PER_CONNECTION`,
   `IpcDecodeError::RequestIdLimitExceeded`, budget-checked `admit`.
2. **Socket safety** (Task 3.2): `socket.rs` — private 0600 socket under a
   validated current-UID, non-writable runtime root; refuses to unlink
   non-socket/foreign nodes; `SO_PEERCRED` peer principal via nix.
   Tests: `tests/socket_safety.rs` (7).
3. **IPC server** (Task 3.3): `server.rs` — bounded accept loop, per-connection
   peer auth against daemon UID, per-connection request-id tracking, concurrency
   cap, dispatch to `RuntimeService` (`status` + `submit`).
   Tests: `tests/ipc_runtime.rs` (3), including the Phase 3 gate submit-over-IPC.
4. Updated the Phase 1 forward-guard
   (`contracts/tests/hardening_v5_quarantine.rs`) to the Phase 3 boundary: the
   daemon IS wired to runner/ledger but is not an execution/scheduler/run-root
   owner.

## Phase 3 gate assessment — core demonstrated, not yet admitted

The plan's Phase 3 gate requires: "A fresh daemon serves the Phase 2 action over
authenticated native IPC, survives malformed clients, and returns the same strict
verification result as embedded mode."

- Serves Phase 2 action over authenticated IPC: **demonstrated** (submit test).
- Survives malformed clients: **demonstrated** — `daemon_survives_malformed_and_oversized_clients`
  sends an oversized length prefix, non-JSON garbage, and a partial-frame
  disconnect, then verifies a fresh valid request is still served.
- Same strict verification as embedded: **demonstrated for the terminal status
  path**; the daemon relies on the shared `RuntimeService` so parity is structural.

Remaining before Phase 3 is admitted (do not claim otherwise):
- disconnect/cancel deterministic-result test (the runtime's active cancellation
  is a Phase 5 concern; this session only proves terminal-path behavior and
  that a dropped connection never crashes the daemon);
- independent hostile read-only review of the new socket/server surfaces.

`max_concurrent=1` serialization and slow-reader independence are now covered
by `max_concurrent_one_denies_second_connection` and
`slow_reader_does_not_block_other_clients` (evidence in
`task-3.3-concurrency-residuals/`).

## Blocker / degraded

- `cargo fuzz --version` -> "no such command". Per the plan, absence is a
  BLOCKED gate, not a pass; fuzzing is a Phase 11 deliverable and was not
  attempted here.
- `cargo deny check` and `cargo audit` both exit 0 on the current tree (recorded
  as observed; Phase 11 re-verifies against the installed schema).

## Rollback

All Phase 3 files are untracked/new crates or uncommitted edits under
`crates/recursive-agent-daemon/` plus one guard-test edit under
`crates/recursive-agent-contracts/tests/`. No data, committed history, or remote
was touched. Discard the daemon crate and revert the guard test to restore the
pre-Phase-3 tree.
