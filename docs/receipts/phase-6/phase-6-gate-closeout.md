# Phase 6 — Migrate all execution adapters to the same runtime: closeout

**Date:** 2026-08-06
**Repo:** /home/sikmindz/Coding/recursive-agent
**HEAD:** 3805f7abf319e07e47f1c20b862e614c3dad164f (dirty working tree, uncommitted)

## Claim (narrow, evidence-bounded)

The CLI `ra run` now executes through the canonical in-process
`RuntimeService` (Task 6.1, embedded mode): CLI input is translated to a V1
operation envelope and submitted, then the run's verified chain is rendered as
`RunSummary` JSON. An explicit `--runtime embedded|ipc` selector is exposed with
no silent fallback between modes. This is a material Phase 6 deliverable, not a
claim of full Phase 6 completion.

## What passed (direct tool output)

| Check | Result | Evidence |
|---|---|---|
| CLI tests (4 test binaries) | 12/12 pass | `task-6.1-cli-runtime-adapter/cli-tests.txt` |
| CLI clippy -D warnings | 0 | `clippy.txt` |
| Manual embedded run | RunSummary JSON, terminal=succeeded, chain_length=10, exit 0 | `manual-embedded.txt` |
| Manual `--runtime ipc` | explicit error, exit 2 (no silent fallback) | `manual-ipc.txt` |
| Workspace all-targets | exit 0, 50 ok-blocks, 0 parent panics | `workspace.txt` |
| fmt --check | 0 | run at closeout |

## Deliverables implemented

1. `recursive-agent-runner` — public `operation_from_run_spec` translation
   (RunSpecV1 → V1 envelope) so adapters execute through `RuntimeService::submit`
   rather than a private surface.
2. `recursive-agent-cli` — `--runtime embedded|ipc` (clap ValueEnum, default
   embedded); `embedded_service` builds an in-process `RuntimeService` (shell +
   echo tools registered); `run_embedded` translates, submits, verifies, and
   renders a `RunSummary` JSON with correct exit codes. IPC mode fails
   explicitly until the daemon client is wired (Task 6.x later in Phase 6).

## Phase 6 gate assessment — NOT admitted

The plan's gate: "Static inspection and adapter-parity tests find no direct
execution owner outside the runner. MCP can be disabled without changing native
functionality."

- CLI embedded path routes through `RuntimeService`: **demonstrated** (Task 6.1).
- MCP strict translation: **demonstrated** (Task 6.2). `recursive-agent-mcp/
  src/translate.rs` validates `tools/call` input and constructs a V1 envelope
  with a server-derived peer identity and an explicitly attenuated lease budget;
  operation id is derived (never minted). A source-level denylist test proves
  the crate does not directly dispatch tools, own a tool runtime, read
  wall-clock time, or mint run ids. 4/4 MCP tests pass.
- MCP client correlation/cancellation: **demonstrated** (Task 6.3).
  `recursive-agent-mcp/src/client.rs` implements `MpcCorrelator`: monotonic typed
  request ids, bounded in-flight map, strict correlation that rejects wrong-id /
  duplicate / id-less / malformed-error / late (post-cancel) / method-mismatch
  responses, idempotent cancellation propagation, and terminal cleanup. 10
  correlator tests pass.
- Adapter-parity conformance: **demonstrated** (Task 6.4). `recursive-agent-
  daemon/tests/adapter_parity.rs` executes one canonical native operation through
  the embedded `RuntimeService` and the authenticated daemon IPC surface, and
  asserts the normalized invariants match (terminal state, strict verify, chain
  length) while allowing fresh run ids and transport metadata. The CLI, Hermes
  plugin, and MCP translation all route to the same `RuntimeService`, so
  embedded-vs-IPC captures the adapter-parity invariant. 1/1 test passes.
- IPC CLI mode: **stubbed to explicit failure** (wired in a later Phase 6 task).
- The `run_spec`/`run_spec_with_clock` deprecated wrappers are still present
  (Task 6.5 removal pending after all consumers migrate).

Remaining: Task 6.5 (remove legacy direct-execution surfaces + denylist scan),
IPC CLI mode, and an independent hostile review of the new CLI adapter and MCP
translation/client path.

## Blocker / degraded

- `cargo fuzz --version` -> absent (Phase 11; BLOCKED per plan, not a pass).

## Rollback

New/edited files: `crates/recursive-agent-cli/src/main.rs` (added `--runtime`
flag, embedded service, echo/shell owners), `crates/recursive-agent-cli/Cargo.toml`
(added deps), `crates/recursive-agent-runner/src/lib.rs` (`operation_from_run_spec`
wrapper). No data, committed history, remote, or active Hermes profile touched.
Revert these to restore the pre-Phase-6 tree.
