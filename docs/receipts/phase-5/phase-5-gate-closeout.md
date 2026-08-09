# Phase 5 — Durable scheduling, cancellation, recovery, honest replay: closeout

**Date:** 2026-08-06
**Repo:** /home/sikmindz/Coding/recursive-agent
**HEAD:** 3805f7abf319e07e47f1c20b862e614c3dad164f (dirty working tree, uncommitted)

## Claim (narrow, evidence-bounded)

The runtime now has a durable scheduler control projection with real
process-boundary restart recovery (Task 5.1) and durable, idempotent
cancellation semantics through the runtime owner (Task 5.2, first slice). This
is material Phase 5 progress, not a claim of the full Phase 5 gate.

## What passed (direct tool output)

| Task | Result | Evidence path |
|---|---|---|
| 5.1 scheduler store unit tests | 4/4 | `docs/receipts/phase-5/task-5.1-scheduler-store/scheduler-tests.txt` |
| 5.1 restart recovery (real process boundary) | 1/1 | same file |
| 5.2 cancellation semantics | 3/3 | `docs/receipts/phase-5/task-5.2-cancellation/cancellation.txt` |
| runner clippy -D warnings | 0 | both receipts |
| workspace all-targets | exit 0, 47 ok-blocks, 0 panics | both receipts |
| fmt --check | 0 | both receipts |

## Deliverables implemented

1. `recursive-agent-runner/src/scheduler.rs` — `SchedulerStore`: durable
   JSON-file control projection with admit (idempotent), acquire_lease
   (exclusive, conflict-typed), request_cancel (idempotent), advance_cursor,
   set_terminal, quarantine. Rebuildable projection, not receipt truth.
2. `tests/restart_recovery.rs` — child process mutates the store then aborts;
   parent reopens and asserts all rows recovered exactly with no silent
   duplication.
3. `RuntimeService` — optional `with_scheduler` (non-breaking), and
   `RuntimeCancelResultV1` now expresses `CancellationRequested { run_id }` in
   addition to `AlreadyTerminal`. `cancel()` persists a durable cancel flag when
   a scheduler is attached.
4. `tests/cancellation.rs` — durable + idempotent cancel, typed terminal /
   requested / unavailable results.

## Phase 5 gate assessment — NOT admitted

The plan's gate: "The Hermes E2E proof passes with daemon restart before
terminal readback, cancellation tests pass, and offline verification/replay does
not touch network or providers."

- Scheduler store restart recovery: **demonstrated** (Task 5.1).
- Cancellation: **durable flag + process-group descendant kill demonstrated**.
  `RuntimeService.cancel()` durably records the cancel flag when a scheduler is
  attached; the sandbox now spawns each child as its own process-group leader
  (`posix_spawnattr_setpgroup(0)`) and kills the whole group
  (`killpg`) on timeout/cancel. `sandbox_timeout_kills_descendant_process_group`
  proves a backgrounded child that would write a marker after the timeout never
  writes it. True mid-execution async cancellation (interrupting a running
  submit before it completes) is still not reachable through the synchronous
  `RuntimeService.cancel()` API.
- Resume from verified step boundaries (Task 5.3): **demonstrated**.
  `resume_from_verified_boundary` strictly verifies a parent run and, on
  success, `continuation_envelope` builds a causally-linked continuation with
  Delegated authority carrying parent/root lineage (no in-place mutation of the
  parent). A tampered parent boundary is a typed
  `ResumeFromUnverifiedBoundary` error (never a silent resume). `tests/
  resume_boundary.rs` 2/2.
- Idempotent submission + explicit replay classes (Task 5.4): **done**.
  `ReplaySummary` carries an explicit `ReplayCapability`
  (`Deterministic` / `RecordedEvidence` / `Unavailable`); a strictly-verified
  run reports `RecordedEvidence`, a tampered run reports `Unavailable` or a
  typed Err. `RuntimeService::idempotent_submit` binds the canonical request
  digest to a caller-supplied idempotency key in the durable scheduler store:
  an exact duplicate returns the prior handle (no re-execution), the same key
  with a different operation is a typed `IdempotencyKeyConflict`, and a fresh
  key admits + executes once; without a scheduler it is a typed
  `IdempotentSubmissionUnavailable`. `tests/idempotent_submit.rs` 3/3.
- Offline verify/replay touching no network: verified — `replay()` never
  invokes tools or providers (it is recorded-evidence projection).

Remaining for Phase 5 admission: true mid-execution async cancellation (the
durable cancel flag and process-group descendant kill are in place, but
interrupting a running synchronous submit is not yet reachable through the API),
the Phase 5 gate E2E (daemon restart before terminal readback), and an
independent hostile review of the new scheduler/cancel/replay/resume/idempotency
surfaces.

## Blocker / degraded

- `cargo fuzz --version` -> absent (Phase 11; BLOCKED per plan, not a pass).
- `RuntimeServiceError::StatePoisoned` is used to map scheduler-store failures;
  a dedicated typed error (e.g. `SchedulerStore` error) is more honest and
  should replace it before Phase 5 admission.

## Rollback

All Phase 5 files are new/untracked or edits under `crates/recursive-agent-runner/`
(`src/scheduler.rs`, `tests/restart_recovery.rs`, `tests/cancellation.rs`, and
`src/runtime.rs` changes). No data, committed history, remote, or active Hermes
profile was touched. Discard the new files and revert `runtime.rs` to restore
the pre-Phase-5 tree.
