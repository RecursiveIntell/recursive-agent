# Hostile Read-Only Review + Gate Closeout — Recursive Agent Phase 3

**Date:** 2026-08-06 (updated)
**Repo:** /home/sikmindz/Coding/recursive-agent
**HEAD:** 3805f7a (uncommitted workspace)
**Audited surface:** `crates/recursive-agent-daemon/` (socket.rs, server.rs,
protocol.rs, lib.rs, bin/ra-daemon.rs) + tests.

## Phase 3 gate status: ADMITTED (verified green 2026-08-06)

| Gate | Result (live) |
|---|---|
| workspace test `--all-targets` | **exit 0** (212 pass, 0 real failures) |
| workspace clippy `-- -D warnings` | **exit 0** |
| fmt `--all --check` | **exit 0** |
| daemon all-targets tests | **all pass** (3+5+6+4+7 + integration) |

### Correction of an earlier false negative
A prior review flagged `two_process_append_race_has_one_predecessor_owner` as
failing 8/8. That was a **misread of leaked child-process output**: the test
spawns two processes racing to append the ledger chain; the *expected loser*
child exits non-zero and prints a `test result: FAILED` line to inherited
stdout. The parent asserts `success == 1` and passes. Verified: the full
workspace cargo run exits 0 with zero panics/assertions anywhere. The test is
working as designed — exactly one process wins the append race.

## Hardening applied this session (from F-02..F-05 of the prior review)

All changes read in `crates/recursive-agent-daemon/`:

- **F-02 (HIGH): idle-connection DoS closed.** Added
  `CONNECTION_IDLE_TIMEOUT` (30s) applied to each accepted socket
  (`stream.set_read_timeout/set_write_timeout`). A silent/idle peer is now
  evicted instead of holding a `max_concurrent` slot forever.
- **F-03 (MEDIUM): accept-loop resilience.** `serve()` now matches on accept
  errors, logs them, and continues, instead of `?`-propagating (which would
  have torn down the whole daemon on a transient EMFILE/ENFILE).
- **F-04 (MEDIUM): stable wire contract.** Status `terminal_state` now emits
  the serialized `snake_case` discriminant (`succeeded`, `timed_out`, ...) via
  serde instead of Rust `Debug` repr. Embedded and IPC adapters use the same
  discriminant; parity test asserts `"succeeded"` on both.
- **F-05 (LOW): removed dead `MAX_INFLIGHT_PER_CONNECTION` constant.**

## What was verified sound (unchanged)

- Peer auth via `SO_PEERCRED` (kernel, non-forgeable), not client text.
- Framing bounds: length prefix admitted before payload alloc; oversized /
  truncated / trailing / partial-frame all handled; malformed-client survival
  demonstrated.
- Request-id budget (4096) + duplicate rejection.
- Strict JSON (duplicate-key reject), `deny_unknown_fields`, protocol version.
- Socket ownership: refuses non-socket/foreign/symlink nodes; 0600; private
  root.
- daemon owns no execution authority; dispatch goes through canonical
  `RuntimeService`.

## Remaining notes

- `cargo fuzz` absent → fuzzing is a Phase 11 deliverable, not a Phase 3 gate
  blocker (BLOCKED flag, deferred per plan).
- disconnect/cancel deterministic test is a Phase 5 concern; not claimed here.

## Rollback

Hardening changes are confined to `server.rs` (daemon) and test assertions
(`adapter_parity.rs`, `ipc_runtime.rs`). Discard those edits to restore the
pre-hardening daemon; nothing was committed, no remote touched.
