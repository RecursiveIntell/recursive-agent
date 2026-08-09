# Independent Hostile Phase 2 Admission Review

Verdict: ADMIT  
Phase 3 may begin: YES

- **Scope:** Read-only Phase 2 admission review at `main`, HEAD `3805f7abf319e07e47f1c20b862e614c3dad164f`.
- **Worktree:** Intentionally dirty; no files modified or created by the auditor.

## Evidence

- Exact source manifest:
  - 76 records confirmed.
  - Manifest SHA-256: `e193c1238194e4aca58d31946d3b38a23f2255ee4f48e6e0312b5590bb2122ab`.
  - `sha256sum -c docs/receipts/phase-2/closeout/source-manifest-v1.sha256`: **exit 0; all 76 records OK**.
- Controller receipt:
  - SHA-256 matches claimed `b1c09aa8bccc1395f128c6bddf5ae47ab9407334661e03fa29105f845d316884`.
  - Recorded aggregate status: `GREEN`.
- Phase 2 focused gates:
  - Native vertical test with `--test-threads=1`: **exit 0**.
  - Native vertical test with default parallelism: **exit 0**.
  - Tool-runtime boundary tests: **2 passed, exit 0**.
  - Workspace operation-envelope and runtime-event tests: **all passed**.
- Native vertical test exercised the real:
  - operation validation and identity derivation;
  - policy/permit authorization;
  - sandbox enforcement;
  - admitted tool-runtime dispatch;
  - `/usr/bin/printf`;
  - committed event projection and streaming;
  - artifact persistence/readback and digest validation;
  - strict receipt-chain verification.
- Static production-path audit:
  - No direct `recursive_agent_tools::execute` dispatch outside the named legacy runner executor.
  - Legacy `run_spec` and `run_spec_with_clock` are deprecated wrappers that construct the V1 envelope and route through `RuntimeService`.
  - The only additional `Command::new` occurrence found in production outside the runner sandbox was in `recursive-agent-memory`, but it is inside `#[cfg(test)]` test code and is excluded by the Phase 2 gate.
  - Effectful `Command::new` calls in `sandbox_engine.rs` remain inside the runner-owned runtime path.

## Findings

No Phase 2 admission-blocking defects found.

### Informational caveat — workspace-wide concurrent-test instability

- **Severity:** Informational / non-Phase-2
- **Evidence:** The independent `cargo test --workspace --all-targets --all-features` invocation returned exit `101` because:
  - `recursive-agent-ledger/tests/crash_recovery.rs` briefly reported a child-process race failure;
  - `recursive-agent-runner/tests/hardening_v3.rs` briefly reported `SandboxFailed` instead of `TimedOut`.
- The focused crash-race test and timeout test were rerun independently and both passed with exit `0`.
- The nested crash-recovery output includes expected child-process failure diagnostics while the outer harness ultimately passes; those expected child failures are not controller failures.
- **Consequence:** This does not invalidate the Phase 2 gate, which is the embedded proof plus static call-path audit, but it remains suite-level concurrency/flakiness debt.
- **Fix/acceptance:** Stabilize or isolate the affected concurrent tests; require repeated clean workspace runs with exit `0`.
- **Rollback:** None required for admission; no source changes were made.

## Commands run

- Manifest verification: **exit 0**
- Native vertical serial test: **exit 0**
- Native vertical default-parallel test: **exit 0**
- Tool-runtime boundary test: **exit 0**
- Workspace all-targets/all-features test: **exit 101 on one concurrent run**
- Rerun of affected crash-race test: **exit 0**
- Rerun of affected timeout test: **exit 0**

Source generation **matched exactly**.
