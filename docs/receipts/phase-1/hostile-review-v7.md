# Hostile Review v7 — Phase 1 Admission Audit

## Scope and authority

- Repository: `/home/sikmindz/Coding/recursive-agent`
- Branch: `main`
- Retained HEAD: `3805f7abf319e07e47f1c20b862e614c3dad164f`
- Scope: fresh hostile, read-only admission audit of controller-v11's exact source generation; policy/permit/ledger/lifecycle, executable-byte and ownership invariants, ingress, sandbox launch, and CLI/daemon/MCP quarantine.
- Source-tree mutation: none except this report. No format, commit, push, install, service start, or configuration change.
- Normal Cargo target artifacts were permitted and were produced by local verification.

## Generation identity gate

The identity gate was run first. It **passed** and therefore the remainder of this audit is against the intended controller-v11 source generation, not an inferred or historical snapshot.

- `sha256sum controller-verification-v11/manifest.json`: `4e263f68e97f64c7ab76c8574c565c81dfac40fc1e283885aa60f60f74933d1f` — matches expected.
- `source-files.sha256` records checked: **50/50 match**; no missing or mismatched record.
- Source-generation digest (SHA-256 of `source-files.sha256`): `7ee5c380b93a023389d6cf119baa0a8fbbf3958f434ce710e0eaaabf8d0f8a0d` — matches expected.
- `git diff --binary HEAD | sha256sum`: `972b79ca5a03a5178ab9120d238a24e5098e6f41dcf1129eb8f232083a81312c` — matches controller-v11 expected tracked-binary diff digest.
- Worktree is intentionally dirty; current HEAD and source records agree with controller-v11.

## Evidence classification

- **Observation:** statements below derived from current source, not v6 prose.
- **Locally reproduced:** commands in this report were run during this audit; their exit codes are recorded exactly.
- **Controller-reported:** v11 receipt counts/output hashes are retained evidence only. They are not substituted for local checks.

## Four v6 blockers — current disposition

### 1. Pre-Bubblewrap hostile environment — CLOSED; no blocking finding

**Observation:** `spawn_bash_trampoline` uses `posix_spawn` with an explicit fixed environment at `crates/recursive-agent-runner/src/sandbox_engine.rs:1267-1275`: `PATH=/usr/bin:/bin`, `LANG=C`, and `LC_ALL=C`. It does not inherit the caller environment. Bubblewrap's later argv also includes `--clearenv` and an explicit PATH at `:1312-1317`. The source scan found no production `BASH_ENV`, `LD_PRELOAD`, or `LD_LIBRARY_PATH` use.

**Locally reproduced:** `cargo test -p recursive-agent-cli --all-targets` passed `hostile_launcher_environment_cannot_execute_before_sandbox`; the focused CLI ingress suite passed 8/8, including the hostile launcher test. The runner containment suite passed its launcher/environment and fail-closed cases locally as part of the workspace run.

**Acceptance evidence:** hostile environment is replaced before the Bash trampoline is spawned, and the inner Bubblewrap environment is cleared again before payload execution. No blocker remains. Later phases must not weaken the fixed environment or reintroduce shell trampoline inheritance.

### 2. Post-spawn kill/reap and EINTR — CLOSED; no blocking finding

**Observation:** after spawn at `sandbox_engine.rs:938-949`, the returned `ChildGuard` remains owned through every subsequent `?` path. Parent validation at `:958-969` occurs while the guard owns the child; `supervise` errors at `:970-983` also unwind through the guard. `ChildGuard::Drop` at `:414-423` tries `try_wait`, then kills and waits. POSIX wait wrappers at `:367-388` retry `waitpid` on `EINTR`; `supervise` performs explicit kill-then-wait at `:1493-1524` for revocation and timeout.

**Locally reproduced:** `cargo test -p recursive-agent-runner --lib child_guard_kills_and_reaps_on_early_return -- --nocapture` exited 0 (1/1). The workspace run also passed `post_spawn_parent_revocation_kills_and_reaps_before_effect` and the guard regression (8 runner unit tests and containment tests passed).

**Acceptance evidence:** the guard is structurally present for early returns, and EINTR loops are explicit. No blocker remains. A future change that calls `disarm()` before all post-spawn error-producing operations is a quarantine trigger.

### 3. Parent CLOEXEC and child-only authority transfer — CLOSED; no blocking finding

**Observation:** authority descriptors are opened with CLOEXEC (`sandbox_engine.rs:595`, `:620`, `:1200-1208`). `spawn_bash_trampoline` uses `PosixSpawnFileActions` and same-FD `add_dup2(fd, fd)` at `:1230-1236`; it never clears parent flags. The parent descriptor flags are explicitly checked by the focused test at `:1682-1685`, while sibling visibility is probed at `:1686-1700`. There is no `inherit_fd`, `fcntl_setfd`, or `pre_exec` path.

**POSIX/libc independent check:** a temporary `/tmp` C probe compiled with the host compiler and executed against the target libc. It opened fd 3 as `O_CLOEXEC`, applied `posix_spawn_file_actions_adddup2(&actions, 3, 3)`, and the child reported `fd3_flags=0 cloexec=0`; runtime exit was 0. This independently confirms the target runtime's same-FD spawn action clears CLOEXEC in the child while the controller's Rust test checks the parent remains CLOEXEC. This is consistent with POSIX `posix_spawn_file_actions_adddup2` semantics and Austin Group Issue 411; raw `dup2(fd,fd)` is not being used as the implementation mechanism.

**Locally reproduced:** `cargo test -p recursive-agent-runner authority_descriptors_remain_cloexec_and_do_not_leak_to_siblings -- --nocapture` exited 0 (1/1). The source scan for child-only transfer exited 0, and the full containment suite passed 13/13.

**Acceptance evidence:** no sibling/global inheritance window is present in current source. No blocker remains. Do not replace `posix_spawn` file actions with parent-side CLOEXEC toggling; that would reopen the race.

### 4. Strict ingress, sibling multi-step objects, complete semantic ceilings — CLOSED; no blocking finding

**Observation:** current contracts use the contract-owned recursive duplicate-safe visitor at `crates/recursive-agent-contracts/src/lib.rs:434-513`, then canonicalize and enforce aggregate material bytes at `:516-543`. `validate_ingress_spec` at `:575-613` enforces nonempty bounded identifiers, max 4 steps, unique sibling step names, tool allowlist, and per-step argument ceilings. Shell validation at `:675-726` enforces command/argument/path byte ceilings, collection cardinality, duplicate roots, network denial, and both nonzero bounded timeout/output ceilings. The former `parse_with_dup_check` path is absent from current source. The runner performs boundary and allowlist validation before run-root creation at `crates/recursive-agent-runner/src/lib.rs:318-340`.

**Locally reproduced:** `cargo test -p recursive-agent-contracts --test hardening_v6_ingress -- --nocapture` exited 0, 5/5, including valid sibling objects reusing field names and all semantic ceilings. The CLI ingress tests passed 8/8, including valid multi-step decode/execute and rejection-before-run-creation cases.

**Acceptance evidence:** valid sibling multi-step objects are admitted; duplicate object keys, duplicate step names, unknown fields, over-limit collections/strings/time/output, invalid paths, network requests, and empty semantics reject before effects. No blocker remains. Any future decoder change must preserve original-byte duplicate detection and pre-run side-effect ordering.

## Cross-cutting invariants inspected

- **Policy/permit/attenuation:** controller-v11 focused policy and lifecycle receipts report cumulative child-budget, issue/consume, expiry/revocation, and parent-binding gates passing. Locally, workspace tests passed policy attenuation (4/4) and permit lifecycle (7/7); lifecycle validation passed 8/8. These are local reproductions of behavior, not claims about later-phase readiness.
- **Ledger/crash/artifact:** controller-v11 reports one expected nested losing subprocess race diagnostic while its enclosing Cargo command exits 0. Locally, the workspace command itself exited 0; its raw output contained the expected inner losing `two_process_append_race_has_one_predecessor_owner` diagnostic followed by a passing rerun and enclosing test result. This was not treated as a clean 100%-pass transcript; the enclosing exit status was recorded separately as the gate authority, per v11 manifest notes. Artifact tamper tests passed 8/8 and lifecycle validation passed 8/8 locally. The retained controller receipt for the focused crash-recovery command reports exit 0, failed count 1, passed 10, matching the documented nested-race behavior.
- **Executable-byte authority and ownership:** current runner source hashes/validates executable bytes, pins descriptors, rejects path-component escapes, and revalidates source identity before transfer. Local executable-byte tests passed 4/4 and containment tests passed 13/13. No source scan found a second production process owner: controller-v11's process-owner scan exited 0 and local scans found process creation confined to runner sandbox code (plus memory's test-only process probe).
- **Lifecycle/receipt ownership:** current runner opens chain/store/permit state from the pinned run-root descriptor (`runner/src/lib.rs:346-359`) and verifies identity consistency before durable work. Controller-v11 source scans for child-store reopen, dispatch-token serialization, bounded ledger reads, and unsafe/lint escapes all exited 0. Local workspace tests and strict Clippy passed.
- **CLI/daemon/MCP quarantine:** controller-v11 quarantine scans for CLI and daemon exited 0. Locally, workspace tests passed CLI quarantine (2/2), terminal exit (2/2), daemon pure decoding (3/3), MCP compiled with no effect tests, and public effect-surface checks passed. Current source keeps daemon decoding-only and MCP protocol-only; no claim is made that later daemon/MCP phases are complete.

## Independent command log

All commands below were run from `/home/sikmindz/Coding/recursive-agent` during this audit.

1. `git rev-parse HEAD; git status --porcelain=v1; git diff --stat HEAD` — exit 0.
2. Manifest/source-record Python verification; `git diff --binary HEAD | sha256sum` — exit 0; all 50 records match; all expected digests match.
3. `cargo fmt --all -- --check` — exit 0.
4. `git diff --check` — exit 0.
5. `cargo test -p recursive-agent-contracts --test hardening_v6_ingress -- --nocapture` — exit 0; 5 passed.
6. `cargo test -p recursive-agent-runner --lib child_guard_kills_and_reaps_on_early_return -- --nocapture` — exit 0; 1 passed.
7. `cargo test -p recursive-agent-runner authority_descriptors_remain_cloexec_and_do_not_leak_to_siblings -- --nocapture` — exit 0; 1 passed.
8. `cargo test --workspace --all-targets` — enclosing exit 0; 135 tests reported passed by the retained/current run output, with the documented nested losing crash-recovery race diagnostic. The final enclosing test result was successful.
9. `cargo clippy --workspace --all-targets -- -D warnings` — exit 0.
10. Host compiler/libc POSIX same-FD probe in `/tmp` — compile exit 0; runtime exit 0; child observed CLOEXEC cleared (`fd3_flags=0 cloexec=0`).
11. Source scans for environment inheritance, process ownership, wait/EINTR, child-only FD transfer, ingress ceilings, quarantine, and unsafe/lint escapes — exit 0 for the asserted gates.

## Findings

**No blocking findings established in the current exact source generation.** The four v6 blockers are closed by current source plus focused local reproduction. The intentionally dirty tree, retained controller evidence, and nested race diagnostic remain constraints on the claim: this is Phase 1 admission only, not evidence that Phase 2 or later adapter/daemon/integration phases are complete.

## Rollback/quarantine note

No implementation rollback was performed because this was read-only. If any admission invariant regresses, quarantine Phase 1 immediately, reject Phase 2, and revert/quarantine the change that introduces the regression; do not replace child-only descriptor transfer, fixed launcher environment, guard ownership, or pre-effect ingress validation with compatibility fallbacks.

Verdict: ADMIT
Phase 2 may begin: YES
Admitted source-generation digest: 7ee5c380b93a023389d6cf119baa0a8fbbf3958f434ce710e0eaaabf8d0f8a0d
