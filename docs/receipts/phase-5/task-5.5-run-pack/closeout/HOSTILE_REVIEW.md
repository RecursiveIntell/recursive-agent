# Task 10 hostile review — Auditable Run Pack v1

**Mode:** read-only source inspection plus independently executed acceptance gates.

## Scope

- `recursive-agent-contracts`: pack boundary types and canonical validation.
- `recursive-agent-ledger`: export planning, filesystem safety, manifest binding, transactional publication, and pack-only verification.
- `recursive-agent-runner`: recorded-evidence replay projection.
- `recursive-agent-cli`: translation-only operator commands.
- Task 10 documentation and claim boundary.

## Findings

### H-01 — destination publication could overwrite a concurrently-created destination (resolved)

- **Severity:** high before remediation; resolved before certification.
- **Affected surface:** `export_run_pack_with_interruption` publication step.
- **Evidence:** the pre-review publication used `renameat` after a separate `ensure_destination_absent` check. A process could create an empty destination between those operations, allowing ordinary rename replacement.
- **Consequence:** an export could replace an unrelated concurrent empty destination, violating the declared non-destructive destination contract.
- **Root cause:** check-then-act publication.
- **Fix applied:** `crates/recursive-agent-ledger/src/lib.rs` now publishes with `rustix::fs::renameat_with(..., RenameFlags::NOREPLACE)`. The existing precheck remains diagnostic only; the kernel no-replace operation is the authority at publication.
- **Acceptance evidence:** `cargo test -p recursive-agent-ledger --test run_pack_export` passed after the change; the full Task 10 gate also passed. Existing destination file, empty directory, nonempty directory, symlink, dangling symlink, and FIFO cases are covered by the focused test.
- **Residual / rollback:** this is Linux/rustix `RENAME_NOREPLACE` behavior. A deterministic post-precheck contention harness is still absent; do not replace `renameat_with(...NOREPLACE)` with ordinary rename. Revert only the Task 7–10 source/docs set if necessary.

## No unresolved critical or high defect found

Static inspection found the canonical boundary checks at:

- contracts manifest path/duplicate rejection: `crates/recursive-agent-contracts/src/lib.rs:387-427`;
- ledger contained, no-follow read and digest/length binding: `crates/recursive-agent-ledger/src/lib.rs:1124-1149`;
- ledger rejects symlinks/non-regular files and missing/extra files before strict chain verification: `crates/recursive-agent-ledger/src/lib.rs:1195-1284`;
- runner replay accepts a verified pack snapshot and builds only a recorded-evidence projection: `crates/recursive-agent-runner/src/lib.rs:1828-1861`;
- CLI calls ledger/runner owners and serializes their results: `crates/recursive-agent-cli/src/main.rs:490-542`.

The review also scanned the changed production crates for unsafe blocks and panic/TODO/unimplemented macros. No executable instances were found; the one `panic!` hit is documentation text in the contracts crate.

## Evidence limits

- Test success is locally reproduced, not a production/security certification.
- The clean-process acceptance test uses `strace` on this host to inspect replay process/network syscalls. It proves this bounded test scenario, not all kernels, platforms, providers, or future code paths.
- An Agent Graph council (`run-19fe8fd34d7-e`) supplied an advisory that identified H-01. Its claims were treated as unverified until live source inspection confirmed the race and the controller applied/retested the no-replace fix.
