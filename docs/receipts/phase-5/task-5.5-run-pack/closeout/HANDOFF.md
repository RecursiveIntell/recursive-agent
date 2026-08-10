# Auditable Run Pack v1 — Task 10 handoff

## Certified boundary

For the local test matrix, an already-verified terminal run can be exported into a portable Run Pack. The pack manifest binds every packed file; verification reads pack bytes only and reuses strict ledger receipt/artifact/lifecycle validation; replay is recorded evidence only.

This handoff does not claim production readiness, provider-backed execution/replay, remote execution, deployment, hosted operation, or general security certification.

## Auditor rerun commands

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p recursive-agent-ledger --test run_pack_plan
cargo test -p recursive-agent-ledger --test run_pack_export
cargo test -p recursive-agent-ledger --test run_pack_verify
cargo test -p recursive-agent-ledger --test run_pack_provenance
cargo test -p recursive-agent-runner --test run_pack_replay
cargo test -p recursive-agent-cli --test run_pack_cli
cargo test -p recursive-agent-cli --test run_pack_clean_process
./scripts/verify-run-pack.sh
git diff --check
```

## Required environmental fact

The shell acceptance wrapper requires `strace`; it returns exit `69` and a `BLOCKED` message if unavailable. The recorded closeout run observed `/usr/bin/strace` version 7.0.

## Evidence and scope discipline

- `CHANGE_RECEIPT.json` is the closeout status record; it supersedes the scaffold's incomplete top-level receipt for Task 10 status only.
- `HOSTILE_REVIEW.md` distinguishes inspected source from executed results.
- `GIT_STATUS_AFTER.txt` records foreign dirty/untracked material and must not be staged merely to create a clean tree.
- No commit, push, merge, publish, deploy, reset, or deletion is included in this closeout.
