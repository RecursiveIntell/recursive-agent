# Phase 1 hardening-v5 controller closeout candidate

Generated: 2026-08-05T10:39:11Z  
Branch: `main`  
HEAD: `3805f7abf319e07e47f1c20b862e614c3dad164f`  
Worktree: intentionally dirty and uncommitted

## Disposition

**Candidate only — awaiting independent hostile admission.** This document does not admit Phase 1 or authorize Phase 2.

Latest complete controller evidence: `docs/receipts/phase-1/controller-verification-v9/manifest.json`

- manifest SHA-256: `469c1fd8a397ca14cdc4b11e3691146a3fdd4b3c89720076784b3e07aa974137`
- source-generation SHA-256: `85e7aed739fd292cc87a70f56b3391b351d86b765552bc44b8fea908bbc0e943`
- tracked binary-diff SHA-256: `b7a38853fc611128a42f4b95156cce2a5e50f6a9d91058d3c0b7d76a5ec82277`
- workspace tests reported by controller: 124 passed, 0 failed
- required matrix, focused gates, strict Clippy, formatting, diff checks, and ownership/quarantine scans: all exit 0

Controller-v6 predates hardening-v5 and is superseded. Controller-v7 failed because its daemon-quarantine scan still required removed prototype text; the scan was corrected to assert the pure bounded decoder and reject listener, thread, runtime, process, permit-store, and receipt surfaces. Controller-v8 was green, but a subsequent controller spot audit found that the descriptor walker dropped `ParentDir` while Bubblewrap retained the original destination. Controller-v9 is the first complete green matrix after that authority/path repair.

## Controller-authored fixes after interrupted worker

1. **Canonical boundary on original bytes**
   - `parse_run_spec_bytes` now invokes `boundary_compiler::parse_with_dup_check` on the original UTF-8 input before typed deserialization.
   - The bounded recursive visitor still classifies duplicate keys and enforces depth/node/string limits; typed deserialization rejects unknown and trailing material.

2. **Crash-recoverable child allocation**
   - Parent allocation is calculated from a proposed map where the child permit ID is inserted/replaced once, preventing idempotent retry from double-counting a reservation left by interruption.
   - Existing child records are reconciled against the parent allocation.
   - Added a regression that removes the child state after parent reservation and proves retry restores it with exactly one allocation.

3. **Truthful post-dispatch authority time**
   - Post-dispatch parent validation and effect terminal receipts use one wall-clock observation.
   - If wall time has already passed parent expiry before child issuance, the runner writes explicit bounded denial evidence and a `Denied` step/run terminal instead of returning an internal invalid-lease error.
   - The adversarial advancing/rollback clock test passes.

4. **Strict-Clippy cleanup without lint suppression**
   - Reduced the Linux sandbox function argument count by deriving the constant launcher path locally.
   - Renamed hook variants to remove redundant enum prefixes.
   - No `allow`, `warn`, `expect`, ignored-test, or unsafe suppression was introduced.

5. **Daemon quarantine evidence**
   - Phase 1 daemon surface is pure `decode_run_spec(&[u8])` over the canonical bounded ingress parser.
   - The controller scan rejects listener/socket/thread/process/runtime/permit/receipt ownership in the daemon.

6. **Supply-chain configuration repair**
   - `deny.toml` was updated for cargo-deny 0.19.8.
   - `cargo deny check` exits 0 with advisories, bans, licenses, and sources all reported `ok`.
   - Duplicate versions remain warnings. Cargo-fuzz is still unavailable and is not claimed complete.

7. **Descriptor/destination path agreement**
   - A RED public-runner regression proved that a write root such as `/tmp/a/../b` was not rejected before run creation.
   - The prior descriptor walk dropped `ParentDir`, potentially opening `/tmp/a/b` while Bubblewrap interpreted the declared destination as `/tmp/b`.
   - The walker now accepts only `RootDir` plus `Normal` components and rejects `CurDir`, `ParentDir`, or prefixes before opening the source descriptor.
   - The regression proves typed preparation rejection and zero run-root creation; all four executable/path hardening tests pass.

## Commands actually executed after final source repair

```text
cargo fmt --all
cargo test -p recursive-agent-runner --test hardening_v5_executable_bytes -- --nocapture
cargo clippy -p recursive-agent-runner --all-targets -- -D warnings
git diff --check
cargo deny check
RA_PHASE1_CONTROLLER_OUT=docs/receipts/phase-1/controller-verification-v9 python3 docs/receipts/phase-1/hardening-v4/controller-verification/run_matrix.py
```

All commands in the final focused/controller-v9 sequence exited 0. The controller-v9 command itself reran pre/post formatting checks, every crate and workspace target, strict workspace Clippy, focused gates, diff checking, and ownership/quarantine scans; see its manifest for exact subcommands and hashes. Earlier red and failed iterations remain preserved in temporary logs and prior evidence; they are not represented as green.

## Exact executable evidence spot audit

Static controller inspection observed:

- executable-role paths opened read-only using Linux `openat2` with `BENEATH`, `NO_SYMLINKS`, and `NO_MAGICLINKS`;
- regular executable, bounded length, executable mode, owner/mount mutability admission;
- byte digest calculated from the retained readable descriptor;
- command, Bash trampoline, and Bubblewrap descriptor identities and byte digests bound into effective-policy evidence;
- Bubblewrap receives command and Bash through `--ro-bind-fd` and executes the descriptor-mounted command path;
- the Bash trampoline closes every inherited descriptor above 2 except the explicit Bubblewrap/mount/seccomp allowlist before exec;
- timeout or parent-authority loss kills and reaps the supervised child;
- setup proof is required before enforcement is reported as successful.

These are source-inspection observations, not a substitute for hostile admission.

## Remaining limitations and gates

- Independent hostile review v6 is required and may reject this candidate.
- Phase 2 must not begin unless that review explicitly returns `ADMIT`.
- `cargo fuzz` is not installed; fuzz execution remains a Phase 11 blocker.
- No commit, push, deploy, live Hermes configuration change, daemon/service launch, or no-MCP Hermes action was performed.
- Later-phase daemon, MCP, memory, skills, delegation, and MCTS capabilities remain quarantined or prototype claims.
