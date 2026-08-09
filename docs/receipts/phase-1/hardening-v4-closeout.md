# Phase 1 Hardening Pass 4 Closeout

Recorded: 2026-08-05 (America/Chicago)  
Repository: `/home/sikmindz/Coding/recursive-agent`  
Branch: `main`  
HEAD: `3805f7abf319e07e47f1c20b862e614c3dad164f`  
Phase status: rejected pending controller hostile admission  
Disposition: **controller hostile admission required**

This pass addresses only the four admission blockers in `hostile-review-v4.md`. It does not admit Phase 1 and does not advance Phase 2.

## RED evidence

- R1: `docs/receipts/phase-1/hardening-v4/R1/red.txt`
- R2: `docs/receipts/phase-1/hardening-v4/R2/red.txt`
- R3: `docs/receipts/phase-1/hardening-v4/R3/red.txt` and `R3/red-false-spec.json`
- R4: `docs/receipts/phase-1/hardening-v4/R4/red.txt`

Each receipt predates its corresponding source fix and records the rejected public execution surface, admitted impossible permit chain, success-shaped CLI failure, or split pathname-root construction.

## Blocker disposition

### R1 — runner-private one-shot effect boundary

- The Bubblewrap/Bash/seccomp process engine is owned only by private runner module `sandbox_engine`.
- The public sandbox crate is plan/result/evidence types plus pure validation; it exports no process-launch function.
- Policy consumption returns typed durable `PermitEvidenceV1`. The runner converts consumed evidence into a private, by-value, non-Clone, non-serde `DispatchToken` that the private engine consumes once.
- All real containment cases traverse `run_spec`; sandbox package tests are pure plan/API tests.
- A downstream compile-fail test proves no public sandbox executor exists. The canonical runner test proves reopening the same deterministic run does not start a second process.
- Doctor truth now says `runner-private one-shot dispatch`; daemon availability is not claimed.

### R2 — continuous permit transition truth

- Canonical ledger validation retains permit ID, binding digest, purpose, issuance window, and observed transition state for each step.
- Issued/consumed/rejected/revoked evidence must preserve identity, binding, purpose, ordering, receipt binding, and valid time.
- Effect artifact/completion/success requires a consumed effect permit; rejected or revoked effects cannot become successful.
- Reconciliation, append validation, expected-run verification, directory-bound verification, and verified snapshots call the same authoritative sequence validator.
- Eight negative cases exercise mismatched IDs, mismatched bindings, early/late consumption, pre-issue revoke, terminal contradiction, revoked-success fabrication, and valid-time mismatch through every strict public verifier plus append-time validation.

### R3 — truthful CLI and daemon transport

- `RunSummary` always serializes `terminal_state` and pinned run-root identity.
- `ra run` emits stable JSON and exits 1 for every non-success terminal; argument/spec transport errors remain exit 2.
- Real-binary tests cover false, signal/no-code, timeout, stdout overrun, and stderr overrun, then strictly verify each retained non-success run.
- Daemon preparation returns a typed envelope separating `transport_ok`, operation terminal state, valid run identity, and typed error.
- The active CLI `serve` command and daemon availability claim are removed. The daemon crate remains unexposed preparation code for later review.

### R4 — one pinned run-root owner and strict readback

- Runner opens one private `PinnedRunRoot` using component-wise no-follow descriptor-relative operations.
- Ledger, artifact, and permit handles derive from that descriptor. Artifact and permit child stores have no pathname reopen constructor.
- Ledger/artifact/permit root lineage is checked by device/inode. Child ownership and group/world write modes are bounded.
- Final summaries come only from expected-run strict verification and artifact readback through the retained pinned descriptor, followed by locator inode comparison.
- Private deterministic hooks prove directory and symlink replacement before authorization cause zero dispatch; post-dispatch plausible-directory replacement keeps all stores on the original inode and verifies it, but locator mismatch cannot return success.
- Trusted system executables must be regular, executable, non-group/world-writable, and either root-owned or descriptor-observed on a read-only filesystem. This admits the immutable UID-remapped system image without admitting a writable non-root executable.

## Source paths changed by Pass 4

- `Cargo.toml`, `Cargo.lock`
- `crates/recursive-agent-cli/Cargo.toml`
- `crates/recursive-agent-cli/src/main.rs`
- `crates/recursive-agent-cli/tests/terminal_exit.rs`
- `crates/recursive-agent-contracts/tests/phase1_effect_surface.rs`
- `crates/recursive-agent-contracts/tests/workspace_lints.rs`
- `crates/recursive-agent-daemon/Cargo.toml`
- `crates/recursive-agent-daemon/src/lib.rs`
- `crates/recursive-agent-ledger/Cargo.toml`
- `crates/recursive-agent-ledger/src/lib.rs`
- `crates/recursive-agent-ledger/tests/artifact_tamper.rs`
- `crates/recursive-agent-ledger/tests/crash_recovery.rs`
- `crates/recursive-agent-ledger/tests/lifecycle_validation.rs`
- `crates/recursive-agent-policy/Cargo.toml`
- `crates/recursive-agent-policy/src/lib.rs`
- `crates/recursive-agent-policy/tests/permit_lifecycle.rs`
- `crates/recursive-agent-runner/Cargo.toml`
- `crates/recursive-agent-runner/src/lib.rs`
- `crates/recursive-agent-runner/src/sandbox_engine.rs`
- `crates/recursive-agent-runner/tests/canonical_containment.rs`
- `crates/recursive-agent-runner/tests/permit_dispatch.rs`
- `crates/recursive-agent-sandbox/Cargo.toml`
- `crates/recursive-agent-sandbox/src/lib.rs`
- `crates/recursive-agent-sandbox/tests/public_surface.rs`
- `crates/recursive-agent-tools/Cargo.toml`
- `crates/recursive-agent-tools/src/lib.rs`
- `docs/receipts/phase-1/hardening-v4/**`
- `docs/receipts/phase-1/hardening-v4-closeout.md`

The repository was already dirty and shared. Unrelated current work and pre-existing receipts were preserved. No commit, stage, reset, restore, clean, checkout, rebase, history/config mutation, service/config installation, live Hermes mutation, network call, provider call, or secret read was performed.

## Source generation and retained controller evidence

- Source-generation SHA-256: `3910002dbdfdabd55174019781dcd03580908d2999edaa9393f00e4f9f08e1b2`
  - Construction: SHA-256 of sorted per-file SHA-256 records for `Cargo.toml`, `Cargo.lock`, and every regular file below `crates/`.
- Tracked binary diff SHA-256: `79f7ef36a527339ab1f1795ebec4bd400d02067b3b26466b036756fa279868a7`
  - Scope: `git diff --binary -- Cargo.toml Cargo.lock crates`.
- Controller manifest SHA-256: `5326bd0e47f8b0abdcdbde035ce3de3233580c2f0feec4086a4b9fe7a8a7cb24`.
- Controller manifest: `docs/receipts/phase-1/hardening-v4/controller-verification/manifest.json`.
- Release-gate proof packet: `docs/receipts/phase-1/hardening-v4/release-gate-workbench/evidence-workbench-20260805T091653Z.json`.
- Release-gate packet SHA-256: `bb8f8c3d3a3759bef3c6b3abc496dd3b76fae9d161bf34efd28043d4c3b6ab1d`.

The workbench packet's `promote` disposition applies only to its three command receipts. It does not supersede this closeout disposition or admit Phase 1.

## Required controller matrix

Every command exited 0. Per-command combined-output hashes and byte counts are retained in the controller manifest and corresponding `.txt` receipt.

| Command | Tests passed | Output SHA-256 |
|---|---:|---|
| `cargo fmt --all -- --check` (pre) | 0 | `6d3d6760d3a4510ca5eefd0657057e1b07437d52fec6c66ebcebee70cfd3c503` |
| `cargo test -p recursive-agent-contracts --all-targets` | 11 | `1c1573b69bac2660dda35b29c3c09a2889dd5ccf9876134aad0b6091c8b0dd7f` |
| `cargo test -p recursive-agent-policy --all-targets` | 7 | `768a4b31c424903b25d5d003302403ce72bc1b6bb71ac56b9d2f537a7cecb76e` |
| `cargo test -p recursive-agent-ledger --all-targets` | 26 | `f74cd4ebb9d71acd50f42e7d15342b189bfcc06d3e11809989e167efd4f47dde` |
| `cargo test -p recursive-agent-sandbox --all-targets` | 2 | `e2484d276c7429de533005341bd006f3926bdb47dc9dd1d396cf2244d0ac6d62` |
| `cargo test -p recursive-agent-provider --all-targets` | 11 | `64a1fbc1c918ea28c046e0395910c3aa93fe720ba12187e37708bd2c54c25597` |
| `cargo test -p recursive-agent-runner --all-targets` | 31 | `ee51ecf3b14e7e5253131df588b1cbe4445499bf3ef20e471901170e96795d15` |
| `cargo test -p recursive-agent-tools --all-targets` | 8 | `3b1dffdcec74407ba625d700be924a56342081735ffe4ca88b813e14d64c665b` |
| `cargo test -p recursive-agent-cli --all-targets` | 4 | `20051f887fa32e78d47c56a4a8b430281bb9ca8cebf2a839fa53764fce1fc948` |
| `cargo test -p recursive-agent-daemon --all-targets` | 3 | `c109c36b98a30cbd90843e9d2c06cb324943e6efe901d1a86779c35377ced389` |
| `cargo test --workspace --all-targets` | 116 | `ea9435325eb5432b2ad2cc4b55ab94819dab160b14452feb652b47e346f47450` |
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 | `9a8597391c1d9235dfe601f64cfd7c4236ff8f9b7dc465db86a01482b2e2da56` |
| `cargo fmt --all -- --check` (post) | 0 | `4d27d6d7657109b8712c3859b6c2ec3b3fc677489a470c40a4a948c965f6bd99` |
| `git diff --check` | 0 | `91c1271139dfd4f1eef92454188d909454ccfed261489267e87728dc67a5cf5e` |

The ledger crash-recovery race deliberately runs one losing inner harness that prints a failure before the enclosing regression proves exactly one predecessor owner and exits successfully. Test totals count successful enclosing harnesses, matching Cargo's command exit.

## Focused gates and scans

All exited 0. Exact commands, counts, byte lengths, and output hashes are in the manifest.

- Public effect API and workspace lint inheritance: 1 + 1 tests.
- Canonical containment and one-shot replay prevention: 13 tests.
- Pinned-root directory/symlink/post-dispatch races: 3 tests.
- Canonical permit continuity/temporal negatives: 8 tests.
- Real CLI terminal/exit matrix: 2 tests.
- Typed daemon envelope matrix: 3 tests.
- Deterministic IDs: 6 tests.
- Crash recovery: 10 successful enclosing tests.
- Replay/artifact replacement and bounded-read races: 8 tests.
- Memory corruption: 6 tests.
- Provider secret/endpoint quarantine: 7 tests.
- Skill traversal/replacement: 5 tests.
- Doctor truth: 1 test.
- Downstream sandbox compile-fail surface: 1 doctest.
- Source scans prove process launch is runner-private; dispatch token is not reusable/serde; child stores have no pathname reopen; authoritative verification/readback is bound and bounded; no production unsafe/lint override/ignored test exists; and later CLI capabilities remain quarantined.

## Residual risks

1. Controller hostile admission has not run. Green candidate receipts are not admission.
2. The real containment suite is Linux/Bubblewrap/libseccomp specific. Unsupported platforms remain fail-closed and require separate controller evidence before admission there.
3. The daemon crate remains prototype preparation code. It is intentionally unreachable from the default operator CLI pending the later IPC phase.
4. The shared worktree remains dirty and uncommitted. Source and diff digests bind this candidate generation; later edits require a new matrix and new receipts.

## Rollback and quarantine

- No Git history or index operation was performed, so there is no commit-level rollback artifact. Reverting must be a deliberate file-scoped edit that preserves unrelated dirty work; broad reset/restore/clean operations remain prohibited.
- Provider networking, MCP client spawn, runtime memory, skills, delegation, MCTS, and daemon operator exposure remain unavailable or unexposed in default Phase 1 production paths.
- Recorded replay remains provider-free and does not re-execute tools.

**Disposition: controller hostile admission required**
