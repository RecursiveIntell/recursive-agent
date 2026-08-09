# Recursive Agent Phase 1 Hardening Pass 3 — Candidate Closeout

**Disposition: controller hostile review required**

**Phase status:** Phase 1 remains rejected pending controller hostile review. This is candidate controller evidence only. It does not advance Phase 2 and does not change any claim to complete.

## Scope and provenance

- Repository: `/home/sikmindz/Coding/recursive-agent`
- Branch: `main`
- HEAD: `3805f7abf319e07e47f1c20b862e614c3dad164f`
- Final code/manifests source-tree SHA-256: `7203d08baccaf226d56c9a889146153228484d8dfb7f5ac2f8fc57e0c55ca3df`
- Source-tree digest construction: SHA-256 of sorted per-file SHA-256 records for `Cargo.toml`, `Cargo.lock`, and every regular file below `crates/`. Documentation, `.hermes/`, and this closeout are excluded, so the receipt does not self-reference.
- Tracked binary-diff SHA-256 over `Cargo.toml`, `Cargo.lock`, and `crates/`: `b7b3387c85450ef999099a9e1e21b16443d93e63e001ff38445fe1846a4091df`.
- The repository was already dirty and contained untracked Phase work. It was preserved. No commit, push, stage, reset, restore, clean, checkout, rebase, history mutation, or Git configuration mutation was performed.
- No file under `.hermes/` or `/home/sikmindz/Coding/Libraries` was modified. No credential value was read. No provider or network call was made.
- Pre-change RED evidence is retained in `docs/receipts/phase-1/hardening-v3/R1/red.txt` through `R12/red.txt`.
- Machine-readable gate evidence: `docs/receipts/phase-1/hardening-v3/controller-verification/manifest.json`.
- Final scan evidence: `docs/receipts/phase-1/hardening-v3/source-scans.txt`.

## Candidate remediation

### R1–R3 — fixed trust chain and sealed effect boundaries

- Removed the same-owner helper from production and removed its binary target. The sandbox pins root-owned `/usr/bin/bash` and `/usr/bin/bwrap`, invokes Bash through its descriptor, passes only positional numeric descriptor data and Bubblewrap argv, closes every non-preserved descriptor above stderr, and executes the pinned Bubblewrap descriptor. Bash, Bubblewrap, command, operation/runtime roots, seccomp, authorization, and setup-proof identities are bound into effective-policy evidence.
- The mandatory malicious sibling executable can copy/read the nonce and run a direct marker if consulted; production never consults it, the marker remains absent, and the legitimate run is independently `Enforced`.
- `allow_network=true` is rejected by the Phase 1 policy boundary, sealed shell validation, and sandbox before dispatch. Network-disabled positive socket creation receives `EPERM` under `Enforced`.
- Public sandbox execution requires a sealed consumed `AuthorizedExecutionContext` and validates tool/call/actor/run/step/permit/effect/budget/root binding. Provider execution and MCP client spawn are absent from the default production surface. Runtime memory store mutation is test-private. Skills remain typed unavailable.

### R4–R8 — truthful terminal state, fresh leases, complete evidence, and replay snapshot

- Shell success now requires `Enforced`, no timeout, exit code exactly zero, and no truncation or dropped stdout/stderr bytes. Nonzero exit, signal/no-code, stdout overrun, stderr overrun, timeout, and sandbox failure all produce typed non-success step/run terminals; bounded failure observations may be stored without becoming successful observations.
- Runner-owned wall time is freshly sampled at validation, issue, consume, reject/revoke, step terminals, and run terminal transitions. A runner-owned monotonic deadline prevents wall-clock rollback from extending active authorization. Advancing/rollback clock regressions deny affected dispatch and strictly verify the non-success terminal.
- Stable receipt and permit identity material excludes live/recorded wall-clock observations. Persisted validity remains evidence, not identity entropy.
- Effective policy binds declared read/write roots with descriptor identities and access modes, runtime roots, command, Bash, Bubblewrap, seccomp, authorization, and setup proof. Wrong policy version and root identity/mode changes reject or change the policy digest.
- Permit issue/consume/reject/revoke receipts carry typed complete permit-evidence artifacts. Strict lifecycle verification validates evidence against durable material and neighboring receipts. Successful completion requires a matching observed artifact between step start and completion.
- All public authoritative strict verification is expected-run or directory-bound. The only unbound reader is explicitly legacy, non-authoritative inspection.
- Replay obtains one immutable, exact-byte verified snapshot under the pinned directory lock. It never reopens the receipt path. Append, truncate, replacement, and greater-than-64-MiB growth races terminate within bounds and cannot project bytes outside the verified snapshot.

### R9–R12 — strict quarantined boundaries and operator truth

- `CurrentMemoryId` validates the current family at all memory boundaries. Canonical identity includes namespace, key, content, provenance, and validity material. Test-private SQLite get/search decodes every row, recomputes identity, and returns typed corruption for wrong family/UUID, field mutation, null/invalid data, and mixed valid/corrupt results.
- `ValidatedEndpoint` is origin-only: HTTP(S), host, optional port, and root path. Userinfo, query, fragment, controls, and non-root paths are rejected without echoing a path sentinel. Provider routes are fixed typed implementation constants; provider execution remains unavailable.
- Every one of 13 workspace members inherits workspace lints exactly once. No local lint allowance or ignored/skipped test was introduced, and strict Clippy passes.
- `ra doctor` truthfully reports Phase 1 candidate/rejected status, Bubblewrap plus seccomp, pure `echo`/frozen `time_now`, sealed bounded `shell`, and every typed-unavailable surface.
- Skill IDs are validated single components. Registry reads are descriptor-relative, no-follow, bounded, and reject traversal, absolute paths, symlinks, and active replacement.

## Required controller matrix

Every authoritative invocation below was run after the final production-source change and exited `0`.

| Command | Passed / result |
|---|---:|
| `cargo fmt --all -- --check` | clean, pre-matrix |
| `cargo test -p recursive-agent-contracts --all-targets` | 11 |
| `cargo test -p recursive-agent-policy --all-targets` | 7 |
| `cargo test -p recursive-agent-ledger --all-targets` | 24 |
| `cargo test -p recursive-agent-sandbox --all-targets` | 14 |
| `cargo test -p recursive-agent-provider --all-targets` | 11 |
| `cargo test -p recursive-agent-runner --all-targets` | 13 |
| `cargo test -p recursive-agent-memory --all-targets` | 6 |
| `cargo test -p recursive-agent-tools --all-targets` | 8 |
| `cargo test -p recursive-agent-daemon --all-targets` | 2 |
| `cargo test -p recursive-agent-mcp --all-targets` | 0 (crate compiles; no default effect client or tests) |
| `cargo test -p recursive-agent-skills --all-targets` | 5 |
| `cargo test -p recursive-agent-mcts --all-targets` | 2 |
| `cargo test --workspace --all-targets` | 105 |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `cargo fmt --all -- --check` | clean, post-matrix |
| `git diff --check` | clean |

The ledger two-process race deliberately launches one losing child whose inner harness prints `FAILED`; the enclosing regression proves exactly one predecessor owner and the ledger package/workspace commands exit `0`.

## Focused admission evidence

Focused invocations also exited `0` and executed nonzero tests:

- Malicious sibling helper: 1 passed.
- Runner hardening suite: 4 passed, covering network/version zero dispatch, all terminal failures/overruns, advancing and rollback clocks, and replay snapshot races.
- Default effect API surface: 1 passed.
- Strict lifecycle/transplant suite: 7 passed.
- SQLite corruption: 1 passed.
- Endpoint secret/path contract: 7 passed.
- Workspace lint audit: 1 passed.
- Doctor snapshot: 1 passed.
- Skill traversal and active replacement: 2 separately selected tests passed.
- Root identity/access policy digest: 1 passed.

Package suites additionally retained the mandatory positive `/usr/bin/printf`, network `EPERM`, FD leak, timeout/descendant, mount replacement, and setup-proof assertions.

## Relevant changed paths

- Workspace dependency/lint surface: `Cargo.toml`, `Cargo.lock`, and all 13 member `Cargo.toml` files.
- Contracts/API audit: `crates/recursive-agent-contracts/src/lib.rs`, `tests/phase1_effect_surface.rs`, `tests/workspace_lints.rs`.
- Policy: `crates/recursive-agent-policy/src/lib.rs`, `tests/permit_lifecycle.rs`.
- Ledger: `crates/recursive-agent-ledger/src/lib.rs`, artifact/crash/lifecycle tests.
- Sandbox: `crates/recursive-agent-sandbox/src/lib.rs`, `tests/enforcement_truth.rs`; the custom helper source/target was deleted.
- Runner/tools: `crates/recursive-agent-runner/src/lib.rs`, all runner integration tests, `crates/recursive-agent-tools/src/lib.rs`.
- Provider: `crates/recursive-agent-provider/src/lib.rs`, `tests/secret_contract.rs`; effect implementation/dependency removed.
- Memory: `crates/recursive-agent-memory/src/lib.rs`; runtime store is default-surface quarantined.
- MCP: `crates/recursive-agent-mcp/src/lib.rs`, `protocol.rs`, `server.rs`; public client/spawn source removed.
- Skills: `crates/recursive-agent-skills/src/lib.rs`.
- Operator truth: `crates/recursive-agent-cli/src/main.rs` and doctor/direct-verification tests.
- Lint inheritance: daemon, MCP, MCTS, and skills manifests, plus the workspace audit.
- Evidence: `docs/receipts/phase-1/hardening-v3/` and this closeout.

## Exact residual risks and quarantine

- Controller hostile review remains mandatory. Local passing evidence is not admission and is not a Phase 1 completion claim.
- Positive containment was verified on this `x86_64` host with Bubblewrap `0.11.0`, libseccomp `2.6.0`, Rust `1.97.1`, and the current root-owned Bash/Bubblewrap descriptors. No other architecture, packaging layout, or host kernel is claimed.
- Provider calls, MCP client process spawn, runtime memory mutation/search, skill execution, delegation, and provider networking remain compiled absent or typed unavailable. Their retained data/pure surfaces do not authorize effects.
- Replay and receipt verification deliberately reject logs larger than 64 MiB. Artifact and skill reads have their own smaller explicit bounds.
- The receipt ID fixed vector changed because live `valid_time` was removed from stable identity material; it is now `v1:recursive-agent/receipt/v1:det:717174c5a3bc175818c01a2ed044e05b7aa8735e4fc0afa5b680c21d70fe855e`.
- The worktree contains preserved uncommitted/untracked Phase work predating this pass. A rollback must be controller-directed and path-scoped; a blanket restore/clean could destroy unrelated user work. No rollback or Git mutation was performed.
- Quarantine on rejection: retain all typed-unavailable effect boundaries, do not enable provider/MCP/memory/skills, and do not publish or rely on this candidate as authoritative admission evidence.

**Final disposition: controller hostile review required. Phase 1 remains rejected; Phase 2 remains out of scope.**
