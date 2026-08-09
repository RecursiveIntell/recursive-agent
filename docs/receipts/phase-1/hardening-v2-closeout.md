# Recursive Agent Phase 1 Hardening Pass 2 — Candidate Closeout

**Disposition:** controller review required

**Phase status:** Phase 1 remains rejected pending controller re-review. This document is candidate evidence only. It does not advance Phase 2 and does not alter any completion claim.

## Scope and provenance

- Repository: `/home/sikmindz/Coding/recursive-agent`
- Branch: `main`
- HEAD: `3805f7abf319e07e47f1c20b862e614c3dad164f`
- Tracked binary-diff SHA-256: `4430b9ee999b05a263905b0b0c334ab599c0eb71c31745d4503ce85f9292f344`
- Dirty-manifest SHA-256: `8c296775937181120b4eadafb7905e6b250cbd28ee9d22db5e4afea2103cf153`
- Dirty-manifest construction: SHA-256 over the tracked binary-diff hash plus sorted SHA-256 records for every untracked file, excluding this closeout so that the receipt can carry a stable pre-closeout digest.
- The pre-existing dirty worktree was preserved. No commit, stage, reset, restore, clean, checkout, rebase, history rewrite, or Git configuration mutation was performed.
- `hostile-review.md`, `hostile-rereview.md`, and `hardening-closeout.md` were checked with `git diff --exit-code`; exit was `0`.
- No files under `.hermes/` or `/home/sikmindz/Coding/Libraries` were changed. No credential values were read and no provider network call was made.

Strict pre-fix RED evidence is retained at:

- `docs/receipts/phase-1/hardening-v2/R1/red.txt`
- `docs/receipts/phase-1/hardening-v2/R2/red.txt`
- `docs/receipts/phase-1/hardening-v2/R3/red.txt`
- `docs/receipts/phase-1/hardening-v2/R4/red.txt`
- `docs/receipts/phase-1/hardening-v2/R5/red.txt`
- `docs/receipts/phase-1/hardening-v2/R6/red.txt`
- `docs/receipts/phase-1/hardening-v2/R7/red.txt`
- `docs/receipts/phase-1/hardening-v2/R8/red.txt`

## Candidate remediation summary

### R1 — unforgeable positive sandbox and local network denial

- `execute` is the only public production execution entry point. Launcher/runtime injection is private to same-module tests and cannot produce `Enforced` without the fixed trusted-launcher validation path.
- `/usr/bin/bwrap`, the fixed-purpose FD helper, and the trusted init are descriptor-pinned and validated as non-symlink regular executables with owner/mode constraints. The helper accepts only the pinned Bubblewrap descriptor and explicitly enumerated preserved descriptors, closes all other descriptors above stderr, then executes the pinned descriptor.
- The static marker was replaced with a per-execution 32-byte nonce. The trusted init writes proof as the first setup-channel bytes before payload execution; payload suffixes cannot satisfy the proof. Proof generation, setup, or verification failure is fail-closed.
- Bubblewrap uses mount/PID/session containment with `--unshare-all --share-net`. When network is denied, safe `libseccomp` APIs generate/export a native classic-BPF filter passed through `bwrap --seccomp FD`. The policy returns `EPERM` for native supported socket creation/communication calls and `io_uring_setup`. No handwritten BPF or local `unsafe` was added.
- Payload `/proc` is an empty directory, so host `/proc/net` is not exposed.
- Enforcement evidence now records the network mechanism, seccomp-policy digest and syscall set, reviewed runtime roots, trusted executable identities, setup-proof digest, and proof status. `network_isolated=true` is assigned only after the filter and trusted-init proof succeed.
- Mandatory `/usr/bin/printf`, Python socket-denial, undeclared-read/write, descendant-bound, and fake-launcher zero-dispatch regressions pass with `Enforced`; the positive tests do not accept fail-closed as success.

### R2 — descriptor-pinned mounts and explicit runtime roots

- Command, declared read/write roots, `/usr`, `/etc/ld.so.cache`, Bubblewrap, helper, and trusted init are opened once with safe no-follow descriptor APIs before spawn. Source descriptors are provided to Bubblewrap with its FD mount arguments.
- The effective policy and digest distinguish operation roots from reviewed runtime roots and bind pinned identities; there is no hidden readable host tree in the policy.
- Active file/directory/symlink replacement and runtime-sentinel tests assert that attacker replacements and undeclared paths are not exposed.

### R3 — actual budget/time enforcement

- Production lease validation uses runner-owned `SystemClock`; deterministic tests inject a `Clock`. Request `frozen_clock` is not trusted lease time.
- Permit identity uses typed `PermitIdentityMaterialV1`, binding digest, requested delay, and requested validity duration. Live issue/recording time is excluded from identity while the durable binding retains and validates issue, not-before, and expiry times against trusted now and the policy maximum.
- Successful durable permit consumption yields a bounded `AuthorizedExecutionContext`. The production tools API consumes that context and has no generic public unmetered dispatch closure.
- Shell receives wall-time and output limits through the sandbox. Returned observation/artifact bytes and elapsed time are checked. Actual elapsed and output overruns reject within bounds; pre-dispatch binding/expiry/revocation failures remain zero-dispatch.
- Current effectful allowlisting is restricted to bounded `shell` plus pure `echo` and bounded `time_now`. Provider, delegate, MCP call, skill, and memory effects return typed unavailable. Direct MCP `time_now` dispatch was removed; the MCP server currently exposes only pure `echo`.

### R4 — expected-run-bound exhaustive lifecycle

- `verify_expected_run` requires `CurrentRunId` and returns the verified run ID. Runner existing-run/readback paths call it; directory-bound CLI verification and replay bind the directory name to the verified run identity digest.
- Lifecycle validation now covers run start, permit issue/consume/reject/revoke, step start/complete/fail, artifact storage, run finalization, typed outcomes, prior states, and post-terminal prohibition.
- Append and offline verification reject whole-chain transplantation, rejection without issue, failed permit issue, denied failure after completion, finalization without start, duplicate/post-terminal authorization events, and mixed-run chains.

### R5 — stable ledger lock and direct recovery

- Serialization locks the pinned run-directory descriptor rather than reopening a replaceable `.ledger.lock` path.
- A single locked reconciliation routine is used by open, append, verification, replay/status verification, and CLI verification.
- Direct verification repairs a missing, stale, or partial `chain.meta` projection from the authoritative receipt log without a prior open/heal call. Failpoint, two-handle/process, root replacement, legacy lock-entry replacement, and direct `ra verify` crash-recovery tests pass.

### R6 — complete material identity boundary

- `memory_put` derives a deterministic domain-qualified `stack-ids` episode ID from canonical namespace/key/content/provenance material. Recording time remains non-identity metadata; identical material is idempotent.
- `derive_step_id` accepts `CurrentRunId`. `derive_permit_id` accepts only the complete typed permit identity material.
- Fixed identity vectors and a cross-process memory identity regression pass.
- Production source scans found no UUID/random/live-time authority or evidence ID minting. MCTS randomness remains the explicitly deferred Phase 10 algorithm concern and cannot mint current authority/evidence IDs.
- `memory_put` remains removed from the effectful allowlist pending controller acceptance of this boundary.

### R7 — bounded artifact and metadata reads

- Artifact bytes, descriptor metadata, chain metadata, and receipt logs use bounded streaming with a `max + 1` read and post-read rejection. Metadata has a separate small maximum.
- Concurrent-growing artifact/metadata and partial artifact/metadata tests terminate and reject beyond their bounds. A pre-read metadata length check is not treated as sufficient.

### R8 — validated provider ingress

- Public provider state uses `ValidatedEndpoint` with a private representation and validated construction/deserialization. Non-HTTP(S), userinfo/password, query, fragment, control, missing-authority, and malformed inputs fail before `ProviderSpecV1` exists.
- Direct invalid field construction is unavailable. `Debug` and `Serialize` operate only on normalized, validated, secret-free endpoints.
- CLI/tools migrations use the validated type. Constructor, JSON, Debug, serialization, tool-envelope, resolver-error, and invocation-error sentinel coverage passes.

## Focused hostile-re-review checks

Every command below exited `0` and executed the named regression (no zero-test selector is cited):

| Finding | Command | Observed assertion |
|---|---|---|
| Positive sandbox | `cargo test -p recursive-agent-sandbox --test enforcement_truth fixed_printf_is_mandatorily_enforced_on_this_host -- --exact --nocapture` | Fixed `/usr/bin/printf` returned the expected bytes with `Enforced`. |
| Network denial | `cargo test -p recursive-agent-sandbox --test enforcement_truth network_socket_creation_receives_eperm_under_enforcement -- --exact --nocapture` | Python socket creation returned errno `1` under `Enforced`. |
| Launcher spoof | `cargo test -p recursive-agent-sandbox --lib tests::fake_launcher_is_rejected_before_payload_dispatch -- --exact --nocapture` | The fake launcher and known-proof spoof were rejected with zero payload dispatch. |
| Mount replacement | `cargo test -p recursive-agent-sandbox --test enforcement_truth active_mount_source_replacement_never_exposes_attacker_bytes -- --exact --nocapture` | Active source replacement never exposed attacker bytes. |
| Actual budget | `cargo test -p recursive-agent-tools tests::actual_elapsed_time_is_enforced_before_dispatch -- --exact --nocapture` | An exhausted wall-time budget rejected before effect dispatch. Package tests also exercised output-limit rejection. |
| Transplant | `cargo test -p recursive-agent-ledger --test lifecycle_validation expected_run_binding_rejects_whole_chain_transplant -- --exact --nocapture` | Expected-run verification rejected a transplanted valid chain. |
| Direct crash verify | `cargo test -p recursive-agent-cli --test direct_crash_verify -- --nocapture` | Direct `ra verify` reconciled stale/partial metadata without a preliminary open. |
| Lock replacement | `cargo test -p recursive-agent-ledger --test crash_recovery root_and_legacy_lock_entry_replacement_cannot_split_pinned_handles -- --exact --nocapture` | Root and legacy lock-entry replacement did not split pinned handles. |
| Growing reads | `cargo test -p recursive-agent-ledger --test artifact_tamper concurrently_growing_artifact_and_metadata_reads_remain_bounded -- --exact --nocapture` | Artifact and metadata growth remained bounded and terminated. |
| Provider ingress | `cargo test -p recursive-agent-tools tests::invalid_provider_endpoint_is_rejected_in_tool_args_before_state_exists -- --exact --nocapture` | Invalid endpoint material was rejected before provider state existed. |

Additional focused package tests covered undeclared read/write denial, descendant timeout, partial artifact/meta writes, impossible lifecycle sequences, fixed ID vectors, cross-process memory identity, and provider sentinel non-retention.

## Required verification matrix

The following exact matrix was rerun after the final production-source change. Each command's final authoritative invocation exited `0`:

| Command | Result summary |
|---|---|
| `cargo fmt --all -- --check` | Formatting clean. |
| `cargo test -p recursive-agent-contracts --all-targets` | All targets passed. |
| `cargo test -p recursive-agent-policy --all-targets` | All targets passed. |
| `cargo test -p recursive-agent-ledger --all-targets` | All targets passed, including artifact, crash, process-lock, lifecycle, and transplantation coverage. |
| `cargo test -p recursive-agent-sandbox --all-targets` | All targets passed, including mandatory positive enforcement and network denial. |
| `cargo test -p recursive-agent-provider --all-targets` | All targets passed. |
| `cargo test -p recursive-agent-runner --all-targets` | All targets passed. |
| `cargo test -p recursive-agent-memory --all-targets` | All targets passed. |
| `cargo test -p recursive-agent-tools --all-targets` | All targets passed. |
| `cargo test --workspace --all-targets` | Entire workspace passed. |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed with warnings denied. |
| `git diff --check` | No whitespace errors. |

Production scans also exited `0` for local `unsafe`, lint overrides, skipped/ignored tests, public launcher/runtime injection, and UUID/random/live-time identity patterns across every enabled crate. All local `#[allow(...)]` attributes were removed; high-arity receipt APIs now accept complete typed materials/drafts, and unit tests use fallible results rather than unwrap exemptions. The identity scan's only general randomness match was the already-scoped MCTS algorithm; a focused authority/evidence-ID scan had no match. All remaining artifact/metadata `read_to_end` sites are applied only to readers already capped with `take(max + 1)` and then checked after reading.

## Environment and dependencies

- Host architecture: `x86_64`
- `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- `cargo 1.97.1`
- Bubblewrap `0.11.0`
- System libseccomp `2.6.0`
- Rust `libseccomp 0.4.0`, `libseccomp-sys 0.3.0`
- Sandbox-relevant resolved crates include `rustix 1.1.4`, `getrandom 0.3.4`, `hex 0.4.3`, `nix 0.30.1`, and `tempfile 3.27.0`.
- The receipt fixed vector changed consistently with the expanded canonical receipt contract to `v1:recursive-agent/receipt/v1:det:895d42d60e9ad065b14b81c2cabbb83b502304dc4b1f8345821ee40f925992fc`; run and step vectors remained stable.

## Relevant changed paths

- Workspace manifests: `Cargo.toml`, `Cargo.lock`
- CLI: `crates/recursive-agent-cli/Cargo.toml`, `src/main.rs`, `tests/direct_crash_verify.rs`
- Contracts: `crates/recursive-agent-contracts/src/lib.rs`
- Daemon: `crates/recursive-agent-daemon/Cargo.toml`, `src/lib.rs`; socket-backed handler tests are serialized on this host while retaining the positive run/receipt assertion
- Ledger: `crates/recursive-agent-ledger/Cargo.toml`, `src/lib.rs`, and artifact/crash/lifecycle integration tests
- Memory: `crates/recursive-agent-memory/Cargo.toml`, `src/lib.rs`
- MCP: `crates/recursive-agent-mcp/Cargo.toml`, `src/client.rs`, `src/lib.rs`, `src/protocol.rs`, `src/server.rs`
- MCTS: `crates/recursive-agent-mcts/Cargo.toml`, `src/lib.rs`; test lint suppression removed, algorithm randomness otherwise unchanged
- Policy: `crates/recursive-agent-policy/Cargo.toml`, `src/lib.rs`, permit lifecycle tests
- Provider: `crates/recursive-agent-provider/Cargo.toml`, `src/lib.rs`, secret/endpoint contract tests
- Runner: `crates/recursive-agent-runner/Cargo.toml`, `src/lib.rs`, identity/lifecycle/permit tests
- Sandbox: `crates/recursive-agent-sandbox/Cargo.toml`, `src/lib.rs`, fixed FD helper, enforcement tests
- Skills: `crates/recursive-agent-skills/Cargo.toml`, `src/lib.rs`; malformed substitution now returns a typed JSON error instead of a null/default fallback
- Tools: `crates/recursive-agent-tools/Cargo.toml`, `src/lib.rs`
- Evidence: `docs/receipts/phase-1/hardening-v2/R1` through `R8`

## Unresolved risks and quarantine

- Controller hostile re-review remains mandatory. Passing local tests is candidate evidence, not controller acceptance or a Phase 1 completion claim.
- The seccomp policy is generated for the native architecture tested here. This closeout makes no multiarch/32-bit execution claim.
- Trusted executable identity and positive containment evidence are for this host's `/usr/bin/bwrap`, helper artifact, runtime roots, and libseccomp stack. Packaging or another host requires its own positive evidence.
- This host denies `shutdown(2)` in the command environment and showed `EPERM` when daemon socket tests raced. The tests now serialize socket setup and close peers normally; two consecutive workspace runs and the final authoritative workspace invocation passed without accepting failure as success.
- Provider, delegate, memory, skill, and generic MCP effects remain typed unavailable rather than pretending to enforce budgets they do not yet honor. This intentional quarantine narrows current functionality.
- MCTS algorithm randomness is deferred to Phase 10 as specified; it is not accepted as an authority/evidence identity source.
- The worktree includes preserved candidate work predating this pass. Rollback, replacement, or quarantine should be applied only by the controller after reviewing the listed paths and digests; no Git history operation was performed here.
- The original implementation receipt, first hardening closeout, hostile review, and hostile re-review remain unchanged.

**Final disposition: controller review required. Phase 2 remains out of scope.**
