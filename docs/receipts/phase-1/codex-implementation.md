# Phase 1 Codex Implementation Receipt

## Disposition

**Blocked / not promoted.** The allowed Phase 1 crate tests, formatting, strict
Clippy, and `git diff --check` pass. The required workspace test passed during
the ordered final gate, but a later release-proof rerun failed because this
execution environment began denying AF_UNIX socket creation/connect with
`EPERM`. The affected tests are in the explicitly out-of-scope
`recursive-agent-daemon` crate. A minimal Python AF_UNIX bind probe reproduced
the same host denial. Because the latest workspace rerun is not green, this
receipt does not claim Phase 1 completion.

## Source state

- Starting HEAD: `3805f7abf319e07e47f1c20b862e614c3dad164f`
- Ending HEAD: `3805f7abf319e07e47f1c20b862e614c3dad164f`
- Starting branch: `main`
- Ending branch: `main`
- The pre-existing dirty tree was retained. No history operation was used.

## Changed paths owned by this implementation

- `Cargo.lock` (Cargo refresh for allowed dependency changes; pre-existing
  dirty lockfile content was preserved)
- `crates/recursive-agent-contracts/src/lib.rs`
- `crates/recursive-agent-policy/Cargo.toml`
- `crates/recursive-agent-policy/src/lib.rs`
- `crates/recursive-agent-policy/tests/permit_lifecycle.rs`
- `crates/recursive-agent-ledger/Cargo.toml`
- `crates/recursive-agent-ledger/src/lib.rs`
- `crates/recursive-agent-ledger/tests/artifact_tamper.rs`
- `crates/recursive-agent-ledger/tests/crash_recovery.rs`
- `crates/recursive-agent-sandbox/Cargo.toml`
- `crates/recursive-agent-sandbox/src/lib.rs`
- `crates/recursive-agent-sandbox/tests/enforcement_truth.rs`
- `crates/recursive-agent-runner/Cargo.toml`
- `crates/recursive-agent-runner/src/lib.rs`
- `crates/recursive-agent-runner/tests/deterministic_identity.rs`
- `crates/recursive-agent-runner/tests/lifecycle_state_machine.rs`
- `crates/recursive-agent-provider/src/lib.rs`
- `crates/recursive-agent-provider/tests/secret_contract.rs`
- `docs/receipts/phase-1/codex-implementation.md`

No out-of-scope crate or `.hermes` file was modified by this implementation.
Other dirty and untracked paths shown by `git status` pre-existed or appeared
outside this implementation and were left untouched.

## RED evidence

The baseline focused package suite was green before regressions were added,
confirming the defects were not guarded.

1. Deterministic identity
   - Command: `cargo test -p recursive-agent-contracts tests::empty_family_is_rejected -- --exact --nocapture`
   - Exit: `101`
   - Observed failure: `FamilyId::new("", "x").is_err()` was false.
   - Command: `cargo test -p recursive-agent-runner --test deterministic_identity -- --nocapture`
   - Exit: `101`
   - Observed failures: identical specs produced different UUID run IDs, and
     the production-source scan found `Uuid::new_v4`.

2. Typed terminal lifecycle
   - Command: `cargo test -p recursive-agent-runner --test lifecycle_state_machine -- --nocapture`
   - Exit: `101`
   - Observed failure: `RunTerminalStateV1` did not exist. The pre-change
     runner also unconditionally emitted `RunFinalized/Ok` after a failed
     tool step.

3. Durable one-shot permit lifecycle
   - Command: `cargo test -p recursive-agent-policy --test permit_lifecycle -- --nocapture`
   - Exit: `101`
   - Observed failures: `DurablePermitStore`, `PermitBindingV1`, and
     `PermitAlreadyConsumed` did not exist, so concurrent/restart consumption
     regressions could not compile.

4. Crash-safe ledger metadata
   - Command: `cargo test -p recursive-agent-ledger --test crash_recovery -- --nocapture`
   - Exit: `101`
   - Observed failures: a complete record lacking its final newline verified
     successfully; metadata ahead of the log was trusted; log-ahead metadata
     reopened at length zero instead of recovering to length one.

5. Artifact integrity
   - Command: `cargo test -p recursive-agent-ledger --test artifact_tamper -- --nocapture`
   - Exit: `101`
   - Observed failure: typed `ArtifactCorrupted` did not exist and modified
     artifact bytes were returned without rehash verification.

6. Sandbox truth and fail-closed setup
   - Command: `cargo test -p recursive-agent-sandbox --test enforcement_truth -- --nocapture`
   - Exit: `101`
   - Observed failures: typed `MissingAllowPath` and `InvalidTimeout` did not
     exist; source still contained unconditional `sandboxed: true` and the
     fail-open Landlock comment/path.
   - Evidence gap: the named descendant-cleanup regression was added after
     the main sandbox production rewrite rather than observed RED beforehand.
     The preserved starting source and Phase 1 plan show single-PID kill, and
     the final descendant regression passes, but this sequencing does not meet
     the requested strict RED timing for that one subcase.

7. Secret-free provider contract
   - Command: `cargo test -p recursive-agent-provider --test secret_contract -- --nocapture`
   - Exit: `101`
   - Observed failures: `CredentialRef`, `SecretBytes`, and typed missing
     credential errors did not exist; `OpenAiCompatible` still required the
     serializable `api_key` field.

## Implemented behavior

- Run IDs bind canonical `RunSpecV1`; step IDs bind run ID, stable index,
  step name, and canonical call; permit IDs bind the complete requested effect;
  receipt IDs bind run, step, kind/outcome, artifacts, and predecessor. The
  adapters use `stack-ids` owner types with distinct
  `recursive-agent/.../v1` domains after JCS material hashing. The documented
  narrow mismatch is that step identity uses owner `EffectIntentId` because
  `stack-ids` has no dedicated step ID.
- Empty legacy family names are rejected. Production identity paths in the
  contracts, policy, and runner contain no UUID, random, or wall-clock minting.
- `RunTerminalStateV1` distinguishes succeeded, failed, denied, timed out,
  cancelled, sandbox failed, and corrupted. `RunLifecycle` admits exactly one
  terminal transition. Failures stop later steps, `RunSummary` exposes the
  typed state, and final receipt outcome matches it.
- The policy crate owns canonical durable issue records and atomic
  `create_new` consumption markers, with file and directory sync. Restart and
  concurrent second spends fail closed. Runner consumption occurs immediately
  before dispatch and emits a `PermitConsumed` receipt.
- The receipt log is authoritative. Open scans canonical records before
  metadata, rejects malformed tails/interior records, bad predecessor/identity,
  duplicate receipts, metadata ahead/wrong head/wrong genesis, and recovers a
  valid log ahead of metadata. Metadata uses same-directory temp write,
  `sync_all`, atomic rename, and parent-directory sync while preserving creation
  time.
- Artifact IDs are owner-qualified content addresses. Put/read/strict verify
  reject missing, modified, malformed, non-regular, symlink-swapped, and
  escaping artifacts; every receipt reference is rehashed.
- Sandbox results carry requested/applied mechanisms, enforcement outcome,
  policy digest, and reason instead of `sandboxed: bool`. Zero timeout and
  missing requested paths fail before spawn. Child pre-exec setup failure
  prevents exec and is reported over an explicit confirmation path. Output is
  drained concurrently with a 64 KiB per-stream ceiling and typed truncation
  evidence. Timeout and normal leader exit kill the whole process group; a
  descendant cleanup regression passes. Tests include an injected child setup
  failure and do not require host Landlock availability.
- Provider specs serialize only opaque credential references. Environment
  resolution returns typed missing/unsupported/invalid errors. Secret bytes
  have redacted debug output, are zeroed on drop, are used only to build a
  sensitive authorization header, and are scrubbed from returned provider JSON
  and assistant text. Transport/status errors omit headers, bodies, URLs, and
  secret-bearing debug detail. Ollama remains credential-free.
- Touched runner prose now says recorded-evidence replay; touched sandbox
  metadata no longer claims seccomp or unconditional sandboxing.

## GREEN and gate evidence

Focused final commands, each exit `0`:

- `cargo fmt --all -- --check`
- `cargo test -p recursive-agent-contracts --all-targets` (8 tests)
- `cargo test -p recursive-agent-policy --all-targets` (8 tests)
- `cargo test -p recursive-agent-ledger --all-targets` (12 tests)
- `cargo test -p recursive-agent-sandbox --all-targets` (8 tests)
- `cargo test -p recursive-agent-provider --all-targets` (6 tests)
- `cargo test -p recursive-agent-runner --all-targets` (6 tests)
- `cargo test --workspace --all-targets`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `git diff --check`

The exact ordered final gate above completed with every command at exit `0`.
Strict Clippy was reached without adding new lint suppressions.

The release-gate skill then reran three gates through its proof wrapper:

- Proof packet:
  `/tmp/recursive-agent-phase1-proof/evidence-workbench-20260805T041549Z.json`
- Packet SHA-256:
  `bd988bb836a19dbc3233fc4796548abb1685afb953101bc2662ef675ea531cfb`
- Disposition: `reject`
- `cargo fmt --all -- --check`: exit `0`
- `cargo clippy --workspace --all-targets -- -D warnings`: exit `0`
- `cargo test --workspace --all-targets`: exit `101`
- Exact failure: both `recursive-agent-daemon` tests failed connecting to
  their local Unix sockets with `Os { code: 1, kind: PermissionDenied,
  message: "Operation not permitted" }`.
- A subsequent direct `cargo test -p recursive-agent-daemon --lib -- --nocapture`
  also exited `101` with the same `EPERM`.
- A minimal Python AF_UNIX probe under `/tmp` exited `1` at socket bind with
  `PermissionError: [Errno 1] Operation not permitted`, demonstrating an
  execution-environment socket restriction independent of repository code.

## Explicit non-goals and untouched areas

- No daemon, MCP, CLI, memory, skills, MCTS/search, or tool-dispatch source was
  modified.
- No repository-wide claim rewrite, native runtime service, adapter migration,
  provider network smoke, fuzzing, `cargo deny`, release, install, service
  change, or deployment was attempted.
- No claim is made that this host supports Landlock; fail-closed behavior is
  the contract when setup is unavailable.
- Replay remains recorded-evidence replay and never re-executes tools/providers.

## Unresolved defects and blockers

1. Latest workspace/release-proof rerun is blocked by the host denying AF_UNIX
   socket operations required by the out-of-scope daemon tests. Phase 1 must not
   be promoted until an independent controller reruns the exact workspace test
   in an environment that permits the existing daemon fixture and obtains exit
   `0`.
2. The descendant-cleanup test did not have a chronologically prior observed
   RED run. Treat that regression's process evidence as incomplete even though
   its final test is green.
3. The proof packet disposition is `reject`, so the release-gate skill's
   promotion condition is not satisfied.

## Rollback / quarantine guidance

- Quarantine the Phase 1 changes and do not promote or commit them while the
  blockers above remain.
- Because the workspace contained intentional pre-existing changes, do not use
  a broad reset/restore/clean. Roll back only the paths/hunks listed under
  “Changed paths owned by this implementation,” using the preserved Phase 0
  baseline and an independently reviewed patch.
- Permit and run directories created only in temporary test directories were
  removed automatically by `tempfile`; no persistent runtime migration was
  performed.
- The rejected proof packet is diagnostic and can be deleted from `/tmp`; it is
  not repository authority.

## Safety confirmation

No commit, push, stage, reset, restore, clean, checkout, rebase, history rewrite,
external canonical-owner edit, service edit, installed-binary edit, active Hermes
edit, credential access, credential serialization, or network provider call
occurred. No API key or secret value was printed or persisted.
