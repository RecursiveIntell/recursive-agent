# Phase 1 Hostile Review

**Disposition:** REJECT — Phase 1 remains quarantined.  
**Review mode:** read-only static inspection plus non-mutating format/diff/metadata gates.  
**Reviewed:** 2026-08-04/05 against Phase 1 Tasks 1.1–1.7.

The controller's green test manifest proves the current tests pass. It does not cover the hostile cases below.

## Release-blocking findings

### P1-1 — Landlock evidence overstates the mediated filesystem surface

- **Evidence:** `recursive-agent-sandbox/src/lib.rs` handles execute/read/write-file/read-dir, omitting create/remove/rename/refer/truncate rights, yet can return `Enforced`. `shell` is enabled by default by policy.
- **Consequence:** operations outside declared write roots may remain possible on kernels exposing those rights while the evidence claims enforcement.
- **Fix:** query the Landlock ABI, mediate the complete supported filesystem-rights matrix, and return typed unavailable/failed instead of weakening the policy.
- **Acceptance:** real public-API attempts to create/remove/rename/truncate outside allowed roots fail; unsupported ABI levels never return `Enforced`.
- **Quarantine:** disable sandbox-dependent effects until green.

### P1-2 — Permits are not complete capability leases

- **Evidence:** `PermitBindingV1` binds only run, step, tool, args digest, effect scope, and policy version. No actor, action digest, budget, parent lease, expiry, or revocation state is represented. Store paths are reopened by name.
- **Consequence:** wrong actor/action/budget/parent, expired, revoked, and path-swap cases cannot be rejected.
- **Fix:** bind actor, canonical action/effect digest, budget, policy version, parent, expiry; add durable revoke and atomic state transitions; harden the store against symlink/path replacement.
- **Acceptance:** wrong actor/action/budget/parent, expired, revoked, concurrent/restart double-spend, crash-point, and directory/symlink-swap tests all prove zero dispatch.
- **Quarantine:** treat the current store only as an at-most-once prototype.

### P1-3 — Ledger append is neither crash-recoverable nor multi-handle safe

- **Evidence:** canonical receipt bytes and newline are separate writes; a missing newline permanently blocks reopen. The crash test accepts this failure. No append lock exists. Metadata temp names collide per process. Chain hashing uses predecessor hex text instead of the contract's predecessor digest bytes.
- **Consequence:** kill points can leave unrecoverable tails; concurrent handles can fork one chain or race metadata replacement.
- **Fix:** exclusive ledger ownership/locking, one-write canonical line or recoverable transaction marker, unambiguous incomplete-tail recovery, collision-safe metadata replacement, idempotent reconciliation, and raw predecessor bytes in the fixed chain vector.
- **Acceptance:** process-kill/failpoint matrix after artifact write, partial record, receipt append, log fsync, metadata temp write/fsync, rename, and directory fsync; two-process append race; every reopen yields exactly the previous or new valid chain.
- **Quarantine:** do not call the ledger crash-recoverable.

### P1-4 — Offline verification does not enforce lifecycle truth

- **Evidence:** lifecycle dominance is in-memory only. The ledger verifier does not validate receipt-order semantics. Existing-run status trusts only the last receipt.
- **Consequence:** failed-then-success, multiple finalizations, post-terminal receipts, or mixed-run receipts can structurally verify.
- **Fix:** one canonical receipt transition validator used during append, reopen, verify, replay, and status; bind a chain to one run ID and exactly one final receipt.
- **Acceptance:** canonical hostile chains for failed/cancelled then success, duplicate finalization, post-terminal receipt, and wrong run ID are rejected at append and offline verification.
- **Quarantine:** disable successful existing-run fast-path claims until green.

### P1-5 — Persisted material IDs are loose strings and receipt preimages are incomplete

- **Evidence:** transparent `FamilyId` deserialization bypasses constructor validation. `ReceiptV1` stores material IDs as strings. Receipt identity omits lineage, spec digest, and args digest.
- **Consequence:** UUIDs, wrong-family values, and arbitrary strings can cross typed boundaries; materially different receipts can share IDs.
- **Fix:** strict custom construction/deserialization with owner types or validated wrappers; explicit `LegacyV1`; bind every semantic receipt field except explicitly non-identity recording metadata.
- **Acceptance:** wrong-family/UUID ingress rejection, cross-process fixed vectors, and independent mutation of every semantic field changes receipt identity.
- **Quarantine:** deterministic-identity claim remains blocked.

### P1-6 — Artifact verification is TOCTOU-raceable, unbounded, and under-specified

- **Evidence:** path metadata/canonicalization checks happen before reopening by path. `fs::read` is unbounded. Receipts have bare string references without required length/media type.
- **Consequence:** rename/symlink/FIFO/device swaps can redirect or hang verification; large files can exhaust memory; strict length/media-type checks are impossible.
- **Fix:** descriptor-relative no-follow/beneath open; validate the opened descriptor; bounded streaming hash; typed artifact descriptor with ID, digest, length, media type; explicit `LegacyIntegrityOnly` mode.
- **Acceptance:** active swap loop, FIFO, huge sparse file, missing/truncated/replaced/wrong-length/wrong-media-type tests.
- **Quarantine:** strict-artifact claim remains blocked.

### P1-7 — Sandbox setup/supervision can hang or leak descendants and violates no-unsafe doctrine

- **Evidence:** complex setup runs inside `pre_exec`; timeout starts after spawn/setup confirmation; cleanup targets one process group; escaping `setsid` descendants can hold pipes; inherited FDs are not closed; crate-level `#![allow(unsafe_code)]` overrides workspace doctrine.
- **Consequence:** setup deadlock is unbounded, descendants can escape cleanup, pipe-reader joins can hang, and non-CLOEXEC FDs can leak.
- **Fix:** narrowly separated safe launcher/helper, bounded setup handshake, explicit FD hygiene, and containment descendants cannot escape (PID namespace/cgroup or equivalent). Remove unsafe code and the lint override.
- **Acceptance:** forced setup hang, inherited FD, `setsid` descendant, leader-exits-first, signal race, infinite-output descendant, and non-Linux compile/fail-closed tests.
- **Quarantine:** no effectful sandbox dispatch.

### P1-8 — Credential references and URLs can carry raw secrets into evidence

- **Evidence:** `CredentialRef` accepts every nonempty string and derived deserialization bypasses that check. Errors interpolate the full reference. `base_url` accepts URL userinfo/query credentials.
- **Consequence:** raw secrets placed in the reference or URL can enter serialization, Debug, errors, and receipts.
- **Fix:** closed credential-reference grammar with custom deserialization and validated environment variable names; error-safe nonsecret fingerprint/typed ID; reject URL credentials/userinfo/query before transport.
- **Acceptance:** sentinels in credential_ref, URL userinfo/query, resolver errors, serialization, Debug, and error/event paths never appear.
- **Quarantine:** disable OpenAI-compatible execution and secret-safe claim until green.

### P2-9 — Existing tests and receipts overfit the implementation

- Expand tests to the acceptance matrices above. Preserve `docs/receipts/phase-1/codex-implementation.md` as historical blocked evidence. Regenerate a separate controller closeout only after hostile cases pass.

## Read-only verification performed

- `cargo fmt --all -- --check` — exit 0
- `git diff --check` — exit 0
- locked offline Cargo metadata for the six Phase 1 packages — exit 0
- Phase 1 controller manifest JSON parse — exit 0

No files were changed by the reviewer. No dynamic hostile/failpoint tests were run by the reviewer.

## Claim fence

Keep RA-C006 through RA-C011 blocked/prototype. Do not assert Phase 1 completion, fully validated material identity, lifecycle-complete offline verification, actor/budget/expiry/revocation-bound authority, crash recovery, race-safe strict artifact verification, secure complete sandboxing, or secret-safe provider state until this review is superseded by a passing closeout receipt.
