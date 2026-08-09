# Phase 7.2 audit handoff

## Current evidence state

**Implemented and workspace-verified; two decisive adversarial regressions are now passed, but the full semantic tamper matrix is still incomplete.**

The Phase 7.2 source sequence is now committed through:

- `9388911` — attenuated family policy
- `9cc7367` — V2 family-authority contracts
- `ca00d31` — ledger links and scheduler projection
- `66f9542` — authority-free pre-admission proposal
- `8b7501c` — runtime-owned V2 live parent lifecycle
- `01bd225` — cancelled live-parent terminal closure

`CHANGE_RECEIPT.json` is the current machine-readable evidence record.

## Verified implementation boundaries

- `RuntimeService::submit` remains the V1 synchronous terminal path.
- `RuntimeService::begin_parent_v2` executes the direct root steps while retaining a runtime-owned appendable parent chain and family authority.
- `submit_child` accepts only `ChildOperationProposalV2`. It appends `ChildAdmissionPrepared`, strictly reads it back, then derives the closed envelope and atomically reserves through `FamilyAuthorityStore`.
- `ChildLinked` carries the immutable content-addressed link before child dispatch.
- The child runner checks the family guard before and after every effect; the child chain is strictly verified from its canonical run directory before `ChildClosed` is appended.
- `finalize` requires every prepared child to have exactly one verified closure. Parent cancellation revokes family authority, rejects new admission, writes `ParentCancelled`, and finalizes as `Cancelled` rather than success.
- Scheduler parent/root/child fields remain projection-only and do not mint authority, reserve budget, or verify closure.

## Verified commands

```bash
cargo test -p recursive-agent-contracts --tests --no-fail-fast
cargo test -p recursive-agent-policy --tests --no-fail-fast
cargo test -p recursive-agent-runner --test phase2_runtime_service --no-fail-fast
cargo test --workspace --all-targets --no-fail-fast
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

On 2026-08-09, the focused runner gate passed 12/12 tests after adding:

- `live_parent_strict_verification_rejects_tampered_link_and_closure_artifacts`, which corrupts the immutable artifacts referenced by both `ChildLinked` and `ChildClosed` and proves strict parent verification rejects them.
- `live_parent_cancellation_during_child_effect_prevents_child_success_and_cancels_parent`, which holds a real admitted child effect in flight, revokes the parent family, releases the effect, and proves the post-effect guard prevents child success while the parent closes `Cancelled`.

`cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --all-targets --no-fail-fast`, `cargo fmt --all -- --check`, and `git diff --check` all exited zero on this source generation. The workspace crash-recovery test deliberately prints one losing child-process append race before its enclosing test confirms the expected race-safe pass.

## Remaining certification delta

Do **not** mark Phase 7.2 complete yet. The immutable-artifact and in-flight race gates are covered; add focused semantic fixtures for:

1. altered parent admission receipt ID;
2. duplicate link and duplicate closure;
3. missing closure receipt;
4. mismatched child terminal state and chain head with otherwise valid artifact descriptors.

## Rollback

Revert `01bd225` and `8b7501c` to remove the live-parent lane; revert earlier Phase 7.2 commits only for full feature rollback. Quarantine family-state directories under the selected runtime root. Preserve parent/child receipts and permits; deny new V2 admission rather than rewriting evidence.
