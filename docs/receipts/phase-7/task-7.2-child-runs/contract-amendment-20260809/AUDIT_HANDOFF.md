# Phase 7.2 audit handoff

## Verified source phase: 7.2A contracts and family policy

- V1 ingress now admits only direct root operations. A V2-tagged/delegated shape cannot enter through the V1 parser.
- V2 child envelopes carry closed parent/root/permit/receipt/budget/digest proof. The child material digest excludes the proof to avoid circularity; the complete child operation ID binds the proof.
- `FamilyAuthorityStore` is a separate descriptor-rooted store. It does not modify `DurablePermitStore` or scheduler semantics. It atomically reserves child budgets, retains idempotent child requests, rejects widened/over-budget/root-mismatched requests, and fails closed after parent revocation.
- Phase 7.2A focused package checks passed on a stable source-status digest. See `CHANGE_RECEIPT.json` and `VALIDATION_MATRIX.csv`.

## Independent audit required before Phase 7.2B implementation

Read current source, not this handoff, then verify the blocker in `PHASE_7_2B_BLOCKED.md`:

1. `RuntimeService::submit` is synchronous and its public `RuntimeHandleV1` exists only after terminal receipt verification.
2. Runner finalizes the parent chain before returning the handle.
3. Existing child effects are derived from a same-run `DurablePermitStore` control permit.

A child-runtime implementation is admissible only after a new V2 live-parent lifecycle creates appendable parent admission state and family-root authority before child dispatch. Reject any proposal that appends a child link after parent finalization, treats the family reservation as advisory, or lets scheduler state satisfy authority/closure verification.

## Auditor rerun commands

```bash
cargo fmt --manifest-path crates/recursive-agent-contracts/Cargo.toml -- --check
cargo fmt --manifest-path crates/recursive-agent-policy/Cargo.toml -- --check
cargo test -p recursive-agent-contracts --tests
cargo test -p recursive-agent-policy --tests
cargo clippy -p recursive-agent-contracts -p recursive-agent-policy --all-targets -- -D warnings
```

## Rollback

Revert the Phase 7.2A checkpoint only; quarantine/delete new family-authority runtime roots; deny V2 child admission. Preserve all existing V1 evidence unchanged.
