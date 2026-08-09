# Phase 7.2B — runner/ledger admission blocker

**Status:** BLOCKED — no runner, ledger, or scheduler source changes were made.

## Fresh source evidence

The Phase 7.2A contract/policy slice is locally green, but the existing runtime cannot satisfy the Phase 7.2B causal ordering without a new parent lifecycle owner:

1. `RuntimeService::submit` in `crates/recursive-agent-runner/src/runtime.rs` executes synchronously and returns `RuntimeHandleV1` only after `run_spec_internal_with_run_id(...)` completes.
2. `RuntimeHandleV1` is documented and implemented as terminal-only. `submit` calls the runner and returns only after the child-independent run already has `RunFinalized` evidence.
3. `run_spec_internal_with_run_id` appends `ReceiptKindV1::RunFinalized` before returning its verified summary. The authoritative receipt lifecycle treats that as terminal; a parent admission receipt cannot safely be appended afterward.
4. The existing root-run path creates only a `DurablePermitStore` control permit for same-run effect delegation. It neither creates a `FamilyRootGrantV1` nor exposes a live parent authority/session that can receive an admission receipt and defer parent finalization.
5. The existing `run_step` derives child effect permits only through the same-run `DurablePermitStore`. Directly calling it for a V2 child would create effects under a fresh local control permit rather than under the family reservation; that would violate the amendment's no-cross-run-bypass rule.

Therefore, a superficially convenient `submit_child(&RuntimeHandleV1, ChildOperationEnvelopeV2)` implementation would be unsound in both available shapes:

- terminal parent handle: parent is already finalized and cannot append the required child-admission/closure evidence;
- fresh child local permit: child effects are not constrained by the admitted family-control allocation.

## Required design decision

The next admissible implementation must introduce a **separate V2 live parent lifecycle** while preserving current V1 `RuntimeService::submit` semantics unchanged. The minimal direction is:

1. V2 root admission creates a runtime-owned, nonterminal parent session plus `FamilyRootGrantV1` before any child request.
2. The parent session owns an appendable parent chain and an explicit finalization operation; child admission verifies the active parent chain/receipt, reserves through `FamilyAuthorityStore`, writes the parent link receipt, then starts child execution.
3. Child execution receives a family dispatch guard plus a local child-run effect ceiling derived from the already-reserved request. The guard must be checked before and after effect dispatch; it must fail after parent revocation/cancellation.
4. A child terminal chain is strictly verified before the parent appends closure evidence and only then may the parent finalization path report success.
5. Scheduler fields remain derived visibility/cancellation projection only.

## Why this is a stop condition

Creating the live-parent API changes the lifecycle contract, receipt sequencing, and public runtime semantics across contracts, runner, ledger, scheduler, and tests. It is not a safe continuation of the bounded 7.2A contract/policy phase. Implementing a child adapter before that new contract would create exactly the bypass and terminal-close violation prohibited by `PHASE_CONTRACT.md`.

## Verified 7.2A evidence

- `cargo test -p recursive-agent-contracts --tests -- --nocapture` — PASS (30 tests).
- `cargo clippy -p recursive-agent-contracts --all-targets -- -D warnings` — PASS.
- `cargo test -p recursive-agent-policy --tests -- --nocapture` — PASS (20 tests).
- `cargo clippy -p recursive-agent-policy --all-targets -- -D warnings` — PASS.
- `cargo fmt --manifest-path crates/recursive-agent-contracts/Cargo.toml -- --check` — PASS.
- `cargo fmt --manifest-path crates/recursive-agent-policy/Cargo.toml -- --check` — PASS.

## Rollback

Revert only the 7.2A contracts/policy commit(s) and delete/quarantine any new family-store runtime roots. Do not rewrite existing V1 receipts, permits, scheduler projections, or prior evidence.
