# Phase 7.2A — V2 child-operation contracts and family authority

**Admission state:** admitted for bounded local implementation. The prior amendment remains the governing design; this document narrows the first executable slice.

## Goal

Make it impossible for a V1 ingress or the existing single-run permit store to admit a delegated child operation, while adding a separate V2 envelope and a family-scoped policy store that can reserve an attenuated child-control allocation without scheduler authority.

## Scope

Allowed source paths:

- `crates/recursive-agent-contracts/src/{lib.rs,operation.rs}`
- `crates/recursive-agent-contracts/tests/phase7_child_operation_contract.rs`
- `crates/recursive-agent-policy/src/lib.rs`
- `crates/recursive-agent-policy/tests/phase7_child_family_authority.rs`
- this receipt packet

Forbidden:

- runner, ledger, scheduler, CLI, daemon, provider, MCP, remote, memory, skill, and `/home/sikmindz/Coding/Libraries/**` source changes;
- changing V1 identities, fixed vectors, or allowing a V1 parser fallback;
- any child effect dispatch, adapter result acceptance, or parent terminal-success claim.

## Owners and non-negotiable invariants

| Surface | Canonical owner | Required invariant |
|---|---|---|
| V1/V2 envelope schema, canonical material, ingress | `recursive-agent-contracts` | V1 is direct-root-only; V2 is delegated-only and must carry closed child proof. |
| Parent/child family grant, attenuation, reservation, revocation | `recursive-agent-policy` | one family-rooted store/lock owns child control permits and cumulative reservations; the old single-run store rejects cross-run issuance. |
| Scheduler | deferred | may not mint permits, reserve budget, or certify a child terminal. |
| Ledger/run closure | deferred | policy receipt IDs remain opaque until Phase 7.2B runtime/ledger verification. |

## Contract shape

1. `OperationEnvelopeV1::validate` must require `schema == V1`, `origin == Direct`, and no parent/root lineage. Existing V1 delegated operation acceptance is removed, not preserved.
2. `ChildOperationEnvelopeV2` must require `schema == V2`, `origin == Delegated`, both causal IDs, exact equality between causal and child-authority parent/root IDs, `budget == requested_budget`, and a `child_operation_digest` over material excluding `child_authority`.
3. V2 parsing is a separate closed ingress and is re-exported explicitly. `derive_child_operation_id` binds the complete V2 envelope after semantic validation; V1 material and fixed vectors remain unchanged.
4. The policy lane introduces versioned family-only types rather than changing `DelegationCeilingV1` or `DurablePermitStore` semantics. It persists a root-family grant, child-control permit records, reservation journal, and revocation state under one descriptor-relative family lock.
5. A family child permit must bind a distinct child `run_id`, immediate parent run, unchanged root run, parent permit ID, parent admission receipt ID, child-envelope digest, depth, and strictly attenuated budget. The policy lane does **not** claim to verify the referenced ledger receipt; Phase 7.2B must verify it before calling the store.

## RED gates

1. `phase7_child_operation_contract::v1_ingress_rejects_a_delegated_v2_shape_without_child_authority` fails before the V1 boundary repair, proving V1 cannot silently widen.
2. V2 contract tests fail for schema/origin mismatch, absent lineage, authority/causality mismatch, budget mismatch, and digest tampering.
3. Family-policy tests fail for old single-run cross-run issuance, widened budget/depth/root, dual-power confusion, parent revocation, concurrent cumulative over-reservation, and retry idempotence.

The initial source contains an uncommitted partial V2 implementation that does not compile (`ChildOperationEnvelopeV2::validate` missing). That is a prerequisite repair, not GREEN evidence. After the smallest compile repair, the first RED must reach the V1 ingress assertion above before the V1 boundary is changed.

## GREEN acceptance gates

```bash
cargo test -p recursive-agent-contracts --test phase7_child_operation_contract -- --nocapture
cargo test -p recursive-agent-contracts --tests
cargo test -p recursive-agent-policy --test phase7_child_family_authority -- --nocapture
cargo test -p recursive-agent-policy --tests
cargo clippy -p recursive-agent-contracts -p recursive-agent-policy --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Stop conditions

Stop and quarantine if the implementation needs V1 fallback, a shared `DurablePermitStore` cross-run bypass, scheduler-owned admission/reservation, any child effect dispatch, or a claim that an opaque receipt ID is ledger-verified.

## Rollback

Revert only the Phase 7.2A commit(s), delete/quarantine newly created family-store roots, and deny V2 child parsing/admission. Do not rewrite existing V1 receipts, permits, scheduler projections, or prior phase evidence.
