# Phase 7.2 — causal-family child-run contract amendment

**Status:** source-grounded amendment. Phase 7.2A is admitted and implemented under `PHASE_7_2A_CONTRACTS_POLICY.md`; Phase 7.2B is blocked pending a V2 live-parent lifecycle decision (`PHASE_7_2B_BLOCKED.md`).

## Decisive preflight finding

The current implementation cannot safely create a child run:

- `DelegationCeilingV1.run_id` and `validate_parent_permits` require the child permit, parent permit, and ceiling to bind the same run. A child operation necessarily has a different `run_id`.
- `DurablePermitStore` is rooted at one run directory. Its reservation map is useful only for same-run permits and cannot atomically prove or reserve a parent-to-child allocation across two run roots.
- A control permit expresses exactly one transition: `ControlToEffect` *or* `ControlToControl`; a parent run needs both its own effect permits and a bounded child-control power.
- `RuntimeService::submit` executes synchronously and passes only `RunSpecV1` into the runner. It does not convey `OperationEnvelopeV1` causality/budget, child authority, or a scheduler parent/child relationship.
- `SchedulerStore` is explicitly a rebuildable projection, has no parent link, and is therefore not an authority or budget owner.
- The current receipt model can bind a child-link artifact through `artifact_refs`, but has no cross-chain child terminal verifier.

Implementing `delegate` before correcting these boundaries would create a second authority store or child effects that are not causally closed. That is prohibited by the plan and `AGENTS.md`.

## Selected minimal design

Preserve current V1 root-operation semantics. Add a versioned child-operation lane rather than silently widening V1.

### 1. Contracts owner — `recursive-agent-contracts`

Add `OperationSchemaV1::V2` and a closed `ChildRunAuthorityV1` field required for delegated V2 operations:

- `parent_operation_id` and `root_operation_id` (must agree with `causality`);
- `parent_control_permit_id`;
- `parent_admission_receipt_id` (the committed parent receipt authorizing this child proposal);
- `requested_budget` and `child_operation_digest`.

The V2 envelope identity binds this proof. V1 remains valid only for direct root work; a V1 delegated envelope must continue to fail closed. No optional/default authority field and no V1 parser fallback.

### 2. Policy owner — `recursive-agent-policy`

Add one **family-scoped authoritative store**, rooted deterministically below the runtime-owned output root and keyed by the root operation ID. It owns parent control permits, child control permits, per-child budget reservations, revocation propagation, and idempotent reservation recovery under one family lock.

Extend the binding/ceiling contract with root-family identity and a child-control capability. A parent control grant has two explicitly separated powers:

- `effect_ceiling`: current bounded effects for the parent run;
- `child_run_ceiling`: bounded child operation proposals, nested depth, cumulative family budget, and terminal-close policy.

A child control permit must bind a distinct child `run_id`, immediate parent run, unchanged root run, parent permit ID, admitted parent receipt ID, and a strict subset of both child and cumulative budgets. The family store, not `SchedulerStore`, performs reservation before child admission. Parent revocation/cancellation makes a not-yet-dispatched child reject; consumed permits are governed by the declared close/cancel policy and terminal receipt requirements.

### 3. Runner/ledger owner — `recursive-agent-runner` and `recursive-agent-ledger`

Add a runtime-owned `submit_child(parent_handle, child_envelope)` path. It must:

1. strictly verify the parent chain and the referenced parent admission receipt;
2. open the family authority store; derive, validate, and atomically reserve the child control permit;
3. append a parent admission receipt with a content-addressed `ChildRunLinkV1` artifact containing parent run/receipt/permit, child run/permit, root ID, reserved budget, and child-envelope digest;
4. run the child only through the canonical runtime path, passing the family-authority context into the runner;
5. strictly verify the child terminal chain; append a parent closure receipt whose linked artifact binds the child terminal receipt ID, terminal state, and chain head;
6. apply the declared parent closure policy only after that verified closure evidence exists.

`ChildRunLinkV1` is a ledger-verifier input, not a scheduler projection. The verifier must reject a missing, mismatched, duplicate, unverified, or terminal-incomplete child link. No child result may be surfaced as success solely from an adapter return value.

### 4. Scheduler projection owner — `recursive-agent-runner::SchedulerStore`

Add `parent_operation_id`, `root_operation_id`, and `children` only as rebuildable visibility/cancellation projection fields. The scheduler may request cancellation and fan it out, but it must never mint permits, make budget decisions, or satisfy child-close verification.

## Required RED gates before implementation

| Gate | Required failing assertion before GREEN |
|---|---|
| Parent admission | Child with missing/unverified parent run or missing parent admission receipt cannot reserve or dispatch. |
| Cross-run permit | A different child `run_id` succeeds only through the family store and fails through the old single-run store. |
| Attenuation | Any widened action, audience, duration, output/artifact/wall budget, depth, or root identity is rejected. |
| Atomic reservation | Two children that cumulatively exceed parent family budget admit at most one; restart/retry never double-reserves. |
| Dual powers | Parent may issue an in-budget effect and an in-budget child-control permit; neither power can be used as the other. |
| Cancellation | Parent cancellation prevents queued child dispatch and produces linked terminal cancellation evidence. |
| Child failure | Parent cannot finalize successful while a required child lacks a verified terminal closure link. |
| Tamper | Altering parent/child permit, receipt ID, terminal state, chain head, or link artifact makes strict verification fail. |

## Green/phase acceptance order

1. Contracts and policy RED/GREEN gates above.
2. Family-store crash/retry and concurrent-reservation tests.
3. Runner child submission with deterministic fake tool only.
4. Parent-child cancellation and terminal closure tests.
5. Ledger strict verifier tamper matrix.
6. Package checks (`fmt`, contracts/policy/runner tests, Clippy) and then workspace/release gate on the final frozen source generation.

## Explicit non-goals

No raw subprocess scheduler; no remote worker; no provider; no MCP/CLI public delegation command until the runtime lane passes; no edits under `/home/sikmindz/Coding/Libraries`; no scheduler-owned authority; no persistence migration that silently treats legacy runs as child-authorized.

## Stop and rollback conditions

Stop and quarantine this phase if the design needs a V1 compatibility fallback, a cross-run permit bypass, a scheduler-owned authority/budget decision, a child effect before a persisted reservation, parent success without a verified child terminal link, or cancellation that can leave an unrecorded child active.

Rollback is a revert of this phase's commits plus quarantine of V2 child submission. Preserve all parent/child evidence and deny new V2 child admissions; do not rewrite receipts, permits, or scheduler projections.

## Orchestration note

Agent Graph council instantiation was attempted but blocked by the live daemon's graph-capacity error (`256` capacity with `259` registered graphs). This packet is based on current local source inspection, not a council outcome.
