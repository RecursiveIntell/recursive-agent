# Rollback and quarantine

## Phase 7.2A checkpoint

Revert only the checkpoint commit that changes:

- `recursive-agent-contracts` V2 envelope/ingress and its tests;
- `recursive-agent-policy` family-authority store and its tests;
- this Phase 7.2 packet.

Quarantine or delete any runtime-created family authority root only when no active execution references it. Do **not** rewrite or delete existing V1 receipt chains, permit records, scheduler projections, or artifacts.

## Phase 7.2B status

No runner, ledger, scheduler, CLI, daemon, or external source changed. V2 child submission remains unavailable; do not add a fallback through terminal parent handles or a fresh child-local root permit. See `PHASE_7_2B_BLOCKED.md`.

## External effects

No push, merge, deployment, publication, reset, deletion, or Hermes configuration change occurred. A local checkpoint commit is explicitly authorized by the user request; it is reversible with `git revert <checkpoint>`.
