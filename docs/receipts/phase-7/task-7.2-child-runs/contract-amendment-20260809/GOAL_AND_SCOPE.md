# Goal and scope

## Goal

Admit a strict, versioned causal-family contract for Phase 7.2 child runs before modifying the runtime. The contract must make a child run runtime-managed, budgeted, cancellable, and causally closed without creating scheduler- or adapter-owned authority.

## Non-goals

- Implementing raw subprocess delegation, remote workers, providers, MCP/CLI delegation, skills, memory, search, or later phases.
- Modifying `/home/sikmindz/Coding/Libraries`.
- Treating legacy/V1 runs as child-authorized.
- Pushing, deploying, publishing, deleting, resetting, or changing active Hermes configuration. A local checkpoint commit is separately authorized by the user.

## Allowed paths

- `crates/recursive-agent-contracts/{src,tests}` — versioned child-envelope/receipt-link contract.
- `crates/recursive-agent-policy/{src,tests}` — family authority, attenuation, reservation, revocation.
- `crates/recursive-agent-runner/{src,tests}` — canonical child submission/cancellation path and rebuildable scheduler projection.
- `crates/recursive-agent-ledger/{src,tests}` — child-link strict verification only.
- `docs/receipts/phase-7/task-7.2-child-runs/contract-amendment-20260809/` — this evidence packet.

## Forbidden paths

- `/home/sikmindz/Coding/Libraries/**`
- provider, MCP, remote, memory, skill, search crates
- existing V1 parser behavior except to reject a V1 delegated child admission explicitly
- broad write-mode formatting outside files modified by the phase
