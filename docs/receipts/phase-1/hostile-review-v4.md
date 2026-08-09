# Phase 1 Hostile Admission Review — Post-Hardening v3

**Verdict:** REJECT  
**Date:** 2026-08-05  
**Mode:** read-only static inspection and independent tests

## P0-1 — Public callers can self-mint and reuse sandbox authority

Evidence:

- public permit binding/issuer/consume surfaces: `crates/recursive-agent-policy/src/lib.rs:83`, `:540`, `:595`;
- sandbox execution borrows the context: `crates/recursive-agent-sandbox/src/lib.rs:221`;
- effect-surface test is only a source-string assertion: `crates/recursive-agent-contracts/tests/phase1_effect_surface.rs:18`.

An in-process caller can derive IDs, create a permit store/binding, call `consume_authorized`, then invoke the same shell effect repeatedly without the canonical runner or receipts. Bubblewrap still contains the process, but authority and evidence ownership are bypassed.

Minimum fix: only the canonical runner owns an unforgeable one-shot dispatch path; actual sandbox execution is not a downstream public API; the effect token is consumed by value; public self-issuance cannot yield an effect-capable token.

Acceptance: an external integration test cannot self-mint effect authority; a second dispatch attempt with one authorization produces zero additional starts.

## P1-2 — Strict verification does not prove one continuous permit transition

Evidence:

- lifecycle stores only coarse step phases: `crates/recursive-agent-contracts/src/lib.rs:520`;
- `PermitRevoked(Ok)` completes a step without observation: `contracts/src/lib.rs:635`;
- finalization can then default to success: `contracts/src/lib.rs:747`;
- permit evidence does not validate transition time: `policy/src/lib.rs:291`;
- ledger verifies each permit artifact independently: `ledger/src/lib.rs:657`.

Strict verification can admit `issued(A) -> consumed/revoked(B)`, pre-validity consumption, revoke-before-issue, or a revoked effect followed by successful finalization without observation.

Minimum fix: retain one permit ID and binding digest per step; validate issue/consume/reject/revoke identity, order, validity, and timestamps; effect revocation cannot become successful completion; successful effects require consumed authority plus an observed artifact.

Acceptance: cross-permit issue/consume, consume-before-validity, revoke-before-issue, and revoked-effect-success chains fail every authoritative verifier.

## P1-3 — Failed runs are reported as successful by active operator surfaces

Evidence:

- runner returns `Ok(RunSummary)` for non-success terminals: `runner/src/lib.rs:293`;
- CLI maps every `Ok` to process success and omits terminal state: `cli/src/main.rs:89`;
- daemon returns success-shaped JSON without terminal state: `daemon/src/lib.rs:79`.

Nonzero exit, signal, timeout, truncation, or sandbox failure can produce truthful failed receipts while `ra run` exits zero and daemon clients see a success-shaped response.

Minimum fix: always expose terminal state; map non-success runs to nonzero CLI status and typed daemon failure responses. Keep the daemon command disabled until Phase 3 if necessary.

Acceptance: `/usr/bin/false`, signal, timeout, and output-overrun fixtures produce nonzero CLI exits and typed daemon failure responses.

## P1-4 — Runner ownership can split across different run-directory inodes

Evidence:

- receipt chain pins the run root: `runner/src/lib.rs:144`;
- artifacts and permits reopen it by pathname: `runner/src/lib.rs:156`;
- a completed run returns without strict verified readback: `runner/src/lib.rs:280`.

Concurrent run-directory replacement can place receipts in the original pinned directory and artifacts/permits in a replacement, allow dispatch, and return a success summary whose advertised directory cannot verify.

Minimum fix: derive ledger, artifact, and permit stores descriptor-relatively from one pinned run-root capability and perform expected-run strict verification on that exact pinned root before successful return.

Acceptance: replacing the run directory between owner construction phases either causes typed zero-dispatch failure or all owners stay on one inode and final strict verification succeeds.

## Prior blockers now independently supported

Fresh evidence supports fixed root-owned Bash/Bubblewrap descriptors, FD closure, setup proof, malicious sibling exclusion, seccomp network denial, process containment, network opt-in rejection, shell terminal truth, effective-policy binding, bounded replay snapshots, endpoint normalization, mandatory lints, and provider-network quarantine.

Memory mutation, skills, provider networking, MCP client spawn, delegation, and MCTS remain later-phase/quarantined surfaces.

## Executed gates

- workspace tests: exit 0, 105 passed, 0 failed, 0 ignored;
- strict Clippy: reviewer blocked by read-only Cargo target lock; controller v4 independently passed it;
- formatting and diff checks: exit 0;
- sandbox: 12 passed;
- runner hardening v3: 4 passed;
- lifecycle: 7 passed;
- effect surface: 1 passed;
- workspace lints: 1 passed;
- policy lifecycle: 7 passed;
- provider secret contract: 7 passed;
- memory: 6 passed;
- skills: 5 passed.

No files were modified by the reviewer. Tracked code diff digest remained `b7b3387c85450ef999099a9e1e21b16443d93e63e001ff38445fe1846a4091df`.

**Disposition:** Phase 1 remains quarantined until all four blockers have RED regressions, fixes, a green controller matrix, and independent hostile admission.
