# Recursive Agent Claim Fence

**Authority:** This file governs current capability language for the `recursive-agent` working tree until superseded by a verified release-closure receipt.

**Evidence cutoff:** 2026-08-04 Phase 0 baseline at `docs/receipts/phase-0/baseline/manifest.json`.

## Rules

1. A capability is not `verified` unless its row names a durable receipt or test artifact that exercises the public boundary and required negative cases.
2. Compilation, formatting, unit tests, a configured field, a type name, or a source comment does not prove runtime behavior.
3. Historical reports remain historical evidence. They do not override this fence or prove the current dirty working tree.
4. External owner results are `source-observed` until reproduced through this workspace.
5. `complete`, `production`, `secure`, `sandboxed`, `durable`, `replayable`, `recursive`, `MCTS`, `Hermes-integrated`, and equivalent terms are forbidden unless the corresponding row is `verified`.
6. A failed or unavailable gate remains visible. It must not be converted into success language.
7. Adapters may not claim execution, policy, or receipt authority; those belong to the native runtime and canonical owners.

## Evidence states

- `verified`: reproduced against the current source generation with an inspectable receipt.
- `observed`: directly inspected in current source or tool output, without full behavioral proof.
- `source-observed`: reported by an external owner or historical artifact, not reproduced here.
- `prototype`: code exists but acceptance semantics are missing.
- `blocked`: a named required gate failed or required evidence is absent.
- `not implemented`: no admitted implementation exists.

## Current claim ledger

| Claim ID | Capability | Current state | Admissible language | Required evidence to promote | Current evidence / blocker |
|---|---|---|---|---|---|
| RA-C001 | Workspace formats | verified | `cargo fmt --all -- --check` passed at the Phase 0 baseline | Rerun after final source quiescence | `docs/receipts/phase-0/baseline/fmt.txt` |
| RA-C002 | Workspace tests | verified, smoke scope only | Current workspace unit/all-target tests passed; this is not capability acceptance | Hostile and process-boundary acceptance suites | `docs/receipts/phase-0/baseline/tests.txt` |
| RA-C003 | Strict Clippy | verified at baseline | Strict all-target Clippy passed at the Phase 0 baseline | Rerun after final source quiescence | `docs/receipts/phase-0/baseline/clippy.txt` |
| RA-C004 | Supply-chain policy | blocked | `cargo deny check` is currently failing | Valid policy plus green `cargo deny check` receipt | `docs/receipts/phase-0/baseline/deny.txt` |
| RA-C005 | Fuzzing | blocked | A receipt fuzz source exists, but an operational fuzz toolchain/package is not proven | Pinned toolchain, runnable target, bounded clean fuzz receipt | `docs/receipts/phase-0/baseline/fuzz_version.txt` |
| RA-C006 | Deterministic material identity | prototype / blocked | Identity contracts exist but deterministic, domain-separated derivation is not yet certified | Cross-process and restart stability tests; no random/timestamp authoritative IDs | Phase 1 acceptance pending |
| RA-C007 | Terminal lifecycle truth | prototype / blocked | Runner lifecycle exists but failed-step dominance is not yet certified | Negative lifecycle matrix proving failed/cancelled/denied/timed-out/sandbox-failed/corrupted cannot finalize success | Phase 1 acceptance pending |
| RA-C008 | Permit lifecycle | prototype / blocked | Policy checks exist; one-shot atomic permit consumption is not certified | concurrent double-spend and restart persistence tests | Phase 1 acceptance pending |
| RA-C009 | Receipt ledger integrity | prototype / blocked | Append-only receipt code exists; crash-safe recovery and full artifact binding are not certified | truncate/tamper/reopen/verify tests with typed failures | Phase 1 acceptance pending |
| RA-C010 | OS sandboxing | blocked | Linux process isolation is attempted, but current source can report `sandboxed: true` after Landlock setup fails | fail-closed enforcement outcome plus negative filesystem/network/process tests | Current source in `crates/recursive-agent-sandbox/src/lib.rs` |
| RA-C011 | Secret-safe provider boundary | prototype / blocked | Provider adapters exist; secret-free serialization and debug output are not certified | redaction/serialization tests and secure resolver path | Phase 1 acceptance pending |
| RA-C012 | Canonical native runtime | not implemented | Multiple crates exist; there is not yet one certified `RuntimeService` owning the full operation path | no-MCP embedded execution with policy, sandbox, events, artifacts, and verified readback | Phases 2–4 pending |
| RA-C013 | Native daemon IPC | prototype / blocked | A Unix-socket daemon prototype exists; peer admission, owned-socket safety, framing, and concurrency limits are not certified | process-boundary malformed-frame, peer, socket-ownership, concurrency, stream, and cancel tests | Phase 3 pending |
| RA-C014 | Hermes integration | not implemented | No first-class no-MCP Hermes runtime execution is installed or certified | isolated Hermes plugin fixture traversing the native runtime with negative cases | Phase 4 pending; active Hermes profile must not be changed without separate authority |
| RA-C015 | Durable scheduling and recovery | not implemented | No certified durable queue/resume owner exists | kill/restart/reclaim/resume/idempotency/replay suite | Phase 5 pending |
| RA-C016 | MCP parity | prototype / blocked | An MCP adapter exists but may bypass canonical runtime semantics | parity suite showing same IDs, events, terminal state, artifacts, and receipt digest as native/CLI paths | Phase 6 pending |
| RA-C017 | Recursive delegation | prototype / blocked | Subprocess delegation scaffolding exists; attenuation, budgets, cancellation, lineage, and child-receipt closure are not certified | two-level attenuation and cancellation tests plus remote admission negatives | Phase 7 pending |
| RA-C018 | Provenance-aware memory | prototype / blocked | Local SQLite scaffolding exists; scoped, provenance-bearing owner integration is not certified | tenant/session/run isolation, read/write receipt, contradiction and restart tests | Phase 8 pending |
| RA-C019 | Governed skills | prototype / blocked | JSON/template scaffolding exists; source receipt, validation, promotion, versioning, revocation, and safe rendering are not certified | full candidate-to-revoke lifecycle with negative provenance tests | Phase 9 pending |
| RA-C020 | MCTS / UCT search | false as currently named | Current random sampling must be described as a prototype selector, not MCTS | deterministic UCT selection, expansion, backpropagation, budget, restart, cancellation, and branch receipt tests | Phase 10 pending |
| RA-C021 | Replay | prototype / blocked | Recorded inputs/outputs may exist; deterministic replay, evidence replay, and unavailable replay are not yet distinguished end to end | typed replay classification with changed-external-state and missing-material negatives | Phases 5 and 12 pending |
| RA-C022 | Offline verification/export | not implemented | No certified portable evidence bundle verifier exists | fresh-process export and tamper verification suite | Phase 12 pending |
| RA-C023 | Operator TUI/web | not implemented | No operator control surface is certified | tested projection-only surface with no direct effect path | Phase 12 pending |
| RA-C024 | External receipt anchoring | not implemented / optional | No external witness or anchor is configured or claimed | receipt-only anchor adapter plus offline verification and failure semantics | Optional Phase 12 gate |
| RA-C025 | Production readiness | blocked | This is a founder-led R&D workspace with uncommitted prototypes, not a production release | all mandatory phase gates, hostile acceptance, supply-chain/fuzz gates, release receipt, and explicit release authority | Phase 13 pending |

## Mandatory wording until closure

Use:

> `recursive-agent` is an in-development, local-first execution-kernel workspace. The current tree contains verified smoke-level build/test gates and multiple prototype components. Native runtime, sandbox, durability, recursion, memory, skill, search, adapter-parity, and release claims remain blocked until their named acceptance receipts pass.

Do not use:

- “Phases 4–6 are complete.”
- “Production-ready,” “secure sandbox,” or “enterprise-ready.”
- “MCTS” for the current random sampler.
- “Hermes integrated” before the no-MCP plugin fixture and isolated-host smoke pass.
- “Durable resume” when only terminal rows survive restart.
- “Deterministic replay” when external provider state or inputs were not retained.

## Promotion procedure

A claim row may move to `verified` only when all of the following are recorded:

1. source generation or exact commit;
2. public entry point exercised;
3. canonical owner and durable identity;
4. positive and negative tests;
5. exact commands and exit codes;
6. receipt/artifact paths and SHA-256 digests;
7. replay or explicit replay limitation;
8. rollback or quarantine procedure;
9. independent controller rerun after the implementation agent exits;
10. no unresolved higher-severity defect invalidating the claim.
