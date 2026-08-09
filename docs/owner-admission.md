# Recursive Agent Canonical-Owner Admission Ledger

**Phase:** 0, Task 0.3<br>
**Recorded:** 2026-08-04<br>
**Consumer workspace:** `/home/sikmindz/Coding/recursive-agent`<br>
**Consumer baseline:** branch `main`, HEAD `3805f7abf319e07e47f1c20b862e614c3dad164f`, dirty generation preserved at `docs/receipts/phase-0/baseline/manifest.json`.

This ledger decides which external contracts may own truth for `recursive-agent`. It does not claim that an admitted owner is already integrated or behaviorally verified through this workspace.

## Admission rules

1. `recursive-agent` remains the only owner of operation scheduling, policy/effect ordering, lifecycle terminality, durable run/event state, cancellation, replay classification, and authoritative run receipt publication.
2. An external crate owns only the concepts its current source explicitly owns. Names and README claims are insufficient.
3. A protocol or orchestration crate is never the internal execution kernel.
4. Dirty external sources require a source-generation fence and revalidation before acceptance.
5. An owner-provided schema/receipt does not prove the represented effect occurred.
6. No external repository may be modified by this implementation pass.
7. Path dependencies are local development bindings, not reproducible release pins. Phase 13 must replace or bind them to a reproducible release/source manifest before any release claim.

## Source revisions

Ten candidates are directories in `/home/sikmindz/Coding/Libraries` on branch `main`, reported HEAD `716716f809ef08ff046a1227f346bbd92a5d87f7`. Repository cleanliness is **blocked/unknown**, not clean: `git status --porcelain=v1` exits 128 because of a stale worktree metadata reference at `/home/sikmindz/Coding/Libraries/semantic-memory-mcp/.git/worktrees/semantic-memory-mcp-transport`. This pass does not repair or mutate that sibling repository. Admission therefore binds each owner directory to an independently computed source-generation hash that excludes `.git` and `target`:

| Owner | Package | Source-generation SHA-256 | Files |
|---|---|---|---:|
| `boundary-compiler` | 0.1.0, Rust 1.75 | `24638f93681825ca54fc5cc3294674da139499134f5ee3dd6b846733bdbba148` | 9 |
| `stack-ids` | 0.1.3, Rust 1.75.0 | `0dc6183d6dc101df2c581cc6d6f8cf98c20bc842f8926ffe47e32533086f5ba2` | 17 |
| `bitemporal-runtime` | 0.1.0, Rust 1.75 | `3c2cbc2803bc22393c85040020e8a1e9a56a093542cbed0eb31b4b73fc0cd8da` | 7 |
| `claim-ledger` | 0.2.1 | `cf81d7e490fb2a62108970acf145f0ffe0dc43ccc9db4c52c0571ff8c615627d` | 19 |
| `llm-tool-runtime` | 0.1.0, Rust 1.75 | `9cd1b843dccba32564c38d522cd8c9cf3c3ce0e1a284297861eb586624d93439` | 12 |
| `authority-delegation` | 0.1.0, Rust 1.75.0 | `7c27b4a5f60177658887e7643deeba11696aba4b0fd37b70e5df565dadc6593b` | 14 |
| `assurance-runtime` | 0.1.0, Rust 1.75.0 | `6380d0a72eec25ec3b07e177ccdc168b985e5c455ae2ce1fea87b98a8bc23b1d` | 18 |
| `remote-oracle-admission` | 0.1.0, Rust 1.75.0 | `05b4f97ac507f9d8bc12a238b436ded95b0954e5d5af4f8dee15210c46a300d8` | 6 |
| `agent-graph` | 0.2.0 | `735a9ff4371c7e1ea26ac4fe3dc719ad259f9d333935b282bd6a1e216273acdd` | 65 |
| `kernel-oracles` | 0.1.0, Rust 1.75.0 | `c093940c850c547a11d4863a073061606a650141ff9e5706a32be227357ba835` | 4 |

`semantic-memory` is a separate dirty repository on branch `main`, HEAD `bcfe3af6e311ac27b31716b6a47ab2a40efb6cb2`, package version 0.5.14, Rust 1.75. At admission time:

- status entries: 8;
- status SHA-256: `04891e99d6b6f43e1f0765f3473b6c2f5dee32bc614fc3b73a3bf487aa9c4215`;
- tracked diff SHA-256: `7a8412d174a4eb5ccfcb375139a633e73812bed5de387750bbe9394651ffc72f`;
- tracked working-generation SHA-256: `4eec433d80837e0e645554b0bdc1b540f023bdb01ec3691585bb1644bcee1c58` across 165 tracked files.

Any change to these revisions or the semantic-memory generation invalidates this admission until rechecked.

## Owner decisions

### `boundary-compiler` — admit directly, bounded surface

**Owned truth:** RFC 8785/JCS canonical bytes and canonical-value BLAKE3 digest.

**Admitted API:** `Canonicalizer`, `parse_with_dup_check`, `parse_and_validate`, and canonical `ContentDigest` from `src/lib.rs:39-51` and `src/digest.rs:10-29`.

**Rejected surface:** `SchemaValidator` as a validation claim. Its current source explicitly says it is a stub that always succeeds (`src/schema.rs:13-28`).

**Integration law:** all external envelopes and material-ID preimages use this canonicalizer; schema enforcement remains typed contract validation in `recursive-agent-contracts` until a real schema owner is admitted.

### `stack-ids` — admit directly as ID/digest owner

**Owned truth:** opaque cross-crate IDs, scopes, trace context, and content digests (`src/lib.rs:3-25`).

**Admitted types:** `KernelRunId`, `AttemptId`, `ControlReceiptId`, `ExecutionPermitId`, `ArtifactId`, `EffectIntentId`, `ContentDigest`, `Scope`, `ScopeKey`, and `TraceCtx`. The ID macro exposes validated and domain-labelled constructors (`src/ids.rs:43-83`).

**Restrictions:**

- never use `random()` for authoritative identity;
- hash canonical semantic material first, then use a versioned domain-specific deterministic constructor;
- `TraceCtx::generate()` is correlation-only, not authoritative identity;
- local `FamilyId` may exist only as an explicitly fenced wire-compatibility wrapper while call sites migrate; it cannot be a second ID authority.

**Known gap:** no exact `RecursiveAgentStepId` type exists. Phase 1 may use `AttemptId` for bounded step-attempt identity and must keep the domain explicit; Phase 13 decides whether a reusable upstream type is warranted without modifying the owner during this pass.

### `bitemporal-runtime` — admit directly for temporal semantics only

**Owned truth:** valid time versus recorded time, supersession receipts, as-of queries, and temporal snapshots (`src/types.rs:13-96`, `src/queries.rs:24-118`).

**Restrictions:** it does not own run identity, receipt chaining, durable run storage, or operation scheduling. Its generic `RecordId` cannot replace stack-ids owner types.

**Use:** contract projections and later memory/claim history; no current P0 runtime dependency is required.

### `claim-ledger` — admit behind a projection adapter

**Owned truth:** claims, source spans, evidence bundles, support judgments/admissions, contradictions, proof debt, append-only claim events, and claim/export receipts (`src/lib.rs:1-74`).

**Admitted APIs:** `Claim`, `EvidenceBundle`, `SupportJudgment`, `LedgerEvent`, `verify_ledger`, `verify_snapshot`, proof-debt gates, and export/admission receipts.

**Restrictions:**

- its ULID/hash helper IDs are not recursive-agent run/step/permit identity;
- it consumes verified runtime evidence but cannot certify the runtime that produced it;
- no adapter may copy claim truth into the recursive-agent run ledger.

**Use:** Phase 12/13 evidence projection after native receipts verify.

### `llm-tool-runtime` — admit behind the canonical runtime

**Owned truth:** tool definitions, side-effect/idempotency/output classes, execution-permit contract shape, tool registry, provider-facing tool schemas, tool receipts, and starter tool ports (`src/lib.rs:1-11`, `src/contracts.rs:15-144`, `src/starter_tools.rs:12-65`).

**Restrictions:**

- `recursive-agent-runner`/`RuntimeService` owns scheduling, authorization order, permit consumption, sandbox invocation, event publication, and run terminality;
- no direct adapter call into `llm-tool-runtime` may bypass the runtime;
- an llm-tool-runtime receipt becomes a child evidence item in the native receipt, not a second terminal run receipt.

**Use:** Phase 2 Task 2.4 replaces the current direct switch in `recursive-agent-tools` with a thin admitted tool-runtime boundary.

### `authority-delegation` — admit schema/profile surfaces behind enforcement

**Owned truth:** `CapabilityClassV1`, `AuthorityLeaseV1`, `DelegationBundleV1`, `AuthorityChainV1`, break-glass/revocation/on-behalf artifacts, and separation-of-duties artifacts (`src/lib.rs:18-43`, `src/capability.rs:82-222`).

**Important limitation:** the crate describes itself as typed authority surfaces and bounded profiles, not a general access-control runtime (`src/lib.rs:1-4`). Its `validate()` methods establish structural validity, not attenuation or effect authorization.

**Use:** Phase 7 imports these artifacts and enforces strict subset attenuation, budget monotonicity, expiry, depth, cancellation, and child-receipt closure in the canonical runtime. Do not claim delegated-authority enforcement from successful deserialization alone.

### `assurance-runtime` — admit as release projection only

**Owned truth:** assurance cases, control mappings, deployment profiles, operating envelopes, hazards, certification bundles, residual-risk acceptance, and release-readiness decisions (`src/lib.rs:17-44`, `src/assurance.rs:23-190`).

**Important limitation:** it publishes typed assurance surfaces rather than a standalone release runtime (`src/lib.rs:1-4`).

**Use:** Phase 13 may emit a release-readiness projection after all mandatory native evidence exists. It cannot self-certify recursive-agent or turn missing evidence into readiness.

### `remote-oracle-admission` — admit behind local remote admission

**Owned truth:** remote leases, disclosure/exactness classes, slice requests/results, replay tickets, attestation revocation/supersession, and re-admission artifact shapes (`src/lib.rs:1-19`, `src/lib.rs:70-300`).

**Restrictions:** current validation is mostly structural/non-empty checks. Local worker identity, signature/trust-root verification, expiry interpretation, authority attenuation, result re-admission, and artifact verification remain mandatory runtime policy.

**Use:** Phase 7 remote adapter; returned remote evidence stays untrusted until locally admitted.

### `agent-graph` — admit as an orchestration edge

**Owned truth:** graph structure/execution, nodes/edges/routers/joins, interrupts, checkpoints, retries, event sinks, graph execution receipts, and cancellable graph control (`src/lib.rs:35-66`, `src/checkpoint_store.rs:80-87`, `src/event_sink.rs:205-212`, `src/engine.rs:55-176`).

**Restrictions:**

- never make graph state, graph receipt, or MCP request the recursive-agent operation model;
- graph nodes that can cause effects must submit native operation envelopes through `RuntimeService`;
- graph checkpoint durability does not replace run/event/permit/receipt durability;
- the observed Luna planning graph failure is not evidence of application runtime correctness.

**Use:** Phase 6 adapter and Phase 10 search orchestration where useful, with native receipt correlation.

### `semantic-memory` — conditionally admit behind a generation-fenced adapter

**Owned truth:** authoritative SQLite memory state, scoped hybrid/BM25/vector retrieval, governed mutation authority, origin-authority labels, transition contracts, evidence-aware retrieval, and procedural-memory lifecycle (`src/lib.rs:27-78`, `src/lib.rs:159-215`, `src/lib.rs:672-820`, `src/authority.rs:45-74`, `src/lib.rs:2657-2685`).

**Admission condition:** because the owner tree is dirty, Phase 8 must recheck the recorded source-generation hash immediately before adding a path dependency and again before acceptance. A mismatch stops the phase for re-admission.

**Restrictions:**

- delete/quarantine the recursive-agent shadow memory path only after migration tests prove owner read/write parity;
- use `MemoryAuthority` for governed writes; compatibility `add_fact` paths cannot support authoritative write claims;
- preserve explicit namespace, tenant/principal, session/run/step, valid/recorded time, source receipt, and trust state;
- do not import semantic-memory’s large default feature surface accidentally; select the smallest admitted feature set and record it;
- semantic-memory procedural-memory types own procedure artifacts/lifecycle; recursive-agent owns execution and supplies effect evidence.

### `kernel-oracles` — defer; optional bounded adjudication only

**Owned truth:** bounded exact/conservative graph assessments, delta parity, temporal replay assessment, and bounded refutation (`src/lib.rs:10-87`, `src/lib.rs:92-215`).

**Restrictions:** it is not a general correctness verifier, policy engine, release gate, or execution owner. It must never be required for the first native vertical slice.

**Use:** optional Phase 10/12 branch adjudication after the runtime and evidence paths are already correct.

## Dependency-cycle and integration decisions

- Contracts may depend only on neutral primitive owners such as `stack-ids`, `boundary-compiler`, and narrowly `bitemporal-runtime`; they must not depend on adapters, runner, memory, graph, or MCP.
- Policy may consume owner ID and authority artifact types but cannot depend on runner, tools, daemon, or adapters.
- Ledger depends on contracts/primitives only; claim-ledger and assurance-runtime consume exports later rather than becoming ledger dependencies.
- Runner may depend on contracts, policy, ledger, sandbox, and the admitted tool boundary. It must not depend on CLI, daemon, MCP, Hermes, TUI, or web adapters.
- Memory, claim, assurance, graph, remote, Hermes, CLI, MCP, TUI, and web integrations depend inward on a narrow runtime interface. The runtime never imports their transport models.
- If a cycle appears, move only the pure shared contract into `recursive-agent-contracts` or an already admitted neutral owner; do not add callback globals, feature-dependent shadow types, or reverse dependencies.

## Phase 0 gate

Phase 0 owner admission is satisfied for planning and implementation only when:

- every current or planned external dependency above has an explicit decision;
- source revisions/generations remain unchanged;
- no external repository was edited;
- later phase prompts cite this ledger and recheck any conditional source generation.

This document does not mark any later capability as implemented or verified.
