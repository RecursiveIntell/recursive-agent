# Recursive Agent × Coding Stack — Pairing Audit

**Evidence cutoff:** 2026-08-09 local checkout inspection.
**Scope:** immediate Git roots under `/home/sikmindz/Coding`, normalized so duplicate worktrees/releases are not treated as separate products.
**Decision class:** advisory architecture/portfolio assessment; no source, configuration, or remote state was changed.

## Verdict

The strongest direction is not another standalone agent app. It is a **Witnessed Workbench** whose distinct owners remain separate:

```text
Hermes (operator interaction)
  -> Agent Graph (bounded orchestration only)
  -> Recursive Agent (authoritative execution, permits, receipts, run packs)
  -> ClaimLedger (claim/evidence judgments)
  -> Mnemes / semantic-memory (durable, bitemporal memory and replication)
  -> Gloss (human inspection and research UI)
  -> benchmark (fixtures, repeatable evaluation, claim boundary)
```

The core immediate product pairing is **Recursive Agent + Hermes + its existing Auditable Run Pack**. The next architectural pairing is **Recursive Agent + Mnemes**, with ClaimLedger and semantic-memory supplied as projections—not alternate execution or evidence authorities.

## Evidence observed locally

| Surface | Observed role | Current signal | Boundary relevant to Recursive Agent |
|---|---|---|---|
| `recursive-agent` | Rust execution/evidence kernel | README describes M0 deterministic receipt, offline verification, and disk replay. HEAD `e644c46` is dirty with retained receipts and run-pack closeout material. | Owns execution authority, permits, run lifecycle, run-pack export/verify/replay. |
| `integrations/hermes-native/` in `recursive-agent` | Hermes adapter | Existing plugin/tests and Phase 4 closeout are present. | Hermes must remain a thin operator adapter; it must not mint or reinterpret execution evidence. |
| `mnemes` | multi-device memory control plane | Manifest describes device/actor provenance, bitemporal lineage, routing, idempotent envelopes, replication; HEAD `d38659b`, clean. | Owns replicated durable memory, not execution lifecycle. |
| `Libraries/semantic-memory` | retrieval/memory substrate | `recursive-agent/docs/owner-admission.md` conditionally admits it behind a generation-fenced adapter. | Owns retrieval/procedural-memory artifacts; execution effects remain Recursive Agent evidence. |
| `ClaimLedger` / `Libraries/claim-ledger` | claim/evidence support ledger | README says bundle-scoped support judgments and explicitly says Gloss consumes, not redefines, its semantics. `recursive-agent` already names it as a direct dependency/envelope owner. | Owns claim support/proof semantics; must not become an execution ledger. |
| `agent-graph-mcp-release` | graph orchestration MCP surface | README claims typed graph workflows, checkpoints/resume, approvals, and receipts. Two local checkouts share one remote and are dirty. | Orchestrates bounded work; must not create a parallel authoritative executor. |
| `Gloss` | source-grounded desktop research/chat | Tauri source has semantic-memory integration and receipt-aware design; source-build maturity only. | Best human inspection plane for run packs, not an alternate store. |
| `benchmark` | deterministic local benchmark harness | README limits it to synthetic fixtures and explicitly disclaims performance proof. | Owns fixtures/adapters/replay checks and claim-boundary tests. |

### Inventory normalization notes

- `mnemes`, `mnemes-sync-recovery`, and `mnemes-replication` resolve to the same Git remote and are one product identity.
- `agent-graph-mcp-release` and `agent-graph-mcp-proof-v1` resolve to the same remote and are one product identity; they are operational copies, not two product bets.
- `Libraries/semantic-memory` and `worktrees/semantic-memory-cert` resolve to one remote identity.
- Multiple web/portfolio surfaces exist (`website`, `recursiveintell-web`, `stack-showcase`, `realtry-web`). They should not all become product owners; select one publishing surface later.

## Ranked combinations

Scores are 0–5 decision aids, not performance measurements. Formula: `(fit×.20)+(leverage×.20)+(proof×.15)+(differentiation×.15)+(distribution×.10)+(time_to_proof×.10)+(maintenance×.10)`.

| Rank | Combination | Fit | Leverage | Proof | Differentiation | Distribution | Time | Maintain | Score / 5 | Disposition |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 1 | Recursive Agent + Hermes native adapter + Run Pack | 5 | 5 | 4 | 4 | 4 | 5 | 4 | 4.50 | **CONCENTRATE** |
| 2 | Recursive Agent + Mnemes + ClaimLedger/semantic-memory projections | 5 | 5 | 3 | 5 | 3 | 3 | 3 | 4.10 | **MAINTAIN AS SUBSTRATE; gate integration** |
| 3 | Recursive Agent + Gloss run-pack inspector | 4 | 4 | 3 | 4 | 4 | 3 | 3 | 3.65 | **PREPARE ONLY** |
| 4 | Recursive Agent + benchmark evidence matrix | 4 | 3 | 4 | 3 | 2 | 4 | 4 | 3.45 | **MAINTAIN AS PROOF SUBSTRATE** |
| 5 | Agent Graph -> Recursive Agent supervised execution | 4 | 4 | 2 | 4 | 3 | 2 | 2 | 3.20 | **GATED RESEARCH** |

## The three pairings worth pursuing

### 1. Hermes → Recursive Agent → portable run-pack (first external workflow)

**Why now:** Recursive Agent already contains a Hermes-native adapter surface and the locally certified run-pack CLI path. It offers the shortest path to a complete operator-visible workflow without expanding scope.

- **Canonical owners:** Hermes owns interaction/tool routing; Recursive Agent owns authorization, execution, receipts, and pack bytes.
- **Forbidden shadow owner:** Hermes session state or an adapter must never be considered the authoritative run ledger.
- **Smallest decisive proof:** from a clean process, start a bounded deterministic operation through the Hermes adapter, export one pack, copy it after deleting the original run, then verify and replay offline. The record must bind operator-facing output to the pack manifest/run ID.
- **Acceptance gate:** existing `scripts/verify-run-pack.sh`, adapter E2E test, plus a new *cross-boundary* test that asserts the adapter cannot forge a run ID or modify pack content.
- **Kill/freeze criterion:** if the adapter bypasses the native permit/ledger boundary or the clean-process test needs provider/network access, freeze integration and repair the boundary first.

### 2. Recursive Agent → ClaimLedger → Mnemes / semantic-memory (governed memory projection)

**Why it matters:** this combines execution-grounded evidence with claim-level support and durable multi-device retrieval. It is the defensible differentiator: an agent result can be replayed, assessed as a claim, and retained/replicated with provenance.

- **Canonical owners:** Recursive Agent emits immutable execution/run-pack evidence; ClaimLedger evaluates support/testimony; Mnemes owns replication and bitemporal memory; semantic-memory owns retrieval/procedural-memory projections.
- **Forbidden shadow owner:** no duplicate SQLite “agent memory” store inside Recursive Agent; no claim-support state inferred directly in the UI.
- **Smallest decisive proof:** one completed run-pack produces a projection envelope; ClaimLedger creates a bundle-scoped testimony that references pack digests; Mnemes imports an idempotent projection; a second device/store verifies the referenced pack and shows the claim’s provenance chain.
- **Acceptance gate:** idempotent re-import, digest/backpointer verification, supersession behavior, and explicit failure when a referenced pack is unavailable or tampered.
- **Risk:** this is not currently demonstrated end-to-end. `recursive-agent` admission documents semantic-memory as generation-fenced/conditional, so direct dependency changes are premature until exact generation and projection contract are admitted.

### 3. Gloss as the human inspection plane for exported packs

**Why it matters:** Gloss already has local-first, source-grounded, receipt-aware research behavior and substantial semantic-memory work. A read-only pack inspector yields a coherent user-facing story without turning Gloss into another executor.

- **Canonical owners:** Recursive Agent writes/verifies/replays; Gloss renders pack manifest, event/receipt chain, evidence links, and degraded/unsupported states.
- **Forbidden shadow owner:** Gloss must not reconstruct “its own” ledger or silently treat a local display cache as verification.
- **Smallest decisive proof:** import a verified pack into a disposable Gloss notebook, render chain/event/claim links, and display a strong warning for missing or tampered artifacts.
- **Acceptance gate:** a fixture pack shown accurately, a tampered pack rejected by Recursive Agent before UI rendering, and a no-retrieval/degraded UI path that does not claim verification.
- **Risk:** Gloss is source-build only and live GUI certification remains incomplete; keep this after the first Hermes proof.

## Explicit defer: Agent Graph as Recursive Agent’s runtime

Agent Graph pairs well **above** Recursive Agent, not inside it. Use it to plan/coordinate bounded runs after a supervised adapter contract exists. Do not embed graph state, graph receipts, or graph scheduling as Recursive Agent’s authoritative run state. The local daemon registry is currently capacity-exhausted (261 registered graphs reported against capacity 256 during this audit), so any new operational dependence would add an immediate reliability blocker.

## 30/60/90-day decision sequence

| Window | Bounded outcome | Gate | Stop condition |
|---|---|---|---|
| 0–30 days | One reproducible Hermes-to-offline-run-pack workflow | clean-process replay + adapter boundary test | any authority bypass or provider/network requirement |
| 31–60 days | Projection contract from run-pack to ClaimLedger and Mnemes | idempotent import + digest/backpointer + tamper rejection | duplicate evidence/memory owner or generation mismatch |
| 61–90 days | Read-only Gloss inspection + a benchmarked scenario matrix | GUI smoke + fixture replay matrix + claim-safe case study | UI presents cached/unverified material as verified |

## What not to do

1. Do not create a second agent-memory database inside Recursive Agent.
2. Do not make Agent Graph a second executor or authoritative ledger.
3. Do not put claim adjudication into Gloss or Hermes adapters.
4. Do not use the benchmark’s synthetic fixtures as external reliability/performance claims.
5. Do not fan out across the duplicate Agent Graph/Mnemes worktrees; reconcile to one canonical checkout before mutation.

## Evidence and uncertainty

This report is grounded in local manifests, READMEs, current Git metadata, and Recursive Agent’s own admission/boundary documentation. It does **not** reproduce live GUI behavior, multi-device replication, registry/package ownership, provider-backed execution, or a full workspace build. Historical semantic-memory retrieval was used only as context and was not accepted as current proof. The attempted Agent Graph advisory council was not run: no compatible registered graph existed under the queried name and new graph creation failed because registry capacity is exhausted. That operational failure is itself current evidence, but no model-generated conclusion is used here.

## Rollback / quarantine

No changes were made. The recommended first proof is additive and should live behind a fixture/test-only adapter boundary. If it fails, remove the adapter/projection implementation and retain the pack fixture, logs, and receipt as a quarantined failing case; do not delete original run evidence.
