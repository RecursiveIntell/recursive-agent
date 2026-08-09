# Cross-Phase Parallelization Agent Graph Advisory

- Run: `run-19fd16caacb-6`
- Graph: `recursive-agent-cross-phase-parallelization-council`
- Version: `sha256:024f8060745cdb30dfaf0db96c9a28b361d9f7cfb686d60aac021875102813af`
- Observed execution: success=true; llm_calls=5; nodes=7; wall_clock_ms=33648
- Evidence class: model-generated advisory; not source verification

# Critical-Path Execution Wave Plan — Phases 2-13

## Dependency DAG (Strict Serial Chain)

```
Phase 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13
   ↑       ↑    ↑    ↑    ↑    ↑    ↑    ↑     ↑     ↑     ↑
   │       │    │    │    │    │    │    │     │     │     │
   └─── All edges mandatory; no phase can skip or parallelize
```

## Wave A: Parallel-Now (Immediate Start)

| Task | Classification | Integration Edge |
|------|---------------|------------------|
| CI pipeline (lint, unit, build) | **parallel-now** | Pre-integration gate for Phase 11 |
| Static analysis for anti-bypass | **parallel-now** | Hard gate for Phase 6 certification |
| Evidence collection framework | **parallel-now** | Feeds Phase 10/11 evidence requirements |
| Property-based tests (pure functions) | **parallel-now** | Directly reusable in Phase 11 |
| Failure injection framework | **parallel-now** | Validated in Phase 11 CI |
| Observability dashboards / UX prototypes | **parallel-now** | Consumes Phase 12 data contracts |
| Documentation / canonical law training | **parallel-now** | Continuous; no integration gate |

## Wave B: After Phase 1 (RuntimeService Contract Frozen)

| Task | Classification | Trigger |
|------|---------------|---------|
| Migration tooling skeleton → aligns to Phase 2 schema | **prepare-only** | Phase 2 schema frozen |
| Fuzz harnesses → updated to real IPC | **prepare-only** | Phase 3 boundary signed |
| Offline verification tooling | **prepare-only** | Phase 8 provenance model |

## Wave C: After RuntimeService Available

| Task | Classification | Trigger |
|------|---------------|---------|
| Migration tooling full implementation | **prepare-only** | Phase 2 integration tests passing |
| Fuzz harnesses (real IPC) | **prepare-only** | Phase 3 boundary signed |
| Observability dashboards (production) | **parallel-now** | Phase 12 data contracts |

## Hard-Blocked Items (No Parallel Execution)

- **Phases 2-13**: Strict serial chain; each requires prior phase gate
- **No phase can skip**: Mandatory gates enforced

## Source-Admission Gates

| Gate | Requirement |
|------|-------------|
| **G1** | Ws2 artifacts must reference only canonical state enum (Q1) |
| **G2** | Ws0 code cannot import from ws2 tooling (Q2) |
| **G3** | No new adapter interface methods (Q3) |
| **G4** | All observability is pass-through only; no inferred states |
| **G5** | Mocks are ephemeral; no shared test-type libraries |

## No-Go List (Immediate Rejection)

1. Any adapter that adds fields to `CanonicalEnvelope`
2. Any component that infers state instead of consuming canonical event stream
3. Any shadow schema that persists beyond test execution
4. Any bypass of `RuntimeService.execute()` as sole execution path
5. Any adapter that defaults missing fields, re-orders args, or strips unknown fields

---

**ALL CONCLUSIONS ADVISORY AND SOURCE-UNVERIFIED** — This plan is derived from the provided input and does not constitute verified architectural guidance.