# Phase 2 Report — Provider Integration

> **Status:** Implemented, built, tested, and verified against a live local
> provider. This lifts the M0 "provider-free" constraint **deliberately and
> only** for the new `llm` tool; every other tool remains provider-free and
> the receipt chain still verifies offline.

## What was done

Added a typed, boundary-checked provider layer behind the existing
receipt-bearing tool path:

1. **New crate `recursive-agent-provider`**
   - `ProviderSpecV1` — typed, serializable endpoint description with an
     explicit `kind` discriminant (`ollama` | `openai_compatible`).
   - `CompletionRequestV1` / `CompletionResponseV1` — typed request and
     canonical response.
   - `complete()` — blocking, no-panic dispatch to:
     - **Ollama** via `POST /api/generate` (`llama3.2:3b` live-tested)
     - **OpenAI-compatible** via `POST /chat/completions` with optional
       Bearer auth.
   - Every error is a typed `ProviderError`; no `unwrap`/`expect`/`panic`.

2. **`llm` tool** in `recursive-agent-tools`
   - Parses `LlmArgs { provider, prompt, max_tokens }`.
   - Calls the provider and returns `LlmOutput { model, text }`.
   - Malformed args are a typed rejection; no network I/O on bad input.

3. **Policy** — `Allowlist::default()` now admits `llm`
   (`policy_version` bumped `m0-1` → `m0-2`).

4. **Runner** — unchanged orchestration; the `llm` step flows through the
   same `StepStarted`/`StepCompleted`/`StepFailed` receipt path, and its
   output is stored as a content-addressed artifact.

5. **Baseline repair** — fixed a pre-existing `stack-ids` 0.1.3 API drift
   (`ContentDigest::as_bytes()` removed) that had broken the ledger build.
   Replaced with `.hex().as_bytes()` per the ledger's documented
   `blake3(prev_chain_digest || ...)` intent.

## Evidence (live, not synthesized)

Run `run:450fecd3-6eaa-4f1b-b39c-e81de175428f` against local Ollama
`llama3.2:3b`:

- `chain_length: 6`, `chain_head: c12653f1...`, `verify: ok`.
- Step 2 (`llm`) produced artifact
  `blake3:4c1b550a...` = `{"model":"llama3.2:3b","text":"READY"}`.
- Replay re-emitted both artifacts offline; it did **not** re-call the
  provider.
- Captured under `docs/receipts/phase2-llm-receipts.ndjson`.

## Gates

| Gate | Result |
|---|---|
| `cargo fmt --check` (per crate) | clean |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | clean |
| `cargo test --workspace` | all pass (incl. new `llm` args test) |
| Live `llm` step | passed, artifact recorded |
| `ra verify` + `ra replay` | ok |

## Scope discipline

- Only `llm` gains provider access. `echo`, `time_now` unchanged.
- Provider `raw` response is captured for evidence but `text` is the
  canonical extraction.
- No edits under `~/Coding/Libraries/`; the new crate depends on Libraries
  by path only.
- AiDENs P32 untouched.

## Out of scope (later phases)

- Sandboxed tool plane (Phase 3)
- MCP / messaging / daemon (Phase 4)
- Memory / skills / delegation / Monte Carlo (Phase 5)
- Operator experience & hardening (Phase 6)
