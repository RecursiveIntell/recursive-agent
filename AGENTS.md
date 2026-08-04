# AGENTS.md — Recursive Agent Platform (M0)

## Mission

Build the smallest runnable vertical slice of a provenance-native agent
platform. M0 produces a tamper-evident receipt chain for a single
deterministic run, verifies it offline, and replays it from disk without any
provider or network call.

## Doctrine (carried from RecursiveIntell)

1. **Receipts are execution semantics.** Every state transition emits a
   typed receipt or an explicit non-durable/degraded outcome. A "completed"
   status without an inspectable chain is a false claim.
2. **Truth is append-only + supersession.** No silent destructive rewrite.
3. **Valid time and recorded time are distinct.**
4. **Material IDs come from `stack-ids`.** No process-local counters, no
   random UUIDs as material IDs. Family-qualified, parseable, stable.
5. **Boundary check at every typed ingress/egress.** Use
   `boundary-compiler` RFC 8785 JCS everywhere. Malformed input is a typed
   rejection, not a panic.
6. **Provider-free in M0.** No Ollama, no OpenAI-compatible call, no
   network. The product survives its own restart and verifies offline.
   **Phase 2 deliberately lifts this** for the `llm` tool only: provider
   calls are receipt-bearing and typed (see `recursive-agent-provider`),
   and the receipt chain still verifies offline. All other tools remain
   provider-free.
7. **Recorded replay only.** Do not promise "deterministic replay" of any
   LLM. Recorded replay is the only replay contract M0 offers. A
   provider-backed `llm` step records its response as a content-addressed
   artifact; replay re-emits that recorded output and never re-calls the
   provider.
8. **Bounded safety.** No `unsafe`, no `unwrap`/`expect` in lib code
   (`cargo clippy -D warnings`). Any panic is a bug.
9. **Source hierarchy.** This workspace depends on Libraries by **path**.
   No edits under `~/Coding/Libraries/`. AiDENs P32 is still
   `feature_expansion_allowed: false`.

## Source-of-truth ownership

| Concern | Owner | Adapter here |
|---|---|---|
| Canonical JSON / boundary | `boundary-compiler` 0.1.0 | direct dep |
| Material IDs / digests | `stack-ids` 0.1.1 | direct dep |
| Bitemporal semantics | `bitemporal-runtime` 0.1.0 | direct dep (in-memory view in M0) |
| Claims / evidence | `claim-ledger` 0.1.0 | direct dep |
| Run orchestration | this workspace | new |
| Receipt chain | this workspace (`ledger` crate) | new |
| Tool plane | this workspace (`tools` crate) | new |
| Provider / LLM | `recursive-agent-provider` (new) | Ollama + OpenAI-compatible adapters |
| MCP / channel | none | out of scope M0/Phase 2 |

## Receipt contract (M0)

- `receipts.ndjson` under `<run-dir>/`.
- One receipt per line. Each line is JCS canonical JSON.
- Chain digest: `blake3(prev_chain_digest || jcs(receipt))`. Initial
  `prev_chain_digest = blake3(b"recursive-agent-m0-genesis")`.
- A separate `chain.meta` records genesis and final digest.
- A separate `artifacts/` directory holds content-addressed payloads.
- `ra verify <run-dir>` rewinds the chain and prints first divergence.
- `ra replay <run-dir>` re-emits observed payloads offline; it does not
  re-execute tools.

## Hard-fail patterns

- `unwrap` / `expect` / `panic!` in lib code (enforced by `clippy`).
- "ok" with `unwrap_or_default` in material paths.
- Provider calls anywhere.
- Mocks that hide the real chain digest.
- Disabling a check to pass CI.
- Random UUIDs in receipt identity (must be family-qualified).
- Two distinct digests that should agree.

## Finish-line focus (M0)

- `ra run`, `ra verify`, `ra replay`, `ra doctor` from a clean tree.
- `cargo test --workspace` green.
- A negative tampering test that fails verification with a precise error.
- All output captured under `docs/receipts/`.
