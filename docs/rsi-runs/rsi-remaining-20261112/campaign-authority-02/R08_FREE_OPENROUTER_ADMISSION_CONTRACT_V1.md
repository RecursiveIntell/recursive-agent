# R08 Free-OpenRouter Admission Contract — V1 (design/qualification draft)

**Status:** proposed, not admitted, not enforced, not a permit/grant/activation record. **RSI activation OFF.**  
**Authority context:** `CAMPAIGN_AUTHORITY_ADDENDUM_02.md` authorizes **$0.00 paid spend** and **OpenRouter free (zero monetary cost) models only**, supervised and fail-closed. `R00_DECISIONS_RECORDED.json` records no campaign launch, no model-backed calls dispatched by that step, and enforcement not admitted by canonical owners. `CONTRACT.md` and `APPROVAL_ADDENDUM.md` remain frozen evidence.

This contract defines the minimum reusable, owner-bound conditions required before any model-backed bounded-RSI send may be admitted under the selected budget posture. Unknown route, unknown pricing, paid fallback, ambiguous request bounds, unavailable quota/identity evidence, or missing settlement authority **MUST refuse** (fail closed). A run-local document, hint, cache label, or “free” suffix match alone is **not** admission.

## 1. Exact admitted send tuple (must be bound as a closed contract)

Every physical send (including retries, continuations, tool/model subcalls, auxiliary/diagnostic/summary sends, and provider retries) must be admitted against one exact, immutable tuple:

- `campaign_id` / canonical mission-contract ref + digest (owner-derived, not prose)
- `kanban_root_task_ref` / admitted task identity
- `provider_identity` = qualified OpenRouter endpoint identity (scheme/host/path as admitted; no credential/query-secret material)
- `wire_protocol` / `api_mode` (e.g. OpenAI-compatible chat/completions or responses as actually qualified for the selected route)
- `model_ref` = exact OpenRouter model id (explicit `:free` identity only if that exact id is the admitted zero-paid artifact; not a family/prefix wildcard)
- `reasoning_effort` / native control projection (exact, serialized/observed form)
- `request_digest` / canonical request preimage and bounded request metadata (exact body/projection admitted by owner; no opaque unbounded send)
- `input_token_upper_bound` and `output_token_upper_bound` (independently qualified/enforceable; not caller-declared optimism)
- `tariff_evidence_digest` and tariff interpretation = **`zero_paid_free_tier`** for the exact route/model/api-mode tuple, with retained evidence proving paid spend is blocked/unavailable for that admitted path
- `max_paid_nanodollars` = `0` (or explicit owner extension proving equivalent fail-closed zero-paid semantics)
- `nonmonetary ceilings` = admitted per-send/per-campaign caps for sends/retries/tokens/wall time/queue wait/rate-limit backoff as required by canonical owners
- `physical_send_owner` / dispatch intent ref / execution id / lease identity
- `settlement_identity` = durable attempt/receipt id for once-only release and conservative outcome accounting

No send is admitted if any field is missing, inferred, downgraded, or derived from a different route/model/request.

## 2. Existing owners to reuse (no new repos/crates/providers/budget stores)

| Concern | Existing owner/surface (observed) | Reuse requirement |
|---|---|---|
| Ares task/mission binding | `Ares/hermes_cli/kanban_db.py`, `Ares/ares_runtime/collaboration.py` | Canonical mission/task admission must be owner-derived; no run-local mission/task bank. |
| Managed call / request projection / route facts | `Ares/ares_runtime/managed_calls.py`, `Ares/ares_runtime/dispatch_route.py`, `Ares/ares_runtime/physical_dispatch.py`, `Ares/ares_runtime/transport_lease.py` | Bind exact request/body/route/model/effort/bounds at physical-send boundary; no relaxed aliasing. |
| Durable dispatch observation / send-started settlement | `Ares/plugins/dispatch_governor/__init__.py`, `hermes_state` execution records, `hermes_cli/middleware.py` dispatch hooks | Must compose with monetary reservation/release; observation alone is not monetary authority. |
| OpenRouter model/catalog/free hints | `Ares/hermes_cli/models.py`, `Ares/agent/credits_tracker.py::is_free_tier_model`, `Ares/agent/auxiliary_client.py`, `Ares/hermes_constants.py` | Hints/catalog only; cannot authorize zero-paid enforcement without canonical route/tariff/request qualification. |
| Native campaign funding/terms/root/budget accounting | `recursive-agent/crates/recursive-agent-policy/src/{campaign_funding.rs,campaign_root.rs,inference_terms.rs,inference_budget.rs,campaign_inference.rs}` and related tests (qualified composition candidates) | Extend/compose existing owners; preserve conservative charging, once-only transitions, non-refund on unknown/crash, historical readback, and no second budget bank. |
| Execution/session/permit/IPC/recovery | `recursive-agent-policy` session/permit/grant modules, daemon IPC/framing, runner/provider/sandbox owners, `integrations/hermes-native/*` | No generic permit bypass; deserialized tickets/reports not authority; IPC cannot authorize release before native checks agree. |
| Evidence/integration spine | `forge-pilot`, `forge-memory-bridge`, `semantic-memory*`, `verification-policy`, `check-runner`, `sandbox-workspace`, `typed-patch` (Libraries) | Reuse qualified evidence/export/import and admission primitives; no shadow bridge/controller/store. |

## 3. Contract gaps (must be closed in isolated candidates with receipt-native tests)

1. **Zero-paid representation:** `InferenceBudgetLimitsV1` currently requires non-zero rates/ceilings and rejects zero totals/sends (`inference_terms.rs`). A truthful $0-paid contract requires an explicit, tested extension in the existing policy owner (or an equivalently admitted closed form) that cannot be interpreted as paid headroom and that refuses any paid/unknown billing path. No adapter-level workaround.
2. **Authoritative free-route determination:** `:free` suffix / `is_free_tier_model` / pricing-cache labels are non-authoritative hints. Admission needs exact route+model+api-mode qualification and fail-closed refusal on paid fallback, missing evidence, route mismatch, model substitution, or unknown cost.
3. **Physical-send monetary binding:** every actual provider byte egress must be preceded by durable reservation/admission and followed by once-only conservative settlement through canonical owners, covering retries/auxiliaries/SDK-internal retries where observable. Ares `dispatch_governor` `send_started`/settlement and native campaign accounting must be composed without bypass paths.
4. **Request/tariff honesty:** tariff evidence must represent the admitted free route’s zero-paid boundary; if provider may bill, route may fall back, or bounds are unprovable, refuse.
5. **Rate/availability limits:** free-tier throttling/429/queue/capability limits require bounded retry/backoff and explicit nonmonetary admission; they do not authorize unlimited attempts or paid fallback.
6. **No shared mutation/live egress:** no edits to installed/shared config, credentials, routing defaults, production stores, or live grants; no provider calls until a specific canary path is explicitly admitted and qualified.

## 4. Minimum qualification evidence (offline/receipt-backed unless explicitly admitted otherwise)

- Source/freeze identity for every mutated candidate and unchanged dependencies.
- Unit/contract tests proving: exact admitted tuple accepted only when complete; paid/unknown route/model/pricing/request-bounds refused; reservation precedes send; duplicate/retry settlement is once-only; crash/timeout/unknown outcome conservatively charged or blocks replay per owner law; no bypass through dispatch governor, managed call, or IPC paths.
- Negative/mutant controls for critical checks (as already practiced in run receipts).
- Verbatim gate outputs, selected receipt verification, package/hash integrity, rollback applicability, and explicit residual risks.

## 5. Admission boundary

This draft **does not** admit a campaign, producer, evaluator, containment qualification, adoption, or any model-backed send. Implementation must proceed in isolated candidates with existing gate harnesses and explicit owner-transition/admission decisions where required.

