# R08 Zero-Paid Owner Extension Proposal (reuse-first, design-only)

**Status:** proposed engineering design, **not admitted, not implemented, not qualified**. No product source changed. **RSI activation OFF.**

**Purpose:** close the identified contract gap — `CAMPAIGN_AUTHORITY_ADDENDUM_02.md` authorizes **$0.00 paid spend / OpenRouter free models only** (fail-closed), but existing native policy owners currently encode **positive-rate, positive-ceiling** monetary reservations. This proposal maps the minimal extension in **existing owners** (no new repos/crates/budget stores) required to represent a truthful zero-paid/free-tier admission while preserving invariants.

## 1. Observed constraints in existing owners (current composition candidate)

Source inspected: `native-composition-r08/recursive-agent/crates/recursive-agent-policy/src/{inference_terms.rs,inference_budget.rs,campaign_inference.rs,campaign_funding.rs}`.

| Owner / location | Current behavior | Zero-paid implication |
|---|---|---|
| `inference_terms.rs` `InferenceBudgetLimitsV1::quote_nanodollars()` | Rejects `max_sends==0`, `input/output_nanodollars_per_token==0`, `max_input/output_tokens_per_send==0`, `max_total_nanodollars==0`, overflows, and quote > total | Cannot express `0` paid quote/ceiling; truthful free tier needs explicit zero-paid semantics, not sentinel positive values |
| `inference_terms.rs` `InferenceBudgetLimitsV1::values()` / validation | Requires values `<= (1_u64<<53)-1`; `quote_nanodollars()?` called by `validate()` | Validation path must admit zero-paid form only under a closed, explicit mode |
| `inference_terms.rs` `InferenceBudgetTermsV1` | Closed schema `recursive-agent.inference-budget-terms/v1`, content-addressed digest over full validated object; validates route strings and calls `limits.quote_nanodollars()` | May require new schema/version or explicit tagged mode field so old v1 positive terms remain unambiguous and deserialization stays fail-closed |
| `inference_budget.rs` `validate_inference_records` / status | `reserved_nanodollars = n * limits.quote_nanodollars()?`; enforces `reserved_nanodollars <= max_total_nanodollars` | Zero-paid mode must keep cumulative send/token/attempt ceilings authoritative; monetary reservation becomes `0` only when explicitly admitted as non-billable |
| `inference_budget.rs` `InferenceBudgetGrantV1::validate` | Calls `self.quote()?` and enforces family/ceiling/identity checks | Must accept zero-paid grant form only with explicit policy/tariff evidence binding |
| `campaign_inference.rs` V2 state/binding/status | Binds `terms.computed_digest()`, stores `terms`, validates records via shared bounds/`quote_nanodollars()` | Binding/digest must cover zero-paid mode; settlement/conservative charging invariants must remain (unknown/crash never creates paid headroom or replay authority) |
| `campaign_funding.rs` `CampaignFundingGrantV1` | Rejects `max_total_nanodollars == 0` or `> (1_u64<<53)-1`; expects matching `budget_terms_digest`/limits/provider/model/api_mode/effort | Must represent `authorized_paid_spend_usd = 0.00` truthfully for the exact admitted free route, with fail-closed refusal on paid/unknown billing |

## 2. Design principles (must hold)

- **Truthful, not permissive:** zero-paid means the admitted route/model/api-mode/request class is evidenced as non-billable with no paid fallback; unknown pricing/route/billing/capability => refuse (not zero).
- **Reuse existing owners:** extend `recursive-agent-policy` in an isolated candidate; no parallel bank/store/provider/controller.
- **Preserve invariants:** one-time initialization semantics, once-only dispatch transitions, immutable settlements, conservative charging for crash/unknown/small-observed usage, historical readback without authority, no refund/replenish/replay, exact route/model/effort/digest binding.
- **Closed and versioned:** any new mode/schema/field must be explicitly versioned or tagged; deserialization rejects unknown/ambiguous forms; old positive-rate records remain valid and uninterpreted as free.
- **No authority from data:** deserialized terms/grants/tickets/reports never authorize egress; physical send still requires canonical reservation/release/settlement composition.
- **Nonmonetary ceilings remain real:** sends, tokens, wall/queue/rate limits, and request bounds must still be enforced for free-tier operation.

## 3. Proposed extension shape (candidate, to be tested)

### Option E1 (preferred): explicit zero-paid tariff mode in existing terms/limits (versioned)

- Introduce a closed tariff/payment mode, e.g. `tariff_mode = "positive_nanodollar_v1" | "zero_paid_free_tier_v1"` (exact naming/placement to fit existing owner APIs), carried in terms/grant and included in canonical digests.
- **Positive mode:** preserve current validation exactly (`>0` rates/ceilings, `quote > 0`, `quote <= total`).
- **Zero-paid mode:** require `input_nanodollars_per_token == 0`, `output_nanodollars_per_token == 0`, `max_total_nanodollars == 0`, `quote_nanodollars() == 0`, while still requiring/enforcing `max_sends > 0`, bounded positive token/send ceilings, and total token ceilings >= per-send bounds. `validate_inference_records` must treat monetary reservation as `0` without bypassing send/token/overrun checks.
- **Admission preconditions (owner-composed):** exact qualified provider identity/endpoint/protocol, exact `:free` model id (or otherwise proven non-billable id) for that route, `api_mode`, `reasoning_effort`, request bounds, and `tariff_digest` covering retained evidence that paid spend/fallback is impossible for the admitted path. Hints (`is_free_tier_model`, catalog labels) are insufficient alone.
- **Fail-closed rules:** refuse mode/model/route mismatch, missing evidence, unknown pricing, paid-capable fallback, substituted model, unsupported protocol/bounds, or any attempt to represent positive spend as zero-paid.

### Option E2 (alternative): separate `InferenceBudgetLimitsV2`/`TermsV2` schema alongside V1
- Cleaner separation but larger API/test surface; only justified if V1 field compatibility cannot be preserved safely. Prefer smallest truthful extension.

## 4. Test/qualification matrix (receipt-native, isolated candidate)

| Category | Required evidence |
|---|---|
| Backward compatibility | Existing positive V1/V2 tests remain green unchanged; serialized positive records still parse/validate/settle identically |
| Admission | Exact zero-paid tuple accepted only with complete qualified evidence; digest stable/canonical |
| Refusal/negatives | Zero fields in positive mode refused; positive fields in zero-paid mode refused; unknown tariff/route/model/pricing/fallback refused; mismatched digest refused; deserialized artifacts grant no authority |
| Accounting invariants | `reserved_nanodollars==0` only in zero-paid mode; send/token ceilings still enforced; once-only dispatch/settlement; crash/unknown outcomes conservatively charged/blocked per owner law; no replay/refund/reinit |
| Mutation controls | Targeted mutants removing zero-paid guards, paid-fallback refusal, or monetary checks must be detected (as in existing run practice) |
| Composition | Binding to funding/terms/root/campaign owners and, later, Ares physical-send/dispatch-governor path proven for every send incl. retries/auxiliaries (separate gate) |

## 5. Candidate OpenRouter `:free` models (from existing Ares catalog/hints; **not admitted**)

Observed in `hermes_cli/models.py` fallback/catalog and OpenRouter free labels (current checkout): `z-ai/glm-5.2:free`, `nvidia/nemotron-3-super-120b-a12b:free`, `nvidia/nemotron-3-ultra-550b-a55b:free`, `nvidia/nemotron-3.5-lightning:free`, `poolside/laguna-s-2.1:free`, `poolside/laguna-xs-2.1:free`, `openrouter/elephant-alpha` (free), `stealth/ox-alpha` (free). Live availability/capabilities/rate limits/pricing/fallback behavior vary and are **unverified for admission**.

**Operator decision needed:** select exact model id(s), endpoint/protocol/api mode, reasoning effort, request/token bounds, and acceptable evidence that the chosen route is zero-paid with no paid fallback.

## 6. PR/reconciliation note (observed)

- Libraries [#95](https://github.com/RecursiveIntell/Libraries/pull/95): open, mergeable.
- Ares [#259](https://github.com/RecursiveIntell/Ares/pull/259): open, mergeable.
- recursive-agent [#36](https://github.com/RecursiveIntell/recursive-agent/pull/36): open, mergeable, checks passing (primitive).
- recursive-agent [#37](https://github.com/RecursiveIntell/recursive-agent/pull/37): open, **conflicting** (composition; overlaps #36 intent). Reconciliation direction needed (rebase/cherry-pick/consolidate onto current `main` after preserving evidence), without disturbing unrelated dirty canonical checkouts.

## 7. Not authorized by this proposal

No campaign admission, no model-backed sends, no provider calls, no shared-config/credential mutation, no live grants, no install/merge/deploy/activation. Implementation requires explicit owner-extension and route-admission decisions plus isolated receipt-backed qualification.
