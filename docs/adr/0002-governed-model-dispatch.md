# ADR-0002 — Governed Model Dispatch

**Status:** Operator authorized implementation of the recommended decisions below in isolated worktrees. The ADR remains a design proposal; implementation readiness depends on the revised recovery-contract review and phase gates. No live activation, commit, push, website publication, or service replacement is authorized.  
**Evidence snapshot:** Recursive Agent `88e121e479e48accfbf361ad9d392042ef4d7eda`; Ares `56caa3efc0854a527b125ba34c964ebce437b8ad`; Libraries `3d32dd9ddb57d80d9c04b3089403dcb0d39782e5`.  
**Scope:** Plan v2, ADR/P1 design snapshot. Implementation is authorized only in the isolated worktrees; no live runtime/service change, commit, push, website publication, or activation is authorized.

## 0. Current owner status and decision

### Current status (observed at the pinned Recursive Agent source)

- `NormalChatOperationV1` and `NormalChatAttemptV1` are closed, non-authorizing identity/accounting material. Their module explicitly says they cannot grant a permit, select a route, resolve credentials, send a request, or assert a terminal outcome (`crates/recursive-agent-contracts/src/normal_chat_operation.rs:1-7,58-77,170-179`).
- The default `DenyNormalChatAdmission` rejects (`recursive-agent-policy/src/lib.rs:2049-2060`). `DurablePermitStore::issue_normal_chat` rechecks the current verifier and requires a durable parent permit; it is not a free-standing grant-to-egress path (`recursive-agent-policy/src/lib.rs:2707-2738`).
- The current native IPC is protocol v1 and has no normal-chat request variants (`recursive-agent-daemon/src/protocol.rs:17-28,114-220`).
- `NativeNormalChatExecutor` is explicitly not registered with the daemon or host and does not create a full terminal run chain (`recursive-agent-runner/src/normal_chat.rs:1-2`). It can consume a pre-existing permit, record a reported outcome, and retain the observed response plus observation artifacts; it is not the governed Ares integration (`normal_chat.rs:139-164,247-328`).
- Existing owner surfaces to reuse include `NormalChatOperationV1` / `NormalChatAttemptV1`, `NormalChatAdmissionVerifier`, `DurablePermitStore`, `PermitPreflightReceiptV1`, `PermitOutcomeReceiptV1`, `NormalChatSettlementV1`, `ArtifactStore`, `ChainHandle::append`, and `ra verify --run`. However, `DurablePermitStore::read_external_permit` explicitly rejects records whose tool is `NORMAL_CHAT_LANE` (`recursive-agent-policy/src/lib.rs:3375-3405`); do **not** claim `ExternalPermitReadbackV1` is currently a usable normal-chat readback path. A new normal-chat-specific policy-owner readback API is required. `NormalChatSettlementV1` requires a response `ArtifactDescriptorV1`; the current executor stores the full observed response before settlement (`recursive-agent-policy/src/lib.rs:1031-1045`; `recursive-agent-runner/src/normal_chat.rs:274-328`).
- `RuntimeService` is the canonical general run-composition owner and uses `ChainHandle`; its model-autonomous entry without an egress authorizer fails closed (`recursive-agent-runner/src/runtime.rs:1050-1139`). It does not currently own a normal-chat session-root map, cumulative session budget, or a cross-store reconciler. `ChainHandle::append` is individually locked/durable and rejects stale heads or duplicate receipt IDs, but there is no atomic transaction spanning it and `DurablePermitStore` (`recursive-agent-ledger/src/lib.rs:840-960`). A new composition/recovery API must live in the owners, not the plugin.
- The existing `ProviderEgressOperationV3` is a separate direct-root candidate lane: it admits one `sealed_completion` with an injected `ProviderEgressAdmissionVerifier`, runs a terminal provider operation, and supports full-response recorded replay (`recursive-agent-contracts/src/provider_egress_operation.rs:44-56,92-145`; `recursive-agent-runner/src/runtime.rs:893-1019`; `recursive-agent-runner/src/sealed_completion.rs:181-200`). It does not supply operator grant-file authority, a session-root/attempt-child lifecycle, digest-only replay, or proof of one physical send through arbitrary Ares SDK transports. Reuse its strict request/binding validation and policy/receipt primitives only where semantics match; do not route Ares provider execution through the RA daemon or redefine V3 replay.
- `docs/context-authority-v1.md` governs context-scope enrollment and a separate per-call approval witness. It expressly says IPC does not enroll a scope or approve a grant. It is not normal-chat egress policy and must not be widened to serve as one.

### Decision proposed

Keep provider execution and credentials in Ares. Add a **separate, closed normal-chat egress grant** owned by the operator and loaded by the RA daemon. Add new, non-downgradable IPC and policy-owner composition that checks that grant, durably reserves an attempt, issues one permit immediately before each provider network attempt, records the reported outcome, and appends the lifecycle to the canonical RA ledger. Ares continues sending the unchanged provider request. The daemon remains local IPC only and never proxies provider traffic.

The permit unit is **one provider network egress attempt**, not one outer Ares/SDK invocation. Hidden SDK retries must be disabled or surfaced as separately admitted attempts. A fallback that sends another request requires another permit. This is the only proposed boundary that can support a defensible statement that every in-scope egress attempt is admitted and receipted.

The current source does **not** yet prove that boundary for every in-scope transport. In particular, Bedrock's client has no explicit retry configuration in the observed constructor, `RiPipeline` hides its native send behind one Python call, and the call-site census still has three direct live bypasses and unverified ambient session propagation. These are implementation gates: P2 may begin after the final ADR review and approved decisions, but no affected route may enter `enforce`, no coverage claim is authorized, and no route-specific capability is considered implemented until its gate passes. If a canonical owner or compatible transport hook cannot be established, stop that route at RED rather than bypassing the boundary.

**Proposed design:**

```
operator-owned grant (mode 0600; separately loaded; no IPC grant widening)
  -> RA policy owner validates current grant + reserves session budget durably
  -> RA daemon returns one single-use permit for one network attempt
  -> Ares transport sends unchanged request once
  -> Ares reports result; RA records outcome and digest-only observation
  -> RA ChainHandle appends receipts; `ra verify --run` checks the run
```

## 1. Grant

### Proposed owner and boundary

Add a new `NormalChatEgressGrantV1` and loader in the Recursive Agent policy owner. Do **not** extend `ContextAuthorityConfigurationV1`: its enrollment, verifier, context-store, and transition semantics are unrelated. Load with a separate `ra-daemon serve --egress-grant-file <path>` startup input. The daemon refuses missing, symlinked, non-regular, wrong-owner, or non-0600 files; rejects malformed, duplicate-key, unknown-field, expired, wrong-home, or stale-revision grants. The daemon does not accept grant material, routes, caps, or mode changes over IPC. An operator edit plus daemon restart is the initial update procedure; no live reload is proposed in P2.

The grant is local operator authority under the host filesystem trust boundary, not a cryptographic defense against root or a compromised process running as the same UID. The RA receipt chain is tamper-evident under its verifier, not immutable against an operator replacing the entire store and history. Those limits must remain explicit.

The grant fields are closed and typed:

- `schema`: exact tag `recursive-agent.normal-chat-egress-grant/v1`.
- `revision`: positive monotonic integer, checked against the durable grant head retained by the daemon/policy owner.
- `ares_home_digest`: `sha256:<64 lowercase hex>` over the canonical resolved Ares home path bytes; raw path is not emitted in receipts.
- `mode`: `observe` or `enforce`.
- `any_route`: boolean. True is permitted only in `observe`.
- `routes`: explicit list of `{provider_identity, model_ref, api_mode}`. `enforce` requires a nonempty list and `any_route=false`.
- `caps`: `max_attempts` and `max_output_tokens` are cumulative session ceilings; each durable Begin consumes one attempt and reserves one operation's `output_reserve`, with the sum never exceeding `max_output_tokens`. `max_wall_time_ms` is the maximum timeout for one physical send; `max_request_bytes` is the maximum serialized request-body size for one send. V1 hard maxima are `max_attempts=1024`, `max_output_tokens=1,000,000`, per-send `max_wall_time_ms=300,000`, and per-send `max_request_bytes=1,048,576`; values must be positive and within these limits. There is no `max_input_tokens` field in V1 of this grant because no authoritative route-specific input-token counter is currently available. A future version may add it only with a policy-owner-verifiable counting witness. The per-attempt request-byte and timeout bounds are not claims about provider billing or remote work after timeout.
- `expires_at`: UTC RFC 3339 timestamp.
- `content_retention`: exact value `digest_only` in this grant version. Full-content retention is not admitted by V1; it requires a future version and separate at-rest/erasure controls.
- `policy_digest`: `sha256:<64 lowercase hex>` over JCS of every grant field except `policy_digest` itself. The exact domain and canonicalization test are part of the new contract.

Illustrative grant (all values are fixtures, not an admitted grant):

```json
{
  "schema": "recursive-agent.normal-chat-egress-grant/v1",
  "revision": 1,
  "ares_home_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "mode": "observe",
  "any_route": true,
  "routes": [],
  "caps": {
    "max_attempts": 20,
    "max_output_tokens": 8192,
    "max_wall_time_ms": 120000,
    "max_request_bytes": 1048576
  },
  "expires_at": "2027-01-01T00:00:00Z",
  "content_retention": "digest_only",
  "policy_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}
```

The shown digest strings are shape examples only; the contract tests must recompute them from the exact fixture before any fixture is described as valid. An `enforce` fixture must use `any_route:false` and at least one explicit route. No production grant exists in this phase.

### Authority composition that must be added in the policy owner

A grant file is not itself an `ExecutionPermitV1`, and the existing `issue_normal_chat` requires a durable control parent. P2 now contains startup-only `NormalChatGrantAuthorityV1`, closed nonauthorizing `NormalChatSessionV1` identity, and `DurablePermitStore::open_normal_chat_session_control`. The latter derives grant/home/revision/policy/actor/budget material internally and persists an ordinary canonical `PermitRecordV1`. Its root binding **and every delegation action** have `network_allowed:false`; the sole audience is `normal_chat` with the accounting-only scope `normal-chat-session-accounting/v1`. Routes remain in operator grant/accounting state, not in network-enabled root actions. The preimplementation source review identified that the prior route-action wording would have created executable network delegation despite a network-disabled root binding; that rejected design was not implemented.

`ValidatedNormalChatSessionControlV1` is native/non-serializable. `FamilyAuthorityStore::from_normal_chat_session_control` verifies its exact pinned run/permit directory and current durable record, then returns `NormalChatControlledFamilyV1`, a guarded view over existing canonical stores rather than another budget/permit database. Reopen recomputes all immutable authority from the loaded grant and original issuance time; it preserves expiry, revocation, identity and charges, and rejects ambiguous, mixed or corrupt roots. The guarded family samples its supplied trusted clock under the permit lock and rechecks after accounting operations. Neither its reservation nor its dispatch guard is a send permit. A future child-local effect gate must require fresh exact-request grant admission plus the canonical guarded reservation and full ledger release barrier; it must not widen or reinterpret the network-denying root ceiling or accept raw accounting readback as authority.

Existing V1 lease law limits this initial session-control lease to the earlier of grant expiry and **original issuance + 300,000 ms**. Reopen never renews that lease. Runtime-owned explicit segment rotation for a longer Ares conversation is still a required P2 lifecycle gate; no hidden new session identity or V1 lifetime widening is authorized. Parent-session references in the new identity are lineage material only until RuntimeService verifies their parent chain. Local metadata byte ceilings are bounded policy constants, not a conversion from model tokens or a guarantee about provider response bytes.

The bounded policy Begin/consume portion is described below; RuntimeService composition, full effect lifecycle, digest-only settlement, recovery and the terminal ledger release barrier remain **P2 implementation gates**. No governed IPC or live effect follows from the root-control implementation alone. `ContextAuthorityConfigurationV1` is not reused; no IPC request may create or widen a grant. The approved trust boundary remains a same-UID-owned mode-0600 operator file, without a new signature/key owner or claims of protection against root/same-UID store replacement.

### P2 child-local policy consumption (implemented in the isolated worktree)

`DurablePermitStore::begin_normal_chat_attempt_v2` now takes the startup grant authority, native `NormalChatControlledFamilyV1`, one intent reference and a trusted clock. It does not accept client-selected ordinals, budgets, permit IDs or alternate admission material. It reads the exact canonical family reservation and rechecks current root control, route, grant and time window. Parent/child run or permit-directory aliasing is rejected before nested locks. The child-local network-authorizing control is explicitly admitted by the file grant **intersected with** that guarded allocation; it is not an attenuation or widening of the session root's network-denying ceiling.

The closed policy lanes are `normal_chat_attempt_control_v2` and `normal_chat_v2` with effect scope `native-normal-chat-v2`. This is a separate V2 policy boundary, not a new generic provider tool or a reinterpretation of V1. Generic issuers remain network-denying and generic consumption, reported-outcome and external-readback paths reject the V2 lanes. The canonical `PermitRecordV1` writer/identity/evidence machinery is reused with an optional closed `normal_chat_attempt_v2` role field: the local control retains the immutable reservation and session expiry once; the effect marker requires validation against that exact retained control admission. Older closed readers reject the additive association; named V2 records missing the marker are corrupted, never downgraded to V1. The `Effect {}` struct variant is deliberate: a negative test demonstrated that serde's internally tagged unit variant accepted unknown fields despite `deny_unknown_fields`.

The exact local control and its one allocation are durable before the effect record. Effect issuance and consumption publish together as one atomic `Consumed` record with its canonical `PermitPreflightReceiptV1`; there is no observable `Issued` effect. The two local records are **not** a cross-store transaction. A partial control-only prefix is reported as `Prepared`, not completed or retried. Exact Begin retries, lost-ACK readback and concurrent duplicate calls return status only and cannot mint another native continuation. The first successful policy transition returns a nonserializable `NormalChatAttemptConsumptionV2`; neither that continuation nor readback satisfies the runtime ledger send-release barrier. Fault tests cover all four existing write stages on both records, and charged/consumed evidence survives an error after publication.

Readback now resolves intent identity through the canonical `FamilyAuthorityStore`; it does not accept a caller-authored reservation, including when the local child store is empty. A `NormalChatControlledFamilyV1` convenience method delegates to that same owner path without reauthorizing historical status. `Unbegun` denotes absence of local records for that canonical reservation, not proof that an arbitrary lost/replaced store never admitted or sent an earlier call. RuntimeService must quarantine inconsistent parent/child ledger prefixes rather than recreate authority from missing local history.

The permit store now retains the admitted run-root descriptor as well as the permit-directory descriptor. V2 Begin and readback recheck the descriptor-relative `permits` locator, including around publication, so replacing that child directory fences the old handle. Global deterministic root selection and parent-path locator verification remain RuntimeService/RunPaths obligations, not a claim that the policy component authenticates filesystem history against a same-UID/root writer.

Both permit issuance times are fixed at the durable reservation time. Expiry is no later than that time plus the per-attempt timeout or the current session-control expiry. Consumers must preserve the remaining lease rather than start a fresh timeout window after IPC/ledger delay. Trusted clocks and exact guarded reservation checks bracket publication/readback and the final release check; a detected post-commit expiry/regression returns no continuation without refunding or rewriting the record. Historical readback proves local policy state only, not current authority, provider send, success, usage or billing.

Typed settlement/readback of terminal outcomes, degraded/TTL reconciliation, strict parent/child ledger composition, runtime-owned segment rotation and daemon IPC are still required P2 gates. RuntimeService must select each deterministic child `RunPaths` root and verify the full parent/child release barrier before any successful admission response can reach Ares. Ares still must prove the exact physical request/length/output ceiling at its transport owner; digest-only policy checks are not independent evidence of the bytes sent.

## 2. Field mapping table

The current `NormalChatOperationV1` validators require nonempty, control-free references up to 4096 bytes; `materialization_digest` and `request_digest` use `sha256:<64 lowercase hex>`; `policy_basis_digest` accepts `sha256:` or `blake3:`; budget values must be nonzero; replay is exactly `recorded_response_only`; provenance must be nonempty. See `normal_chat_operation.rs:257-309,339-368`. `NormalChatAttemptV1` binds an attempt number and a native `ContentDigest`; it does not authorize it (`normal_chat_operation.rs:118-145,170-227`).

| `NormalChatOperationV1` field | Intended source owner / mapping | Validator-conformant fixture value | Status |
|---|---|---|---|
| `schema` | Contract owner; exact V1 enum tag | `recursive-agent.normal-chat/v1` | Existing |
| `conversation_ref` | Ares session identity owner; exact session id, not an adapter-generated substitute | `conversation:fixture-1` | Valid only when an Ares session id exists; no-session calls are blocked in `enforce` (section 5) |
| `parent_run_id` | RA owner-issued parent session-run id for subagent lineage; null only for a root before/without an owner-issued parent | `v1:recursive-agent/run/v1:det:` + 64 lowercase hex | Existing type; production value must be returned by RA, never fabricated by the plugin |
| `materialization_ref` | **No canonical Ares owner was established in P0.** Propose an Ares-owned `LlmDispatchMaterializationV1` emitted at the final physical request boundary, binding the exact request projection and source revision | `materialization:fixture-1` | **Blocked for production.** Fixture string is copied from current contract tests; it is not a real materialization record |
| `materialization_digest` | Digest of the owner-issued materialization record, produced by the same Ares owner | `sha256:` + 64 lowercase hex | **Blocked with `materialization_ref`;** do not hash an adapter-created projection and call it owner evidence |
| `policy_basis_ref` | RA policy owner reference to the exact loaded grant revision | `policy-basis:fixture-1` | Proposed new owner reference; fixture only |
| `policy_basis_digest` | Digest of the immutable grant snapshot used for this admission | `blake3:` + 64 lowercase hex | Existing validator accepts it; production digest must be computed by grant owner |
| `source_revision` | Ares runtime source-revision owner (installed release manifest), not a user/plugin claim | `source:fixture-1` | **Blocked for production** until the source revision can be read from a canonical runtime manifest; the pinned git SHA is known for this design snapshot only |
| `route_class` | Reuse `ManagedCallContextV1.purpose` exactly; normal-chat `surface="normal_chat"` requires `purpose="conversation"`. Auxiliary tasks map to existing purposes such as `planning`, `specialist`, or `background_summary`; do not add `auxiliary:<task>` to the managed-call vocabulary | `conversation` | Existing owner vocabulary, but a call without a canonical managed-call context is blocked in `enforce` |
| `provider_identity` | Ares route/transport owner, normalized stable provider identifier, excluding credential material | `openai_compatible:https://provider.test/v1` | Fixture from existing contract tests; production mapping requires route identity from the resolved transport, not caller-supplied text |
| `model_ref` | Ares resolved model route, secret-free | `model:fixture` | Fixture from existing contract tests; production value is route-owner output |
| `request_digest` | Ares physical-dispatch materialization owner; hash the final payload using an explicitly versioned projection | `sha256:` + 64 lowercase hex | Current V1 lacks a projection-algorithm field. **Do not silently assign a new preimage.** Proposed V2 adds `request_projection_schema` and `max_request_bytes` |
| `budget` | RA grant caps intersected with a per-operation request; reject if request exceeds the grant rather than silently widening or changing it | `{ "max_attempts": 2, "input_tokens": 10, "output_reserve": 20, "max_wall_time_ms": 1000 }` | Existing syntax; exact input-token enforcement is blocked unless an authoritative provider-specific count is available. V2 also carries a byte ceiling |
| `replay` | Existing V1 means retained-response replay only | `recorded_response_only` | **Not suitable for digest-only retention.** Add closed V2 operation/attempt and settlement schemas with `replay:"unavailable"`; do not reuse V1 while omitting the response artifact |
| `provenance` | Nonempty list of owner-issued source refs and `ContentDigest`s | `[{"source":"urn:test:normal-chat","digest":"` + 64 lowercase hex + `"}]` | Contract-conformant fixture shape; production provenance owner/source needs resolution |

The following complete JSON is adapted from the current `normal_chat_operation_v1.rs` fixture. The references and digest strings are synthetic, validator-shaped examples; they are not production authority, proof of a materialization, or an admitted route. The typed test constructs a valid `parent_run_id` with the same domain and lowercase digest syntax shown here. This is a contract-shape example only.

```json
{
  "schema": "recursive-agent.normal-chat/v1",
  "conversation_ref": "conversation:fixture-1",
  "parent_run_id": "v1:recursive-agent/run/v1:det:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "materialization_ref": "materialization:fixture-1",
  "materialization_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "policy_basis_ref": "policy-basis:fixture-1",
  "policy_basis_digest": "blake3:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "source_revision": "source:fixture-1",
  "route_class": "conversation",
  "provider_identity": "openai_compatible:https://provider.test/v1",
  "model_ref": "model:fixture",
  "request_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "budget": {
    "max_attempts": 2,
    "input_tokens": 10,
    "output_reserve": 20,
    "max_wall_time_ms": 1000
  },
  "replay": "recorded_response_only",
  "provenance": [
    {
      "source": "urn:test:normal-chat",
      "digest": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    }
  ]
}
```

The production mapping uses `route_class:"conversation"` for a `ManagedCallContextV1` with `surface="normal_chat"`; auxiliary calls use the exact existing `purpose` value. This fixture has no `ManagedCallContextV1` artifact, so the example does not prove that the context exists or is linked.

The proposed `NormalChatOperationV2` is a separate closed schema, not a reinterpretation of V1. It retains the stable identity/route/provenance fields, uses `schema:"recursive-agent.normal-chat/v2"`, sets `parent_run_id` to the owner-issued session parent, carries `provider_identity`, `model_ref`, and **`api_mode`** from the resolved Ares transport route for exact grant-route matching, adds `request_projection_schema:"ares-json-sorted-v1"`, and uses a closed per-attempt budget containing `output_reserve`, `max_wall_time_ms`, and `max_request_bytes`. The policy owner requires `output_reserve` to fit within the remaining cumulative session `max_output_tokens`; it sets the provider request's output ceiling to that reserve. V2 deliberately omits V1's caller-provided `input_tokens`; an input-token cap is not claimed until a policy-owner-verifiable route counter exists. Replay is the exact value `unavailable`. Its companion `NormalChatAttemptV2` uses `schema:"recursive-agent.normal-chat-attempt/v2"`, the operation, 1-based durable attempt ordinal, per-send `provider_request_digest`, stable `dispatch_intent_ref`, owner-issued `session_run_id`, and owner-derived `attempt_id`. The daemon allocates the ordinal and attempt/run ids; clients do not supply them. The child run id is separately derived by the RA run-id owner from the validated attempt identity. The V2 operation/attempt schemas and strict parsers are implemented in the P2 worktree; grant admission, daemon composition, settlement, recovery, and transport execution remain unimplemented.

The V1 contract cannot honestly carry the approved production mapping because of its replay and identity semantics. The P2 worktree now contains a separate closed V2 operation/attempt contract and strict parsers while leaving V1 behavior unchanged. P2 must still implement and verify digest-only settlement, policy/daemon composition, and durable lifecycle/recovery before V2 can authorize or describe any live call.

## 3. Attempt unit and retry accounting

### Chosen unit (proposed)

One permit and one terminal outcome per **network egress attempt**. A network attempt begins at the last Ares-owned callback immediately before the transport sends request bytes. An outer model/SDK function call is not an adequate unit if that function can retry, downgrade, fallback, or issue multiple requests internally. The existing `ContextDispatchPhysicalScope` around an SDK callback may carry call/session provenance, but by itself does not prove the final serialized body or reveal transport-internal retry sends. P3 must add a low-level send wrapper for each in-scope transport (including botocore and RiPipeline) or prove that every hidden retry is disabled before using the higher callback as the send boundary. The permit must bind the exact immutable body buffer submitted to that transport. A request denied before any transport send has a `PermitRejected`/denial record and zero provider egress. A provider response/error after send is a reported outcome; it is not independently confirmed.

An SDK retry must be configured off or exposed through a per-network-attempt hook. A retry must increment the attempt ordinal and obtain a distinct single-use permit. A fallback request is a new attempt even if it is inside one user-visible call. If the runtime cannot observe and gate a nested send, that route is not enforceable and must be denied in `enforce` or remain explicitly out of the coverage claim; no hidden aggregate may be described as one fully governed attempt.

### Source-backed cases at this snapshot

| Path | Observed source | Required accounting / current status |
|---|---|---|
| Bedrock Converse streaming | `Ares/agent/chat_completion_helpers.py:3541-3573` performs `converse_stream` and can then call `converse` after IAM denial | Two network attempts, two permits and two outcomes. The current physical-scope calls do not by themselves establish that botocore's internal retries are disabled |
| Bedrock runtime client | `Ares/agent/bedrock_adapter.py:113-123` constructs `boto3.client("bedrock-runtime", region_name=region)` without an explicit retry `Config` | **Blocked** until all runtime client constructors have an explicit tested one-attempt policy or per-send hook. Do not infer zero retries from Ares wrapper structure |
| Auxiliary streamed-request fallback | `Ares/agent/auxiliary_client.py:9248-9302` can send `stream=True`, then send plain `kwargs` on a streaming-specific rejection | Separate permit for every send. Preserve provider errors; ensure fallback cannot pass around a denial |
| Direct Gemini HTTP | `Ares/agent/gemini_native_adapter.py` uses direct HTTP `generateContent`/`streamGenerateContent` routes (P0 census) | Gate each HTTP send, including stream path; audit configured HTTP transports and prove no automatic retry |
| RiPipeline | `Ares/agent/transports/ri_llm.py:287-318` calls native Rust `pipe.call`; the pinned `Libraries/llm-pipeline-python/src/lib.rs:87-141` builds `ExecCtx` internally and exposes no custom client/send callback. The Recursive Agent/Libraries owner instructions prohibit editing Libraries in this plan | **Unsupported in `enforce` for this build:** deny with `UNSUPPORTED_TRANSPORT` before `_NativePipeline.call`; `observe` may allow only with an explicit unwitnessed record. Do not silently fall back to a different provider/transport. Re-enable in `enforce` only after the Libraries owner exposes and tests a per-send hook in a separately approved source change |
| Primary OpenAI/Anthropic | P0 source census observed several primary constructors with `max_retries=0`; it did not establish every provider-specific and auxiliary constructor | Audit every live constructor and test the actual configured SDK transport with retries disabled. Any missing/unknown constructor blocks the network-attempt guarantee |
| Codex auxiliary stream | P0 census: `Ares/agent/auxiliary_client.py:9775` calls the SDK directly outside the common stream funnel | Route through the governed per-send seam; fallback/retry sends each need a new permit |
| Iteration-limit summaries | P0 census: `Ares/agent/chat_completion_helpers.py:3199,3264` directly calls OpenAI outside the physical scope | Both paths must be governed at their actual network callback; retry is a separate permit |
| Bedrock context-size diagnostic | P0 census found a model endpoint probe | Count as model egress and gate as a separate attempt; metadata discovery that does not invoke a model is not an attempt |

The P0 census is source evidence, not runtime coverage. Exact SDK retry configuration for every constructor, Gemini transport retry behavior, and the RiPipeline native send contract remain required implementation admission checks. The implementation must not start by claiming these are already solved.

## 4. IPC variants

### Protocol boundary

Add a new closed IPC request/response schema (proposed protocol v2). Keep v1 byte-compatible and do not downgrade an unrecognized or failed v2 request to `Submit`, generic `PermitIssue`, or a permissive v1 operation. Every payload is size-limited before parsing, rejects duplicate keys and unknown fields, binds a request id, and returns typed denials. No IPC request accepts or widens a grant. Begin/settle/readback must be idempotent against the exact attempt identity.

The four required effect lifecycle variants are `NormalChatAttemptBegin`, `NormalChatAttemptSettle`, `NormalChatAttemptReadback`, and `NormalChatRunClose`. Add `NormalChatSessionOpen` to establish a session root before the first operation; it returns an owner-issued root id. These are new schemas, not aliases of the existing generic permit messages.

### Request/response shapes (proposed; not implemented)

`NormalChatSessionOpen` is keyed by the canonical Ares session reference and optional parent session-run reference. A duplicate open returns the same live root; a closed/expired run cannot be reopened. Example:

```json
{
  "schema": "recursive-agent.ipc/request/v2",
  "protocol_version": 2,
  "request_id": "fixture-open-1",
  "request": {
    "kind": "normal_chat_session_open",
    "conversation_ref": "conversation:fixture-1",
    "parent_session_run_id": null
  }
}
```

Success response shape:

```json
{
  "schema": "recursive-agent.ipc/response/v2",
  "request_id": "fixture-open-1",
  "result": {
    "kind": "normal_chat_session_opened",
    "session_run_id": "v1:recursive-agent/run/v1:det:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "grant_revision": 1,
    "policy_basis_digest": "blake3:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  }
}
```

`NormalChatAttemptBegin` carries a complete closed V2 operation, owner-issued `dispatch_intent_ref`, and provider-request `ContentDigest`; the policy owner allocates the ordinal under its durable session/operation lock. In one policy-owner transaction it validates the current grant and route, reserves cumulative budget, derives the V2 attempt id, issues and consumes exactly one permit, and persists the preflight. The daemon returns only after that state is durable and the admission-response release barrier in §4 passes; Ares sends only after receiving the exact successful admission response. If a live Ares caller definitively receives no successful response (for example, a timeout before response receipt), it MUST NOT send; it may settle `not_sent`, and an exact Begin retry/readback is status-only and never authorizes a later send. If the Ares or daemon process crashes after the complete barrier but before a durable transport outcome, response delivery/send state may be unknown and recovery MUST record `may_have_been_sent` as degraded. An exact retry never creates another permit or grants a second send. This can waste a reserved attempt but cannot create duplicate egress. This operation requires a new atomic policy-owner API; the current separate `issue_normal_chat` and consume methods are not an atomic Begin implementation.

The following complete JSON is a **proposed parser fixture** for the V2 contract described in section 2, not a currently accepted message or production grant:

```json
{
  "schema": "recursive-agent.ipc/request/v2",
  "protocol_version": 2,
  "request_id": "fixture-begin-1",
  "request": {
    "kind": "normal_chat_attempt_begin",
    "session_run_id": "v1:recursive-agent/run/v1:det:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "dispatch_intent_ref": "ares-dispatch-intent:fixture-1",
    "operation": {
      "schema": "recursive-agent.normal-chat/v2",
      "conversation_ref": "conversation:fixture-1",
      "parent_run_id": "v1:recursive-agent/run/v1:det:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "materialization_ref": "materialization:fixture-1",
      "materialization_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "policy_basis_ref": "normal-chat-grant:revision-1",
      "policy_basis_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "source_revision": "source:fixture-1",
      "route_class": "conversation",
      "provider_identity": "openai_compatible:https://provider.test/v1",
      "model_ref": "model:fixture",
      "api_mode": "chat_completions",
      "request_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "request_projection_schema": "ares-json-sorted-v1",
      "budget": {
        "output_reserve": 20,
        "max_wall_time_ms": 1000,
        "max_request_bytes": 65536
      },
      "replay": "unavailable",
      "provenance": [
        {
          "source": "urn:test:normal-chat",
          "digest": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        }
      ]
    },
    "provider_request_digest": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "provider_request_bytes": 512
  }
}
```

The V2 example demonstrates a complete proposed type shape, but its refs and digests are fixtures and the source/materialization owners are still blocked. Contract implementation must test the example and recompute every digest from its declared preimage; the example is not valid production authority until then.

### Normative V2 attempt identity and digest preimages (proposed)

- `NormalChatDispatchMaterializationV1` is an Ares-owned, immutable logical-call projection. It uses the canonical `ManagedCallContextV1.call_ref`, exact owner-issued Ares session reference/generation, installed runtime `source_revision`, route (`provider_identity`, `model_ref`, `api_mode`), and a closed `request_projection_schema`. It does not contain credentials or raw prompt/response content in digest-only mode. `NormalChatOperationV2.materialization_ref` and `materialization_digest` come only from this owner; no plugin-derived UUID or placeholder is accepted.
- `NormalChatOperationV2.request_digest` is `sha256:<lowercase hex>` over the exact canonical bytes of that logical-call materialization using its named projection schema. It remains stable across separate transport attempts for the same logical call, including a stream downgrade/fallback.
- `NormalChatAttemptV2.provider_request_digest` is the Libraries `ContentDigest` (BLAKE3) over the exact request-body bytes submitted to one provider transport send, before transport framing/authentication/compression. The attempt binds provider/model/api-mode through its operation. Every retry/fallback with different request bytes is a new attempt. The low-level Ares transport hook must hash the same immutable body buffer it hands to the transport; hashing earlier kwargs is insufficient evidence of the bytes submitted.
- V2 attempt id domain is exactly `recursive-agent/normal-chat-attempt/v2`. The owner computes `material = content_digest(AttemptIdentityMaterialV2 { operation, attempt_number, provider_request_digest, provider_request_bytes })`, then `TrialId::deterministic(domain, material.hex())`, followed by the existing family-qualified ID validator for that exact V2 domain. `attempt_number` is a 1-based ordinal allocated durably by the RA policy owner under the session/operation lock; the IPC client does not select it or send an `attempt_id`.
- **P2 correction before release:** `provider_request_bytes` is a required positive integer, no greater than the hard request-body limit. It is the length of the exact immutable body buffer hashed by the Ares transport owner, not the declared byte ceiling. Policy rejects a measured length above the operation/grant ceiling before reserving the attempt. Both digest and length participate in the V2 identity and exact-intent reservation digest. The daemon sees executor-reported measurements; it cannot independently derive length from a hash. P3 transport conformance must prove that both values come from the buffer actually submitted. Missing length is rejected; there is no fallback to a ceiling or earlier draft preimage. V2 has not been published or activated, so no deployed records are migrated by this correction.
- The attempt child run id is `KernelRunId::deterministic(RUN_ID_DOMAIN, content_digest(&validated_attempt_v2).hex())`, converted through the existing `CurrentRunId` owner. Therefore each physical attempt has its own chain/run path, while its `NormalChatOperationV2` and `ManagedCallContextV1.call_ref` preserve logical-call grouping. V1 `NormalChatAttemptV1::run_id()` remains unchanged.
- Each physical network send receives a distinct Ares-owner `dispatch_intent_ref`. The Begin RPC is idempotent on `(session_run_id, dispatch_intent_ref)`: exact duplicate material returns the same persisted attempt/permit state; a different operation or body digest under that key is `INTENT_CONFLICT`. The key must survive an IPC retry but is not reused for another provider send. A repeated Begin that returns an already-consumed attempt never authorizes a second send.
- `response_digest` in V2 settlement is `sha256:<lowercase hex>` over the exact response-body byte stream observed by the same transport owner; stream chunks are hashed incrementally. It is null when no response bytes were observed. `response_bytes` and `response_complete` distinguish complete response from partial/abandoned stream. This proves only the bytes observed by Ares at that transport boundary, not provider-side completion or billing.

The exact canonicalization bytes and positive/negative vectors for both materialization and body hashing are still an admission gate: they require the Ares owner API and tests. Until then the above is the proposed contract, not verified behavior.

Success response shape:

```json
{
  "schema": "recursive-agent.ipc/response/v2",
  "request_id": "fixture-begin-1",
  "result": {
    "kind": "normal_chat_attempt_admitted",
    "attempt_number": 1,
    "attempt_id": "v1:recursive-agent/normal-chat-attempt/v2:det:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "permit_id": "v1:recursive-agent/permit/v1:det:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "preflight_receipt_digest": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "permit_state": { "state": "consumed", "consumed_at": "2026-10-14T11:59:55Z" },
    "expires_at": "2026-10-14T12:00:30Z"
  }
}
```

These identifier strings are schema-shaped fixtures; the owner must derive each from canonical identity material. The caller must not hash or supply a permit id.

`NormalChatAttemptSettle` reports only the exact already-admitted attempt, the preflight digest, a closed outcome, provider-reported usage if present, and digest/size of the response projection. It stores no raw prompt/response in digest-only mode. Duplicate settle returns the identical persisted state; a conflicting second settle is rejected.

```json
{
  "schema": "recursive-agent.ipc/request/v2",
  "protocol_version": 2,
  "request_id": "fixture-settle-1",
  "request": {
    "kind": "normal_chat_attempt_settle",
    "attempt_id": "v1:recursive-agent/normal-chat-attempt/v2:det:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "permit_id": "v1:recursive-agent/permit/v1:det:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "preflight_receipt_digest": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "reported": { "state": "succeeded", "duration_ms": 4200, "error_type": null },
    "response_digest": "sha256:abababababababababababababababababababababababababababababababab",
    "response_bytes": 8192,
    "response_complete": true,
    "usage": { "source": "provider_reported", "input_tokens": 1200, "output_tokens": 240 }
  }
}
```

Success response includes the immutable reported outcome receipt digest, observation metadata artifact descriptor, and chain digest:

```json
{
  "schema": "recursive-agent.ipc/response/v2",
  "request_id": "fixture-settle-1",
  "result": {
    "kind": "normal_chat_attempt_settled",
    "attempt_id": "v1:recursive-agent/normal-chat-attempt/v2:det:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "outcome_receipt_digest": "1111111111111111111111111111111111111111111111111111111111111111",
    "response_digest": "sha256:abababababababababababababababababababababababababababababababab",
    "response_bytes": 8192,
    "observation_artifact": {
      "owner_id": "v1:recursive-agent/artifact/v1:det:3333333333333333333333333333333333333333333333333333333333333333",
      "digest": "3333333333333333333333333333333333333333333333333333333333333333",
      "byte_length": 512,
      "media_type": "application/json",
      "encoding": "utf-8"
    },
    "operation_chain_digest": "2222222222222222222222222222222222222222222222222222222222222222"
  }
}
```

If ACK is lost, the client calls readback; it never resends the provider request.

`NormalChatAttemptReadback` accepts the owner-issued `session_run_id` plus the original `dispatch_intent_ref`, so it can reconcile a lost Begin ACK even when Ares never received the derived attempt/permit ids. For post-settle ACK loss, the same exact intent returns the settled state. It calls a **new normal-chat-specific policy-owner readback method**. It must not call existing `read_external_permit`: that method explicitly rejects `NORMAL_CHAT_LANE`. The new method returns a closed, secret-free projection of the exact persisted normal-chat permit state and receipt digests plus the versioned digest-only settlement projection. It is rebuilt from the policy-owned permit record and is not a second authority source. It does not issue, consume, renew, replay, or restore a permit.

```json
{
  "schema": "recursive-agent.ipc/request/v2",
  "protocol_version": 2,
  "request_id": "fixture-readback-1",
  "request": {
    "kind": "normal_chat_attempt_readback",
    "session_run_id": "v1:recursive-agent/run/v1:det:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "dispatch_intent_ref": "ares-dispatch-intent:fixture-1"
  }
}
```

Success response shape (the policy readback reports the preflight as consumed; that proves admission, not that Ares sent the provider request):

```json
{
  "schema": "recursive-agent.ipc/response/v2",
  "request_id": "fixture-readback-1",
  "result": {
    "kind": "normal_chat_attempt_readback",
    "attempt_id": "v1:recursive-agent/normal-chat-attempt/v2:det:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "permit_id": "v1:recursive-agent/permit/v1:det:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "permit_state": { "state": "consumed", "consumed_at": "2026-10-14T11:59:55Z" },
    "preflight_receipt_digest": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "outcome_receipt_digest": null,
    "settlement": null,
    "attempt_status": { "schema": "recursive-agent.normal-chat-attempt-status/v2", "state": "pending" }
  }
}
```

The attempt status is a rebuildable readback projection. `pending` means the permit was consumed before the Ares transport callback, but no terminal transport report has been committed; it proves neither that a request was sent nor that it was not sent. It never authorizes retry. A live Ares call that knows the send callback did not run must settle a typed `not_sent` outcome; if the caller disappears and the transport state cannot be proven, the reconciler records the degraded artifact described in §7.

`NormalChatRunClose` takes an owner-issued session-run id and a closed reason (`session_finalized`, `session_reset`, or `ttl_expired`). It does not accept a caller-authored terminal state; RA derives the session lifecycle outcome from durable child/attempt receipts. Its generic `RunFinalized` outcome describes closure/chain integrity only; `NormalChatSessionStatusV2` separately summarizes child model-attempt outcomes, so a successful parent close is not a claim that every model call succeeded. Close is idempotent. A closed run cannot accept another begin.

```json
{
  "schema": "recursive-agent.ipc/request/v2",
  "protocol_version": 2,
  "request_id": "fixture-close-1",
  "request": {
    "kind": "normal_chat_run_close",
    "session_run_id": "v1:recursive-agent/run/v1:det:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "reason": "session_finalized"
  }
}
```

Success response:

```json
{
  "schema": "recursive-agent.ipc/response/v2",
  "request_id": "fixture-close-1",
  "result": {
    "kind": "normal_chat_run_closed",
    "session_run_id": "v1:recursive-agent/run/v1:det:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "final_chain_digest": "4444444444444444444444444444444444444444444444444444444444444444",
    "terminal_outcome": { "kind": "ok" },
    "normal_chat_status": { "state": "succeeded", "attempts_verified": true }
  }
}
```

`terminal_outcome` is derived from the durable receipt lifecycle; it is not accepted from the request. Session open, begin, settle, readback, and close each require complete serialized examples and strict parser tests before P2 passes its contract gate. All values shown are schema-shaped fixtures; owner-derived ids/digests must be recomputed and verified by the actual contract tests.

Receipt sequence is appended only by the existing ledger owner: session-parent `RunStarted`; per-attempt parent `ChildAdmissionPrepared` / `ChildLinked`; child `RunStarted`, local-control `StepStarted` / `PermitIssued`, effect `StepStarted`, the closed `NormalChatAttemptAdmittedV2` metadata receipt, then effect `PermitIssued` (the policy-owned historical projection of atomic issue+consume) and exact `PermitConsumed`; later terminal composition records the digest-only observation/failure and child finalization, parent `ChildClosed`, and one parent `RunFinalized` at session close. `ProviderEgressAdmitted` and its V3 sealed-completion semantics remain separate and cannot substitute for V2 evidence. The new admission receipt follows an already Started effect step, has exactly one canonical metadata artifact, precedes issuance, is unique/disjoint from V3 admission, and does not advance permit state or grant permission to send. A policy denial cannot fabricate consumed admission metadata or an issued effect: existing `PermitRejected` requires an actual preceding issuance. Denial/degraded terminal composition remains a RuntimeService gate. The policy store's normal-chat-specific readback remains canonical for permit state; the ledger owns verified run history. A policy receipt or child prefix alone is not a verified terminal run or the parent/child release barrier.

**P2 preflight amendment (source-reviewed, unpublished):** required retained V2 context comprises the operator grant snapshot, canonical session identity and original network-denying root control, replacing the redundant expiry field. The policy owner recomputes root/family/child/local-control/effect identity and historical time/route/body/budget bindings using the existing transforms. Native consumption and canonical readback produce identical non-authorizing `NormalChatLedgerAdmissionEvidenceV2`; Unbegun/Prepared state cannot produce consumed proof. Offline identity uses the validated recorded actor, not the verifier UID; native issuance and filesystem ownership checks remain current-UID-owned. Prior incomplete V2 records lacking required context fail closed without fallback, upgrade, reissue or refund. These new closed receipt/event variants are an explicit protocol surface addition: older readers must reject unknown variants, never strip them. A single child's metadata does not prove cumulative family charges or the actual parent receipt/link; those remain runtime-owned checks. Same-UID/root store rewriting remains outside the selected filesystem trust boundary.

**Typed-wire closure:** V2 admission/permit evidence and owned governed records must reproduce the original canonical bytes after typed decoding; lossy enum aliases, omitted/default-inserted fields or discarded members reject instead of being normalized. Shared `PermitStateV1` and `PermitEvidenceStateV1` retain their public Rust constructors and serialized V1 shapes, but their owner deserializers explicitly reject unknown members on `Issued`, matching the already-declared closed-state contract. Valid V1/V3 admission semantics remain unchanged; previously tolerated malformed state objects are no longer accepted.

## 5. Run lifecycle

### Proposed run model

Use one typed **session-root parent run** per Ares session and one child run per **physical provider network attempt**. Logical calls are grouped by the Ares-owned `ManagedCallContextV1.call_ref`; retries/fallbacks have the same logical call reference but distinct `dispatch_intent_ref`s and child runs. This is a new versioned session-run contract: do not use `NormalChatAttemptV1::run_id()` as the session id. New `NormalChatAttemptV2` derives a distinct child `run_id` from its owner-derived attempt id; the session root id is returned by the RA owner and is carried separately. A child operation has exactly one governed transport attempt and one terminal lifecycle; after a child failure the session parent may admit another attempt. Subagent session roots link to the parent session root through the existing child-link owner.

The session parent owns the durable cumulative grant/budget authority. Each attempt child owns its own `RunPaths`, `DurablePermitStore`, `ArtifactStore`, and `ChainHandle`, preserving the current same-pinned-run-root invariant for permit and artifact state (`recursive-agent-runner/src/normal_chat.rs:224-227`). `NormalChatAttemptV2` uses the owner-issued session run id as its parent lineage, while the policy/ledger child run id is derived from the attempt. V1 derivation and behavior remain unchanged.

`NormalChatSessionOpen` is lazy on the first governed call if the runtime has not opened the session yet. A new `RuntimeService` owner API opens or resumes the session parent from the deterministic Ares session reference/generation and active grant revision. It persists the parent chain and family authority before returning the session-run id. Repeating an open for the same live identity is idempotent. Finalize/reset closes the parent; `on_session_end` is per turn and must not close it. On restart, the service reopens the exact verified parent and family state, reconciles open attempt children, then resumes admission. TTL closes unresolved children as failures with typed degradation evidence and never marks them successful. A closed/expired parent is not reopened under the same generation. Ares reset/new session generation creates a new parent. The daemon must not infer identity from a missing session id.

### Owner map and cross-store recovery (required; not implemented)

| Responsibility | Canonical owner / proposed API | Durable boundary |
|---|---|---|
| Load/validate grant and mint in-process authority | New `NormalChatEgressGrantV1` loader plus non-serializable `NormalChatGrantAuthorityV1` in `recursive-agent-policy`; only startup loading creates it | Grant snapshot + revision bound in policy state; IPC cannot construct or widen it |
| Session budget, control parent, attempt ordinal, permit issue/consume, policy readback | New `FamilyAuthorityStore::reserve_normal_chat_attempt` in the session parent atomically allocates the child slot and reserves attempt/output/request-byte budgets; input-token usage is telemetry only in this phase. Child-local `DurablePermitStore` APIs (`begin_normal_chat_attempt`, `read_normal_chat_attempt`, digest-only `settle_normal_chat_v2`) issue/consume the exact effect permit and record outcome | Parent family reservation is durable before child link; child permit/receipt/artifact state lives under the child run root and is linked by exact family child permit and attempt ids. Ambiguous parent reservations are not refunded |
| Session root and per-attempt child run lifecycle | New split-phase `RuntimeService` methods in `recursive-agent-runner`, reusing `RuntimeLiveParentV2`, `FamilyAuthorityStore`, `ChildRunLinkV1`, and `ChainHandle`; one child per physical provider send | Parent `RunStarted`, `ChildAdmissionPrepared`, `ChildLinked`, child attempt `RunStarted`/step/terminal, `ChildClosed`, and parent `RunFinalized`; daemon/plugin owns no parallel chain |
| Digest-only observation metadata | Existing `ArtifactStore` under a run-root owner, with new V2 metadata schema | Immutable artifact descriptor referenced by the outcome/ledger receipt; raw prompt/response are absent |
| Actual dispatch materialization and transport body hash | New Ares core/transport owner, not the RA plugin | Ares creates the stable logical-call ref and per-send intent; transport hashes the same immutable bytes it submits |
| Policy-to-ledger reconciliation after crash | New `RuntimeService` reconciler using policy-owner readback + existing `ChainHandle` append/read/verify | Policy records determine whether an attempt was issued/consumed/reported; ledger receipts are deterministic projections. Exact existing receipt id + bytes is idempotent; a conflicting receipt or missing policy evidence quarantines the run as corrupted/degraded. No permit is reissued during reconciliation. |

There is **no atomic transaction** across the session parent, attempt child, policy state, artifacts, and `ChainHandle`. The Begin commit point and recovery order are therefore normative:

1. Validate the exact grant, session generation, `ManagedCallContextV1.call_ref`, logical-call digest, `dispatch_intent_ref`, route, and request/output reservations.
2. Under the runtime session gate, validate a closed `NormalChatCallRequestV2` containing the existing owner-issued parent id, operation, physical body digest/length and dispatch intent, but NO allocation-dependent ordinal/child id/parent receipt/caller budget. Persist its canonical request artifact, then append/read back `ChildAdmissionPrepared` whose spec/args digest is the canonical request content digest. The generic preparation receipt keeps its existing empty `artifact_refs` contract: RuntimeService derives the exact request artifact descriptor using the contracts owner's artifact id/digest transforms and requires its bytes and descriptor in the complete inventory. Generic chain verification alone does not verify this additional normal-chat request-artifact binding; the runtime barrier does. Preparation identity excludes its own receipt id.
3. Only after exact preparation readback, the policy-owned conversion stamps that receipt id and a fixed local metadata budget; `reserve_normal_chat_attempt` atomically allocates the ordinal/attempt/child ids and cumulative charges. The immutable parent `ChildLinked` binds the preparation digest and the exact typed-attempt digest, canonical family child-control id, and policy-owned generic link-budget projection. That projection retains V1 units: `max_steps:2` counts both local-control and effect declarations; output bytes remain an unused stdout/stderr ceiling (actual captured output is zero); artifacts use the fixed byte ceiling. Output tokens never become bytes. Exact-intent reservation readback never restores a send continuation. Create the child root only through the runtime owner; no header, prepared intent or link grants egress authority.
4. In the child-local policy owner, validate the grant/current route and canonical family, derive the exact constrained local control/effect, atomically issue+consume once, and persist its required retained context and preflight. No externally readable issued-but-not-consumed effect exists. Complete the child preflight transcript in this order: `RunStarted`; local-control `StepStarted` and `PermitIssued`; effect `StepStarted`; `NormalChatAttemptAdmittedV2`; historical effect `PermitIssued`; exact `PermitConsumed`. Evidence must come from the canonical policy projection, not adapter-authored rewrites. Repair retains historical valid times and existing recorded times; receipt order does not imply monotonically increasing valid_time. Strictly verify/read back both child and parent state.
5. **Admission-response release barrier (still a RuntimeService/daemon gate):** no successful Begin response may reach IPC until the complete child transcript in step 4, canonical current policy/family state, cumulative charges and exact parent link/heads are durable, read back and verified. The child preflight gate alone is not this cross-store response-release barrier. Incomplete, conflicting or corrupt evidence never releases permission. Only a fresh native admission that crosses that full barrier can allow Ares's one physical send; historical metadata/readback never restores a lost continuation. Any retry/fallback is a new intent and child.
6. After send, persist the exact Ares-reported result in child policy/artifact state, append the explicit V2-only `NormalChatAttemptSettledV2` terminal observation, close the actual child-local control, and append `RunFinalized`. Strictly verify the child, then append/read back parent `ChildClosed`. Only then does settle return a terminal receipt. The generic `ArtifactStored`/`StepCompleted`/`StepFailed` recipe is superseded for admitted V2 normal-chat effects: those generic observation gates require a still-valid parent lease and cannot truthfully carry late settlement metadata. Never backdate local report metadata or relax V1/V3 gates.

A partial parent/child commit is resolved as follows; no path sends before step 5 and no recovery issues a second permit:

| Durable state found at restart/readback | Provider send possible? | Recovery decision |
|---|---:|---|
| No request artifact, preparation, reservation or child history for the intent | No | Fresh Begin may prepare and reserve once |
| Request artifact exists without preparation | No | Recovery-required, including exact retry; never silently ignore/remove the artifact or proceed to Fresh |
| Parent `ChildAdmissionPrepared` exists without reservation | No | Recovery-required/status only. Preparation-first is a legitimate interrupted prefix; no reservation is NOT proof that Begin never started. Explicit recovery may classify no-send, but cannot resume it into Fresh |
| Family reservation exists without parent `ChildAdmissionPrepared` | No | Invariant violation requiring quarantine/reconciliation; the normative runtime always prepares first. Never invent a matching receipt after the fact or resume a send |
| Exact preparation and reservation exist, but no child link/child root and policy has no Begin record | No | Explicit terminal recovery must retain the charge and cannot resume a fresh send. Until terminal recovery is implemented this prefix returns recovery-required, never automatic authority |
| Parent linked; child root exists; policy has no Begin record and verified child chain is a valid preflight-free prefix | No | No successful response could have passed the release barrier. Record one no-send terminal outcome and close the exact parent link. Conflicting or unverifiable evidence is quarantined/degraded |
| Policy Begin record says consumed; child preflight receipts are absent/incomplete; verified chain is a valid prefix before response-release barrier | No, only while the release-barrier invariant is proven | Reconcile deterministic missing preflight receipts from policy readback, then record a no-send terminal outcome and close the parent link. If the barrier is not proven, or any evidence conflicts, classify as `may_have_been_sent` and degraded; never refund or retry |
| Child permit consumed + complete pre-send receipts verified, no terminal transport report | Maybe (unknown) | The success response may have reached Ares and send may have started. Mark `NormalChatDegradationRecordV1{provider_send_state:"may_have_been_sent"}` and close as `normal_chat_degraded:OUTCOME_UNKNOWN`; never refund or retry |
| Policy outcome/settlement durable, child terminal append incomplete | No further send | Rebuild only deterministic missing child receipts from exact policy readback and metadata; verify, then close the parent link |
| Child terminal verified, parent `ChildClosed` absent | No further send | Append/read back the deterministic closure descriptor only; do not rerun the child |
| Any binding, digest, chain-head, or closure mismatch | No | Quarantine as `corrupted`; block new session egress until operator recovery |

The parent session API must make each operation idempotent on `(session_run_id, dispatch_intent_ref)`, and the attempt child id/receipt ids must be deterministically derived before any provider send. `RuntimeService` restart recovery must discover the session parent by owner-derived id, verify the parent chain, load its `FamilyAuthorityStore`, and reconcile every open link from child policy/ledger state. This is a new owner API; generic terminal `RuntimeService::submit` is not a substitute.

This topology preserves the existing pinned-run-root requirement: every attempt child's `DurablePermitStore` and `ArtifactStore` share that child's `RunPaths`. The session parent's `FamilyAuthorityStore` and a new closed `NormalChatSessionBudgetV1` owner record hold cumulative child/attempt/request-byte/output-reserve charges. Input-token usage is telemetry, not a session admission charge in this phase. **Neither the split-phase external-child APIs, the session budget record, nor durable parent resume/reconciliation exists today.** P2 must implement and fault-test them under the `RuntimeService`/`FamilyAuthorityStore` and policy owners; it must not bypass the current root-identity check or move counters into plugin memory.

### V2 terminal-settlement contract amendment

Reviewed design: `reports/p2-runtime-terminal-design-review/`, longmemeval-bench source/receipt lane (advisory). Contracts and ledger, not an adapter exception, own a new closed receipt/event `NormalChatAttemptSettledV2`. It requires the same step's unique V2 admission and exact preceding PermitConsumed state, one canonical settlement metadata artifact, plus one exact typed degradation artifact iff OutcomeUnknown. It transitions only that V2 effect directly to Complete; a Failed outcome establishes the existing generic failure state, Ok denotes only a bounded reported success with no violations. Generic ArtifactStored/StepCompleted/StepFailed substitution for an admitted V2 effect rejects. Old readers reject the new variant; no tolerant fallback or wire migration.

Policy owns the pure settlement/admission validator and reported-outcome mapping: exact attempt/effect/preflight, ordered recomputed violations, both outcome/settlement digests and local recorded_at; OutcomeUnknown precedence before bound exceeded, then ordinary reported states. The receipt valid_time is the canonical outcome.recorded_at, including late reports after expiry/revocation; it grants no permission or provider confirmation. OutcomeUnknown is Failed with `normal_chat_degraded:OUTCOME_UNKNOWN`, with the separately bound degradation artifact; generic Degraded terminal semantics remain unchanged. This amendment supersedes older generic ArtifactStored/StepFailed degradation recipes for the V2 lane throughout this ADR.

Actual child control closure is durable policy-owner revocation/readback, preserving the original reason/time, never rewriting non-Operator revocation into orderly closure. Existing strict successful finalization still requires Operator control closure; unsupported prior non-Operator closure remains blocked rather than falsely successful. Missing terminal receipts use immutable policy-owned settlement/closure valid_time anchors. Newly appended rows receive their actual recorded_time from the ledger owner; every retained complete row preserves its exact original recorded_time and canonical bytes. EOF-partial tail recovery belongs only to the existing ledger owner, not to a runtime rewrite. Recovery recognizes only exact expected terminal artifacts left ahead of their receipts, rejects unrelated/conflicting inventory, never restores a send, and retains all charges.

The runtime serializes this composition through the session gate, requires existing exact parent/child stores and a complete verified preflight, and appends only deterministic missing terminal suffix rows. Strict child terminal and exact original admission fields in parent ChildClosed must verify durably before returning terminal success. The parent session stays open. A second new intent remains blocked until the broader family reconciler is implemented. Full quarantine/TTL/lease rotation/subagents and daemon response release are later gates.

### Bounded first-attempt runtime implementation boundary

The isolated P2 runtime supports a first fresh native child plus explicit terminal report/child closure and exact terminal-suffix recovery. It still deliberately blocks any second new intent until broader family reconciliation is implemented; a completed child report does not silently widen admission. It is not a complete P2, a daemon success response, provider execution or an end-to-end send governor.

At release, both retained ArtifactStores must still match the `artifacts` locators of their pinned run roots; parent binding and child preflight/inventory are checked again after the mutation seam. Legitimate normal-chat ledger/artifact writers must share the runtime session gate through this boundary. Ledger internal locks are short-lived per operation; a retained ChainHandle is not a held writer lock. These checks do not protect against arbitrary same-UID store rewriting.

The final native release check holds locks in child-permit → family → root-permit order. All relevant policy revocation/close writers acquire one of those same locks. Current time is sampled after waits; the root control, complete expected family snapshot, exact canonical reservation, child control/consumed preflight, expiry, grant and pinned locators must agree. This locked validation is the release linearization point; a subsequent close cannot retroactively cancel an already admitted attempt. The runtime gate is nonblocking; downstream owner locks may block. Runtime tracks clock regression across the entire operation, including ledger publication delays. Daemon response release must later consume the fresh, nonclone/nonserializable runtime handle and define its own final publication boundary.

Preflight aggregate artifact accounting counts each unique canonical payload once (not repeated receipt references); descriptor sidecars are bounded store overhead, not payload budget. The runtime checks the four actual child metadata payloads with checked arithmetic and reserves 64KiB of headroom for later digest-only terminal metadata. The exact-size check is currently after native consumption but before any child payload/receipt publication; failure withholds Fresh and retains the charged consumed prefix. The preflight headroom reservation alone is not terminal-capacity proof. The explicit terminal owner now checks the actual combined unique preflight/terminal payload aggregate against the original ceiling and recovers only exact policy-derived terminal suffix/artifact prefixes. Broader preflight/unknown-outcome recovery, quarantine and family reconciliation remain later gates. Fixed metadata budgets harden the unpublished V2 lane; earlier experimental V2 records with different caps reject, without rewriting or migration. V1/V3 contracts are unchanged.

### Attempt idempotency and crash/retry state machine

| State / event | Provider send permitted? | Required recovery |
|---|---:|---|
| Begin denied before durable admission | No | Append `PermitRejected`/denial; terminal denied step; no retry under same intent |
| Live Ares caller definitively receives no successful Begin response | No | The caller MUST NOT invoke transport. It may settle the attempt with a typed `not_sent` outcome; retry/readback of the same intent is status-only and never authorizes a later send |
| Ares or daemon process crashes after the complete response-release barrier but before a durable transport outcome | Maybe (unknown) | The success response may have reached Ares and a send may have started. Record `NormalChatDegradationRecordV1{provider_send_state:"may_have_been_sent"}` and expose `degraded`; never retry, refund, or infer no-send |
| Begin acknowledged and Ares submits the transport request once | Exactly one request for this intent | Provider SDK retries are disabled or every transport send has a new intent and child run |
| Provider send may have started, but settle is absent (process crash/stream abandoned) | No further send for this attempt | Write `NormalChatDegradationRecordV1`, close the child as a failed RA run with the exact `outcome_unknown` reason, and expose normal-chat status `degraded`; never refund or retry |
| Policy outcome/settlement durable, child-ledger append or parent closure incomplete | No | Reconciler rebuilds deterministic child receipts from policy readback and metadata, verifies the child, then appends exact `ChildClosed` evidence; conflicting evidence quarantines the session |
| Exact child policy and ledger terminal records verified | No further send for the settled intent | Readback returns immutable state; duplicate settle is exact-idempotent, conflicting settle rejected |

The policy owner allocates ordinals serially per logical operation. `dispatch_intent_ref` is unique per physical transport send but stable across IPC retry; same ref with different operation/body is `INTENT_CONFLICT`. A new provider retry/fallback creates a new intent and obtains the next ordinal. `request_id` is connection correlation only and is not the durable idempotency key.

### Run-close outcome precedence

Each attempt child uses the current `ReceiptOutcomeV1` contract without pretending it has a generic degraded terminal state. On a provider result that is known failed, the child ends `Failed` with a stable provider-error code. If the transport may have sent bytes but no durable settlement can be established, the child stores a closed `NormalChatDegradationRecordV1` artifact, then finalizes with `Failed{reason:"normal_chat_degraded:OUTCOME_UNKNOWN"}`. A normal-chat-specific `NormalChatAttemptStatusV2` verifier reads the exact child chain and degradation artifact and returns the distinct status `degraded`; generic `RunTerminalStateV1` remains `Failed`. If the child chain itself is corrupted, it is quarantined and no successful `ChildClosed` is appended.

`NormalChatSessionStatusV2` is a rebuildable projection over the verified parent and every linked attempt child: `corrupted` if any child/link fails verification; `degraded` if any child has an outcome-unknown degradation artifact; `failed` if any settled attempt failed; `denied` if every attempt was policy-denied and no provider send occurred; `succeeded` only if every attempt succeeded and the parent closed cleanly. The session parent's generic `RunFinalized` state records that the lifecycle was closed and its children were reconciled; it alone never claims every model attempt succeeded. The projection must be recomputable from verified child artifacts and links, not a second mutable status database.

For each admitted attempt, the policy owner durably reserves one attempt and that operation's `output_reserve` against the cumulative session ceilings **before** returning the permit; `output_reserve` must be no greater than the remaining `max_output_tokens`, and the exact reserve is sent as the provider's output ceiling. It enforces `max_request_bytes` and `max_wall_time_ms` per physical send. Reservations are serialized/atomic across concurrent calls, survive restart, and are not refunded after durable Begin (including an ambiguous or no-send outcome). Input-token usage is not an admission budget in this phase: it is provider-reported telemetry unless a future route-specific policy owner supplies verifiable pre-call evidence. A reported provider usage value does not retroactively authorize a retry or prove billing. The grant's cumulative session caps are stored and verified by the canonical policy owner; no plugin-local counter is authoritative.

### No-session calls

In `enforce`, deny an in-scope call that has no canonical Ares session identity and no owner-issued one-call request identity. The P0 census found seven CLI/plugin callsites with no session id passed directly, plus a Gemini setup probe; ambient propagation is not yet verified. An absent id is not permission. In `observe`, preserve the no-block behavior and append a local degraded/unwitnessed record, but count that call as **not receipted** and do not claim full governance for it. A future one-call root requires an Ares owner-issued identity and separate ADR amendment; the plugin may not invent a sentinel.

### Budget guarantees and limits

`max_attempts` can be enforced at permit issuance. `max_request_bytes` can be enforced from the exact final serialized projection supplied by the physical request owner. `max_output_tokens` can be enforced only where the selected transport accepts and preserves an output-token ceiling; the same ceiling must bind the exact request sent to the provider and pass route-specific tests. The approved scope for this phase has **no hard input-token ceiling**: input counts cannot be independently verified from arbitrary provider payloads with the current daemon contracts, so usage is provider-reported telemetry only and is never treated as admission proof. `max_wall_time_ms` bounds permit validity and the configured transport timeout, not remote provider work after client timeout. A route lacking any required enforceable bound is unsupported in `enforce`.

A wall-time cap can bound permit validity and the configured transport timeout, but cannot guarantee that a remote provider stopped work after a client timeout. The receipt records local duration and reported outcome, not remote cancellation. Exact cost, billing, and provider-side work are outside the guarantee.

## 6. Denial codes

The daemon's new denial enum is closed. Proposed policy codes:

- `GRANT_MISSING`
- `GRANT_EXPIRED`
- `ROUTE_NOT_ALLOWED`
- `CAP_EXHAUSTED_ATTEMPTS`
- `CAP_EXHAUSTED_OUTPUT_TOKENS`
- `CAP_EXHAUSTED_WALL_TIME_MS`
- `CAP_EXHAUSTED_REQUEST_BYTES`
- `RUN_CLOSED`
- `INTENT_CONFLICT`
- `MATERIALIZATION_UNAVAILABLE`
- `SOURCE_REVISION_UNAVAILABLE`
- `MALFORMED`
- `DAEMON_OVERLOADED`

The Ares plugin/transport adds separate local failure codes from the plan: `DAEMON_UNREACHABLE`, `DAEMON_TIMEOUT`, `GOVERNANCE_MODE_INVALID`, and `UNSUPPORTED_TRANSPORT`. A core governor error is `DISPATCH_GOVERNOR_ERROR`. A post-send settlement/readback failure is **not a pre-dispatch denial**; it is `DISPATCH_OUTCOME_UNRECORDED`, with provider-attempted state retained, response withheld in `enforce`, and no retry, fallback, credential rotation, or budget refund.

Example typed denial:

```json
{
  "schema": "recursive-agent.ipc/response/v2",
  "request_id": "fixture-begin-1",
  "result": {
    "kind": "denied",
    "code": "ROUTE_NOT_ALLOWED",
    "reason": "route is not present in the active grant",
    "provider_attempted": false
  }
}
```

A repeated `NormalChatAttemptBegin` with the same `(session_run_id, dispatch_intent_ref)` and exact operation/body returns the same persisted state, never another permit. Reusing that intent for a different operation or body returns `INTENT_CONFLICT`. If the daemon is unreachable or the grant cannot be verified in `enforce`, the low-level provider send callback count is zero.

## 7. What receipts prove and retention

### Retention decision proposed

Choose `digest_only` by default. Preserve `NormalChatOperationV1` and `NormalChatSettlementV1` semantics; add a new closed V2 operation/attempt/settlement family where `replay` is explicitly `unavailable`. The V2 settlement stores a digest and byte length for a versioned response projection plus outcome/usage metadata, not the raw prompt or response. The `ArtifactStored` receipt refers to a canonical metadata observation artifact, not to a hidden full response. A digest-only record cannot be used to replay a response. Full content retention is a separate future operator decision requiring explicit at-rest controls, retention/erasure policy, and a new versioned contract; it is not enabled by this ADR.

The request digest uses a named versioned projection, proposed `ares-json-sorted-v1+sha256`, and the response digest uses a separately named versioned response projection. They are not RFC 8785/JCS unless independently implemented and verified as such. Existing RA `ContentDigest` fields use the Libraries-owned digest type; external algorithm-prefixed fields use the exact format their validator accepts. No content is silently omitted from a V1 settlement while leaving `recorded_response_only` in place.

### Degraded and unknown outcomes without widening V1 receipts

The generic V1 ledger cannot finalize `ReceiptOutcomeV1::Degraded` as a `RunTerminalStateV1`; `terminal_state()` returns `None` for `Degraded`, and strict `RunFinalized` requires a terminal state. Preserve V1 semantics. **Current P2 amendments supersede the earlier generic `ArtifactStored`/`StepFailed` sketch:** a real executor-reported `OutcomeUnknown` uses `NormalChatAttemptSettledV2`, its exact executor report and its derived `NormalChatDegradationRecordV1`, with generic `Failed{reason:"normal_chat_degraded:OUTCOME_UNKNOWN"}`. An absent executor report must never be synthesized into that lane.

For a natively consumed V2 attempt with no executor report after its actual stored effect expiry, the policy owner may publish its closed `NormalChatRecoveryRecordV1` with distinct origin `executor_outcome_missing_after_expiry`, send uncertainty `may_have_been_sent`, exact attempt/permit/preflight bindings and owner-observed time. The report-versus-recovery terminal slot is exclusive under the native child lock; family admission closes durably first, charges and leases remain unchanged, and exact recovery ACK confirmation is clock-free. The corresponding **versioned historical ledger transition** is `NormalChatAttemptRecoveredV1` (wire `normal_chat_attempt_recovered_v1`), not `NormalChatAttemptSettledV2`. It requires the exact V2 consumed-admission prefix, one canonical recovery-record artifact and fixed generic failed reason `normal_chat_degraded:EXECUTOR_OUTCOME_MISSING_AFTER_EXPIRY`. The recovery record itself is the distinct degradation/origin evidence: it contains no SDK outcome, usage, response or duration. The event completes that effect step; strict child finalization still requires local-control closure and preserves the exact effect binding and failed reason, no output artifacts, and a valid time no earlier than the observation or the control closure. Old report lanes and generic active-effect rules are not widened.

A verified recovery child is failed **because executor evidence is unavailable**, not because the provider is known to have failed, timed out or never received a request. Offline verification proves canonical evidence consistency, not native mutation authenticity against arbitrary same-UID writers or current egress authority. This bounded ledger amendment does not implement RuntimeService recovery/restart routing, parent `ChildClosed`, degraded-parent finalization, quarantine, TTL automation, IPC, Ares transport governance, or new send authority; those consumers must remain fail-closed until separately integrated and verified. Implementation/test evidence belongs to the frozen P2 receipts, not this design text. The additional normal-chat status remains a distinct, verified projection, never inferred from the generic terminal alone.

Proposed degradation record (fixture values only):

```json
{
  "schema": "recursive-agent.normal-chat-degradation/v1",
  "attempt_id": "v1:recursive-agent/normal-chat-attempt/v2:det:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "permit_id": "v1:recursive-agent/permit/v1:det:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
  "reason_code": "OUTCOME_UNKNOWN",
  "provider_send_state": "may_have_been_sent",
  "preflight_receipt_digest": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "recorded_at": "2026-10-14T12:01:00Z"
}
```

`NormalChatAttemptStatusV2` and `NormalChatSessionStatusV2` are rebuildable projections from verified parent/child receipts, policy readback, and any linked degradation artifacts. Allowed attempt states are `pending`, `succeeded`, `failed`, `denied`, `degraded`, and `corrupted`. `pending` is not permission to retry; `degraded` requires the exact degradation artifact and matching permit/preflight binding. Session status aggregates those attempt states and is not stored as independent authority. The API must preserve both the generic RA terminal (`failed`) and the normal-chat classification (`degraded`) so a caller cannot mistake either for provider confirmation.

### P2 ledger-owned closed native family proof (bounded prerequisite)

`verify_closed_normal_chat_child_from_dir_fd` is the ledger-owned exact join of a canonical native reservation, retained admission/preflight, closed local control and exclusive terminal source to the strict ten-row child transcript and its complete canonical metadata inventory. `VerifiedNormalChatDispositionV1` distinguishes actual executor-reported `OutcomeUnknown` from distinct native missing-executor recovery, and does not classify known Failed/NotSent as unknown. Runtime family history delegates that closed-child semantic proof to the ledger owner instead of maintaining a parallel terminal transcript interpreter.

`verify_closed_normal_chat_family_from_runtime_root_fd` receives one caller-pinned runtime-root descriptor and expected parent run ID. It verifies nonempty, complete pre-finalization prep/link/closure groups against ALL canonical native reservations, the original root/session context and every strict child. Parent phase step IDs reuse `derive_child_receipt_step_id`, factored unchanged from the runtime's existing preimage into the contracts owner. Pinned source descriptors, native snapshots, exact inventories and chain heads are retained privately and can be rechecked. The proof exposes only historical metadata: no mutation handle, grant enrollment, new permit, serialized capability, send continuation or parent finalization. No current grant or clock is required. Missing/partial/open/conflicting evidence rejects rather than recreating authority or appending semantic rows. Canonical appendable ledger readers may reconcile tails/metadata; this is not a forensic read-only byte contract.

The family proof is not an atomic multi-owner transaction: callers that compose later runtime transitions must hold the canonical runtime session gate and revalidate after native closure/publication. Arbitrary same-UID full-source rewriting remains outside the filesystem threat model. The current helper checks child aggregate payload capacity and exact parent inventory; parent aggregate-capacity enforcement remains in the existing runtime owner and must also be bound at any later degraded-parent terminal publication. The proof deliberately rejects empty, pending and already-suffixed/finalized parents; the typed cause/event substrate is described below, while suffix-aware native-family acceptance and runtime finalization remain unimplemented. Generic `ra verify --run` is not silently promoted into this complete native-family proof. Evidence is in the frozen P2-native-family-proof receipts, not this amendment alone.

### P2 degraded-session cause contract and unscoped fence (not finalization)

The closed `NormalChatSessionDegradationV1` reference-only artifact and `NormalChatSessionDegradedV1` receipt/event preserve distinct reported-unknown versus missing-executor source references, root close references, ordered child closures and bitemporal anchors. The parser rejects duplicate/unknown members, noncanonical or lossy typed encodings, malformed/self/duplicate identities, missing unknown references and declared resource-bound violations. Receipt-only lifecycle validation requires the exact completed root/control and nonempty closed group shape, a sole cause, and an exactly bound final outcome/time with no artifacts. It does not inspect or authenticate native state or sibling bytes and cannot establish that an unknown reference is genuine.

All current generic authoritative ledger append/read/strict/event/replay/pack routes refuse marker-bearing chains with typed `NormalChatFamilyScopeRequired`. No scoped bypass, verified marker snapshot, marker writer, CLI scope flag or RuntimeService finalizer is exposed in this slice. Recognizing structural metadata is deliberately not acceptance of its evidence. Actual admission must first prove at least one genuinely unknown child via the canonical complete-family join, regardless of native revocation reason, and require the existing closed root/family pair; Operator revocation alone never proves unknown. Only then may source-owned cancellation, PolicySuperseded denial or fixed Failed `normal_chat_degraded:CHILD_OUTCOME_UNKNOWN` precedence be selected. Generic terminal enums and older lanes are unchanged.

The scoped suffix/append owner is held until the complete native join, aggregate parent publication capacity and global session-gate/ledger/native lock order are established. A future writer must not recursively read-lock the parent under its append flock or duplicate/bypass the canonical session gate. No new authority, report, usage, duration, refund, lease or provider/no-send claim follows from this contract. Latest frozen command/review receipts, not this amendment, own implementation acceptance.

### P2 shared session-gate owner (coordination, not authority)

`NormalChatSessionGateV1` in the ledger/root-descriptor owner is the single implementation of normal-chat lifecycle coordination. It retains the same `.normal-chat-runtime.lock` name, exact 0600/same-UID/single-link regular-file law, no-follow/nonblocking opens and exclusive nonblocking flock. `acquire` retains bootstrap/create behavior; `acquire_existing` never creates or falls back. The private, non-Clone/nonserializable guard owns the held descriptor. Consuming unlock explicitly releases the open-description flock; ordinary File drop closes this guard's reference, while fork/dup references can retain it until exec/close. Failed post-flock validation explicitly unlocks before returning its error; a cleanup I/O failure is reported rather than claimed released. RuntimeService now delegates through an error-projection-only wrapper, preserving Busy and the old Unsafe/LocatorChanged/Io diagnostic vocabulary; no second lock implementation remains there.

The shared public guard additionally binds the original root descriptor through the ledger's canonical `run_root_identity` law and checks both root and gate locator immediately after flock and at later `check` calls. Moving the same gate inode cannot retarget the guard to another root. A failed post-flock fence drops/releases the detached held file. Root admission/mismatch failures are explicit typed failures, not a repair or permissive fallback. This is directory-descriptor scope, not a perpetual pathname lease: the outer pinned run-locator owner is still required and arbitrary same-UID replacement/bypass is not prevented between checks.

The gate itself takes no ledger-directory or native policy lock and has no clock, grant, budget, marker writer or send continuation. It is the outer coordination layer, not proof of a global lock graph. Current runtime paths share this exact primitive; a future scoped writer must borrow the held guard instead of copying its rules or acquiring it again. Complete writer-specific lock ordering, native/source/closed-pair proof, suffix acceptance and aggregate publication-capacity obligations remain held. `NormalChatFamilyScopeRequired` remains unconditional. Frozen executable receipts, not this amendment alone, own acceptance of this prerequisite.

### P2 guard-bound native degradation preparation (not publication)

`PreparedNormalChatSessionDegradationV1<'gate>` is an immutable, non-Clone/nonserializable source projection which borrows the matching live shared gate. Before any reconciliation-capable parent read, the preparation entrypoint opens and checks one parent pin; a private factored verifier carries that exact descriptor through full native family verification and its gate-fenced internal final recheck. The old public family verifier retains its checks and behavior without acquiring a second gate. The preparation's own recheck checks the borrowed gate before family readers and reconfirms exact current already-closed native root/family state without a clock, creator, revoke or authority-repair branch.

Every cause branch first requires at least one actual source-verified unknown child. Known Failed/NotSent/success, pending or corrupt families and Issued roots do not become unknown by default. Actual family cancellation/root cancellation precedes PolicySuperseded denial; an eligible Operator-closed unknown family maps only to the fixed CHILD_OUTCOME_UNKNOWN failure. Root close evidence, ordered parent group/child terminal/source references and semantic time anchors are derived from retained canonical sources. The proposed revoke receipt ID uses the existing pure contracts identity material and immutable prefix head, not make_receipt or a synthesized recorded_time.

Preparation checks unique canonical parent payload capacity—including implicit preparation artifacts—plus exact candidate closed-root and marker payloads, against the original native root ceiling with checked arithmetic and consistent duplicate descriptors. Getters expose metadata and a draft only; no stores, mutation handle, successful terminal snapshot, append method or send continuation is exposed. It deliberately accepts only pristine complete pre-finalization source families; suffixes/orphans/recovery/publication remain unsupported. Ordinary marker append/read/replay/pack still return scope-required rather than accepting the projection as evidence. Gate borrowing and source rechecks are cooperative fences, not a perpetual filesystem lease or global writer-lock certification. Frozen executable receipts own acceptance, not this amendment alone.

### Evidence and claim boundary

A passing `ra verify --run` proves that the stored receipt/artifact chain satisfies the ledger's structural and digest checks for that exact run. A `PermitPreflightReceiptV1` proves the RA policy owner recorded permit consumption against its binding. A `PermitOutcomeReceiptV1` proves only the bounded outcome reported by Ares. Usage is provider-reported where supplied. A response digest proves equality to the exact declared projection only if the Ares materialization/response owner and its projection algorithm are independently bound and tested.

None of these artifacts alone proves that a provider performed no internal work, that provider billing equals reported usage, that the provider succeeded when Ares reports success, or that every request from other processes or unclassified code paths was governed. Same-UID/root modification of the complete local grant/store is outside the filesystem trust boundary. No claim of “every model call is receipted” is allowed until the live in-process census has zero unrouted sites; every enabled transport has a tested per-network-attempt hook or disabled retry contract; every unsupported in-scope transport is type-denied before its network callback in `enforce`; fail-closed tests observe zero egress on denial; and every successful/failed attempt has one verified terminal child receipt plus a session-parent closure link. `observe` does not satisfy this claim.

### Specialist review outcome (advisory, not approval)

The `longmemeval-bench` profile reviewed the prior ADR draft read-only against the pinned RA worktree. Its execution receipt is `reports/adr-longmemeval-review/panel.json`; the separate verifier receipt is `reports/adr-longmemeval-review/verifications/20261014T214035598797Z-1c6ed22dfba24dfa82576bf2cfe3abcc.json` (`execution_artifacts_verified`). The profile returned with exit 0 and explicitly said the prior draft was **not implementation-ready**. It identified seven material gaps: V2 attempt identity/wire mismatch; grant-to-parent composition; owner/run/ledger recovery mapping; concurrent ordinal and lost-ACK behavior; incomplete/ambiguous receipt terminalization; digest preimages/projection ownership; and run-close outcome derivation.

This revision incorporates those findings as proposed V2 identity rules, an exact grant-parent constraint, a new owner/recovery map and crash-state table, distinct logical-request versus per-send digest preimages, and explicit degraded/failed/denied close precedence. The controller independently confirmed another source constraint: existing `read_external_permit` rejects `NORMAL_CHAT_LANE`, so a normal-chat-specific policy readback API is required. These additions are design proposals, not existing implementation. The session-root/policy-store/artifact-root topology remains an explicit P2 blocker, as do missing Ares materialization/source owners and unverified low-level transport hooks. The panel receipt proves execution artifacts only; it does not approve the revised ADR or the operator's decisions.

### Operator approval and implementation gates

The operator's message “You have my approval for everything, just get it done properly please” authorizes the following recommended choices for implementation in isolated worktrees. This grants no live activation, commit, push, publication, or service-replacement authority. It does not waive the source-backed blockers and test gates below.

1. Attempt boundary: one permit per actual network egress attempt, rather than one permit per outer SDK invocation.
2. Scope: in-process LLM completion and inference-probe requests only; image/video generation, TTS/STT, standalone scripts, and other processes remain out of scope.
3. No-session behavior: deny in `enforce`; allow only with a degraded/unwitnessed local record in `observe`; no fabricated IDs.
4. Grant authority: separate operator-owned mode-0600 grant file; no IPC enrollment. Same-UID filesystem ownership is the selected authority boundary for this local deployment; root or compromised same-UID processes remain outside the guarantee. No signature/key owner is added in this phase.
5. Run lifecycle: a session-root run with operation child runs and cumulative durable reservations.
6. Content retention: digest-only by default and replay unavailable, requiring V2 contracts.
7. Budget semantics: enforce durable attempt-count, request-byte, wall-time/transport-timeout, and provider-preserved output-token ceilings. Do not claim a hard input-token ceiling until an authoritative route-specific counter exists; input usage is provider-reported telemetry and is not admission proof. A route that cannot preserve the output ceiling is unsupported in `enforce`.
8. Materialization/source ownership: add an Ares-owned final-dispatch materialization, per-send body-digest, and installed source-revision contract. Until each route has the owner and transport hook, that route is denied in `enforce` and excluded from coverage claims.
9. Defaults: installer writes `observe`, uses a separate per-home daemon, and does not modify the existing `recursive-agent.service`.
10. Storage/recovery topology: session parent with one child per physical network attempt; implement split-phase external-child, parent-resume, and reconciliation APIs only if they pass the P2 fault matrix while preserving each child's pinned policy/artifact root. Stop at a typed blocker rather than bypassing root ownership or using a terminal handle as a live parent.
11. Attempt identity: V2 domain/preimage and owner-allocated ordinals keyed by one Ares `dispatch_intent_ref` per physical send; sample IDs are shape fixtures and must be regenerated by contract tests.
12. Receipt semantics: keep generic RA V1 `RunTerminalState` unchanged; represent an outcome-unknown attempt as failed with a stable reason plus a verified `NormalChatDegradationRecordV1`, and expose `degraded` only through the rebuildable `NormalChatAttemptStatusV2`/session projection.

**P1 gate:** the initial `longmemeval-bench` review and subsequent ordering review identified a recovery-state contradiction. This revision makes the successful response-release barrier normative and distinguishes a verified pre-barrier prefix from a complete preflight whose send outcome is unknown. The operator has approved the recommended implementation decisions above. A final `longmemeval-bench` review must confirm this revised recovery model and fit to current owners; the controller must independently verify the review receipt and source claims. If the specialist still finds a material contradiction, P2 remains stopped at RED. Otherwise P2 may begin in isolated worktrees under the per-phase owner and fault-test gates; unresolved source gaps remain explicit implementation blockers, not assumed capabilities.
