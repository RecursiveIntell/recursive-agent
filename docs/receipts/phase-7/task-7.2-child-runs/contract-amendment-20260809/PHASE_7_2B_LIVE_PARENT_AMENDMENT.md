# Phase 7.2B — live-parent amendment

**Status:** proposed from current source inspection; implementation is not yet admitted green.

## Decisive correction: V2 caller envelope has an identity cycle

`ChildOperationEnvelopeV2` currently requires `child_authority.parent_admission_receipt_id`, while `ChildRunLinkV1` requires the same receipt ID and is intended to be stored as an artifact on that admission receipt. This cannot be constructed honestly:

1. the link artifact bytes include the parent admission receipt ID;
2. the artifact descriptor digests those bytes;
3. the receipt ID binds its artifact descriptors;
4. therefore the receipt ID would have to be known before calculating itself.

A terminal `RuntimeHandleV1` also cannot be used as the parent because the parent chain has already finalized. Neither a scheduler row nor a local child `DurablePermitStore` repairs either boundary.

## Minimal admissible API

Keep the existing closed `ChildOperationEnvelopeV2` as the post-admission material that binds a parent receipt. Add a separate `ChildOperationProposalV2` for caller input. It contains the same delegated operation material but **no** `ChildRunAuthorityV1`.

`RuntimeService::submit_child` accepts only a private live-parent session plus a validated proposal:

1. derive the proposal digest and append a durable `ChildAdmissionPrepared` parent receipt whose arguments bind that digest;
2. use the now-existing receipt ID to construct `ChildRunAuthorityV1` and the closed `ChildOperationEnvelopeV2`;
3. derive the child run ID, strictly re-read the appendable parent chain, then atomically reserve the family child-control permit;
4. append `ChildLinked` with a content-addressed `ChildRunLinkV1` artifact; only after this receipt succeeds can the child run dispatch;
5. execute the child through the canonical runner with a family dispatch guard checked immediately before and after every child effect;
6. strictly verify the child terminal chain, append `ChildClosed` with immutable closure evidence, and reject parent success unless every prepared child has exactly one verified link and terminal closure.

The split is required to break the receipt/artifact identity cycle. It is not a V1 fallback, a scheduler-owned admission path, or adapter-owned state.

## Lifecycle shape

`begin_parent_v2` is separate from `RuntimeService::submit` and keeps the existing V1 synchronous terminal semantics unchanged. The session owns only the pinned parent root, appendable ledger chain, parent lifecycle permit, and family store rooted under that same runtime-selected root. It executes the V1 root operation's declared steps before returning the live session but defers the parent lifecycle permit revocation and `RunFinalized` receipt until explicit parent finalization.

The family store remains the sole reservation/revocation owner. The scheduler may receive parent/child visibility projection only after admission; it does not participate in authority, budgets, or closure verification.

## Required acceptance tests

1. A caller cannot submit a complete V2 envelope directly; only `ChildOperationProposalV2` may enter the live-parent lane.
2. A parent-admission receipt exists and binds proposal material before a family reservation or child dispatch.
3. Link tampering, altered parent receipt ID, duplicate child link, missing closure, mismatched terminal state, or chain-head mismatch causes strict parent verification/finalization failure.
4. Parent cancellation revokes the family before queued child dispatch; a guard check both before and after a child effect prevents a revoked family from reporting success.
5. A V1 `submit` remains terminal-only and cannot create a live-parent session implicitly.

## Explicit exclusions

No raw process scheduler, provider, remote worker, CLI/MCP delegation command, V1 compatibility path, scheduler authority, or edits under `/home/sikmindz/Coding/Libraries`.

## Rollback

Revert the Phase 7.2B commit(s) and quarantine any family-state directories below run roots. Preserve all receipts and permits; deny new live-parent admissions rather than rewriting historical state.
