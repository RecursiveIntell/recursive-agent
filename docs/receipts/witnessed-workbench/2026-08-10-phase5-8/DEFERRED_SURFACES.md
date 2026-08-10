# Deferred surfaces — controlled boundary record

## Phase 7: controlled orchestration

**Status:** deferred pending a separately proven Phase 6 clean-host deployment and explicit activation authority.

Any future Agent Graph integration is limited to choosing or sequencing requests through a narrow native/Hermes adapter. It may receive only native run IDs and verified pack references. Graph receipts are correlation metadata only: they cannot issue permits, expand authority, authorize effects, alter native terminality, or manufacture a run result.

**Future acceptance gate:** cancellation, retry, and duplicate submission leave exactly one native idempotent execution; an unavailable/tampered pack remains visibly degraded in every operator result.

**Rollback:** remove the orchestration adapter binding. The native vault and offline verifier/replay remain operational.

## Phase 8: surfaces explicitly outside this pass

- **Gloss:** may become a read-only inspector only after it requests Recursive Agent verification and renders unavailable/tampered state. It is never an executor or alternate ledger.
- **Direct semantic-memory integration:** deferred until a new source-generation admission. Mnemes remains the intended control-plane/shard owner; no Recursive Agent shadow memory database is allowed.
- **Replication:** deferred until Mnemes continuous replication is locally source-verified. Transfer must be content-addressed and independently verified; a remote `sync succeeded` is not proof.
- **Providers and remote workers:** deferred to a separate security and authority design. Recorded outputs can be replayed as evidence, not re-executed through a provider.

No code or configuration in this pass activates any deferred surface.