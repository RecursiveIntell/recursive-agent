# Witnessed Workbench Server Roadmap

**Status:** proposed implementation plan; no source or service state changed by this document.
**Evidence cutoff:** 2026-08-10.
**Primary product outcome:** an operator can submit a bounded local job through Hermes, retain a portable verified run pack in a server-owned vault, replay it offline on that server after the originating machine is gone, and retrieve a claim/provenance trail without turning Hermes, Agent Graph, ClaimLedger, Mnemes, or a UI into a second execution ledger.
**Explicit defer:** Gloss, packaged Hermes GUI/plugin-loader certification, provider-backed execution, public hosting, multi-tenant service, and continuous cross-device replication.

## 1. Decision and current evidence

The recommended product is a **Witnessed Workbench**, not another generic agent application:

```text
Hermes (operator interaction; untrusted display/session state)
    │ bounded native request
    ▼
Recursive Agent (only execution authority)
    │ verified immutable portable pack
    ├── server-owned content-addressed pack vault (bytes + offline verifier/replayer)
    └── ProjectionEnvelopeV1 (references, never substitutes for pack bytes)
           ├── ClaimLedger (claim/evidence support judgment)
           └── Mnemes (device/actor/bitemporal provenance and retrieval metadata)
                    └── semantic-memory shard (retrieval projection only)

Agent Graph: optional planner above the native request boundary.
benchmark: fixtures/conformance matrix only.
Gloss: later read-only inspection client.
```

### Verified starting point

- `recursive-agent` at `045c5fb` has a locally verified native Hermes-handler → daemon → runtime path and portable run-pack export/verification/replay. Its committed change receipt records passing daemon, adapter, pack, workspace, Clippy, format, and diff gates.
- The claim is deliberately local and bounded: no installed Hermes plugin loader, provider/remote run, or production deployment was exercised.
- Mnemes currently owns authenticated device/actor identity, server-stamped operation envelopes, idempotency, bitemporal provenance edges, per-device semantic-memory shards, and routing receipts. Its README explicitly says continuous replication remains under development.
- ClaimLedger currently owns bundle-scoped claim/evidence support semantics and deterministic exports. Its existing `ProvProjectionReceiptV1` is only a projection receipt (`bundle_id`, `output_ref`, digest, timestamps); it is not a Run Pack contract.
- `Libraries/semantic-memory` is dirty. Recursive Agent's admission ledger requires a source-generation recheck immediately before any dependency/admission change. This roadmap does not authorize one.
- Agent Graph plan execution was attempted with the built-in `plan_critique_refine` template after a compatible registered plan graph was not found. The call timed out after 300 seconds, so it supplies **no planning evidence**. This document is based on inspected source and receipts, not that failed run.

## 2. Canonical-owner laws

These laws are acceptance criteria, not aspirations.

| Concern | Canonical owner | Hard prohibition |
|---|---|---|
| Operation permits, execution order, terminality, run/event chain, native receipt, pack export/verify/replay | Recursive Agent | No Hermes, Agent Graph, ClaimLedger, Mnemes, or UI may mint/reinterpret a terminal run result. |
| Pack bytes, manifest digest, retention index | Recursive Agent pack-vault adapter | Mnemes and ClaimLedger retain references/digests only; no alternate artifact blob or mutable "latest run" copy. |
| Claim extraction, evidence bundles, support/contradiction/admission state, testimony | ClaimLedger | No pack verifier, UI, or memory search result may be called claim support. |
| Device/actor identity, server-recorded operation envelope, provenance edges, bitemporal indexing/routing | Mnemes | Mnemes operation receipts never prove that an execution occurred. |
| Semantic facts/documents/vectors/retrieval | semantic-memory | No execution state or claim judgment is recreated in semantic-memory. |
| Graph planning/checkpoints | Agent Graph | No graph receipt becomes an execution receipt; effectful graph nodes submit only native Recursive Agent requests. |
| Benchmark fixtures and matrix results | `benchmark` | Synthetic fixtures are not reliability, security, or performance claims. |

**Identity rule:** `run_id`, `pack_manifest_digest`, every immutable file digest, ClaimLedger bundle ID, Mnemes operation ID, and provenance-edge ID remain distinct typed identities. Never use one as a substitute for another.

**Read-path rule:** before a pack can create a ClaimLedger or Mnemes projection, the server independently runs Recursive Agent's verifier against the exact bytes being admitted. A precomputed client-side `ok` field is inadmissible.

**Retention rule:** a Mnemes/ClaimLedger projection may outlive a local client, but it must become explicitly `pack_unavailable` rather than silently appearing verified if the vault object disappears.

## 3. First product slice: server-owned offline replay

The first real deliverable is intentionally smaller than “distributed agent memory.”

1. A server owned by Josh has a dedicated **pack vault root** and the `ra verify` / `ra replay` binaries available.
2. A known deterministic run pack is admitted into that vault only after server-local verification.
3. The original client run directory is deleted or unavailable.
4. The server runs `ra verify` and recorded replay using the vaulted pack with network/process effects traced or forbidden.
5. The server stores a projection reference in ClaimLedger and Mnemes, each bound to the exact manifest digest and vault object ID.
6. A retrieval result can show the run, pack digest, claim-support state, device/actor, valid/recorded timestamps, and degraded status. It cannot display `verified` merely because a cache entry exists.

This establishes useful offline replay on infrastructure you own before there is any remote execution, continuous replication, or GUI scope.

## 4. Contract set — define before implementation

Do **not** begin with cross-repository path dependencies. Define strict versioned JSON contracts and a fixture corpus first.

### 4.1 `RunPackEvidenceProjectionV1` — owned by Recursive Agent

Create a new strict schema in the Recursive Agent contracts crate. It must describe an already-verified pack, not the execution itself.

Required fields:

```json
{
  "schema": "RunPackEvidenceProjectionV1",
  "projection_id": "deterministic, domain-separated ID",
  "run_id": "native Recursive Agent run identity",
  "pack_manifest_digest": "sha256:<exact PACK_MANIFEST.json bytes>",
  "pack_content_digest": "digest of canonical pack index / listed immutable file digests",
  "verification": {
    "verifier_contract_version": "...",
    "verified_at": "server-recorded RFC3339 timestamp",
    "verification_receipt_digest": "...",
    "outcome": "verified"
  },
  "vault": {
    "object_id": "opaque server vault identity",
    "relative_ref": "non-escaping relative reference only",
    "retention_state": "available"
  },
  "origin": {
    "operator_adapter": "hermes-native",
    "source_device_ref": "opaque device reference, optional",
    "observed_at": "optional RFC3339",
    "recorded_at": "RFC3339"
  },
  "event_summary": {
    "terminal_state": "...",
    "receipt_chain_digest": "...",
    "artifact_digests": ["..."]
  }
}
```

Rules:

- `additionalProperties: false`; all URI/path fields are bounded and relative where applicable.
- Server derives `verification.*`, `vault.*`, and its recorded time. The client cannot submit them as trusted facts.
- The schema contains no raw prompt, secret, credential, provider response, unbounded event body, or executable path.
- `retention_state` is an explicit enum: `available`, `quarantined`, `pack_unavailable`, `tampered`, `superseded`.
- A projection's `verified` outcome means only the exact pack verified under a named verifier contract. It is not security, truth, or operational-success certification.

### 4.2 `RunPackEvidenceBundleV1` — owned by ClaimLedger

Add a ClaimLedger import adapter/schema that accepts `RunPackEvidenceProjectionV1` only after validating the projection schema and checking its detached Recursive Agent verification receipt/digests. It emits a normal ClaimLedger evidence bundle and support judgment; it does not convert a run into a universally true statement.

Minimum semantic mapping:

| Projection field | ClaimLedger representation |
|---|---|
| pack manifest and pack content digest | source/evidence objects with immutable digest metadata |
| native run ID and terminal state | bounded source-span/claim context, not global truth |
| verifier receipt digest | method-specific proof payload/reference |
| vault `available` / degraded state | evidence availability and testimony degradation |
| superseding pack relationship | explicit supersession/admission record |

A new ClaimLedger-specific receipt must contain the source projection digest, generated bundle ID, support state, proof-debt state, and output digest. Do not overload the existing minimal `ProvProjectionReceiptV1`.

### 4.3 `MnemesRunPackObservationV1` — owned by Mnemes adapter boundary

Do not add a second run database. Use Mnemes' existing authenticated operation envelope plus provenance-edge model to record a compact observation:

- operation target: `run_pack_projection/<projection_id>`;
- content digest: exact projection JSON digest;
- operation idempotency key: domain-separated `mnemes-run-pack-import:<pack_manifest_digest>:<projection_schema_version>`;
- provenance edges: pack projection `derived_from` native pack manifest; ClaimLedger bundle/testimony `supports` its bounded claim; later supersession references are explicit;
- Mnemes's accepting server stamps `recorded_at`; requester-supplied time is only `observed_at`/`valid_time` if admitted.

No raw pack payload goes into `pooled.db` or a semantic-memory fact. A retrieval document may summarize the projection but must preserve the manifest digest, native verification receipt reference, ClaimLedger bundle reference, Mnemes operation/edge IDs, and a degradation/availability state.

## 5. Ordered implementation program

Each phase is independently releasable only at its listed boundary. No phase grants the next phase's claims.

### Phase 0 — freeze evidence and admit the change boundary

**Goal:** make cross-project work auditable before code changes.

1. Record exact roots, branches, HEADs, dirty status, and source-generation hashes for `recursive-agent`, `ClaimLedger`, `mnemes`, `Libraries/semantic-memory`, `agent-graph-mcp-release`, and `benchmark`.
2. Re-run Recursive Agent's existing `scripts/verify-hermes-native.sh` and `scripts/verify-run-pack.sh` on the candidate baseline; retain command log and pack fixture digests.
3. Capture ClaimLedger and Mnemes schema/API source witnesses. Recheck the semantic-memory generation fence; do not admit a changed generation merely because it compiles.
4. Write owner map, non-goals, rollback, redaction policy, and allowed-path manifest.

**Gate:** current source identity and baseline pack verification are reproducible.
**Stop:** any dirty source assumed clean, canonical owner conflict, pack validation failure, or unknown secret-bearing artifact.
**Rollback:** delete only this phase's additive plan/fixture metadata; preserve prior receipts.

### Phase 1 — strict projection contract and adversarial fixtures

**Roots:** `recursive-agent` first; fixture mirrors in ClaimLedger and Mnemes only after the schema is frozen.

1. Add `RunPackEvidenceProjectionV1` in `recursive-agent-contracts` with canonical bytes and deterministic material-ID rules.
2. Add a pure projection builder that consumes a locally verified pack result; it must reject an unverified, incomplete, mismatched, path-escaping, or unknown-schema pack.
3. Add fixture corpus:
   - valid deterministic pack projection;
   - manifest digest mismatch;
   - altered artifact/receipt chain;
   - pack copied under a path containing spaces;
   - missing required file;
   - client-forged `verification.outcome=verified`;
   - traversal/symlink vault reference;
   - schema forward-version and unknown-field rejection;
   - redacted/degraded projection.
4. Add conformance tests in all consuming repositories. Fixtures are copied byte-for-byte with a manifest of fixture SHA-256 values; no hand-maintained equivalent JSON.

**Gate:** every consumer accepts the same valid canonical fixture and rejects every negative fixture deterministically.
**Stop:** a consumer needs to infer semantics from UI state, can accept unknown fields, or needs a semantic-memory dependency.
**Rollback:** remove new contract/builder atomically; retain fixtures as quarantined cases only if they expose a defect.

### Phase 2 — server-owned pack vault and offline replay admission

**Root:** `recursive-agent`; do not deploy to a personal server yet.

1. Define `PackVault` as a narrow adapter (`admit`, `get`, `quarantine`, `availability`, `delete is forbidden without explicit retention workflow`). It uses opaque object IDs and relative validated storage paths.
2. Admission flow: copy pack to staging → server-local `verify_run_pack` → create immutable object directory/index → atomically publish → write an admission receipt containing input source digest, verification result, pack manifest digest, object ID, and server-recorded timestamp.
3. On every retrieval/admission, reverify or use a verifier-cache entry that is itself manifest/version-bound and invalidated by file metadata change. Never cache a client verdict.
4. Implement an offline replay command that locates by vault object ID, verifies before replay, and emits a replay receipt. Replay is recorded replay: it must not run tools or call providers.
5. Implement quarantine rather than deletion for verification mismatch, missing file, or content collision.

**Gate:** copy a pack to a fresh vault, delete the original run root, then verify and replay on a clean process under effect tracing. Tampered, colliding, path-escaping, and interrupted admission cases fail closed.
**Stop:** pack admission requires network/provider access, uses absolute client paths as identities, or gives successful replay without pre-verification.
**Rollback:** disable vault admission; retain objects/read-only logs; do not purge evidence automatically.

### Phase 3 — ClaimLedger evidence import and bounded testimony

**Root:** ClaimLedger, with fixture-only dependency on Phase 1's contract.

1. Add an import command/library API that reads only `RunPackEvidenceProjectionV1` and its detached verification receipt.
2. Validate canonical bytes/digests before creating any bundle. Explicitly distinguish `pack_verified`, `pack_unavailable`, `pack_tampered`, and `projection_invalid`.
3. Create a bundle-scoped claim such as “this exact pack passed the named offline verifier at server-recorded time,” not “the agent's conclusion is true.”
4. Require a support judgment with method/payload linking the exact manifest and verification receipt digests. Missing vault availability produces `unknown`/degraded testimony rather than a default support state.
5. Add supersession tests: a newer projection can supersede its prior claim relationship but cannot rewrite original source/bundle bytes.

**Gate:** ClaimLedger tests prove idempotent re-import, tamper rejection, unavailable-pack degradation, and bundle-scoped—not global—testimony.
**Stop:** evidence presence/retrieval is treated as support proof, imported data can silently overwrite a bundle, or support is inferred from a status string.
**Rollback:** remove adapter/import entry point; retain exported rejected diagnostics and original bundles as append-only evidence.

### Phase 4 — Mnemes observation/provenance import

**Root:** Mnemes; integrate through its authenticated HTTP/API surface rather than a new Recursive Agent path dependency.

1. Add an explicit `run_pack_projection` operation kind/target admission policy, or a narrowly validated adapter mapping if operation kinds are intentionally closed.
2. Submit the server-side projection digest via Mnemes' idempotent operation envelope using a domain-separated key.
3. Record provenance edges only after the operation exists and foreign-key checks pass. Preserve source/target type and digest metadata; never put an unverified claim-support edge into the graph.
4. Generate a retrieval projection document that contains references/digests and a clearly rendered availability/degradation state. It is an index/view, not a pack or a ClaimLedger bundle.
5. Add cross-process tests for duplicate submission, idempotency-key conflict, forged actor/device, invalid bitemporal interval, missing referenced pack, tampered projection, and as-of queries across a supersession.

**Gate:** two imports of the same exact projection yield one stable Mnemes operation/edge set; a semantically different projection under the same key is rejected; server-recorded time overrides client time.
**Stop:** Mnemes stores a duplicate pack or run ledger, accepts unauthenticated import, or declares an execution verified.
**Rollback:** disable importer; preserve Mnemes operation/edge receipts and mark any associated retrieval entry degraded rather than deleting provenance.

### Phase 5 — end-to-end witnessed-server conformance harness

**Roots:** a small test-only harness, plus fixture adapters in the three owners. Keep it out of Hermes and Gloss.

1. Build a disposable local server fixture: Recursive Agent vault + ClaimLedger test storage + Mnemes test storage, with explicit temporary roots and no ambient production configuration.
2. Drive the lifecycle from one known native Hermes submission fixture to final retrieval projection.
3. Require independently generated receipts at every boundary: native run/pack, vault admission/replay, ClaimLedger import/testimony, Mnemes operation/edge.
4. Test the disaster case: delete original client run root and shut down the client; restore only server vault + database snapshots; verify/replay and query the provenance chain offline.
5. Run fault injection at copy, verify, ClaimLedger import, Mnemes import, and final indexing boundaries; assert no false success and safe resume/idempotence.

**Gate:** one command produces a machine-readable evidence matrix where all positive and negative cases have exit status, artifact paths, SHA-256 values, and explicit state.
**Stop:** passing requires an external provider, a live user Hermes session, network egress, or mutable shared dev state.
**Rollback:** test data is disposable; production-like vault objects are quarantined only.

### Phase 6 — controlled home-server deployment (approval gate)

This phase requires a separate explicit authorization before host changes, credentials, systemd units, firewall/Tailscale configuration, or data migration.

1. Select a server with sufficient disk, encrypted backup policy, and an offline recovery path. Document owner, data root, retention, threat model, and restore target.
2. Deploy pack vault and Mnemes as distinct least-privilege services. Keep Mnemes loopback-bound initially; any tailnet exposure is explicit and audited.
3. Store credentials outside receipts, fixtures, logs, and pack material. Use separate service identities and file permissions for vault, ClaimLedger, and Mnemes.
4. Install health, integrity, backup-restore, capacity, and retention checks. Backups include vault objects plus their index and database state; restoring one without the others must surface degraded references.
5. Perform a clean-host acceptance: create one deterministic pack on a client, admit it, delete client data, restore the server snapshot into a fresh root, and verify/replay offline.

**Gate:** clean-host restore evidence, least-privilege service review, no secret leakage in receipts, and documented rollback/disable path.
**Stop:** public listener, auto-updater, remote executor, or credential-sharing requirement appears without separate scope approval.
**Rollback:** stop services, revoke credentials, retain encrypted snapshots and vault evidence subject to retention policy.

### Phase 7 — controlled orchestration and operator hardening

Only after Phase 6 is proven.

1. Permit Agent Graph to choose/sequence requests only through a narrow Hermes/native adapter that returns native run IDs and pack references.
2. Graph receipt correlation is metadata only; it cannot authorize effects, change permits, or replace native run closure.
3. Add operator dashboards/CLI queries that render the status ladder: `native_verified`, `vault_available`, `claim_supported|unknown|degraded`, `mnemes_observed`, `replay_verified`. Never collapse them into one green check.
4. Add rate/size quotas, concurrency caps, queue backpressure, permit expiry, retention controls, audit export, and deterministic recovery drills.

**Gate:** graph cancellation/retry/duplicate submit leaves exactly one native idempotent execution and does not create a shadow execution result.
**Stop:** a graph retry can produce an unbounded effect, or status UI hides a missing pack/claim evidence condition.
**Rollback:** remove orchestration adapter binding; native vault/replay remains usable.

### Phase 8 — deferred surfaces, only after core proof

- **Gloss:** read-only inspector of a server-verified pack/projection. It must ask Recursive Agent to verify before presenting pack content and render a degraded state when unavailable. No executor, no ledger.
- **semantic-memory direct integration:** only after a new source-generation admission. Prefer Mnemes's existing control-plane/shard ownership; do not add a Recursive Agent shadow memory database.
- **Replication:** only after Mnemes's documented continuous-replication work becomes locally source-verified. Start by replicating vault/index metadata with explicit content-addressed pack transfer and independent verification, never by trusting a remote “sync succeeded.”
- **Providers/remote workers:** separate security/authority design. Recorded outputs may be retained for replay; provider replay is not re-execution.

## 6. Test and evidence matrix

| Case | Native RA | Vault | ClaimLedger | Mnemes | Required result |
|---|---:|---:|---:|---:|---|
| Valid deterministic pack | verify/replay | admit/get | bounded supported/known method | one idempotent observation | full chain references exact same manifest digest |
| Original client deleted | replay fails locally by absence | replay succeeds server-local | reference remains valid | provenance remains queryable | server proves offline survivability |
| Manifest/artifact tamper | fails | quarantine/no admission | no bundle or degraded rejected import | no verified edge | fail closed |
| Duplicate exact import | no duplicate run | stable object ID | stable/duplicate-safe bundle rule | stable op/edge IDs | idempotent |
| Same idempotency key, different bytes | n/a | collision rejection | conflict rejection | conflict rejection | no overwrite |
| Missing vaulted pack | n/a | `pack_unavailable` | unknown/degraded testimony | degraded retrieval view | never green/verified |
| Invalid device/actor | n/a | n/a | n/a | authorization rejection | no observation |
| Superseding pack | immutable prior pack | immutable old + new relation | explicit supersession | explicit supersedes edge | as-of query differs correctly |
| Interrupted boundary | no false terminal claim | staging never published | no half bundle | no dangling edge | recoverable/retry-safe |
| Offline clean-host restore | verify/replay | restored vault | restored bundle evidence | restored metadata | no network/process/provider effect |

Every row must retain: input fixture digest, command line, exit code, stdout/stderr log path, produced artifact digests, exact repository identity, timestamp source, and a named owner.

## 7. Operational and claim boundaries

### Supported after Phase 5

> A deterministic Recursive Agent run can be verified and recorded-replayed offline from a server-owned portable pack; its exact evidence can be represented in a bundle-scoped ClaimLedger judgment and a Mnemes provenance observation, with explicit degradation when the pack is unavailable or tampered.

### Not supported without separate proof

- external correctness of an agent's content;
- general security, multi-tenancy, compliance, availability, or disaster resilience;
- provider-backed deterministic re-execution;
- remote worker trust, device-to-device replication, or public service operation;
- Hermes GUI/plugin-loader behavior;
- any benchmark superiority or performance figure.

## 8. Delivery sequencing and commits

Keep commits owner-scoped and reversible. Suggested sequence:

1. `test(contracts): add run-pack projection conformance fixtures`
2. `feat(ledger): export strict verified-pack projection`
3. `feat(vault): admit and replay verified portable packs offline`
4. `feat(claim-ledger): import witnessed run-pack evidence bundles`
5. `feat(mnemes): record witnessed run-pack observations`
6. `test(workbench): add offline server conformance matrix`
7. `docs(operations): add witnessed workbench recovery runbook`

Do not mix generated run directories, unrelated phase receipts, dirty semantic-memory changes, or Agent Graph working-state changes into these commits. Every phase gets its own precheck, validation log, machine-readable change receipt, hostile review, and rollback note.

## 9. First admissible implementation gate

Start with **Phase 0 plus Phase 1 only**. The immediate first patch should be a failing `RunPackEvidenceProjectionV1` conformance test and a frozen valid/invalid fixture corpus in Recursive Agent. It is cheap, fully local, and can falsify the core integration assumption before a server, a deployment, cross-repo dependency churn, or any UI work.

The next decision point is not “does this look badass?” It is: **can all three owners accept the same exact positive fixture and reject the same forged/tampered fixtures without inventing a second owner of execution or evidence?**
