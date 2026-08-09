# Recursive Agent: Total Remediation and Native-Kernel Implementation Plan

> **Status:** Proposed implementation authority; no implementation authorized by this document alone<br>
> **Planning snapshot:** 2026-08-04T22:18:35-05:00<br>
> **Repository:** `/home/sikmindz/Coding/recursive-agent`<br>
> **Baseline:** `main` at `3805f7abf319e07e47f1c20b862e614c3dad164f`; dirty working tree; 13 workspace crates<br>
> **Supersedes for execution:** `.hermes/plans/2026-08-04-phases-4-5-6-plan.md`<br>
> **Architecture authority:** `.hermes/plans/2026-08-04-recursive-agent-native-integration-architecture.md`<br>
> **Governing instructions:** `AGENTS.md`

## 0. Purpose and verdict

The current Phase 4–6 work is useful prototype material, not an acceptance-ready system. The repair is not “finish the adapters.” The repair is to establish one protocol-independent native execution and evidence kernel, prove it through a no-MCP Hermes vertical slice, and only then migrate every adapter and higher-level subsystem to that owner.

This plan fixes every controller-verified and auditor-converged blocker:

- random or wall-clock-derived material identities;
- success finalization after failed steps;
- non-durable, reusable permits;
- ledger crash windows and incomplete artifact verification;
- false sandbox-attestation claims;
- raw provider-secret serialization;
- unsafe daemon socket ownership, missing peer authentication, unbounded framing, and unused concurrency limits;
- MCP and tool paths that bypass policy, sandbox, runtime lifecycle, or canonical receipts;
- unmanaged recursive delegation;
- unscoped and unprovenanced memory;
- unvalidated and unprovenanced skills;
- random one-step “MCTS” masquerading as search;
- incomplete cancellation, recovery, replay, fuzz, supply-chain, observability, UI, and anchoring work;
- documentation claims that outrun measured capability.

The first product proof is deliberately narrow:

> A standalone Hermes plugin invokes one bounded subprocess action over authenticated native Unix IPC. The Rust runtime authorizes it, truthfully enforces or rejects sandboxing, executes it, emits monotonic typed events, durably records terminal state, re-reads the record, verifies all referenced artifact bytes, and returns a causal receipt. MCP is absent from the path.

## 1. Non-negotiable invariants

1. `recursive-agent-runner` is the sole execution and lifecycle owner. It exposes the canonical `RuntimeService`; adapters translate only.
2. `recursive-agent-ledger` is the sole receipt-chain and evidence-verification owner. `chain.meta` is a rebuildable projection, never an independent authority.
3. `recursive-agent-policy` is the sole policy-decision, capability-lease, attenuation, issue, consume, expiry, and revocation owner.
4. `recursive-agent-sandbox` is the sole enforcement and observed-effect attestation owner.
5. `recursive-agent-tools` owns schemas, registry lookup, and executor implementations, but cannot authorize itself, choose run identity, or mint authoritative receipts.
6. Material IDs come from the admitted `stack-ids` API. No UUID v4, timestamps, counters, or adapter-generated random IDs are material identities.
7. Every durable boundary uses the admitted JCS/canonicalization owner. No ad hoc `serde_json::to_vec` is treated as canonical evidence.
8. Every effect is policy-authorized before dispatch, executed through the runtime, and closed by terminal evidence.
9. A child receives a strict subset of the parent’s authority and remaining budgets. Copying a parent grant is forbidden.
10. Memory is scoped evidence with citations, trust, time validity, and source receipts—not ambient truth.
11. Skills are versioned evidence artifacts with quarantine, validation, promotion, and revocation—not executable text files.
12. Replay claims are classified as deterministic replay, recorded-evidence replay, or unavailable. External state is never silently re-fetched during replay.
13. An adapter cannot execute effects directly, mutate authoritative state directly, or mint authoritative receipts.
14. Runtime failures are typed and terminal. `Failed` and `Cancelled` can never transition to successful finalization.
15. No fallback silently widens authority, disables sandboxing, switches stores, or bypasses the runtime.
16. Credentials never enter serializable config, events, receipts, logs, memory, or model prompts.
17. Tests, receipts, source snapshots, and exact commands outrank plans and prose.

## 2. Evidence baseline and planning limits

### 2.1 Observed baseline

At the planning snapshot:

- `cargo fmt --all -- --check` exited 0.
- Workspace tests and strict all-target Clippy exited 0 in the current audit session; the hostile audit counted 47 unit tests. These are smoke evidence only.
- `cargo deny check` exited 1; the present `deny.toml` is not accepted by the installed tool.
- `cargo fuzz --version` exited 101; an operational fuzz toolchain/package has not been demonstrated.
- The worktree had 15 dirty entries, including uncommitted Phase 4–6 crates and planning artifacts.
- No commit or push was verified.

### 2.2 Planning orchestration evidence

Agent Graph run `run-19fcff12c95-1`, graph version `sha256:f875299b4ca4a974e252e58ac6118d4d9b789b8a3305d6c1d4c2b62c2eebbaf0`, attempted a Luna planner/critic/refiner pass. The planner timed out after approximately 120 seconds. The durable terminal receipt records one attempted LLM call, no successful step output, `evidence_authority=structural_unverified`, and `terminal_output.provenance=legacy_input_fallback`. Therefore this plan admits no graph-generated recommendation. It is controller-authored from live source plus the three completed read-only audits.

### 2.3 Scope limits

This plan does not authorize:

- commits, pushes, releases, deployment, service changes, or installation into active Hermes profiles;
- credential access or migration;
- modifications to `/home/sikmindz/.hermes/hermes-agent`;
- retroactive claims that old receipts prove semantics they did not record;
- adoption of any external library before its exact API, version, invariants, and compatibility are admitted in Phase 0.

## 3. Canonical owner map

| Concern | Canonical owner | Allowed consumers | Forbidden duplication |
|---|---|---|---|
| Material IDs | `stack-ids` after admission | contracts, runner, ledger, adapters | UUID/timestamp IDs in adapters or stores |
| Canonical bytes | `boundary-compiler` after admission | contracts, ledger, IPC, exports | local canonicalization variants |
| Operation/event schemas | `recursive-agent-contracts` | all crates and adapters | MCP/CLI-specific internal request models |
| Policy and leases | `recursive-agent-policy` | runner, delegation, remote admission | adapter-local allow/deny logic |
| Sandbox enforcement | `recursive-agent-sandbox` | runner only | adapters reporting sandbox status |
| Tool schema/execution implementation | `recursive-agent-tools` | runner | direct adapter dispatch |
| Run lifecycle/scheduler/cancellation | `recursive-agent-runner` | embedded API, daemon, adapters | daemon-owned or adapter-owned lifecycle |
| Receipt chain/verification | `recursive-agent-ledger` | runner, CLI verifier, exports | adapter-minted receipts |
| Provider invocation | `recursive-agent-provider` | runner | provider calls from adapters |
| Memory evidence | `recursive-agent-memory` | runner-mediated reads/writes | implicit process-local stores |
| Skill artifacts | `recursive-agent-skills` | runner-mediated expansion/promotion | raw template execution |
| Branch search | renamed evidence-search crate | runner | search-node direct effects |
| Unix IPC | `recursive-agent-daemon` | Hermes/CLI/remote local adapters | IPC semantics becoming runtime semantics |
| MCP translation | `recursive-agent-mcp` | MCP clients only | MCP as scheduler/capability/receipt owner |
| Hermes tool exposure | standalone `integrations/hermes-native` plugin | Hermes plugin loader | Hermes core modification or MCP detour |

## 4. Target contract shape

The exact imported ID and canonicalization types are locked in Task 0.3. The behavioral shape below is normative; do not invent substitute local owners if imported names differ.

```rust
pub struct OperationEnvelopeV1 {
    pub schema: SchemaVersion,
    pub run_id: RunId,
    pub step_id: StepId,
    pub branch_id: Option<BranchId>,
    pub actor: ActorIdentity,
    pub delegated_authority: CapabilityLease,
    pub budgets: BudgetEnvelope,
    pub causality: CausalParents,
    pub action: ToolInvocation,
    pub declared_effects: EffectSet,
    pub provenance: ProvenanceEnvelope,
    pub replay: ReplayDeclaration,
}

pub enum RuntimeEventKindV1 {
    Submitted,
    Authorized { decision: PolicyDecisionRef },
    SandboxPrepared { enforcement: EnforcementOutcome },
    Started,
    OutputChunk { stream: OutputStream, artifact: ArtifactRef },
    ChildLinked { child_run: RunId },
    CancelRequested,
    Cancelled,
    Failed { failure: FailureEnvelope },
    Completed { receipt: ReceiptRef },
}

pub struct RuntimeEventV1 {
    pub run_id: RunId,
    pub sequence: u64,
    pub causal_parent: Option<EventId>,
    pub kind: RuntimeEventKindV1,
    pub evidence_receipt: ReceiptRef,
}

#[async_trait]
pub trait RuntimeService: Send + Sync {
    async fn submit(&self, op: OperationEnvelopeV1) -> Result<RunHandle, RuntimeError>;
    async fn events(&self, run: &RunId, after: Option<u64>) -> Result<EventStream, RuntimeError>;
    async fn status(&self, run: &RunId) -> Result<RunSnapshot, RuntimeError>;
    async fn cancel(&self, run: &RunId, actor: ActorIdentity) -> Result<CancelReceipt, RuntimeError>;
    async fn verify(&self, run: &RunId, mode: VerifyMode) -> Result<VerificationReport, RuntimeError>;
}

pub enum EnforcementOutcome {
    Enforced { mechanism: SandboxMechanism, policy_digest: Digest },
    Degraded { reason: TypedReason },
    Unavailable { reason: TypedReason },
}
```

An effectful operation proceeds only on `Enforced`. `Degraded` and `Unavailable` are visible terminal policy failures unless an explicit policy class admits a non-effectful operation.

## 5. Execution protocol for every task

Every mutating task below follows this sequence:

1. Re-read the named files and their current diff. Do not implement from this plan alone if source changed.
2. Add the named RED test and run only its focused command.
3. Capture the expected failing exit code and failure reason under `docs/receipts/<phase>/<task>/red.txt`.
4. Implement the minimum behavior needed for that test.
5. Run the focused GREEN command, then the phase gate.
6. Capture commands, exit codes, toolchain versions, source commit, dirty diff hash, and outputs under the same receipt directory.
7. Revert the task if the rollback trigger occurs. Do not add a compatibility bypass.
8. Update claims only to the narrow claim listed on the card.

Do not parallelize tasks that modify `recursive-agent-contracts`, `recursive-agent-runner`, `recursive-agent-ledger`, or the workspace lockfile. Parallel work is allowed only for read-only audits or disjoint adapter tests after the relevant contract phase is frozen.

---

# Phase 0 — Freeze truth, admit dependencies, and quarantine overclaims

## Task 0.1 — Create the implementation baseline packet

- **Owner/files:** repository controller; create `docs/receipts/phase-0/baseline/manifest.json`; do not alter source.
- **RED:** verification script fails if branch, HEAD, dirty paths, tool versions, or all baseline gate results are absent.
- **GREEN:** record `git status --porcelain=v1`, `git diff --binary`, `cargo metadata --no-deps`, Rust/Cargo versions, and direct gate outputs.
- **Gate:** `cargo fmt --all -- --check`; `cargo test --workspace --all-targets`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo deny check`; `cargo fuzz --version`.
- **Evidence:** exact exits; preserve failures rather than normalizing them.
- **Migration:** none.
- **Rollback:** delete only the incomplete receipt directory.
- **Claim:** “The pre-remediation source and gate state are reproducibly inventoried.”

## Task 0.2 — Fence inaccurate capability claims

- **Owner/files:** documentation authority; `README.md`; `.hermes/plans/2026-08-04-phases-4-5-6-plan.md`; create `docs/capability-status.md`.
- **RED:** a documentation test searches for unqualified claims of complete BM25, MCTS, daemon safety, fuzzing, anchoring, or Phase 4–6 completion and fails.
- **GREEN:** label each as prototype, blocked, planned, or verified with evidence links; mark the older plan superseded for execution without deleting it.
- **Gate:** `cargo test --workspace --all-targets` plus documentation-claim test.
- **Evidence:** before/after claim matrix.
- **Migration:** preserve historical wording in git, not active docs.
- **Rollback:** revert documentation only if a corrected claim cannot cite evidence.
- **Claim:** “Public/internal capability language matches observed evidence.”

## Task 0.3 — Admit canonical external owners before adding dependencies

- **Owner/files:** architecture controller; create `docs/adr/0002-canonical-owner-admission.md`; inspect root `Cargo.toml` and current source of `stack-ids`, `boundary-compiler`, `bitemporal-runtime`, `claim-ledger`, `authority-delegation`, `llm-tool-runtime`, `assurance-runtime`, and `remote-oracle-admission` under `/home/sikmindz/Coding/Libraries`.
- **RED:** an owner-matrix test fails if any required concern lacks exactly one admitted owner, version/commit, supported API, invariant test, and rejection reason for alternatives.
- **GREEN:** admit only APIs that compile and whose tests demonstrate the needed invariant; otherwise keep the local crate owner and record the gap.
- **Gate:** targeted tests in each admitted dependency plus `cargo tree -d` after any workspace dependency edit.
- **Evidence:** dependency commit IDs, dirty status, API symbols, test outputs, license findings.
- **Migration:** do not add path dependencies that make the project non-portable without documenting the release strategy.
- **Rollback:** remove an admitted dependency if its invariant is not test-backed or it creates duplicate truth.
- **Claim:** “Canonical owners are selected from current source, not memory or naming.”

### Phase 0 gate

No implementation phase starts until Tasks 0.1–0.3 pass and the dirty tree is backed up as a patch or worktree snapshot. Failure of `cargo deny` and fuzz remains admitted, not waived.

---

# Phase 1 — P0 correctness and security containment

## Task 1.1 — Replace material UUID/timestamp identities

- **Owner/files:** `recursive-agent-contracts/src/lib.rs`, `recursive-agent-runner/src/lib.rs`, `recursive-agent-policy/src/lib.rs`, `recursive-agent-ledger/src/lib.rs`, affected tests.
- **RED:** tests reject UUID v4 and wall-clock-derived run, step, permit, receipt, memory, and branch IDs; identical canonical material produces the same ID; different domain tags do not collide.
- **GREEN:** use the Task 0.3-admitted `stack-ids` constructors and strict family parsing at all material boundaries.
- **Gate:** `cargo test -p recursive-agent-contracts -p recursive-agent-runner -p recursive-agent-ledger -p recursive-agent-policy`.
- **Evidence:** fixed vectors and cross-crate conformance output.
- **Migration:** old IDs remain parseable only through an explicit `LegacyV1` reader and are never re-minted as current IDs.
- **Rollback:** revert if canonical vectors differ across processes or platforms.
- **Claim:** “Current material identities are deterministic, domain-separated, and validated.”

## Task 1.2 — Enforce a typed terminal-state machine

- **Owner/files:** `recursive-agent-contracts/src/lib.rs`, `recursive-agent-runner/src/lib.rs`; add `recursive-agent-runner/tests/lifecycle_state_machine.rs`.
- **RED:** failed step followed by successful finalization must fail; cancelled/failed/completed states reject every illegal transition; exactly one terminal state is admitted.
- **GREEN:** centralize transition validation in the runner; remove unconditional `RunFinalized { Ok }` behavior.
- **Gate:** focused lifecycle test plus runner package tests.
- **Evidence:** transition table and test output.
- **Migration:** map old ambiguous terminal receipts to `LegacyUnknown`, not `Completed`.
- **Rollback:** revert if any adapter must bypass the transition API to compile.
- **Claim:** “A failed or cancelled run cannot be finalized as successful.”

## Task 1.3 — Implement durable capability-lease issue/consume/revoke

- **Owner/files:** `recursive-agent-policy/src/lib.rs`; `recursive-agent-runner/src/lib.rs`; add `recursive-agent-policy/tests/permit_lifecycle.rs`.
- **RED:** reused, expired, revoked, wrong-actor, wrong-action, over-budget, and wrong-parent leases all fail with typed reasons.
- **GREEN:** persist issue and consume records through the canonical policy owner; consume atomically before effect dispatch; bind actor, action digest, budget, policy version, parent, and expiry.
- **Gate:** policy tests plus a runner double-dispatch race test.
- **Evidence:** issue/consume/rejection receipt chain.
- **Migration:** derived string permits are legacy-only and fail closed for effectful current requests.
- **Rollback:** revert if consumption is not atomic under concurrent dispatch.
- **Claim:** “Effect authorization is single-use, actor-bound, scoped, and durable.”

## Task 1.4 — Make receipt append crash-recoverable

- **Owner/files:** `recursive-agent-ledger/src/lib.rs`; add `recursive-agent-ledger/tests/crash_recovery.rs`.
- **RED:** injected crashes after artifact write, receipt append, file sync, metadata-temp write, and metadata rename must recover to either the previous valid chain or the new valid chain—never a falsely valid mixed state.
- **GREEN:** make receipt NDJSON the append-only source; fsync it; update `chain.meta` through same-directory temp, fsync, atomic rename, and directory fsync; rebuild metadata from receipts on recovery.
- **Gate:** ledger unit tests plus fault-injection matrix.
- **Evidence:** per-failpoint recovered digest and verifier result.
- **Migration:** preserve current line format if valid; regenerate metadata as a projection.
- **Rollback:** revert if recovery needs deletion of valid receipts.
- **Claim:** “Receipt-chain metadata is recoverable after tested crash points.”

## Task 1.5 — Verify all referenced artifact bytes

- **Owner/files:** `recursive-agent-ledger/src/lib.rs`; add `recursive-agent-ledger/tests/artifact_tamper.rs`.
- **RED:** missing, truncated, replaced, symlink-swapped, and digest-mismatched output artifacts fail strict verification.
- **GREEN:** resolve artifacts beneath the run root without symlink escape, stream-hash bytes, compare digest/length/media type, and include results in `VerificationReport`.
- **Gate:** ledger strict-verification tests.
- **Evidence:** tamper fixture matrix.
- **Migration:** old receipts without artifact metadata verify only in explicit `LegacyIntegrityOnly` mode.
- **Rollback:** revert if verifier follows paths outside the run root.
- **Claim:** “Strict verification covers the receipt chain and every referenced local artifact byte.”

## Task 1.6 — Make sandbox evidence truthful and fail closed

- **Owner/files:** `recursive-agent-sandbox/src/lib.rs`, `recursive-agent-runner/src/lib.rs`; add `recursive-agent-sandbox/tests/enforcement_truth.rs`.
- **RED:** simulate unavailable/failed Landlock and prove the result is never `Enforced` or `sandboxed=true`; effectful execution must not start.
- **GREEN:** replace ambiguous booleans with `EnforcementOutcome`; record mechanism, policy digest, setup errors, and observed effects; runner authorizes dispatch only on an admitted outcome.
- **Gate:** sandbox tests plus runner no-dispatch test.
- **Evidence:** negative-path receipts and process-spawn counter remaining zero.
- **Migration:** remove or deprecate boolean status fields; V1 readers map them to unverified legacy state.
- **Rollback:** revert if any setup error can produce effect execution.
- **Claim:** “Sandbox claims distinguish enforced, degraded, and unavailable states and effectful work fails closed.”

## Task 1.7 — Remove credentials from serializable provider state

- **Owner/files:** `recursive-agent-provider/src/lib.rs`; provider config tests.
- **RED:** serialize/debug/error/event paths containing a sentinel API key must never emit the sentinel.
- **GREEN:** separate provider identity/config from credential handles; use non-serializable secret wrappers; resolve credentials at invocation boundary; redact errors.
- **Gate:** provider tests and repository sentinel scan.
- **Evidence:** serialized fixtures and scan output.
- **Migration:** refuse raw-key config deserialization with an actionable migration error.
- **Rollback:** revert if provider invocation requires copying secrets into receipt-bearing structures.
- **Claim:** “Provider credentials do not enter serializable runtime evidence.”

### Phase 1 gate

All focused tests pass; the workspace test/Clippy/format gates remain green; failure injection passes; no adapter or provider can execute an effect if identity, lease, lifecycle, ledger, artifact, or sandbox validation fails.

---

# Phase 2 — Canonical native contracts and runtime owner

## Task 2.1 — Add versioned operation, authority, causality, budget, effect, provenance, and replay envelopes

- **Owner/files:** split `recursive-agent-contracts/src/lib.rs` only after tests pass into `operation.rs`, `authority.rs`, `causality.rs`, `budget.rs`, `effects.rs`, `provenance.rs`, `replay.rs`, and `event.rs`.
- **RED:** JSON round-trip, unknown-version, missing-field, canonical-byte, invalid-parent, invalid-budget, and effect-underdeclaration tests fail on current contracts.
- **GREEN:** implement `OperationEnvelopeV1` and strict validation; preserve unknown fields only where the version contract explicitly permits them.
- **Gate:** `cargo test -p recursive-agent-contracts` and canonical fixed-vector tests.
- **Evidence:** schemas, vectors, and schema digest.
- **Migration:** adapters translate their legacy inputs into V1 at the boundary; they do not become V1 owners.
- **Rollback:** revert contract split if behavior changes beyond reviewed schema deltas.
- **Claim:** “Native V1 contracts carry the minimum complete execution/evidence context.”

## Task 2.2 — Define monotonic typed runtime events as ledger-backed evidence

- **Owner/files:** contracts event module; ledger append/stream APIs; runner tests.
- **RED:** duplicate, missing, reordered, wrong-parent, post-terminal, and receipt-less event sequences fail.
- **GREEN:** append each accepted state transition as a ledger-backed event with sequence, causal parent, and evidence receipt; stream only committed events.
- **Gate:** event conformance and concurrent-reader tests.
- **Evidence:** deterministic event transcript and chain verification.
- **Migration:** no separate authoritative event store; any scheduler event table is an indexed projection rebuildable from ledger evidence.
- **Rollback:** revert if streamed events can precede durable commit.
- **Claim:** “Clients stream committed, monotonic, causally linked runtime events.”

## Task 2.3 — Establish `RuntimeService` in `recursive-agent-runner`

- **Owner/files:** `recursive-agent-runner/src/lib.rs`; add `runtime.rs`, `deps.rs`, `error.rs`; runner integration tests.
- **RED:** a compile-time/behavioral test proves adapters cannot construct execution internals or mint terminal receipts; submission without required dependencies fails.
- **GREEN:** expose submit/events/status/cancel/verify; inject policy, sandbox, tool registry, provider, ledger, clock, and store through explicit dependencies.
- **Gate:** runner tests with deterministic fake clock/provider/tool and real ledger temp directory.
- **Evidence:** one embedded run transcript.
- **Migration:** retain old runner calls only as deprecated thin wrappers that immediately construct V1 and call `RuntimeService`; remove them in Phase 6.
- **Rollback:** revert if dependency injection allows a test-only bypass in production builds.
- **Claim:** “One native service owns operation lifecycle and terminal evidence.”

## Task 2.4 — Reduce tools to schemas, registry, and executor implementations

- **Owner/files:** `recursive-agent-tools/src/lib.rs`; runner integration tests; MCP/CLI compile fixes only.
- **RED:** direct calls to effectful tool executors without `AuthorizedExecutionContext` fail to compile or return typed denial; registry cannot mint receipts.
- **GREEN:** require runner-created execution context; remove implicit stores and wall clocks; return observations/artifacts only.
- **Gate:** tool package tests and a source-level denylist for direct `execute` use outside runner/tests.
- **Evidence:** call-graph inventory before/after.
- **Migration:** adapters compile against runtime APIs; no temporary direct-dispatch fallback.
- **Rollback:** revert if a tool must infer actor, policy, sandbox, or receipt identity.
- **Claim:** “Tool implementations cannot authorize themselves or become receipt owners.”

## Task 2.5 — Prove the embedded native vertical core

- **Owner/files:** add `recursive-agent-runner/tests/native_vertical.rs` and fixtures.
- **RED:** current system cannot complete authenticate/authorize/sandbox/execute/stream/persist/readback/verify in one test.
- **GREEN:** execute a fixed `/usr/bin/printf` argv through real policy, sandbox, tool executor, ledger, artifact store, event stream, and strict verifier in a temporary run root.
- **Gate:** focused test repeated under `--test-threads=1` and default parallel mode.
- **Evidence:** run directory, event transcript, receipt chain, artifact hash, verifier report.
- **Migration:** fixed action is an acceptance fixture, not a general shell bypass.
- **Rollback:** revert if test uses mocks for policy, sandbox result, ledger, or artifact bytes.
- **Claim:** “The embedded native runtime completes and verifies one bounded local action.”

### Phase 2 gate

The embedded proof passes without CLI, daemon, Hermes, Agent Graph, or MCP. A static call-path audit finds no effectful path outside `RuntimeService`.

---

# Phase 3 — Safe native IPC and daemon

## Task 3.1 — Define bounded versioned IPC framing

- **Owner/files:** `recursive-agent-daemon/src/lib.rs`; create `protocol.rs`; add `tests/framing.rs`.
- **RED:** partial, oversized, truncated, duplicate-ID, unknown-version, and trailing-frame inputs fail without allocation spikes or hangs.
- **GREEN:** use length-prefixed canonical envelopes with a hard configured maximum; correlate request/response/event IDs; explicit protocol version negotiation.
- **Gate:** daemon framing tests plus fuzz target added in Phase 11.
- **Evidence:** valid/invalid wire fixtures and schema digest.
- **Migration:** reject old unframed protocol with a typed upgrade error; no autodetection.
- **Rollback:** revert if the decoder allocates from untrusted length before limit validation.
- **Claim:** “Unix IPC framing is bounded, versioned, and request-correlated.”

## Task 3.2 — Fix socket ownership, peer identity, and single-instance safety

- **Owner/files:** daemon socket setup and tests `socket_safety.rs`.
- **RED:** symlink socket, non-socket existing path, foreign-owned parent, world-writable unsafe parent, second daemon, and mismatched peer UID are rejected without unlinking data.
- **GREEN:** create an owned private runtime directory, validate type/owner/mode, bind atomically, set `0600`, obtain `SO_PEERCRED`, and derive the local peer principal server-side.
- **Gate:** daemon tests under temporary directories and same-UID/mismatched-credential fixtures where supported.
- **Evidence:** filesystem metadata and peer-auth decisions.
- **Migration:** require explicit operator migration from arbitrary socket paths.
- **Rollback:** revert if startup can unlink a non-socket or foreign-owned node.
- **Claim:** “The daemon binds only a validated private socket and authenticates local peers.”

## Task 3.3 — Enforce concurrency, backpressure, streaming, and cancellation

- **Owner/files:** daemon server loop; runner cancellation API; `tests/ipc_runtime.rs`.
- **RED:** `max_concurrent_runs=1` must prevent a second dispatch; slow readers cannot cause unbounded buffering; disconnect/cancel has a deterministic result.
- **GREEN:** semaphore before runtime submit, bounded per-client queues, committed event frames, cancellation request/ack, and graceful connection teardown.
- **Gate:** concurrency, backpressure, cancel, and disconnect tests.
- **Evidence:** peak queue depth, dispatch counters, terminal states.
- **Migration:** no background detached execution unless request explicitly selects durable-detach semantics.
- **Rollback:** revert if dropping a connection silently changes authority or terminal state.
- **Claim:** “IPC respects configured concurrency and streams durable events with explicit cancellation semantics.”

### Phase 3 gate

A fresh daemon serves the Phase 2 action over authenticated native IPC, survives malformed clients, and returns the same strict verification result as embedded mode.

---

# Phase 4 — No-MCP Hermes vertical slice

Hermes remains unmodified. The integration is a standalone plugin shipped from this repository and installed into `~/.hermes/plugins/` only after separate user approval. Current Hermes source confirms the supported edge: `plugin.yaml`, `register(ctx)`, and `ctx.register_tool(name, toolset, schema, handler, check_fn, ...)`.

## Task 4.1 — Build a standalone, service-gated Hermes plugin

- **Owner/files:** create `integrations/hermes-native/plugin.yaml`, `integrations/hermes-native/__init__.py`, `client.py`, `schema.py`, and `tests/test_registration.py`.
- **RED:** plugin loader test proves no tool is callable when socket identity/protocol checks fail; malformed runtime responses are rejected.
- **GREEN:** register one non-overriding tool `recursive_agent_execute` in toolset `recursive_agent`; `check_fn` verifies private socket reachability/version; handler submits the fixed bounded acceptance action and returns terminal status plus receipt reference.
- **Gate:** Python tests in an isolated venv or Hermes project environment with temporary `HERMES_HOME`.
- **Evidence:** plugin manifest validation, registry record, unavailable/available checks.
- **Migration:** external standalone plugin only; no Hermes core edits, no MCP, no env-var behavioral config.
- **Rollback:** remove the isolated plugin directory; active profile remains untouched.
- **Claim:** “A standalone Hermes plugin translates one tool call to native recursive-agent IPC.”

## Task 4.2 — Prove the real Hermes dispatch path end to end

- **Owner/files:** `integrations/hermes-native/tests/test_e2e.py`; daemon and runner fixtures; create `scripts/verify-hermes-native.sh` only if a script is needed.
- **RED:** invoke the plugin through Hermes’s real plugin loader/tool registry against a real temporary daemon; current prototype cannot produce a verified run.
- **GREEN:** assert actor/session binding, lease decision, enforced sandbox outcome, subprocess output, monotonic events, persisted terminal state, readback, artifact hash, and strict receipt verification.
- **Gate:** run the same handler path used by Hermes; no direct call to the Rust runner from the test.
- **Evidence:** Hermes registry record, IPC transcript digests, run evidence bundle, verifier output.
- **Migration:** the model need not choose the tool for the deterministic acceptance test; a separate manual chat smoke is observational only.
- **Rollback:** revert plugin/IPC changes if any evidence field is synthesized by Python rather than returned from the runtime.
- **Claim:** “One real Hermes plugin tool action traverses the no-MCP native kernel and returns verifiable evidence.”

## Task 4.3 — Package—but do not auto-install—the Hermes integration

- **Owner/files:** plugin README, `integrations/hermes-native/pyproject.toml` if needed, `scripts/install-hermes-plugin.sh`, `scripts/uninstall-hermes-plugin.sh`.
- **RED:** install into a temporary `HERMES_HOME`; manifest discovery, enable/disable, and uninstall tests fail before packaging.
- **GREEN:** deterministic copy/install with file manifest and rollback; config through `config.yaml`, not new non-secret env vars.
- **Gate:** temporary-home install/uninstall round trip.
- **Evidence:** file manifest and before/after tree.
- **Migration:** active installation is a separately approved deployment action.
- **Rollback:** uninstall by manifest; never edit Hermes core.
- **Claim:** “The Hermes plugin is reproducibly packageable and removable in an isolated home.”

### Phase 4 gate

The no-MCP Hermes E2E test is green and strict verification independently succeeds. This is the first point where “Hermes native integration” may be claimed, limited to the tested action and environment.

---

# Phase 5 — Durable scheduling, cancellation, recovery, and honest replay

## Task 5.1 — Add a durable scheduler store as a rebuildable control projection

- **Owner/files:** runner `scheduler.rs`, `store.rs`, `recovery.rs`; `tests/restart_recovery.rs`.
- **RED:** kill/restart during submitted, authorized, running, and terminal states; current system loses or ambiguously duplicates work.
- **GREEN:** persist queue, lease holder, heartbeat, idempotency key, cancel flag, and projection cursor; rebuild run status from ledger-backed events; quarantine inconsistent rows.
- **Gate:** restart matrix with real process boundaries.
- **Evidence:** pre/post-restart snapshots and duplicate-dispatch count.
- **Migration:** scheduler database is not receipt truth and must rebuild from evidence plus pending admission records.
- **Rollback:** revert if restart re-executes an effect without explicit resume/retry policy.
- **Claim:** “The runtime durably recovers admitted work without silent duplicate effects.”

## Task 5.2 — Propagate cancellation to process groups and children

- **Owner/files:** runner cancel module; sandbox process management; daemon API; tests.
- **RED:** cancel a running subprocess tree and prove no descendant remains; repeated cancellation is idempotent; unauthorized cancellation fails.
- **GREEN:** use process groups/cgroups where admitted, record request/ack/termination evidence, propagate to child runs, and enforce a bounded escalation policy.
- **Gate:** descendant-process and cancellation-race tests.
- **Evidence:** PID/process-group inventory and terminal receipts.
- **Migration:** cancellation unsupported for legacy runs is explicit.
- **Rollback:** revert if cancellation can target a process outside the run sandbox.
- **Claim:** “Authorized cancellation is durable, idempotent, and reaches tested subprocess descendants.”

## Task 5.3 — Resume only from verified step boundaries

- **Owner/files:** runner checkpoint/recovery modules; contracts replay module; tests.
- **RED:** resume from a partial artifact, mismatched policy version, changed tool schema, changed skill/model provenance, or unverified parent receipt fails.
- **GREEN:** checkpoint only after committed step receipts; require matching schema/policy/tool/provenance digests; resume by creating a causally linked continuation run.
- **Gate:** valid/invalid resume matrix.
- **Evidence:** checkpoint and continuation receipt graph.
- **Migration:** no in-place mutation of old runs.
- **Rollback:** revert if resume overwrites prior evidence or reuses consumed permits.
- **Claim:** “Resume creates a new causally linked continuation from a verified boundary.”

## Task 5.4 — Implement idempotent submission and replay classes

- **Owner/files:** contracts replay types; runner idempotency store; CLI tests.
- **RED:** duplicate submission with same key/different payload, network-dependent replay, and missing recorded output all fail predictably.
- **GREEN:** bind idempotency key to canonical request digest; return original handle for exact duplicates; implement `Deterministic`, `RecordedEvidence`, and `Unavailable` replay reports.
- **Gate:** concurrent duplicate-submit and offline replay tests with network disabled.
- **Evidence:** digest bindings and replay report.
- **Migration:** old runs default to `Unavailable` unless their evidence satisfies a stricter class.
- **Rollback:** revert if replay calls providers, network, current memory, or current skills implicitly.
- **Claim:** “Submission is idempotent and replay capability is explicitly classified.”

### Phase 5 gate

The Hermes E2E proof passes with daemon restart before terminal readback, cancellation tests pass, and offline verification/replay does not touch network or providers.

---

# Phase 6 — Migrate all execution adapters to the same runtime

## Task 6.1 — Migrate CLI to embedded or IPC `RuntimeService`

- **Owner/files:** `recursive-agent-cli/src/main.rs`; CLI integration tests.
- **RED:** source/call-path test detects direct tool/provider/ledger use; current path differs from runtime semantics.
- **GREEN:** explicit `--runtime embedded|ipc`; both translate CLI input to V1 and render runtime events/verification; no silent fallback between modes.
- **Gate:** identical fixture through both modes.
- **Evidence:** normalized event/receipt parity report.
- **Migration:** retain CLI syntax where safe; incompatible legacy flags return migration guidance.
- **Rollback:** revert if one mode weakens policy or sandbox requirements.
- **Claim:** “CLI modes are adapters over one runtime contract.”

## Task 6.2 — Reduce MCP server to strict translation

- **Owner/files:** `recursive-agent-mcp/src/lib.rs`; MCP integration tests.
- **RED:** direct tool dispatch, wall-clock `time_now`, adapter-minted IDs/receipts, and missing authority context fail source and behavior tests.
- **GREEN:** validate MCP input, construct V1 with server-derived peer identity and supplied attenuated lease, call runtime, translate committed events/results; use injected/frozen time only through runtime-owned tools.
- **Gate:** MCP-to-runtime test and direct-dispatch denylist.
- **Evidence:** translation field map and runtime receipt.
- **Migration:** return typed protocol errors for callers missing current authority/schema fields.
- **Rollback:** revert if MCP becomes a policy, scheduler, capability, or receipt owner.
- **Claim:** “MCP is an optional compatibility edge over the native runtime.”

## Task 6.3 — Harden MCP client correlation and cancellation

- **Owner/files:** MCP client module and tests.
- **RED:** wrong response ID, duplicate response, cancellation race, malformed error envelope, and late response must be rejected.
- **GREEN:** strict outstanding-request map, typed IDs, bounded in-flight requests, cancellation propagation, and terminal cleanup.
- **Gate:** adversarial fake-server tests.
- **Evidence:** protocol trace matrix.
- **Migration:** no permissive acceptance of ID-less legacy responses.
- **Rollback:** revert if a mismatched response can satisfy another request.
- **Claim:** “The MCP client strictly correlates requests, responses, errors, and cancellation.”

## Task 6.4 — Add adapter semantic-parity conformance

- **Owner/files:** create `crates/recursive-agent-runner/tests/adapter_parity.rs`; fixtures consumed by CLI, IPC, Hermes, and MCP tests.
- **RED:** normalized policy, sandbox, lifecycle, artifact, and receipt semantics differ between adapters.
- **GREEN:** execute one canonical request through embedded, daemon IPC, CLI, Hermes plugin, and MCP; compare invariants while allowing fresh run IDs and transport metadata.
- **Gate:** parity matrix.
- **Evidence:** machine-readable per-field comparison.
- **Migration:** an adapter remains experimental until it passes.
- **Rollback:** quarantine the failing adapter; never weaken shared invariants.
- **Claim:** “Tested adapters preserve native execution semantics.”

## Task 6.5 — Remove legacy direct execution surfaces

- **Owner/files:** runner/tools/provider public APIs; all adapter crates.
- **RED:** a workspace source/API test lists public bypass-capable functions.
- **GREEN:** remove, make crate-private, or require unforgeable runner context; delete deprecated wrappers after all consumers migrate.
- **Gate:** workspace build plus denylist scan.
- **Evidence:** before/after API inventory.
- **Migration:** one release-note section for intentionally broken prototype APIs; no fake compatibility layer.
- **Rollback:** revert only if a legitimate native consumer cannot use `RuntimeService`; then repair the service contract first.
- **Claim:** “No supported execution surface bypasses the canonical runtime.”

### Phase 6 gate

Static inspection and adapter-parity tests find no direct execution owner outside the runner. MCP can be disabled without changing native functionality.

---

# Phase 7 — Recursive authority, delegation, budgets, and remote admission

## Task 7.1 — Model actor/delegate identity and attenuation algebra

- **Owner/files:** contracts authority module; policy attenuation module; property tests.
- **RED:** child grant with any extra action, resource, duration, budget, delegation depth, or audience must fail; attenuation must be monotonic and transitive.
- **GREEN:** use the Task 0.3-admitted authority owner or implement one canonical policy module; persist parent grant and derivation proof.
- **Gate:** example and property tests.
- **Evidence:** attenuation vectors and counterexamples rejected.
- **Migration:** legacy copied grants cannot authorize current child effects.
- **Rollback:** revert if subset checking relies on string prefix or unordered serialization.
- **Claim:** “Child authority is a verifiable strict subset of parent authority.”

## Task 7.2 — Replace unmanaged subprocess delegation with child runs

- **Owner/files:** runner child-run module; CLI delegation surface; existing subprocess delegate code.
- **RED:** child without parent run, lease, budget share, cancellation link, or terminal child receipt fails.
- **GREEN:** create child `OperationEnvelopeV1`, reserve parent budget atomically, submit through runtime, link events/receipts, and close parent only after child closure policy.
- **Gate:** nested depth, budget exhaustion, failure, and cancellation tests.
- **Evidence:** parent-child causal graph and budget ledger.
- **Migration:** raw subprocess delegation remains only as a tool executor inside an authorized child run, not a scheduler.
- **Rollback:** revert if child execution can outlive revoked authority without recorded policy.
- **Claim:** “Recursive delegation is runtime-managed, budgeted, cancellable, and causally closed.”

## Task 7.3 — Add provider/model provenance without secrets

- **Owner/files:** provider invocation result; contracts provenance; runner receipts.
- **RED:** missing provider/model/config digest, hidden retry, or secret leakage fails.
- **GREEN:** record provider class, model alias/version when available, non-secret config digest, request/response artifact hashes, retry attempts, timing source, and limitation flags.
- **Gate:** deterministic fake-provider plus one approved live provider smoke only when credentials/use are separately authorized.
- **Evidence:** redacted provider receipt.
- **Migration:** source-reported provider metadata is labeled as such.
- **Rollback:** revert if provenance captures prompts/responses contrary to configured retention.
- **Claim:** “Provider invocations carry redacted, explicit provenance and retry evidence.”

## Task 7.4 — Implement remote-worker admission as a separate edge

- **Owner/files:** create `recursive-agent-remote` only if Task 0.3 proves no canonical existing owner; otherwise adapter under admitted crate; tests.
- **RED:** schema mismatch, capability mismatch, expired/revoked lease, wrong worker identity, unsupported sandbox, and missing attestation fail before dispatch.
- **GREEN:** versioned handshake, worker identity, capability manifest, schema/tool/policy digests, attenuated lease, budget, heartbeat, cancellation, and returned child receipt verification.
- **Gate:** local fake-worker adversarial suite; no internet required.
- **Evidence:** admission decisions and remote child receipt bundle.
- **Migration:** remote execution stays disabled by default until the suite passes.
- **Rollback:** quarantine remote adapter on any admission ambiguity.
- **Claim:** “A local test worker is admitted only through typed identity, capability, authority, and evidence checks.”

### Phase 7 gate

Property tests prove attenuation; nested child runs preserve budgets and cancellation; no remote worker can widen authority or satisfy verification with an untrusted receipt.

---

# Phase 8 — Provenance-aware memory

## Task 8.1 — Replace implicit paths and clock IDs with explicit scoped memory context

- **Owner/files:** `recursive-agent-memory/src/lib.rs`; schema migration tests.
- **RED:** open/write without tenant, session, run, store root, source receipt, or time validity fails; same content in different scopes cannot collide.
- **GREEN:** `MemoryContext` is passed by runner; IDs use admitted material identity; schema carries tenant/session/run, source receipt, content digest, valid/transaction time, trust, retention, supersession, and tombstone state.
- **Gate:** fresh/migrated database tests.
- **Evidence:** schema and migration fixtures.
- **Migration:** preserve V1 rows as `legacy_unprovenanced` and exclude them from trusted retrieval by default.
- **Rollback:** restore backup database if migration verification differs; never silently recreate a blank store.
- **Claim:** “Current memory records are scoped, content-addressed, temporal, and source-linked.”

## Task 8.2 — Implement real lexical retrieval or remove the BM25 claim

- **Owner/files:** memory query layer and tests; capability docs.
- **RED:** ranking fixture requiring term frequency, inverse document frequency, field length, scope, time, trust, and tombstone filtering fails current LIKE query.
- **GREEN:** use SQLite FTS5 BM25 if available and deterministic in the supported environment; otherwise name the feature accurately and keep BM25 blocked.
- **Gate:** ranking, deletion, supersession, and scope-isolation tests.
- **Evidence:** fixed corpus and ranked results.
- **Migration:** rebuild search index from canonical rows; index is disposable projection.
- **Rollback:** drop/rebuild only the index, never source memory rows.
- **Claim:** either “FTS5 BM25 passes the published fixture” or “lexical filtering only”; nothing broader.

## Task 8.3 — Bind memory reads and writes to runtime evidence

- **Owner/files:** runner, memory, contracts provenance, tests.
- **RED:** direct write, uncited read, cross-scope read, and write after failed run are rejected.
- **GREEN:** runtime issues read queries under authority; results return citation IDs/digests; receipts record cited rows/query digest; writes occur only after policy and terminal-state rules.
- **Gate:** end-to-end read-use-write test and tampered-memory replay test.
- **Evidence:** citation and write receipts.
- **Migration:** adapter memory APIs become read-only translators or are removed.
- **Rollback:** revert if memory can alter an existing run’s historical evidence.
- **Claim:** “Memory use and mutation are scoped, authorized, cited, and receipted.”

### Phase 8 gate

A run can cite scoped memory and write a derived record; strict verification proves the sources and write authority; old unprovenanced rows do not silently influence trusted decisions.

---

# Phase 9 — Governed skill lifecycle

## Task 9.1 — Secure skill discovery and typed parameter binding

- **Owner/files:** `recursive-agent-skills/src/lib.rs`; path/parameter tests.
- **RED:** traversal, symlink escape, duplicate names, unknown parameter, missing required parameter, type mismatch, and delimiter injection fail.
- **GREEN:** canonical skill root, no-follow path resolution, manifest schema, typed parameters, strict substitution/AST expansion, and content digest.
- **Gate:** adversarial skill fixture suite.
- **Evidence:** accepted/rejected manifests.
- **Migration:** legacy raw templates import into quarantine only.
- **Rollback:** revert if loading a skill can read outside its root or silently ignore a parameter.
- **Claim:** “Skill discovery and binding are path-safe, typed, and deterministic.”

## Task 9.2 — Add source provenance, validation, promotion, and revocation

- **Owner/files:** skills manifest/schema/store; runner policy integration; tests.
- **RED:** skill without source run/receipt, validation evidence, content digest, version, state, or promoter authority cannot execute.
- **GREEN:** lifecycle `Draft -> Quarantined -> Validated -> Promoted -> Revoked`; promotion/revocation are policy-controlled receipts; immutable versions.
- **Gate:** transition and concurrent-promotion tests.
- **Evidence:** lifecycle receipt chain.
- **Migration:** imported skills start quarantined regardless of filename/location.
- **Rollback:** revoke the new version; do not mutate promoted history.
- **Claim:** “Executable skill versions are source-linked, validated, promoted, and revocable.”

## Task 9.3 — Make skill expansion produce child operations, not effects

- **Owner/files:** skills expansion API; runner child-run integration; tests.
- **RED:** skill expansion that dispatches a tool/provider directly or widens authority fails.
- **GREEN:** expansion returns validated `OperationEnvelopeV1` proposals; runner attenuates authority and budgets, then schedules child runs.
- **Gate:** skill-to-child causal and cancellation tests.
- **Evidence:** skill version/source receipt plus child receipt graph.
- **Migration:** remove callback-based direct execution.
- **Rollback:** quarantine any skill that cannot express its effects declaratively.
- **Claim:** “Skills propose versioned child operations; only the runtime executes them.”

### Phase 9 gate

A promoted skill expands into bounded child runs with source, validation, authority, budget, cancellation, and terminal evidence; traversal and unpromoted execution are denied.

---

# Phase 10 — Evidence-aware branch search

## Task 10.1 — Remove the false MCTS claim and choose an accurate algorithm

- **Owner/files:** rename `crates/recursive-agent-mcts` to `crates/recursive-agent-search` and update workspace/docs, or retain the crate name only if real tree-search contracts are immediately implemented.
- **RED:** current random one-step sampler fails tests requiring explicit nodes, expansion, deterministic tie-breaks, visit/evidence state, and multi-depth traversal.
- **GREEN:** implement bounded deterministic best-first search first; reserve “MCTS/UCT” terminology until UCT equations and visit statistics have dedicated tests.
- **Gate:** fixed-tree selection tests.
- **Evidence:** algorithm contract and trace fixtures.
- **Migration:** mark prototype API removed; it is uncommitted and has no verified stable consumers.
- **Rollback:** revert terminology if implementation does not satisfy the named algorithm.
- **Claim:** “The runtime has bounded evidence-aware branch search,” not MCTS unless separately proven.

## Task 10.2 — Persist branch state, score components, and proof debt

- **Owner/files:** search crate; contracts branch provenance; tests.
- **RED:** random selection, hidden score component, score without evidence, unbounded branch, and unstable tie fail.
- **GREEN:** branch node carries parent, proposal digest, policy status, costs, evidence refs, uncertainty, proof debt, visits/expansions where applicable, and deterministic priority.
- **Gate:** score decomposition/property tests.
- **Evidence:** branch-state transcript and score receipts.
- **Migration:** score caches are rebuildable projections.
- **Rollback:** revert if aggregate score cannot be reconstructed from recorded components.
- **Claim:** “Branch ranking is deterministic and decomposable into cited evidence and costs.”

## Task 10.3 — Execute selected branches only through child runs

- **Owner/files:** search/runner integration; tests.
- **RED:** branch evaluator invoking tools/providers directly, exceeding budget, or omitting blocked-branch policy evidence fails.
- **GREEN:** selected proposals become attenuated child operations; runtime results update branch evidence; denied branches retain policy receipts without effects.
- **Gate:** multi-depth search with success, denial, failure, and cancellation.
- **Evidence:** search tree linked to child receipts.
- **Migration:** remove executor closures with ambient authority.
- **Rollback:** disable search entry point if any branch bypass exists.
- **Claim:** “Search explores through governed child runs and preserves denied/failed evidence.”

## Task 10.4 — Recover and cancel search deterministically

- **Owner/files:** search persistence; runner scheduler integration; tests.
- **RED:** restart or cancellation changes already-decided priorities, loses child links, or expands after cancel.
- **GREEN:** persist canonical frontier/closed-set digests and branch cursor; resume only from verified checkpoint; cancellation closes frontier and children.
- **Gate:** restart/cancel equivalence test.
- **Evidence:** pre/post-restart selected sequence.
- **Migration:** old random traces are not replayable search evidence.
- **Rollback:** restart search as a new run if exact continuation proof is unavailable.
- **Claim:** “Tested search checkpoints resume deterministically and cancel causally.”

### Phase 10 gate

No random decision affects material search behavior unless its seed and algorithm are explicit evidence. Every evaluated branch is tied to runtime child evidence and budget accounting.

---

# Phase 11 — Verification, fuzzing, supply chain, and failure injection

## Task 11.1 — Repair and enforce dependency-policy gates

- **Owner/files:** `deny.toml`, `Cargo.toml`, `Cargo.lock`; create `docs/supply-chain-policy.md`.
- **RED:** preserve current `cargo deny check` failure; add a fixture proving an unlicensed/banned/duplicate-risk dependency is detected.
- **GREEN:** update to the installed cargo-deny schema, explicitly configure advisories, bans, sources, and licenses; document accepted exceptions with owner/reason/expiry.
- **Gate:** `cargo deny check`; `cargo tree -d`; `cargo audit` if installed or an explicitly recorded missing-tool blocker.
- **Evidence:** tool versions and full reports.
- **Migration:** dependency changes require lockfile review; no blanket allow.
- **Rollback:** revert dependency additions that cannot satisfy policy without broad exceptions.
- **Claim:** “The recorded dependency policy passes the installed gate”; do not claim vulnerability-free software.

## Task 11.2 — Make fuzzing an operational workspace artifact

- **Owner/files:** complete `fuzz/Cargo.toml`; targets for receipt decode/verify, IPC framing, contract parsing, lineage/attenuation, and skill manifests.
- **RED:** `cargo fuzz list` and target builds fail now.
- **GREEN:** pin compatible fuzz dependencies/toolchain instructions; seed corpora from conformance fixtures; assert no panic, OOM-scale allocation, traversal, or invalid acceptance.
- **Gate:** build each target; bounded smoke run per target; longer runs only with explicit resource approval.
- **Evidence:** command, duration, seed, corpus digest, crashes/artifacts.
- **Migration:** fuzz findings become failing regression tests before fixes.
- **Rollback:** disable only a broken target with a tracked blocker; never claim fuzz coverage from source presence.
- **Claim:** “Named targets built and completed the recorded bounded fuzz run.”

## Task 11.3 — Add property and failure-injection suites

- **Owner/files:** package tests; optional dev-only `proptest`/failpoint dependency after admission.
- **RED:** generate counterexamples for state transitions, canonicalization, attenuation, budgets, sequence monotonicity, crash points, and cancellation races.
- **GREEN:** encode invariants and deterministic failpoints; preserve minimal counterexamples.
- **Gate:** property suite with recorded seed and failure-injection matrix.
- **Evidence:** seeds, cases, failpoints, outputs.
- **Migration:** no production failpoint activation.
- **Rollback:** revert a generator only if it violates the contract, not because it finds a defect.
- **Claim:** “Named invariants passed the recorded generated and injected cases.”

## Task 11.4 — Build CI and release gates around the real acceptance suite

- **Owner/files:** create `.github/workflows/ci.yml`, `.github/workflows/security.yml`, `scripts/verify-release.sh` if absent.
- **RED:** CI fixture fails when any formatting, test, Clippy, deny, contract, parity, tamper, or E2E gate is skipped.
- **GREEN:** pin toolchain/actions by reviewed versions or digests; upload evidence bundles; keep credentials absent; separate bounded PR gates from scheduled fuzz/audit.
- **Gate:** local script exits non-zero on injected failure; CI is not claimed until run remotely.
- **Evidence:** local output and later CI URL/ID when authorized and observed.
- **Migration:** no branch-protection or remote workflow change without explicit approval.
- **Rollback:** revert workflow if it silently skips unavailable tools.
- **Claim:** local only: “The release script enforces the listed gates”; remote CI only after observed runs.

### Phase 11 gate

All required gates produce machine-readable evidence. Missing tools are blockers, not passes. No release claim exists without current direct outputs.

---

# Phase 12 — Independent verification, observability, operator UX, and optional anchoring

## Task 12.1 — Add offline receipt export and verification

- **Owner/files:** ledger export module; CLI `receipt export|verify`; tests.
- **RED:** export with missing artifact, altered manifest, path escape, omitted dependency receipt, or changed verifier version fails.
- **GREEN:** self-describing bundle with schemas, canonical manifests, chain, artifacts, dependency envelopes, verifier version, and limitation report; verify offline in a clean temp directory.
- **Gate:** export/import/tamper matrix with network disabled.
- **Evidence:** bundle digest and independent verifier output.
- **Migration:** legacy bundles identify their reduced verification class.
- **Rollback:** reject incomplete export rather than emitting a partial “verified” bundle.
- **Claim:** “A named evidence bundle verifies offline under the recorded verifier.”

## Task 12.2 — Add redacted tracing and metrics derived from runtime events

- **Owner/files:** runner/daemon observability modules; tests.
- **RED:** sentinel secrets or raw model content in logs/metrics fail; metric state diverging from events fails rebuild test.
- **GREEN:** structured tracing IDs, run/step status, queue depth, latency, budget, policy denials, sandbox outcomes, verification failures; all derived from committed events with cardinality limits.
- **Gate:** redaction, rebuild, and cardinality tests.
- **Evidence:** sample redacted trace/metrics fixture.
- **Migration:** observability is opt-in/local by default; no outbound telemetry without separate consent.
- **Rollback:** disable exporter, preserving local event truth.
- **Claim:** “Local observability is redacted and reconstructable from committed runtime evidence.”

## Task 12.3 — Build operator CLI and read-only TUI before web control

- **Owner/files:** CLI `status`, `events`, `cancel`, `verify`, `tree`, `inspect`; optionally new `recursive-agent-tui` crate only after CLI contracts stabilize.
- **RED:** UI displaying state not backed by a current event/receipt ref fails; destructive commands without typed confirmation/authority fail.
- **GREEN:** render daemon/runtime snapshots and causal trees; actions call runtime APIs; show stale/degraded/legacy states explicitly.
- **Gate:** snapshot tests plus live temporary-daemon test.
- **Evidence:** UI state-to-event mapping.
- **Migration:** no UI-owned state database.
- **Rollback:** remove UI projection without affecting runtime state.
- **Claim:** “Operator views display runtime-backed state and invoke canonical control APIs.”

## Task 12.4 — Add web/API, IDE/CI, cron, and Agent Graph adapters only as thin edges

- **Owner/files:** `integrations/` subdirectories or dedicated adapter crates after contract admission; conformance fixtures.
- **RED:** each adapter fails a source-level owner check if it dispatches effects, stores authority, or mints receipts.
- **GREEN:** authenticate edge caller, translate to V1, call runtime/IPC, stream committed events, expose receipt references, and pass adapter parity.
- **Gate:** per-adapter contract/parity tests; no blanket “ecosystem integrated” claim.
- **Evidence:** field map and parity report per adapter.
- **Migration:** adapters remain feature-gated/experimental until their own gate passes.
- **Rollback:** quarantine an adapter without changing kernel behavior.
- **Claim:** only the specific adapter and operations proven by its tests.

## Task 12.5 — Add optional external anchoring after local verification

- **Owner/files:** contracts anchor envelope; ledger anchor module; feature-gated adapter such as RFC 3161/Rekor only after current protocol admission.
- **RED:** anchor for an unverified bundle, mismatched digest, untrusted authority, missing inclusion proof, or unavailable verifier fails.
- **GREEN:** anchor only the offline bundle digest; persist service response/proof and verification result as a child evidence envelope; local receipt truth remains valid without anchor.
- **Gate:** deterministic local fake-anchor tests plus approved external smoke when network/cost/terms are separately authorized.
- **Evidence:** request digest, response/proof bytes, verifier output, external identifier if real.
- **Migration:** remove fake `Blockchain`/`Timestamp` capability claims until a concrete adapter passes.
- **Rollback:** disable anchor adapter; never invalidate the local evidence chain.
- **Claim:** “The named bundle digest was anchored and its proof verified by the recorded method,” never generic immutability.

## Task 12.6 — Export governed evaluation/training datasets without becoming a second truth store

- **Owner/files:** read-only export under `integrations/evaluation`; tests.
- **RED:** export of unverified, revoked, secret-bearing, cross-tenant, or retention-forbidden evidence fails.
- **GREEN:** select by explicit policy, redact, retain source receipt IDs/digests and labels, emit immutable manifest; downstream datasets are projections.
- **Gate:** provenance round-trip and redaction tests.
- **Evidence:** dataset manifest and source coverage report.
- **Migration:** no training-success claim is implied by export.
- **Rollback:** delete projection; source evidence remains unchanged.
- **Claim:** “The dataset projection is reproducibly derived from the listed verified evidence.”

### Phase 12 gate

Offline verification passes; observability and UI are projections; each optional adapter passes its own parity suite; anchoring and dataset exports make only evidence-bounded claims.

---

# Phase 13 — Migration, hostile acceptance, and release closure

## Task 13.1 — Migrate V1 prototype data without laundering evidence

- **Owner/files:** versioned migration command in CLI/ledger/memory/skills; fixtures copied from the baseline snapshot.
- **RED:** migration that invents missing actor, sandbox, permit, artifact, or provenance fields must fail or mark them unknown.
- **GREEN:** verify old bytes under legacy rules, produce a migration receipt, preserve originals read-only, import only fields actually present, and quarantine incomplete records.
- **Gate:** byte-preservation and downgrade/unknown-field tests.
- **Evidence:** old/new manifests and migration receipt.
- **Migration:** one-way into a new root; no in-place rewrite.
- **Rollback:** point back to untouched legacy root; remove failed new projection.
- **Claim:** “Legacy evidence was preserved and classified; absent facts were not invented.”

## Task 13.2 — Run the full hostile acceptance gauntlet

- **Owner/files:** `scripts/acceptance.sh`; test manifests; no behavior change in this task.
- **RED:** the gauntlet must fail before full remediation. Scenarios: sandbox unavailable; policy deny; permit replay; failed step; ledger crash at every failpoint; artifact deletion/tamper/symlink swap; daemon socket attack; malformed/oversized IPC; concurrency saturation; client disconnect; cancellation race; process descendants; daemon restart; duplicate submission; child authority escalation; budget exhaustion; child receipt tamper; memory cross-scope read; unpromoted/revoked skill; search restart/cancel; MCP wrong ID; provider secret sentinel; offline replay network denial.
- **GREEN:** every scenario reaches the specified typed state and verifier outcome; no hang, silent fallback, or false success.
- **Gate:** `scripts/acceptance.sh` plus workspace gates.
- **Evidence:** indexed scenario receipt bundle with exact exit codes.
- **Migration:** none.
- **Rollback:** block release and quarantine the affected surface.
- **Claim:** only that the named scenarios passed on the recorded source/environment.

## Task 13.3 — Reconcile documentation and capability status with evidence

- **Owner/files:** `README.md`, `docs/capability-status.md`, architecture/plan status, crate READMEs.
- **RED:** automated claim matrix finds a capability labeled complete without a current acceptance artifact.
- **GREEN:** each capability links to a test/receipt or is labeled prototype/blocked/experimental; document replay and platform limits.
- **Gate:** documentation claim test and link/file existence check.
- **Evidence:** claim-to-receipt matrix.
- **Migration:** preserve superseded plans as historical documents.
- **Rollback:** downgrade claim immediately if evidence expires or regresses.
- **Claim:** “Documentation reflects the latest admitted evidence.”

## Task 13.4 — Produce an auditor-rerunnable closeout

- **Owner/files:** create `docs/receipts/release-candidate-<id>/MANIFEST.json` and `HANDOFF.md`.
- **RED:** closeout fails if changed files, commands, exits, skipped gates, unresolved risks, rollback, source commit/diff digest, or evidence locations are missing.
- **GREEN:** run all gates from a clean controlled worktree; include failures/skips; require independent read-only audit before any release recommendation.
- **Gate:** manifest verifier and independent rerun.
- **Evidence:** complete release-candidate bundle.
- **Migration:** commit/tag/push/release remain separately approved actions.
- **Rollback:** restore pre-phase snapshot and preserve failed evidence bundle.
- **Claim:** “This exact release candidate passed the listed gates”; no broader production/security guarantee.

---

# Implementation dependency graph and stop conditions

```text
Phase 0 truth/admission
  -> Phase 1 P0 containment
    -> Phase 2 native contracts/runtime
      -> Phase 3 safe IPC
        -> Phase 4 no-MCP Hermes proof
          -> Phase 5 durability/replay
            -> Phase 6 adapter migration
              -> Phase 7 recursion/remote
                -> Phase 8 memory
                -> Phase 9 skills
                  -> Phase 10 branch search
                    -> Phase 11 hardening
                      -> Phase 12 UX/optional edges
                        -> Phase 13 migration/hostile closure
```

Stop immediately and quarantine the active phase if any of the following occurs:

- an effect executes without a consumed lease, enforced sandbox outcome, and runner-owned lifecycle;
- a failed/cancelled run can appear successful;
- canonical IDs/bytes differ across repeated or cross-process fixed vectors;
- ledger recovery discards valid evidence or accepts mixed state;
- strict verification follows a symlink/path outside the run root;
- any adapter becomes an authority, scheduler, execution, or receipt owner;
- child authority or budgets widen;
- replay reaches network/provider/current ambient state;
- credentials appear in any serialized or logged artifact;
- migration invents absent provenance;
- a test claims real integration while using mocks at the governing boundary.

# Defect coverage matrix

| Verified gap | Primary repair tasks | Acceptance evidence |
|---|---|---|
| UUID/wall-clock material IDs | 0.3, 1.1 | fixed vectors, domain separation |
| Failed step finalizes OK | 1.2 | lifecycle transition suite |
| Non-durable/reusable permits | 1.3, 7.1 | race and attenuation tests |
| Ledger/meta crash window | 1.4 | failpoint recovery matrix |
| Artifact bytes not verified | 1.5, 12.1 | tamper/offline verification |
| False Landlock sandbox claim | 1.6 | no-dispatch negative test |
| Raw API key serialization | 1.7, 7.3 | sentinel scans |
| Incomplete native envelopes/events | 2.1, 2.2 | schema/conformance vectors |
| No sole runtime owner | 2.3–2.5, 6.5 | call-path audit and embedded proof |
| Unsafe/unbounded daemon | 3.1–3.3 | framing/socket/concurrency tests |
| No native Hermes path | 4.1–4.3 | real plugin-loader E2E |
| No durable scheduler/cancel/resume | 5.1–5.4 | restart/cancel/replay suite |
| MCP/tool bypass | 2.4, 6.2, 6.5 | denylist and parity |
| MCP response/cancel weakness | 6.3 | adversarial fake server |
| Adapter semantic drift | 6.1–6.4 | parity matrix |
| Unmanaged delegation | 7.1–7.2 | child causal/budget tests |
| Missing remote admission | 7.4 | adversarial local worker |
| Unscoped/provenance-free memory | 8.1–8.3 | scope/citation/migration tests |
| Weak skill paths/templates/lifecycle | 9.1–9.3 | adversarial/lifecycle tests |
| Random fake MCTS | 10.1–10.4 | deterministic tree traces |
| Invalid cargo-deny and absent fuzz proof | 11.1–11.3 | direct gate outputs |
| No comprehensive CI/release gate | 11.4, 13.2–13.4 | local/remote receipts |
| No offline export verifier | 12.1 | clean-room bundle verification |
| Missing observability/TUI/web edges | 12.2–12.4 | projection/parity tests |
| Fake/absent anchoring | 12.5 | concrete proof verification |
| Legacy evidence ambiguity | 13.1 | non-inventing migration receipt |
| Documentation overclaims | 0.2, 13.3 | claim-to-evidence matrix |

# Direct final verification commands

The final command set is run from `/home/sikmindz/Coding/recursive-agent` with direct exit-code capture. Adjust only when a checked-in script replaces an equivalent command and its contents have been audited.

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
cargo audit
cargo fuzz list

cargo test -p recursive-agent-contracts
cargo test -p recursive-agent-policy
cargo test -p recursive-agent-sandbox
cargo test -p recursive-agent-ledger
cargo test -p recursive-agent-runner
cargo test -p recursive-agent-daemon
cargo test -p recursive-agent-mcp
cargo test -p recursive-agent-memory
cargo test -p recursive-agent-skills
cargo test -p recursive-agent-search

cargo test -p recursive-agent-runner --test native_vertical
cargo test -p recursive-agent-runner --test lifecycle_state_machine
cargo test -p recursive-agent-runner --test adapter_parity
cargo test -p recursive-agent-ledger --test crash_recovery
cargo test -p recursive-agent-ledger --test artifact_tamper
cargo test -p recursive-agent-daemon --test framing
cargo test -p recursive-agent-daemon --test socket_safety
cargo test -p recursive-agent-daemon --test ipc_runtime

./scripts/verify-hermes-native.sh
./scripts/acceptance.sh
./scripts/verify-release.sh
```

If `cargo audit`, `cargo fuzz`, an OS sandbox mechanism, or Hermes test dependencies are unavailable, the associated gate is `BLOCKED`, not skipped/passed. Linux-specific sandbox tests must record kernel and Landlock support; portability claims require separate platform evidence.

# Rollback and migration strategy

1. Before Phase 1, preserve the full dirty baseline as a binary diff plus untracked-file archive under the receipt root; do not commit/push unless separately authorized.
2. Each phase writes a new evidence directory and records its source diff digest.
3. Contract/schema changes use explicit versions. Readers may support legacy evidence, but writers emit only the current admitted version.
4. Legacy data is never rewritten in place. Migrations target a new root and carry migration receipts.
5. `chain.meta`, search indexes, metrics, UI state, and scheduler status are projections. They must be rebuildable; rollback may delete/rebuild them.
6. Receipts, artifacts, source memory records, promoted skill versions, and migration inputs are preserved evidence. Rollback must not rewrite or delete them.
7. Runtime mode changes are explicit. There is no silent fallback from IPC to embedded, enforced to degraded sandbox, strict to legacy verification, or native to MCP.
8. A failing adapter is quarantined without changing the kernel.
9. External plugin installation, daemon service activation, CI changes, and anchoring require separate approval and their own rollback receipts.

# Execution handoff

Start with Phase 0 only. After each phase:

- run the phase gate and workspace smoke gates;
- perform an independent hostile read-only review of the changed owner surfaces;
- update the coverage matrix with evidence paths;
- stop if any invariant or rollback condition is unresolved;
- obtain approval before deployment, active-profile changes, commits, pushes, releases, paid/network services, or credential-bearing tests.

For orchestration, use Agent Graph for bounded planning/review/council work when it is live and receipt-producing. Use full-capability isolated coding agents only for tasks that require terminal/file execution unavailable to graph nodes, and independently verify their changes and outputs. The failed planning run recorded in Section 2.2 is not reusable plan evidence.

The implementation is complete only when Phase 13 passes. Intermediate phases support only their narrow claims; they do not imply production maturity, security guarantees, complete ecosystem integration, or deterministic replay of external state.
