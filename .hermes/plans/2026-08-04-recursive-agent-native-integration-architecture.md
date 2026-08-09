# Recursive Agent: Native Integration Architecture

**Date:** 2026-08-04<br>
**Repository:** `/home/sikmindz/Coding/recursive-agent`<br>
**Observed branch / HEAD:** `main` / `3805f7abf319e07e47f1c20b862e614c3dad164f`<br>
**Status:** Architecture decision and implementation gate; no source implementation is certified by this document.

## Verdict

`recursive-agent` should become the **protocol-independent execution, authority, and evidence kernel** for the local agent stack. It should not become an MCP-centric tool server, a second memory database, or a collection of string-dispatched utilities.

Its durable value is the composition of:

- typed requests and outcomes;
- principal and delegated-authority lineage;
- capability and budget policy;
- sandboxed effect execution;
- append-only causal receipts;
- content-addressed artifacts;
- durable lifecycle and event streaming;
- recorded replay and independent verification;
- trust-aware memory and procedure lifecycle;
- receipted search over isolated execution branches.

Every integration surface must map onto those native semantics. MCP is one optional compatibility adapter at the perimeter.

## Evidence state

### Verified on the current working tree

- `cargo fmt --all -- --check` passed.
- `cargo clippy --workspace --all-targets -- -D warnings` passed.
- `cargo test --workspace --all-targets` passed.
- The working tree is dirty and contains uncommitted Phase 4–6 additions.
- The native core already contains useful **prototype** primitives: `RunSpecV1`, `ReceiptV1`, authority-lineage records, policy permits, canonical JSON checks, `stack-ids` digests, BLAKE3 receipt chaining, content-addressed artifacts, recorded-replay scaffolding, provider abstraction, Landlock-oriented process isolation, and sequential runner composition. The findings below prevent treating the ledger, replay, authority, or sandbox paths as acceptance-ready.

### Material gaps observed in source

- `recursive-agent-runner/src/lib.rs:35-57` uses UUID v4 for durable run, step, and receipt IDs despite `AGENTS.md` requiring material IDs from `stack-ids`. `recursive-agent-contracts/src/lib.rs:54-62` merely concatenates family strings and even has a test accepting an empty family.
- `recursive-agent-runner/src/lib.rs:171-213` records `StepFailed` but continues, and `107-122` always writes `RunFinalized` with `ReceiptOutcomeV1::Ok`. A run containing failed effects can therefore terminate as successful.
- `recursive-agent-policy` produces permits, but the ledger has no permit-issued/approved/consumed/expired/revoked events and consumption is not atomic with effect admission. The current lineage validator checks endpoint labels and uniqueness, not authority-transition semantics, argument binding, principal continuity, or one-shot consumption.
- `recursive-agent-sandbox/src/lib.rs:117-124` ignores UID/GID-map failures, `204-223` treats unavailable Landlock as success, and `163-170` always reports `sandboxed: true`. Timeout kills only the immediate child, output is bounded only after full collection, and CPU/memory/process/network ceilings are absent. This is a critical false-attestation path.
- `recursive-agent-ledger/src/lib.rs:147-173` fsyncs a receipt and then non-atomically rewrites `chain.meta`; a crash can leave a valid appended event with stale/truncated metadata. `open()` trusts metadata instead of reconstructing it. `verify()` does not compare computed head/length/genesis to `chain.meta` or verify referenced artifact bytes. `replay()` lists artifact IDs without reading or hashing them.
- `recursive-agent-mcp/src/server.rs:107-113` executes local `echo` and `time_now` handlers directly. It bypasses the runner, policy, sandbox, ledger, and receipt chain.
- `recursive-agent-mcp/src/client.rs:20-24` directly spawns an arbitrary command. No manifest pin, capability lease, sandbox classification, bounded output, cancellation, or child receipt is present.
- `recursive-agent-daemon/src/lib.rs:51-80` accepts newline-delimited JSON and invokes `run_spec`; it has no typed lifecycle protocol, peer authority, resumability, cancellation, event subscriptions, or daemon-boundary receipts.
- `recursive-agent-tools/src/lib.rs:221-267` owns memory, skill, and delegation behavior directly in a string match. This concentrates unrelated owner semantics in an adapter-like dispatch crate.
- `recursive-agent-tools/src/lib.rs:146-149` parses a delegation timeout, while `260-267` launches `ra` without enforcing it. Delegated identity, authority attenuation, budgets, cancellation, and parent/child receipt linkage are absent.
- `recursive-agent-memory/src/lib.rs:50-55` derives material identity from wall-clock nanoseconds and uses `unwrap_or_default`; `88-121` implements substring term counting while calling it “BM25-inspired.” It duplicates the canonical semantic-memory owner.
- `recursive-agent-skills/src/lib.rs:116-127` serializes JSON, performs raw string replacement, and converts expansion failures to null. It is not a typed or fail-closed procedure compiler.
- `recursive-agent-mcts/src/lib.rs:51-77` randomly samples one tool per iteration and returns the best single sample. It has no tree, UCT selection, branch state, execution, evidence, deterministic seed, or backpropagation.
- The fuzz target and `deny.toml` are source artifacts, not operational gates. Direct controller execution confirmed `cargo deny check` exits 1 because `unmaintained = "warn"` is invalid for the installed schema. `cargo fuzz --version` exits 101 because `cargo-fuzz` is not installed. The lineage fuzz module is an explicit placeholder and the multi-target layout is unverified.

### Reconciled hostile-audit blocker matrix

The controller inspected the three independent read-only audit reports and rechecked material claims against the current working tree. These are the blockers that should govern sequencing:

| Severity | Verified blocker | Required acceptance direction |
|---|---|---|
| Critical | MCP executes duplicate `echo`/wall-clock `time_now` paths outside policy and receipts | Identical native request through SDK/daemon/CLI/MCP yields one kernel event model; unfrozen time is rejected |
| Critical | Sandbox can run without Landlock while reporting `sandboxed: true` | Forced isolation failure is denied or explicitly degraded; executor never reports unobserved protection |
| High | UUID v4 and wall-clock IDs violate material-identity doctrine; `FamilyId` accepts malformed values | Deterministic domain-separated IDs reproduce across processes and malformed IDs fail at ingress |
| High | Failed steps still permit `RunFinalized(Ok)` | Terminal status is derived from events; failed effect cannot produce successful run closure |
| High | Permit lineage is label-based; issuance/consumption/revocation are not durable or atomic | Argument-bound one-shot permits; duplicate use and authority escalation are denied and receipted |
| High | Ledger append/meta update is crash-inconsistent; verifier ignores metadata and artifact bytes | Crash-injection reopen, metadata tamper, missing artifact, and changed artifact all fail or recover explicitly |
| High | Daemon deletes existing paths, uses `/tmp`, has no peer authentication, unbounded framing, or enforced concurrency | XDG runtime socket, peer credentials, ownership-safe startup, bounded frames, deadlines, and queue/admission tests |
| High | Delegation ignores timeout, cancellation, lineage, output bounds, and child receipt verification | Child run inherits attenuated authority/budgets and closes with verified parent-linked terminal receipt |
| High | Skill names can traverse the registry path; expansion is textual and silently becomes JSON `null` | Contained identifiers/symlinks, structural typed substitution, explicit compilation failures |
| High | Memory is a shadow mutable store with nondeterministic timestamp identity and no provenance | Canonical semantic-memory/claim owners, append-only versioning, deterministic order, read/write receipts |
| High | MCP client does not enforce its timeout, response ID/version correlation, or stable buffered framing | Deadline kills child; mismatched IDs/versions fail; multiple sequential calls remain correlated |
| High | Serializable provider specs contain raw API keys and missing OpenAI content becomes empty success | Secret references/redaction plus malformed-response rejection and no-secret receipt/artifact tests |
| Medium | “MCTS” is random one-step selection | Rename to random search or implement deterministic, multi-level, receipt-bearing branch search |
| Medium | Fuzzing, supply-chain configuration, documentation, and flat capability allowlist overstate readiness | Runnable pinned gates, capability-specific policy, and evidence-linked capability documentation |

### Agent Graph attempt

Luna graph run `run-19fcfe07d01-1` used the explicit `gpt-5.6-luna` model through `codex-app-server://`, but timed out after one LLM call. Its durable terminal receipt reports `status=failed`, `step_count=0`, `evidence_authority=structural_unverified`, and `replay_capability=integrity_only`. It produced no architecture output and is not used as support for this decision.

## Correct system boundary

```text
                  ┌──────────────────────────────────────────┐
                  │          Native recursive runtime         │
                  │                                          │
Requests ───────▶ │  admit → authorize → plan → execute      │
                  │      → observe → commit → receipt         │
                  │                                          │
                  │  lifecycle • events • artifacts • replay │
                  └───────────────┬──────────────────────────┘
                                  │
                  canonical typed contracts / owner receipts
                                  │
    ┌──────────────┬──────────────┼─────────────┬──────────────┐
    ▼              ▼              ▼             ▼              ▼
 Embedded SDK   Native IPC     Hermes bridge  Agent Graph   Remote worker
    CLI/TUI       daemon       + context      executor      / edge lease
    tests/UI     systemd       + memory       + checkpoints
                                  │
                         ┌────────┴────────┐
                         ▼                 ▼
                    ACP / IDE         MCP adapter
                                     compatibility only
```

## Native kernel contracts

The kernel needs a small, stable contract set. These are native Rust types and traits, not wire-protocol DTOs.

### 1. `RunRequestV1`

Binds:

- run, trace, attempt, and parent identifiers;
- caller principal and authority lineage;
- capability lease and policy profile;
- budgets: time, tokens, cost, effects, recursion depth, branches, disclosure;
- source/workspace identity;
- deterministic inputs and retained-artifact policy;
- requested lifecycle behavior.

### 2. `EffectRequestV1`

Describes one proposed effect before execution:

- typed operation and versioned schema;
- validated concrete arguments;
- origin adapter and originating run/node/branch;
- requested resources and disclosure class;
- idempotency and retry policy;
- deadline and cancellation token;
- expected pre-state digest when stateful.

### 3. `AdmissionDecisionV1` and `ExecutionPermitV1`

One canonical policy path decides whether an effect may execute. A flat string allowlist is not sufficient. The decision binds:

- principal and delegated authority;
- operation family and resource scope;
- budget consumption and remaining ceilings;
- required sandbox/capability class;
- approval obligations;
- denial/degradation reason;
- single-use or bounded reuse semantics.

### 4. `EffectOutcomeV1`

A typed sum, never an ambiguous JSON blob:

- `Completed`;
- `Denied`;
- `Failed`;
- `TimedOut`;
- `Cancelled`;
- `Degraded`;
- `UnknownAfterCrash`.

It carries artifact references, observed capability/sandbox facts, provider/tool metadata, state transition digests, and error classification.

### 5. `ExecutionEventV1`

An append-only lifecycle stream:

- admitted, queued, started, progress, output, policy decision, sandbox decision;
- branch fork/join, delegation started/completed;
- memory read/write candidate, skill compiled/executed;
- paused, awaiting approval, resumed, cancelled, terminal;
- anchor pending/confirmed/rejected.

Events feed the TUI, desktop, daemon clients, observability, and durable recovery. UIs never own lifecycle truth.

### 6. `ExecutionReceiptV1`

Binds the causal closure:

- request and outcome digests;
- policy/permit and authority references;
- parent/child run, node, branch, and effect relationships;
- provider/tool/sandbox identities;
- input/output/artifact digests;
- valid time and recorded time;
- replay class and retained-input status;
- explicit degraded or unknown state;
- prior receipt/ledger head;
- optional external anchor record.

### 7. `RuntimeService`

The native control-plane interface:

- `submit`;
- `inspect`;
- `subscribe`;
- `pause`;
- `resume`;
- `cancel`;
- `approve` / `deny` through authenticated operator authority;
- `replay_recorded`;
- `reexecute_from_retained_inputs` as a separate operation;
- `verify`;
- `export`.

The embedded Rust API and native daemon protocol expose the same semantics.

## Canonical owner map

Do not rebuild mature owners inside `recursive-agent`.

| Responsibility | Canonical owner / direction | Recursive-agent role |
|---|---|---|
| Tool execution contracts and receipts | `Libraries/llm-tool-runtime` | Compose and supply policy/sandbox/evidence context |
| Semantic memory, hybrid retrieval, bitemporal truth | `Libraries/semantic-memory` | Emit governed reads/writes and retain owner backpointers |
| Claims, evidence, tamper-evident claim history | `Libraries/claim-ledger` | Project verified execution evidence and proof debt |
| Delegated authority and leases | `Libraries/authority-delegation` | Attenuate parent authority and bind child receipts |
| Graph orchestration, checkpoints, interrupts, joins, event sink | `Libraries/agent-graph` | Execute graph nodes through the native runtime; correlate receipts |
| Remote execution admission | `Libraries/remote-oracle-admission` | Issue/consume bounded remote leases and replay obligations |
| Stable material IDs | `Libraries/stack-ids` | Use directly; never wall-clock/process/random identity |
| Boundary canonicalization | `Libraries/boundary-compiler` | Validate every external ingress/egress |
| Release/assurance cases | `Libraries/assurance-runtime` | Supply execution evidence, not self-certification |
| Exact/conservative checks | `Libraries/kernel-oracles` | Optional bounded adjudication and refutation path |
| Artifacts and receipt chain | Existing recursive-agent ledger/artifact layer, reconciled with owners | Canonical run/effect evidence store |

## Every high-value wiring path

### A. Embedded Rust SDK — strongest and lowest overhead

Rust applications call `RuntimeService` in process. This is the reference path for tests, deterministic local workflows, and other Libraries crates. It preserves typed contracts without serialization loss.

**Improves:** correctness, latency, compile-time schema checking, reusable conformance tests.

### B. Native daemon over Unix-domain IPC — primary operational path

A long-running daemon owns durable run lifecycle, event streaming, cancellation, recovery, policy state, and receipt publication. Use length-delimited/versioned frames, kernel peer credentials, bounded messages, idempotency, and authenticated operator routes.

**Improves:** crash isolation, concurrent clients, resumability, durable work, least authority, desktop/Hermes sharing.

### C. CLI — thin operator and automation client

`ra` becomes a client of the same service rather than a separate semantics owner. Commands submit, inspect, follow events, cancel, verify, replay, and export.

**Improves:** scriptability without bypassing governance.

### D. TUI and desktop control plane

The UI consumes `ExecutionEventV1` and `RuntimeService`; it shows active runs, causal trace trees, branch graphs, capability/permit state, artifacts, receipts, memory provenance, and approval queues. Steering operations go through authenticated lifecycle commands.

**Improves:** situational awareness, safe intervention, debugging, proof inspection. It must not scrape logs or mutate databases.

### E. Hermes execution-backend bridge — highest immediate ROI

Do not expose the whole platform merely as an MCP server. Build a standalone Hermes plugin backed by the native daemon or PyO3 SDK:

1. **Execution backend:** selected Hermes tool calls become `EffectRequestV1`; recursive-agent performs authorization, sandboxing, execution, artifacts, and receipts.
2. **Pre-tool governor:** a Hermes `pre_tool_call` hook can provide defense in depth, but is not the sole proof boundary.
3. **Post-tool witness:** `post_tool_call` records externally executed tools as observed/degraded evidence, never as native execution proof.
4. **Memory provider:** use semantic-memory as the owner; finished turns create candidate facts/claims with source and trust state.
5. **Context engine:** `select_context` retrieves evidence packets and `on_turn_complete` observes the completed turn. Hermes documentation explicitly supports both hooks.
6. **Subagent lifecycle bridge:** child Hermes agents map to child runs with attenuated authority, depth/cost/effect budgets, cancellation propagation, and parent/child receipts.
7. **Session lifecycle:** session start/end/finalize events bind conversation and run identities without polling.
8. **Desktop plugin:** render runs, approvals, receipts, and evidence inside Hermes without moving execution truth into the UI.

**Improves:** every Hermes effect can become governed and auditable while retaining Hermes as the conversational interface.

Three evidence levels must remain distinct:

- observer hook: saw an event;
- governor hook: admitted/blocked a request;
- native executor: actually performed and receipted the effect.

### F. Agent Graph executor and checkpoint bridge

Agent Graph owns control flow, joins, interrupts, and checkpoints. Recursive-agent owns effect admission/execution. Each graph node submits a native run/effect and stores only backpointers to owner receipts. Correlate graph run/node/attempt IDs with recursive run/effect IDs.

**Improves:** durable multi-step workflows, parallelism, HITL, retries, and deterministic joins without duplicating graph semantics.

### G. Native recursive delegation

A delegate is a child `RunRequestV1`, not a subprocess helper. The parent attenuates authority and allocates budgets. The child may use a local runtime, Hermes agent, coding-agent CLI, Graph subworkflow, or remote worker through an adapter, but must return a typed child terminal receipt.

**Improves:** safe recursive autonomy, cancellation, cost control, attribution, independent child verification.

### H. Search/MCTS as branch orchestration

Search operates over forked checkpoints and candidate action sequences:

- deterministic seed and search policy;
- branch ID and isolated mutable state;
- per-branch capability/effect/token/cost budgets;
- expansion, selection, rollout/evaluation, backpropagation;
- evidence-quality, risk, cost, and reward scoring;
- branch receipts and explicit discarded-branch records;
- selected branch promoted only through normal policy admission.

It can use Agent Graph for branch control and kernel oracles for bounded checks.

**Improves:** planning quality while making exploration inspectable and containing speculative effects.

### I. Trust-aware memory

Every retrieval is a receipted read with query/profile/result digests and evidence references. Every write is initially a candidate fact, claim, episode, or procedure event—not immediately trusted truth. Supersession, contradiction, provenance, valid/recorded time, and retrieval routing remain owned by semantic-memory and claim-ledger.

**Improves:** context quality, correction, temporal truth, and explainable retrieval without a shadow SQLite store.

### J. Governed skills/procedural memory

A skill is a versioned, typed procedure artifact derived from source runs. The lifecycle is:

`candidate → compile → sandbox test → evaluate → review/adjudicate → promote/quarantine → execute → supersede/revoke`.

Execution uses concrete validated argument values, not JSON string substitution. Promotion cites source receipts, test evidence, policy, environment, and authority.

**Improves:** genuine compounding capability without silently teaching the agent unsafe or ineffective behavior.

### K. Model providers and routing

Provider calls are native effects with model/provider identity, prompt/input digest, token/cost/latency, routing decision, retained-output policy, failure/fallback reason, and receipt. Providers remain adapters beneath a typed provider trait.

**Improves:** reproducibility, budget control, provider comparison, fallback analysis, and training-data quality.

### L. Local tools, containers, VMs, browser, and hardware

All effectors implement a common executor contract and report observed containment/capability facts:

- Landlock/local process;
- Podman/container;
- VM/QEMU;
- browser/computer use;
- SSH/remote host;
- GPU/training worker;
- embedded/edge device;
- database or service mutation.

Policy selects the required isolation class; adapters cannot self-assert safety.

**Improves:** one governance/evidence path across heterogeneous execution backends.

### M. Remote workers and edge devices

Use typed, bounded leases and signed/content-addressed envelopes rather than exporting the internal runtime through MCP. Bind worker identity, allowed artifact/effect families, disclosure ceiling, exactness class, budget, expiry, replay obligation, and revocation behavior. Admit returned results locally before they affect truth.

**Improves:** distributed execution, GPU offload, edge inference, and multi-device operation without surrendering local authority.

### N. CI, release, and deployment gates

CI jobs submit native run specs. Receipts bind source revision, dependency closure, exact command, environment, artifact digest, test/lint/security results, and release decision. Claim-ledger and assurance-runtime consume these as evidence; they do not infer success from exit code alone.

**Improves:** reproducible build proof, release closure, deployment rollback, and public-claim safety.

### O. Cron, webhooks, queues, gateways, and Kanban

These are origin adapters that create `RunRequestV1` with a declared principal, trigger source, policy profile, and bounded authority. They never execute privileged work directly. Event-driven lifecycle hooks are preferred over polling when a precise event exists.

**Improves:** durable automation while retaining identity, idempotency, and centralized cancellation.

### P. IDE/ACP and coding-agent integration

ACP/IDE commands and coding agents submit runs/effects through the native daemon. Worktree identity, requested patch scope, commands, tests, output artifacts, and rollback become part of the receipt chain.

**Improves:** auditable coding work, isolated parallel agents, and verifiable implementation handoffs.

### Q. Observability and operations

Emit OpenTelemetry/log/metrics projections from the canonical event stream. Track latency, queueing, denials, retries, sandbox degradation, provider cost, branch waste, retrieval quality, and receipt/anchor health. Telemetry is rebuildable and never authority.

**Improves:** bottleneck diagnosis, SLOs, anomaly detection, and operational recovery.

### R. Evaluation, training, and self-improvement

Convert verified runs into curated trajectories only after filtering secrets, ambiguous outcomes, policy violations, and low-evidence steps. Compare candidate policies, prompts, skills, providers, and search strategies against held-out tasks. A learning proposal cannot promote itself.

**Improves:** evidence-backed continual improvement instead of self-reinforcing anecdote.

### S. Portable evidence exports and external anchors

Export canonical bundles containing receipts, required artifacts/backpointers, schemas, verification instructions, and explicit replay class. Optional anchor backends submit a receipt-root digest to a transparency service, timestamp service, Git object, or other external witness. Anchoring does not replace local verification.

**Improves:** cross-machine audit, third-party review, dispute resolution, and durable tamper evidence.

### T. MCP compatibility adapter

MCP imports or exports capabilities only after:

- manifest/schema validation and version pinning;
- policy classification;
- principal/capability mapping;
- sandbox and timeout selection;
- output bounds and cancellation;
- conversion into `EffectRequestV1`;
- owner receipt capture and provenance mapping.

MCP metadata that cannot represent native semantics remains in the internal receipt. The adapter must not invent a weaker parallel truth model.

**Improves:** interoperability with external ecosystems without constraining the native platform.

## Compounding feedback loops

The uncommon leverage appears when the components reinforce one another:

1. A tool effect produces a receipt and artifacts.
2. Claims/evidence are projected to claim-ledger and semantic-memory.
3. Retrieval returns trust- and time-aware evidence packets, with read receipts.
4. Repeated successful action sequences become skill candidates linked to source runs.
5. Skills are compiled, tested, adjudicated, and promoted under separate authority.
6. Search explores candidate plans in isolated branches and scores evidence quality, risk, and cost—not merely model preference.
7. Delegated children receive attenuated authority and produce independently verifiable child receipts.
8. CI/evaluation compares outcomes and proposes routing/policy/skill changes.
9. A human or separately governed policy admits those changes.
10. Replay and external witnesses make regressions and tampering detectable.

That is a governed learning and execution system, not a tool server.

## Implementation sequence

### P0 — Recover architectural truth

- Mark current MCP, daemon, memory, skills, delegation, and MCTS additions as prototypes.
- Remove “Phase complete” and “MCTS/BM25/delegation” claims until behavior gates exist.
- Freeze a native runtime ADR and owner map.
- Replace UUID/wall-clock material identity with validated, domain-separated `stack-ids` derivation.
- Make failed effects derive a failed/degraded/cancelled terminal run state; never unconditionally finalize `Ok`.
- Make sandbox admission fail closed and emit observed isolation facts; kill the complete effect subtree and enforce resource/output ceilings.
- Make event/receipt append crash-safe, reconcile metadata on open, and verify metadata plus artifact contents offline.
- Add durable permit lifecycle and atomic one-shot effect admission.
- Repair and execute the supply-chain and fuzzing gates before claiming them.
- Add RED tests proving adapters cannot execute without a native permit/receipt path.

**Gate:** deterministic IDs; truthful isolation; crash/reopen recovery; artifact and metadata tamper rejection; failed-step terminal correctness; one-shot permit enforcement; no adapter-owned execution semantics; current core remains green.

### P1 — Native runtime and lifecycle

- Introduce `RuntimeService`, request/effect/outcome/event contracts, cancellation, budgets, and typed terminal states.
- Refactor current runner behind it.
- Add durable event/run storage and restart-safe lifecycle.
- Wire `llm-tool-runtime` rather than duplicating tool semantics.

**Gate:** process-boundary run submit/follow/cancel/restart/recover with verified persisted receipts.

### P2 — Native daemon, CLI, and Hermes vertical slice

- Replace raw newline daemon protocol with versioned framed IPC and peer credentials.
- Make CLI a thin client.
- Implement one Hermes execution-backend vertical slice: an `echo` or bounded shell effect must traverse Hermes → native runtime → policy → sandbox → receipt → Hermes result.
- Add context observation/retrieval only after execution truth works.

**Gate:** no MCP in the vertical slice; negative permit, timeout, cancellation, and restart tests pass.

### P3 — Canonical memory, claims, skills, and delegation

- Delete/quarantine the shadow memory implementation and integrate semantic-memory/claim-ledger owners.
- Implement typed procedure lifecycle.
- Implement child runs with authority attenuation, budgets, joins, cancellation, and parent/child receipts.

**Gate:** reopened owner stores prove write/read lineage; child receipt closure and revocation tests pass.

### P4 — Agent Graph and real search

- Add native runtime executor nodes and receipt correlation to Agent Graph.
- Implement checkpoint-isolated branch search with deterministic UCT/MCTS or explicitly choose a simpler search name/contract.
- Add HITL and branch visualization.

**Gate:** deterministic seeded replay, branch isolation, budget enforcement, discarded-branch evidence, and selected-branch admission tests pass.

### P5 — Remote execution, release gates, exports, and anchoring

- Add remote leases/admission and one copied-data/canary worker path.
- Bind CI/release artifacts to assurance and claim evidence.
- Add portable bundle verification and a deterministic local anchor backend before any external anchor.

**Gate:** expiry/revocation/replay/conflict tests, third-party bundle verification, and anchor readback pass.

## Hard no list

- No MCP-owned internal object model.
- No adapter that bypasses native policy, sandbox, lifecycle, or receipts.
- No second memory/claim/procedure truth store.
- No material IDs derived from wall clock, process counters, or random UUIDs.
- No raw string template substitution for executable procedures.
- No flat default allowlist for high-effect capabilities.
- No caller-supplied identity treated as authorization.
- No “replay” that silently re-calls providers or tools.
- No UI, telemetry, or cache as authority.
- No subprocess delegation without attenuated authority, enforced budgets, cancellation, and child receipt closure.
- No search branch sharing mutable state or executing effects outside policy.
- No external result admitted because a remote/MCP server labels itself trusted.
- No public capability claim from compilation or happy-path unit tests alone.

## Immediate recommendation

First complete a bounded **P0 integrity and containment slice**: deterministic identity, terminal-state correctness, crash-safe ledger verification, truthful fail-closed sandboxing, and permit consumption. These are prerequisites, not parallel polish.

Then build the **native runtime + Hermes execution-backend vertical slice**. Use the native daemon as the shared operational boundary and the Rust SDK as the reference implementation/testing path. Integrate one real effect end to end without MCP. This proves the central architecture and creates the seam used later by Agent Graph, delegation, memory, TUI, CI, and remote workers.

Do not add more adapters until that slice passes negative policy, sandbox, timeout, cancellation, restart, receipt readback, and recorded-replay gates.

## Primary sources inspected

- Current repository `AGENTS.md`, `README.md`, `M0_REPORT.md`, manifests, and source files.
- Current `Libraries` source for `agent-graph`, `semantic-memory`, `llm-tool-runtime`, `authority-delegation`, `claim-ledger`, `remote-oracle-admission`, `assurance-runtime`, and `kernel-oracles`.
- Hermes Agent documentation:
  - <https://hermes-agent.nousresearch.com/docs/developer-guide/context-engine-plugin>
  - <https://hermes-agent.nousresearch.com/docs/developer-guide/plugins>
  - <https://hermes-agent.nousresearch.com/docs/user-guide/features/hooks>
  - <https://hermes-agent.nousresearch.com/docs/developer-guide/architecture>
  - <https://hermes-agent.nousresearch.com/docs/user-guide/features/memory>
