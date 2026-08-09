# Auditable Run Pack v1 Proof Sprint — Implementation Plan

> **For Hermes:** Execute only after explicit implementation authorization. Use the existing `recursive-agent-checkpoint-and-next-gate-20260809` Agent Graph for planning/review work unless a fresh topology is demonstrably necessary.

**Status:** Proposed; planning-only. This document authorizes neither implementation nor commits, pushes, releases, services, profile changes, provider credentials, or network effects.

**Goal:** Prove one bounded local Recursive Agent workflow can be exported as a self-contained, tamper-evident pack that independently verifies and performs recorded-evidence replay from a clean process with no original run directory, provider, tool, MCP, scheduler, or network access.

**Architecture:** `recursive-agent-ledger` remains the authoritative owner of receipt-chain and artifact verification; `recursive-agent-policy` remains the authority/permit owner; and `recursive-agent-runner` remains lifecycle owner. The Run Pack is an **additive, immutable export projection** of already-verified canonical evidence. It must not become a second ledger, scheduler, lifecycle machine, authorization engine, or adapter-owned semantics.

**Tech stack:** Rust workspace; `recursive-agent-contracts`, `recursive-agent-ledger`, `recursive-agent-runner`, `recursive-agent-policy`, `recursive-agent-cli`; `boundary-compiler` JCS; `stack-ids`; existing CLI integration-test conventions.

---

## 1. Current-state verdict and evidence baseline

**Observed 2026-08-09**

- Repository: `/home/sikmindz/Coding/recursive-agent`
- Branch: `main`, 11 commits ahead of `origin/main`; `HEAD=2ae62bd` (`test(child-runs): certify semantic link matrix`).
- The tracked tree was clean at observation. Untracked `.hermes/runs/`, receipt directories, a permit lock, and Python caches existed. They are **not** eligible for automatic staging or inclusion in this sprint.
- `AGENTS.md` requires provider-free M0 behavior, canonical JCS boundaries, family-qualified IDs, no false completion, and offline verification/replay.
- Existing CLI surfaces: `ra run`, `ra verify`, `ra replay`, `ra doctor` (`crates/recursive-agent-cli/src/main.rs`). Existing CLI tests already cover embedded execution, direct verification after stale metadata, terminal exit semantics, and hostile ingress.
- Recent Phase 7.2B live-parent/child lifecycle commits are source/test evidence for admission ordering, cancellation, tamper rejection, and child closure. They are **not this sprint’s feature target**. Preserve their semantics and V1 behavior.
- The Phase 7.2B evidence packet needs a separate status reconciliation before a broad formal completion claim. This plan treats it as source-complete but status-evidence-pending.

**Source inventory checked**

- `AGENTS.md`
- `README.md`
- `.hermes/plans/2026-08-04_221835-recursive-agent-total-remediation-plan.md`
- `crates/recursive-agent-cli/src/main.rs`
- `crates/recursive-agent-cli/tests/direct_crash_verify.rs`
- `crates/recursive-agent-cli/tests/embedded_runtime_tools.rs`
- `crates/recursive-agent-cli/tests/terminal_exit.rs`
- `crates/recursive-agent-cli/tests/hardening_v5_ingress.rs`
- `crates/recursive-agent-runner/tests/phase2_runtime_service.rs`

**Verdict:** The repository has the necessary substrate—canonical receipt chain, content-addressed artifacts, offline verify/replay, runtime lifecycle, permits, and child links—but no first-class portable pack contract. The highest-ROI proof is an additive Run Pack, not broader autonomy, provider integration, UI, MCP, or deployment.

---

## 2. Product boundary

### In scope

A Run Pack exported from exactly one already-completed local run:

```text
<pack-root>/
├── PACK_MANIFEST.json
├── OPERATOR_REPORT.json
├── receipts.ndjson
├── chain.meta
├── artifacts/
├── verification/
│   ├── VERIFY_RESULT.json
│   ├── REPLAY_RESULT.json
│   └── NEGATIVE_CASES.json
└── provenance/
    ├── SOURCE_PROVENANCE.json
    └── TOOLCHAIN.json
```

- Exact historical copies of canonical receipt bytes, chain metadata, and referenced artifact bytes.
- Canonical manifest/result/provenance schemas with deterministic, bounded fields.
- Pack-only verification and recorded-evidence replay in a fresh process.
- Positive and destructive negative cases: manifest tamper, receipt tamper, artifact tamper, path escape/symlink, missing/extra file, and child-closure/link conflict where child evidence is present.
- A descriptive, non-authoritative operator report.

### Explicitly out of scope

- Providers, credentials, provider-backed replay, MCP, Hermes activation, remote workers, service deployment, UI, hosted/multi-tenant operation, external anchoring/signing, memory/skills/search expansion, new scheduler semantics, and generic autonomous-agent behavior.
- Any rewrite, normalization, sort, truncation, migration, or repair of historical receipts/artifacts.
- New authority or lifecycle semantics. A pack export cannot alter run state.
- Claiming production readiness, security certification, deterministic LLM replay, or market validation.

---

## 3. Contract and invariant lock

### 3.1 Canonical ownership

| Concern | Canonical owner | Pack responsibility | Forbidden behavior |
|---|---|---|---|
| Receipt chain / artifact bytes | `recursive-agent-ledger` | Copy and invoke ledger verification | Reimplement or reinterpret chain rules |
| Run/child lifecycle | `recursive-agent-runner` | Read only verified terminal evidence | Infer success from report/exit status |
| Permit/authority | `recursive-agent-policy` | Include only canonical, manifest-bound evidence | Re-adjudicate or mint permits |
| Schema / boundary canonicality | contracts + `boundary-compiler` | Define exported schemas and JCS bytes | Ad hoc JSON serialization as authority |
| CLI UX | `recursive-agent-cli` | Thin export/verify/replay translation | Own verification/lifecycle semantics |

### 3.2 Required invariants

1. Pack creation begins only after authoritative run verification succeeds.
2. Pack verification begins by validating manifest bytes and then delegates receipt/artifact validation to admitted ledger owners.
3. The manifest binds every included file by safe relative path, byte size, content digest, role, and schema/version where applicable.
4. The pack contains no unreferenced non-directory files and no manifest-referenced missing files.
5. Every path is relative, normalized, contained under pack root, and a regular file; symlinks, devices, FIFO/socket paths, duplicate normalized paths, and traversal are rejected.
6. `receipts.ndjson`, `chain.meta`, and artifact bytes are copied exactly. The manifest/report never substitute for authoritative records.
7. Pack-only replay first verifies the pack and then reads only packed evidence. It must not invoke tools, providers, MCP, schedulers, or network access.
8. Success is not inferred from CLI exit status, `OPERATOR_REPORT.json`, parent terminal status alone, or child descriptor presence. Canonical strict verification and required child closure dominate.
9. V1 run/verify/replay semantics and current Phase 7.2B admission ordering remain unchanged.
10. Export failure leaves the source run untouched and removes/quarantines only the incomplete destination pack.

### 3.3 Discovery gate—do not invent a second schema family

Before naming types, inspect existing public contracts and ledger APIs for export manifests, file descriptors, verification reports, and run identities. Evolve an existing owner/type if it owns the same boundary; create `RunPackManifestV1` only after recording a field-level overlap matrix and a rejection reason for every candidate owner.

Evidence: `docs/receipts/phase-5/task-5.5-run-pack/discovery-owner-matrix.md`.

Abort if the proposed pack type duplicates an existing authoritative receipt/manifest family.

---

## 4. Ordered implementation tasks

All code tasks use RED → minimal GREEN → focused regression. Do not stage or commit while executing this plan unless a separate commit authority is supplied.

### Task 0: Freeze the sprint baseline and quarantine foreign artifacts

**Objective:** Capture current source and gate state before modifying behavior.

**Files:**
- Create: `docs/receipts/phase-5/task-5.5-run-pack/preflight/MANIFEST.json`
- Create: `docs/receipts/phase-5/task-5.5-run-pack/preflight/{git-status.txt,git-head.txt,toolchain.txt}`

**Steps:**
1. Capture `git status --porcelain=v1`, `git rev-parse HEAD`, `git diff --binary`, and `cargo --version`/`rustc --version`.
2. Record every pre-existing untracked path as excluded, without deleting it.
3. Run the baseline gate bundle.

**Commands:**
```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

**Expected:** Exit 0, or an exact failed/blocked receipt. Never convert a failed command to a pass.

**Rollback:** Delete only the incomplete preflight receipt directory; never remove pre-existing user artifacts.

---

### Task 1: Reconcile the Phase 7.2B status discrepancy

**Objective:** Prevent the new pack from inheriting contradictory status language.

**Files:**
- Create: `docs/receipts/phase-7/task-7.2-child-runs/contract-amendment-20260809/STATUS_RECONCILIATION.md`
- Test/inspect: `crates/recursive-agent-runner/tests/phase2_runtime_service.rs`

**Steps:**
1. Run the named test matrix and cite source commit and receipt packet paths.
2. Compare source/test evidence with `PHASE_7_2B_BLOCKED.md`, `CHANGE_RECEIPT.json`, `PACKET_MANIFEST.json`, and `VALIDATION_MATRIX.csv`.
3. Mark each statement as historical, superseded, source-proven, evidence-proven, or still blocked. Do not rewrite old evidence.

**Command:**
```bash
cargo test -p recursive-agent-runner --test phase2_runtime_service
```

**Expected:** Existing focused matrix passes unchanged. A discrepancy is a documentation/evidence issue, not a reason to modify lifecycle logic.

**Abort:** If source and test evidence conflict on terminal/authority semantics, stop the Run Pack sprint and open a separate remediation plan.

---

### Task 2: Inventory the existing owner surface and lock the pack schema

**Objective:** Choose the smallest authoritative extension path.

**Files:**
- Modify (only after discovery): `crates/recursive-agent-contracts/src/lib.rs` **or** the existing canonical owner identified by Task 2
- Create: `docs/receipts/phase-5/task-5.5-run-pack/discovery-owner-matrix.md`
- Create: `crates/recursive-agent-contracts/tests/run_pack_contract.rs` (if contracts owns the pack boundary)

**RED:** Add a contract test that rejects a manifest missing `schema_version`, source run identity, file role, size, digest, or safe relative path; also reject duplicate normalized paths and unsupported schema version.

**GREEN:** Add the smallest versioned schema, e.g. `RunPackManifestV1`, `RunPackFileEntryV1`, `PackVerificationResultV1`, and `RecordedReplayResultV1`, with boundary/JCS validation through the admitted owner. The exact names are discovery-gated.

**Focused commands:**
```bash
cargo test -p recursive-agent-contracts --test run_pack_contract
cargo test -p recursive-agent-contracts
```

**Evidence:** `docs/receipts/phase-5/task-5.5-run-pack/task-2-schema/{red.txt,green.txt,owner-matrix.md}`.

**Rollback:** Revert only the new schema/test files if they duplicate an owner; retain the discovery matrix.

---

### Task 3: Add a ledger-owned, read-only export plan

**Objective:** Derive an exact pack file set from verified canonical run evidence without writing files yet.

**Files:**
- Modify: `crates/recursive-agent-ledger/src/lib.rs`
- Test: `crates/recursive-agent-ledger/tests/run_pack_plan.rs`

**RED:** Given a known valid run root, assert planning fails for an unverified/stale/tampered run and returns a deterministic ordered file plan only for a verified run.

**GREEN:** Add a read-only `plan_run_pack(...)`-equivalent API in the ledger owner. It must use existing run identity, receipt verification, artifact descriptors, and strict child evidence rather than scanning arbitrary files.

**Focused commands:**
```bash
cargo test -p recursive-agent-ledger --test run_pack_plan
cargo test -p recursive-agent-ledger
```

**Acceptance:** Output identifies only canonical receipts, metadata, referenced artifacts, and pack-generated result/provenance placeholders. It contains no outside path and no scheduler/adapter-owned state.

**Rollback:** Delete the new projection API if it needs to bypass ledger verification or introduce runner-owned byte copying.

---

### Task 4: Export exact bytes into a transactional destination

**Objective:** Materialize a pack only after source verification and prevent incomplete packs from appearing valid.

**Files:**
- Modify: `crates/recursive-agent-ledger/src/lib.rs`
- Test: `crates/recursive-agent-ledger/tests/run_pack_export.rs`

**RED:** Tests must prove export rejects: source run verification failure; pre-existing non-empty destination; destination symlink; artifact symlink; a referenced artifact that changes between validation and copy; injected copy/rename failure.

**GREEN:** Implement export through a same-parent temporary directory with restrictive permissions, byte-copy-and-redigest each planned source file, write canonical generated files, fsync required file/directory boundaries, validate the completed temp pack, then atomically rename. The exact durability primitives must reuse established ledger patterns where they already exist.

**Focused commands:**
```bash
cargo test -p recursive-agent-ledger --test run_pack_export
cargo test -p recursive-agent-ledger --test crash_recovery
```

**Evidence:** `docs/receipts/phase-5/task-5.5-run-pack/task-4-export/{red.txt,green.txt,failpoint-matrix.csv}`.

**Rollback/quarantine:** Remove only the temp/incomplete destination. Never mutate the source run or repair copied bytes in place.

---

### Task 5: Verify a pack solely from pack bytes

**Objective:** Prove portability and tamper detection without source-run dependence.

**Files:**
- Modify: `crates/recursive-agent-ledger/src/lib.rs`
- Test: `crates/recursive-agent-ledger/tests/run_pack_verify.rs`

**RED:** Add one test each for receipt tamper, chain metadata tamper, artifact tamper, manifest tamper, missing entry, extra file, duplicate path, `../` path, absolute path, symlink, and child-link/closure semantic conflict. Each must fail with a typed/localized reason and no panic.

**GREEN:** Implement `verify_run_pack(...)`-equivalent in the ledger owner. It validates pack filesystem safety and manifest bindings, reconstructs a temporary/admitted read-only view if needed, and delegates authoritative receipt/artifact/strict-link verification to the existing verifier. It must not consult original run paths or live runtime state.

**Focused commands:**
```bash
cargo test -p recursive-agent-ledger --test run_pack_verify
cargo test -p recursive-agent-ledger --test artifact_tamper
```

**Acceptance:** A pack copied to a fresh temporary root verifies after the original run root is made unavailable to the test process.

**No-go:** Any verifier that trusts `OPERATOR_REPORT.json` or source-run fallback is rejected.

---

### Task 6: Add explicit recorded-evidence pack replay

**Objective:** Make replay machine-readable and unable to re-execute effects.

**Files:**
- Modify: `crates/recursive-agent-runner/src/lib.rs` only if current `replay` API cannot accept a verified pack view
- Modify: `crates/recursive-agent-ledger/src/lib.rs` for verified pack view, if needed
- Test: `crates/recursive-agent-runner/tests/run_pack_replay.rs`

**RED:** A fake provider/tool/MCP/scheduler invocation counter must remain zero during pack replay. Replay must reject invalid/incomplete packs and emit `unavailable` rather than fallback/re-execution.

**GREEN:** Reuse the existing recorded-evidence replay behavior through a verified pack input. Emit a stable canonical `REPLAY_RESULT.json` with mode=`recorded_evidence`, source run identity, verification digest/reference, terminal classification, and artifact references.

**Focused commands:**
```bash
cargo test -p recursive-agent-runner --test run_pack_replay
cargo test -p recursive-agent-runner
```

**Rollback:** Revert any change that makes replay call an executor, provider, network client, or scheduler.

---

### Task 7: Keep the CLI a translator; expose explicit pack commands

**Objective:** Provide an operator path without moving evidence semantics into the CLI.

**Files:**
- Modify: `crates/recursive-agent-cli/src/main.rs`
- Create: `crates/recursive-agent-cli/tests/run_pack_cli.rs`
- Modify: `README.md` only after all acceptance gates pass

**RED:** CLI tests require:
- `ra pack export --run <run-dir> --out <empty-destination>` produces valid JSON summary with pack path and manifest digest/reference;
- `ra pack verify --pack <pack-root>` returns non-zero and typed stderr on tamper;
- `ra pack replay --pack <pack-root>` produces only recorded evidence;
- no command accepts a path that aliases outside the requested root;
- existing `ra verify` and `ra replay` remain behaviorally unchanged.

**GREEN:** Add thin subcommands that parse paths, call ledger/runner owners, and render their authoritative result. Do not duplicate digest, receipt, policy, or lifecycle code.

**Focused commands:**
```bash
cargo test -p recursive-agent-cli --test run_pack_cli
cargo test -p recursive-agent-cli --test direct_crash_verify
cargo test -p recursive-agent-cli --test terminal_exit
```

**Claim boundary:** CLI output is a rendering of verified result, not evidence by itself.

---

### Task 8: Bind provenance and negative-case evidence without making reports authoritative

**Objective:** Make the proof independently inspectable.

**Files:**
- Modify: canonical pack export owner identified in Tasks 2–5
- Create: `crates/recursive-agent-ledger/tests/run_pack_provenance.rs`
- Create: `docs/receipts/phase-5/task-5.5-run-pack/negative-case-matrix.md`

**RED:** Test that changing `OPERATOR_REPORT.json`, `SOURCE_PROVENANCE.json`, or `TOOLCHAIN.json` without a matching manifest update fails verification; test that a report claiming success cannot override a failed terminal/verification result.

**GREEN:** Generate canonical, manifest-bound descriptive documents. Required provenance fields: pack schema, source run ID, source verification outcome/ref, source commit/diff state supplied by the caller or explicitly `unknown`, Rust/Cargo version, command argv, and timestamp classification. Machine/path-specific values must be explicitly labeled volatile and must not alter canonical source evidence.

**Commands:**
```bash
cargo test -p recursive-agent-ledger --test run_pack_provenance
cargo fmt --all -- --check
```

---

### Task 9: Clean-process acceptance drill

**Objective:** Prove the product claim from a fresh process and controlled filesystem layout.

**Files:**
- Create: `scripts/verify-run-pack.sh` only after the script contract is reviewed
- Create: `crates/recursive-agent-cli/tests/run_pack_clean_process.rs`
- Create: `docs/receipts/phase-5/task-5.5-run-pack/acceptance/<run-id>/{MANIFEST.json,HANDOFF.md,...}`

**Protocol:**
1. Start from a clean controlled worktree, separate clean process, and empty temporary run/pack roots.
2. Run one deterministic fixture through `ra run` with the embedded runtime.
3. Run normal `ra verify`.
4. Export the pack.
5. Copy only the pack to a fresh root and remove/revoke test-process access to the original run root.
6. Run pack verify and pack replay from the fresh root.
7. Execute every negative mutation against separate pack copies; capture command, exit code, stderr/stdout digest, and localized failure classification.
8. Verify no provider/network/tool/scheduler call counter was touched during pack verification/replay.
9. Record `git status --porcelain=v1` before/after and prove no foreign untracked artifact was absorbed.

**Commands:**
```bash
cargo test -p recursive-agent-cli --test run_pack_clean_process
./scripts/verify-run-pack.sh
```

**Expected:** Green only if all positive and negative scenarios meet their stated contract. Missing sandbox/provider/network guard instrumentation is `BLOCKED`, not a pass.

---

### Task 10: Full gate, hostile review, and truthful documentation

**Objective:** Certify only the tested local proof boundary.

**Files:**
- Modify: `README.md`
- Create: `docs/capability-status.md` entry or existing status owner update
- Create: `docs/receipts/phase-5/task-5.5-run-pack/closeout/{MANIFEST.json,HANDOFF.md,ROLLBACK.md}`

**Commands:**
```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p recursive-agent-ledger --test run_pack_plan
cargo test -p recursive-agent-ledger --test run_pack_export
cargo test -p recursive-agent-ledger --test run_pack_verify
cargo test -p recursive-agent-runner --test run_pack_replay
cargo test -p recursive-agent-cli --test run_pack_cli
cargo test -p recursive-agent-cli --test run_pack_clean_process
```

**Review gate:** Conduct a read-only hostile review of changed contracts, ledger logic, CLI translation, path handling, race/failpoint behavior, and claim language. Review must cite live file/line evidence and distinguish static inspection from executed gates.

**Allowed claim after all gates pass:**

> Auditable Run Pack v1 has been proven for the recorded local test matrix: an exported bounded run pack is content-addressed, offline-verifiable, recorded-evidence-replayable, and rejects the documented tamper cases. This does not establish production readiness, provider-backed execution/replay, remote execution, deployment support, or general security certification.

**Rollback:** Revert source/docs introduced by the sprint; preserve the failed/positive receipt bundle. Do not delete source-run evidence or rewrite historical pack bytes.

---

## 5. Threat and risk matrix

| Threat / failure | Consequence | Primary control | Proof |
|---|---|---|---|
| Pack is a second truth store | Semantic drift / false verification | Ledger-owned export/verify only | Owner matrix + no duplicate chain logic |
| Receipt or artifact changes during export | Pack lies about source state | Verify-before-plan, copy-redigest, atomic publish | mutation/failpoint test |
| Manifest/report trusted over receipts | False success | Canonical chain/lifecycle verification dominates | report-tamper test |
| Path traversal/symlink/device | Host-file read or confused evidence | strict contained regular-file validation | hostile path matrix |
| Original run still consulted | Not portable | clean-process, source-root-unavailable test | clean-process gate |
| Replay re-executes effect | Unexpected side effect | verify-first recorded replay, zero-call counters | provider/tool/MCP/scheduler denial test |
| Parent closes before child proof | False terminal success | reuse strict Phase 7.2B link/closure validation | semantic child tamper test |
| V1 regression | Breaks existing consumers | retained V1 CLI/test matrix | pre/post existing tests |
| Incomplete pack published | Later false verification | temp root + validate + atomic rename | injected failure matrix |
| Documentation outruns evidence | Misleading product claim | evidence-linked capability update | claim review gate |

---

## 6. Sprint gates and no-go criteria

### Entry gate

- Baseline receipts exist, including dirty/untracked exclusion list.
- Phase 7.2B discrepancy is classified without rewriting prior evidence.
- Owner overlap matrix names one authoritative export/verification location.

### Exit gate

- All Task 10 commands exit 0.
- A pack verifies from a fresh root with the original run unavailable.
- Recorded replay has zero provider/tool/MCP/scheduler/network calls by direct test instrumentation.
- Each listed destructive test fails non-zero with a typed/localized reason.
- No new authority, scheduler, adapter lifecycle, or silent fallback exists.
- `git diff --check` is clean and closeout identifies every changed file, command, command exit, skipped/blocked gate, risk, evidence path, and rollback procedure.

### Immediate no-go / quarantine

Stop and quarantine the active change if any one occurs:

- Pack verification consults source run, runtime state, or ambient filesystem outside pack root.
- Any replay path executes a tool/effect or performs network/provider access.
- A failed/cancelled/denied/tampered child or parent can produce pack success.
- A manifest/report can override canonical evidence.
- A path traversal/symlink is accepted.
- The implementation needs to weaken V1 semantics or bypass current strict child verification.
- The source evidence must be rewritten to make export work.

---

## 7. Migration and compatibility

- Existing run directories and `ra verify`/`ra replay` remain unchanged.
- Export supports only the explicitly admitted current source schema at first. Unsupported/legacy evidence yields typed `unsupported_schema` or `unavailable`; it is never silently upgraded.
- Pack schema readers must reject unknown required semantics and may ignore only explicitly declared, non-authoritative additive fields.
- Future signing, anchoring, compression, retention, provider output, remote workers, and UI consume the pack as a projection and must not make it an authority.

---

## 8. 30 / 60 / 90 day follow-on sequence

### Days 0–30 — complete this proof

- Finish the Run Pack v1 acceptance matrix for one bounded embedded workflow.
- Reconcile Phase 7.2B status evidence.
- Produce the auditor-rerunnable closeout.

**Decision gate:** no second workflow until clean-process pack verification/replay and destructive cases pass.

### Days 31–60 — harden the existing proof

- Add bounded scenario fixtures for policy deny, failure, timeout, interruption, cancellation, retry, and supported recovery.
- Add predeclared crash/failpoint coverage around export publication and metadata projections.
- Add a second independently structured local workflow only if it reuses all canonical owners unchanged.

**Decision gate:** expand only when the second workflow requires no new authority store and has no evidence/lifecycle ownership conflict.

### Days 61–90 — choose one adjacent product wedge

Choose exactly one, based on source-backed demand discovery:

1. policy-gated internal automation for a narrowly defined workflow, **or**
2. replay/regression bundles for repository/agent-runtime tests.

Provider integration, MCP/Hermes exposure, remote execution, UI, and hosted services remain separate plans with their own admission, threat model, and external-effect approval.

---

## 9. Graph orchestration receipt

**Reuse decision:** Existing graph `recursive-agent-checkpoint-and-next-gate-20260809` was listed and reused rather than creating a new graph. It matched the planning/review topology and avoided the Agent Graph registry capacity issue.

**Run:** `run-19fe8bf4a24-a` on graph version `sha256:00e2fb6592533904536eed8f707d90974b5042c9363794cc135a16b3e45aff89`.

**Observed execution:** 7 nodes, 5 LLM calls, 145,913 ms. Its output is a planning aid with `structural_unverified` evidence authority, not independent source validation. The plan above treats all graph-specific proposals as subject to the stated live-source discovery gates.
