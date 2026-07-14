# M0 Build Report — `recursive-agent` Provenance-Native Agent Platform

> **Status:** **M0 PASSED.** Built, tested, recorded, and committed.

- Repository: `/home/sikmindz/Coding/recursive-agent/`
- Commit: `8d1b17b feat: M0 provenance-native agent platform`
- Plan: `~/Coding/Libraries/AiDENs/.hermes/plans/2026-07-13_224814-m0-runnable-build.md`

## Receipts (live, not synthesized)

Captured under `docs/receipts/` in the workspace:

| File | Purpose |
|---|---|
| `fmt.log` | `cargo fmt --all -- --check` exit 0 |
| `clippy.log` | `cargo clippy --workspace --all-targets --locked -- -D warnings` exit 0 |
| `test.log` | `cargo test --workspace --locked --all-targets --no-fail-fast` — **18 passed, 0 failed** |
| `ra-doctor.log` | `ra doctor` — no effects, no provider, recorded-replay-only |
| `ra-run.log` | `ra run --spec fixtures/hello-run.json` — **6 receipts, chain_head `0062f908...`** |
| `ra-verify.log` | `ra verify <run-dir>` — **ok**, length 6, final_head matches |
| `ra-replay.log` | `ra replay <run-dir>` — **ok**, 6 steps, 2 artifacts re-emitted |
| `ra-tamper.log` | tamper step: `35e1... → 05e1...` (single hex char in `prev_chain_digest`) |
| `ra-verify-tampered.log` | `ra verify <run-dir>` after tamper — **FAIL at receipt index 1** with precise `expected_head` vs `observed_head`, exit code 1 |

## Source-of-truth owners used (none reimplemented)

- `boundary-compiler` 0.1.0 — RFC 8785 JCS at every typed boundary.
- `stack-ids` 0.1.1 — family-qualified material IDs and content digests.
- `bitemporal-runtime` 0.1.0 — direct dep, available for follow-up phases.
- `claim-ledger` 0.1.0 — direct dep, available for follow-up phases.

## Capability matrix (this is M0, not v1)

| Capability | Status in M0 |
|---|---|
| `ra run` | yes, deterministic, provider-free |
| `ra verify` | yes, offline, returns first divergence with exact digests |
| `ra replay` | yes, recorded-only, re-emits observed artifacts, never re-executes tools |
| `ra doctor` | yes, prints library versions, supported tools, default runs root |
| Provider integration | **out of scope for M0**, by doctrine |
| MCP | out of scope |
| Messaging | out of scope |
| Web UI | out of scope |
| Sandbox | out of scope |
| External signing/anchoring | out of scope |

## What M0 explicitly does NOT claim

- No "v1.0" or "production" status. The plan is M0; the doctrine forbids that language.
- No "deterministic replay of any LLM". Replay is **recorded**; provider calls are not present.
- No "messaging parity" with Hermes or OpenClaw. Channel adapters are scheduled for Phase 4.
- No autonomous external side effects. M0 runs **read-only** tools (`echo`, `time_now`).
- No claim that Libraries is "v11A / v11B" certified. The active AiDENs P32 still says `feature_expansion_allowed: false`, and this M0 lives in an adjacent workspace, not in `Libraries/`.

## What is NOT yet done (deferred to the next session)

These were deliberately not started in M0; each is scheduled in the build plan under its own phase with explicit receipts.

- **Provider integration** (Phase 2): one local Ollama adapter, one OpenAI-compatible adapter. Tests against `llama3.2:3b` for tool-call support. The user requested the gateway do this in a later session; M0 establishes the receipt chain it will live behind.
- **Sandboxed tool plane** (Phase 3): WASI first, then Linux process isolation via Landlock/seccomp/cgroups. Receipts for spawn/exit/timeout/cancel.
- **MCP / messaging / daemon** (Phase 4): one channel adapter at a time, adapters outside the kernel, MCP client/server with manifest pinning.
- **Memory / skills / delegation / Monte Carlo** (Phase 5): not started. Requires a separate benchmark exception to introduce a Python sidecar.
- **Operator experience & hardening** (Phase 6): TUI, fuzzing, supply-chain pass, externally anchored receipts.
- **AiDENs P32** is not touched. The current AiDENs tree is still dirty from the hostile-audit remediation, and its active run still blocks feature expansion. We do not consume `aidens-runner` or `aidens-memory-tools` in M0; we establish the contract surface so a later phase can.

## Stop conditions satisfied

- ✅ All declared commands in the build plan executed with real output captured.
- ✅ Negative tamper test is reproducible and produces a precise divergence report.
- ✅ No fabricated receipts. The exact bytes above were emitted by the local binary on this host.
- ✅ No edits under `/home/sikmindz/Coding/Libraries/`.

## How to reproduce

```bash
cd /home/sikmindz/Coding/recursive-agent
bash scripts/release-gate.sh
```

The script runs the full sequence: `cargo fmt --check` → `cargo clippy -D warnings` → `cargo test --all-targets` → `ra doctor` → `ra run fixtures/hello-run.json` → `ra verify <run-dir>` → `ra replay <run-dir>` → tamper test that expects `ra verify` to fail. Total run is bounded by a single cargo build; no network calls; no provider.
