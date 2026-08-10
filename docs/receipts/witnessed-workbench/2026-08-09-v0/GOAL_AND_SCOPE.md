# Witnessed Workbench v0 — bounded vertical-slice contract

**Evidence cutoff:** 2026-08-09, local checkout `recursive-agent` at `e644c46` before this pass.

## Goal

Prove one local, provider-free operator flow:

```text
Hermes native tool -> authenticated Recursive Agent daemon IPC -> RuntimeService
-> terminal run -> daemon-owned strict verification result -> operator-visible response
-> `ra pack export` -> copied pack -> offline `ra pack verify` and `ra pack replay`
```

The adapter is a transport and presentation boundary only. It must not mint a receipt reference, verification result, run identifier, pack manifest, artifact digest, or execution status.

## In scope

- Add a narrow read-only `verify` IPC request that exposes the RuntimeService's already-authoritative strict verification result for an existing run ID.
- Require the Hermes plugin to return only daemon-provided run ID, terminal state, and verification facts.
- Add cross-boundary tests for the daemon wire contract and real plugin-to-daemon flow.
- Make the plugin test invocation runnable from the repository without relying on accidental Python import behavior.
- Capture a local Run Pack proof through the existing CLI owner and document exact replay commands.

## Non-goals / forbidden changes

- No Gloss work, UI, MCP, Agent Graph, ClaimLedger/Mnemes/semantic-memory integration, provider/network execution, Hermes-core edits, new database, new durable evidence store, or adapter-owned pack export.
- Do not modify `/home/sikmindz/Coding/Libraries`.
- Do not stage, reset, clean, or alter pre-existing untracked work outside this run directory.
- Do not claim a packaged Hermes installation or a graphical Hermes invocation was live-tested unless it is actually exercised.

## Canonical ownership

| Surface | Canonical owner | Adapter constraint |
|---|---|---|
| Interaction/tool routing | Hermes | forwards one bounded request only |
| Native IPC parsing/authentication | `recursive-agent-daemon` | none |
| Execution, lifecycle, verification | `recursive-agent-runner::RuntimeService` | never recompute or invent |
| Receipt/artifact chain and Run Pack | ledger/runner/CLI crates | plugin only displays daemon facts |
| Portable pack export/verify/replay | `ra pack` CLI | invoked outside the adapter |

## Required invariants

1. The daemon validates every IPC request before runtime dispatch.
2. The daemon computes verification through `RuntimeService::verify`; no client-controlled verification value is admitted.
3. A plugin response is unavailable on malformed/missing daemon verification facts; it never substitutes `run:<id>` as proof.
4. Offline pack verification and replay consume only copied pack bytes and do not execute tools/providers.
5. Negative tampering remains rejected by the existing pack lane.

## Acceptance gates

1. `cargo fmt --all -- --check`
2. `cargo test -p recursive-agent-daemon --tests`
3. Hermetic plugin tests using the repository's explicit import mode.
4. Existing clean-process Run Pack gate: `scripts/verify-run-pack.sh`.
5. Full workspace test and Clippy gate, recorded with pass/fail/blocked state.
6. Read-only hostile review after implementation.

## Rollback

Revert only the files named in the final receipt. The IPC request addition is additive; rollback removes the `verify` variant/dispatch and its plugin client usage together. Preserve any generated run pack, logs, and receipts as evidence; do not delete them to conceal a failing gate.
