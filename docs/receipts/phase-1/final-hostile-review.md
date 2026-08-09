# Phase 1 Final Hostile Admission Review

**Verdict:** REJECT  
**Date:** 2026-08-05  
**Mode:** read-only static inspection and selected independent tests

## P0 findings

### P0-1 — current-owner helper can forge positive sandbox enforcement

The sandbox locates a sibling FD-hygiene helper beside the invoking executable and permits current-UID ownership. The helper sees the complete Bubblewrap argv and setup nonce; a malicious same-owner sibling can skip Bubblewrap, emit the nonce, run the payload directly, and cause `Enforced` evidence.

**Required fix:** remove the mutable helper trust path. Use a fixed root-owned/hash-pinned implementation and bind its identity. Test a malicious sibling that copies the nonce and attempts direct payload execution; it must be rejected with zero dispatch.

### P0-2 — Phase 1 shell callers can opt into the shared host network

Caller-controlled `allow_network` flows into permits. Policy does not reject it. The sandbox always shares host networking and omits seccomp when true.

**Required fix:** Phase 1 policy rejects `allow_network=true` before permit issue, with zero dispatch. Provider networking stays quarantined.

### P0-3 — quarantined effects remain independently callable

Public production APIs can invoke the sandbox from a bare spec, perform provider HTTP, spawn arbitrary MCP client commands, and mutate SQLite memory without runner identity/boundary/policy/permit/receipt prerequisites.

**Required fix:** compile out, make unavailable, or require a sealed runner-created authorization context on every effect entrypoint. Direct downstream calls must not execute.

## P1 findings

### P1-1 — failed or output-overrun shell commands can finalize successfully

Tools serialize a sandbox result without requiring exit code zero or zero dropped output. Runner can then emit `StepCompleted` and successful finalization.

**Required fix:** nonzero exit and any output truncation/dropped bytes become typed non-success terminal outcomes. Test `/usr/bin/false` and exit-zero excessive output.

### P1-2 — trusted lease time is sampled once and becomes stale

Runner samples its clock once and reuses that time across later issue/consume operations.

**Required fix:** sample trusted time at every issue, consume, parent validation, revoke, and terminal transition; bind execution to a monotonic deadline. An advancing fake clock must expire a parent between steps and prevent second dispatch.

### P1-3 — effective policy evidence omits pinned operation roots and submitted policy version

The sandbox policy digest binds runtime roots but not pinned declared read/write root identities/access modes. Runner does not compare submitted policy version with the active allowlist version.

**Required fix:** bind each pinned operation root and mode; reject policy-version mismatch before permit issue.

### P1-4 — strict lifecycle admits evidence-free success and exposes unbound verify

Successful step completion does not require an observed artifact. Permit issue/consume events need no typed permit evidence. Ledger still exposes strict expected-run-unbound verification.

**Required fix:** bind permit evidence and required observed artifacts into lifecycle verification. Authoritative public strict verification must require expected-run/directory identity.

### P1-5 — replay reopens an unbounded unverified receipt path

Replay verifies, releases that scope, then performs unbounded path-based receipt reading and projects newly read bytes without rechecking.

**Required fix:** verify and return a bounded receipt snapshot from the pinned ledger under the same lock; replay only that snapshot. Test concurrent replacement and growth.

### P1-6 — memory read boundaries are loose and lose identity provenance

Stored IDs return as raw strings, provenance used for identity is not persisted, and search silently drops row errors.

**Required fix:** domain-validating current memory ID, complete persisted provenance, recomputation at ingress, and typed corruption on any invalid row.

### P1-7 — endpoint paths can carry serializable/debug-visible secrets

Validated URLs reject userinfo/query/fragment but accept arbitrary path material and derive full Debug/Serialize.

**Required fix:** serializable endpoint identity permits only reviewed secret-free paths or separates nonserializable invocation paths. A path sentinel must be rejected or absent everywhere.

### P1-8 — four workspace crates do not inherit mandatory lints

Daemon, MCP, MCTS, and skills manifests omit `[lints] workspace = true`, weakening strict Clippy and allowing prohibited test `expect` calls.

**Required fix:** enable workspace lints in every member and remove all resulting violations. Add a mechanical manifest audit.

## P2 findings

1. `ra doctor` reports obsolete Phase/provider/Landlock claims; update it to exact candidate truth.
2. Skill names can traverse outside the configured root. This remains non-blocking only while skills are unavailable, but should be fixed with single-component IDs and descriptor-relative no-follow access.

## Independent gates

- formatting: passed
- workspace all-target tests: passed; reviewer reported 93 top-level tests, 0 failed, 0 ignored
- selected positive sandbox, network denial, transplant, direct crash verify, growing-read, and provider suites: passed; 12 tests
- diff check and production unsafe/lint-override/ignored-test/credential-sentinel scans: passed after correcting test-file exclusions
- strict Clippy: blocked by review sandbox read-only target, not independently reproduced
- manifest lint inheritance: failed for 4 crates
- cargo-deny: failed before checks because current `deny.toml` syntax is invalid; retained as Phase 11 blocker
- controller v3 manifest check: failed because the controller script hit its 50-tool-call cap after producing outputs but before writing the manifest; controller must repair this evidence packet

## Disposition

Phase 1 cannot advance until P0/P1 findings are fixed, focused regressions and the full controller matrix pass, and a hostile admission review returns ADMIT.
