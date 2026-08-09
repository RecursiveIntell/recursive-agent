# Phase 1 Hostile Re-review

**Disposition:** REJECT  
**Date:** 2026-08-05  
**Mode:** read-only static inspection plus limited direct tests

The controller independently reproduced green formatting, Phase 1 package tests, full workspace tests, strict Clippy, diff check, production unsafe scan, and lint-override scan. Those results do not resolve the source defects below.

## Findings

### P0-1 — arbitrary launcher injection can forge `Enforced`

`recursive-agent-sandbox::execute_with_launcher` is public and accepts any executable path. Setup proof is a compile-time stderr marker; a fake executable can report a plausible version, ignore containment arguments, emit the marker, and receive an `Enforced` result.

**Fix:** remove production launcher injection; pin a trusted launcher/helper; use a trusted setup channel or proof that payload output cannot forge. Add a fake-launcher regression proving zero dispatch.

### P1-2 — filesystem policy has path-reopen races and undeclared runtime roots

Sandbox paths are canonicalized, then reopened later by Bubblewrap. Source replacement can redirect the bind. All of `/usr` is always readable even with no declared read roots, but that effective runtime dependency is absent from the policy/evidence digest.

**Fix:** pin mount sources/command by descriptor or equivalent stable capability; include effective runtime roots in the policy contract and evidence. Add replacement-loop and undeclared-runtime-root tests.

### P1-3 — permit budgets and time are bound but not enforced

Runner treats user-supplied frozen time as trusted lease time. Budget validation compares requested and stored bindings but does not meter elapsed time, output, artifacts, provider timeout, or delegate timeout during execution.

**Fix:** runner-owned trusted clock plus enforced execution limits mapped into every effectful executor. Add actual overrun tests with zero/terminated dispatch as appropriate.

### P1-4 — lifecycle verification is not expected-run-bound and accepts incomplete authorization sequences

The verifier enforces a single internally consistent run ID but does not accept/return the caller's expected run ID. A valid run-B chain can be transplanted to run A's directory. `PermitRejected`, `StepFailed`, and permit receipt outcomes lack exhaustive prior-state/outcome checks.

**Fix:** exhaustive receipt transition table and `verify_expected_run`; status/readback must bind expected run identity. Add transplant and impossible-sequence regressions.

### P1-5 — ledger lock identity and direct recovery remain incomplete

Each operation reopens `.ledger.lock` by name, so lock-entry replacement can split serialization. Metadata recovery occurs on `open`, while direct `verify` can reject stale metadata; crash tests call `open` first and mask the problem.

**Fix:** lock a stable pinned run-directory object and use one idempotent recovery routine for open, verify, replay, and status. Test lock-entry replacement and direct verify after every crash point.

### P1-6 — enabled memory path still mints wall-clock IDs; ID constructors are too generic

`memory_put` emits `mem:<wall-clock-nanos>` and is enabled in default policy/tool dispatch. `derive_step_id` accepts an unchecked string and `derive_permit_id` accepts any serializable value.

**Fix:** deterministic domain-qualified memory IDs, typed step derivation, and one typed complete permit identity material. Scan every enabled production crate.

### P1-7 — artifact and metadata reads can grow beyond bounds after size checks

`ArtifactStore::get` and descriptor metadata use unbounded `read_to_end` after a raceable metadata-length check. A concurrent writer can grow files after the check.

**Fix:** bounded streaming reads (`max + 1`) everywhere plus post-read checks. Test concurrent growth and partial-write recovery.

### P1-8 — invalid provider URLs can enter serializable/debug state before invocation validation

Provider variants publicly store raw URL strings and derive `Debug`/`Serialize`; custom deserialization does not validate. Userinfo/query sentinels are rejected only at `complete`, after they can enter evidence-bearing state.

**Fix:** validated URL newtype at construction/deserialization boundary; direct invalid construction impossible; redacted/safe formatting. Test deserialization, direct construction, serialization, and Debug.

## Sandbox host observation

The reviewer reproduced Bubblewrap 0.11.0 failing the default network namespace path with `NETLINK_ROUTE: Operation not permitted`. Fail-closed-only evidence is sufficient for the narrow negative portion of Phase 1 Task 1.6, but not for positive enforcement truth and it blocks Phase 2 Task 2.5.

The controller separately proved that the same Bubblewrap mount/PID/session containment succeeds on this host with `--share-net`. A safe path exists: share the host network namespace only when a maintained seccomp filter denies socket creation/use and hides host network `/proc` state. If filter generation, FD transfer, or loading fails, execution must fail closed. This is proposed remediation, not yet verified.

## Reproduced by reviewer

- sandbox hostile suite: exit 0, 7 tests
- fixed direct Bubblewrap probe: exit 1, network-namespace failure
- formatting and diff checks: exit 0
- production unsafe and lint-override scans: exit 0
- selected prebuilt pure tests passed; additional Cargo tests were blocked by the review sandbox's read-only target lock and are not claimed as locally reproduced by the reviewer

## Remaining gate

Phase 1 remains quarantined until all findings pass focused regressions, the positive sandbox action succeeds locally with network denied, the controller reruns all gates, and another hostile review admits the phase.
