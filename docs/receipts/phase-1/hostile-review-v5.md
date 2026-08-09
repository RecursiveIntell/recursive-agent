# Phase 1 Hostile Admission Review — Controller v6

**Verdict:** REJECT  
**Date:** 2026-08-05  
**Mode:** independent read-only static audit, retained-evidence verification, direct-binary subset

## Evidence binding

- Branch/HEAD: `main` at `3805f7abf319e07e47f1c20b862e614c3dad164f`.
- Live source-generation digest: `ff12c7988e287d3c7318e48b5e352316004807c3280e9ca7332468faf3950f18`.
- Live tracked binary-diff digest: `5326607be7cfba967b133ddabe6f01c9a293b7d5dd5935bb50d4ed6313d8a72e`.
- Both matched `controller-verification-v6/manifest.json`.
- All 36 command-output files matched their recorded SHA-256 values.
- Manifest: 14 required commands, 15 focused commands, 7 scans; all exit 0. Workspace receipt: 116 passing tests; focused gates: 75 passing tests.
- Independent `git diff --check`, exact-binary subset, and seven source scans passed.
- A fresh Cargo rebuild was blocked by the reviewer sandbox's read-only target lock. This was classified as an environment limitation, not a source failure.

## P1-1 — Child effect authority widens beyond its control parent

**Affected surface:** policy issuance/consumption, runner deadlines, strict ledger verification.

**Evidence:**

- Permit purpose distinguishes `Control` and `Effect`, but parent validation checks only state, IDs, and run equality.
- Lifecycle control permit defaults to 120 seconds. A child can request nearly 300 seconds under the global ceiling.
- The child deadline is independent; the parent deadline is checked only before issuance, while dispatch checks only the child deadline.
- Strict verification validates permits per step without parent-child attenuation.

**Consequence:** A shell child issued while the control permit is active can outlive it, consume a larger wall-time budget, complete after parent expiry, and still participate in a successful verified run.

**Minimum fix:** Enforce actor/policy/run/purpose linkage, child effect-scope subset, child expiry no later than parent expiry, cumulative budget no greater than parent remaining authority, and dispatch deadline `min(child, parent)`. Verify the relationship offline.

**Acceptance:**

- Wider/later child authority is denied with zero process starts.
- Parent expiry between consume and spawn yields zero dispatch.
- Crossing the parent deadline terminates the child and cannot finalize success.
- Fabricated widened/unrelated-parent chains fail append and every strict verifier.

**Quarantine:** Disable effect-child issuance or `shell` until attenuation is proven.

## P1-2 — Active run-spec ingress is unbounded and not strict canonical input

**Affected surface:** CLI run-spec input, daemon preparation, material run identity.

**Evidence:**

- CLI uses unbounded `read_to_string`, then direct Serde parsing.
- Run/step/tool-call structs do not reject unknown fields; arguments are unconstrained `serde_json::Value`.
- Active ingress does not use duplicate-key checking.
- Current-binary probes accepted unknown top-level input, duplicate nested `allow_network` keys using last-value semantics, and a spec prefixed with two MiB of whitespace.
- No explicit maximum step count or aggregate material budget exists.

**Consequence:** FIFOs/devices/huge files or step lists can consume unbounded resources; duplicate/unknown-field parser differentials occur before material-ID derivation.

**Minimum fix:** One shared bounded duplicate-checking RunSpec parser with regular-file input, maximum bytes/steps/aggregate material, closed V1 fields, and strict tool-specific argument schemas. CLI and future daemon ingress must share it.

**Acceptance:** Oversized whitespace, FIFO/device, unknown fields, nested duplicates, excess steps, and excess aggregate material reject before run-directory creation or dispatch.

**Quarantine:** Disable external JSON run ingress until the parser passes.

## P1-3 — Pinned executable identity does not bind executable bytes

**Affected surface:** runner-private shell dispatch and enforcement evidence.

**Evidence:**

- Command identity contains path/device/inode/owner/mode/kind, but no content digest or immutable-byte proof.
- Pre-spawn revalidation compares the same metadata identity.
- Trusted-executable ownership/mode checks apply to Bash/Bubblewrap, not the requested command.
- Bubblewrap binds the live descriptor and executes its path.

**Consequence:** A writable executable can be modified in place or through a hard link after authorization while retaining inode/owner/mode, so different bytes execute under the original permit and evidence.

**Minimum fix:** Restrict commands to trusted non-writable executables and bind a digest of the opened executable bytes into action/effect authorization and enforcement evidence, or copy into a sealed immutable execution object.

**Acceptance:** Same-inode and hard-link mutation either executes exactly the authorized digest or rejects with zero dispatch. Successful evidence contains the executed-byte digest.

**Quarantine:** Fixed trusted executable allowlist or disable shell until byte sealing is proven.

## P2 — Later-phase surfaces remain public or mislabeled

- MCP still publicly exports a stdio server with unbounded line input, direct Serde parsing, and receipt-free echo dispatch, despite CLI command removal.
- Daemon `prepare_response` is documented as pure but calls `run_spec` and can create runs/launch shell work.
- Skill and random `Mcst` prototype APIs remain public, although unreachable through the Phase 1 allowlist.

**Minimum fix:** Remove/default-private-gate MCP serving and execution-capable daemon preparation until their scheduled phases. Keep only pure protocol/data contracts; use compile-fail/source tests for quarantine.

## Confirmed fixes

- Real process execution and `DispatchToken` are runner-private, by-value, and non-Clone/non-Serde.
- CLI non-success exits and operation envelopes are truthful.
- Ledger/artifact/permit stores share one descriptor-relative pinned root in the canonical runner.
- Provider HTTP, MCP client spawn, memory mutation, delegation, and skill execution are unreachable through the Phase 1 allowlist.
- Provider secrets remain non-serializable and execution unavailable.
- No production unsafe, lint override, ignored test, panic, unwrap, or expect escape was found.
- Sandbox scope remains Linux/Bubblewrap/seccomp-specific.

**Disposition:** Phase 1 and all later phases remain quarantined.