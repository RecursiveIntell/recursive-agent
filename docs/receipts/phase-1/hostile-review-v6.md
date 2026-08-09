VERDICT: REJECT

Audit time: `2026-08-05T11:07:34Z`  
Snapshot: `main` at `3805f7abf319e07e47f1c20b862e614c3dad164f`  
Worktree: dirty — 18 tracked modifications, 390 untracked files, 408 entries total. No repository files were modified by this audit.

Controller-v9 integrity: all 36 retained output hashes matched; independently recomputed source-generation digest `85e7aed...e943` and tracked-diff digest `b7a38853...2277`, both matching the manifest. These establish evidence identity, not admission. Controller-v8 was also compared; v9 adds one runner test, increasing runner tests 34→35.

## Blocker disposition

| Area | Disposition |
|---|---|
| 1. Attenuation/allocation | **PARTIAL; BLOCKED** — durable cumulative reservation and offline attenuation are present, but parent loss immediately after spawn leaves a running, unreaped payload. |
| 2. External run-spec ingress | **BLOCKED** — byte, duplicate, unknown-field, and file-type checks exist; semantic/cardinality/depth closure and valid multi-step boundary behavior remain defective. |
| 3. Exact executable/path chain | **BLOCKED** — descriptor hashing/mounting and `ParentDir`/`CurDir` rejection are present, but inherited launcher environment and FD handling bypass them. |
| 4. Adapter quarantine/ownership | **PASS for Phase 1** — no reachable daemon/MCP/provider/skill/MCTS effect adapter found. |
| 5. Other P0/P1 bypasses | Four concrete blockers below; no additional admission blocker established. |

## P0-1 — Caller environment executes before Bubblewrap

Evidence: the runner starts descriptor-pinned Bash with `--noprofile --norc` but never clears its environment ([sandbox_engine.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-runner/src/sandbox_engine.rs:1031)); that command is then spawned unchanged ([sandbox_engine.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-runner/src/sandbox_engine.rs:764)). The setup nonce is included later in the Bash arguments ([sandbox_engine.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-runner/src/sandbox_engine.rs:1163)).

A standalone read-only probe reproduced that `BASH_ENV` executes even with these flags:

```text
injected-by-bash-env
body
```

Consequence: `BASH_ENV` can execute arbitrary unsandboxed shell code before FD hygiene and Bubblewrap. `LD_PRELOAD`/loader variables likewise influence the trusted helper process. The effect can occur outside declared roots/network policy while the subsequent sandbox invocation still emits a valid setup nonce and is recorded as `Enforced`.

Fix: clear the launcher environment before both probe and payload spawn, then add only reviewed fixed variables. Consider privileged-mode Bash or eliminating the shell trampoline.

Acceptance test: set hostile `BASH_ENV`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, exported shell functions, and related startup variables; attempt marker creation and network access outside policy. Assert zero effect, successful normal launch, and no false `Enforced` proof.

## P0-2 — Parent loss after spawn does not kill or reap payload

Evidence: the payload is spawned at [sandbox_engine.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-runner/src/sandbox_engine.rs:769). Parent authority is then checked, but failure returns through `?` before `child` is passed to supervision ([sandbox_engine.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-runner/src/sandbox_engine.rs:785)). This failure branch has no `kill` or `wait`. Kill/reap exists only after supervision starts ([sandbox_engine.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-runner/src/sandbox_engine.rs:1268)).

Consequence: expiry/revocation during setup or the immediate post-spawn window can return a typed failure while the payload continues producing effects. Later runner checks can prevent successful receipts but cannot undo the effect.

Fix: transfer the child directly into a guard/supervisor that kills and reaps on every early return. Validate authority immediately before spawn and continuously thereafter.

Acceptance test: deterministically revoke/expire the parent after `spawn` but before supervision; assert zero marker, zero surviving descendant/zombie, failed terminal evidence, and strict verification success only for the failure chain.

## P1-1 — Preserved descriptors become process-global inheritable FDs

Evidence: `inherit_fd` clears `FD_CLOEXEC` on Bash, Bubblewrap, command, roots, and seccomp descriptors ([sandbox_engine.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-runner/src/sandbox_engine.rs:1024)). The flags are not restored. The current test only proves that an unrelated inherited FD is hidden from the sandbox payload; it does not test leakage of runner descriptors into a concurrent sibling process ([canonical_containment.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-runner/tests/canonical_containment.rs:469)). `run_spec` is a public library entrypoint ([lib.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-runner/src/lib.rs:288)).

Consequence: a concurrent application spawn can inherit pinned command/root descriptors and access them outside Bubblewrap, including renamed/unlinked operation roots.

Fix: use atomic spawn file actions/descriptor duplication that exposes FDs only in the intended child; retaining/restoring CLOEXEC around `Command::spawn` alone still leaves a race.

Acceptance test: repeatedly race dispatch against an external sibling spawn that inventories `/proc/self/fd`; assert no executable, root, seccomp, permit, ledger, or artifact descriptor escapes.

## P1-2 — Run-spec decoder is not semantically closed

Positive evidence: input is limited to 1 MiB; canonical material to 512 KiB; steps to four ([contracts/lib.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-contracts/src/lib.rs:350)). Recursive duplicate detection, closed Serde fields, regular-file/no-follow input, and bounded reads are present ([contracts/lib.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-contracts/src/lib.rs:409), [contracts/lib.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-contracts/src/lib.rs:524)).

Rejection evidence:

- Shell validation rejects only network, zero timeout, and zero output; it has no upper output/timeout, array-cardinality, or explicit depth limit ([contracts/lib.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-contracts/src/lib.rs:553)).
- A large nonzero `max_output_bytes` therefore decodes successfully. The runner creates the run root ([runner/lib.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-runner/src/lib.rs:340)), assigns a fixed 128 KiB permit budget ([runner/lib.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-runner/src/lib.rs:1181)), and only rejects the mismatch at dispatch ([sandbox_engine.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-runner/src/sandbox_engine.rs:148)). Thus semantic rejection is not side-effect-free.
- The original-byte boundary call uses `parse_with_dup_check` ([contracts/lib.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-contracts/src/lib.rs:491)). Its admitted dependency tracks keys globally by `(key, depth)`, not by object identity ([canonicalizer.rs](/home/sikmindz/Coding/Libraries/boundary-compiler/src/canonicalizer.rs:160)). Valid sibling step objects repeating `name`, `call`, or `tool` are therefore misclassified as duplicates. Existing ingress tests exercise one valid step or five rejected steps, but no valid two-to-four-step external spec ([hardening_v5_ingress.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-cli/tests/hardening_v5_ingress.rs:21)).

Consequence: malformed resource requests can create durable state before denial, while legitimate multi-step external specs can fail at the wrong boundary.

Fix: define one complete ingress profile with explicit depth, per-array cardinality, string/path counts, timeout/output ceilings, nonempty semantic fields, and policy version. Correct the boundary owner’s per-object duplicate tracking.

Acceptance tests: valid 1–4 sibling steps; recursive duplicates; trailing tokens; depth/cardinality boundaries; zero/over-limit timeout/output; empty names/steps; and assertions that every rejection leaves no run directory or process start.

## Confirmed non-blocking fixes

- Parent/child actor, policy, run, action, effect subset, expiry, executable authority, and cumulative budgets are checked ([policy/lib.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-policy/src/lib.rs:1291)).
- Parent allocation is durably reserved before child creation and keyed idempotently by child permit ID ([policy/lib.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-policy/src/lib.rs:946)).
- Strict verification independently recomputes cumulative allocations and requires exact allocation evidence at parent revocation ([ledger/lib.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-ledger/src/lib.rs:930), [ledger/lib.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-ledger/src/lib.rs:1035)).
- Executables are descriptor-opened, hashed, authorized, revalidated, descriptor-mounted, and executed through the mounted destination ([sandbox_engine.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-runner/src/sandbox_engine.rs:413), [sandbox_engine.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-runner/src/sandbox_engine.rs:1132)).
- `ParentDir`, `CurDir`, and platform-prefix path components are rejected before descriptor/destination construction ([sandbox_engine.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-runner/src/sandbox_engine.rs:427)).
- Daemon is pure decoding ([daemon/lib.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-daemon/src/lib.rs:1)); MCP exports protocol types only ([mcp/lib.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-mcp/src/lib.rs:1)); skill/MCTS implementations are feature-gated; later tools return `Unavailable` ([tools/lib.rs](/home/sikmindz/Coding/recursive-agent/crates/recursive-agent-tools/src/lib.rs:201)).

## Commands actually run

- `date -u`, `pwd`, `git branch --show-current`, `git rev-parse HEAD`, and `git status --short/--porcelain`.
- `sed -n` and `nl -ba | sed -n` over `AGENTS.md`, the Phase 1 plan, hostile-review-v5, v8/v9 manifests, and all named current source/test surfaces.
- Targeted `rg` scans for permit lineage/allocation, process creation, FD handling, ingress bounds, adapter entrypoints, unsafe/lint escapes, and path handling.
- `jq`, `sha256sum`, `cmp`, and `diff -u` for v8/v9 evidence inspection and all 36 v9 output hashes.
- Independent source-generation and tracked-binary-diff SHA-256 pipelines.
- `git diff --check`.
- Local Bash manual search for `BASH_ENV`.
- Standalone read-only `BASH_ENV=/dev/fd/9 /usr/bin/bash --noprofile --norc ...` startup probe.
- Target writability check: `target-not-writable`.

Limitations: no Cargo test, rebuild, formatter, process-race injection, or end-to-end malicious-environment runner test was run. The target directory was read-only, and formatters were expressly forbidden. Controller outputs were verified as retained evidence, not accepted as fresh reproduction.

Phase 2 may begin: **NO**. Phase 1 remains quarantined until all four blockers have focused regressions, a fresh controller matrix, and another hostile admission review.

```json
{
  "memory_candidates": [
    {
      "content": "Phase 1 launch inherits BASH_ENV/loader environment before Bubblewrap.",
      "confidence": "high",
      "sources": ["crates/recursive-agent-runner/src/sandbox_engine.rs"],
      "verification_gaps": ["end-to-end hostile-environment runner regression"]
    },
    {
      "content": "Post-spawn parent validation failure drops Child without kill/reap.",
      "confidence": "high",
      "sources": ["crates/recursive-agent-runner/src/sandbox_engine.rs"],
      "verification_gaps": ["deterministic post-spawn revocation test"]
    },
    {
      "content": "Runner launch temporarily makes authority descriptors globally inheritable.",
      "confidence": "medium-high",
      "sources": ["crates/recursive-agent-runner/src/sandbox_engine.rs"],
      "verification_gaps": ["concurrent sibling-spawn leak test"]
    },
    {
      "content": "Run-spec ingress lacks complete semantic ceilings and valid sibling-step coverage.",
      "confidence": "high",
      "sources": ["crates/recursive-agent-contracts/src/lib.rs", "Libraries/boundary-compiler/src/canonicalizer.rs"],
      "verification_gaps": ["direct valid multi-step and over-limit parser regressions"]
    }
  ]
}
```