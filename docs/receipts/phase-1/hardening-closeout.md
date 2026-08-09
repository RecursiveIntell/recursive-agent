# Phase 1 Hardening Closeout (Controller Review Required)

Date: 2026-08-05 (America/Chicago)  
Branch: `main`  
HEAD: `3805f7abf319e07e47f1c20b862e614c3dad164f`  
Disposition: **quarantined; not admitted and not marked complete**

This receipt records the remediation of the release-blocking findings in the
original hostile review. It does not supersede that review, admit Phase 1, or
authorize Phase 2. The primary controller must rerun the gates and perform a
second hostile review.

## Preserved evidence

The original blocked implementation receipt and hostile review were not
edited:

- `docs/receipts/phase-1/codex-implementation.md`
  SHA-256 `6f2c8d1758e81b3b34805a1dbb7f87b79b17e3fbde6a63d02efe592dfd3eec2a`
- `docs/receipts/phase-1/hostile-review.md`
  SHA-256 `3160ab31f3bae1b872e2027e4af60507653b0083eec19419852984a6c9370390`

The required pre-change RED records are retained at:

- `hardening/h1-sandbox/red.txt`
- `hardening/h2-permits/red.txt`
- `hardening/h3-ledger/red.txt`
- `hardening/h4-lifecycle/red.txt`
- `hardening/h5-identities/red.txt`
- `hardening/h6-artifacts/red.txt`
- `hardening/h7-provider/red.txt`
- `hardening/h0-lint-integrity/red.txt` (additional hard-boundary finding)

## Changed paths

Primary contract and implementation changes:

- `Cargo.toml`, `Cargo.lock`
- `crates/recursive-agent-contracts/src/lib.rs`
- `crates/recursive-agent-policy/{Cargo.toml,src/lib.rs,tests/permit_lifecycle.rs}`
- `crates/recursive-agent-ledger/{Cargo.toml,src/lib.rs,tests/artifact_tamper.rs,tests/crash_recovery.rs,tests/lifecycle_validation.rs}`
- `crates/recursive-agent-sandbox/{Cargo.toml,src/lib.rs,src/bin/recursive-agent-sandbox-launcher.rs,tests/enforcement_truth.rs}`
- `crates/recursive-agent-provider/{Cargo.toml,src/lib.rs,tests/secret_contract.rs}`
- `crates/recursive-agent-runner/{Cargo.toml,src/lib.rs,tests/deterministic_identity.rs,tests/lifecycle_state_machine.rs,tests/permit_dispatch.rs}`

Strict compile migrations only:

- `crates/recursive-agent-cli/{Cargo.toml,src/main.rs}`
- `crates/recursive-agent-tools/{Cargo.toml,src/lib.rs}`

Evidence only:

- `docs/receipts/phase-1/hardening/**`
- this closeout receipt

No daemon, MCP, memory, skills, or MCTS behavior was changed. No file under
`/home/sikmindz/Coding/Libraries` or `.hermes/` was edited by this hardening
work.

Exact added safety dependencies are `rustix = 1.1.4`, `url = 2.5.8`, and
`nix = 0.30.1` (the latter is used only by the safe FD-hygiene launcher).

## Remediation summary

### H1 — sandbox

The local Landlock/pre-exec implementation was removed. Linux containment now
uses `/usr/bin/bwrap` through a safe Rust launcher which closes inherited file
descriptors and then `exec`s Bubblewrap. Arguments are constructed directly;
payload values are positional arguments, not shell-interpolated commands.
The policy uses `--unshare-all`, `--die-with-parent`, `--new-session`, a private
PID namespace, a private root and `/tmp`, minimal read-only runtime mounts,
exact declared read/write binds, cleared environment, and network isolation
unless explicitly declared. The timeout starts before probe/setup. Output and
reader shutdown are bounded. The enforcement record names Bubblewrap, its
path/version, the FD launcher, exact argv, PID/lifecycle controls, and network
state. This host reports `bubblewrap 0.11.0`.

Hostile coverage includes missing launcher, zero timeout, setup hang, missing
allow path, inherited non-CLOEXEC FD, outside create/remove/rename/truncate,
outside read, network, `setsid` descendant, leader-exits-first descendant,
infinite output, and signal/timeout races. The non-Linux branch was compiled
with `x86_64-linux-android` and returns typed `UnsupportedPlatform` before an
effect.

### H2 — capability leases

`PermitBindingV1` now binds a validated actor, action digest, complete effect
scope and digest, typed budgets, policy version, parent lease/operation,
trusted issued/not-before/expiry times, and run/step/tool/args. The durable
store has issued, consumed, and revoked states with typed reasons. Transitions
use a pinned no-follow directory descriptor, an exclusive process lock,
same-directory temporary files, file sync, atomic rename, and directory sync.
The runner revalidates and durably consumes the full binding immediately
before dispatch, and emits issue/consume/reject evidence. Every root component
is opened or created relative to a pinned no-follow descriptor; intermediate
symlinks are rejected. Parent state and time are revalidated at child issue
and dispatch. The runner records the lifecycle-parent issue and atomically
revokes it before finalization, so no parent authority survives a terminal run.

Hostile coverage includes reuse, expiry, revocation, actor, action, effect,
budget, parent, policy, and arguments; concurrent and restart double-spend;
unissued and revoked parent; `TempWrite`, `TempFsync`, `Rename`, and
`DirectoryFsync` crash points for both consume and revoke; root replacement,
intermediate/root symlink, and state-file symlink swap. Every runner rejection
case retains a zero effect-dispatch counter.

### H3 — ledger

All opens/appends reconcile under one safe exclusive lock shared across
threads, handles, and processes. An append writes one complete canonical
NDJSON line buffer. Recovery finalizes a complete canonical EOF receipt that
lacks only its newline, truncates only an unambiguously incomplete tail to the
last durable newline, and rejects ambiguous bytes without deleting a durable
receipt. Metadata is rebuilt from receipts and replaced through a
collision-safe same-directory temp file, file sync, atomic rename, and parent
directory sync. Receipt, metadata, and lock operations stay relative to the
pinned run-root descriptor, so replacing the path cannot redirect an open
chain. Intermediate symlink roots are rejected.

The process-kill matrix covers artifact write, partial record, full receipt
append, log fsync, metadata temp write, metadata fsync, metadata rename, and
directory fsync. Reopen is always the previous or new valid chain. Separate
two-handle and two-process races prove that only one contender can own a
predecessor.

The fixed raw-byte chain vector is:

```text
prev = 0000000000000000000000000000000000000000000000000000000000000000
jcs  = {"a":1}
blake3(prev_raw_bytes || jcs) = 7e94084bce94902db91a1fcd90448c118e748e57c8c812348e09af0d03830054
```

The genesis input remains exactly `recursive-agent-m0-genesis`.

### H4 — lifecycle

One lifecycle validator is used by append, open/recovery, strict verify,
replay, and existing-run status. It binds one run ID, enforces step and permit
ordering, terminal dominance, exactly one finalization, no post-terminal
receipt, and final outcome consistency. The hostile matrix covers
failed/cancelled/denied/timed-out/sandbox-failed/corrupted followed by success,
duplicate finalization, post-terminal receipt, finalization without start,
and mixed run IDs at append and offline verification. Legacy integrity mode
returns `LegacyUnknown` and cannot set current strict success.

### H5 — material boundaries

Current receipt material uses custom-deserialized, owner-backed run, step,
permit, receipt, and artifact IDs with exact current domains and 64-character
lowercase digests. Empty, arbitrary, UUID, and wrong-family values are
rejected. `LegacyV1Id` is an explicit inspection-only reader and has no path to
remint current authority.

Receipt identity now binds run, step, kind, valid time, authority lineage,
spec digest, args/action digest, outcome, complete artifact descriptors, and
predecessor. Only `recorded_time` is excluded as explicitly non-authoritative.
Each semantic field has an independent mutation assertion.

Fixed cross-process vectors:

```text
run     v1:recursive-agent/run/v1:det:c38abdfd083f535830a6131e7249c9bc1c2f4204ca8629d6784adb0553b3a781
step    v1:recursive-agent/step/v1:det:433ca03f0ccad68c4da232add29e049886a1cb61868cb1ab33f49d6f6604701f
receipt v1:recursive-agent/receipt/v1:det:5f32d001b404aa59e4b0072c8f046b34ef48dd229d6a9aeabc0717a2740af253
```

### H6 — artifacts

Receipt artifact references are typed descriptors binding owner ID/digest,
byte length, media type, and optional encoding. The store pins the artifact
directory descriptor and uses no-follow/beneath descriptor-relative opens.
The same opened regular-file descriptor is streamed with bounded buffers and
a 16 MiB maximum by both `ArtifactStore::get` and strict chain verification.

Hostile coverage rejects missing, truncated, replaced, wrong-digest,
wrong-length, wrong-media-type, malformed-owner, FIFO, device/non-regular,
directory, symlink, rename race, huge sparse file, and artifact-directory
replacement cases. `StrictCurrent` and `LegacyIntegrityOnly` are explicit;
legacy verification never reports current strict success.

### H7 — provider ingress

`CredentialRef` custom deserialization accepts only
`environment:PORTABLE_NAME`. Provider errors never retain the reference or a
resolver payload. URL validation uses `url 2.5.8` and rejects malformed
authority, userinfo/password, query, fragment, control characters, and
non-HTTP(S) schemes before resolving credentials or transport. Raw-key input
returns a typed migration error without echoing input. Tests use fake
resolvers only and assert that sentinels never appear through deserialization,
serialization, `Debug`, resolver, URL, or error paths.

### Lint integrity

All crate-level lint overrides discovered in the hostile tests were removed.
The inherited workspace `unsafe_code`, `unwrap_used`, `expect_used`, `panic`,
`todo`, and `dbg_macro` policy passes without weakening the workspace lint
configuration.

## GREEN evidence

The current authoritative Phase 1 proof packet is:

```text
docs/receipts/phase-1/hardening/release-gate-final-v2/evidence-workbench-20260805T053545Z.json
workbench packet digest: 2163318e3c8c57f985dcf29f7991d6949874fb2ef4d6c3b2abc715ba38ae65c4
file SHA-256: eeec20d6c68c6ab7f8d7d85190d915bf1eddf97a3e87c0768a68211d7c6e2f01
disposition: promote
```

It contains successful receipts for:

- `cargo fmt --all -- --check`
- all-target tests for contracts, policy, ledger, sandbox, provider, and runner
- `cargo check -p recursive-agent-sandbox --target x86_64-linux-android --all-targets`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `git diff --check`
- source scans for local unsafe/unsafe overrides, crate-level lint overrides,
  random/UUID/time identity inputs, and raw credential fields
- focused zero-dispatch permit and revoked-parent checks, pinned-root ledger
  checks, sandbox access/network checks, and artifact race tests

The exact `cargo test --workspace --all-targets` command was rerun after the
final lint-integrity changes in a direct PTY execution and exited 0. All
workspace tests passed. The expected losing child in the ledger two-process
race prints a failed child-test transcript; the owning parent test passes and
the workspace exit status is 0.

Three earlier workbench packets are intentionally retained with `reject`
dispositions. Their only workspace integration failure is the existing daemon
AF_UNIX test receiving `EPERM` under the workbench's captured-subprocess
profile; one also records a stale sandbox test selector. Earlier `promote`
packets are superseded by the current v2 packet. Captured direct non-PTY
attempts are retained under `hardening/direct-workspace-gate/` and show the
same environmental `EPERM`. They are not cited as passing evidence.

## Source and safety confirmation

- Branch and HEAD remain `main` / `3805f7abf319e07e47f1c20b862e614c3dad164f`.
- The intentionally dirty Phase 0/Phase 1 tree was preserved. No commit,
  staging, reset, restore, clean, checkout, rebase, push, or history rewrite
  was performed.
- No local library or binary source contains `unsafe` or an unsafe lint
  override. No crate-level lint override remains.
- No current material identity path uses UUID, random, or live wall-clock
  input. Supplied frozen/trusted times remain typed binding data; receipt
  recording time is non-identity metadata.
- Tests did not read credential values and no provider network call was made.
- Permit rejection returns before the effect closure. Ledger/lifecycle and
  artifact evidence must append/verify successfully before the runner reaches
  its tool call. Sandbox setup never reports `Enforced` without its in-sandbox
  readiness marker; every unavailable/failed setup returns typed evidence and
  no payload result.

## Unresolved environmental risks and quarantine

This execution host exposes `/usr/bin/bwrap` but cannot create Bubblewrap's
network namespace inside the outer container (`NETLINK_ROUTE: Operation not
permitted`). The implementation therefore took its required typed fail-closed
path; a successful positive `Enforced` execution could not be observed on this
host. The controller should repeat the hostile sandbox suite on a host that
permits unprivileged Bubblewrap namespaces.

The evidence-workbench subprocess profile also blocks the pre-existing daemon
AF_UNIX tests, while the exact workspace command passes in the direct PTY
profile. The retained reject packets make that distinction inspectable; it is
not converted into a degraded pass.

No known hostile-review implementation finding is intentionally deferred, but
admission is still withheld. Rollback remains the quarantined dirty-tree
boundary: the controller can discard only the paths listed in this receipt
using its approved recovery workflow. No history was created or rewritten.
