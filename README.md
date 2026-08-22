# Recursive Agent Platform — local development workspace

> `recursive-agent` is an in-development, local-first Rust execution-kernel
> workspace. Its original M0 receipt/verification/replay vertical slice remains
> the baseline; the dirty working tree also contains an **experimental**
> provider-facing autonomous-loop surface. Neither label is a production,
> reliability, unattended-autonomy, or provider-integration certification.

## Criterion-referenced capability boundary

The current documented claims are limited to the evidence recorded in
[`docs/claims.md`](docs/claims.md). At the 2026-08-21 evidence cutoff, the
following commands were observed to pass in this working tree:

```bash
cargo test --workspace --all-targets --locked --no-fail-fast
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

These are local source checks, not proof of release readiness, provider
reliability, autonomous recursion, native child lineage, real-provider
execution, or external integration. `cargo deny check advisories bans licenses
sources` is currently blocked: it exits 4 because
`webpki-roots` carries `CDLA-Permissive-2.0`, which the current policy rejects.
Operational fuzzing is also blocked because `cargo-fuzz` is unavailable.

## Original M0 boundary

The baseline M0 design provides a deterministic local run that emits a
receipt chain, verifies it offline, and replays recorded disk artifacts without
re-calling a provider. It is not a general deployment, sandbox certification,
or deterministic replay guarantee for a provider response.

```bash
cd ~/Coding/recursive-agent
cargo build --release
./target/release/ra doctor
./target/release/ra run fixtures/hello-run.json
./target/release/ra verify <run-dir-printed-above>
```

## Experimental provider-facing autonomous-loop surface

The source tree exposes an `ra autonomous` command with explicit model,
provider URL, output root, and budgets:

```bash
ra autonomous \
  --goal "run the admitted operation" \
  --model <ollama-model> \
  --provider-url http://127.0.0.1:11434 \
  --out /tmp/recursive-agent-autonomous
```

A model-fixture-to-native-submit path was locally exercised. No authorized live
provider call is recorded in the current packet. Therefore this command may be
described only as an experimental, bounded local surface whose provider,
model-quality, autonomous-recursion, native-child-lineage, and reliability
behavior remain unverified. It must not be described as a provider-backed
production loop, an unattended agent, a recursive autonomous system, or a
provider-deterministic replay mechanism.

Malformed, unavailable, over-budget, cancelled, or unregistered work is
intended to fail closed by the implementation; the current evidence does not
promote that intent into a general reliability claim.

## Recorded pack boundary

```bash
ra pack export --run <run-dir> --out <empty-pack-dir>
ra pack verify --pack <pack-dir>
ra pack replay --pack <pack-dir>
```

Pack verification/replay is a recorded-artifact boundary: it does not establish
provider re-execution, remote execution, deployment support, general security,
or availability guarantees.

## Layout

```text
recursive-agent/
├── crates/
├── fixtures/
├── scripts/
├── docs/
│   └── receipts/
├── AGENTS.md
└── Cargo.toml
```

## Capability matrix

| Capability | Current evidence state | Claim boundary |
|---|---|---|
| Workspace tests / Clippy / formatting | observed local pass | Exact commands above passed at the evidence cutoff only |
| Provider-facing autonomous CLI | experimental / unverified | Fixture → native submit observed; no live provider or reliability proof |
| Autonomous recursion / native child lineage | unverified | No current acceptance evidence recorded |
| Recorded offline replay | baseline design / scope-limited | Does not re-call providers or prove provider determinism |
| Cargo-deny policy | blocked | Exit 4: `webpki-roots` `CDLA-Permissive-2.0` rejected |
| Operational fuzzing | blocked | `cargo-fuzz` unavailable |
| Three-owner conformance | degraded | Mnemes offline build needs uncached `allocator-api2` |
| MCP, messaging, web UI, deployment | unverified or out of scope | No release claim |
