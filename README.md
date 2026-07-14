# Recursive Agent Platform (M0)

> Local-first, provenance-native agent platform in Rust. This is **M0**: the
> smallest vertical slice that produces a tamper-evident receipt chain for
> a deterministic run, verifies it offline, and replays it from disk with
> no provider call.

## What M0 is not

- Not a Hermes or OpenClaw clone. It is a new platform that adopts useful
  *behaviors* (CLI, receipts, replay, scopes) without copying source,
  brand, or upstream contracts.
- Not a provider integration. No Ollama, no OpenAI-compatible call, no
  network. That is **Phase 2**, gated on M0 acceptance.
- Not a UI. CLI only.
- Not MCP. That is **Phase 3**.
- Not a sandboxed execution plane. That is **Phase 4**.

## What M0 *is*

A small Rust workspace at `~/Coding/recursive-agent/` that depends on
canonical Libraries crates by path:

- `boundary-compiler` for RFC 8785 JCS at every typed boundary.
- `stack-ids` for family-qualified material IDs.
- `bitemporal-runtime` for valid-time / recorded-time semantics.
- `claim-ledger` for claim/evidence/provenance primitives.
- Local crates:
  - `recursive-agent-contracts` — typed protocol.
  - `recursive-agent-ledger` — append-only chain + content-addressed
    artifact store.
  - `recursive-agent-policy` — permits, lineage, allowlist.
  - `recursive-agent-tools` — `echo` and `time_now` manifests.
  - `recursive-agent-runner` — typed run DAG, deterministic walk.
  - `recursive-agent-cli` — `ra run`, `ra verify`, `ra replay`,
    `ra doctor`.

## Quick start

```bash
cd ~/Coding/recursive-agent
cargo build --release
./target/release/ra doctor
./target/release/ra run fixtures/hello-run.json
./target/release/ra verify <run-dir-printed-above>
```

The first run prints a `<run-dir>` under
`~/.local/share/recursive-agent/runs/`. Capture stdout into
`docs/receipts/` so the chain can be reproduced.

## Layout

```text
recursive-agent/
├── crates/
│   ├── recursive-agent-contracts/
│   ├── recursive-agent-ledger/
│   ├── recursive-agent-policy/
│   ├── recursive-agent-tools/
│   ├── recursive-agent-runner/
│   └── recursive-agent-cli/
├── fixtures/
├── scripts/
├── docs/
│   ├── adr/
│   └── receipts/
├── AGENTS.md
└── Cargo.toml
```

## Capability matrix

| Capability | Source | M0 |
|---|---|---|
| Canonical JSON boundary | `boundary-compiler` | yes |
| Family-qualified IDs | `stack-ids` | yes |
| Bitemporal | `bitemporal-runtime` | in-memory |
| Claim/evidence | `claim-ledger` | envelope only |
| Provider | none | out of scope |
| MCP | none | out of scope |
| Messaging | none | out of scope |
| Web UI | none | out of scope |
| Sandbox | none | out of scope |
