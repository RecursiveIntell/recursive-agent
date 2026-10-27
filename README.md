# Recursive Agent Platform — local development workspace

> `recursive-agent` is an in-development, local-first Rust execution-kernel
> workspace. Its original M0 receipt/verification/replay vertical slice remains
> the baseline; the checked-in source also contains an **experimental**
> provider-facing autonomous-loop surface. Neither label is a production,
> reliability, unattended-autonomy, or provider-integration certification.

## Criterion-referenced capability boundary

The current documented claims are limited to the evidence recorded in
[`docs/claims.md`](docs/claims.md). At the 2026-08-22 evidence cutoff, the
following commands were observed to pass in this working tree:

```bash
cargo test --workspace --all-targets --locked --no-fail-fast
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

These are local source checks, not proof of release readiness, provider
reliability, autonomous recursion, native child lineage, real-provider
execution, or external integration. `cargo deny check advisories bans licenses
sources` and bounded ingress fuzzing were subsequently recorded as passing in the August 22 closeout. Those dated receipts supersede the older unavailable-tool/license-policy blockers; they still require rerunning for a new source/environment.

<!-- last-verified: 2026-10-26 -->
<!-- Scope: source-pairing and CLI option/default notes only; broader validation evidence retains its recorded cutoff. -->

## Source checkout prerequisite

The root [`Cargo.toml`](Cargo.toml) resolves `boundary-compiler`, `stack-ids`, `bitemporal-runtime`, `claim-ledger`, and `llm-tool-runtime` by path from a sibling `../Libraries` checkout. A `recursive-agent` checkout alone cannot resolve those workspace dependencies. CI pairs this source with [`Libraries` commit `0b099ec416de60f6adafb182f1d1e83795d05c56`](https://github.com/RecursiveIntell/Libraries/commit/0b099ec416de60f6adafb182f1d1e83795d05c56); use that pin for the documented CI pairing rather than assuming the current `Libraries` default branch is compatible.

From a parent directory where neither checkout already exists, create the paired roots with:

```bash
git clone https://github.com/RecursiveIntell/recursive-agent.git
git clone https://github.com/RecursiveIntell/Libraries.git
git -C Libraries checkout 0b099ec416de60f6adafb182f1d1e83795d05c56
cd recursive-agent
```

The commands above describe the current CI source pairing; they have not been run as a clean onboarding flow here. The dated validation below does not certify an arbitrary new pairing of the repositories' default branches.

## CLI options and defaults

The CLI is implemented in [`crates/recursive-agent-cli/src/main.rs`](crates/recursive-agent-cli/src/main.rs). After building, `ra --help` and each subcommand's `--help` show the parser-generated usage. The table records the parser's current named options; it does not imply that the experimental provider-facing path has been validated. Clap also supplies `-h`/`--help` and `-V`/`--version`.

| Command | Option | Required or default |
|---|---|---|
| Global CLI option | `--log-level` | `info` |
| `ra` and subcommands | `-h`, `--help` | Generated usage; no command runs |
| `ra` | `-V`, `--version` | CLI package version (`0.1.0`) |
| `ra run` | `--spec <PATH>` | Required run-spec file |
| `ra run` | `--out <DIR>` | Embedded mode only; ignored with `--runtime ipc`. `$RECURSIVE_AGENT_RUNS` when present; otherwise `$HOME/.local/share/recursive-agent/runs` (or `./.local/share/recursive-agent/runs` if `HOME` is absent) |
| `ra run` | `--runtime <embedded\|ipc>` | `embedded`; no automatic fallback between modes |
| `ra run` | `--socket <PATH>` | No default; required with `--runtime ipc` |
| `ra autonomous` | `--goal <TEXT>` | Required |
| `ra autonomous` | `--model <NAME>` | Required; must be admitted by the configured provider |
| `ra autonomous` | `--provider-url <URL>` | `http://127.0.0.1:11434` |
| `ra autonomous` | `--out <DIR>` | `$RECURSIVE_AGENT_RUNS/autonomous` when present; otherwise `$HOME/.local/share/recursive-agent/runs/autonomous` (or `./.local/share/recursive-agent/runs/autonomous` if `HOME` is absent) |
| `ra autonomous` | `--max-depth` | `3` |
| `ra autonomous` | `--max-steps` | `8` |
| `ra autonomous` | `--max-children` | `2` |
| `ra autonomous` | `--max-wall-time-ms` | `120000` |
| `ra autonomous` | `--max-output-bytes` | `65536` |
| `ra autonomous` | `--max-tokens` | Unset unless supplied |
| `ra verify`, `ra replay` | `--run <DIR>` | Required |
| `ra pack export` | `--run <DIR>`, `--out <DIR>` | Both required |
| `ra pack verify`, `ra pack replay` | `--pack <DIR>` | Required |

When `RECURSIVE_AGENT_RUNS` is present, its value is the run-data root; otherwise the CLI derives the root from `HOME` (falling back to `.` if `HOME` is absent). Embedded `ra run` uses that root directly, while `ra autonomous` appends an `autonomous/` directory. In IPC mode, the server owns the run output location; the CLI's `--out` option does not change it. The autonomous command accepts an Ollama-compatible URL and model name; no API-key environment variable is defined by this CLI parser. No external provider call is included in the validation for this README.

## Original M0 boundary

The baseline M0 design provides a deterministic local run that emits a
receipt chain, verifies it offline, and replays recorded disk artifacts without
re-calling a provider. It is not a general deployment, sandbox certification,
or deterministic replay guarantee for a provider response.

```bash
# From the root of your recursive-agent checkout:
cargo build --release
./target/release/ra doctor
./target/release/ra run --spec fixtures/hello-run.json
./target/release/ra verify --run <run-dir-printed-above>
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
| Cargo-deny policy | recorded local pass | August 22 closeout; rerun for the current revision |
| Operational fuzzing | recorded bounded pass | August 22 corpus runs; not a general reliability proof |
| Three-owner conformance | recorded disposable offline pass | August 22 generated bytes, idempotency, and tamper checks; no production-owner claim |
| MCP, messaging, web UI, deployment | unverified or out of scope | No release claim |
