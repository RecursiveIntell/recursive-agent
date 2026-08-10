# Witnessed Workbench v0 — hostile-review closeout

## Reviewed boundary

Only the native Hermes adapter, authenticated Recursive Agent daemon IPC, RuntimeService strict-verification exposure, and the existing CLI-owned Run Pack proof were in scope. Gloss, Hermes core and GUI/plugin loader, MCP, providers, remote workers, and `~/Coding/Libraries` were excluded.

## Review evidence

- **Independent read-only review:** delegated run `deleg_5cc91530`, executed after the first full local validation. The reviewer directly inspected the current dirty working tree and reproduced the plugin lane (7 tests), daemon IPC lane (6 tests), and the slot-reservation regression.
- **Agent Graph attempt:** `run-19fe96b1ef0-2` did not yield analyst output because the Codex app-server timed out. It is a degraded review attempt, not evidence of a completed council.

## Finding disposition

| Finding | Severity | Disposition | Evidence / regression test |
|---|---:|---|---|
| Non-atomic `load` then `fetch_add` could oversubscribe daemon connection capacity | High | **Fixed** | `try_reserve_connection_slot` uses compare/exchange; concurrent 32-contender/1-slot test passes. |
| Adapter could render absent daemon verification fields | High | **Fixed** | Handler returns `unavailable` for absent facts; Python negative test passes. |
| Human-readable output rendered `run_dir` as a whitespace-delimited token, truncating paths containing spaces | Medium | **Fixed** | Handler now returns the versioned `recursive-agent.hermes-result/v1` JSON result; real E2E uses a `runs with spaces` root, consumes the exact `run_dir`, and completes `ra pack export`, verify, and replay. |
| Earlier audit reported absent `run_dir` in client result | Medium | **Superseded** | Current client requires and returns daemon-provided `run_dir`; hermetic E2E exercises it. |
| Generic pytest collection fails for the hyphenated plugin directory | Low | **Not a release gate** | Canonical hermetic command is `scripts/verify-hermes-native.sh`; it uses an explicit test root. |

## Final executable gates

The exact final-command log and hashes are recorded in `CHANGE_RECEIPT.json`. Required gates are:

- `cargo test -p recursive-agent-daemon --tests`
- `scripts/verify-hermes-native.sh`
- `scripts/verify-run-pack.sh`
- `cargo test --workspace --all-targets`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo fmt --all -- --check`
- `git diff --check`

## Remaining non-claims

No packaged Hermes GUI/plugin-loader runtime, graceful daemon shutdown/drain contract, protocol-version reachability handshake, provider-backed execution, remote execution, production deployment, or general security certification was tested or claimed.

## Auditor rerun

```bash
cd /home/sikmindz/Coding/recursive-agent
cargo test -p recursive-agent-daemon --tests
scripts/verify-hermes-native.sh
scripts/verify-run-pack.sh
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
git diff --check
```
