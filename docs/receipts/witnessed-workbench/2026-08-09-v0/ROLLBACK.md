# Witnessed Workbench v0 rollback

## Scope

The implementation is additive: daemon `verify` IPC dispatch, Hermes client verification requirement, same-run pack E2E, and this receipt packet.

## Source rollback

Revert only these implementation paths as one compatibility unit:

- `crates/recursive-agent-daemon/src/protocol.rs`
- `crates/recursive-agent-daemon/src/server.rs`
- `crates/recursive-agent-daemon/tests/ipc_runtime.rs`
- `integrations/hermes-native/__init__.py`
- `integrations/hermes-native/client.py`
- `integrations/hermes-native/plugin.yaml`
- `integrations/hermes-native/tests/test_e2e.py`
- `scripts/verify-hermes-native.sh`

Do **not** revert, reset, clean, or stage unrelated untracked directories listed in `PRECHECK.json`.

## Evidence preservation

Keep `proof/run` and `proof/run-pack` intact. They are generated local evidence, not a source owner. If the vertical slice is withdrawn, move the whole proof directory to a quarantine location with its manifest hash; do not mutate pack bytes or delete failure evidence.

## Re-entry gate

Before any replacement implementation, rerun:

```bash
cargo test -p recursive-agent-daemon --tests
scripts/verify-hermes-native.sh
scripts/verify-run-pack.sh
```

A replacement must continue to use daemon-derived strict verification and must not reintroduce `receipt_ref = "run:<id>"` or adapter-side receipt/pack semantics.
