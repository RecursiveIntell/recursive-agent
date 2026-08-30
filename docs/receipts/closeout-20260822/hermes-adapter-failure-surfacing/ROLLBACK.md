# Rollback and quarantine — adapter failure surfacing

The phase is additive and source-local.

## Source rollback

Revert only:

- `integrations/hermes-native/client.py`
- `integrations/hermes-native/__init__.py`
- `integrations/hermes-native/tests/test_registration.py`
- `crates/recursive-agent-daemon/src/server.rs`
- `crates/recursive-agent-daemon/tests/ipc_runtime.rs`

Do not use `git reset`, `git clean`, or broad checkout restoration because the worktree contains unrelated dirty source, tests, receipts, and generated artifacts.

## Receipt quarantine

Remove or quarantine only this `adapter-failure-surfacing-20260822` packet and the additive `closeout-20260822` receipt directory if the operator explicitly requests it. Retain the historical 2026-08-21 packets as historical evidence.

No commit, push, merge, install, deploy, gateway restart, credential change, or release activation is authorized by this packet.
