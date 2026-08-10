#!/usr/bin/env bash
# Task 9 acceptance entrypoint. The integration test creates a deterministic
# embedded run, exports it, copies only the pack to a fresh root, removes the
# original run, then traces pack replay for forbidden network/process effects.
# It is intentionally an invocation wrapper: pack evidence semantics remain in
# the contracts, ledger, and runner owners.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"

if ! command -v strace >/dev/null 2>&1; then
  printf '%s\n' 'BLOCKED: strace is required for the clean-process external-effect acceptance check.' >&2
  exit 69
fi

cargo test -p recursive-agent-cli --test run_pack_clean_process
