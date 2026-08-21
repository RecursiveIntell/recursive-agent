#!/usr/bin/env bash
# Execute a Cargo test binary in an isolated, bounded user scope.
set -euo pipefail

if [[ $# -eq 0 ]]; then
    printf '%s\n' 'guarded-test-runner: missing test binary' >&2
    exit 64
fi
if ! command -v systemd-run >/dev/null 2>&1; then
    printf '%s\n' 'guarded-test-runner: systemd-run is required; refusing unguarded execution' >&2
    exit 69
fi

exec systemd-run --user --scope --quiet --collect \
    --property=MemoryHigh=768M \
    --property=MemoryMax=1G \
    --property=MemorySwapMax=0 \
    --property=OOMPolicy=stop \
    -- "$@"
