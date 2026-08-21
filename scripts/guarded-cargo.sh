#!/usr/bin/env bash
# Run Cargo itself in a bounded user scope; use via `cargo guarded <args>`.
set -euo pipefail

if [[ $# -eq 0 ]]; then
    printf '%s\n' 'usage: cargo guarded <cargo arguments>' >&2
    exit 64
fi
if ! command -v systemd-run >/dev/null 2>&1; then
    printf '%s\n' 'guarded-cargo: systemd-run is required; refusing unguarded execution' >&2
    exit 69
fi

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
exec systemd-run --user --scope --quiet --collect \
    --property=MemoryHigh=2304M \
    --property=MemoryMax=3G \
    --property=MemorySwapMax=0 \
    --property=OOMPolicy=stop \
    -- cargo "$@"
