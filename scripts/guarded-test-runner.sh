#!/usr/bin/env bash
# Execute a Cargo test binary in an isolated, bounded user scope.
set -euo pipefail

if [[ $# -eq 0 ]]; then
    printf '%s\n' 'guarded-test-runner: missing test binary' >&2
    exit 64
fi
# Prefer the host-managed systemd-run binary. A stale user-local binary can
# remain earlier on PATH after a systemd package upgrade and fail before it can
# execute, so command -v alone is not a sufficient readiness check.
systemd_run_bin=''
for candidate in /usr/bin/systemd-run /bin/systemd-run; do
    if [[ -x "$candidate" ]] && "$candidate" --version >/dev/null 2>&1; then
        systemd_run_bin="$candidate"
        break
    fi
done
if [[ -z "$systemd_run_bin" ]]; then
    candidate="$(command -v systemd-run 2>/dev/null || true)"
    if [[ -n "$candidate" ]] && [[ -x "$candidate" ]] && "$candidate" --version >/dev/null 2>&1; then
        systemd_run_bin="$candidate"
    fi
fi
if [[ -z "$systemd_run_bin" ]]; then
    printf '%s\n' 'guarded-test-runner: no loadable systemd-run found; refusing unguarded execution' >&2
    exit 69
fi

exec "$systemd_run_bin" --user --scope --quiet --collect \
    --property=MemoryHigh=768M \
    --property=MemoryMax=1G \
    --property=MemorySwapMax=0 \
    --property=OOMPolicy=stop \
    -- "$@"
