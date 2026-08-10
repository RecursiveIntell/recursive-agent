#!/usr/bin/env bash
# Hermetic adapter verification entrypoint. The plugin directory is intentionally
# hyphenated for Hermes' plugin naming, so pytest must use the tests directory as
# its root to avoid treating the plugin's production __init__.py as an invalid
# Python package name during collection.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q \
  --rootdir=integrations/hermes-native/tests \
  integrations/hermes-native/tests
