#!/usr/bin/env bash
# Uninstall the hermes-native plugin using the recorded manifest. Never touches
# Hermes core.
set -euo pipefail

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
PLUGIN_DIR="$HERMES_HOME/plugins/recursive-agent-native"
MANIFEST="$HERMES_HOME/plugins/recursive-agent-native.manifest"

if [[ ! -e "$PLUGIN_DIR" ]]; then
  echo "info: plugin not installed ($PLUGIN_DIR); nothing to do"
  exit 0
fi

# Remove only files recorded in the manifest.
if [[ -f "$MANIFEST" ]]; then
  while IFS= read -r f; do
    rm -f "$PLUGIN_DIR/$f"
  done < "$MANIFEST"
fi

rm -rf "$PLUGIN_DIR"
rm -f "$MANIFEST"
echo "uninstalled: $PLUGIN_DIR"
