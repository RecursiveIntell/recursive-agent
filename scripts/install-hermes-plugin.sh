#!/usr/bin/env bash
# Install the hermes-native plugin into a Hermes home (defaults to $HERMES_HOME
# or ~/.hermes/plugins/recursive-agent-native). Deterministic copy + manifest.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/integrations/hermes-native"
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
PLUGIN_DIR="$HERMES_HOME/plugins/recursive-agent-native"

if [[ -e "$PLUGIN_DIR" ]]; then
  echo "error: $PLUGIN_DIR already exists; uninstall first or choose another HERMES_HOME" >&2
  exit 2
fi

mkdir -p "$(dirname "$PLUGIN_DIR")"
cp -R "$SRC" "$PLUGIN_DIR"
rm -rf "$PLUGIN_DIR/tests"

# Write a manifest recording the installed files for clean uninstall.
find "$PLUGIN_DIR" -type f | sed "s#^$PLUGIN_DIR/##" | sort > "$PLUGIN_DIR/../recursive-agent-native.manifest"

echo "installed: $PLUGIN_DIR"
echo "manifest: $HERMES_HOME/plugins/recursive-agent-native.manifest"
