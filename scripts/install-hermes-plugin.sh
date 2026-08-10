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

mkdir -p "$PLUGIN_DIR"
# Ship only the declared runtime package. Copying the whole source directory
# would also install pytest caches and other development artifacts.
for file in __init__.py client.py schema.py plugin.yaml pyproject.toml; do
  cp "$SRC/$file" "$PLUGIN_DIR/$file"
done

# Write a manifest recording the installed files for clean uninstall.
find "$PLUGIN_DIR" -type f | sed "s#^$PLUGIN_DIR/##" | sort > "$PLUGIN_DIR/../recursive-agent-native.manifest"

echo "installed: $PLUGIN_DIR"
echo "manifest: $HERMES_HOME/plugins/recursive-agent-native.manifest"
