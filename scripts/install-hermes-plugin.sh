#!/usr/bin/env bash
# Install the hermes-native plugin into a Hermes home (defaults to $HERMES_HOME
# or ~/.hermes/plugins/recursive-agent-native). Deterministic copy + manifest.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/integrations/hermes-native"
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
PLUGIN_DIR="$HERMES_HOME/plugins/recursive-agent-native"
MANIFEST="$HERMES_HOME/plugins/recursive-agent-native.manifest"
RUNTIME_FILES=(__init__.py client.py plugin.yaml pyproject.toml schema.py)

verify_installed() {
  [[ -d "$PLUGIN_DIR" && ! -L "$PLUGIN_DIR" ]] || {
    echo "error: plugin directory is missing or not a regular directory: $PLUGIN_DIR" >&2
    return 1
  }
  [[ -f "$MANIFEST" && ! -L "$MANIFEST" ]] || {
    echo "error: plugin file manifest is missing or unsafe: $MANIFEST" >&2
    return 1
  }
  local expected actual file
  expected="$(printf '%s\n' "${RUNTIME_FILES[@]}" | LC_ALL=C sort)"
  actual="$(LC_ALL=C sort <"$MANIFEST")"
  [[ "$actual" == "$expected" ]] || {
    echo "error: installed file manifest differs from the runtime package list" >&2
    return 1
  }
  for file in "${RUNTIME_FILES[@]}"; do
    [[ -f "$PLUGIN_DIR/$file" && ! -L "$PLUGIN_DIR/$file" && -f "$SRC/$file" ]] || {
      echo "error: missing or non-regular plugin source/file: $file" >&2
      return 1
    }
    cmp -s "$SRC/$file" "$PLUGIN_DIR/$file" || {
      echo "error: installed plugin payload differs from pinned source: $file" >&2
      return 1
    }
  done
  echo "verified: $PLUGIN_DIR matches its source runtime files"
}

if [[ "${1:-}" == "--verify" ]]; then
  [[ $# -eq 1 ]] || { echo "usage: $0 --verify" >&2; exit 2; }
  verify_installed
  exit $?
fi
[[ $# -eq 0 ]] || { echo "usage: $0" >&2; exit 2; }

if [[ -e "$PLUGIN_DIR" || -L "$PLUGIN_DIR" ]]; then
  echo "error: $PLUGIN_DIR already exists; uninstall first or choose another HERMES_HOME" >&2
  exit 2
fi

mkdir -p "$PLUGIN_DIR"
# Ship only the declared runtime package. Copying the whole source directory
# would also install pytest caches and other development artifacts.
for file in "${RUNTIME_FILES[@]}"; do
  cp "$SRC/$file" "$PLUGIN_DIR/$file"
done

# Write a manifest recording the installed files for clean uninstall.
find "$PLUGIN_DIR" -type f | sed "s#^$PLUGIN_DIR/##" | LC_ALL=C sort > "$MANIFEST"

verify_installed

echo "installed: $PLUGIN_DIR"
echo "manifest: $MANIFEST"
