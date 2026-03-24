#!/bin/bash
# Cached test runner — skips execution if no source files changed since last pass.
# Usage: ./scripts/cached-test.sh [cargo test args...]
# Example: ./scripts/cached-test.sh -p aegis-orchestrator --lib
#
# Stores a stamp file per unique arg signature. If no .rs/.toml files changed
# since the stamp, prints the cached result and exits 0.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CACHE_DIR="$PROJECT_ROOT/.test-cache"
mkdir -p "$CACHE_DIR"

# Build a deterministic key from args
ARGS_KEY=$(echo "$@" | shasum -a 256 | cut -c1-16)
STAMP_FILE="$CACHE_DIR/$ARGS_KEY.stamp"
RESULT_FILE="$CACHE_DIR/$ARGS_KEY.result"

# Find newest source file (rs or toml) in the workspace
NEWEST_SOURCE=$(find "$PROJECT_ROOT/crates" "$PROJECT_ROOT/Cargo.toml" \
  -name '*.rs' -o -name '*.toml' 2>/dev/null | \
  xargs stat -f '%m %N' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f1)

# Check if stamp exists and is newer than all source files
if [[ -f "$STAMP_FILE" ]] && [[ -f "$RESULT_FILE" ]]; then
  STAMP_TIME=$(stat -f '%m' "$STAMP_FILE" 2>/dev/null || echo 0)
  if [[ "$STAMP_TIME" -ge "$NEWEST_SOURCE" ]]; then
    echo "[cached-test] No source changes since last pass — using cached result"
    cat "$RESULT_FILE"
    exit 0
  fi
fi

# Run the actual tests, capture output
echo "[cached-test] Source changed — running: cargo test $*"
set +e
OUTPUT=$(cargo test "$@" 2>&1)
EXIT_CODE=$?
set -e

echo "$OUTPUT"

# Only cache on success
if [[ $EXIT_CODE -eq 0 ]]; then
  echo "$OUTPUT" > "$RESULT_FILE"
  touch "$STAMP_FILE"
fi

exit $EXIT_CODE
