#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WHEELHOUSE="$REPO_DIR/vendor/test-wheels"

rm -rf "$WHEELHOUSE"
mkdir -p "$WHEELHOUSE"

echo "Downloading Python 3.8-compatible test dependencies..."

"$REPO_DIR/py" -m pip download \
  --disable-pip-version-check \
  --dest /scripts/vendor/test-wheels \
  'pytest>=8,<9' \
  'jsonschema==4.17.3'

echo
echo "Offline test dependencies:"
ls -1 "$WHEELHOUSE"

echo
echo "Offline test dependency bundle is ready:"
echo "  vendor/test-wheels"
