#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

rm -rf .test-deps
mkdir -p .test-deps

if [ -d "$REPO_DIR/vendor/test-wheels" ] &&
   find "$REPO_DIR/vendor/test-wheels" -maxdepth 1 -type f | grep -q .; then
    echo "Installing test dependencies from offline bundle..."
    ./py -m pip install \
      --disable-pip-version-check \
      --no-index \
      --find-links /scripts/vendor/test-wheels \
      --target /scripts/.test-deps \
      'pytest>=8,<9' \
      'jsonschema==4.17.3'
else
    echo "Offline dependency bundle not found."
    echo "Installing test dependencies from PyPI..."
    ./py -m pip install \
      --disable-pip-version-check \
      --target /scripts/.test-deps \
      'pytest>=8,<9' \
      'jsonschema==4.17.3'
fi

echo
echo "Running test suite..."
./py -c '
import sys
sys.path.insert(0, "/scripts/.test-deps")
import pytest
raise SystemExit(pytest.main(["-q"]))
'
