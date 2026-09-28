#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

mkdir -p .test-deps

echo "Installing test dependencies..."
./py -m pip install \
  --disable-pip-version-check \
  --target /scripts/.test-deps \
  'pytest>=8,<9' \
  'jsonschema==4.17.3'

echo
echo "Running test suite..."
./py -c '
import sys
sys.path.insert(0, "/scripts/.test-deps")
import pytest
raise SystemExit(pytest.main(["-q"]))
'
