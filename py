#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec docker run --rm -it \
  --entrypoint python \
  --workdir /scripts \
  --env PYTHONPATH=/scripts/src \
  -v "${REPO_DIR}:/scripts" \
  juniper/pyez \
  "$@"
