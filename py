#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec docker run --rm -it \
  --user "$(id -u):$(id -g)" \
  --env USER="${USER:-$(id -un)}" \
  --env LOGNAME="${LOGNAME:-${USER:-$(id -un)}}" \
  --entrypoint python \
  --workdir /scripts \
  --env PYTHONPATH=/scripts/src \
  -v "${REPO_DIR}:/scripts" \
  juniper/pyez \
  "$@"
