#!/usr/bin/env bash
# TRUST404 Track 1 entry point:  ./run.sh <dir>  -> one JSON array on stdout, logs on stderr, exit 0
# Runs BOTH engines (noexit + detector) and merges them - see README "Ensemble" and tools/ensemble.py.
#   ./run_detector.sh <dir>            detector alone
#   noexit/run.sh <dir>                noexit alone
set -uo pipefail
if [[ $# -lt 1 || ! -d "$1" ]]; then
  echo "usage: ./run.sh <dir>" >&2
  exit 2
fi
ROOT="$(cd "$(dirname "$0")" && pwd)"
DIR="$(cd "$1" && pwd)"
shift

if [[ -z "${ENSEMBLE_NO_DOCKER:-}" ]] \
    && command -v docker >/dev/null 2>&1 \
    && docker image inspect trust404/ensemble:latest >/dev/null 2>&1; then
  exec docker run --rm --network none -v "${DIR}":/input:ro trust404/ensemble:latest /input "$@"
fi

if [[ -x "${ROOT}/.venv/bin/python" ]]; then
  exec "${ROOT}/.venv/bin/python" "${ROOT}/tools/ensemble.py" "${DIR}" "$@"
fi
exec python3 "${ROOT}/tools/ensemble.py" "${DIR}" "$@"
