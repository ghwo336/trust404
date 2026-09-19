#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: ./run.sh <dir> [extra args]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "$0")" && pwd)"
if [[ ! -d "$1" ]]; then
  echo "run.sh: not a directory: $1" >&2
  exit 2
fi
DIR="$(cd "$1" && pwd)"
shift

export PYTHONPATH="${ROOT}${PYTHONPATH:+:${PYTHONPATH}}"

if [[ -z "${DETECTOR_NO_DOCKER:-}" ]] \
    && command -v docker >/dev/null 2>&1 \
    && docker image inspect trust404/detector:latest >/dev/null 2>&1; then
  exec docker run --rm --network none -v "${DIR}":/input:ro trust404/detector:latest "$@"
fi

if [[ -x "${ROOT}/.venv/bin/python" ]]; then
  exec "${ROOT}/.venv/bin/python" -m detector.cli "${DIR}" "$@"
fi

exec python3 -m detector.cli "${DIR}" "$@"
