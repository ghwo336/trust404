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

_no_backend() {
  echo "run.sh: no usable detector runtime found." >&2
  echo "  (1) docker load < trust404-detector-amd64.tar.gz   # release asset" >&2
  echo "      or docker pull ghcr.io/sdh2222/trust404-detector:latest" >&2
  echo "  (2) docker build --platform linux/amd64 -f detector/Dockerfile -t trust404/detector:latest ." >&2
  echo "  (3) scripts/setup_local.sh" >&2
  exit 2
}

_image_present() {
  docker image inspect "$1" >/dev/null 2>&1
}

IMAGE="${DETECTOR_IMAGE:-trust404/detector:latest}"
FALLBACK_IMAGE="ghcr.io/sdh2222/trust404-detector:latest"

if [[ -z "${DETECTOR_NO_DOCKER:-}" ]] && command -v docker >/dev/null 2>&1; then
  if ! _image_present "$IMAGE"; then
    if _image_present "$FALLBACK_IMAGE"; then
      IMAGE="$FALLBACK_IMAGE"
    else
      IMAGE=""
    fi
  fi
  if [[ -n "$IMAGE" ]]; then
    echo "run.sh: backend=docker image=${IMAGE}" >&2
    exec docker run --rm --network none -e DETECTOR_MODE=submission -v "${DIR}":/input:ro "$IMAGE" "$@"
  fi
fi

if [[ -n "${DETECTOR_PYTHON:-}" ]]; then
  PY="${DETECTOR_PYTHON}"
elif [[ -x "${ROOT}/.venv/bin/python" ]]; then
  PY="${ROOT}/.venv/bin/python"
else
  PY="python3"
fi

if ! "$PY" -c 'import slither' 2>/dev/null; then
  _no_backend
fi

echo "run.sh: backend=python interpreter=${PY}" >&2
exec "$PY" -m detector.cli "${DIR}" "$@"
