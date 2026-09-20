#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -d .venv ]]; then
  if command -v uv >/dev/null 2>&1; then
    uv venv --python 3.12 .venv
  else
    python3 -m venv .venv
  fi
fi

if command -v uv >/dev/null 2>&1; then
  uv pip install --python .venv/bin/python -e '.[dev]'
  uv pip install --python .venv/bin/python -r detector/requirements.txt
else
  .venv/bin/pip install -e '.[dev]'
  .venv/bin/pip install -r detector/requirements.txt
fi

installed=0
for v in $(cat detector/solc_versions.txt); do
  dest="${HOME}/.solc-select/artifacts/solc-${v}/solc-${v}"
  if [[ ! -f "$dest" ]]; then
    .venv/bin/solc-select install "$v"
  fi
  installed=$((installed + 1))
done

echo "INSTALLED ${installed}"
echo "hint: ./run.sh <dir>  or  DETECTOR_NO_DOCKER=1 ./run.sh <dir>"
