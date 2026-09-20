#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: scripts/judge_smoke.sh <dir> [image]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$1"
if [[ $# -ge 2 ]]; then
  export DETECTOR_IMAGE="$2"
fi

WORKDIR="${HOME}/.dsmoke/judge_smoke.$$"
mkdir -p "$WORKDIR"
OUT="${WORKDIR}/out.json"

if [[ -n "${DETECTOR_PYTHON:-}" ]]; then
  PY="${DETECTOR_PYTHON}"
elif [[ -x "${ROOT}/.venv/bin/python" ]]; then
  PY="${ROOT}/.venv/bin/python"
else
  PY="python3"
fi

set +e
"${ROOT}/run.sh" "$DIR" > "$OUT"
run_exit=$?
set -e

if command -v check-jsonschema >/dev/null 2>&1; then
  set +e
  check-jsonschema --schemafile "${ROOT}/detector/schema/judge.schema.json" "$OUT" >&2
  val_exit=$?
  set -e
else
  set +e
  "$PY" -m detector.submission --validate "$OUT"
  val_exit=$?
  set -e
fi

if command -v jq >/dev/null 2>&1; then
  jq -r '.[] | "\(.file)\t\(.verdict)"' "$OUT"
  n="$(jq 'length' "$OUT")"
  m="$(jq '[.[] | select(.verdict=="MALICIOUS")] | length' "$OUT")"
  b="$(jq '[.[] | select(.verdict=="BENIGN")] | length' "$OUT")"
  u="$(jq '[.[] | select(.verdict=="UNCERTAIN")] | length' "$OUT")"
  echo "judge_smoke: ${n} files, ${m} MALICIOUS, ${b} BENIGN, ${u} UNCERTAIN, run.sh exit=${run_exit}"
else
  "$PY" -c '
import json
import sys

path = sys.argv[1]
run_exit = sys.argv[2]
obj = json.load(open(path, encoding="utf-8"))
if not (isinstance(obj, list) and obj):
    raise SystemExit("expected a non-empty JSON array")
n = len(obj)
m = sum(1 for row in obj if row.get("verdict") == "MALICIOUS")
b = sum(1 for row in obj if row.get("verdict") == "BENIGN")
u = sum(1 for row in obj if row.get("verdict") == "UNCERTAIN")
for row in obj:
    print("%s\t%s" % (row["file"], row["verdict"]))
print(
    "judge_smoke: %s files, %s MALICIOUS, %s BENIGN, %s UNCERTAIN, run.sh exit=%s"
    % (n, m, b, u, run_exit)
)
' "$OUT" "$run_exit"
fi

if [[ "$run_exit" -ne 0 || "$val_exit" -ne 0 ]]; then
  exit 1
fi
