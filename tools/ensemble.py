#!/usr/bin/env python3
"""TRUST404 Track 1 entry point: run both engines on one directory and merge their verdicts.

    python3 tools/ensemble.py <dir>            -> one JSON array (judge schema) on stdout, logs on stderr, exit 0

Engines (each is a complete Track 1 tool on its own; both are 100 % offline):
  * noexit    - TypeScript AST rule engine       (noexit/run.sh <dir>)
  * detector  - Python rules-layer + solc ladder (python -m detector.cli <dir>)

Merge rule, chosen on BAYBENCH with the official +1 / 0 / -1 scoring (see README "Ensemble"):
  MALICIOUS  if either engine says MALICIOUS   (each engine has zero high-severity false positives on the benign-risky tier,
                                                so their positive calls are additive: 575/607 vs 562 / 527 alone)
  BENIGN     if no engine says MALICIOUS and at least one says BENIGN (an abstain for compile/parse reasons on one side
                                                must not erase the other engine's clean bill - scores identically on BAYBENCH)
  UNCERTAIN  otherwise (both abstain, or both engines failed / timed out / produced no row for the file)
Reasons and evidence are the union of the engines that voted for the final verdict.  A MALICIOUS row without any
evidence location is downgraded to UNCERTAIN (schema requirement).  Every *.sol directly inside <dir> gets a row.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUDGET_S = float(os.environ.get("ENSEMBLE_BUDGET_S", "540"))  # judge kills at 600 s; leave headroom to print
NOEXIT_ONLY = os.environ.get("ENSEMBLE_ENGINES", "").lower() == "noexit"
DETECTOR_ONLY = os.environ.get("ENSEMBLE_ENGINES", "").lower() == "detector"


def log(msg: str) -> None:
    sys.stderr.write(f"[ensemble] {msg}\n")
    sys.stderr.flush()


def run_engine(name: str, cmd: list[str], cwd: Path, out: dict, budget: float) -> None:
    t0 = time.time()
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=budget, env={**os.environ, "PYTHONPATH": str(ROOT)})
        sys.stderr.write(p.stderr[-4000:])
        rows = json.loads(p.stdout)
        if not isinstance(rows, list):
            raise ValueError("stdout is not a JSON array")
        out[name] = {r.get("file"): r for r in rows if isinstance(r, dict) and isinstance(r.get("file"), str)}
        log(f"{name}: {len(out[name])} rows in {time.time() - t0:.1f}s")
    except subprocess.TimeoutExpired:
        log(f"{name}: timed out after {budget:.0f}s - ignored")
        out[name] = None
    except Exception as e:  # engine missing, crashed, or printed garbage: the other engine carries the file
        log(f"{name}: failed ({type(e).__name__}: {str(e)[:200]}) - ignored")
        out[name] = None


def norm_verdict(v) -> str:
    v = str(v or "").upper()
    return v if v in ("MALICIOUS", "BENIGN", "UNCERTAIN") else "UNCERTAIN"


def clean_evidence(ev) -> list[dict]:
    out = []
    for e in ev or []:
        if not isinstance(e, dict):
            continue
        item = {}
        if isinstance(e.get("function"), str) and e["function"]:
            item["function"] = e["function"]
        if isinstance(e.get("line"), int) and e["line"] >= 1:
            item["line"] = e["line"]
        if item and item not in out:
            out.append(item)
    return out


def merge(file: str, a: dict | None, b: dict | None) -> dict:
    rows = [r for r in (a, b) if r]
    verdicts = [norm_verdict(r.get("verdict")) for r in rows]
    if "MALICIOUS" in verdicts:
        final = "MALICIOUS"
    elif "BENIGN" in verdicts:
        final = "BENIGN"
    else:
        final = "UNCERTAIN"
    voters = [r for r, v in zip(rows, verdicts) if v == final] or rows
    reasons: list[str] = []
    evidence: list[dict] = []
    for r in voters:
        for s in r.get("reasons") or []:
            if isinstance(s, str) and s and s not in reasons:
                reasons.append(s)
        for e in clean_evidence(r.get("evidence")):
            if e not in evidence:
                evidence.append(e)
    if final == "MALICIOUS" and not evidence:
        final = "UNCERTAIN"
        reasons.insert(0, "An engine flagged this file as malicious but produced no code location; downgraded to UNCERTAIN.")
    if final == "UNCERTAIN" and not reasons:
        reasons = ["Engines disagree or could not analyse this file (parse/compile failure or timeout); no confident verdict."]
    out = {"file": file, "verdict": final, "reasons": reasons, "evidence": evidence if final == "MALICIOUS" else evidence[:20]}
    # optional fields: carry the strongest voter's, when present
    for k in ("risk_level", "risk_type", "confidence"):
        for r in voters:
            if k in r:
                out[k] = r[k]
                break
    return out


def main(argv: list[str]) -> int:
    if len(argv) < 2 or not os.path.isdir(argv[1]):
        log("usage: ensemble.py <dir>")
        print("[]")
        return 2
    d = Path(argv[1]).resolve()
    files = sorted(p.name for p in d.iterdir() if p.is_file() and p.suffix == ".sol")
    t0 = time.time()
    results: dict = {}
    engines = []
    if not DETECTOR_ONLY:
        engines.append(("noexit", ["sh", str(ROOT / "noexit" / "run.sh"), str(d)], ROOT / "noexit"))
    if not NOEXIT_ONLY:
        py = str(ROOT / ".venv" / "bin" / "python") if (ROOT / ".venv" / "bin" / "python").exists() else sys.executable
        engines.append(("detector", [py, "-m", "detector.cli", str(d)], ROOT))
    threads = [threading.Thread(target=run_engine, args=(n, c, cwd, results, BUDGET_S), daemon=True) for n, c, cwd in engines]
    for t in threads:
        t.start()
    for t in threads:
        t.join(max(1.0, BUDGET_S - (time.time() - t0)))
    a = results.get("noexit") or {}
    b = results.get("detector") or {}
    rows = [merge(f, a.get(f), b.get(f)) for f in files]
    if not rows:  # empty input dir: schema needs a non-empty array, so say so in one UNCERTAIN row
        rows = [{"file": "empty.sol", "verdict": "UNCERTAIN", "reasons": ["input directory holds no .sol file"], "evidence": []}]
    sys.stdout.write(json.dumps(rows, ensure_ascii=False, indent=2) + "\n")
    sys.stdout.flush()
    log(f"{len(files)} files -> {sum(r['verdict'] == 'MALICIOUS' for r in rows)} MALICIOUS / {sum(r['verdict'] == 'BENIGN' for r in rows)} BENIGN / {sum(r['verdict'] == 'UNCERTAIN' for r in rows)} UNCERTAIN in {time.time() - t0:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
