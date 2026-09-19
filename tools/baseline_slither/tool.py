"""Slither HIGH-impact overlay baseline for BAYBENCH.

Keeps only High-impact detectors to show that bug detection is not malice
detection. Never crashes the whole run: per-file errors become Uncertain.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

TOOL_NAME = "baseline_slither"
TOOL_VERSION = "0.1.0"

INSTALLED_SOLC = ("0.4.26", "0.5.17", "0.6.12", "0.7.6", "0.8.20", "0.8.24")
DEFAULT_SOLC = "0.8.20"
SOLC_ARTIFACTS = Path.home() / ".solc-select" / "artifacts"
SLITHER_TIMEOUT_S = 240

_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)
_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")


def _ver_tuple(version: str) -> tuple[int, int, int]:
    parts = [int(piece) for piece in version.split(".")]
    while len(parts) < 3:
        parts.append(0)
    return parts[0], parts[1], parts[2]


def pick_solc(source: str) -> str:
    """Pick an installed solc by nearest same-minor version; default 0.8.20."""
    match = _PRAGMA_RE.search(source)
    if not match:
        return DEFAULT_SOLC
    found = _VERSION_RE.findall(match.group(1))
    if not found:
        return DEFAULT_SOLC
    requested = _ver_tuple(found[0])
    same_minor = [ver for ver in INSTALLED_SOLC if _ver_tuple(ver)[:2] == requested[:2]]
    if not same_minor:
        return DEFAULT_SOLC

    def rank(ver: str) -> tuple[int, int, tuple[int, int, int]]:
        actual = _ver_tuple(ver)
        distance = abs(actual[2] - requested[2])
        prefer_ge = 0 if actual >= requested else 1
        return distance, prefer_ge, actual

    return min(same_minor, key=rank)


def solc_binary(version: str) -> Path:
    return SOLC_ARTIFACTS / f"solc-{version}" / f"solc-{version}"


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    candidates = (
        here.parent.parent.parent,  # tools/baseline_slither/tool.py
        here.parent,
        Path.cwd(),
    )
    for candidate in candidates:
        if (candidate / "vendor" / "openzeppelin-contracts").is_dir():
            return candidate
    return candidates[0]


def _oz_remap() -> str | None:
    vendor = _repo_root() / "vendor" / "openzeppelin-contracts"
    if not vendor.is_dir():
        return None
    return f"@openzeppelin/contracts/={vendor.as_posix()}/"


def _sol_files(input_dir: str | Path) -> list[tuple[str, Path]]:
    root = Path(input_dir).resolve()
    if not root.is_dir():
        return []
    files = sorted(path for path in root.rglob("*.sol") if path.is_file())
    out: list[tuple[str, Path]] = []
    for path in files:
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            rel = path.name
        out.append((rel, path))
    return out


def _slither_executable() -> str:
    sibling = Path(sys.executable).resolve().parent / "slither"
    if sibling.is_file():
        return str(sibling)
    found = shutil.which("slither")
    return found or "slither"


def _extract_json(text: str) -> dict | None:
    if not text:
        return None
    stripped = text.strip()
    try:
        obj = json.loads(stripped)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    best: dict | None = None
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            obj, _end = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        if "results" in obj:
            return obj
        best = obj
    return best


def _uncertain(rel: str) -> dict:
    return {"file": rel, "verdict": "Uncertain", "reason": "slither_error"}


def analyze_file(rel: str, path: Path) -> dict:
    """Run Slither on one file. Errors become Uncertain; never raise."""
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        version = pick_solc(source)
        solc_bin = solc_binary(version)
        if not solc_bin.is_file():
            return _uncertain(rel)
        argv = [
            _slither_executable(),
            str(path),
            "--solc",
            str(solc_bin),
            "--json",
            "-",
        ]
        if "@openzeppelin" in source:
            remap = _oz_remap()
            if remap is not None:
                argv.extend(["--solc-remaps", remap])
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=SLITHER_TIMEOUT_S,
            cwd=str(path.parent),
        )
        data = _extract_json(proc.stdout) or _extract_json(proc.stderr)
        if data is None:
            return _uncertain(rel)
        results = data.get("results")
        if not isinstance(results, dict) or "detectors" not in results:
            return _uncertain(rel)
        detectors = results.get("detectors") or []
        high = [
            det
            for det in detectors
            if isinstance(det, dict) and det.get("impact") == "High"
        ]
        if not high:
            return {"file": rel, "verdict": "Benign"}
        findings = []
        for det in high:
            check = det.get("check") or "unknown"
            findings.append(
                {
                    "rule_id": "SLITHER_HIGH_OVERLAY",
                    "family": "C",
                    "severity": "HIGH",
                    "reasoning": str(check),
                }
            )
        return {"file": rel, "verdict": "Malicious", "findings": findings}
    except Exception:
        return _uncertain(rel)


def classify(input_dir: str | Path) -> list[dict]:
    return [analyze_file(rel, path) for rel, path in _sol_files(input_dir)]


def write_results(output_path: str | Path, results: list[dict]) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "results": results,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv if argv is None else argv
    if len(args) < 3:
        sys.stderr.write("usage: tool.py <input_dir> <output_results_json_path>\n")
        return 2
    write_results(args[2], classify(args[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
