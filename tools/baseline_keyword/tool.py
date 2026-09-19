"""Naive identifier/keyword regex baseline for BAYBENCH."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

TOOL_NAME = "baseline_keyword"
TOOL_VERSION = "0.1.0"

# Each pattern maps to (rule_id, family). Severity is always HIGH.
KEYWORD_RULES: tuple[tuple[str, str, str], ...] = (
    (r"blacklist|bots?", "EXIT_ADDR_GATE", "A"),
    (r"paused|pause", "EXIT_GLOBAL_SWITCH", "A"),
    (r"setfee|settax|setmaxtx", "FEE_UNBOUNDED", "A"),
    (r"mint", "BAL_PRIV_MINT", "B"),
    (r"burnfrom", "BAL_PRIV_BURN_OTHER", "B"),
    (r"selfdestruct", "STRUCT_SELFDESTRUCT", "E"),
    (r"delegatecall", "STRUCT_DELEGATECALL_SETTABLE", "E"),
    (r"tx\.origin", "OWN_TX_ORIGIN", "D"),
)


def scan_text(text: str) -> list[dict]:
    """Return one finding per distinct keyword hit in ``text``."""
    findings: list[dict] = []
    for pattern, rule_id, family in KEYWORD_RULES:
        seen: set[str] = set()
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            keyword = match.group(0)
            key = keyword.lower()
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "rule_id": rule_id,
                    "family": family,
                    "severity": "HIGH",
                    "reasoning": f"keyword match: {keyword}",
                }
            )
    return findings


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


def classify(input_dir: str | Path) -> list[dict]:
    """Classify every ``.sol`` file under ``input_dir`` (recursive)."""
    results: list[dict] = []
    for rel, path in _sol_files(input_dir):
        text = path.read_text(encoding="utf-8", errors="replace")
        findings = scan_text(text)
        item: dict = {
            "file": rel,
            "verdict": "Malicious" if findings else "Benign",
        }
        if findings:
            item["findings"] = findings
        results.append(item)
    return results


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
