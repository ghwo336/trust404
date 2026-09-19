"""python -m detector.cli <input_dir> <results.json> [--timeout 120] [--no-summary]"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from detector import TOOL_NAME, TOOL_VERSION
from detector.engine import WORKER_TIMEOUT_DEFAULT, analyze_dir
from detector.model import FileResult, write_results
from detector.summary import render_summary


def _count_verdicts(results: list[FileResult]) -> tuple[int, int, int]:
    malicious = 0
    uncertain = 0
    benign = 0
    for result in results:
        match result.verdict:
            case "Malicious":
                malicious += 1
            case "Uncertain":
                uncertain += 1
            case "Benign":
                benign += 1
            case _ as unreachable:
                raise AssertionError(f"unreachable verdict: {unreachable}")
    return malicious, uncertain, benign


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="detector.cli")
    parser.add_argument("input_dir", type=Path)
    parser.add_argument("results_json", type=Path)
    parser.add_argument("--timeout", type=int, default=WORKER_TIMEOUT_DEFAULT)
    parser.add_argument("--no-summary", action="store_true")
    args = parser.parse_args(argv)
    results, skipped = analyze_dir(args.input_dir, timeout_s=args.timeout)
    write_results(args.results_json, results)
    if not args.no_summary:
        summary_path = args.results_json.parent / "summary.md"
        meta = {
            "name": TOOL_NAME,
            "version": TOOL_VERSION,
            "skipped_dependency_files": skipped,
        }
        summary_path.write_text(render_summary(results, meta), encoding="utf-8")
    malicious, uncertain, benign = _count_verdicts(results)
    print(
        f"detector: {len(results)} files, {malicious}/{uncertain}/{benign}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
