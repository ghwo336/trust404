"""python -m detector.cli <input_dir> [<results.json>] [--timeout 120] [--budget 480] [--recursive]."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from detector import TOOL_NAME, TOOL_VERSION
from detector.engine import WORKER_TIMEOUT_DEFAULT, analyze_dir
from detector.model import FileResult, write_results
from detector.submission import DEFAULT_BUDGET_S, run_submission
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


def _configure_logging() -> None:
    name = os.environ.get("DETECTOR_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, name, logging.INFO)
    if not isinstance(level, int):
        level = logging.INFO
    logging.basicConfig(stream=sys.stderr, level=level, force=True)


def _run_bench_mode(args: argparse.Namespace) -> int:
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


def _run_submission_mode(args: argparse.Namespace) -> int:
    saved = os.dup(1)
    objs: list[dict] = []
    try:
        os.dup2(2, 1)
        sys.stdout = sys.stderr
        _configure_logging()
        objs = run_submission(
            args.input_dir,
            timeout_s=args.timeout,
            budget_s=args.budget,
            recursive=args.recursive,
            strict=args.strict,
        )
    except Exception:
        logging.getLogger("detector.cli").exception("submission run failed")
    finally:
        payload = json.dumps(objs, ensure_ascii=False) + "\n"
        with os.fdopen(saved, "w", encoding="utf-8") as real_out:
            real_out.write(payload)
            real_out.flush()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="detector.cli")
    parser.add_argument("input_dir", type=Path)
    parser.add_argument("results_json", type=Path, nargs="?")
    parser.add_argument("--timeout", type=int, default=WORKER_TIMEOUT_DEFAULT)
    parser.add_argument("--budget", type=float, default=DEFAULT_BUDGET_S)
    parser.add_argument("--recursive", action="store_true")
    parser.add_argument("--no-summary", action="store_true")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)
    if args.results_json is None:
        return _run_submission_mode(args)
    return _run_bench_mode(args)


if __name__ == "__main__":
    raise SystemExit(main())
