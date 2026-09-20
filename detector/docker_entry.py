"""Docker ENTRYPOINT: bench when /output is a writable dir, else submission mode."""

from __future__ import annotations

import logging
import os
import sys

from detector import cli

INPUT_DIR = "/input"
OUTPUT_DIR = "/output"

logger = logging.getLogger(__name__)


def _auto_mode() -> str:
    if os.path.isdir(OUTPUT_DIR) and os.access(OUTPUT_DIR, os.W_OK):
        return "bench"
    return "submission"


def _mode() -> str:
    raw = os.environ.get("DETECTOR_MODE", "").strip().lower()
    if raw == "submission" or raw == "bench":
        return raw
    if raw:
        logger.warning("unknown DETECTOR_MODE=%r; falling back to auto-detect", raw)
    return _auto_mode()


def main(argv: list[str] | None = None) -> int:
    extra = list(sys.argv[1:] if argv is None else argv)
    match _mode():
        case "bench":
            return cli.main([INPUT_DIR, f"{OUTPUT_DIR}/results.json"] + extra)
        case "submission":
            return cli.main([INPUT_DIR] + extra)
        case _ as unreachable:
            raise AssertionError(f"unreachable mode: {unreachable}")


if __name__ == "__main__":
    raise SystemExit(main())
