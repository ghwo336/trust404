"""Docker ENTRYPOINT: bench when /output is a writable dir, else submission mode."""

from __future__ import annotations

import os
import sys

from detector import cli

INPUT_DIR = "/input"
OUTPUT_DIR = "/output"


def _mode() -> str:
    if os.path.isdir(OUTPUT_DIR) and os.access(OUTPUT_DIR, os.W_OK):
        return "bench"
    return "submission"


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
