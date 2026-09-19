"""Network-isolation probe for BAYBENCH (BB-2)."""

from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

TOOL_NAME = "probe_network"
TOOL_VERSION = "0.1.0"


def network_reachable() -> bool:
    """Return True if either probe host accepts a TCP connection."""
    for host in ("1.1.1.1", "8.8.8.8"):
        try:
            conn = socket.create_connection((host, 53), timeout=3)
        except OSError:
            continue
        conn.close()
        return True
    return False


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


def classify(input_dir: str | Path, reachable: bool | None = None) -> list[dict]:
    """Emit Uncertain for every ``.sol`` file, tagged with network reachability."""
    if reachable is None:
        reachable = network_reachable()
    reason = "network_reachable" if reachable else "network_unreachable"
    results: list[dict] = []
    for rel, _path in _sol_files(input_dir):
        results.append(
            {
                "file": rel,
                "verdict": "Uncertain",
                "reason": reason,
            }
        )
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
    reachable = network_reachable()
    write_results(args[2], classify(args[1], reachable=reachable))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
