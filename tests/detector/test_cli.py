"""CLI: write results.json + summary.md and print the stderr summary line."""

from __future__ import annotations

import json
import re
import subprocess
import sys

from detector.model import validate_output
from tests.detector.conftest import HARNESS, REPO_ROOT

SUMMARY_LINE = re.compile(r"^detector: (\d+) files, (\d+)/(\d+)/(\d+)$", re.MULTILINE)


def test_cli_harness_writes_results_and_summary(tmp_path) -> None:
    results_path = tmp_path / "results.json"
    proc = subprocess.run(
        [sys.executable, "-m", "detector.cli", str(HARNESS), str(results_path)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert results_path.is_file()
    summary_path = tmp_path / "summary.md"
    assert summary_path.is_file()
    payload = json.loads(results_path.read_text(encoding="utf-8"))
    validate_output(payload)
    assert payload["tool"]["name"] == "detector"
    expected = len(sorted(HARNESS.rglob("*.sol")))
    assert len(payload["results"]) == expected
    # Verdict counts (M/U/B) for the OZ regression fixtures are scored by BAYBENCH, not pinned here;
    # only the file count and that the three buckets partition it are asserted.
    match = SUMMARY_LINE.search(proc.stderr)
    assert match, proc.stderr
    files, malicious, uncertain, benign = (int(g) for g in match.groups())
    assert files == expected
    assert malicious + uncertain + benign == expected
    assert uncertain >= 1  # compile_fail/broken.sol is always Uncertain(compile_failed)
    assert "Skipped" not in summary_path.read_text(encoding="utf-8")
