"""CLI: write results.json + summary.md and print the stderr summary line."""

from __future__ import annotations

import json
import subprocess
import sys

from detector.model import validate_output
from tests.detector.conftest import HARNESS, REPO_ROOT


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
    assert len(payload["results"]) == 4
    assert "detector: 4 files, 0/1/3" in proc.stderr
