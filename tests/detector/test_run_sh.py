"""run.sh cold-clone path, judge_smoke, and submission --validate."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from detector.submission import validate_against_schema
from tests.detector.conftest import REPO_ROOT

TIER0 = REPO_ROOT / "cases" / "tier0_judge"
RUN_SH = REPO_ROOT / "run.sh"
JUDGE_SMOKE = REPO_ROOT / "scripts" / "judge_smoke.sh"


def _flat_tier0(tmp_path: Path) -> Path:
    dest = tmp_path / "in"
    dest.mkdir()
    for src in sorted(TIER0.glob("*/*.sol")):
        shutil.copy2(src, dest / src.name)
    return dest


def test_run_sh_no_backend_exits_2_empty_stdout(tmp_path: Path) -> None:
    shim = tmp_path / "no_slither"
    shim.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    shim.chmod(0o755)
    cases = tmp_path / "cases"
    cases.mkdir()
    env = {**os.environ, "DETECTOR_NO_DOCKER": "1", "DETECTOR_PYTHON": str(shim)}
    proc = subprocess.run(
        [str(RUN_SH), str(cases)],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    err = proc.stderr
    assert "docker load" in err
    assert "docker build" in err
    assert "setup_local.sh" in err


def test_run_sh_no_docker_tier0(tmp_path: Path) -> None:
    dest = _flat_tier0(tmp_path)
    env = {**os.environ, "DETECTOR_NO_DOCKER": "1"}
    env.pop("DETECTOR_PYTHON", None)
    proc = subprocess.run(
        [str(RUN_SH), str(dest)],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert isinstance(payload, list)
    assert len(payload) == 5
    validate_against_schema(payload)
    assert "backend=python" in proc.stderr


def test_run_sh_no_args_exits_2_empty_stdout() -> None:
    proc = subprocess.run(
        [str(RUN_SH)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert proc.stdout == ""


def test_judge_smoke_tier0(tmp_path: Path) -> None:
    dest = _flat_tier0(tmp_path)
    env = {**os.environ, "DETECTOR_NO_DOCKER": "1"}
    env.pop("DETECTOR_PYTHON", None)
    proc = subprocess.run(
        [str(JUDGE_SMOKE), str(dest)],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    assert len(lines) >= 6
    pairs = [ln.split("\t") for ln in lines if "\t" in ln]
    assert len(pairs) == 5
    by_file = {name: verdict for name, verdict in pairs}
    assert by_file["P1_StandardToken_sol.sol"] == "BENIGN"
    assert by_file["P4_CappedMint_sol.sol"] == "BENIGN"
    assert by_file["P2_HiddenMint_sol.sol"] == "MALICIOUS"
    assert by_file["P3_Honeypot_sol.sol"] == "MALICIOUS"
    assert by_file["P5_DelegatecallBackdoor_sol.sol"] == "MALICIOUS"
    summary = lines[-1]
    assert summary.startswith("judge_smoke:")
    assert "5 files" in summary
    assert "3 MALICIOUS" in summary
    assert "2 BENIGN" in summary
    assert "run.sh exit=0" in summary


def test_submission_validate_good(tmp_path: Path) -> None:
    path = tmp_path / "ok.json"
    path.write_text(
        json.dumps(
            [
                {
                    "file": "P1.sol",
                    "verdict": "BENIGN",
                    "reasons": ["ok"],
                    "evidence": [],
                }
            ]
        ),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, "-m", "detector.submission", "--validate", str(path)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""


def test_submission_validate_empty_array(tmp_path: Path) -> None:
    path = tmp_path / "empty.json"
    path.write_text("[]\n", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "detector.submission", "--validate", str(path)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    assert proc.stderr.strip() != ""


def test_submission_validate_lowercase_verdict(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps(
            [
                {
                    "file": "P1.sol",
                    "verdict": "benign",
                    "reasons": ["ok"],
                    "evidence": [],
                }
            ]
        ),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, "-m", "detector.submission", "--validate", str(path)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    assert proc.stderr.strip() != ""
