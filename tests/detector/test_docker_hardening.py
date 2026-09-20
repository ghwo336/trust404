"""Judge-run Docker hardening: any-uid, read-only rootfs, DETECTOR_MODE."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from detector.submission import validate_against_schema
from tests.detector.conftest import CASES

TIER0 = CASES / "tier0_judge"
TEST_IMAGE = os.environ.get("DETECTOR_TEST_IMAGE", "trust404/detector:latest")
DSMOKE = Path.home() / ".dsmoke" / "wave-a"

EXPECTED_TIER0 = {
    "P1": "BENIGN",
    "P2": "MALICIOUS",
    "P3": "MALICIOUS",
    "P4": "BENIGN",
    "P5": "MALICIOUS",
}

ROW_RESTRICTED = [
    "--user",
    "65534:65534",
    "--read-only",
    "--tmpfs",
    "/tmp",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--memory",
    "4g",
    "--cpus",
    "2",
    "--pids-limit",
    "512",
]
ROW_READONLY = ["--user", "65534:65534", "--read-only"]

RELAX_SOURCE = (
    "// SPDX-License-Identifier: MIT\n"
    "pragma solidity 0.8.38;\n"
    "contract Relax { uint256 public x; }\n"
)


def _image_present() -> bool:
    proc = subprocess.run(
        ["docker", "image", "inspect", TEST_IMAGE],
        capture_output=True,
        check=False,
    )
    return proc.returncode == 0


pytestmark = pytest.mark.skipif(
    os.environ.get("DETECTOR_DOCKER_TESTS") != "1" or not _image_present(),
    reason="DETECTOR_DOCKER_TESTS!=1 or image missing",
)


def _verdict_map(payload: list[dict]) -> dict[str, str]:
    got: dict[str, str] = {}
    for item in sorted(payload, key=lambda row: str(row.get("file", ""))):
        name = str(item.get("file", ""))
        for prefix in EXPECTED_TIER0:
            if name.startswith(f"{prefix}_"):
                got[prefix] = str(item["verdict"])
                break
    return got


def _run_detector(opts: list[str], in_dir: Path) -> subprocess.CompletedProcess:
    cmd = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        *opts,
        "-v",
        f"{in_dir}:/input:ro",
        TEST_IMAGE,
    ]
    return subprocess.run(cmd, capture_output=True, timeout=900)


@pytest.fixture(scope="module")
def tier0_in() -> Path:
    dest = DSMOKE / str(uuid.uuid4()) / "in"
    dest.mkdir(parents=True)
    for src in sorted(TIER0.glob("*/*.sol")):
        shutil.copy2(src, dest / src.name)
    try:
        yield dest
    finally:
        shutil.rmtree(dest.parent, ignore_errors=True)


@pytest.fixture(scope="module")
def row_runs(tier0_in: Path) -> dict[str, subprocess.CompletedProcess]:
    out = tier0_in.parent / "out"
    out.mkdir()
    rows: list[tuple[str, list[str]]] = [
        ("root", []),
        ("user1000", ["--user", "1000:1000"]),
        ("restricted", ROW_RESTRICTED),
        ("readonly_notmpfs", ROW_READONLY),
        (
            "mode_submission",
            ["-e", "DETECTOR_MODE=submission", "-v", f"{out}:/output"],
        ),
    ]
    results: dict[str, subprocess.CompletedProcess] = {}
    for name, opts in rows:
        results[name] = _run_detector(opts, tier0_in)
    return results


@pytest.mark.parametrize(
    "row_id",
    ["root", "user1000", "restricted", "readonly_notmpfs", "mode_submission"],
)
def test_docker_hardening_tier0_row(
    row_id: str, row_runs: dict[str, subprocess.CompletedProcess]
) -> None:
    proc = row_runs[row_id]
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert isinstance(payload, list)
    assert len(payload) == 5
    validate_against_schema(payload)
    assert _verdict_map(payload) == EXPECTED_TIER0
    assert b"Traceback" not in proc.stderr


def test_docker_hardening_stdout_byte_identical(
    row_runs: dict[str, subprocess.CompletedProcess],
) -> None:
    assert row_runs["root"].stdout == row_runs["user1000"].stdout
    assert row_runs["root"].stdout == row_runs["restricted"].stdout


def test_docker_scratch_degrade_relax() -> None:
    dest = DSMOKE / str(uuid.uuid4()) / "in"
    dest.mkdir(parents=True)
    (dest / "Relax.sol").write_text(RELAX_SOURCE, encoding="utf-8")
    try:
        degraded = _run_detector(ROW_READONLY, dest)
        assert degraded.returncode == 0, degraded.stderr
        payload = json.loads(degraded.stdout)
        assert isinstance(payload, list)
        assert len(payload) == 1
        validate_against_schema(payload)
        assert payload[0]["verdict"] == "UNCERTAIN"
        assert b"Traceback" not in degraded.stderr

        rescued = _run_detector(ROW_RESTRICTED, dest)
        assert rescued.returncode == 0, rescued.stderr
        rescued_payload = json.loads(rescued.stdout)
        assert isinstance(rescued_payload, list)
        assert len(rescued_payload) == 1
        validate_against_schema(rescued_payload)
        assert rescued_payload[0]["verdict"] == "BENIGN"
        assert b"Traceback" not in rescued.stderr
    finally:
        shutil.rmtree(dest.parent, ignore_errors=True)
