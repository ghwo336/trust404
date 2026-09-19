"""Engine batch, timeout/error mapping, and results.json schema validation."""

from __future__ import annotations

import json
import time

from detector.engine import analyze_dir, analyze_file
from detector.model import FileResult, Finding, validate_output, write_results
from tests.detector.conftest import HARNESS, REPO_ROOT


def _sleeper(path: str, rel: str) -> dict:
    time.sleep(30)
    return {"file": rel, "verdict": "Benign", "findings": []}


def _raiser(path: str, rel: str) -> dict:
    raise RuntimeError("boom")


def test_analyze_dir_harness() -> None:
    results = analyze_dir(HARNESS)
    files = [r.file for r in results]
    assert files == sorted(files)
    assert files == [
        "compile_fail/broken.sol",
        "multi_file/Helper.sol",
        "multi_file/Token.sol",
        "oz_import/TokenOZ.sol",
    ]
    by_file = {r.file: r for r in results}
    broken = by_file["compile_fail/broken.sol"]
    assert broken.verdict == "Uncertain"
    assert broken.reason == "compile_failed"
    for rel in ("multi_file/Helper.sol", "multi_file/Token.sol", "oz_import/TokenOZ.sol"):
        assert by_file[rel].verdict == "Benign"
        assert by_file[rel].reason == ""
        assert by_file[rel].findings == ()


def test_timeout_and_analysis_error(monkeypatch, tmp_path) -> None:
    dummy = tmp_path / "x.sol"
    dummy.write_text("pragma solidity 0.8.20; contract X {}\n", encoding="utf-8")
    monkeypatch.setattr("detector.engine._analyze_in_process", _sleeper)
    timed = analyze_file(dummy, "x.sol", timeout_s=1)
    assert timed == FileResult("x.sol", "Uncertain", reason="timeout")

    monkeypatch.setattr("detector.engine._analyze_in_process", _raiser)
    failed = analyze_file(dummy, "x.sol", timeout_s=10)
    assert failed == FileResult("x.sol", "Uncertain", reason="analysis_error")


def test_write_results_validates_and_round_trips(tmp_path) -> None:
    results = [
        FileResult(
            file="b.sol",
            verdict="Benign",
        ),
        FileResult(
            file="a.sol",
            verdict="Malicious",
            findings=(
                Finding(
                    rule_id="EXIT_ADDR_GATE",
                    family="A",
                    severity="HIGH",
                    contract="Token",
                    function="transfer",
                    lines=(10, 12),
                    reasoning="addr gate",
                ),
            ),
        ),
    ]
    out = tmp_path / "results.json"
    obj = write_results(out, results)
    validate_output(obj)
    raw = out.read_text(encoding="utf-8")
    assert raw.endswith("\n")
    loaded = json.loads(raw)
    validate_output(loaded)
    assert loaded["tool"]["name"] == "detector"
    assert loaded["results"][0]["file"] == "a.sol"
    assert "reason" not in loaded["results"][0]
    finding = loaded["results"][0]["findings"][0]
    assert set(finding) <= {
        "rule_id",
        "family",
        "severity",
        "contract",
        "function",
        "lines",
        "reasoning",
    }
    vendored = (REPO_ROOT / "detector" / "schema" / "result.schema.json").read_bytes()
    bench = (REPO_ROOT / "baybench" / "schema" / "result.schema.json").read_bytes()
    assert vendored == bench
